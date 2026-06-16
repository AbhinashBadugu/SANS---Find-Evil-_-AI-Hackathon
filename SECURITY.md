# Security Model & Guardrails

An autonomous agent that touches forensic evidence carries three risks:

1. **Spoliation** — modifying, deleting, or executing on evidence (destroys chain of custody).
2. **Hallucination** — asserting findings not grounded in an actual artifact.
3. **Coercion** — being talked (or prompt-injected) into an unsafe action.

We defend against all three with **two categories** of guardrail. The distinction matters:
**prompt-based** rules are advisory (the model is *asked* to behave); **architecture-based**
rules are structural (the model *cannot* misbehave even if fully jailbroken). We rely on
the architecture layer; the prompt layer is defense-in-depth on top.

---

## Category 1 — Prompt-based guardrails (advisory; first line, not relied upon alone)

The conversational orchestrator's system prompt ([`webui/server.py`](webui/server.py), the
`SYSTEM` block) instructs the model with hard rules:

1. **No direct evidence access and no shell** — the only capabilities are the provided
   read-only tools.
2. **Never state a forensic fact** (file, path, hash, IP, PID, confidence tier, time)
   unless it came from a tool result in the conversation.
3. **Every claim must cite** a host and a `provenance_id`; prefer `resolve_provenance`
   to verify the id resolves before asserting.
4. **Cannot change confidence tiers, invent findings, or modify evidence** — confidence
   is assigned deterministically; the model only reports it.
5. **Refuse out-of-scope actions** — "delete", "modify evidence", "run a shell command"
   are refused with an explanation of the read-only design.

> **Honest limitation:** a prompt rule can, in principle, be bypassed by a sufficiently
> clever or injected prompt. That is *exactly why* every prompt rule above is backed by a
> Category-2 control that holds regardless of what the model decides.

---

## Category 2 — Architecture-based guardrails (enforced by code; hold even if the LLM is jailbroken)

These are structural. There is no prompt that bypasses them, because the unsafe capability
**does not exist** to be invoked.

| # | Guardrail | How it's enforced | Where |
|---|-----------|-------------------|-------|
| 1 | **No write/exec/shell tool exists.** The server exposes 28 typed, **read-only** tools. There is no delete/write/modify/shell tool — the tool menu *is* the security boundary. | A jailbroken model has no capability to spoliate; it can only call read-only tools. | `mcp_server/forensic_mcp/server.py` |
| 2 | **Two-root path gate.** Inputs must resolve under read-only `EVIDENCE_ROOT`; outputs only under `CASE_ROOT`. A path that escapes either root raises `PathValidationError` and is refused. | `ensure_inside_evidence()` / `ensure_inside_case()` resolve + check the real path before any I/O. | [`mcp_server/forensic_mcp/paths.py`](mcp_server/forensic_mcp/paths.py) |
| 3 | **No shell — argv lists only.** Every external tool runs via `subprocess.run(argv, shell=False)`. No string interpolation, no shell metacharacters → no command-injection surface. | `shell=False` is hard-coded; an empty/invalid argv raises `ValueError`. | [`mcp_server/forensic_mcp/executor.py`](mcp_server/forensic_mcp/executor.py) |
| 4 | **Volatility plugin allowlist.** Only approved memory plugins run; anything else is refused. | `validate_volatility_plugin()` raises `ValueError` for any plugin not on the list. | [`mcp_server/forensic_mcp/allowlists.py`](mcp_server/forensic_mcp/allowlists.py) |
| 5 | **Citation linter — zero uncited claims.** Every finding must cite a `provenance_id` that resolves in the logbook, or it is dropped from the report. | The anti-hallucination guarantee is *enforced at render time*, not requested. | `agent/dfir_agent/nodes/report.py` |
| 6 | **Deterministic facts.** Confidence tiers, correlation, dedup, and contradiction detection are plain Python — never model judgment. | The LLM only narrates prose; it cannot change a tier or invent an artifact. | `agent/dfir_agent/rules/` |
| 7 | **Immutable provenance ledger.** Every action — success, failure, **and refusal** — appends one line `{tool, command(argv), inputs, outputs, timestamps, status}`. | Refusals are logged as `REJECTED` entries (`log_rejection`), so bypass *attempts* are themselves auditable. | [`mcp_server/forensic_mcp/provenance.py`](mcp_server/forensic_mcp/provenance.py) |
| 8 | **Evidence mounted read-only.** Disk images are mounted via FUSE `ewfmount` (read-only) at NTFS offset 0. | The OS-level mount cannot be written, independent of the application. | `mcp_server/forensic_mcp/wrappers/` |

---

## Tested for bypass

The guardrails are not just asserted — they are exercised by unit tests (part of the 158-test suite, runnable with `./install.sh` or `pytest`):

- **Path traversal / out-of-root access** → [`mcp_server/tests/test_paths.py`](mcp_server/tests/test_paths.py)
  `test_id_blocks_traversal`, `test_case_root_rejects_etc`, `test_evidence_root_rejects_outside` — each asserts a `PathValidationError` is raised.
- **Non-allowlisted memory plugin** → [`mcp_server/tests/test_volatility_allowlist.py`](mcp_server/tests/test_volatility_allowlist.py)
  `test_unknown_plugin_rejected`, `test_malfind_rejected_in_v1` — each asserts a `ValueError`.
- **No case IOCs in detection logic** (universality guard) → `agent/tests/test_no_case_iocs_in_core.py`.

**Live demonstration:** an attempt to hash a file *outside* `EVIDENCE_ROOT` (e.g. `/etc/passwd`)
is refused with `Path escapes …` and recorded as a `REJECTED` line in `provenance.jsonl` —
it is **never executed**. You can reproduce this against any path outside the configured roots.

---

## Summary

| Risk | Prompt-based control | Architecture-based control (the real boundary) |
|------|----------------------|--------------------------------------------------|
| Spoliation | "refuse delete/modify" | no write/exec tool exists · read-only mount · path gate |
| Hallucination | "never state an uncited fact" | citation linter drops uncited findings · deterministic facts |
| Coercion / injection | "refuse out-of-scope asks" | the capability isn't exposed; refusals are logged |

If you find a way to make the agent modify evidence, run a shell command, or emit an
uncited finding, that is a security bug — please open an issue with the steps to reproduce.

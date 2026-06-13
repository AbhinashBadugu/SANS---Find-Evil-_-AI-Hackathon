# Find Evil! — Autonomous Incident-Response Agent

An autonomous DFIR agent that triages a multi-host intrusion at machine speed and
produces a **fully-cited, reproducible report — without hallucinating.** It drives a
**read-only forensic MCP server** (Volatility, Sleuth Kit, Plaso, EZ Tools,
bulk_extractor) and turns thousands of rows of raw tool output into a structured
incident narrative where **every finding cites the exact artifact it came from.**

Built for the SANS / Protocol SIFT **Find Evil!** hackathon. Validated end-to-end on
the 4-host **SRL-2015** case (disk + memory).

## Headline result — accuracy vs the evidence-verified oracle

Scored against `oracle_v2` (10 evidence-adjudicated attack milestones), apples-to-apples
with the stock-Claude baseline:

| Metric | Stock baseline | **This agent** |
|--------|----------------|----------------|
| **Recall** | 0.90 | **1.0 — all 10 milestones** |
| **Hallucinations** | 1 / run | **0** |
| **Unsupported claims** | — | **0** |
| **Citation quality** | partial | **100% of 79 findings** carry `{tool, artifact, provenance_id, record_id}` |

Reproduce it: `python -m webui.scorer --case srl2015` (deterministic, no LLM).

## The core idea: code decides, the LLM only narrates

The anti-hallucination guarantee is **architectural, not a prompt:**

- **The agent has no shell and no direct evidence access.** Every evidence action is
  one MCP tool call; the menu of read-only tools *is* the security boundary.
- **Confidence, correlation, dedup, and contradiction detection are deterministic
  Python** (`agent/dfir_agent/rules/` + `scoring.py`) — never model judgment.
- **Every finding cites a `provenance_id`** that resolves in an immutable logbook, or
  it is dropped. A citation linter enforces zero uncited claims.
- The LLM's only job is to turn structured facts into prose. It cannot invent an
  artifact, change a confidence tier, or touch evidence.

This is also why results are **reproducible** — same evidence + same code → the same
10/10, every run.

## Three layers

```
┌─ webui/        Conversational UI (localhost) — chat with the investigation,
│                trigger runs, verify any citation, score vs the oracle
├─ agent/        Autonomous DFIR agent — 8 LangGraph-style nodes + deterministic
│                rules; cross-host correlation; capped self-correction loop
└─ mcp_server/   16 typed, read-only forensic tools (the evidence boundary)
```

### What the agent detects (each rule grounded + precision-tested)
process masquerade · code injection · hidden processes · malicious services ·
netscan & **carved-URL C2** · **staged-archive exfil** · Run-key / at-job
**persistence** · **multi-profile + Prefetch-confirmed droppers** · DC lateral
movement (PsExec / RDP / explicit creds / 4672) · timestomp · cross-host campaign &
patient-zero — plus **self-correction** (e.g. disputing a benign USB-over-Ethernet
service that memory flagged).

## Quick start

**1. The forensic MCP server (the read-only tool layer)**
```bash
cd mcp_server
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e .
python scripts/preflight.py     # confirm the SIFT tools are found
pytest -q                       # path-safety + allowlist tests
```

**2. Run the agent on the case** (produces cited per-host + cross-host reports)
```bash
cd agent
python -m eval.run_case --case srl2015 \
  --host-ip xp-tdungan=10.3.58.7 win7-32-nromanoff=10.3.58.5 \
            win7-64-nfury=10.3.58.6 win2008R2-controller=10.3.58.4
# re-build the cross-host report from cache in ~0.5s:  … --cross-host-only
pytest -q                       # 62 deterministic rule/scoring tests
```

**2b. Start from raw evidence files** — point the agent at the images and it leads the
whole pipeline (build manifest → hash → mount → memory+disk+timeline → correlation →
cross-host report). It auto-classifies disk vs memory and groups by host from the
filename; everything stays under one read-only `EVIDENCE_ROOT`.
```bash
cd agent
python -m eval.run_from_evidence --case srl2015 \
  /cases/SRL-2015/xp-tdungan/xp-tdungan-c-drive/xp-tdungan-c-drive.E01 \
  /cases/SRL-2015/xp-tdungan/xp-tdungan-memory/xp-tdungan-memory-raw.001 \
  …(the other six files for the other three hosts)…
# preview the plan + manifest without running:           … --dry-run
# disambiguate a file inference is unsure about:  --host xp-tdungan disk=<path> memory=<path>
```
A path that is missing, or that escapes `EVIDENCE_ROOT`, is **refused** — and an image
the filename can't classify is refused rather than guessed. On unreadable evidence the
agent emits **zero findings and discloses every gap** (each citing a `provenance_id`),
never a fabricated result. The GUI exposes the same thing: *"analyse these evidence
files: …"* → `run_pipeline_from_evidence`.

**3. Score it against the oracle** (the accuracy "after" report)
```bash
python -m webui.scorer --case srl2015   # writes accuracy_report.md
```

**4. Talk to it — the conversational UI**
```bash
cp webui/.env.example webui/.env        # paste your ANTHROPIC_API_KEY, then save
mcp_server/.venv/bin/python -m webui.server
# open http://127.0.0.1:8077  — ask "who is patient zero and how do you know?"
```
The chat LLM is an orchestrator/explainer only: read-only tools, every claim cites a
real `provenance_id`, and *"delete the evidence"* is refused by design. See
[`webui/README.md`](webui/README.md).

## Outputs (per case, under `CASE_ROOT`)
- `hosts/<host>/agent/<host>_report.md` — cited per-host report
- `CASE_REPORT.md` — cross-host campaign (patient zero → spread)
- `provenance.jsonl` — immutable evidence audit ledger
- `agent/accuracy_report.md` — recall + citation quality vs `oracle_v2`

## The 16 MCP tools (the read-only evidence boundary)
| Area | Tools |
|------|-------|
| Integrity | `hash_evidence`, `verify_ewf` |
| Memory | `run_volatility_plugin` (10 allowlisted plugins), `carve_network_artifacts` |
| Disk (no admin) | `open_ewf`, `close_ewf`, `inspect_disk`, `extract_artifacts` |
| Parsers | `parse_mft`, `parse_registry`, `parse_evtx`, `parse_shimcache`, `parse_evt_legacy` |
| Timeline | `generate_timeline`, `filter_timeline` |
| Read-back | `read_artifact` |

No shell tool exists; commands are built as argv lists run with `shell=False`. Two
separate roots — `EVIDENCE_ROOT` (read-only) and `CASE_ROOT` (all output) — are path-
validated. Every run (success, failure, or refusal) appends a line to `provenance.jsonl`.

## Scope / honesty
Validated and tuned on **SRL-2015 (4 hosts)**; generalization to an unseen case is
not yet proven (SRL-2018 is the stretch). The agent finds what it has rules for — a
human still wins on novel attacks. Tool execution (esp. Plaso) dominates wall-clock
(~45–90 min for a full 4-host run from scratch); reviewing/scoring is seconds.

## License
MIT — see [LICENSE](LICENSE).

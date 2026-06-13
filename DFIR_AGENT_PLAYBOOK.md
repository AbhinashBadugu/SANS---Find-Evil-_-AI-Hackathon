# DFIR Agent v1 — Build & Operating Playbook

> **Use this in VS Code with the Claude Code extension.** It is the canonical
> spec + task list for building the multi-agent DFIR investigation system on top
> of **MCP Server v1**. Work it **one phase at a time**; each phase ends with a
> STOP gate — do not start the next phase until the acceptance criteria pass and
> the operator confirms.
>
> **Golden rule:** the agent never runs shell. It calls **MCP tools only**. Every
> finding cites a `provenance_id` from MCP output, or it is not a finding.

---

## 0. How to drive this playbook in VS Code / Claude Code

1. Open the repo `findevil-autonomous-ir/` as the VS Code workspace.
2. Register the MCP server once (the agent's only way to touch evidence):
   ```bash
   claude mcp add forensic -- /abs/path/findevil-autonomous-ir/mcp_server/.venv/bin/python -m forensic_mcp.server
   ```
   Confirm the 16 tools are visible to the extension before building.
3. For each task below, prompt Claude Code with **just that task's heading** and
   "follow DFIR_AGENT_PLAYBOOK.md." Let it implement, then check the task's
   **Acceptance criteria** before moving on.
4. After each phase: run the phase's check, commit, and **wait for operator
   confirmation** (this is a hard gate, not a suggestion).

> Tip: you can also symlink this file to `CLAUDE.md` so the extension auto-loads
> the guardrails into every turn.

---

## 1. Architecture (8 agents, one flow)

```
Analyst
  │
  ▼
Orchestrator ──loads manifest, picks host, sequences agents, tracks steps
  ├─► Evidence Intake   (hash_evidence, verify_ewf, inspect_disk)
  ├─► Memory Analysis   (run_volatility_plugin × allowlist)
  ├─► Disk Artifact     (parse_mft / parse_registry / parse_evtx / parse_shimcache)
  ├─► Timeline          (generate_timeline / filter_timeline)
  ├─► DC / Identity     (parse_evtx with DC event-ID ruleset)   [DC hosts only]
  ├─► Correlation + Self-Correction  (cross-source, dedup, confidence, refute)
  └─► Report            (host report → later cross-host)
  ▼
Final cited report
```

Each box is a **LangGraph node** with typed input/output state. The Orchestrator
is the router; analysis agents are leaves that only emit `ToolResult` +
`Finding` objects. The Correlation and Report agents consume those.

**Design principle that governs everything:** the LLM **extracts and narrates**;
**code decides and scores**. Confidence tiers, citation checks, dedup, and
contradiction detection are deterministic Python — not model judgment. This is
the core anti-hallucination guarantee and must not be relaxed.

---

## 2. How the agent uses MCP tools

- The agent holds an **MCP client**. Every evidence action = one MCP tool call.
- **No `subprocess`, no shell, no file mutation** in agent code. If a step needs a
  capability the 16 tools don't provide, the agent records a **gap** and refuses
  the claim — it does not improvise with shell.
- Tool outputs are written by the MCP server under the case folder; the agent
  **reads them back** (via `read_artifact` or by path under `CASE_ROOT`) to extract
  facts. The agent treats those files as read-only.
- Every MCP call returns a `provenance_id`; the agent stores it on every fact it
  derives from that call.

### Real MCP Server v1 tool names (USE THESE — reconciled with the spec)

| Playbook/spec name | **Actual MCP tool** | Notes |
|--------------------|---------------------|-------|
| hash_evidence | `hash_evidence` | SHA-256 of evidence file |
| verify_ewf | `verify_ewf` | ewfverify |
| inspect_partitions | `inspect_disk` | mmls → NTFS-offset-0 fallback |
| mount_ewf_readonly | `open_ewf` / `close_ewf` | ewfmount FUSE, RO |
| mount_ntfs_readonly | (handled inside `extract_artifacts`) | no separate RW mount exists |
| run_volatility_plugin | `run_volatility_plugin` | allowlisted plugins only |
| parse_mft | `parse_mft` | MFTECmd |
| parse_registry | `parse_registry` | RECmd |
| parse_evtx | `parse_evtx` | EvtxECmd |
| parse_shimcache | `parse_shimcache` | AppCompatCacheParser |
| generate_timeline | `generate_timeline` | Plaso |
| filter_timeline | `filter_timeline` | psort slice |
| — | `parse_evt_legacy` | **XP `.evt`** (use when parse_evtx is empty) |
| — | `extract_artifacts` | carves $MFT/hives/logs (prereq for parsers) |
| — | `carve_network_artifacts` | bulk_extractor (XP net indicators) |
| — | `read_artifact` | read back our own outputs |

> ⚠️ XP hosts (tdungan): `parse_evtx` returns nothing → fall back to
> `parse_evt_legacy`; `windows.netscan` is unsupported → use `carve_network_artifacts`.

---

## 3. Agent decision logs vs MCP provenance logs (keep separate)

| | **MCP provenance log** | **Agent decision log** |
|--|------------------------|------------------------|
| File | `cases/<case>/provenance.jsonl` (written by MCP server) | `cases/<case>/agent_decisions.jsonl` (written by agent) |
| Records | every tool execution: argv, inputs, exit code, output paths, refusals | every agent *choice*: which node ran, why, what it concluded, what it skipped |
| Truth role | **evidence source of truth** — immutable, court-grade | reasoning trace — explains the agent, not the evidence |
| Who can write | only the MCP executor | only the agent runtime |

**Rule:** a `Finding` cites **provenance** IDs (evidence), never decision IDs.
The decision log is for audit/debugging the *agent*; provenance is for proving the
*evidence*. Never blend them.

---

## 4. Python project structure

```
findevil-autonomous-ir/
  mcp_server/                     # EXISTS — do not modify in this phase
  agent/
    pyproject.toml
    dfir_agent/
      __init__.py
      state.py                    # CaseState + all Pydantic schemas (§5)
      mcp_client.py               # thin async wrapper around the MCP client
      decisions.py                # agent_decisions.jsonl writer (≠ provenance)
      scoring.py                  # DETERMINISTIC confidence + citation validation
      graph.py                    # LangGraph wiring (§6)
      nodes/
        orchestrator.py
        intake.py
        memory.py
        disk.py
        timeline.py
        dc_identity.py
        correlation.py
        report.py
      rules/
        suspicious_process.py     # masquerade / path-anomaly (deterministic)
        dc_events.py              # DC event-ID ruleset
        benign_allowlist.py       # known-good paths/files (anti-FP, e.g. winsxs)
    eval/
      run_agent.py                # run agent on a host, N times
      score_vs_oracle.py          # reuse ~/baseline-runs/scoring/score_baseline.py
      accuracy_report.py          # emit the accuracy report (§9)
    tests/
      fixtures/                   # snapshotted tool outputs for golden tests
      test_schemas.py
      test_scoring.py             # confidence + citation rules
      test_golden_findings.py     # fixed-fixture replay → expected Findings
```

Outputs go under the **existing** case folder:
`~/analysis/mcp-cases/cases/<case>/hosts/<host>/agent/`.

---

## 5. Pydantic schemas (contracts — implement exactly)

Implement all nine from the spec. Key hardening to bake in:

- `Finding.confidence` → **Enum**: `confirmed | likely | suspicious | false_positive`.
- `Finding.evidence: list[EvidenceReference]` → **validator rejects empty list**
  for any confidence above `suspicious`. A claim with no resolvable `provenance_id`
  cannot be `confirmed`/`likely`.
- `EvidenceReference` must carry `provenance_id` **and** `record_id` (the specific
  MFT row / event record / process PID), so a citation points to a line, not a file.
- Add **`AgentDecision`** (not in the original list): `decision_id, agent_name,
  step, inputs_summary, action, rationale, ts` → the decision-log row.
- `ToolResult.status` Enum: `success | failed | refused`.

Schemas to implement: `CaseState, Host, EvidenceFile, ToolResult,
EvidenceReference, Finding, TimelineEvent, Contradiction, HostReport, AgentDecision`.

---

## 6. LangGraph workflow design

- **State** = `CaseState` (single typed object threaded through the graph).
- **Nodes** = the 8 agents (§1). **Edges:**
  - `intake → memory → disk → timeline → [dc_identity if role==DC] → correlation → report`
  - Orchestrator is the **conditional router**: chooses the next node from
    `completed_steps` + host role; loops back if a node reports a recoverable gap.
- **Self-correction loop:** `correlation` may route **back** to a specific analysis
  node when it detects a contradiction needing another tool call (e.g. "memory says
  malicious, disk unchecked → re-run disk for that path"). Cap loops with a hard
  `max_iterations`.
- **Every node:** (1) reads needed prior results from state, (2) makes MCP calls,
  (3) writes `ToolResult`s + draft `Finding`s into state, (4) appends an
  `AgentDecision`. Nodes never finalize confidence — only `correlation` does.
- Persist `CaseState` after every node (resumable runs).

---

## 7. The deterministic core (do not put this in the LLM)

Implement as plain Python in `scoring.py` + `rules/`:

1. **Confidence assignment** — count distinct independent sources per claim:
   `≥2 → confirmed`, `1 strong + weak → likely`, `1 → suspicious`,
   `contradicted/benign → false_positive`.
2. **Citation validation** — resolve every `provenance_id` against
   `provenance.jsonl`; drop/flag any finding whose citations don't resolve.
3. **Benign allowlist (anti-FP)** — a system file in a standard signed location
   (e.g. `winsxs` `6.1.7600.16385`) is **not malware** unless an independent
   strong source contradicts it. *This is the rule that kills the baseline's
   `wceisvista.inf` hallucination — it is mandatory.*
4. **Masquerade rule** — system binary (e.g. `svchost.exe`) running from a
   non-standard path → `suspicious` lead (this catches the tdungan implant from
   `pslist` alone).
5. **Dedup + contradiction** — merge identical artifacts across sources; emit a
   `Contradiction` when sources disagree.

The LLM's job: turn structured facts into the `description`/`executive_summary`
prose. It must never invent an artifact, path, hash, or `provenance_id`.

---

## 8. Build order — phased tasks with STOP gates

> Build **one phase at a time.** Each ends with a check + commit + operator confirm.

### Phase 1 — Vertical slice (memory only, one host) ⭐ start here
- Implement `state.py` schemas (§5) + `mcp_client.py` + `decisions.py`.
- Orchestrator loads the case manifest, selects host **`xp-tdungan`**.
- Intake: call `hash_evidence` on the memory image.
- Memory: call `run_volatility_plugin` for `windows.info`, then `windows.pslist`.
- Apply the **masquerade rule** to pslist → produce draft `Finding`(s).
- Emit `host_memory_summary.json` + `agent_decisions.jsonl`. **No report yet.**
- **Acceptance:** summary contains ≥1 `Finding` for the `\dllhost\svchost.exe`
  masquerade (PID 3296), each fact carries a real `provenance_id` that resolves in
  `provenance.jsonl`; zero shell calls; decision log populated. **→ STOP, confirm.**

### Phase 2 — Full memory plugin set
- Add `psscan, pstree, cmdline, netscan, malfind, svcscan` (allowlisted).
- Extract: suspicious processes, command lines, network connections, injected
  regions, suspicious services. Feed the masquerade + hidden-process diff rules.
- **Acceptance:** memory findings for tdungan match the manual `01_xp-tdungan`
  analysis (RAT masquerade HIGH; correct refusal where evidence is thin). **→ STOP.**

### Phase 3 — Disk artifact agent
- `extract_artifacts` → then `parse_mft / parse_registry / parse_evtx`
  (+ `parse_evt_legacy` on XP) `/ parse_shimcache`.
- Extract: execution (shimcache/amcache), dropped files (MFT), registry
  persistence, service installs, logon events.
- **Acceptance:** the tdungan RAT becomes **multi-source** (memory + MFT +
  shimcache) → confidence `confirmed` by the deterministic scorer. **→ STOP.**

### Phase 4 — Timeline agent
- `generate_timeline` → `filter_timeline` (attack window / keyword).
- Emit `TimelineEvent`s: first suspicious activity, execution sequence.
- **Acceptance:** timeline pins patient-zero timing; events cite provenance. **→ STOP.**

### Phase 5 — Correlation + confidence
- Cross-source merge, dedup, contradiction detection, confidence assignment,
  benign allowlist, self-correction loop (capped).
- **Acceptance:** confidence tiers populated deterministically; ≥1 `Contradiction`
  resolved; **no** built-in Windows file marked malware. **→ STOP.**

### Phase 6 — Host report agent
- Emit `HostReport`: confirmed / likely / suspicious / false-positive sections;
  every claim shows host_id, artifact, tool, output path, provenance_id, timestamp.
- **Acceptance:** report renders; a citation-linter pass finds **0 uncited claims**.
  **→ STOP.**

### Phase 7 — Scale to 4 hosts (+ DC/Identity agent)
- Run all hosts; enable `dc_identity` (DC event-ID ruleset §rules) on the DC.
- **Acceptance:** 4 host reports produced; DC shows lateral-movement / admin
  events with citations. **→ STOP.**

### Phase 8 — Cross-host correlation ✅ BUILT
- Correlate findings across hosts (shared implants, lateral-movement chain).
- **Acceptance:** a cross-host narrative (patient zero → spread) with per-hop
  citations. **→ STOP.**
- **Implementation:** `dfir_agent/nodes/cross_host.py` — a case-level deterministic
  pass over the finished per-host bundles (no new evidence; reuses each finding's
  provenance). Produces: (1) **shared implants** (same file basename on ≥2 hosts,
  per-host confidence + cites), (2) an ordered **lateral-movement chain** (each
  `lateral_movement` finding is a hop INTO its host; `src:<ip>` tags resolved to a
  source host via `Host.ip` topology — unmapped IPs become a disclosed gap, never a
  guess), (3) case **patient zero** (earliest per-host marker), (4) a **spread
  graph**. Rendered to `cases/<case>/CASE_REPORT.md`; lint enforces 0 uncited
  hops/implants (same gate as the host report).
- **Run:** `python -m eval.run_case --case srl2015 --host-ip xp-tdungan=10.3.58.7 …`
  (full pipeline + Phase 8). Re-run Phase 8 alone in seconds from cached
  `hosts/<host>/agent/findings.json`: `… --cross-host-only`.
- **Tests:** `tests/test_phase8_cross_host.py` (7 cases): shared-implant ≥2-host
  rule, patient-zero = earliest, hop attribution via topology, unmapped-IP gap,
  spread edges, lint clean/dirty.

### Do NOT build yet
DNS/DHCP/firewall/proxy/VPN/PCAP parsers, cloud forensics, frontend, Kubernetes,
vector DB, LLM training/fine-tuning. (Gaps surfaced during analysis go in
`~/analysis/mcp-cases/agent-analysis/TOOL_GAPS.md`, not into scope creep.)

---

## 9. Evaluation — the accuracy report (first-class deliverable)

After **each** of Phases 2/3/5/6 (and finally Phase 7), score the agent vs the
evidence-verified oracle.

- **Oracle:** `~/baseline-runs/scoring/oracle_v2.json` (the same ruler the baseline
  was graded on — apples-to-apples).
- **Scorer:** reuse `~/baseline-runs/scoring/score_baseline.py`.
- **Run N≥3 times** per host — report **mean and variance**, not one number
  (the baseline's real weakness was variance 0.79→1.0).
- **Adversarial verification:** before a finding is `confirmed`, a refute-pass
  checks "is this file built-in? does the path exist in MFT? is there a 2nd
  source?" Log every refutation.

**Accuracy report metrics (the table you ship):**

| Metric | Definition |
|--------|------------|
| Recall | true Oracle-V2 milestones the agent found |
| Hallucinations | claims contradicted by evidence (e.g. benign file called malware) |
| Missing findings | Oracle milestones not reported |
| Extra unsupported | agent claims with no resolvable `provenance_id` |
| Citation quality | % of claims with full {tool, path, provenance_id, record_id} |
| Variance | recall spread across N runs |
| Cost | API tokens/$ per run |

**Target (the "after" column vs the baseline "before"):** recall ≥ 0.90 with
**lower variance**, **0** hallucinations, **0** extra-unsupported, 100% citation
quality.

---

## 10. Definition of Done (per-finding guardrail checklist)

A finding ships only if **all** are true:
- [ ] Derived from MCP tool output (no shell, ever).
- [ ] Carries ≥1 `EvidenceReference` with a `provenance_id` that resolves.
- [ ] Confidence set by the **deterministic** scorer, not the LLM.
- [ ] Passed the benign allowlist (not a built-in file mislabeled malware).
- [ ] If `confirmed`: ≥2 independent sources.
- [ ] Recorded in the agent decision log with a rationale.

---

## 11. Existing assets to build on (don't reinvent)

| Asset | Path |
|-------|------|
| MCP Server v1 (16 tools) | `mcp_server/` (this repo) |
| Already-collected tool outputs (4 hosts) | `~/analysis/mcp-cases/cases/srl2015/` |
| Provenance ledger (141 actions) | `~/analysis/mcp-cases/cases/srl2015/provenance.jsonl` |
| Manual host analysis + method | `~/analysis/mcp-cases/agent-analysis/` |
| Gap backlog (build-next list) | `~/analysis/mcp-cases/agent-analysis/TOOL_GAPS.md` |
| Oracle V2 (truth) + scorer | `~/baseline-runs/scoring/{oracle_v2.json,score_baseline.py}` |
| Baseline "before" numbers | `~/baseline-runs/BASELINE_RESULTS.md` |
| Baseline hallucination evidence | `~/baseline-runs/baseline-accuracy-gaps/` |
| Project status / architecture writeup | `~/reports/PROJECT_STATUS.md` |

---

**Operating discipline:** one phase, one gate, one confirmation. The agent's value
is *correct, cited, reproducible* findings — never speed, never coverage for its
own sake. When in doubt, the agent **refuses and logs a gap** rather than guessing.
```

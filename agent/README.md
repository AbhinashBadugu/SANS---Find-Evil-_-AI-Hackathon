# DFIR Agent

Autonomous incident-response agent that drives the read-only forensic MCP server
(`../mcp_server`). It **never runs shell or touches evidence directly**: every
evidence action is one MCP tool call, and every fact it reports cites a
`provenance_id` from that call's logbook line. Built per `../DFIR_AGENT_PLAYBOOK.md`.

**Design law:** the LLM (later phases) only *extracts* facts and *narrates* prose;
deterministic Python (`dfir_agent/rules/` + `scoring.py`) *decides* and *scores*.

## Status — Phase 4 complete (timeline agent)

Flow: `orchestrator → intake → memory → disk → timeline → correlation`, host
`xp-tdungan`. The **timeline** node builds a Plaso super-timeline from the carved
artifacts (`generate_timeline`), slices it around the implant directory
(`filter_timeline`), and emits `TimelineEvent`s. It pins **patient-zero timing**
using the `$FILE_NAME` creation (which ordinary tooling cannot backdate) rather
than the timestomped `$STANDARD_INFORMATION`, and emits the SI backdating as its
own timestomp event. Validated live: patient-zero `2012-04-03 00:35:02 UTC`
(implant drop), config drop `winclient.reg` at `00:35:10`, timestomp flagged at
`2003-03-31`; every event cites a resolvable provenance_id.

Earlier flow:

Flow: `orchestrator → intake → memory → disk → correlation`, host `xp-tdungan`.
Memory runs the full allowlisted plugin set and five deterministic rules
(parent-anomaly, path-masquerade, hidden-process, injected-PE, suspicious-service).
The **disk** node mounts read-only (`open_ewf`→`inspect_disk`→`extract_artifacts`),
parses `$MFT`/shimcache/hives/event-logs, and corroborates each memory-surfaced
path against disk (existence, **timestomp**, co-located drops, execution record).
The **correlation** node fuses findings by shared entity/path (union-find) and sets
confidence from the count of **distinct independent evidence families** (≥2 →
`confirmed`).

Validated live on `xp-tdungan`: the implant (`\system32\dllhost\svchost.exe`) is
`confirmed` across **five** families spanning the memory/disk boundary —
`process_tree` + `command_line` + `injection` (memory) and `disk_mft` (file present,
102 400 bytes, FN-created 2012-04-03, SI-timestomped to 2003, co-located
`winclient.reg` config) + `disk_shimcache` (execution record). `spinlock.exe`/
`cmd.exe` remain `suspicious` leads; `netscan`/`parse_evtx` (thin on XP) are gaps,
not inventions. Citations all resolve, zero shell calls, zero false positives.

> **Self-correction note:** the injection family corrects the manual analysis,
> which claimed malfind missed the implant — the raw evidence shows malfind flags
> PID 3296 (and only 3296) with 105 injected-PE regions.

**Confidence law (operator rule):** nothing is `confirmed` without ≥2 independent
sources, where independence = distinct evidence family (`scoring.py`).

## Layout

| Path | Role |
|------|------|
| `dfir_agent/state.py` | Pydantic contracts (§5) + confidence/citation validators |
| `dfir_agent/mcp_client.py` | the agent's only door to evidence (stdio MCP client) |
| `dfir_agent/decisions.py` | agent decision log (≠ MCP provenance, §3) |
| `dfir_agent/scoring.py` | deterministic confidence + citation validation (§7) |
| `dfir_agent/rules/` | masquerade + benign-allowlist rules (§7) |
| `dfir_agent/nodes/` | orchestrator / intake / memory nodes (§1) |
| `dfir_agent/graph.py` | LangGraph-compatible runner (swap-in once `langgraph` installed) |
| `eval/run_agent.py` | Phase-1 entrypoint |
| `tests/` | schema + scoring/rule golden tests |

## Run

Reuses the MCP server's virtualenv (it has `pydantic` + `mcp`; no separate install):

```bash
VENV=../mcp_server/.venv/bin/python

# unit tests (no MCP, fast)
$VENV -m pytest tests/ -q

# live run: spawns the MCP server, hashes + runs Volatility, writes the summary
$VENV -m eval.run_agent --case srl2015 --host xp-tdungan
```

Outputs land under `~/analysis/mcp-cases/cases/<case>/hosts/<host>/agent/`:
`host_memory_summary.json` and `agent_decisions.jsonl`.

## Not yet built (later phases, gated)

LLM narration + LangGraph wiring need `anthropic` + `langgraph` (declared under
`[project.optional-dependencies].llm`), installed by the operator when online.
Phases 2–8 (full plugin set, disk, timeline, correlation/self-correction, host
report, 4-host scale-out, cross-host) per the playbook.

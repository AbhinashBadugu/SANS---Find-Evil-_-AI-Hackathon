# DFIR Agent

Autonomous incident-response agent that drives the read-only forensic MCP server
(`../mcp_server`). It **never runs shell or touches evidence directly**: every
evidence action is one MCP tool call, and every fact it reports cites a
`provenance_id` from that call's logbook line. Built per `../DFIR_AGENT_PLAYBOOK.md`.

**Design law:** the LLM (later phases) only *extracts* facts and *narrates* prose;
deterministic Python (`dfir_agent/rules/` + `scoring.py`) *decides* and *scores*.

## Status — Phase 1 complete (memory vertical slice)

`orchestrator → intake → memory`, host `xp-tdungan`. Hashes the memory image,
runs `windows.info` + `windows.pslist`, applies the deterministic **parent-anomaly
(masquerade) rule**, and emits a cited summary. Validated live: detects the
`svchost.exe` implant (PID 3296, parent `explorer.exe` instead of `services.exe`)
with a resolvable citation, citations clean, zero shell calls.

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

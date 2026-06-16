# SRL-2015 — Agent Execution Logs

Complete logs from the autonomous DFIR agent's **from-scratch** run on the 4-host
SRL-2015 case (2026-06-15 23:49 → 2026-06-16 00:55 UTC, all 4 hosts).

| File | What it is |
|------|------------|
| `AGENT_RUN_LOG_*.log` | Full pipeline narrative, start → finish, `[UTC]` timestamp per line (1,014 lines). |
| `AGENT_TOOL_LOG_*.log` | Every forensic command the agent ran — **1,244** tool executions, readable. |
| `provenance.jsonl` | The **immutable audit ledger** — 1,244 entries `{tool, command, inputs, outputs, timestamps, status}`. Canonical; what the scorer and citation linter resolve against. |
| `gui_server_live.log` | The web-UI server log. |

`*_latest.log` are symlinks to the timestamped files above.

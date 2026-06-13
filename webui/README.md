# Find Evil — Conversational DFIR Agent (local web UI)

A localhost chat interface to the deterministic, read-only **Find Evil** DFIR
pipeline. Talk to your investigation in natural language — ask who patient zero is,
have it prove a finding, trigger the cross-host correlation, or score itself against
the oracle — without ever opening Claude Code.

```
Browser ──HTTP/SSE──► Starlette ──► chat LLM (orchestrator) ──► read-only tools
                                                                     │
                                          reads pipeline outputs / triggers the
                                          pipeline (which is read-only via the MCP server)
```

## The guardrail still holds (this is the point)

The chat model is an **orchestrator and explainer — never a source of forensic
facts.** It has **no evidence access and no shell**; its only capabilities are the
typed, read-only tools in [`tools.py`](tools.py). It cannot invent a finding, change
a confidence tier, or mutate evidence. Every forensic claim it makes is backed by a
`provenance_id` it resolves against the immutable logbook — ask it to prove anything
and it calls `resolve_provenance`. A request like *"delete the evidence"* is refused
by design, because no such tool exists.

## Run it

```bash
# 1. (chat only) supply a key — the model orchestrates, it does not analyze evidence
export ANTHROPIC_API_KEY=sk-ant-...

# 2. start the server (uses the mcp_server venv, which has all deps)
cd findevil-autonomous-ir
mcp_server/.venv/bin/python -m webui.server
#  → http://127.0.0.1:8077
```

Without a key the **dashboard still works** — the reports, findings, and oracle
scorecard are served from REST endpoints; only the chat box needs the key.

Env: `DFIR_UI_PORT` (default 8077), `DFIR_CHAT_MODEL` (default `claude-sonnet-4-6`).

## What you can ask

- *"What cases do you have?"* → `list_cases`
- *"Who is patient zero and how do you know?"* → `list_findings` + `resolve_provenance`
- *"Show the cross-host campaign report."* → `get_report`
- *"Rebuild the cross-host report with the host IPs."* → `run_cross_host` (~1s)
- *"Re-run the full analysis on nfury."* → `run_full_pipeline` (background job)
- *"Analyse these 8 evidence files: /cases/…E01 /cases/…001 …"* → `run_pipeline_from_evidence`
  (builds the manifest from the paths and leads the whole pipeline; background job)
- *"Score the agent against the oracle."* → `score_vs_oracle`
- *"Try to delete the evidence."* → refused (architectural read-only)

## Pieces

| File | Role |
|------|------|
| `server.py` | Starlette app: REST endpoints + `/api/chat` SSE tool-use loop + static serving |
| `tools.py` | The read-only tool surface + background `JobManager` |
| `scorer.py` | Agent-vs-`oracle_v2` accuracy scorer (also runnable standalone: `python -m webui.scorer`) |
| `static/` | Chat UI (vanilla JS, `marked` for markdown) with inline tool-use display + report panel |

## Accuracy (standalone)

```bash
mcp_server/.venv/bin/python -m webui.scorer --case srl2015
# writes cases/<case>/agent/accuracy_report.md + accuracy_score.json
```
This is the agent's **"after" column** — same oracle and same hit rule as the
baseline scorer, so the numbers are directly comparable.

# Find Evil! — Autonomous IR (Forensic MCP Server)

A safe, **read-only** forensic tool layer for the SANS SIFT Workstation, exposed as
an [MCP](https://modelcontextprotocol.io) server. A future AI agent can call typed
forensic tools but **cannot run arbitrary shell commands and cannot modify evidence** —
the menu of tools *is* the security boundary.

Built for the SANS / Protocol SIFT **Find Evil!** hackathon. Validated end-to-end on
the 4-host **SRL-2015** case (disk + memory).

## Why it's safe (architectural, not prompt-based)
- No shell tool exists. Every command is built in code as an argv list and run with `shell=False`.
- Two separate roots: `EVIDENCE_ROOT` (read-only) and `CASE_ROOT` (all output). Paths are validated against them.
- Disk images are opened read-only (`ewfmount`, FUSE, no admin) — never mounted read-write.
- Volatility plugins are allowlisted; unknown plugins are refused.
- Every tool run — success, failure, or refusal — appends one line to `provenance.jsonl` (the audit ledger).
- The wrappers never draw conclusions; they run tools and return structured results.

## The 16 tools
| Area | Tools |
|------|-------|
| Integrity | `hash_evidence`, `verify_ewf` |
| Memory | `run_volatility_plugin` (10 allowlisted plugins), `carve_network_artifacts` |
| Disk (no admin) | `open_ewf`, `close_ewf`, `inspect_disk`, `extract_artifacts` |
| Parsers | `parse_mft`, `parse_registry`, `parse_evtx`, `parse_shimcache`, `parse_evt_legacy` |
| Timeline | `generate_timeline`, `filter_timeline` |
| Read-back | `read_artifact` |

## Layout
```
mcp_server/
  forensic_mcp/
    config.py  schemas.py  paths.py  provenance.py  executor.py  allowlists.py
    server.py            # the MCP server: exposes the 16 tools
    wrappers/            # one module per tool group
  scripts/               # preflight + per-stage drivers (memory / disk / timeline)
  tests/                 # path-safety + allowlist unit tests
```

## Quick start
```bash
cd mcp_server
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e .          # or: pip install "mcp[cli]" pydantic python-dotenv pytest
cp .env.example .env                # adjust EVIDENCE_ROOT / CASE_ROOT
python scripts/preflight.py         # confirm tools are found
pytest -q                           # safety + allowlist tests
```

Register with Claude Code so an agent can call the tools directly:
```bash
claude mcp add forensic -- /abs/path/mcp_server/.venv/bin/python -m forensic_mcp.server
```

## Scope / status
Tool layer is complete and validated on SRL-2015 (4 hosts). Tools are partly general
and partly tuned to these single-volume images (e.g. `inspect_disk` assumes offset 0;
`extract_artifacts` pulls a curated artifact set). The autonomous reasoning/correlation
agent layer is the next phase.

## License
MIT — see [LICENSE](LICENSE).

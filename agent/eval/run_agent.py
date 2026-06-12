"""Phase 1 entrypoint: run the agent on one host and emit its memory summary.

    python -m eval.run_agent --case srl2015 --host xp-tdungan

Produces (under CASE_ROOT/cases/<case>/hosts/<host>/agent/):
  * host_memory_summary.json  — findings + tool results + citation report
  * agent_decisions.jsonl     — the reasoning trace (written live by the nodes)

Every fact in the summary cites a provenance_id that the citation validator has
resolved against the server's provenance.jsonl. Zero shell calls: the agent only
ever talks to the MCP server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Allow running as a script (python eval/run_agent.py) as well as a module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.decisions import DecisionLog  # noqa: E402
from dfir_agent.graph import run_case  # noqa: E402
from dfir_agent.manifest import load_or_build_manifest  # noqa: E402
from dfir_agent.mcp_client import ForensicMCPClient  # noqa: E402
from dfir_agent.nodes import NodeContext  # noqa: E402
from dfir_agent.scoring import load_provenance_ids, validate_citations  # noqa: E402
from dfir_agent.state import CaseState  # noqa: E402

DEFAULT_CASE_ROOT = os.path.expanduser("~/analysis/mcp-cases")


def _summary_path(case_root: str, case_id: str, host_id: str) -> Path:
    d = Path(case_root) / "cases" / case_id / "hosts" / host_id / "agent"
    d.mkdir(parents=True, exist_ok=True)
    return d / "host_memory_summary.json"


async def _run(case_id: str, host: str | None, case_root: str) -> dict:
    state = CaseState(case_id=case_id, case_root=case_root)

    async with ForensicMCPClient() as client:
        # The agent's whole surface is the server's tool menu — prove it loaded.
        if not client.tool_names:
            raise RuntimeError("MCP server exposed no tools.")
        # We don't yet know the host until the orchestrator runs; use a temp log
        # then re-point once selected.
        target = host
        # Resolve the host up front so the decision log is correctly host-scoped
        # (same default rule the orchestrator uses: prefer an XP host).
        manifest = load_or_build_manifest(case_root, case_id)
        resolved_host = host or next(
            (h for h in manifest if "xp" in h.lower()), sorted(manifest)[0] if manifest else "_pending"
        )
        decisions = DecisionLog(case_root, case_id, resolved_host)
        ctx = NodeContext(client=client, decisions=decisions, case_root=case_root)
        state = await run_case(state, ctx, target_host=target)

    host_id = state.current_host
    prov_ids = load_provenance_ids(case_root, case_id)
    citation_report = validate_citations(state.findings, prov_ids)

    summary = {
        "case_id": case_id,
        "host_id": host_id,
        "os": state.hosts[host_id].os if host_id else None,
        "role": state.hosts[host_id].role.value if host_id else None,
        "completed_steps": state.completed_steps,
        "gaps": state.gaps,
        "tool_results": [tr.model_dump(mode="json") for tr in state.tool_results],
        "findings": [f.model_dump(mode="json") for f in state.findings],
        "citation_report": citation_report.as_dict(),
        "counts": {
            "tool_calls": len(state.tool_results),
            "findings": len(state.findings),
            "provenance_ids_in_ledger": len(prov_ids),
        },
    }

    out = _summary_path(case_root, case_id, host_id)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["_summary_path"] = str(out)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the DFIR agent (Phase 1: memory vertical slice).")
    ap.add_argument("--case", default="srl2015")
    ap.add_argument("--host", default="xp-tdungan", help="target host_id (default: xp-tdungan)")
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    args = ap.parse_args()

    summary = asyncio.run(_run(args.case, args.host, args.case_root))

    print(f"\n=== Agent run: {args.case} / {summary['host_id']} ===")
    print(f"OS: {summary['os']}  role: {summary['role']}")
    print(f"Tool calls: {summary['counts']['tool_calls']}  Findings: {summary['counts']['findings']}")
    for f in summary["findings"]:
        cites = ", ".join(f"{e['provenance_id']}:{e.get('record_id')}" for e in f["evidence"])
        print(f"  [{f['confidence']}] {f['title']}")
        print(f"      rule={f['rule']}  cites=[{cites}]")
    cr = summary["citation_report"]
    print(f"Citations clean: {cr['clean']}  (uncited={len(cr['uncited'])}, unresolved={len(cr['unresolved'])})")
    if summary["gaps"]:
        print("Gaps:", *summary["gaps"], sep="\n  - ")
    print(f"\nSummary: {summary['_summary_path']}")
    # Phase-1 acceptance: at least one resolvable masquerade finding, citations clean.
    masquerade = [f for f in summary["findings"] if f["category"] == "process_masquerade"]
    ok = bool(masquerade) and cr["clean"]
    print("ACCEPTANCE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

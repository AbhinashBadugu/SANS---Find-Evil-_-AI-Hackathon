"""Phase 7 entrypoint: run the agent across ALL hosts in a case.

    python -m eval.run_case --case srl2015

Runs the full per-host pipeline (memory -> disk -> timeline -> [dc_identity on the
DC] -> correlation <-> disk_recheck -> report) for every host in the manifest,
using one shared MCP client. Each host gets its own cited HostReport; a
case-level case_summary.json indexes them.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.decisions import DecisionLog  # noqa: E402
from dfir_agent.graph import run_case as run_graph  # noqa: E402
from dfir_agent.manifest import load_or_build_manifest  # noqa: E402
from dfir_agent.mcp_client import ForensicMCPClient  # noqa: E402
from dfir_agent.nodes import NodeContext  # noqa: E402
from dfir_agent.state import CaseState, Confidence  # noqa: E402

DEFAULT_CASE_ROOT = os.path.expanduser("~/analysis/mcp-cases")


def _host_metrics(state: CaseState) -> dict:
    by = lambda c: [f for f in state.findings if f.confidence == c]  # noqa: E731
    pz = min((te.ts for te in state.timeline if "PATIENT-ZERO MARKER" in te.description), default=None)
    lateral = [f for f in state.findings if f.category == "lateral_movement"]
    return {
        "report_path": state.report_path,
        "lint_clean": bool((state.report_lint or {}).get("clean")),
        "confirmed": len(by(Confidence.confirmed)),
        "likely": len(by(Confidence.likely)),
        "suspicious": len(by(Confidence.suspicious)),
        "false_positive": len([f for f in state.findings if f.confidence == Confidence.false_positive]),
        "contradictions": len(state.contradictions),
        "lateral_movement_findings": len(lateral),
        "patient_zero_utc": pz.isoformat() if pz else None,
        "tool_calls": len(state.tool_results),
        "timeline_events": len(state.timeline),
    }


async def _run(case_id: str, case_root: str, only: list[str] | None) -> dict:
    manifest = load_or_build_manifest(case_root, case_id)
    hosts = [h for h in manifest if (not only or h in only)]
    results: dict[str, dict] = {}

    async with ForensicMCPClient() as client:
        if not client.tool_names:
            raise RuntimeError("MCP server exposed no tools.")
        for host_id in hosts:
            print(f"\n>>> {host_id} ({manifest[host_id].role.value}) ...", flush=True)
            state = CaseState(case_id=case_id, case_root=case_root)
            decisions = DecisionLog(case_root, case_id, host_id)
            ctx = NodeContext(client=client, decisions=decisions, case_root=case_root)
            try:
                state = await run_graph(state, ctx, target_host=host_id)
                results[host_id] = _host_metrics(state)
                m = results[host_id]
                print(f"    report={Path(m['report_path']).name if m['report_path'] else 'NONE'} "
                      f"lint_clean={m['lint_clean']} confirmed={m['confirmed']} "
                      f"lateral={m['lateral_movement_findings']} contradictions={m['contradictions']}",
                      flush=True)
            except Exception as e:  # noqa: BLE001 — one host must not abort the case
                results[host_id] = {"error": f"{type(e).__name__}: {e}"}
                print(f"    ERROR: {e}", flush=True)

    case_summary = {"case_id": case_id, "hosts": results}
    out = Path(case_root) / "cases" / case_id / "case_summary.json"
    out.write_text(json.dumps(case_summary, indent=2), encoding="utf-8")
    case_summary["_path"] = str(out)
    return case_summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the DFIR agent across all hosts in a case (Phase 7).")
    ap.add_argument("--case", default="srl2015")
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    ap.add_argument("--only", nargs="*", help="optional subset of host_ids")
    args = ap.parse_args()

    cs = asyncio.run(_run(args.case, args.case_root, args.only))
    hosts = cs["hosts"]

    print("\n=== CASE SUMMARY:", cs["case_id"], "===")
    print(f"{'host':26} {'report':8} {'lint':5} {'conf':4} {'lkly':4} {'susp':4} {'lat':4} {'contra':6} {'patient-zero'}")
    reports = 0
    dc_lateral = 0
    all_clean = True
    for host_id, m in hosts.items():
        if "error" in m:
            print(f"{host_id:26} ERROR: {m['error']}")
            all_clean = False
            continue
        reports += 1 if m["report_path"] else 0
        all_clean = all_clean and m["lint_clean"]
        if "controller" in host_id or "dc" in host_id.lower() or "2008" in host_id:
            dc_lateral = m["lateral_movement_findings"]
        print(f"{host_id:26} {'yes' if m['report_path'] else 'NO':8} "
              f"{str(m['lint_clean']):5} {m['confirmed']:<4} {m['likely']:<4} {m['suspicious']:<4} "
              f"{m['lateral_movement_findings']:<4} {m['contradictions']:<6} {m['patient_zero_utc'] or '-'}")
    print(f"\nCase summary: {cs['_path']}")

    ok = reports == len([h for h in hosts]) and all_clean and dc_lateral > 0
    print(f"ACCEPTANCE: {'PASS' if ok else 'FAIL'}  "
          f"(reports: {reports}/{len(hosts)}, all_lints_clean: {all_clean}, dc_lateral_movement: {dc_lateral})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

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

DEFAULT_CASE_ROOT = os.path.expanduser("~/Desktop/DFIR agent/Agent analysis")


def _summary_path(case_root: str, case_id: str, host_id: str) -> Path:
    d = Path(case_root) / "cases" / case_id / "hosts" / host_id / "agent"
    d.mkdir(parents=True, exist_ok=True)
    return d / "host_summary.json"


async def _run(case_id: str, host: str | None, case_root: str, evidence_root: str | None = None) -> dict:
    state = CaseState(case_id=case_id, case_root=case_root, evidence_root=evidence_root)

    async with ForensicMCPClient() as client:
        # The agent's whole surface is the server's tool menu — prove it loaded.
        if not client.tool_names:
            raise RuntimeError("MCP server exposed no tools.")
        # We don't yet know the host until the orchestrator runs; use a temp log
        # then re-point once selected.
        target = host
        # Resolve the host up front so the decision log is correctly host-scoped.
        if evidence_root:
            # Universal path: the orchestrator discovers + selects from the manifest.
            resolved_host = host or "_pending"
        else:
            # Legacy path: same default rule the orchestrator uses (prefer an XP host).
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

    # Patient-zero = earliest timeline event flagged as the marker.
    pz_events = [te for te in state.timeline if "PATIENT-ZERO MARKER" in te.description]
    patient_zero = min((te.ts for te in pz_events), default=None)
    timeline_cites_resolve = all(
        e.provenance_id in prov_ids for te in state.timeline for e in te.evidence
    )

    summary = {
        "case_id": case_id,
        "host_id": host_id,
        "os": state.hosts[host_id].os if host_id else None,
        "role": state.hosts[host_id].role.value if host_id else None,
        "completed_steps": state.completed_steps,
        "gaps": state.gaps,
        "patient_zero_utc": patient_zero.isoformat() if patient_zero else None,
        "tool_results": [tr.model_dump(mode="json") for tr in state.tool_results],
        "findings": [f.model_dump(mode="json") for f in state.findings],
        "timeline": [te.model_dump(mode="json") for te in sorted(state.timeline, key=lambda x: x.ts)],
        "contradictions": [c.model_dump(mode="json") for c in state.contradictions],
        "self_correction": {
            "attempted": state.self_correction_attempted,
            "disk_recheck_done": state.disk_recheck_done,
            "rechecked_names": state.recheck_names,
        },
        "citation_report": citation_report.as_dict(),
        "timeline_citations_resolve": timeline_cites_resolve,
        "report": {
            "path": state.report_path,
            "lint": state.report_lint,
            "narrated": state.report_narrated,
        },
        "counts": {
            "tool_calls": len(state.tool_results),
            "findings": len(state.findings),
            "timeline_events": len(state.timeline),
            "contradictions": len(state.contradictions),
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
    ap.add_argument("--host", default=None,
                    help="target host_id (default: auto — legacy prefers an XP host)")
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    ap.add_argument("--evidence-root", default=None,
                    help="scan this folder via the Universal Case Manifest Builder "
                         "(case-agnostic discovery). Omit for the legacy manifest path.")
    args = ap.parse_args()

    summary = asyncio.run(_run(args.case, args.host, args.case_root, args.evidence_root))

    print(f"\n=== Agent run: {args.case} / {summary['host_id']} ===")
    print(f"OS: {summary['os']}  role: {summary['role']}")
    print(f"Tool calls: {summary['counts']['tool_calls']}  Findings: {summary['counts']['findings']}")
    for f in sorted(summary["findings"], key=lambda x: x["confidence"]):
        fams = sorted({e.get("source_family") for e in f["evidence"] if e.get("source_family")})
        cites = ", ".join(f"{e['provenance_id']}:{e.get('record_id')}" for e in f["evidence"])
        print(f"  [{f['confidence']}] {f['title']}  (sources={f['source_count']})")
        print(f"      families={fams}  rule={f['rule']}")
        print(f"      cites=[{cites}]")
    cr = summary["citation_report"]
    print(f"Citations clean: {cr['clean']}  (uncited={len(cr['uncited'])}, unresolved={len(cr['unresolved'])})")
    if summary["timeline"]:
        print(f"Timeline events: {len(summary['timeline'])}  patient-zero: {summary['patient_zero_utc']} UTC")
        for te in summary["timeline"]:
            print(f"  {te['ts']}  [{te['source']}]  {te['description'][:88]}")
            print(f"      cite: {te['evidence'][0]['provenance_id']}:{te['evidence'][0]['record_id']}")
    if summary["contradictions"]:
        print(f"Contradictions ({len(summary['contradictions'])}):")
        for c in summary["contradictions"]:
            print(f"  [{c['contradiction_id']}] {c['claim']}")
            print(f"      A: {c['source_a']}")
            print(f"      B: {c['source_b']}")
            print(f"      -> {c['resolution']}")
    sc = summary["self_correction"]
    if sc["disk_recheck_done"]:
        print(f"Self-correction: re-checked {sc['rechecked_names']} on disk")
    rep = summary["report"]
    if rep["path"]:
        lint = rep["lint"] or {}
        print(f"Report: {rep['path']}")
        print(f"  citation lint: {'CLEAN' if lint.get('clean') else 'FAILED'} "
              f"({len(lint.get('uncited_claims', []))} uncited)  narrated={rep['narrated']}")
    if summary["gaps"]:
        print("Gaps:", *summary["gaps"], sep="\n  - ")
    print(f"\nSummary: {summary['_summary_path']}")

    # Cross-source confirmed implant (Phase 3 regression).
    MEM = {"process_tree", "command_line", "injection", "network", "services"}
    DISK = {"disk_mft", "disk_shimcache", "disk_registry", "disk_evtx"}
    cross = []
    for f in summary["findings"]:
        if f["confidence"] != "confirmed":
            continue
        fams = {e.get("source_family") for e in f["evidence"] if e.get("source_family")}
        if fams & MEM and fams & DISK:
            cross.append(f)
    netscan_gap = any("netscan" in g for g in summary["gaps"])
    pz_pinned = summary["patient_zero_utc"] is not None
    tl_ok = summary["timeline_citations_resolve"]

    # Phase-5 acceptance: >=1 resolved contradiction; NO benign Windows file is
    # marked malware (nothing tagged benign_* is confirmed); self-correction ran.
    resolved_contradictions = [c for c in summary["contradictions"] if c.get("resolution")]
    benign_marked_malware = [
        f for f in summary["findings"]
        if f["confidence"] in ("confirmed", "likely")
        and ({"benign_binary_confirmed", "benign_allowlist"} & set(f.get("tags", [])))
    ]
    # Phase-6 acceptance: a host report rendered AND the citation linter is clean
    # (0 uncited claims).
    report_lint = (summary["report"]["lint"] or {})
    report_rendered = bool(summary["report"]["path"])
    report_clean = bool(report_lint.get("clean"))

    ok = (
        bool(cross) and cr["clean"] and netscan_gap and pz_pinned and tl_ok
        and bool(resolved_contradictions) and not benign_marked_malware
        and report_rendered and report_clean
    )
    print(
        f"ACCEPTANCE: {'PASS' if ok else 'FAIL'}  "
        f"(memory+disk confirmed: {len(cross)}, resolved_contradictions: {len(resolved_contradictions)}, "
        f"benign_marked_malware: {len(benign_marked_malware)}, "
        f"report_rendered: {report_rendered}, citation_lint_clean: {report_clean})"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

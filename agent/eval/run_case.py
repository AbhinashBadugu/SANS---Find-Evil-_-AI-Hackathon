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
from dfir_agent.nodes.cross_host import (  # noqa: E402
    HostBundle, correlate_cross_host, lint_cross_host, render_case_report,
)
from dfir_agent.scoring import load_provenance_index  # noqa: E402
from dfir_agent.rules.hash_correlation import findings_from_hash_groups  # noqa: E402
from dfir_agent.state import CaseState, Confidence  # noqa: E402

DEFAULT_CASE_ROOT = os.path.expanduser("~/Desktop/DFIR agent/Agent analysis")


def _patient_zero_ts(state: CaseState):
    return min((te.ts for te in state.timeline if "PATIENT-ZERO MARKER" in te.description), default=None)


def _bundle_path(case_root: str, case_id: str, host_id: str) -> Path:
    return Path(case_root) / "cases" / case_id / "hosts" / host_id / "agent" / "findings.json"


def _persist_bundle(case_root: str, case_id: str, bundle: HostBundle) -> None:
    """Cache a host's findings so cross-host correlation can re-run without
    re-analysing evidence (Phase 8 is seconds; the per-host pipeline is minutes)."""
    p = _bundle_path(case_root, case_id, bundle.host_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")


def _load_cached_bundles(case_root: str, case_id: str, manifest, only, ip_map) -> list[HostBundle]:
    bundles: list[HostBundle] = []
    for host_id in [h for h in manifest if (not only or h in only)]:
        p = _bundle_path(case_root, case_id, host_id)
        if not p.exists():
            print(f"    (no cached findings for {host_id}; run the full pipeline once first)", flush=True)
            continue
        b = HostBundle.model_validate_json(p.read_text(encoding="utf-8"))
        if not b.ip:
            b.ip = (ip_map or {}).get(host_id)
        bundles.append(b)
    return bundles


def _shared_binaries_by_hash(case_root: str, case_id: str) -> list:
    """Group every hashed file across hosts by sha256; return shared-binary findings
    (sha256 on >=2 hosts) from the per-host hash manifests file_detect wrote."""
    from collections import defaultdict
    case_dir = Path(case_root) / "cases" / case_id
    groups: dict[str, dict] = defaultdict(lambda: {"hosts": set(), "paths": [], "prov": [], "size": None})
    for manifest in sorted(case_dir.glob("hosts/*/hashes/hash_manifest.jsonl")):
        for line in manifest.open("r", encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            sha = (rec.get("hashes") or {}).get("sha256")
            if not sha:
                continue
            g = groups[sha]
            g["hosts"].add(rec.get("host_id"))
            g["paths"].append(rec.get("path"))
            g["prov"].append(rec.get("provenance_id"))
            g["size"] = rec.get("size")
    shared = [{"sha256": sha, "size": g["size"], "hosts": sorted(h for h in g["hosts"] if h),
               "paths": g["paths"], "provenance_ids": [p for p in g["prov"] if p]}
              for sha, g in groups.items() if len({h for h in g["hosts"] if h}) >= 2]
    return findings_from_hash_groups(shared)


def _emit_cross_host(case_id: str, case_root: str, bundles: list[HostBundle],
                     ip_map: dict[str, str]) -> dict:
    xh = correlate_cross_host(case_id, bundles, ip_map=ip_map or {})
    prov_index = load_provenance_index(case_root, case_id)
    lint = lint_cross_host(xh, prov_index)
    md = render_case_report(xh, bundles, prov_index)

    # Cross-host shared binaries (same sha256 on >=2 hosts) from the hash manifests.
    shared_bins = _shared_binaries_by_hash(case_root, case_id)
    if shared_bins:
        md += f"\n\n## Shared binaries across hosts by hash ({len(shared_bins)})\n\n"
        for f in shared_bins:
            md += f"- {f.title}  ·  {', '.join(e.provenance_id for e in f.evidence[:4])}\n"

    report_path = Path(case_root) / "cases" / case_id / "CASE_REPORT.md"
    report_path.write_text(md, encoding="utf-8")
    print(f"\n>>> CROSS-HOST: patient_zero={xh.case_patient_zero_host} "
          f"shared_implants={len(xh.shared_implants)} hops={len(xh.lateral_chain)} "
          f"lint_clean={lint['clean']} -> {report_path.name}", flush=True)
    return {
        "report_path": str(report_path),
        "lint_clean": lint["clean"],
        "uncited_claims": lint["uncited_claims"],
        "patient_zero_host": xh.case_patient_zero_host,
        "patient_zero_ts": xh.case_patient_zero_ts.isoformat() if xh.case_patient_zero_ts else None,
        "shared_implants": [
            {"key": s.key, "hosts": [p.host_id for p in s.hosts]} for s in xh.shared_implants
        ],
        "lateral_hops": len(xh.lateral_chain),
        "spread_edges": len(xh.spread_edges),
        "shared_binaries_by_hash": len(shared_bins),
        "gaps": xh.gaps,
    }


def _host_metrics(state: CaseState) -> dict:
    by = lambda c: [f for f in state.findings if f.confidence == c]  # noqa: E731
    pz = _patient_zero_ts(state)
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


async def _run(case_id: str, case_root: str, only: list[str] | None,
               ip_map: dict[str, str] | None = None) -> dict:
    manifest = load_or_build_manifest(case_root, case_id)
    hosts = [h for h in manifest if (not only or h in only)]
    results: dict[str, dict] = {}
    bundles: list[HostBundle] = []

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
                host = state.hosts.get(host_id) or manifest[host_id]
                bundle = HostBundle(
                    host_id=host_id, os=host.os, role=host.role,
                    ip=host.ip or (ip_map or {}).get(host_id),
                    findings=state.findings, timeline=state.timeline,
                    patient_zero=_patient_zero_ts(state),
                )
                bundles.append(bundle)
                _persist_bundle(case_root, case_id, bundle)  # cache for --cross-host-only
                m = results[host_id]
                print(f"    report={Path(m['report_path']).name if m['report_path'] else 'NONE'} "
                      f"lint_clean={m['lint_clean']} confirmed={m['confirmed']} "
                      f"lateral={m['lateral_movement_findings']} contradictions={m['contradictions']}",
                      flush=True)
            except Exception as e:  # noqa: BLE001 — one host must not abort the case
                results[host_id] = {"error": f"{type(e).__name__}: {e}"}
                print(f"    ERROR: {e}", flush=True)

    case_summary = {"case_id": case_id, "hosts": results}

    # --- Phase 8: cross-host correlation over the finished host bundles ---
    if bundles:
        case_summary["cross_host"] = _emit_cross_host(case_id, case_root, bundles, ip_map or {})

    out = Path(case_root) / "cases" / case_id / "case_summary.json"
    out.write_text(json.dumps(case_summary, indent=2), encoding="utf-8")
    case_summary["_path"] = str(out)
    return case_summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the DFIR agent across all hosts + cross-host correlation (Phase 7/8).")
    ap.add_argument("--case", default="srl2015")
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    ap.add_argument("--only", nargs="*", help="optional subset of host_ids")
    ap.add_argument("--host-ip", nargs="*", default=[],
                    help="topology facts to attribute lateral hops, e.g. --host-ip xp-tdungan=10.3.58.7")
    ap.add_argument("--cross-host-only", action="store_true",
                    help="skip per-host analysis; rebuild Phase 8 from cached findings.json (seconds)")
    args = ap.parse_args()

    ip_map: dict[str, str] = {}
    for pair in args.host_ip:
        if "=" in pair:
            host, ip = pair.split("=", 1)
            # map BOTH directions usable downstream: ip->host for hop attribution,
            # and stash host->ip on the bundle via the same dict keyed by host_id.
            ip_map[ip.strip()] = host.strip()
            ip_map[host.strip()] = ip.strip()

    if args.cross_host_only:
        manifest = load_or_build_manifest(args.case_root, args.case)
        bundles = _load_cached_bundles(args.case_root, args.case, manifest, args.only, ip_map)
        if not bundles:
            print("No cached findings found. Run the full pipeline once (without "
                  "--cross-host-only) to populate hosts/<host>/agent/findings.json.")
            return 1
        xh = _emit_cross_host(args.case, args.case_root, bundles, ip_map)
        ok = xh["lint_clean"] and (len(xh["shared_implants"]) > 0 or xh["lateral_hops"] > 0)
        print(f"\nACCEPTANCE: {'PASS' if ok else 'FAIL'}  (cross_host lint_clean={xh['lint_clean']}, "
              f"shared_implants={len(xh['shared_implants'])}, lateral_hops={xh['lateral_hops']})")
        return 0 if ok else 1

    cs = asyncio.run(_run(args.case, args.case_root, args.only, ip_map=ip_map))
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

    xh = cs.get("cross_host")
    xh_ok = False
    if xh:
        si = xh["shared_implants"]
        print("\n=== CROSS-HOST (Phase 8) ===")
        print(f"  patient zero:    {xh['patient_zero_host']} @ {xh['patient_zero_ts'] or '-'}")
        print(f"  shared implants: {len(si)}  " + ", ".join(f"{s['key']}×{len(s['hosts'])}" for s in si))
        print(f"  lateral hops:    {xh['lateral_hops']}   spread edges: {xh['spread_edges']}")
        print(f"  lint_clean:      {xh['lint_clean']}   report: {Path(xh['report_path']).name}")
        xh_ok = xh["lint_clean"] and (len(si) > 0 or xh["lateral_hops"] > 0)

    ok = reports == len([h for h in hosts]) and all_clean and dc_lateral > 0 and xh_ok
    print(f"\nACCEPTANCE: {'PASS' if ok else 'FAIL'}  "
          f"(reports: {reports}/{len(hosts)}, all_lints_clean: {all_clean}, "
          f"dc_lateral_movement: {dc_lateral}, cross_host_ok: {xh_ok})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

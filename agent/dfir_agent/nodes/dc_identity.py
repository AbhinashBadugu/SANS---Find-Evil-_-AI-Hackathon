"""DC / Identity node (Phase 7) — runs only on domain-controller hosts.

It reads the Security event log the disk node already parsed (parse_evtx -> evtx.csv)
and applies the deterministic DC ruleset (service installs, RDP logons, explicit-
credential logons) to surface lateral-movement and admin-access events. Benign
service installs (IR tooling, USB-over-Ethernet) are classified out and recorded
as notes, never flagged as malware.
"""

from __future__ import annotations

from ..rules.dc_events import analyze_dc_events
from ..state import CaseState, ToolResultStatus
from . import NodeContext


def _evtx_csv(state: CaseState) -> tuple[str, str] | None:
    for tr in reversed(state.tool_results):
        if tr.tool == "parse_evtx" and tr.status == ToolResultStatus.success and tr.output_paths:
            csv = next((p for p in tr.output_paths if str(p).endswith("evtx.csv")), tr.output_paths[0])
            return str(csv), tr.provenance_id
    return None


async def dc_identity(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    state.completed_steps.append("dc_identity")

    info = _evtx_csv(state)
    if not info:
        state.gaps.append(f"{host.host_id}: no parsed Security log (parse_evtx); DC analysis skipped.")
        ctx.decisions.record(
            agent_name="dc_identity", step="dc_events", inputs_summary="no evtx.csv",
            action="skipped", rationale="Cannot analyse DC events without a parsed Security log.",
        )
        return state

    evtx_csv, prov = info
    findings, notes = analyze_dc_events(
        evtx_csv, host_id=host.host_id, provenance_id=prov, next_id=state.next_finding_id,
    )
    state.findings.extend(findings)
    for n in notes:
        state.gaps.append(f"{host.host_id}: DC note — {n}")

    lateral = sum(1 for f in findings if f.category == "lateral_movement")
    ctx.decisions.record(
        agent_name="dc_identity", step="dc_events",
        inputs_summary=f"parsed Security log {evtx_csv}",
        action=f"{len(findings)} DC finding(s) ({lateral} lateral-movement), {len(notes)} note(s)",
        rationale=(
            "Selective DC ruleset over 7045/4624(Type10)/4648; benign service installs "
            "classified out, not flagged. Every finding cites an EventRecordId."
        ),
    )
    return state

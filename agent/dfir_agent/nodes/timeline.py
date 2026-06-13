"""Timeline node (Phase 4).

Builds a Plaso super-timeline from the carved-artifacts dir, then slices it around
the implant to pin patient-zero timing. It is correlation-aware: the keyword/dir it
anchors on is derived from the suspicious image paths already surfaced — it does
not hunt blindly.

Output: TimelineEvent objects (with provenance citations) for the implant's true
on-disk creation (FN), its config drop, and the SI timestomp — plus the earliest
FN-creation as the host's patient-zero marker.
"""

from __future__ import annotations

from datetime import datetime

from ..rules.timeline_rules import extract_implant_timeline
from ..state import CaseState, ToolResult, ToolResultStatus
from . import NodeContext


async def _call(state: CaseState, ctx: NodeContext, host, tool: str, **kw) -> tuple[ToolResult, dict]:
    resp = await ctx.client.call(tool, case_id=state.case_id, host_id=host.host_id, **kw)
    status = ToolResultStatus(resp.get("status", "failed"))
    out = resp.get("output_paths") or [p for p in [
        resp.get("plaso_path"), resp.get("filtered_csv_path"), resp.get("full_csv_path"),
    ] if p]
    tr = ToolResult(
        tool=tool, status=status, provenance_id=resp.get("provenance_id", "UNKNOWN"),
        host_id=host.host_id, args=kw, output_paths=out, summary=tool, error=resp.get("error"),
    )
    state.add_tool_result(tr)
    if status != ToolResultStatus.success:
        state.gaps.append(f"{host.host_id}: {tool} did not succeed ({(tr.error or '?')[:100]}) ({tr.provenance_id}).")
    ctx.decisions.record(
        agent_name="timeline", step=f"call:{tool}",
        inputs_summary=str({k: str(v)[:60] for k, v in kw.items()}),
        action=f"{tool} -> {status.value} ({tr.provenance_id})",
        rationale="Read-only timeline step; failures logged as gaps, never guessed around.",
    )
    return tr, resp


# Patient-zero is the implant DROP/first execution — anchor it only on findings
# that represent the implant itself, never on downstream artifacts whose own
# timestamps mislead: an `at`-job's MFT entry carries the OS-install date, and a
# staged exfil archive is late-stage. Anchoring on those mis-pins patient zero.
_NON_ANCHOR_RULES = {"persistence.at_job"}
_NON_ANCHOR_CATEGORIES = {"exfil", "c2_connection"}


def _anchor_dirs(state: CaseState) -> dict[str, str]:
    """{dir_basename: '\\dir\\' fragment} for each implant image path's parent dir."""
    anchors: dict[str, str] = {}
    for f in state.findings:
        if f.category in _NON_ANCHOR_CATEGORIES or f.rule in _NON_ANCHOR_RULES:
            continue  # downstream artifact — not the initial compromise
        for p in f.paths:
            parts = p.rstrip("\\").split("\\")
            if len(parts) >= 2 and parts[-2]:
                d = parts[-2]
                anchors.setdefault(d, f"\\{d}\\")
    return anchors


async def timeline(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    if not host.extracted_dir:
        state.gaps.append(f"{host.host_id}: no extracted-artifacts dir; timeline skipped.")
        state.completed_steps.append("timeline")
        return state

    anchors = _anchor_dirs(state)
    if not anchors:
        state.gaps.append(f"{host.host_id}: no implant path to anchor the timeline; skipped slicing.")
        state.completed_steps.append("timeline")
        return state

    gen_tr, gen_resp = await _call(state, ctx, host, "generate_timeline", source_path=host.extracted_dir)
    plaso = gen_resp.get("plaso_path")
    if gen_tr.status != ToolResultStatus.success or not plaso:
        state.gaps.append(f"{host.host_id}: timeline generation failed; no events.")
        state.completed_steps.append("timeline")
        return state

    pzs: list[datetime] = []
    total_events = 0
    for dirname, frag in anchors.items():
        flt_tr, flt_resp = await _call(
            state, ctx, host, "filter_timeline",
            plaso_path=plaso, label=f"tl_{dirname}", keyword=dirname,
        )
        if flt_tr.status != ToolResultStatus.success:
            continue
        filtered = flt_resp.get("filtered_csv_path") or flt_resp.get("full_csv_path")
        if not filtered:
            continue
        events, pz = extract_implant_timeline(
            filtered, {frag.lower()}, host_id=host.host_id,
            provenance_id=flt_tr.provenance_id,
        )
        state.timeline.extend(events)
        total_events += len(events)
        if pz:
            pzs.append(pz)

    patient_zero = min(pzs) if pzs else None
    if patient_zero is None:
        state.gaps.append(f"{host.host_id}: timeline produced no implant FN-creation event; patient-zero unpinned.")
    state.completed_steps.append("timeline")
    ctx.decisions.record(
        agent_name="timeline", step="pin_patient_zero",
        inputs_summary=f"anchors={list(anchors)}",
        action=(
            f"{total_events} timeline event(s); patient-zero "
            f"{patient_zero.isoformat() if patient_zero else 'UNPINNED'}"
        ),
        rationale=(
            "Prefer $FILE_NAME creation (cannot be timestomped) to pin the real drop time; "
            "the backdated $STANDARD_INFORMATION is emitted as a timestomp event, not trusted."
        ),
    )
    return state

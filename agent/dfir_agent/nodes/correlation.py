"""Correlation node.

Phase 3 scope: fuse findings across sources by shared entity/path (union-find),
recompute confidence from the count of distinct evidence families, and apply the
benign allowlist. The full self-correction loop + contradiction detection land in
Phase 5; the deterministic merge that makes the implant multi-source lives here.
"""

from __future__ import annotations

from ..rules.benign_allowlist import is_benign_location
from ..scoring import STRONG_FAMILIES, correlate_findings, families_of
from ..state import CaseState, Confidence
from . import NodeContext


def _apply_benign_guard(findings, ctx: NodeContext) -> None:
    for f in findings:
        if families_of(f) & STRONG_FAMILIES:
            continue  # behavioural evidence overrides a benign location
        if any(is_benign_location(p) for p in f.paths):
            f.confidence = Confidence.false_positive
            f.tags = sorted(set(f.tags) | {"benign_allowlist"})
            ctx.decisions.record(
                agent_name="correlation", step="benign_allowlist",
                inputs_summary=str(f.paths), action=f"demoted {f.finding_id} to false_positive",
                rationale="Standard signed Windows location with no behavioural corroboration.",
            )


async def correlation(state: CaseState, ctx: NodeContext) -> CaseState:
    before = len(state.findings)
    merged = correlate_findings(state.findings)
    _apply_benign_guard(merged, ctx)
    state.findings = merged
    state.completed_steps.append("correlation")

    confirmed = sum(1 for f in merged if f.confidence == Confidence.confirmed)
    multi_source = sum(1 for f in merged if f.source_count >= 2)
    ctx.decisions.record(
        agent_name="correlation", step="cross_source_merge",
        inputs_summary=f"{before} findings in",
        action=f"{len(merged)} findings out ({confirmed} confirmed, {multi_source} multi-source)",
        rationale=(
            "Union-find over entity_key and path fuses memory + disk evidence; "
            "confidence is recomputed from distinct families (>=2 -> confirmed)."
        ),
    )
    return state

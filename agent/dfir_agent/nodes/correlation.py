"""Correlation + self-correction node (Phase 5).

Responsibilities, all deterministic:
  1. Fuse findings across sources by shared entity/path (union-find) and recompute
     confidence from distinct evidence families.
  2. Apply the benign allowlist (a system file in a signed location, with no
     behavioural corroboration, is not malware).
  3. Detect contradictions (e.g. timestomp: SI vs FN creation) and resolve them.
  4. Drive the self-correction loop: on the first pass, if a suspicious memory
     lead names a binary the disk pass never verified, request a disk re-check
     (routed by the graph). On the second pass, simply re-score with the new
     evidence. The loop runs at most once (state flags) under max_iterations.
"""

from __future__ import annotations

from ..rules.contradiction import detect_timestomp_contradictions
from ..scoring import correlate_findings
from ..state import CaseState, Confidence
from ..verification import adversarial_verify
from . import NodeContext


def _needs_recheck(findings) -> set[str]:
    """Names of suspicious memory leads that disk has not yet corroborated."""
    names: set[str] = set()
    for f in findings:
        if f.category != "hidden_process" or f.confidence != Confidence.suspicious:
            continue
        if "disk_corroborated" in f.tags or "benign_binary_confirmed" in f.tags or "not_on_disk" in f.tags:
            continue
        # the process image name was tagged by the hidden-process rule
        for t in f.tags:
            if t.lower().endswith(".exe"):
                names.add(t)
    return names


async def correlation(state: CaseState, ctx: NodeContext) -> CaseState:
    before = len(state.findings)
    merged = correlate_findings(state.findings)
    # Adversarial verification: every finding faces a refutation panel before it
    # stands (subsumes the old benign-allowlist guard) and records its trial.
    adversarial_verify(merged, ctx)
    state.findings = merged

    # Contradiction detection (idempotent: only add ones we haven't recorded).
    existing = {(c.host_id, c.claim) for c in state.contradictions}
    for c in detect_timestomp_contradictions(
        merged, host_id=state.current_host or "", next_id=state.next_contradiction_id
    ):
        if (c.host_id, c.claim) not in existing:
            state.contradictions.append(c)

    if "correlation" not in state.completed_steps:
        state.completed_steps.append("correlation")

    host = state.hosts.get(state.current_host or "")
    if not state.self_correction_attempted:
        state.self_correction_attempted = True
        names = _needs_recheck(merged) if (host and host.disk_image) else set()
        if names:
            state.recheck_names = sorted(names)
            state.needs_disk_recheck = True
            ctx.decisions.record(
                agent_name="correlation", step="self_correction:request",
                inputs_summary=f"{len(merged)} findings",
                action=f"requesting disk re-check of unverified leads: {state.recheck_names}",
                rationale="A suspicious memory lead names a binary disk never checked — verify before judging.",
            )
    else:
        state.recorrelated = True

    confirmed = sum(1 for f in merged if f.confidence == Confidence.confirmed)
    multi_source = sum(1 for f in merged if f.source_count >= 2)
    ctx.decisions.record(
        agent_name="correlation", step="cross_source_merge",
        inputs_summary=f"{before} findings in",
        action=(
            f"{len(merged)} findings out ({confirmed} confirmed, {multi_source} multi-source), "
            f"{len(state.contradictions)} contradiction(s)"
        ),
        rationale="Union-find fuses sources; confidence recomputed from distinct families.",
    )
    return state

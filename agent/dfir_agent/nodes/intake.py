"""Evidence Intake node — fingerprint the evidence before touching it.

Phase 1 scope: SHA-256 the host's memory image via `hash_evidence`. The hash
itself lands in the provenance logbook; downstream findings can cite that line to
prove the image they were derived from never changed.
"""

from __future__ import annotations

from ..state import CaseState, ToolResult, ToolResultStatus
from . import NodeContext


async def intake(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    if not host.memory_image:
        state.gaps.append(f"{host.host_id}: no memory image in manifest; skipped hashing.")
        state.completed_steps.append("intake")
        ctx.decisions.record(
            agent_name="intake",
            step="hash_evidence",
            inputs_summary=f"host={host.host_id}",
            action="skipped (no memory image)",
            rationale="Cannot hash what the manifest does not list; recorded as a gap.",
        )
        return state

    resp = await ctx.client.call(
        "hash_evidence",
        case_id=state.case_id,
        host_id=host.host_id,
        evidence_path=host.memory_image,
    )
    status = ToolResultStatus(resp.get("status", "failed"))
    tr = ToolResult(
        tool="hash_evidence",
        status=status,
        provenance_id=resp.get("provenance_id", "UNKNOWN"),
        host_id=host.host_id,
        args={"evidence_path": host.memory_image},
        output_paths=[p for p in [resp.get("hash_output_path")] if p],
        summary=(resp.get("sha256") or "")[:16] + ("…" if resp.get("sha256") else ""),
        error=resp.get("error"),
    )
    state.add_tool_result(tr)
    state.completed_steps.append("intake")
    ctx.decisions.record(
        agent_name="intake",
        step="hash_evidence",
        inputs_summary=f"memory_image={host.memory_image}",
        action=f"hash_evidence -> {status.value} ({tr.provenance_id})",
        rationale="Chain of custody: fingerprint the image so every later fact ties to a sealed input.",
    )
    return state

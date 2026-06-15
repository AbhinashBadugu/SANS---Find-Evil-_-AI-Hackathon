"""Orchestrator node — loads the manifest and selects exactly one host.

OS-family dispatch happens AFTER this node (see graph.run_case -> select_analyzer):
host selection here is OS-agnostic. `route_next` below is the WINDOWS sub-route
(intake -> memory -> disk -> timeline -> [dc_identity] -> correlation -> report),
driven by WindowsAnalyzer; it is keyed off `completed_steps` and host role.
"""

from __future__ import annotations

from ..manifest import load_or_build_manifest
from ..manifest_intake import (
    build_or_load_manifest,
    host_capabilities,
    manifest_to_runtime_hosts,
    select_host,
)
from ..state import CaseState, HostRole
from . import NodeContext


async def orchestrator_select_host(
    state: CaseState, ctx: NodeContext, target_host: str | None = None
) -> CaseState:
    # Universal Case Manifest path (Step 3): case-agnostic discovery from an
    # evidence folder. Opt-in via state.evidence_root; without it the original
    # Phase-1 behaviour below is untouched.
    if state.evidence_root:
        return await _select_via_manifest(state, ctx, target_host)

    state.hosts = load_or_build_manifest(state.case_root, state.case_id)
    if not state.hosts:
        raise RuntimeError(f"No hosts found for case {state.case_id!r} (empty manifest + no provenance).")

    if target_host:
        if target_host not in state.hosts:
            raise RuntimeError(f"Requested host {target_host!r} not in case. Have: {sorted(state.hosts)}")
        chosen = target_host
    else:
        # Default: prefer an XP host (the vertical-slice target), else first host.
        chosen = next(
            (h for h in state.hosts if "xp" in h.lower()),
            sorted(state.hosts)[0],
        )

    state.current_host = chosen
    host = state.hosts[chosen]
    state.completed_steps.append("orchestrator:select_host")
    ctx.decisions.record(
        agent_name="orchestrator",
        step="select_host",
        inputs_summary=f"{len(state.hosts)} hosts in manifest; target={target_host or 'auto'}",
        action=f"selected host {chosen} (os={host.os}, role={host.role.value})",
        rationale=(
            "Vertical slice runs the XP host first (the implant is detectable from "
            "memory alone)." if "xp" in chosen.lower() else "First host in case order."
        ),
    )
    return state


async def _select_via_manifest(
    state: CaseState, ctx: NodeContext, target_host: str | None
) -> CaseState:
    """Discovery + host selection driven by the Universal Case Manifest Builder."""
    manifest, loaded = build_or_load_manifest(state.case_root, state.case_id, state.evidence_root)
    state.hosts = manifest_to_runtime_hosts(manifest)
    state.host_capabilities = host_capabilities(manifest)

    fam_counts: dict[str, int] = {}
    for mh in manifest.hosts:
        fam_counts[mh.os_family.value] = fam_counts.get(mh.os_family.value, 0) + 1

    ctx.decisions.record(
        agent_name="orchestrator",
        step="manifest",
        inputs_summary=f"evidence_root={state.evidence_root}",
        action=("loaded existing case_manifest.json"
                if loaded else f"generated case_manifest.json by scanning {state.evidence_root}"),
        rationale="Universal Case Manifest Builder — case-agnostic discovery (no hardcoded paths or host names).",
    )
    ctx.decisions.record(
        agent_name="orchestrator",
        step="discover_hosts",
        inputs_summary=f"families={fam_counts}; unassigned={len(manifest.unassigned_evidence)}",
        action=f"discovered {len(state.hosts)} host(s): {sorted(state.hosts)}",
        rationale="Hosts grouped from evidence folder layout + filename classification.",
    )

    host_id, reason = select_host(manifest, target_host)
    state.completed_steps.append("orchestrator:select_host")

    if host_id is None:
        # Only happens when the manifest has no hosts at all — clean stop, no crash.
        state.gaps.append(reason)
        ctx.decisions.record(
            agent_name="orchestrator",
            step="select_host",
            inputs_summary=f"{len(state.hosts)} hosts; target={target_host or 'auto'}",
            action="no host selected (empty manifest)",
            rationale=reason,
        )
        return state

    state.current_host = host_id
    host = state.hosts[host_id]
    ctx.decisions.record(
        agent_name="orchestrator",
        step="select_host",
        inputs_summary=f"{len(state.hosts)} hosts; target={target_host or 'auto'}",
        action=(f"selected host {host_id} (os={host.os}, role={host.role.value}, "
                f"memory_image={'present' if host.memory_image else 'none'})"),
        rationale=reason,
    )
    caps = state.host_capabilities.get(host_id)
    if caps is not None:
        present = [k.replace("has_", "") for k, v in caps.model_dump().items() if v]
        ctx.decisions.record(
            agent_name="orchestrator",
            step="host_capabilities",
            inputs_summary=f"host={host_id}",
            action=f"capabilities: {', '.join(present) or 'none'}",
            rationale="Records which analytic angles this host's evidence supports.",
        )
    return state


def route_next(state: CaseState) -> str:
    """Conditional router. Returns the name of the next node, or 'END'."""
    done = set(state.completed_steps)
    if "orchestrator:select_host" not in done:
        return "orchestrator"
    if state.current_host is None:
        return "END"  # orchestrator ran but found no host the active phase supports
    if "intake" not in done:
        return "intake"
    if "memory" not in done:
        return "memory"
    if "disk" not in done:
        return "disk"
    if "timeline" not in done:
        return "timeline"
    # Phase 7 will slot the DC/identity node here.
    host = state.hosts.get(state.current_host or "")
    if host and host.role == HostRole.dc and "dc_identity" not in done:
        return "dc_identity"  # not yet implemented (Phase 7) — router is ready for it
    if "deep_scan" not in done:
        return "deep_scan"  # expanded detection: credential access, lateral graph, self-correction
    if "correlation" not in done:
        return "correlation"  # first pass: fuse, score, detect contradictions, maybe request re-check
    # Self-correction loop (capped to one round): correlation -> disk_recheck -> correlation.
    if state.needs_disk_recheck and not state.disk_recheck_done:
        return "disk_recheck"
    if state.disk_recheck_done and not state.recorrelated:
        return "correlation"  # second pass: re-score with the disk re-check evidence
    if "report" not in done:
        return "report"
    return "END"

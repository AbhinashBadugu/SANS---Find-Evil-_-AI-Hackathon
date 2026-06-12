"""Orchestrator node — loads the manifest, selects the host, routes the flow.

In Phase 1 the route is fixed (intake -> memory). The router function is written
so later phases can extend it (disk -> timeline -> [dc_identity] -> correlation
-> report) off `completed_steps` and host role without changing node code.
"""

from __future__ import annotations

from ..manifest import load_or_build_manifest
from ..state import CaseState, HostRole
from . import NodeContext


async def orchestrator_select_host(
    state: CaseState, ctx: NodeContext, target_host: str | None = None
) -> CaseState:
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


def route_next(state: CaseState) -> str:
    """Conditional router. Returns the name of the next node, or 'END'."""
    done = set(state.completed_steps)
    if "orchestrator:select_host" not in done:
        return "orchestrator"
    if "intake" not in done:
        return "intake"
    if "memory" not in done:
        return "memory"
    # Phases 3+ extend here: disk -> timeline -> [dc_identity] -> correlation -> report.
    host = state.hosts.get(state.current_host or "")
    if host and host.role == HostRole.dc and "dc_identity" not in done:
        return "dc_identity"  # not yet implemented (Phase 7) — router is ready for it
    return "END"

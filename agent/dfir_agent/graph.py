"""Graph runner.

A minimal, deterministic driver that threads `CaseState` through nodes using the
orchestrator's `route_next` router. The node contract (async `state, ctx ->
state`) and the explicit router mirror LangGraph exactly, so this can be swapped
for a compiled `StateGraph` once `langgraph` is installed (operator, online) with
no change to node code.

A hard `max_iterations` cap prevents any self-correction loop from spinning.
"""

from __future__ import annotations

from .nodes import NodeContext
from .nodes.correlation import correlation
from .nodes.disk import disk
from .nodes.intake import intake
from .nodes.memory import memory
from .nodes.orchestrator import orchestrator_select_host, route_next
from .nodes.timeline import timeline
from .state import CaseState

_TERMINAL = {"END", "dc_identity"}  # dc_identity not implemented until Phase 7


async def run_case(state: CaseState, ctx: NodeContext, target_host: str | None = None) -> CaseState:
    """Run the flow: orchestrator -> intake -> memory -> disk -> correlation -> END."""
    while state.iteration < state.max_iterations:
        state.iteration += 1
        nxt = route_next(state)
        if nxt == "orchestrator":
            state = await orchestrator_select_host(state, ctx, target_host=target_host)
        elif nxt == "intake":
            state = await intake(state, ctx)
        elif nxt == "memory":
            state = await memory(state, ctx)
        elif nxt == "disk":
            state = await disk(state, ctx)
        elif nxt == "timeline":
            state = await timeline(state, ctx)
        elif nxt == "correlation":
            state = await correlation(state, ctx)
        elif nxt in _TERMINAL:
            break
        else:  # pragma: no cover - guard for an unrouted node name
            state.gaps.append(f"router returned unknown node {nxt!r}; stopping.")
            break
    return state

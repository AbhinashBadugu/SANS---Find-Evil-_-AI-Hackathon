"""Graph runner — OS-family matched dispatch.

Two deterministic steps:
  1. orchestrator_select_host  — discover the case, select exactly one host.
  2. select_analyzer(os_family) — route that host to EXACTLY ONE OS-family analyzer.

WindowsAnalyzer wraps the existing memory/disk/timeline/correlation pipeline
unchanged (it owns `route_next` + the node functions). Linux/macOS analyzers are
detected-but-not-implemented stubs; an undetermined OS goes to UnknownEvidenceHandler.
No analyzer can run another family's tools, because only one is ever instantiated.
"""

from __future__ import annotations

from .analyzers import select_analyzer
from .manifest_intake import host_os_family
from .nodes import NodeContext
from .nodes.orchestrator import orchestrator_select_host
from .state import CaseState


async def run_case(state: CaseState, ctx: NodeContext, target_host: str | None = None) -> CaseState:
    """orchestrator (select host) -> select_analyzer(os_family) -> analyzer.analyze()."""
    state = await orchestrator_select_host(state, ctx, target_host=target_host)
    if not state.current_host:
        return state  # empty case / no host discovered

    analyzer = select_analyzer(host_os_family(state.hosts[state.current_host]))
    return await analyzer.analyze(state, ctx)

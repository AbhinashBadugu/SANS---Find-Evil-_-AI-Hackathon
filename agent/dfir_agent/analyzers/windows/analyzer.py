"""WindowsAnalyzer — wraps the EXISTING Windows pipeline unchanged.

Reuses the deterministic router (`route_next`) and the same node functions
(intake -> memory -> disk -> timeline -> [dc_identity] -> correlation <->
disk_recheck -> report). The orchestrator has already selected the host, so the
router proceeds straight to intake. No node behaviour is modified here.
"""

from __future__ import annotations

from ...nodes import NodeContext
from ...nodes.correlation import correlation
from ...nodes.dc_identity import dc_identity
from ...nodes.disk import disk
from ...nodes.disk_recheck import disk_recheck
from ...nodes.deep_scan import deep_scan
from ...nodes.intake import intake
from ...nodes.memory import memory
from ...nodes.orchestrator import route_next
from ...nodes.report import report
from ...nodes.timeline import timeline
from ...state import AnalyzerStatus, CaseState, OSFamily
from ..base import Analyzer
from .modules import CAP_MAP, SUPPORTED, WRAPPED


class WindowsAnalyzer(Analyzer):
    os_family = OSFamily.windows
    name = "WindowsAnalyzer"
    implemented = True
    supported_artifacts = SUPPORTED
    CAP_MAP = CAP_MAP
    WRAPPED = WRAPPED

    async def analyze(self, state: CaseState, ctx: NodeContext) -> CaseState:
        self._record(
            state, ctx, AnalyzerStatus.implemented,
            "Windows evidence — running the memory/disk/timeline/correlation pipeline",
        )
        # The existing route, byte-for-byte. orchestrator:select_host is already
        # complete, so route_next advances to intake on the first call.
        while state.iteration < state.max_iterations:
            state.iteration += 1
            nxt = route_next(state)
            if nxt == "intake":
                state = await intake(state, ctx)
            elif nxt == "memory":
                state = await memory(state, ctx)
            elif nxt == "disk":
                state = await disk(state, ctx)
            elif nxt == "timeline":
                state = await timeline(state, ctx)
            elif nxt == "deep_scan":
                state = await deep_scan(state, ctx)
            elif nxt == "dc_identity":
                state = await dc_identity(state, ctx)
            elif nxt == "disk_recheck":
                state = await disk_recheck(state, ctx)
            elif nxt == "correlation":
                state = await correlation(state, ctx)
            elif nxt == "report":
                state = await report(state, ctx)
            elif nxt == "END":
                break
            elif nxt == "orchestrator":  # pragma: no cover - host already selected upstream
                state.gaps.append("WindowsAnalyzer: unexpected re-entry to orchestrator; stopping.")
                break
            else:  # pragma: no cover - guard for an unrouted node name
                state.gaps.append(f"router returned unknown node {nxt!r}; stopping.")
                break
        return state

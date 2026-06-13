"""UnknownEvidenceHandler — OS family could not be determined.

Runs no OS-specific analyzers; signals that classification must improve first.
"""

from __future__ import annotations

from ..nodes import NodeContext
from ..state import AnalyzerStatus, CaseState, OSFamily
from .base import Analyzer


class UnknownEvidenceHandler(Analyzer):
    os_family = OSFamily.unknown
    name = "UnknownEvidenceHandler"
    implemented = False

    async def analyze(self, state: CaseState, ctx: NodeContext) -> CaseState:
        self._record(
            state, ctx, AnalyzerStatus.unknown_evidence,
            "OS family unknown; improve classification before analysis",
        )
        return state

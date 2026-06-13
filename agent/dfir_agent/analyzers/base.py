"""OS/device-family analyzer base + shared not-implemented stub.

An Analyzer is the single unit the router dispatches to once a host's evidence
family is known. Each analyzer is scoped to ONE family and may only drive that
family's tools — the registry guarantees exactly one is selected per host.

Every analyzer exposes a `build_capability_report()` that returns an honest
ArtifactResult for EACH artifact category it supports: present_and_parsed (a
wrapper exists), present_but_wrapper_missing (architecture supports it but no
wrapper yet), or not_present. It never claims analysis it did not perform.
"""

from __future__ import annotations

import abc

from ..nodes import NodeContext
from ..state import (
    AnalyzerOutcome,
    AnalyzerStatus,
    ArtifactParseStatus,
    ArtifactResult,
    CaseState,
    CoverageReport,
    EvidenceCapability,
    EvidenceType,
    OSFamily,
)

_WRAPPER_MISSING_REASON = "Architecture supports this artifact; MCP wrapper is not implemented yet."


class Analyzer(abc.ABC):
    os_family: OSFamily
    name: str
    implemented: bool

    # Filled by subclasses (declarative — see each family's modules.py):
    supported_artifacts: list[EvidenceType] = []
    CAP_MAP: dict[EvidenceType, str] = {}        # artifact -> EvidenceCapability flag
    WRAPPED: dict[EvidenceType, str] = {}        # artifact -> the MCP wrapper that parses it (if any)

    @property
    def evidence_family(self) -> OSFamily:  # alias the spec uses
        return self.os_family

    @abc.abstractmethod
    async def analyze(self, state: CaseState, ctx: NodeContext) -> CaseState:
        ...

    # ----- capability / coverage reporting (no tools; honest statuses) ----- #
    def artifact_results(
        self, host_id: str | None, caps: EvidenceCapability
    ) -> list[ArtifactResult]:
        out: list[ArtifactResult] = []
        for art in self.supported_artifacts:
            flag = self.CAP_MAP.get(art)
            present = bool(getattr(caps, flag, False)) if flag else False
            if not present:
                status, reason, wrapper = (
                    ArtifactParseStatus.not_present,
                    "Artifact not present in the provided evidence.",
                    None,
                )
            elif art in self.WRAPPED:
                status, reason, wrapper = ArtifactParseStatus.present_and_parsed, None, self.WRAPPED[art]
            else:
                status, reason, wrapper = ArtifactParseStatus.present_but_wrapper_missing, _WRAPPER_MISSING_REASON, None
            out.append(ArtifactResult(
                artifact_type=art, os_family=self.os_family, host_id=host_id,
                status=status, parser_or_wrapper=wrapper, reason=reason,
            ))
        return out

    def build_capability_report(self, state: CaseState, host_id: str | None = None) -> CoverageReport:
        host_id = host_id or state.current_host or ""
        caps = state.host_capabilities.get(host_id) or EvidenceCapability()
        results = self.artifact_results(host_id, caps)
        present = [r.artifact_type for r in results
                   if r.status in (ArtifactParseStatus.present_and_parsed,
                                   ArtifactParseStatus.present_but_wrapper_missing)]
        return CoverageReport(
            case_id=state.case_id, host_id=host_id, os_family=self.os_family, capabilities=caps,
            artifacts_present=present,
            artifacts_parsed=[r.artifact_type for r in results if r.status == ArtifactParseStatus.present_and_parsed],
            artifacts_missing=[r.artifact_type for r in results if r.status == ArtifactParseStatus.not_present],
            artifacts_not_collected=[r.artifact_type for r in results if r.status == ArtifactParseStatus.not_collected],
            wrappers_missing=[r.artifact_type for r in results
                              if r.status == ArtifactParseStatus.present_but_wrapper_missing],
            analyzer_not_implemented=not self.implemented,
        )

    def _record(
        self, state: CaseState, ctx: NodeContext, status: AnalyzerStatus, reason: str | None = None
    ) -> AnalyzerOutcome:
        """Set state.analyzer_outcome (with the coverage report) and log the routing
        decision (analyzer, os_family, status, reason)."""
        outcome = AnalyzerOutcome(
            os_family=self.os_family, analyzer_name=self.name, status=status, reason=reason,
            artifact_results=self.artifact_results(
                state.current_host, state.host_capabilities.get(state.current_host or "") or EvidenceCapability()),
            evidence_capabilities=state.host_capabilities.get(state.current_host or ""),
        )
        state.analyzer_outcome = outcome
        ctx.decisions.record(
            agent_name="router",
            step="select_analyzer",
            inputs_summary=f"os_family={self.os_family.value}",
            action=f"routed to {self.name} (os_family={self.os_family.value}, status={status.value})",
            rationale=reason or "Evidence-family matched analyzer; exactly one selected.",
        )
        return outcome


class NotImplementedAnalyzer(Analyzer):
    """Shared stub: detect the family, record the outcome + coverage, run NO tools."""

    implemented = False
    reason = "analyzer not implemented yet"

    async def analyze(self, state: CaseState, ctx: NodeContext) -> CaseState:
        self._record(state, ctx, AnalyzerStatus.detected_but_not_implemented, self.reason)
        return state

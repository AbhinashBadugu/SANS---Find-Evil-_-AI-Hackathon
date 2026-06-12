"""Typed contracts threaded through the agent graph (playbook §5).

Hardening baked in here, not left to convention:
  * Confidence is an Enum with a strict order.
  * A Finding above `suspicious` MUST carry at least one EvidenceReference that
    has a provenance_id (validator rejects empty evidence) — a claim with no
    resolvable citation cannot be `confirmed` or `likely`.
  * EvidenceReference carries provenance_id AND record_id, so a citation points
    to a specific line (MFT row / event record / process PID), not just a file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class ToolResultStatus(str, Enum):
    success = "success"
    failed = "failed"
    refused = "refused"


class Confidence(str, Enum):
    confirmed = "confirmed"
    likely = "likely"
    suspicious = "suspicious"
    false_positive = "false_positive"


# Strict ordering used by the deterministic scorer and the empty-evidence rule.
_CONFIDENCE_RANK = {
    Confidence.false_positive: 0,
    Confidence.suspicious: 1,
    Confidence.likely: 2,
    Confidence.confirmed: 3,
}


class HostRole(str, Enum):
    workstation = "workstation"
    dc = "dc"
    server = "server"


# --------------------------------------------------------------------------- #
# Evidence + tool I/O
# --------------------------------------------------------------------------- #
class EvidenceFile(BaseModel):
    host_id: str
    kind: str  # "memory" | "disk"
    path: str
    sha256: str | None = None
    provenance_id: str | None = None  # the hash_evidence call that fingerprinted it


class EvidenceReference(BaseModel):
    """A citation that points at one line of tool output, never just a file."""

    provenance_id: str = Field(min_length=1)
    record_id: str | None = None  # e.g. "PID=3296", "EventRecordID=1187", MFT entry
    tool: str | None = None  # the MCP tool that produced it
    artifact_path: str | None = None  # the output file the record lives in
    source_family: str | None = None  # independence axis for scoring (see scoring.py)
    note: str | None = None


class ToolResult(BaseModel):
    """Outcome of one MCP tool call, mirrored from the server response."""

    tool: str
    status: ToolResultStatus
    provenance_id: str
    host_id: str
    args: dict[str, Any] = Field(default_factory=dict)
    output_paths: list[str] = Field(default_factory=list)
    summary: str | None = None
    error: str | None = None


# --------------------------------------------------------------------------- #
# Findings / narrative objects
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    finding_id: str
    host_id: str
    title: str
    category: str  # e.g. "process_masquerade", "persistence", "lateral_movement"
    description: str
    confidence: Confidence
    rule: str | None = None  # which deterministic rule emitted/last-touched it
    entity_key: str | None = None  # what the claim is ABOUT (e.g. "pid:3296") — merge key
    paths: list[str] = Field(default_factory=list)  # normalized image paths — cross-source merge key
    source_count: int = 0  # distinct independent source families supporting the claim
    evidence: list[EvidenceReference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_evidence_above_suspicious(self) -> "Finding":
        # confirmed/likely must cite at least one resolvable provenance_id.
        if _CONFIDENCE_RANK[self.confidence] > _CONFIDENCE_RANK[Confidence.suspicious]:
            has_cite = any(e.provenance_id for e in self.evidence)
            if not has_cite:
                raise ValueError(
                    f"Finding {self.finding_id!r} is {self.confidence.value} but has no "
                    "EvidenceReference with a provenance_id."
                )
        return self


class TimelineEvent(BaseModel):
    ts: datetime
    host_id: str
    source: str  # "mft", "evtx", "prefetch", ...
    description: str
    evidence: list[EvidenceReference] = Field(default_factory=list)


class Contradiction(BaseModel):
    contradiction_id: str
    host_id: str
    claim: str
    source_a: str
    source_b: str
    resolution: str | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)


class HostReport(BaseModel):
    host_id: str
    os: str | None = None
    role: HostRole = HostRole.workstation
    generated_at: datetime = Field(default_factory=_utc_now)
    summary: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Agent reasoning trace (NOT provenance — see playbook §3)
# --------------------------------------------------------------------------- #
class AgentDecision(BaseModel):
    decision_id: str
    agent_name: str  # which node
    step: str  # short slug of the step
    inputs_summary: str  # what it looked at
    action: str  # what it did
    rationale: str  # why
    ts: datetime = Field(default_factory=_utc_now)


# --------------------------------------------------------------------------- #
# Case / host topology + the single threaded state object
# --------------------------------------------------------------------------- #
class Host(BaseModel):
    host_id: str
    os: str | None = None
    role: HostRole = HostRole.workstation
    memory_image: str | None = None
    disk_image: str | None = None
    extracted_dir: str | None = None  # runtime: where disk node carved artifacts (Plaso source)


class CaseState(BaseModel):
    """The one typed object threaded through every graph node."""

    case_id: str
    case_root: str  # CASE_ROOT (where the MCP server writes; we read back from here)
    hosts: dict[str, Host] = Field(default_factory=dict)
    current_host: str | None = None

    findings: list[Finding] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)

    completed_steps: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)

    # Self-correction loop control (Phase 5), all capped to a single re-check round.
    needs_disk_recheck: bool = False
    disk_recheck_done: bool = False
    self_correction_attempted: bool = False
    recorrelated: bool = False
    recheck_names: list[str] = Field(default_factory=list)

    iteration: int = 0
    max_iterations: int = 12

    # Report node outputs (Phase 6).
    report_path: str | None = None
    report_lint: dict = Field(default_factory=dict)
    report_narrated: bool = False

    # ----- small helpers used by nodes ----- #
    def add_tool_result(self, tr: ToolResult) -> None:
        self.tool_results.append(tr)

    def successful_results(self, tool: str | None = None) -> list[ToolResult]:
        out = [r for r in self.tool_results if r.status == ToolResultStatus.success]
        return [r for r in out if tool is None or r.tool == tool]

    def next_finding_id(self) -> str:
        return f"F-{len(self.findings) + 1:04d}"

    def next_contradiction_id(self) -> str:
        return f"C-{len(self.contradictions) + 1:04d}"

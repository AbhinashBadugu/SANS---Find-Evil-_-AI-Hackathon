"""The deterministic core (playbook §7): confidence + citation validation.

NONE of this is model judgment. Confidence tiers, citation resolution, and the
benign allowlist are plain Python so the anti-hallucination guarantee is testable.
"""

from __future__ import annotations

import json
from pathlib import Path

from .state import Confidence, Finding


def load_provenance_ids(case_root: str | Path, case_id: str) -> set[str]:
    """Read every provenance_id the MCP server has logged for this case."""
    path = Path(case_root) / "cases" / case_id / "provenance.jsonl"
    ids: set[str] = set()
    if not path.exists():
        return ids
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            pid = rec.get("provenance_id")
            if pid:
                ids.add(pid)
    return ids


class CitationReport:
    def __init__(self) -> None:
        self.unresolved: list[tuple[str, str]] = []  # (finding_id, provenance_id)
        self.uncited: list[str] = []  # finding_ids with zero evidence
        self.ok: list[str] = []

    @property
    def clean(self) -> bool:
        return not self.unresolved and not self.uncited

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "ok": self.ok,
            "uncited": self.uncited,
            "unresolved": [{"finding_id": f, "provenance_id": p} for f, p in self.unresolved],
        }


def validate_citations(findings: list[Finding], provenance_ids: set[str]) -> CitationReport:
    """Resolve every EvidenceReference.provenance_id against the logbook.

    A finding whose citations don't resolve is reported (and, if it claimed a
    confidence above `suspicious`, is demoted to `suspicious` so an unverifiable
    claim can never ship as confirmed/likely).
    """
    report = CitationReport()
    for fnd in findings:
        if not fnd.evidence:
            report.uncited.append(fnd.finding_id)
            continue
        bad = [e.provenance_id for e in fnd.evidence if e.provenance_id not in provenance_ids]
        for p in bad:
            report.unresolved.append((fnd.finding_id, p))
        if not bad:
            report.ok.append(fnd.finding_id)
        else:
            # Defensive demotion: never let an unverifiable citation hold a high tier.
            if fnd.confidence in (Confidence.confirmed, Confidence.likely):
                fnd.confidence = Confidence.suspicious
                fnd.tags.append("demoted_unresolved_citation")
    return report


def assign_confidence(source_count: int, *, contradicted: bool = False, benign: bool = False) -> Confidence:
    """Deterministic tiering (playbook §7.1).

    >=2 independent sources -> confirmed
    1 source               -> suspicious
    contradicted/benign     -> false_positive
    """
    if contradicted or benign:
        return Confidence.false_positive
    if source_count >= 2:
        return Confidence.confirmed
    if source_count == 1:
        return Confidence.suspicious
    return Confidence.false_positive

"""The deterministic core (playbook §7): confidence + citation validation.

NONE of this is model judgment. Confidence tiers, citation resolution, and the
benign allowlist are plain Python so the anti-hallucination guarantee is testable.
"""

from __future__ import annotations

import json
from pathlib import Path

from .state import Confidence, EvidenceReference, Finding


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


# --------------------------------------------------------------------------- #
# Source-family independence model (playbook §7.1; operator rule:
# "nothing is `confirmed` without two INDEPENDENT sources").
#
# Independence is defined at the level of distinct evidence FAMILIES, not raw
# signal count — two angles on the same process from the same plugin are one
# source, but a parent-process anomaly (process_tree) and an injected PE in
# private RWX memory (injection) are genuinely independent observations.
# --------------------------------------------------------------------------- #
STRONG_FAMILIES = {
    "injection",       # malfind: private RWX region containing an MZ header
    "network",         # netscan: attacker-owned connection
    "services",        # svcscan: malicious service install
    "disk_mft",        # the file exists on disk
    "disk_shimcache",  # it executed
    "disk_registry",   # registry persistence
    "disk_evtx",       # event-log corroboration
    "timeline",        # placed in the attack window
}
IDENTITY_FAMILIES = {
    "process_tree",    # wrong parent / hidden-process diff
    "command_line",    # masqueraded image path
}


def families_of(finding) -> set[str]:
    return {e.source_family for e in finding.evidence if e.source_family}


def score_by_families(families: set[str], *, contradicted: bool = False, benign: bool = False) -> Confidence:
    """Map a set of distinct evidence families to a confidence tier.

    >=2 distinct families                         -> confirmed (two independent sources)
    1 strong/behavioural family                   -> likely
    1 identity-only family                         -> suspicious
    0 / contradicted / benign                      -> false_positive
    """
    fams = set(families)
    if contradicted or benign:
        return Confidence.false_positive
    if len(fams) >= 2:
        return Confidence.confirmed
    if len(fams) == 1:
        return Confidence.likely if fams & STRONG_FAMILIES else Confidence.suspicious
    return Confidence.false_positive


# Ranking used to pick the "lead" signal when merging findings about one entity.
_LEAD_PRIORITY = {
    "code_injection": 5,
    "malicious_service": 4,
    "c2_connection": 4,
    "process_masquerade": 3,
    "hidden_process": 2,
}


def merge_by_entity(findings: list[Finding]) -> list[Finding]:
    """Merge findings that are ABOUT the same entity (e.g. one PID), union their
    evidence, and (re)assign confidence from the count of distinct families.

    This is the within-host correlation that lets the implant accrue
    process_tree + command_line + injection evidence and reach `confirmed`,
    while a lone hidden-process lead stays `suspicious`.
    """
    groups: dict[str, list[Finding]] = {}
    order: list[str] = []
    for f in findings:
        key = f.entity_key or f.finding_id
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    merged: list[Finding] = []
    for key in order:
        group = groups[key]
        lead = max(group, key=lambda x: _LEAD_PRIORITY.get(x.category, 0))
        evidence: list[EvidenceReference] = []
        seen: set[tuple] = set()
        tags: set[str] = set()
        for f in group:
            tags.update(f.tags)
            for e in f.evidence:
                sig = (e.provenance_id, e.record_id, e.source_family)
                if sig not in seen:
                    seen.add(sig)
                    evidence.append(e)
        fams = {e.source_family for e in evidence if e.source_family}
        conf = score_by_families(fams)
        notes = [e.note for e in evidence if e.note]
        merged.append(
            Finding(
                finding_id=lead.finding_id,
                host_id=lead.host_id,
                title=lead.title,
                category=lead.category,
                description=(
                    lead.description
                    + (
                        f"\nCorroborating signals ({len(fams)} independent families: "
                        f"{', '.join(sorted(fams))}):\n  - " + "\n  - ".join(notes)
                        if len(group) > 1
                        else ""
                    )
                ),
                confidence=conf,
                rule=lead.rule,
                entity_key=key,
                source_count=len(fams),
                evidence=evidence,
                tags=sorted(tags),
            )
        )
    return merged

"""Schema contract tests (playbook §5 hardening)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.state import (  # noqa: E402
    Confidence,
    EvidenceReference,
    Finding,
)


def _ref():
    return EvidenceReference(provenance_id="cmd-000038", record_id="PID=3296")


def test_confirmed_requires_evidence():
    with pytest.raises(ValueError):
        Finding(
            finding_id="F-0001",
            host_id="xp-tdungan",
            title="x",
            category="process_masquerade",
            description="d",
            confidence=Confidence.confirmed,
            evidence=[],
        )


def test_likely_requires_evidence():
    with pytest.raises(ValueError):
        Finding(
            finding_id="F-0002",
            host_id="xp-tdungan",
            title="x",
            category="c",
            description="d",
            confidence=Confidence.likely,
            evidence=[],
        )


def test_suspicious_allows_empty_evidence():
    # suspicious is a lead, not a proven claim — empty evidence is permitted.
    f = Finding(
        finding_id="F-0003",
        host_id="xp-tdungan",
        title="x",
        category="c",
        description="d",
        confidence=Confidence.suspicious,
        evidence=[],
    )
    assert f.confidence is Confidence.suspicious


def test_confirmed_with_evidence_ok():
    f = Finding(
        finding_id="F-0004",
        host_id="xp-tdungan",
        title="x",
        category="c",
        description="d",
        confidence=Confidence.confirmed,
        evidence=[_ref()],
    )
    assert f.evidence[0].record_id == "PID=3296"

"""Tests for the deterministic core: masquerade rule, citation validation,
benign allowlist, confidence tiering."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.benign_allowlist import is_benign_location  # noqa: E402
from dfir_agent.rules.suspicious_process import detect_parent_anomalies  # noqa: E402
from dfir_agent.scoring import assign_confidence, validate_citations  # noqa: E402
from dfir_agent.state import Confidence, EvidenceReference, Finding  # noqa: E402


# Mirrors the real xp-tdungan windows.pslist: legit svchosts are children of
# services.exe (1044); the implant (PID 3296) is a child of explorer.exe (1900).
PSLIST = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System"},
    {"PID": 1044, "PPID": 1000, "ImageFileName": "services.exe"},
    {"PID": 1236, "PPID": 1044, "ImageFileName": "svchost.exe"},
    {"PID": 1900, "PPID": 2436, "ImageFileName": "explorer.exe"},
    {"PID": 3296, "PPID": 1900, "ImageFileName": "svchost.exe"},
]


def _counter():
    n = {"i": 0}

    def nxt():
        n["i"] += 1
        return f"F-{n['i']:04d}"

    return nxt


def test_masquerade_flags_pid_3296_only():
    findings = detect_parent_anomalies(
        PSLIST,
        host_id="xp-tdungan",
        provenance_id="cmd-000038",
        artifact_path="/x/windows.pslist.json",
        next_id=_counter(),
    )
    pids = sorted(
        int(e.record_id.split("=")[1])
        for f in findings
        for e in f.evidence
    )
    assert pids == [3296]
    f = findings[0]
    assert f.category == "process_masquerade"
    assert f.confidence is Confidence.suspicious
    assert f.evidence[0].provenance_id == "cmd-000038"
    assert f.source_count == 1


def test_legit_svchost_not_flagged():
    # The svchost under services.exe (1236) must NOT produce a finding.
    findings = detect_parent_anomalies(
        [PSLIST[1], PSLIST[2]],  # services.exe + its child svchost
        host_id="h",
        provenance_id="cmd-1",
        artifact_path=None,
        next_id=_counter(),
    )
    assert findings == []


def test_citation_validation_demotes_unresolved():
    f = Finding(
        finding_id="F-0001",
        host_id="h",
        title="t",
        category="c",
        description="d",
        confidence=Confidence.confirmed,
        evidence=[EvidenceReference(provenance_id="cmd-999999")],
    )
    report = validate_citations([f], provenance_ids={"cmd-000038"})
    assert not report.clean
    assert f.confidence is Confidence.suspicious  # demoted
    assert "demoted_unresolved_citation" in f.tags


def test_citation_validation_clean_passes():
    f = Finding(
        finding_id="F-0002",
        host_id="h",
        title="t",
        category="c",
        description="d",
        confidence=Confidence.suspicious,
        evidence=[EvidenceReference(provenance_id="cmd-000038", record_id="PID=3296")],
    )
    report = validate_citations([f], provenance_ids={"cmd-000038"})
    assert report.clean


def test_benign_allowlist_rejects_masquerade_subdir():
    # The implant path must NOT be allowlisted as benign.
    assert is_benign_location(r"C:\windows\system32\dllhost\svchost.exe") is False
    # A real system32 binary is benign.
    assert is_benign_location(r"C:\windows\system32\svchost.exe") is True
    # A WinSxS component is benign.
    assert is_benign_location(r"C:\Windows\WinSxS\amd64_foo\x.dll") is True


def test_confidence_tiers():
    assert assign_confidence(2) is Confidence.confirmed
    assert assign_confidence(1) is Confidence.suspicious
    assert assign_confidence(1, contradicted=True) is Confidence.false_positive
    assert assign_confidence(1, benign=True) is Confidence.false_positive

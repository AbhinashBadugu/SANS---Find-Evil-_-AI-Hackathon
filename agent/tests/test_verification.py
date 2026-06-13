"""Adversarial self-verification: refute-before-confirm. Each finding faces a
panel; the trial (attempts + verdict) is recorded; only a holding refutation demotes."""

from __future__ import annotations

from dfir_agent.state import Confidence, EvidenceReference, Finding, Verdict
from dfir_agent.verification import adversarial_verify, verify_finding


def _f(fid, confidence, families, paths=None, contradictions=None) -> Finding:
    evs = [EvidenceReference(provenance_id=f"cmd-{i}", record_id=f"r{i}", source_family=fam)
           for i, fam in enumerate(families)]
    return Finding(finding_id=fid, host_id="h", title=f"finding {fid}", category="x",
                   description="d", confidence=confidence, paths=paths or [], evidence=evs,
                   contradictions=contradictions or [])


def test_benign_location_finding_is_refuted():
    f = _f("F1", Confidence.likely, ["command_line"], paths=[r"C:\Windows\System32\wceisvista.inf"])
    assert verify_finding(f) == Verdict.refuted
    assert f.confidence == Confidence.false_positive
    assert "benign_allowlist" in f.tags
    assert any(a.refuter == "benign_location" and a.result == "supported" for a in f.refutation_attempts)


def test_behavioural_evidence_overrides_benign_location():
    # Benign path, BUT injection+network behavioural evidence -> the benign challenge fails.
    f = _f("F2", Confidence.confirmed, ["injection", "network"], paths=[r"C:\Windows\System32\svchost.exe"])
    assert verify_finding(f) == Verdict.survived
    assert f.confidence == Confidence.confirmed
    ben = next(a for a in f.refutation_attempts if a.refuter == "benign_location")
    assert ben.result == "rejected"


def test_multi_family_survives_independence_challenge():
    f = _f("F3", Confidence.confirmed, ["injection", "network"], paths=[r"X:\dllhost\svchost.exe"])
    assert verify_finding(f) == Verdict.survived
    assert f.independent_families == 2
    ind = next(a for a in f.refutation_attempts if a.refuter == "independence")
    assert ind.result == "rejected"  # 2 independent families -> single-axis challenge fails


def test_single_source_documents_independence_challenge_but_survives():
    f = _f("F4", Confidence.suspicious, ["process_tree"], paths=[r"X:\dllhost\svchost.exe"])
    assert verify_finding(f) == Verdict.survived  # not benign, not contradicted
    assert f.confidence == Confidence.suspicious   # unchanged — engine is behaviour-preserving
    ind = next(a for a in f.refutation_attempts if a.refuter == "independence")
    assert ind.result == "supported"   # single axis -> challenge holds (documented, not auto-demoted)
    assert f.independent_families == 1


def test_contradiction_makes_finding_disputed():
    f = _f("F5", Confidence.confirmed, ["injection", "network"], paths=[r"X:\a.exe"],
           contradictions=["memory says running; disk shows the binary absent"])
    assert verify_finding(f) == Verdict.disputed
    assert f.confidence == Confidence.disputed


def test_adversarial_verify_panel_tally():
    fs = [
        _f("A", Confidence.likely, ["command_line"], paths=[r"C:\Windows\System32\x.inf"]),          # refuted
        _f("B", Confidence.confirmed, ["injection", "network"], paths=[r"X:\dllhost\s.exe"]),         # survived
        _f("C", Confidence.confirmed, ["injection", "disk_mft"], paths=[r"X:\a.exe"], contradictions=["c"]),  # disputed
    ]
    tally = adversarial_verify(fs)
    assert tally["refuted"] == 1 and tally["survived"] == 1 and tally["disputed"] == 1

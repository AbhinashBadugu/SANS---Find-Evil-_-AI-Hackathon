"""Phase 8 — config-driven benign/IR enrichment + retired IOC debt.

Confirms the case profile loads (IR hosts, benign service hints incl. the ones
moved out of dc_events, topology), and that enrich_findings self-corrects a
finding that rests on IR infrastructure (demote, not delete; keep provenance).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent import enrichment  # noqa: E402
from dfir_agent.state import Confidence, EvidenceReference, Finding  # noqa: E402

_PROFILE = Path(__file__).resolve().parents[1] / "case_profiles" / "srl2015"


@pytest.fixture()
def srl2015_profile(monkeypatch):
    monkeypatch.setenv("DFIR_CASE_PROFILE_DIR", str(_PROFILE))
    yield


def test_profile_loads(srl2015_profile):
    hints = enrichment.benign_service_hints()
    assert "usboesrv" in hints          # moved here from core (debt retired)
    assert "f-response" in hints        # generic default still present
    assert enrichment.is_ir_host("10.3.58.4") is False
    assert enrichment.is_ir_host("10.3.16.5") is True
    assert "examiner" in (enrichment.ir_label("10.3.16.5") or "").lower()
    ipmap = enrichment.case_host_ip_map()
    assert ipmap.get("10.3.58.7") == "xp-tdungan"


def test_self_correction_demotes_ir_finding(srl2015_profile):
    f = Finding(
        finding_id="X-1", host_id="dc", title="RDP from 10.3.16.5",
        category="lateral_movement", description="Inbound RDP from 10.3.16.5 by rsydow",
        confidence=Confidence.likely,
        evidence=[EvidenceReference(provenance_id="cmd-1", note="4624 type10 src 10.3.16.5")],
    )
    out, corrections = enrichment.enrich_findings([f])
    assert out[0].confidence == Confidence.false_positive
    assert "self_correction" in out[0].tags
    assert out[0].evidence and out[0].evidence[0].provenance_id == "cmd-1"   # provenance retained
    assert corrections and corrections[0]["finding_id"] == "X-1"


def test_no_profile_means_generic_only(monkeypatch):
    monkeypatch.delenv("DFIR_CASE_PROFILE_DIR", raising=False)
    hints = enrichment.benign_service_hints()
    assert "usboesrv" not in hints       # case data absent without a profile
    assert "f-response" in hints         # generic default remains
    assert enrichment.ir_hosts() == {}

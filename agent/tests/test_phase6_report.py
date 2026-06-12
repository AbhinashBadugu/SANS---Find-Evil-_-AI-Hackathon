"""Phase 6: citation linter + report rendering. The linter must flag any asserted
claim (finding above false_positive, contradiction, timeline event) whose
provenance_id does not resolve, and pass when all resolve."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.nodes.report import _cite, _deterministic_summary, _render, lint_citations  # noqa: E402
from dfir_agent.state import (  # noqa: E402
    CaseState, Confidence, Contradiction, EvidenceReference, Finding, Host, HostReport,
    HostRole, TimelineEvent,
)
from datetime import datetime, timezone


PROV = {"cmd-000260": {"tool_name": "parse_mft", "output_paths": ["/x/mft.csv"], "end_time": "2026-06-12T03:00:00Z"}}


def _state_with(findings, contradictions=(), timeline=()):
    s = CaseState(case_id="srl2015", case_root="/tmp")
    s.current_host = "xp-tdungan"
    s.hosts = {"xp-tdungan": Host(host_id="xp-tdungan", os="Windows XP", role=HostRole.workstation)}
    s.findings = list(findings)
    s.contradictions = list(contradictions)
    s.timeline = list(timeline)
    return s


def _confirmed(pid="cmd-000260"):
    return Finding(
        finding_id="F-1", host_id="xp-tdungan", title="Injected PE (PID 3296)", category="code_injection",
        confidence=Confidence.confirmed, source_count=2, paths=["c:\\x\\svchost.exe"], description="d",
        evidence=[
            EvidenceReference(provenance_id=pid, record_id="MFT#3022", tool="parse_mft", source_family="disk_mft"),
            EvidenceReference(provenance_id=pid, record_id="PID=3296", tool="run_volatility_plugin", source_family="injection"),
        ],
    )


def test_lint_clean_when_all_resolve():
    s = _state_with([_confirmed()])
    rep = lint_citations(s, PROV)
    assert rep["clean"] and rep["uncited_claims"] == []


def test_lint_flags_unresolved_finding():
    s = _state_with([_confirmed(pid="cmd-999999")])  # not in PROV
    rep = lint_citations(s, PROV)
    assert not rep["clean"]
    assert "finding:F-1" in rep["uncited_claims"]


def test_lint_ignores_false_positive():
    fp = Finding(
        finding_id="F-2", host_id="xp-tdungan", title="benign", category="hidden_process",
        confidence=Confidence.false_positive, description="d", evidence=[],
    )
    s = _state_with([fp])
    assert lint_citations(s, PROV)["clean"]  # disputed items are not asserted claims


def test_lint_flags_uncited_timeline_and_contradiction():
    te = TimelineEvent(ts=datetime(2012, 4, 3, tzinfo=timezone.utc), host_id="h", source="mft",
                       description="x", evidence=[EvidenceReference(provenance_id="cmd-missing")])
    c = Contradiction(contradiction_id="C-1", host_id="h", claim="x", source_a="a", source_b="b",
                      resolution="r", evidence=[EvidenceReference(provenance_id="cmd-missing")])
    s = _state_with([], [c], [te])
    rep = lint_citations(s, PROV)
    assert "contradiction:C-1" in rep["uncited_claims"]
    assert any(x.startswith("timeline:") for x in rep["uncited_claims"])


def test_cite_line_includes_tool_path_ts():
    e = EvidenceReference(provenance_id="cmd-000260", record_id="MFT#3022")
    line, resolves = _cite(e, PROV)
    assert resolves
    assert "parse_mft" in line and "/x/mft.csv" in line and "2026-06-12" in line


def test_render_produces_cited_markdown():
    s = _state_with([_confirmed()])
    hr = HostReport(host_id="xp-tdungan", os="Windows XP", role=HostRole.workstation)
    md = _render(hr, s, PROV, _deterministic_summary(s, s.hosts["xp-tdungan"]), narrated=False)
    assert "# Host Report — xp-tdungan" in md
    assert "## Confirmed (1)" in md
    assert "cmd-000260" in md  # citation present
    assert "Injected PE" in md

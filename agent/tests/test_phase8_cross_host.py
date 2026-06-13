"""Phase 8: cross-host correlation.

Deterministic fusion of finished per-host findings into a campaign view:
shared implants (same file on >=2 hosts), an ordered lateral-movement chain
(patient zero leads, source IPs attributed via topology), case-level patient
zero, and a citation lint that mirrors the host report's zero-uncited gate.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.nodes.cross_host import (  # noqa: E402
    HostBundle, build_lateral_chain, correlate_cross_host, correlate_shared_implants,
    lint_cross_host, render_case_report,
)
from dfir_agent.state import Confidence, EvidenceReference, Finding, HostRole  # noqa: E402


def _utc(s):
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def _ev(pid, rec="r", fam="disk_mft", note="n"):
    return EvidenceReference(provenance_id=pid, record_id=rec, tool="parse_mft",
                             artifact_path="/x/mft.csv", source_family=fam, note=note)


def _finding(host, title, cat, conf, *, paths=None, tags=None, rule=None, ek=None, ev=None):
    return Finding(
        finding_id=f"F-{abs(hash((host, title))) % 9999:04d}", host_id=host, title=title,
        category=cat, description=title, confidence=conf, rule=rule, entity_key=ek,
        paths=paths or [], tags=tags or [], evidence=ev or [_ev("cmd-1")],
    )


def _impl(host, conf, path):
    return _finding(host, f"implant on {host}", "process_masquerade", conf,
                    paths=[path], ev=[_ev(f"cmd-{host}")])


def _bundles():
    # spinlock.exe appears on two hosts (different full paths, same basename);
    # a unique file appears on only one host (must NOT be a shared implant).
    b1 = HostBundle(
        host_id="xp-tdungan", os="Windows XP", role=HostRole.workstation, ip="10.3.58.7",
        patient_zero=_utc("2012-04-03T00:35:02"),
        findings=[
            _impl("xp-tdungan", Confidence.confirmed, r"c:\dllhost\svchost.exe"),
            _finding("xp-tdungan", "spinlock", "execution_record", Confidence.confirmed,
                     paths=[r"c:\temp\spinlock.exe"], ev=[_ev("cmd-a")]),
        ],
    )
    b2 = HostBundle(
        host_id="win7-nromanoff", os="Windows 7", role=HostRole.workstation, ip="10.3.58.5",
        patient_zero=_utc("2012-04-03T22:40:24"),
        findings=[
            _finding("win7-nromanoff", "spinlock", "execution_record", Confidence.likely,
                     paths=[r"c:\windows\spinlock.exe"], ev=[_ev("cmd-b")]),
            _finding("win7-nromanoff", "lonely file", "dropped_file", Confidence.suspicious,
                     paths=[r"c:\only-here.exe"], ev=[_ev("cmd-c")]),
        ],
    )
    dc = HostBundle(
        host_id="dc-controller", os="Server 2008 R2", role=HostRole.dc, ip="10.3.58.4",
        patient_zero=None,
        findings=[
            _finding("dc-controller", "RDP logon to DC: vibranium from 10.3.58.7",
                     "lateral_movement", Confidence.likely, rule="dc_events.rdp_logon",
                     ek="rdp:vibranium:10.3.58.7", tags=["dc", "src:10.3.58.7"],
                     ev=[_ev("cmd-rdp", rec="EventRecordId=12510253", fam="disk_evtx",
                             note="4624 LogonType=10 user=vibranium src=10.3.58.7 at 2012-04-04 18:17:53")]),
        ],
    )
    return [b1, b2, dc]


def test_shared_implant_needs_two_hosts():
    shared = correlate_shared_implants(_bundles())
    keys = {s.key for s in shared}
    assert "spinlock.exe" in keys              # on tdungan + nromanoff
    assert "only-here.exe" not in keys         # single host -> not shared
    spin = next(s for s in shared if s.key == "spinlock.exe")
    assert {p.host_id for p in spin.hosts} == {"xp-tdungan", "win7-nromanoff"}
    # strongest presence (confirmed) is listed first
    assert spin.hosts[0].confidence == Confidence.confirmed


def test_patient_zero_is_earliest_host():
    xh = correlate_cross_host("srl2015", _bundles())
    assert xh.case_patient_zero_host == "xp-tdungan"
    assert xh.case_patient_zero_ts == _utc("2012-04-03T00:35:02")


def test_lateral_hop_attributed_via_topology_and_ordered():
    bundles = _bundles()
    xh = correlate_cross_host("srl2015", bundles)
    assert len(xh.lateral_chain) == 1
    hop = xh.lateral_chain[0]
    assert hop.dst_host == "dc-controller"
    assert hop.src_ip == "10.3.58.7"
    assert hop.src_host == "xp-tdungan"          # attributed from bundle.ip topology
    assert hop.actor == "vibranium"
    assert hop.ts == _utc("2012-04-04T18:17:53")  # parsed from the evidence note
    assert "Type 10" in hop.method


def test_unmapped_source_ip_is_a_gap_not_a_guess():
    # Strip the topology IP from tdungan -> the hop source can't be attributed.
    bundles = _bundles()
    for b in bundles:
        b.ip = None
    hops, gaps = build_lateral_chain(bundles, ip_map={}, patient_zero_host="xp-tdungan")
    assert hops[0].src_host is None
    assert hops[0].src_ip == "10.3.58.7"
    assert any("10.3.58.7" in g and "not mapped" in g for g in gaps)


def test_spread_edges_connect_patient_zero():
    xh = correlate_cross_host("srl2015", _bundles())
    edges = {(s, d) for s, d, _ in xh.spread_edges}
    # lateral hop tdungan -> dc, and shared implant reach tdungan -> nromanoff
    assert ("xp-tdungan", "dc-controller") in edges
    assert ("xp-tdungan", "win7-nromanoff") in edges


def test_lint_clean_when_citations_resolve_and_render():
    xh = correlate_cross_host("srl2015", _bundles())
    prov = {"cmd-xp-tdungan": {}, "cmd-win7-nromanoff": {}, "cmd-a": {}, "cmd-b": {}, "cmd-rdp": {}}
    lint = lint_cross_host(xh, prov)
    assert lint["clean"], lint["uncited_claims"]
    md = render_case_report(xh, _bundles(), prov)
    assert "Cross-Host Case Report" in md
    assert "spinlock.exe" in md
    assert "patient zero" in md.lower()
    assert "vibranium" in md


def test_lint_flags_unresolved_hop_citation():
    xh = correlate_cross_host("srl2015", _bundles())
    # provenance index missing the RDP hop's id -> the hop is uncited
    prov = {"cmd-xp-tdungan": {}, "cmd-win7-nromanoff": {}, "cmd-a": {}, "cmd-b": {}}
    lint = lint_cross_host(xh, prov)
    assert not lint["clean"]
    assert any(c.startswith("hop:") for c in lint["uncited_claims"])

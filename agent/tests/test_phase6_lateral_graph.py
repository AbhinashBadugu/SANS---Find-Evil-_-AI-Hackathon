"""Phase 6 — lateral-movement graph reconstruction.

Pure rule layer over synthetic EVTX rows. Checks IP->host resolution, PsExec
edge (7045 PSEXESVC + remote logon) confirmed, RDP edge likely, unknown source
kept explicit (not guessed), time ordering, and cited findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.lateral_graph import (  # noqa: E402
    build_lateral_movement_graph, findings_from_lateral_graph, resolve_source_ip_to_host,
)

IP_MAP = {"10.0.0.1": "host-a", "10.0.0.2": "host-b"}

EVENTS = [
    {"event_id": 7045, "host_id": "host-b", "service_name": "PSEXESVC",
     "time": "2012-04-03T20:00:00", "provenance_id": "cmd-1", "record_id": "7045#1"},
    {"event_id": 4624, "host_id": "host-b", "logon_type": 3, "account": "admin",
     "src_ip": "10.0.0.1", "time": "2012-04-03T20:00:05", "provenance_id": "cmd-2", "record_id": "4624#1"},
    {"event_id": 4624, "host_id": "host-c", "logon_type": 10, "account": "admin",
     "src_ip": "10.0.0.2", "time": "2012-04-04T18:17:53", "provenance_id": "cmd-3", "record_id": "4624#2"},
    {"event_id": 4672, "host_id": "host-c", "account": "admin",
     "time": "2012-04-04T18:17:54", "provenance_id": "cmd-4"},
    {"event_id": 4624, "host_id": "host-d", "logon_type": 10, "account": "x",
     "src_ip": "203.0.113.99", "time": "2012-04-05T01:00:00", "provenance_id": "cmd-5", "record_id": "4624#3"},
    {"event_id": 4624, "host_id": "host-d", "logon_type": 2, "account": "local",
     "time": "2012-04-05T02:00:00", "provenance_id": "cmd-6"},  # interactive -> not lateral
]


def test_resolve_source():
    assert resolve_source_ip_to_host("10.0.0.1", IP_MAP) == "host-a"
    assert resolve_source_ip_to_host("8.8.8.8", IP_MAP) is None


def test_build_graph():
    g = build_lateral_movement_graph(EVENTS, ip_map=IP_MAP)
    edges = {(e["src"], e["dst"]): e for e in g["edges"]}
    assert len(g["edges"]) == 3  # interactive logon excluded

    ab = edges[("host-a", "host-b")]
    assert ab["confidence"] == "confirmed" and ab["method"].startswith("PsExec")

    bc = edges[("host-b", "host-c")]
    assert bc["confidence"] == "likely" and "RDP" in bc["method"]

    ud = edges[("unknown", "host-d")]
    assert ud["confidence"] == "suspicious"
    assert "203.0.113.99" in g["unknown_sources"]

    # time-ordered spread path begins at the earliest source
    assert g["spread_path"].startswith("host-a -> host-b -> host-c")


def test_findings_cited():
    g = build_lateral_movement_graph(EVENTS, ip_map=IP_MAP)
    findings = findings_from_lateral_graph(g)
    assert len(findings) == 3
    assert all(f.category == "lateral_movement" for f in findings)
    assert all(f.evidence[0].provenance_id for f in findings)
    # the unknown-source finding discloses the gap rather than naming a host
    ud = next(f for f in findings if "unknown" in f.title)
    assert "not resolved" in ud.description.lower()

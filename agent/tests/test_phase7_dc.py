"""Phase 7: DC event-log ruleset — PsExec/Mnemosyne service installs flagged,
benign IR/USB services classified out, RDP (Type 10) and explicit-cred logons
surfaced with citations. Fixture rows mirror the real DC Security log."""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.dc_events import analyze_dc_events  # noqa: E402

COLS = ["EventRecordId", "TimeCreated", "EventId", "PayloadData1", "ExecutableInfo", "Payload"]


def _logon_payload(logon_type, ip, target, subject="-"):
    return json.dumps({"EventData": {"Data": [
        {"@Name": "SubjectUserName", "#text": subject},
        {"@Name": "TargetUserName", "#text": target},
        {"@Name": "LogonType", "#text": str(logon_type)},
        {"@Name": "IpAddress", "#text": ip},
    ]}})


ROWS = [
    # 7045 PsExec ×2 -> lateral movement
    ["225222", "2012-04-04 17:29:33", "7045", "Name: PsExec", "%SystemRoot%\\PSEXESVC.EXE", ""],
    ["225333", "2012-04-04 18:00:43", "7045", "Name: PsExec", "%SystemRoot%\\PSEXESVC.EXE", ""],
    # 7045 Mnemosyne -> suspicious driver
    ["227205", "2012-04-06 18:54:13", "7045", "Name: Mnemosyne", "C:\\Windows\\system32\\Mnemosyne_x64.sys", ""],
    # 7045 benign -> classified out (no finding)
    ["111", "2012-03-20 17:58:12", "7045", "Name: KernelPro USB over Ethernet Service", "C:\\Windows\\system32\\usboesrv.exe", ""],
    ["112", "2012-03-20 18:55:07", "7045", "Name: F-Response License Manager Service", "C:\\Program Files\\F-Response\\f-response-lm-srv.exe", ""],
    # 4624 Type 10 RDP by vibranium from patient-zero IP
    ["12510253", "2012-04-04 18:17:53", "4624", "", "", _logon_payload(10, "10.3.58.7", "vibranium")],
    # 4624 Type 3 (network) -> NOT RDP, ignored
    ["999", "2012-04-04 18:17:53", "4624", "", "", _logon_payload(3, "10.3.58.7", "x")],
    # 4648 explicit creds for vibranium from patient-zero IP
    ["12510252", "2012-04-04 18:17:53", "4648", "", "", _logon_payload("", "10.3.58.7", "vibranium", subject="CONTROLLER$")],
    # 4648 machine-account self (target ends with $) -> ignored
    ["888", "2012-04-04 18:17:53", "4648", "", "", _logon_payload("", "10.3.58.7", "CONTROLLER$", subject="CONTROLLER$")],
]


def _write(tmp_path):
    p = tmp_path / "evtx.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(COLS)
        w.writerows(ROWS)
    return str(p)


def _counter():
    n = {"i": 0}

    def nxt():
        n["i"] += 1
        return f"F-{n['i']:04d}"

    return nxt


def test_dc_findings_and_classification(tmp_path):
    findings, notes = analyze_dc_events(
        _write(tmp_path), host_id="dc", provenance_id="cmd-evtx", next_id=_counter(),
    )
    cats = sorted(f.category for f in findings)
    titles = " | ".join(f.title for f in findings)
    # PsExec + Mnemosyne + RDP + explicit creds = 4 findings
    assert cats == ["lateral_movement", "lateral_movement", "lateral_movement", "suspicious_driver"]
    assert "PsExec" in titles and "Mnemosyne" in titles
    assert "vibranium from 10.3.58.7" in titles
    # benign usboesrv / F-Response classified out
    assert any("usboesrv" in n for n in notes)
    assert any("F-Response" in n or "f-response" in n.lower() for n in notes)


def test_psexec_aggregates_and_cites(tmp_path):
    findings, _ = analyze_dc_events(
        _write(tmp_path), host_id="dc", provenance_id="cmd-evtx", next_id=_counter(),
    )
    ps = next(f for f in findings if "PsExec" in f.title)
    assert "×2" in ps.title
    assert ps.evidence[0].provenance_id == "cmd-evtx"
    assert ps.evidence[0].record_id.startswith("EventRecordId=")
    assert ps.evidence[0].source_family == "disk_evtx"


def test_rdp_ignores_non_type10_and_machine_accounts(tmp_path):
    findings, _ = analyze_dc_events(
        _write(tmp_path), host_id="dc", provenance_id="cmd-evtx", next_id=_counter(),
    )
    rdp = [f for f in findings if f.rule == "dc_events.rdp_logon"]
    assert len(rdp) == 1  # only the Type-10 vibranium logon; Type-3 ignored
    expl = [f for f in findings if f.rule == "dc_events.explicit_creds"]
    assert len(expl) == 1  # CONTROLLER$ machine-account target excluded
    assert "src:10.3.58.7" in rdp[0].tags  # source IP tagged for cross-host correlation

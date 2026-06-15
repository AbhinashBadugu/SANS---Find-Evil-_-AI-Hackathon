"""deep_scan node — proves the wired detections actually fire on parsed data.

Builds a CaseState whose tool_results point at synthetic EvtxECmd / MFTECmd CSVs,
runs the node, and asserts it emits credential-access + lateral-movement findings
(i.e. it is NOT a silent no-op). Generic fixtures — no case IOCs.
"""

from __future__ import annotations

import asyncio
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.decisions import DecisionLog  # noqa: E402
from dfir_agent.nodes import NodeContext  # noqa: E402
from dfir_agent.nodes.deep_scan import deep_scan  # noqa: E402
from dfir_agent.state import CaseState, Host, HostRole, ToolResult, ToolResultStatus  # noqa: E402


def _payload(items: dict) -> str:
    return json.dumps({"EventData": {"Data": [{"@Name": k, "#text": v} for k, v in items.items()]}})


def _write_evtx(path: Path):
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["EventId", "EventRecordId", "TimeCreated",
                                           "Payload", "PayloadData1", "ExecutableInfo"])
        w.writeheader()
        # 7045 PsExec service install on this host
        w.writerow({"EventId": "7045", "EventRecordId": "1", "TimeCreated": "2012-04-03T20:00:00",
                    "Payload": "", "PayloadData1": "Name: PSEXESVC", "ExecutableInfo": "C:\\Windows\\PSEXESVC.exe"})
        # 4624 type-10 RDP from a known host IP
        w.writerow({"EventId": "4624", "EventRecordId": "2", "TimeCreated": "2012-04-03T20:00:05",
                    "Payload": _payload({"LogonType": "10", "TargetUserName": "admin", "IpAddress": "10.0.0.9"}),
                    "PayloadData1": "", "ExecutableInfo": ""})
        # 4672 special-privilege logon for the same admin account
        w.writerow({"EventId": "4672", "EventRecordId": "3", "TimeCreated": "2012-04-03T20:00:06",
                    "Payload": _payload({"SubjectUserName": "admin"}), "PayloadData1": "", "ExecutableInfo": ""})


def _write_mft(path: Path):
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["FileName", "ParentPath", "EntryNumber"])
        w.writeheader()
        w.writerow({"FileName": "sekurlsa.dll", "ParentPath": r"\Users\attacker\Temp", "EntryNumber": "101"})
        w.writerow({"FileName": "notepad.exe", "ParentPath": r"\Windows\System32", "EntryNumber": "102"})  # benign


def test_deep_scan_emits_cred_and_lateral_findings(tmp_path, monkeypatch):
    case_root = tmp_path
    case_dir = case_root / "cases" / "demo" / "hosts" / "victim" / "agent"
    case_dir.mkdir(parents=True)
    evtx = case_dir.parent / "evtx.csv"
    mft = case_dir.parent / "mft.csv"
    _write_evtx(evtx)
    _write_mft(mft)

    state = CaseState(case_id="demo", case_root=str(case_root))
    state.hosts = {
        "victim": Host(host_id="victim", os="Windows", role=HostRole.workstation),
        "attacker-pc": Host(host_id="attacker-pc", os="Windows", role=HostRole.workstation, ip="10.0.0.9"),
    }
    state.current_host = "victim"
    state.add_tool_result(ToolResult(tool="parse_evtx", status=ToolResultStatus.success,
                                     provenance_id="cmd-evtx", host_id="victim", output_paths=[str(evtx)]))
    state.add_tool_result(ToolResult(tool="parse_mft", status=ToolResultStatus.success,
                                     provenance_id="cmd-mft", host_id="victim", output_paths=[str(mft)]))

    ctx = NodeContext(client=None, decisions=DecisionLog(str(case_root), "demo", "victim"), case_root=str(case_root))
    asyncio.run(deep_scan(state, ctx))

    cats = [f.category for f in state.findings]
    assert "credential_access" in cats, "should detect sekurlsa.dll as credential access"
    assert "lateral_movement" in cats, "should build a lateral-movement edge from the 4624/7045"
    assert state.lateral_graph and state.lateral_graph["edges"], "lateral graph stored for the report"
    assert "deep_scan" in state.completed_steps

    # the RDP edge resolves the source IP to the known host (not 'unknown'), and PsExec is confirmed
    lat = [f for f in state.findings if f.category == "lateral_movement"]
    assert any("attacker-pc" in f.title for f in lat)
    # benign notepad.exe was NOT turned into a finding
    assert not any("notepad" in (f.title or "").lower() for f in state.findings)


def test_deep_scan_no_inputs_is_safe(tmp_path):
    """No parsed EVTX/MFT -> records gaps, emits nothing, does not crash."""
    state = CaseState(case_id="demo", case_root=str(tmp_path))
    state.hosts = {"h": Host(host_id="h", os="Windows", role=HostRole.workstation)}
    state.current_host = "h"
    ctx = NodeContext(client=None, decisions=DecisionLog(str(tmp_path), "demo", "h"), case_root=str(tmp_path))
    asyncio.run(deep_scan(state, ctx))
    assert "deep_scan" in state.completed_steps
    assert any("EVTX" in g for g in state.gaps)

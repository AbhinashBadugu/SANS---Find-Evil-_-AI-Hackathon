"""Phase 9: recall-lifting extraction rules (network C2, exfil, persistence, 4672).

Each test asserts BOTH that the rule fires on the real-world signal AND that it
stays quiet on the benign look-alikes — recall must not come at the cost of the
0-hallucination guarantee.
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json  # noqa: E402

from dfir_agent.rules.dc_events import analyze_dc_events  # noqa: E402
from dfir_agent.rules.exfil import detect_staged_archives  # noqa: E402
from dfir_agent.rules.network import detect_c2_connections, is_public_ip  # noqa: E402
from dfir_agent.rules.persistence import detect_run_keys, detect_scheduled_at_jobs  # noqa: E402


def _counter():
    n = {"i": 0}
    def nxt():
        n["i"] += 1
        return f"F-{n['i']:04d}"
    return nxt


# --------------------------------------------------------------------------- #
# network / C2
# --------------------------------------------------------------------------- #
def test_is_public_ip():
    assert is_public_ip("199.73.28.114")
    assert not is_public_ip("10.3.58.7")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("224.0.0.252")
    assert not is_public_ip("")


def test_c2_flags_suspicious_and_system_not_benign():
    rows = [
        {"ForeignAddr": "199.73.28.114", "ForeignPort": 443, "Owner": "spinlock.exe", "PID": 1328, "Proto": "TCPv4", "State": "CLOSED"},
        {"ForeignAddr": "12.190.135.235", "ForeignPort": 2264, "Owner": "System", "PID": 4, "Proto": "TCPv4", "State": "CLOSED"},
        {"ForeignAddr": "69.171.229.13", "ForeignPort": 443, "Owner": "Skype.exe", "PID": 2000, "Proto": "TCPv4", "State": "CLOSED"},
        {"ForeignAddr": "10.3.58.4", "ForeignPort": 445, "Owner": "System", "PID": 4, "Proto": "TCPv4", "State": "CLOSED"},
    ]
    fs = detect_c2_connections(rows, host_id="h", provenance_id="cmd-ns", artifact_path="ns.json",
                               suspicious_pids={"1328"}, suspicious_names={"spinlock.exe"}, next_id=_counter())
    ips = {t.split(":", 1)[1] for f in fs for t in f.tags if t.startswith("c2:")}
    assert ips == {"199.73.28.114", "12.190.135.235"}     # implant + System-beacon
    # Skype (benign owner) and the private 10.3.58.4 (SMB) are NOT flagged
    assert "69.171.229.13" not in ips
    # the implant finding is keyed by pid so it merges with the process finding
    spin = next(f for f in fs if "199.73.28.114" in f.title)
    assert spin.entity_key == "pid:1328"
    assert spin.evidence[0].source_family == "network"


# --------------------------------------------------------------------------- #
# exfil — .rar in staging, never benign archives
# --------------------------------------------------------------------------- #
_MFT_COLS = ["EntryNumber", "FileName", "Extension", "ParentPath", "FileSize", "Created0x10", "Created0x30"]


def _mft(tmp_path, rows):
    p = tmp_path / "mft.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_MFT_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in _MFT_COLS})
    return str(p)


def test_exfil_flags_rar_in_staging_only(tmp_path):
    rows = [
        {"EntryNumber": "37503", "FileName": "system4.rar", "Extension": "rar",
         "ParentPath": ".\\Users\\Public\\Temp", "FileSize": "6297428"},
        {"EntryNumber": "1", "FileName": "OfficeLR.cab", "Extension": "cab",
         "ParentPath": ".\\MSOCache\\All Users", "FileSize": "9000000"},
        {"EntryNumber": "2", "FileName": "chrome.7z", "Extension": "7z",
         "ParentPath": ".\\Users\\nfury\\AppData\\Local\\Google\\Chrome\\Installer", "FileSize": "8000000"},
        {"EntryNumber": "3", "FileName": "f-response.zip", "Extension": "zip",
         "ParentPath": ".\\Users\\rsydow\\AppData\\Local\\Temp", "FileSize": "5000000"},
        {"EntryNumber": "4", "FileName": "report.rar", "Extension": "rar",
         "ParentPath": ".\\Users\\nfury\\Documents", "FileSize": "1000"},  # .rar but NOT staging
    ]
    fs = detect_staged_archives(_mft(tmp_path, rows), host_id="nfury", provenance_id="cmd-m", next_id=_counter())
    paths = [f.paths[0] for f in fs]
    assert any("system4.rar" in p for p in paths)
    assert len(fs) == 1                                   # only the staged .rar; cab/7z/zip/doc-rar ignored
    assert "exfil" in fs[0].description.lower() and "staging" in fs[0].description.lower()


# --------------------------------------------------------------------------- #
# persistence — Run key + at-job, not benign autoruns/vendor tasks
# --------------------------------------------------------------------------- #
_RECMD_COLS = ["KeyPath", "ValueName", "ValueData"]


def _recmd(tmp_path, rows):
    p = tmp_path / "RECmd_Batch_Kroll_Batch_Output.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_RECMD_COLS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return str(p)


def test_run_key_flags_masquerade_not_legit(tmp_path):
    rows = [
        {"KeyPath": r"...\Microsoft\Windows\CurrentVersion\Run", "ValueName": "svchost",
         "ValueData": r"c:\windows\system32\dllhost\svchost.exe"},
        {"KeyPath": r"...\Microsoft\Windows\CurrentVersion\Run", "ValueName": "VMware Tools",
         "ValueData": r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"},
    ]
    fs = detect_run_keys(_recmd(tmp_path, rows), host_id="h", provenance_id="cmd-r", next_id=_counter())
    assert len(fs) == 1
    assert "svchost" in fs[0].title and "dllhost" in fs[0].description
    assert "Run" in fs[0].description and fs[0].evidence[0].source_family == "disk_registry"


def test_run_key_resolves_dir(tmp_path):
    # parse_registry returns the registry dir, not the CSV — detect_run_keys must resolve it
    d = tmp_path / "registry"
    d.mkdir()
    (d / "20260101_RECmd_Batch_Kroll_Batch_Output.csv").write_text(
        "KeyPath,ValueName,ValueData\n"
        r"x\CurrentVersion\Run,svchost,c:\windows\system32\dllhost\svchost.exe" + "\n",
        encoding="utf-8")
    fs = detect_run_keys(str(d), host_id="h", provenance_id="cmd-r", next_id=_counter())
    assert len(fs) == 1


def test_at_job_flags_at_not_vendor(tmp_path):
    rows = [
        {"EntryNumber": "10", "FileName": "At1.job", "ParentPath": ".\\Windows\\Tasks"},
        {"EntryNumber": "11", "FileName": "At2.job", "ParentPath": ".\\Windows\\Tasks"},
        {"EntryNumber": "12", "FileName": "GoogleUpdateTaskUser.job", "ParentPath": ".\\Windows\\Tasks"},
        {"EntryNumber": "13", "FileName": "AppleSoftwareUpdate.job", "ParentPath": ".\\WINDOWS\\Tasks"},
    ]
    fs = detect_scheduled_at_jobs(_mft(tmp_path, rows), host_id="h", provenance_id="cmd-m", next_id=_counter())
    titles = sorted(f.title for f in fs)
    assert len(fs) == 2 and "At1.job" in titles[0] and "At2.job" in titles[1]


# --------------------------------------------------------------------------- #
# DC 4672 — privileged logon, tied to a lateral actor, off SubjectUserName
# --------------------------------------------------------------------------- #
_EVTX_COLS = ["EventRecordId", "TimeCreated", "EventId", "PayloadData1", "ExecutableInfo", "Payload"]


def _evtx(tmp_path, rows):
    p = tmp_path / "evtx.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(_EVTX_COLS)
        w.writerows(rows)
    return str(p)


def _rdp_payload(user, ip):
    return json.dumps({"EventData": {"Data": [
        {"@Name": "TargetUserName", "#text": user},
        {"@Name": "LogonType", "#text": "10"},
        {"@Name": "IpAddress", "#text": ip},
    ]}})


def _4672_payload(subject):
    return json.dumps({"EventData": {"Data": [
        {"@Name": "SubjectUserName", "#text": subject},
        {"@Name": "PrivilegeList", "#text": "SeDebugPrivilege"},
    ]}})


def test_4672_only_for_lateral_actor(tmp_path):
    rows = [
        # vibranium does Type-10 RDP -> a lateral actor
        ["1", "2012-04-04 18:17:53", "4624", "", "", _rdp_payload("vibranium", "10.3.58.7")],
        # 4672 for vibranium (lateral actor) -> flagged; for 'backupsvc' (not lateral) -> ignored
        ["2", "2012-04-04 18:17:53", "4672", "", "", _4672_payload("vibranium")],
        ["3", "2012-04-04 18:17:53", "4672", "", "", _4672_payload("vibranium")],
        ["4", "2012-04-04 03:00:00", "4672", "", "", _4672_payload("backupsvc")],
        ["5", "2012-04-04 03:00:00", "4672", "", "", _4672_payload("CONTROLLER$")],  # machine acct
    ]
    fs, _ = analyze_dc_events(_evtx(tmp_path, rows), host_id="dc", provenance_id="cmd-e", next_id=_counter())
    priv = [f for f in fs if f.rule == "dc_events.privileged_logon"]
    assert len(priv) == 1
    assert "vibranium" in priv[0].title and "4672" in priv[0].evidence[0].note
    assert "×2" in priv[0].description or "2×" in priv[0].description or "2" in priv[0].description


# --------------------------------------------------------------------------- #
# Regression: downstream artifacts (exfil archive, at-job) must NOT anchor
# patient zero — their timestamps (late-stage / OS-install) mis-pin it.
# --------------------------------------------------------------------------- #
def test_patient_zero_anchors_skip_downstream_artifacts():
    from dfir_agent.nodes.timeline import _anchor_dirs
    from dfir_agent.state import CaseState, Confidence, EvidenceReference, Finding

    def _f(cat, rule, path):
        return Finding(finding_id="F", host_id="h", title=cat, category=cat, description="d",
                       confidence=Confidence.suspicious, rule=rule, paths=[path],
                       evidence=[EvidenceReference(provenance_id="cmd-x")])

    st = CaseState(case_id="c", case_root="/tmp")
    st.findings = [
        _f("process_masquerade", "suspicious_process.path", r"c:\windows\system32\dllhost\svchost.exe"),
        _f("exfil", "exfil.staged_archive", r"c:\users\public\temp\system4.rar"),
        _f("persistence", "persistence.at_job", r"c:\windows\tasks\at2.job"),
    ]
    anchors = _anchor_dirs(st)
    assert "dllhost" in anchors            # the implant anchors patient zero
    assert "temp" not in anchors           # the staged exfil archive does NOT
    assert "tasks" not in anchors          # the at-job (OS-install MFT date) does NOT

"""Phase 2: path-masquerade, hidden-process, injection, service rules + family
scoring and per-entity merge. Fixtures mirror the real xp-tdungan data."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.injection import detect_injected_pe  # noqa: E402
from dfir_agent.rules.suspicious_process import (  # noqa: E402
    detect_hidden_processes,
    detect_parent_anomalies,
    detect_path_masquerade,
)
from dfir_agent.rules.suspicious_service import detect_suspicious_services  # noqa: E402
from dfir_agent.scoring import merge_by_entity, score_by_families  # noqa: E402
from dfir_agent.state import Confidence  # noqa: E402


def _counter(start=0):
    n = {"i": start}

    def nxt():
        n["i"] += 1
        return f"F-{n['i']:04d}"

    return nxt


PSLIST = [
    {"PID": 1044, "PPID": 1000, "ImageFileName": "services.exe"},
    {"PID": 1900, "PPID": 2436, "ImageFileName": "explorer.exe"},
    {"PID": 3296, "PPID": 1900, "ImageFileName": "svchost.exe"},
]
CMDLINE = [
    {"PID": 1236, "Process": "svchost.exe", "Args": '"C:\\WINDOWS\\system32\\svchost.exe" -k netsvcs'},
    {"PID": 3296, "Process": "svchost.exe", "Args": '"C:\\windows\\system32\\dllhost\\svchost.exe" '},
]
PSSCAN = [
    {"PID": 3296, "PPID": 1900, "ImageFileName": "svchost.exe", "ExitTime": None},  # also live
    {"PID": 12244, "PPID": 5872, "ImageFileName": "spinlock.exe", "ExitTime": None},  # hidden
    {"PID": 11640, "PPID": 12236, "ImageFileName": "spinlock.exe", "ExitTime": "2012-04-06T18:58:17+00:00"},
]
MALFIND = [
    # noise: RWX but no MZ -> must NOT flag
    {"PID": 1000, "Process": "winlogon.exe", "Protection": "PAGE_EXECUTE_READWRITE",
     "PrivateMemory": 1, "Hexdump": "90 90 90 90"},
    # implant: private RWX + MZ -> flag
    {"PID": 3296, "Process": "svchost.exe", "Protection": "PAGE_EXECUTE_READWRITE",
     "PrivateMemory": 1, "Hexdump": "4d 5a 90 00 03 00 00 00", "Start VPN": 19070976},
    {"PID": 3296, "Process": "svchost.exe", "Protection": "PAGE_EXECUTE_READWRITE",
     "PrivateMemory": 1, "Hexdump": "4d 5a 90 00", "Start VPN": 19070977},
]


def test_path_masquerade_flags_only_dllhost_svchost():
    f = detect_path_masquerade(CMDLINE, host_id="h", provenance_id="cmd-c", artifact_path=None, next_id=_counter())
    pids = [int(e.record_id.split("=")[1]) for x in f for e in x.evidence]
    assert pids == [3296]
    assert f[0].evidence[0].source_family == "command_line"


def test_hidden_process_flags_nonexited_psscan_only():
    f = detect_hidden_processes(PSSCAN, PSLIST, host_id="h", provenance_id="cmd-p", artifact_path=None, next_id=_counter())
    pids = sorted(int(e.record_id.split("=")[1]) for x in f for e in x.evidence)
    # 3296 is live (in pslist), 11640 has an exit time -> only 12244 qualifies.
    assert pids == [12244]
    assert f[0].category == "hidden_process"


def test_injection_flags_mz_private_rwx_only():
    f = detect_injected_pe(MALFIND, host_id="h", provenance_id="cmd-m", artifact_path=None, next_id=_counter())
    pids = sorted(int(e.record_id.split("=")[1]) for x in f for e in x.evidence)
    assert pids == [3296]  # winlogon noise (no MZ) excluded
    assert f[0].evidence[0].source_family == "injection"
    assert "2" in f[0].description  # counted both MZ regions


def test_merge_promotes_implant_to_confirmed():
    nxt = _counter()
    raw = []
    raw += detect_parent_anomalies(PSLIST, host_id="h", provenance_id="cmd-pl", artifact_path=None, next_id=nxt)
    raw += detect_path_masquerade(CMDLINE, host_id="h", provenance_id="cmd-c", artifact_path=None, next_id=nxt)
    raw += detect_injected_pe(MALFIND, host_id="h", provenance_id="cmd-m", artifact_path=None, next_id=nxt)
    merged = merge_by_entity(raw)
    implant = [m for m in merged if m.entity_key == "pid:3296"]
    assert len(implant) == 1
    f = implant[0]
    fams = {e.source_family for e in f.evidence}
    assert fams == {"process_tree", "command_line", "injection"}
    assert f.confidence is Confidence.confirmed
    assert f.source_count == 3


def test_score_by_families_tiers():
    assert score_by_families({"process_tree", "injection"}) is Confidence.confirmed
    assert score_by_families({"injection"}) is Confidence.likely  # one strong family
    assert score_by_families({"process_tree"}) is Confidence.suspicious  # one identity family
    assert score_by_families(set()) is Confidence.false_positive


def test_lone_hidden_process_stays_suspicious():
    f = detect_hidden_processes(PSSCAN, PSLIST, host_id="h", provenance_id="cmd-p", artifact_path=None, next_id=_counter())
    merged = merge_by_entity(f)
    assert all(m.confidence is Confidence.suspicious for m in merged)


# --- false-positive regressions (real xp-tdungan legitimate forms) --- #

def test_no_fp_on_legitimate_system_paths():
    # smss via \SystemRoot, winlogon as a bare name -> must NOT be flagged.
    rows = [
        {"PID": 876, "Process": "smss.exe", "Args": "\\SystemRoot\\System32\\smss.exe"},
        {"PID": 1000, "Process": "winlogon.exe", "Args": "winlogon.exe"},
        {"PID": 788, "Process": "winlogon.exe", "Args": "\\??\\C:\\WINDOWS\\system32\\winlogon.exe"},
        {"PID": 1236, "Process": "svchost.exe", "Args": '"C:\\WINDOWS\\system32\\svchost.exe" -k netsvcs'},
    ]
    f = detect_path_masquerade(rows, host_id="h", provenance_id="c", artifact_path=None, next_id=_counter())
    assert f == []


def test_no_fp_on_system32_hosted_services():
    # Eventlog/SamSs hosted by services.exe / lsass.exe IN system32 are legitimate.
    rows = [
        {"Name": "Eventlog", "PID": 1044, "State": "RUNNING", "Binary": "C:\\WINDOWS\\system32\\services.exe"},
        {"Name": "SamSs", "PID": 736, "State": "RUNNING", "Binary": "C:\\WINDOWS\\system32\\lsass.exe"},
        # genuinely malicious: system name outside system32, and a temp-dir binary.
        {"Name": "EvilSvc", "PID": 4000, "State": "RUNNING", "Binary": "C:\\WINDOWS\\system32\\dllhost\\svchost.exe"},
        {"Name": "DropperSvc", "PID": 4001, "State": "RUNNING", "Binary": "C:\\Temp\\payload.exe"},
    ]
    f = detect_suspicious_services(rows, host_id="h", provenance_id="c", artifact_path=None, next_id=_counter())
    names = sorted(x.title for x in f)
    assert len(f) == 2
    assert any("EvilSvc" in n for n in names) and any("DropperSvc" in n for n in names)

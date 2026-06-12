"""Phase 5: contradiction detection, benign-binary allowlist, MFT name search,
and the self-correction recheck-name logic."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.decisions import DecisionLog  # noqa: E402
from dfir_agent.nodes import NodeContext  # noqa: E402
from dfir_agent.nodes.correlation import _needs_recheck  # noqa: E402
from dfir_agent.nodes.disk_recheck import disk_recheck  # noqa: E402
from dfir_agent.rules.benign_allowlist import is_benign_windows_binary  # noqa: E402
from dfir_agent.rules.contradiction import detect_timestomp_contradictions  # noqa: E402
from dfir_agent.rules.disk_artifacts import search_mft_by_name  # noqa: E402
from dfir_agent.state import (  # noqa: E402
    CaseState, Confidence, EvidenceReference, Finding, Host, HostRole, ToolResult, ToolResultStatus,
)

IMPLANT = "c:\\windows\\system32\\dllhost\\svchost.exe"


def _counter():
    n = {"i": 0}

    def nxt():
        n["i"] += 1
        return f"C-{n['i']:04d}"

    return nxt


def test_benign_windows_binary():
    assert is_benign_windows_binary("cmd.exe") is True
    assert is_benign_windows_binary("CMD.EXE") is True
    assert is_benign_windows_binary("spinlock.exe") is False


def test_timestomp_contradiction_resolves_to_fn():
    f = Finding(
        finding_id="F-1", host_id="h", title="implant", category="code_injection",
        confidence=Confidence.confirmed, paths=[IMPLANT], description="d", tags=["timestomped"],
        evidence=[EvidenceReference(
            provenance_id="cmd-mft", record_id="MFT#3022", source_family="disk_mft",
            note="$MFT entry 3022: ... FN-created=2012-04-03 00:35:02 SI-created=2003-03-31 12:00:00 [timestomp]",
        )],
    )
    cs = detect_timestomp_contradictions([f], host_id="h", next_id=_counter())
    assert len(cs) == 1
    c = cs[0]
    assert "2012-04-03" in c.source_b and "2003-03-31" in c.source_a
    assert "authoritative" in c.resolution.lower()
    assert c.evidence[0].provenance_id == "cmd-mft"


def test_no_timestomp_without_tag():
    f = Finding(
        finding_id="F-2", host_id="h", title="x", category="code_injection",
        confidence=Confidence.suspicious, description="d", evidence=[],
    )
    assert detect_timestomp_contradictions([f], host_id="h", next_id=_counter()) == []


MFT_CSV = (
    "EntryNumber,ParentPath,FileName,FileSize\n"
    "7793,.\\WINDOWS\\system32,spinlock.exe,2271885\n"
    "41259,.\\WINDOWS\\system32,cmd.exe,389120\n"
    "44513,.\\WINDOWS\\ServicePackFiles\\i386,cmd.exe,389120\n"
)


def test_search_mft_by_name(tmp_path):
    csv = tmp_path / "mft.csv"
    csv.write_text(MFT_CSV, encoding="utf-8")
    hits = search_mft_by_name(str(csv), {"spinlock.exe", "cmd.exe", "absent.exe"})
    assert len(hits["spinlock.exe"]) == 1
    assert hits["spinlock.exe"][0]["parent"] == "c:\\windows\\system32"
    assert hits["spinlock.exe"][0]["full"] == "c:\\windows\\system32\\spinlock.exe"
    assert len(hits["cmd.exe"]) == 2
    assert hits["absent.exe"] == []


def test_disk_recheck_disputes_benign_binary_despite_orphan_entry(tmp_path):
    # wmiprvse.exe present in signed system32\wbem AND an orphaned deleted-copy
    # entry. The orphan must NOT flip a first-party binary to "malicious".
    mft = tmp_path / "mft.csv"
    mft.write_text(
        "EntryNumber,ParentPath,FileName,FileSize\n"
        "144245,.\\Windows\\System32\\wbem,WmiPrvSE.exe,368640\n"
        "109217,.\\PathUnknown\\Directory with ID 0x0000FD5F,WmiPrvSE.exe,368640\n",
        encoding="utf-8",
    )
    hidden = Finding(
        finding_id="F-9", host_id="win7-64-nfury", title="hidden WmiPrvSE", category="hidden_process",
        confidence=Confidence.suspicious, description="d",
        tags=["memory", "psscan", "hidden", "WmiPrvSE.exe"],
        evidence=[EvidenceReference(provenance_id="cmd-ps", record_id="PID=2508", source_family="process_tree")],
    )
    s = CaseState(case_id="srl2015", case_root=str(tmp_path))
    s.current_host = "win7-64-nfury"
    s.hosts = {"win7-64-nfury": Host(host_id="win7-64-nfury", role=HostRole.workstation, disk_image="/x.E01")}
    s.findings = [hidden]
    s.recheck_names = ["WmiPrvSE.exe"]
    s.tool_results = [ToolResult(tool="parse_mft", status=ToolResultStatus.success,
                                 provenance_id="cmd-mft", host_id="win7-64-nfury", output_paths=[str(mft)])]
    ctx = NodeContext(client=None, decisions=DecisionLog(str(tmp_path), "srl2015", "win7-64-nfury"),
                      case_root=str(tmp_path))

    asyncio.run(disk_recheck(s, ctx))

    # disputed, not escalated: no disk_mft evidence added, tagged benign, contradiction emitted.
    assert "benign_binary_confirmed" in hidden.tags
    assert all(e.source_family != "disk_mft" for e in hidden.evidence)
    assert any("WmiPrvSE" in c.claim for c in s.contradictions)
    assert "not malware" in s.contradictions[0].resolution.lower() or "first-party" in s.contradictions[0].resolution.lower()


def test_needs_recheck_picks_uncorroborated_suspicious_processes():
    hidden = Finding(
        finding_id="F-3", host_id="h", title="hidden spinlock", category="hidden_process",
        confidence=Confidence.suspicious, description="d", tags=["memory", "psscan", "hidden", "spinlock.exe"],
        evidence=[EvidenceReference(provenance_id="cmd-p", record_id="PID=12244", source_family="process_tree")],
    )
    already = Finding(
        finding_id="F-4", host_id="h", title="hidden cmd", category="hidden_process",
        confidence=Confidence.suspicious, description="d",
        tags=["memory", "hidden", "cmd.exe", "benign_binary_confirmed"],
        evidence=[EvidenceReference(provenance_id="cmd-p", record_id="PID=9448", source_family="process_tree")],
    )
    names = _needs_recheck([hidden, already])
    assert names == {"spinlock.exe"}  # cmd.exe already reconciled -> excluded

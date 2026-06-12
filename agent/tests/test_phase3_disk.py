"""Phase 3: MFT/shimcache correlation + cross-source (memory<->disk) fusion.
Fixtures mirror the real xp-tdungan disk rows."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.disk_artifacts import correlate_mft, correlate_shimcache  # noqa: E402
from dfir_agent.rules.winpath import mft_full_path, normalize_winpath  # noqa: E402
from dfir_agent.scoring import correlate_findings  # noqa: E402
from dfir_agent.state import Confidence, EvidenceReference, Finding  # noqa: E402

IMPLANT = "c:\\windows\\system32\\dllhost\\svchost.exe"

MFT_CSV = (
    "EntryNumber,ParentPath,FileName,FileSize,Created0x10,Created0x30\n"
    # implant: SI-created 2003 precedes FN-created 2012 -> timestomp
    "3022,.\\WINDOWS\\system32\\dllhost,svchost.exe,102400,2003-03-31 12:00:00.0000000,2012-04-03 00:35:03.8741672\n"
    "3023,.\\WINDOWS\\system32\\dllhost,winclient.reg,342,2012-04-03 00:35:10.3747496,2012-04-03 00:35:10.3747496\n"
    "29,.\\WINDOWS,system32,0,2003-03-31 12:00:00.0000000,2003-03-31 12:00:00.0000000\n"
)
SHIM_CSV = (
    "ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate,SourceFile\n"
    "1,49,C:\\WINDOWS\\system32\\dllhost\\svchost.exe,2008-04-14 00:12:36,NA,False,/x/SYSTEM\n"
)


def _counter():
    n = {"i": 0}

    def nxt():
        n["i"] += 1
        return f"F-{n['i']:04d}"

    return nxt


def test_winpath_mft_normalization():
    assert mft_full_path(".\\WINDOWS\\system32\\dllhost", "svchost.exe") == IMPLANT
    assert normalize_winpath("C:\\WINDOWS\\system32\\dllhost\\svchost.exe") == IMPLANT


def test_mft_correlation_flags_implant_with_timestomp_and_sibling(tmp_path):
    csv = tmp_path / "mft.csv"
    csv.write_text(MFT_CSV, encoding="utf-8")
    f = correlate_mft(str(csv), {IMPLANT}, host_id="h", provenance_id="cmd-mft", next_id=_counter())
    assert len(f) == 1
    fnd = f[0]
    assert fnd.paths == [IMPLANT]
    assert fnd.evidence[0].source_family == "disk_mft"
    assert "timestomped" in fnd.tags
    assert "winclient.reg" in fnd.description  # co-located config surfaced


def test_mft_correlation_resolves_entry_with_bom(tmp_path):
    # MFTECmd writes a UTF-8 BOM before the first column; record_id must still resolve.
    csv = tmp_path / "mft.csv"
    csv.write_bytes(b"\xef\xbb\xbf" + MFT_CSV.encode("utf-8"))
    f = correlate_mft(str(csv), {IMPLANT}, host_id="h", provenance_id="cmd-mft", next_id=_counter())
    assert f and f[0].evidence[0].record_id == "MFT#3022"


def test_mft_correlation_ignores_unrelated_paths(tmp_path):
    csv = tmp_path / "mft.csv"
    csv.write_text(MFT_CSV, encoding="utf-8")
    f = correlate_mft(str(csv), {"c:\\windows\\system32\\notepad.exe"}, host_id="h", provenance_id="c", next_id=_counter())
    assert f == []


def test_shimcache_correlation_flags_execution(tmp_path):
    csv = tmp_path / "shimcache.csv"
    csv.write_text(SHIM_CSV, encoding="utf-8")
    f = correlate_shimcache(str(csv), {IMPLANT}, host_id="h", provenance_id="cmd-sc", next_id=_counter())
    assert len(f) == 1
    assert f[0].evidence[0].source_family == "disk_shimcache"
    assert f[0].paths == [IMPLANT]


def test_cross_source_fusion_to_confirmed():
    # memory finding about PID 3296 carrying the implant path...
    mem = Finding(
        finding_id="F-0001", host_id="h", title="Injected PE (PID 3296)", category="code_injection",
        entity_key="pid:3296", paths=[IMPLANT], description="mem",
        confidence=Confidence.likely, source_count=1,
        evidence=[EvidenceReference(provenance_id="cmd-m", record_id="PID=3296", source_family="injection")],
    )
    # ...fuses with disk findings keyed by the same path.
    disk_mft = Finding(
        finding_id="F-0002", host_id="h", title="On-disk file", category="dropped_file",
        entity_key=f"path:{IMPLANT}", paths=[IMPLANT], description="mft",
        confidence=Confidence.likely, source_count=1,
        evidence=[EvidenceReference(provenance_id="cmd-mft", record_id="MFT#3022", source_family="disk_mft")],
    )
    disk_shim = Finding(
        finding_id="F-0003", host_id="h", title="Execution record", category="execution_record",
        entity_key=f"path:{IMPLANT}", paths=[IMPLANT], description="shim",
        confidence=Confidence.likely, source_count=1,
        evidence=[EvidenceReference(provenance_id="cmd-sc", record_id="shimcache#49", source_family="disk_shimcache")],
    )
    merged = correlate_findings([mem, disk_mft, disk_shim])
    assert len(merged) == 1
    f = merged[0]
    fams = {e.source_family for e in f.evidence}
    assert fams == {"injection", "disk_mft", "disk_shimcache"}
    assert f.confidence is Confidence.confirmed
    assert f.source_count == 3
    assert f.category == "code_injection"  # highest-priority lead retained

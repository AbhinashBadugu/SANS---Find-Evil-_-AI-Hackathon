"""Phase 3 — strings / PE metadata / PyInstaller / PDB / embedded URLs.

Tool layer is tested on byte-blob fixtures (string-level tools) and a real PE
when one is available on the box (pefile path). The rule layer is tested on
synthetic tool-output dicts — behaviour, not IOCs.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "mcp_server"))

from dfir_agent.rules.pe_indicators import pe_indicator_findings  # noqa: E402


@pytest.fixture()
def mcp_roots(tmp_path, monkeypatch):
    fpaths = pytest.importorskip("forensic_mcp.paths")
    ev, case = tmp_path / "evidence", tmp_path / "case"
    ev.mkdir(); case.mkdir()
    monkeypatch.setattr(fpaths, "EVIDENCE_ROOT", ev.resolve())
    monkeypatch.setattr(fpaths, "CASE_ROOT", case.resolve())
    return ev, case


# --------------------------------------------------------------------------- #
# Tool layer — string-level tools on a byte blob
# --------------------------------------------------------------------------- #
def test_string_tools_on_blob(mcp_roots):
    from forensic_mcp.schemas import ExtractStringsRequest, FileToolRequest
    from forensic_mcp.wrappers.pe_strings import (
        detect_pyinstaller, extract_embedded_urls, extract_pdb_paths, extract_strings,
    )
    ev, _ = mcp_roots
    blob = (b"MZ\x90\x00" + b"\x00" * 64
            + b"PyInstaller\x00pyiboot01_bootstrap\x00python27.dll\x00"
            + b"http://c2.example/ads/\x00"
            + b"203.0.113.9:443\x00"
            + b"C:\\build\\proj\\implant.pdb\x00"
            + b"InternetOpenA\x00HttpSendRequestA\x00")
    f = ev / "sample.bin"
    f.write_bytes(blob)

    pyi = detect_pyinstaller(FileToolRequest(case_id="d", host_id="h", file_path=f))
    assert pyi.is_pyinstaller and "PyInstaller" in pyi.markers

    urls = extract_embedded_urls(FileToolRequest(case_id="d", host_id="h", file_path=f))
    assert "http://c2.example/ads/" in urls.urls
    assert any(ip.startswith("203.0.113.9") for ip in urls.ips)

    pdb = extract_pdb_paths(FileToolRequest(case_id="d", host_id="h", file_path=f))
    assert any(p.lower().endswith("implant.pdb") for p in pdb.pdb_paths)

    s = extract_strings(ExtractStringsRequest(case_id="d", host_id="h", file_path=f))
    assert s.status.value == "success"
    assert any("http://c2.example" in i for i in s.interesting)


def test_pe_metadata_on_real_pe(mcp_roots):
    """If a real PE is present on the box, confirm pefile parsing returns structure."""
    pytest.importorskip("pefile")
    ev, _ = mcp_roots
    candidates = list(Path("/opt/zimmermantools").rglob("*.dll")) if Path("/opt/zimmermantools").exists() else []
    if not candidates:
        pytest.skip("no PE available on this box to parse")
    src = candidates[0]
    dst = ev / src.name
    shutil.copy(src, dst)
    from forensic_mcp.schemas import FileToolRequest
    from forensic_mcp.wrappers.pe_strings import extract_pe_metadata
    r = extract_pe_metadata(FileToolRequest(case_id="d", host_id="h", file_path=dst))
    assert r.status.value == "success" and r.is_pe
    assert r.machine and r.sections  # parsed real structure


# --------------------------------------------------------------------------- #
# Rule layer — synthetic tool outputs
# --------------------------------------------------------------------------- #
def test_rule_flags_packed_c2_masquerade_and_caps():
    path = r"\Windows\system32\dllhost\svchost.exe"   # generic masquerade pattern
    findings = pe_indicator_findings(
        host_id="h1", file_path=path,
        pe={"is_pe": True, "provenance_id": "cmd-1",
            "suspicious_imports": ["wininet.dll!InternetOpenA", "kernel32.dll!WriteProcessMemory",
                                   "dbghelp.dll!MiniDumpWriteDump"],
            "pdb_path": r"C:\dev\rat\winclient.pdb"},
        pyinstaller={"is_pyinstaller": True, "markers": ["PyInstaller"], "provenance_id": "cmd-2"},
        embedded={"urls": ["http://198.51.100.7/ads/"], "ips": [], "provenance_id": "cmd-3"},
    )
    cats = {f.category for f in findings}
    assert "packed_executable" in cats
    assert "embedded_c2" in cats
    assert "beacon_capability" in cats
    assert "injection_capability" in cats
    assert "creddump_capability" in cats
    assert "masquerade_path" in cats
    assert "pdb_attribution" in cats
    # masquerade path -> non-benign -> embedded C2 is 'likely'
    c2 = next(f for f in findings if f.category == "embedded_c2")
    assert c2.confidence.value == "likely"
    assert c2.evidence[0].provenance_id == "cmd-3"


def test_rule_handles_empty_pdb_paths_without_crashing():
    # Regression: extract_pdb_paths returning {"pdb_paths": []} must not IndexError.
    findings = pe_indicator_findings(
        host_id="h1", file_path=r"\Windows\system32\dllhost\x.exe",
        pe={"is_pe": True, "provenance_id": "cmd-1", "suspicious_imports": [], "pdb_path": None},
        pdb={"pdb_paths": [], "provenance_id": "cmd-2"},
        embedded={"urls": [], "ips": []},
    )
    assert isinstance(findings, list)  # no exception; masquerade still flagged
    assert any(f.category == "masquerade_path" for f in findings)


def test_rule_signed_location_downgrades_pyinstaller():
    findings = pe_indicator_findings(
        host_id="h1", file_path=r"C:\Program Files\Vendor\app.exe",
        pyinstaller={"is_pyinstaller": True, "markers": ["PyInstaller"], "provenance_id": "cmd-9"},
    )
    pk = next(f for f in findings if f.category == "packed_executable")
    assert pk.confidence.value == "suspicious"   # benign location -> not promoted

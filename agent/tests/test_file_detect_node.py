"""file_detect node — proves the carve→parse→rule chain emits java/PE/registry
findings, using a stub MCP client (no real image) + a fixture MFT.
"""

from __future__ import annotations

import asyncio
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.decisions import DecisionLog  # noqa: E402
from dfir_agent.nodes import NodeContext  # noqa: E402
from dfir_agent.nodes.file_detect import run_file_detections  # noqa: E402
from dfir_agent.state import CaseState, Host, HostRole  # noqa: E402

JAVA_IDX = r"\Users\v\AppData\LocalLow\Sun\Java\Deployment\cache\6.0\1\abc.idx"
SUS_EXE = r"\Windows\System32\dllhost\svchost.exe"
REG = r"\Users\v\Desktop\winclient.reg"
DROP = "aB9xQ2.exe"


def _write_mft(path: Path):
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["FileName", "ParentPath", "EntryNumber", "Created0x10"])
        w.writeheader()
        w.writerow({"FileName": "abc.idx", "ParentPath": r"\Users\v\AppData\LocalLow\Sun\Java\Deployment\cache\6.0\1", "EntryNumber": "10"})
        w.writerow({"FileName": "svchost.exe", "ParentPath": r"\Windows\System32\dllhost", "EntryNumber": "11"})
        w.writerow({"FileName": "winclient.reg", "ParentPath": r"\Users\v\Desktop", "EntryNumber": "12"})
        w.writerow({"FileName": DROP, "ParentPath": r"\Users\v\AppData\Local\Temp", "EntryNumber": "13"})


class FakeClient:
    async def call(self, tool, **kw):
        if tool == "carve_files":
            return {"carved": {p: f"/carved/{i}" for i, p in enumerate(kw["paths"])},
                    "output_dir": "/carved", "provenance_id": "cmd-carve"}
        if tool == "parse_java_cache":
            return {"records": [{"idx_path": "abc.idx", "jar_urls": ["http://attacker/Loader.jar"],
                                 "payload_urls": [f"http://attacker/gw/{DROP}"]}],
                    "provenance_id": "cmd-java"}
        if tool == "extract_pe_metadata":
            return {"is_pe": True, "provenance_id": "cmd-pe",
                    "suspicious_imports": ["wininet.dll!InternetOpenA", "dbghelp.dll!MiniDumpWriteDump"],
                    "pdb_path": r"C:\dev\rat\winclient.pdb"}
        if tool == "detect_pyinstaller":
            return {"is_pyinstaller": True, "markers": ["PyInstaller"], "provenance_id": "cmd-pyi"}
        if tool == "extract_embedded_urls":
            return {"urls": ["http://198.51.100.7/ads/"], "ips": [], "provenance_id": "cmd-url"}
        if tool == "extract_pdb_paths":
            return {"pdb_paths": [], "provenance_id": "cmd-pdb"}
        if tool == "hash_file":
            return {"status": "success", "hashes": {"sha256": "a" * 64}, "provenance_id": "cmd-hash"}
        if tool == "parse_reg_export":
            return {"entries": [{"key": r"HKLM\...\Netman\domain", "value_name": "server",
                                 "value_type": "REG_SZ", "urls": ["http://198.51.100.5/ads/"], "ips": []}],
                    "provenance_id": "cmd-reg"}
        return {}


def test_file_detect_emits_java_pe_registry(tmp_path):
    mft = tmp_path / "mft.csv"
    _write_mft(mft)
    state = CaseState(case_id="demo", case_root=str(tmp_path))
    host = Host(host_id="h1", os="Windows", role=HostRole.workstation)
    state.hosts = {"h1": host}
    state.current_host = "h1"
    ctx = NodeContext(client=FakeClient(), decisions=DecisionLog(str(tmp_path), "demo", "h1"), case_root=str(tmp_path))

    n = asyncio.run(run_file_detections(state, ctx, host, ewf1="/img/ewf1", mft_csv=str(mft)))
    cats = {f.category for f in state.findings}
    assert n > 0
    assert "initial_access" in cats        # Java drive-by + download->drop
    assert "embedded_c2" in cats           # PE embedded URL
    assert "masquerade_path" in cats       # system32\dllhost\svchost.exe
    assert "c2_config" in cats             # registry Netman\domain -> URL
    # the Java payload was correlated to the dropped file on disk
    assert any("Java download landed on disk" in f.title for f in state.findings)

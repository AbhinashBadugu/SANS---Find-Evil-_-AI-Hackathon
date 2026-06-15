"""Phase 4 — registry export (UTF-16) decode + C2-config extraction + rule.

Builds a UTF-16LE .reg export (the winclient.reg-style pattern, generic name is
fine in tests) with a REG_SZ URL, a beacon-interval DWORD, and a hex(2)
REG_EXPAND_SZ value holding a UTF-16 URL. Confirms decode, C2 filtering, and the
behavioural rule.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "mcp_server"))

from dfir_agent.rules.registry_config import suspicious_registry_c2  # noqa: E402


def _hex2(value: str) -> str:
    raw = value.encode("utf-16le") + b"\x00\x00"
    return "hex(2):" + ",".join(f"{b:02x}" for b in raw)


@pytest.fixture()
def mcp_roots(tmp_path, monkeypatch):
    fpaths = pytest.importorskip("forensic_mcp.paths")
    ev, case = tmp_path / "evidence", tmp_path / "case"
    ev.mkdir(); case.mkdir()
    monkeypatch.setattr(fpaths, "EVIDENCE_ROOT", ev.resolve())
    monkeypatch.setattr(fpaths, "CASE_ROOT", case.resolve())
    return ev, case


def _write_reg(ev: Path) -> Path:
    text = (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Netman\\domain]\r\n"
        '"server"="http://198.51.100.5/ads/"\r\n'
        '"interval"=dword:0000003c\r\n'
        f'"expand"={_hex2("http://203.0.113.8/gate")}\r\n'
    )
    f = ev / "winclient.reg"
    f.write_bytes(b"\xff\xfe" + text.encode("utf-16le"))
    return f


def test_parse_reg_export_decodes_and_extracts(mcp_roots):
    from forensic_mcp.schemas import RegExportRequest
    from forensic_mcp.wrappers.registry_config import extract_c2_from_registry, parse_reg_export
    ev, _ = mcp_roots
    reg = _write_reg(ev)

    parsed = parse_reg_export(RegExportRequest(case_id="d", host_id="h", reg_path=reg))
    assert parsed.status.value == "success"
    by_name = {e.value_name: e for e in parsed.entries}
    assert "http://198.51.100.5/ads/" in by_name["server"].urls
    assert by_name["interval"].intervals == [60]
    # hex(2) REG_EXPAND_SZ decoded from UTF-16 hex bytes
    assert any("203.0.113.8" in u for u in by_name["expand"].urls)

    c2 = extract_c2_from_registry(RegExportRequest(case_id="d", host_id="h", reg_path=reg))
    assert c2.status.value == "success"
    assert {e.value_name for e in c2.c2_entries} >= {"server", "expand"}
    assert all(e.urls or e.ips for e in c2.c2_entries)


def test_rule_flags_registry_c2(mcp_roots):
    from forensic_mcp.schemas import RegExportRequest
    from forensic_mcp.wrappers.registry_config import parse_reg_export
    ev, _ = mcp_roots
    reg = _write_reg(ev)
    parsed = parse_reg_export(RegExportRequest(case_id="d", host_id="h", reg_path=reg))

    findings = suspicious_registry_c2([e.model_dump() for e in parsed.entries],
                                      host_id="h", provenance_id=parsed.provenance_id)
    assert findings, "registry C2 config should be flagged"
    f = next(f for f in findings if "198.51.100.5" in f.description)
    assert f.category == "c2_config"
    assert f.confidence.value == "likely"
    assert f.evidence[0].provenance_id == parsed.provenance_id


def test_no_network_value_not_flagged():
    entries = [{"key": "HKLM\\X", "value_name": "Foo", "value_type": "REG_SZ",
                "decoded_data": "just a string", "urls": [], "ips": []}]
    assert suspicious_registry_c2(entries, host_id="h", provenance_id="cmd-1") == []

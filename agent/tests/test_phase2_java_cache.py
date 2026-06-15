"""Phase 2 — Java deployment cache parsing + drive-by rule.

Builds synthetic .idx files (the version-agnostic string-extraction path), parses
them with the MCP tool, and checks the generic rule flags the remote-JAR +
executable-payload drive-by and correlates the payload to a file on disk.
No campaign filenames — the fixtures use generic names.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "mcp_server"))

from dfir_agent.rules.java_cache import correlate_download_to_payload, detect_java_drive_by  # noqa: E402


def _idx_bytes(url: str, content_type: str) -> bytes:
    # A minimal .idx-like blob: binary noise + an HTTP header block + the URL.
    return (
        b"\x00\x00\x06\x05idxhdr\x00\x00"
        + f"HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\n"
          f"last-modified: Tue, 03 Apr 2012 00:33:00 GMT\r\nserver: Apache\r\n\r\n".encode()
        + b"\x00\x10" + url.encode("latin-1") + b"\x00\x00"
    )


@pytest.fixture()
def mcp_roots(tmp_path, monkeypatch):
    fpaths = pytest.importorskip("forensic_mcp.paths")
    ev, case = tmp_path / "evidence", tmp_path / "case"
    ev.mkdir(); case.mkdir()
    monkeypatch.setattr(fpaths, "EVIDENCE_ROOT", ev.resolve())
    monkeypatch.setattr(fpaths, "CASE_ROOT", case.resolve())
    return ev, case


def test_parse_and_detect_java_drive_by(mcp_roots):
    from forensic_mcp.schemas import JavaCacheRequest
    from forensic_mcp.wrappers.java_cache import parse_java_cache
    ev, _ = mcp_roots
    cache = ev / "Users" / "user" / "AppData" / "LocalLow" / "Sun" / "Java" / "Deployment" / "cache"
    cache.mkdir(parents=True)
    (cache / "1.idx").write_bytes(_idx_bytes("http://attacker.example/applet/Loader.jar", "application/java-archive"))
    (cache / "2.idx").write_bytes(_idx_bytes("http://attacker.example/gw/aB9xQ2", "application/octet-stream"))

    resp = parse_java_cache(JavaCacheRequest(case_id="demo", host_id="h1", cache_dir=cache))
    assert resp.status.value == "success" and resp.idx_count == 2
    assert any(r.jar_urls for r in resp.records)
    assert any(r.payload_urls for r in resp.records)

    findings = detect_java_drive_by([r.model_dump() for r in resp.records],
                                    host_id="h1", provenance_id=resp.provenance_id)
    assert findings, "drive-by (remote JAR + payload) should be flagged"
    f = findings[0]
    assert f.category == "initial_access"
    assert f.evidence[0].provenance_id == resp.provenance_id
    assert "T1189" in f.mitre_mapping


def test_no_jar_no_driveby():
    # A cache with a payload but NO remote JAR is not a Java drive-by.
    recs = [{"idx_path": "x.idx", "jar_urls": [], "payload_urls": ["http://x/abc123"]}]
    assert detect_java_drive_by(recs, host_id="h1", provenance_id="cmd-1") == []


def test_correlate_download_to_disk_file():
    recs = [{"idx_path": "2.idx", "jar_urls": ["http://x/a.jar"],
             "payload_urls": ["http://attacker.example/gw/aB9xQ2"]}]
    disk = [{"name": "aB9xQ2", "path": r"\Users\user\AppData\Local\Temp\aB9xQ2",
             "ctime": "2012-04-03 00:33", "provenance_id": "cmd-9", "record_id": "MFT#123"}]
    out = correlate_download_to_payload(recs, disk, host_id="h1", provenance_id="cmd-5")
    assert len(out) == 1
    assert out[0].confidence.value == "confirmed"      # idx + MFT = two sources
    assert {e.provenance_id for e in out[0].evidence} == {"cmd-5", "cmd-9"}

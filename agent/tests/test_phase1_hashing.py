"""Phase 1 — universal hashing.

Covers both layers:
  * the detection RULE (rules/hash_correlation) — pure, agent-side
  * the MCP TOOLS (hash_file, compare_hashes_across_hosts) + the ensure_readable
    path gate — exercised end-to-end on a synthetic case in a tmp dir.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))            # agent/
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "mcp_server"))                           # mcp_server/

from dfir_agent.rules.hash_correlation import findings_from_hash_groups  # noqa: E402


# --------------------------------------------------------------------------- #
# Rule layer (pure)
# --------------------------------------------------------------------------- #
def test_shared_binary_flagged_across_hosts():
    groups = [{
        "sha256": "a" * 64, "size": 1024,
        "hosts": ["host-a", "host-b"],
        "paths": [r"\Users\Public\Temp\evil.exe", r"\Windows\system32\dllhost\evil.exe"],
        "provenance_ids": ["cmd-1", "cmd-2"],
    }]
    findings = findings_from_hash_groups(groups)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "shared_binary"
    assert "evil.exe" in f.title
    assert f.confidence.value == "likely"
    assert {e.provenance_id for e in f.evidence} == {"cmd-1", "cmd-2"}
    assert f.source_count == 2


def test_signed_location_only_is_not_flagged():
    groups = [{
        "sha256": "b" * 64, "hosts": ["host-a", "host-b"],
        "paths": [r"C:\Windows\System32\kernel32.dll", r"C:\Windows\System32\kernel32.dll"],
        "provenance_ids": ["cmd-3", "cmd-4"],
    }]
    assert findings_from_hash_groups(groups) == []


def test_single_host_is_not_cross_host():
    groups = [{"sha256": "c" * 64, "hosts": ["host-a"],
               "paths": [r"\Temp\x.exe"], "provenance_ids": ["cmd-5"]}]
    assert findings_from_hash_groups(groups) == []


# --------------------------------------------------------------------------- #
# Tool layer (hash_file + compare_hashes_across_hosts + ensure_readable)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def mcp_roots(tmp_path, monkeypatch):
    """Point the server's read/write roots at a tmp sandbox."""
    fpaths = pytest.importorskip("forensic_mcp.paths")
    ev = tmp_path / "evidence"
    case = tmp_path / "case"
    ev.mkdir()
    case.mkdir()
    monkeypatch.setattr(fpaths, "EVIDENCE_ROOT", ev.resolve())
    monkeypatch.setattr(fpaths, "CASE_ROOT", case.resolve())
    return ev, case


def test_ensure_readable_accepts_both_roots_rejects_outside(mcp_roots, tmp_path):
    from forensic_mcp.paths import ensure_readable, PathValidationError
    ev, case = mcp_roots
    (ev / "x.bin").write_bytes(b"x")
    (case / "y.bin").write_bytes(b"y")
    assert ensure_readable(ev / "x.bin") == (ev / "x.bin").resolve()
    assert ensure_readable(case / "y.bin") == (case / "y.bin").resolve()
    with pytest.raises(PathValidationError):
        ensure_readable(tmp_path / "outside.bin")


def test_hash_file_multi_algo_and_cross_host_compare(mcp_roots):
    from forensic_mcp.schemas import CompareHashesRequest, HashFileRequest
    from forensic_mcp.wrappers.hashing import compare_hashes_across_hosts, hash_file
    ev, _ = mcp_roots

    payload = b"MZ this is the same implant on two hosts" * 50
    (ev / "a").mkdir()
    (ev / "b").mkdir()
    (ev / "c").mkdir()
    (ev / "a" / "evil.exe").write_bytes(payload)
    (ev / "b" / "evil.exe").write_bytes(payload)          # identical -> should correlate
    (ev / "c" / "other.exe").write_bytes(b"different bytes")

    r1 = hash_file(HashFileRequest(case_id="demo", host_id="host-a", file_path=ev / "a" / "evil.exe"))
    assert r1.status.value == "success"
    assert set(r1.hashes) == {"md5", "sha1", "sha256"}
    assert len(r1.hashes["sha256"]) == 64 and r1.size == len(payload)

    r2 = hash_file(HashFileRequest(case_id="demo", host_id="host-b", file_path=ev / "b" / "evil.exe"))
    hash_file(HashFileRequest(case_id="demo", host_id="host-c", file_path=ev / "c" / "other.exe"))
    assert r1.hashes["sha256"] == r2.hashes["sha256"]

    cmp = compare_hashes_across_hosts(CompareHashesRequest(case_id="demo"))
    assert cmp.status.value == "success"
    assert cmp.total_files == 3
    assert len(cmp.shared) == 1                            # only evil.exe is shared
    grp = cmp.shared[0]
    assert grp.sha256 == r1.hashes["sha256"]
    assert sorted(grp.hosts) == ["host-a", "host-b"]
    # and the rule turns that group into a cited cross-host finding
    findings = findings_from_hash_groups([grp])
    assert len(findings) == 1 and findings[0].confidence.value == "likely"

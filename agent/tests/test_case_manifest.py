"""Tests for the Universal Case Manifest Builder (discovery only, metadata-based).

Builds a synthetic case folder with Windows + Linux + macOS hosts (and an
unknown file) in a temp dir, then asserts OS family, capabilities, grouping,
and graceful handling of the unrecognized file. No real evidence, no tools.
"""

from __future__ import annotations

from pathlib import Path

from dfir_agent.case_manifest import (
    classify_evidence_file,
    scan_case_folder,
)
from dfir_agent.state import EvidenceType, HostRole, OSFamily


def _touch(p: Path, data: bytes = b"x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _build_case(root: Path) -> None:
    # --- Windows host ---
    w = root / "win-host"
    for hive in ("SYSTEM", "SOFTWARE", "NTUSER.DAT"):
        _touch(w / hive)
    _touch(w / "Amcache.hve")
    _touch(w / "$MFT")
    _touch(w / "Security.evtx")
    _touch(w / "Prefetch" / "NOTEPAD.EXE-AABBCCDD.pf")
    _touch(w / "win-host-c-drive.E01", b"x" * 4096)
    _touch(w / "win-host-memory.mem", b"x" * 2048)

    # --- Linux host ---
    lx = root / "linux-host"
    _touch(lx / "etc" / "os-release", b"ID=ubuntu\n")
    _touch(lx / "var" / "log" / "auth.log")
    _touch(lx / "var" / "log" / "syslog")
    _touch(lx / "var" / "log" / "journal" / "system.journal")
    _touch(lx / "etc" / "crontab")
    _touch(lx / "etc" / "systemd" / "system" / "evil.service")
    _touch(lx / "home" / "user" / ".bash_history")
    _touch(lx / "linux-host.qcow2", b"x" * 4096)
    _touch(lx / "linux-host-memory.lime", b"x" * 2048)

    # --- macOS host ---
    mac = root / "mac-host"
    _touch(mac / "SystemVersion.plist")
    _touch(mac / "var" / "log" / "system.log")
    _touch(mac / "logs" / "0000000000000030.tracev3")
    _touch(mac / "LaunchDaemons" / "com.evil.agent.plist")
    _touch(mac / "Users" / "alice" / ".zsh_history")
    _touch(mac / "mac-host.dmg", b"x" * 4096)
    _touch(mac / "mac-host-memory.vmem", b"x" * 2048)

    # --- An unrecognized file (must not crash; must land in unassigned) ---
    _touch(root / "mystery.xyz")


def _by_id(manifest):
    return {h.host_id: h for h in manifest.hosts}


def test_detects_three_os_families(tmp_path: Path):
    _build_case(tmp_path)
    m = scan_case_folder(tmp_path, case_id="synthetic")
    hosts = _by_id(m)

    assert {"win-host", "linux-host", "mac-host"} <= set(hosts)
    assert hosts["win-host"].os_family == OSFamily.windows
    assert hosts["linux-host"].os_family == OSFamily.linux
    assert hosts["mac-host"].os_family == OSFamily.macos
    # OS came from multiple corroborating signals -> high confidence.
    assert hosts["win-host"].classification_confidence == "high"
    assert hosts["linux-host"].classification_confidence == "high"
    assert hosts["mac-host"].classification_confidence == "high"


def test_capabilities_set_correctly(tmp_path: Path):
    _build_case(tmp_path)
    hosts = _by_id(scan_case_folder(tmp_path))

    win = hosts["win-host"].evidence_capabilities
    assert win.has_disk and win.has_memory
    assert win.has_event_logs and win.has_registry and win.has_mft

    lx = hosts["linux-host"].evidence_capabilities
    assert lx.has_disk and lx.has_memory
    assert lx.has_network_logs  # auth.log counts as a network/remote-auth log

    mac = hosts["mac-host"].evidence_capabilities
    assert mac.has_disk and mac.has_memory


def test_unknown_file_goes_to_unassigned_and_does_not_crash(tmp_path: Path):
    _build_case(tmp_path)
    m = scan_case_folder(tmp_path)
    paths = [Path(e.evidence_path).name for e in m.unassigned_evidence]
    assert "mystery.xyz" in paths
    # The unknown file must NOT have been grouped into any host.
    for h in m.hosts:
        assert all("mystery.xyz" not in e.evidence_path for e in h.evidence_files)


def test_every_evidence_file_has_a_reason(tmp_path: Path):
    _build_case(tmp_path)
    m = scan_case_folder(tmp_path)
    every = [e for h in m.hosts for e in h.evidence_files] + m.unassigned_evidence
    assert every, "expected discovered evidence"
    assert all(e.classification_reason for e in every)
    # sha256 is never computed at discovery time (that's the MCP hash tool's job).
    assert all(e.sha256 is None for e in every)


def test_ambiguous_raw_is_low_confidence_not_guessed(tmp_path: Path):
    _touch(tmp_path / "blob.raw")          # no token -> ambiguous
    _touch(tmp_path / "server-ram.raw")    # memory token
    _touch(tmp_path / "box-c-drive.raw")   # disk token

    ambiguous = classify_evidence_file(tmp_path / "blob.raw")
    assert ambiguous.evidence_type == EvidenceType.disk_image
    assert ambiguous.classification_confidence == "low"

    mem = classify_evidence_file(tmp_path / "server-ram.raw")
    assert mem.evidence_type == EvidenceType.memory_image
    assert mem.classification_confidence == "medium"

    disk = classify_evidence_file(tmp_path / "box-c-drive.raw")
    assert disk.evidence_type == EvidenceType.disk_image


def test_domain_controller_role_proven_by_ntds(tmp_path: Path):
    dc = tmp_path / "dc01"
    _touch(dc / "NTDS" / "ntds.dit")
    _touch(dc / "SYSTEM")
    _touch(dc / "dc01-c-drive.E01", b"x" * 4096)
    hosts = _by_id(scan_case_folder(tmp_path))
    assert hosts["dc01"].host_role == HostRole.domain_controller
    # A plain workstation with no AD evidence stays 'unknown', not guessed.
    assert hosts["dc01"].os_family == OSFamily.windows


def test_empty_folder_does_not_crash(tmp_path: Path):
    m = scan_case_folder(tmp_path, case_id="empty")
    assert m.hosts == []
    assert m.unassigned_evidence == []
    assert m.case_id == "empty"

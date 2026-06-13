"""Evidence Capability Matrix across Windows/Linux/macOS/network-device, plus the
honest present_but_wrapper_missing behavior. Synthetic files only; metadata-only."""

from __future__ import annotations

from pathlib import Path

from dfir_agent.analyzers import WindowsAnalyzer
from dfir_agent.case_manifest import scan_case_folder
from dfir_agent.state import ArtifactParseStatus, EvidenceCapability, EvidenceType, OSFamily


def _w(p: Path, data: bytes = b"x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _caps(ev_root: Path):
    hosts = {h.host_id: h for h in scan_case_folder(ev_root).hosts}
    return hosts


def test_windows_capability_matrix(tmp_path: Path):
    h = tmp_path / "WKSTN-1"
    _w(h / "Prefetch" / "CALC.EXE-1.pf")
    _w(h / "Amcache.hve")
    _w(h / "Security.evtx")
    _w(h / "Microsoft-Windows-PowerShell%4Operational.evtx")
    _w(h / "Microsoft-Windows-Windows Defender%4Operational.evtx")
    _w(h / "Microsoft-Windows-SMBClient%4Operational.evtx")
    _w(h / "SYSTEM")
    _w(h / "$MFT")
    _w(h / "srudb.dat")
    _w(h / "ConsoleHost_history.txt")
    _w(h / "WebCacheV01.dat")
    _w(h / "Default.rdp")
    _w(h / "SETUPAPI.dev.log")
    _w(h / "System Volume Information" / "store.bin")
    _w(h / "pagefile.sys")
    _w(h / "hiberfil.sys")
    _w(h / "WKSTN-1.E01", b"x" * 64)
    _w(h / "WKSTN-1-memory.mem", b"x" * 64)

    c = _caps(tmp_path)["WKSTN-1"].evidence_capabilities
    for flag in ("has_prefetch", "has_amcache", "has_event_logs", "has_registry", "has_mft",
                 "has_srum", "has_powershell_history", "has_powershell_logs", "has_browser_history",
                 "has_rdp_artifacts", "has_smb_artifacts", "has_usb_artifacts", "has_vss",
                 "has_pagefile", "has_hiberfil", "has_defender_av_edr_logs", "has_disk", "has_memory"):
        assert getattr(c, flag), f"expected {flag} True"


def test_linux_capability_matrix(tmp_path: Path):
    h = tmp_path / "web01"
    _w(h / "etc" / "os-release", b"ID=ubuntu\n")
    _w(h / "var" / "log" / "auth.log")
    _w(h / "var" / "log" / "syslog")
    _w(h / "var" / "log" / "journal" / "sys.journal")
    _w(h / "home" / "u" / ".bash_history")
    _w(h / "etc" / "crontab")

    c = _caps(tmp_path)["web01"].evidence_capabilities
    for flag in ("has_linux_os_release", "has_linux_auth_logs", "has_linux_syslog",
                 "has_linux_journal", "has_linux_shell_history", "has_linux_cron", "has_linux_ssh_logs"):
        assert getattr(c, flag), f"expected {flag} True"


def test_macos_capability_matrix(tmp_path: Path):
    h = tmp_path / "mac01"
    _w(h / "SystemVersion.plist")
    _w(h / "logs" / "0000.tracev3")
    _w(h / "LaunchAgents" / "a.plist")
    _w(h / "LaunchDaemons" / "b.plist")
    _w(h / "Users" / "u" / ".zsh_history")

    c = _caps(tmp_path)["mac01"].evidence_capabilities
    for flag in ("has_macos_systemversion", "has_macos_unified_logs", "has_macos_launchagents",
                 "has_macos_launchdaemons", "has_macos_shell_history", "has_macos_plists"):
        assert getattr(c, flag), f"expected {flag} True"


def test_network_device_capability_matrix_and_family(tmp_path: Path):
    h = tmp_path / "fw01"
    _w(h / "firewall.log")
    _w(h / "vpn.log")
    _w(h / "dns.log")
    _w(h / "dhcp.log")
    _w(h / "netflow.csv")
    _w(h / "capture.pcap")
    _w(h / "running-config.txt")

    host = _caps(tmp_path)["fw01"]
    assert host.os_family == OSFamily.network_device  # routes to NetworkDeviceAnalyzer
    c = host.evidence_capabilities
    for flag in ("has_firewall_logs", "has_vpn_logs", "has_dns_logs", "has_dhcp_logs",
                 "has_netflow", "has_pcap", "has_device_config"):
        assert getattr(c, flag), f"expected {flag} True"


def test_present_but_wrapper_missing_vs_parsed():
    # Prefetch present but no wrapper -> present_but_wrapper_missing.
    # $MFT present + parse_mft wrapper exists -> present_and_parsed.
    caps = EvidenceCapability(has_prefetch=True, has_mft=True, has_amcache=True)
    results = {r.artifact_type: r for r in WindowsAnalyzer().artifact_results("h", caps)}

    pf = results[EvidenceType.windows_prefetch]
    assert pf.status == ArtifactParseStatus.present_but_wrapper_missing
    assert "wrapper is not implemented yet" in pf.reason

    mft = results[EvidenceType.windows_mft]
    assert mft.status == ArtifactParseStatus.present_and_parsed
    assert mft.parser_or_wrapper == "parse_mft"

    # Absent artifact -> not_present (NOT "clean").
    assert results[EvidenceType.windows_srum].status == ArtifactParseStatus.not_present

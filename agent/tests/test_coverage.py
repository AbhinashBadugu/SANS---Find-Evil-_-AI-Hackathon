"""The demonstrable universal coverage surface: routes each host to its family
analyzer and reports honest per-artifact status (parsed / wrapper-missing / absent)."""

from __future__ import annotations

from pathlib import Path

from dfir_agent.case_manifest import scan_case_folder
from dfir_agent.coverage import host_coverage, render_coverage_markdown


def _w(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x")


def _multi_os_case(root: Path) -> None:
    win = root / "WIN-1"
    _w(win / "WIN-1-c-drive.E01")
    _w(win / "WIN-1-memory-raw.001")
    _w(win / "SYSTEM")
    _w(win / "Security.evtx")
    lin = root / "web-srv"
    _w(lin / "etc" / "os-release")
    _w(lin / "var" / "log" / "auth.log")
    fw = root / "fw01"
    _w(fw / "firewall.log")
    _w(fw / "capture.pcap")


def test_coverage_routes_and_reports_honestly(tmp_path: Path):
    _multi_os_case(tmp_path)
    manifest = scan_case_folder(tmp_path, case_id="multi")
    cov = {c["host_id"]: c for c in (host_coverage(h) for h in manifest.hosts)}

    # Windows host: parsed where a wrapper exists; absent reported, never "clean".
    win = cov["WIN-1"]
    assert win["os_family"] == "windows" and win["analyzer"] == "WindowsAnalyzer"
    assert win["implemented"] is True
    assert "windows_disk_image" in win["parsed"] and "windows_memory_image" in win["parsed"]
    assert win["not_present"]  # absent categories are listed, not hidden

    # Linux + network: detected, architecture-ready, present artifacts -> wrapper_missing.
    assert cov["web-srv"]["analyzer"] == "LinuxAnalyzer" and cov["web-srv"]["implemented"] is False
    assert cov["web-srv"]["wrapper_missing"]
    assert cov["fw01"]["os_family"] == "network_device"
    assert cov["fw01"]["analyzer"] == "NetworkDeviceAnalyzer"


def test_coverage_markdown_renders_all_families(tmp_path: Path):
    _multi_os_case(tmp_path)
    md = render_coverage_markdown(scan_case_folder(tmp_path, case_id="multi"))
    assert "Evidence Coverage" in md
    for token in ("WindowsAnalyzer", "LinuxAnalyzer", "NetworkDeviceAnalyzer",
                  "wrapper missing", "Not present", "arch-ready"):
        assert token in md

"""OS-family analyzer registry + routing.

The router selects EXACTLY ONE analyzer by os_family. Windows -> WindowsAnalyzer
(implemented, wraps the existing pipeline). Linux/macOS -> detected_but_not_implemented.
Unknown -> unknown_evidence. Stub analyzers run no tools, so these tests need no MCP.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from dfir_agent.analyzers import (
    LinuxAnalyzer,
    MacOSAnalyzer,
    NetworkDeviceAnalyzer,
    UnknownEvidenceHandler,
    WindowsAnalyzer,
    implemented_families,
    select_analyzer,
)
from dfir_agent.decisions import DecisionLog
from dfir_agent.manifest_intake import host_os_family
from dfir_agent.nodes import NodeContext
from dfir_agent.state import AnalyzerStatus, CaseState, Host, OSFamily


def _ctx(out: Path) -> NodeContext:
    return NodeContext(client=None, decisions=DecisionLog(out, "c", "_pending"), case_root=str(out))


def _state(out: Path) -> CaseState:
    return CaseState(case_id="c", case_root=str(out))


# --------------------------------------------------------------------------- #
# registry / selection
# --------------------------------------------------------------------------- #
def test_select_analyzer_maps_each_family():
    assert isinstance(select_analyzer(OSFamily.windows), WindowsAnalyzer)
    assert isinstance(select_analyzer(OSFamily.linux), LinuxAnalyzer)
    assert isinstance(select_analyzer(OSFamily.macos), MacOSAnalyzer)
    assert isinstance(select_analyzer(OSFamily.network_device), NetworkDeviceAnalyzer)
    assert isinstance(select_analyzer(OSFamily.unknown), UnknownEvidenceHandler)


def test_network_device_analyzer_detected_but_not_implemented(tmp_path):
    out = tmp_path / "out"
    state = asyncio.run(NetworkDeviceAnalyzer().analyze(_state(out), _ctx(out)))
    o = state.analyzer_outcome
    assert o.os_family == OSFamily.network_device
    assert o.status == AnalyzerStatus.detected_but_not_implemented
    assert state.tool_results == []


def test_only_windows_is_implemented_for_now():
    assert implemented_families() == {OSFamily.windows}
    assert select_analyzer(OSFamily.windows).implemented is True
    assert select_analyzer(OSFamily.linux).implemented is False
    assert select_analyzer(OSFamily.macos).implemented is False


def test_host_os_family_maps_universal_and_legacy_strings():
    assert host_os_family(Host(host_id="a", os="windows")) == OSFamily.windows
    assert host_os_family(Host(host_id="a", os="Windows XP")) == OSFamily.windows
    assert host_os_family(Host(host_id="a", os="Windows Server 2008 R2")) == OSFamily.windows
    assert host_os_family(Host(host_id="a", os="linux")) == OSFamily.linux
    assert host_os_family(Host(host_id="a", os="macos")) == OSFamily.macos
    assert host_os_family(Host(host_id="a", os=None)) == OSFamily.unknown


# --------------------------------------------------------------------------- #
# analyzer outcomes (stubs run no tools)
# --------------------------------------------------------------------------- #
def test_windows_analyzer_metadata():
    a = WindowsAnalyzer()
    assert a.name == "WindowsAnalyzer" and a.os_family == OSFamily.windows and a.implemented


def test_linux_analyzer_detected_but_not_implemented(tmp_path: Path):
    out = tmp_path / "out"
    state = asyncio.run(LinuxAnalyzer().analyze(_state(out), _ctx(out)))
    o = state.analyzer_outcome
    assert o.analyzer_name == "LinuxAnalyzer"
    assert o.os_family == OSFamily.linux
    assert o.status == AnalyzerStatus.detected_but_not_implemented
    assert o.reason == "Linux analyzer not implemented yet"
    assert state.findings == [] and state.tool_results == []  # ran no tools
    log = (out / "cases" / "c" / "hosts" / "_pending" / "agent" / "agent_decisions.jsonl").read_text()
    assert "LinuxAnalyzer" in log and "detected_but_not_implemented" in log


def test_macos_analyzer_detected_but_not_implemented(tmp_path: Path):
    out = tmp_path / "out"
    state = asyncio.run(MacOSAnalyzer().analyze(_state(out), _ctx(out)))
    o = state.analyzer_outcome
    assert o.os_family == OSFamily.macos
    assert o.status == AnalyzerStatus.detected_but_not_implemented
    assert o.reason == "macOS analyzer not implemented yet"
    assert state.tool_results == []


def test_unknown_handler_unknown_evidence(tmp_path: Path):
    out = tmp_path / "out"
    state = asyncio.run(UnknownEvidenceHandler().analyze(_state(out), _ctx(out)))
    o = state.analyzer_outcome
    assert o.os_family == OSFamily.unknown
    assert o.status == AnalyzerStatus.unknown_evidence
    assert "improve classification" in o.reason
    assert state.tool_results == []


# --------------------------------------------------------------------------- #
# end-to-end routing (the path graph.run_case uses), no MCP needed for stubs
# --------------------------------------------------------------------------- #
def test_routing_dispatches_linux_host_to_linux_analyzer(tmp_path: Path):
    out = tmp_path / "out"
    host = Host(host_id="srv1", os=OSFamily.linux.value, memory_image="/x.lime")
    analyzer = select_analyzer(host_os_family(host))
    assert analyzer.name == "LinuxAnalyzer"
    state = _state(out)
    state.hosts = {"srv1": host}
    state.current_host = "srv1"
    state = asyncio.run(analyzer.analyze(state, _ctx(out)))
    assert state.analyzer_outcome.status == AnalyzerStatus.detected_but_not_implemented
    assert state.analyzer_outcome.os_family == OSFamily.linux

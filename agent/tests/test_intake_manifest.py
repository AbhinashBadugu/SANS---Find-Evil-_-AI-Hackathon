"""Step 3: Universal Case Manifest discovery wired into the orchestrator (intake flow).

Covers: load-existing vs generate-on-miss, Windows-memory host selection, the
clear unsupported message for a Linux/macOS-only case, runtime Host mapping
(incl. domain_controller -> dc), and the orchestrator node end-to-end WITHOUT an
MCP server (discovery makes no tool calls).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from dfir_agent.case_manifest import scan_case_folder
from dfir_agent.decisions import DecisionLog
from dfir_agent.manifest_intake import (
    build_or_load_manifest,
    manifest_to_runtime_hosts,
    select_host,
)
from dfir_agent.nodes import NodeContext
from dfir_agent.nodes.orchestrator import orchestrator_select_host, route_next
from dfir_agent.state import CaseState, HostRole, OSFamily


def _win_host(root: Path, name: str = "WIN-01") -> None:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SYSTEM").write_bytes(b"x")
    (d / "Security.evtx").write_bytes(b"x")
    (d / f"{name}.E01").write_bytes(b"x" * 64)
    (d / f"{name}-memory.mem").write_bytes(b"x" * 64)


def _linux_host(root: Path, name: str = "lin-01") -> None:
    d = root / name
    (d / "etc").mkdir(parents=True, exist_ok=True)
    (d / "etc" / "os-release").write_bytes(b"ID=ubuntu\n")
    (d / "var" / "log").mkdir(parents=True, exist_ok=True)
    (d / "var" / "log" / "auth.log").write_bytes(b"x")
    (d / f"{name}.qcow2").write_bytes(b"x" * 64)
    (d / f"{name}-memory.lime").write_bytes(b"x" * 64)


def _ctx(out: Path, case: str) -> NodeContext:
    return NodeContext(client=None, decisions=DecisionLog(out, case, "_pending"), case_root=str(out))


# --------------------------------------------------------------------------- #
# helper-level
# --------------------------------------------------------------------------- #
def test_missing_manifest_triggers_scan_and_persists(tmp_path: Path):
    ev = tmp_path / "evidence"
    _win_host(ev)
    out = tmp_path / "out"
    manifest, loaded = build_or_load_manifest(out, "c1", ev)
    assert loaded is False  # generated, not loaded
    assert (out / "cases" / "c1" / "case_manifest.json").exists()
    assert any(h.os_family == OSFamily.windows for h in manifest.hosts)


def test_existing_manifest_is_loaded_not_regenerated(tmp_path: Path):
    ev = tmp_path / "evidence"
    _win_host(ev)
    out = tmp_path / "out"
    m1, loaded1 = build_or_load_manifest(out, "c1", ev)
    assert loaded1 is False
    # Second call: manifest exists -> load it (evidence path now bogus, must not scan).
    m2, loaded2 = build_or_load_manifest(out, "c1", tmp_path / "does-not-exist")
    assert loaded2 is True
    assert {h.host_id for h in m2.hosts} == {h.host_id for h in m1.hosts}


def test_select_host_prefers_implemented_analyzer_host(tmp_path: Path):
    ev = tmp_path / "e"
    _win_host(ev, "WIN-01")
    _linux_host(ev, "lin-01")
    host_id, reason = select_host(scan_case_folder(ev))
    assert host_id == "WIN-01"  # Windows analyzer is implemented + has memory
    assert "memory" in reason.lower()


def test_select_host_falls_back_for_linux_only_never_unsupported(tmp_path: Path):
    ev = tmp_path / "e"
    _linux_host(ev, "lin-01")
    host_id, reason = select_host(scan_case_folder(ev))
    assert host_id == "lin-01"  # selected (not rejected); analyzer reports status downstream
    assert "implementation status" in reason.lower()


def test_runtime_mapping_memory_and_dc_role(tmp_path: Path):
    ev = tmp_path / "e"
    dc = ev / "DC01"
    (dc / "NTDS").mkdir(parents=True)
    (dc / "NTDS" / "ntds.dit").write_bytes(b"x")
    (dc / "SYSTEM").write_bytes(b"x")
    (dc / "DC01-memory.mem").write_bytes(b"x" * 64)
    runtime = manifest_to_runtime_hosts(scan_case_folder(ev))
    assert runtime["DC01"].role == HostRole.dc  # domain_controller -> dc for the router
    assert runtime["DC01"].memory_image and runtime["DC01"].memory_image.endswith(".mem")


# --------------------------------------------------------------------------- #
# orchestrator node end-to-end (no MCP server)
# --------------------------------------------------------------------------- #
def test_orchestrator_universal_selects_populates_and_logs(tmp_path: Path):
    ev = tmp_path / "e"
    _win_host(ev, "WIN-01")
    _linux_host(ev, "lin-01")
    out = tmp_path / "out"
    state = CaseState(case_id="c1", case_root=str(out), evidence_root=str(ev))
    state = asyncio.run(orchestrator_select_host(state, _ctx(out, "c1")))

    assert state.current_host == "WIN-01"
    assert state.hosts["WIN-01"].memory_image
    assert state.host_capabilities["WIN-01"].has_memory
    assert route_next(state) == "intake"  # flow proceeds normally

    decisions = (out / "cases" / "c1" / "hosts" / "_pending" / "agent" / "agent_decisions.jsonl").read_text()
    for step in ("manifest", "discover_hosts", "select_host", "host_capabilities"):
        assert step in decisions


def test_orchestrator_linux_only_selects_host_no_crash(tmp_path: Path):
    # Reframed: a Linux-only case is SELECTED (not "unsupported"); the LinuxAnalyzer
    # reports detected_but_not_implemented downstream (see test_analyzers.py).
    ev = tmp_path / "e"
    _linux_host(ev, "lin-01")
    out = tmp_path / "out"
    state = CaseState(case_id="c2", case_root=str(out), evidence_root=str(ev))
    state = asyncio.run(orchestrator_select_host(state, _ctx(out, "c2")))  # must NOT raise

    assert state.current_host == "lin-01"
    assert state.hosts["lin-01"].os == OSFamily.linux.value

"""Memory Analysis node (Phase 2: full allowlisted plugin set).

Runs windows.info, pslist, psscan, pstree, cmdline, netscan, malfind, svcscan via
the MCP server, reads the JSON back from our own CASE_ROOT area, and applies the
deterministic rules:
  * parent-process anomaly        (process_tree)   -> suspicious_process
  * image-path masquerade         (command_line)   -> suspicious_process
  * hidden/unlinked process diff  (process_tree)   -> suspicious_process
  * injected PE (private RWX+MZ)   (injection)      -> injection
  * suspicious service binary path (services)       -> suspicious_service

Findings about the same PID are merged; confidence is set from the count of
DISTINCT evidence families (>=2 -> confirmed). No LLM, no shell. A plugin that
fails (e.g. netscan on XP) is recorded as a gap, never invented around.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..rules.injection import detect_injected_pe
from ..rules.network import detect_c2_connections
from ..rules.suspicious_process import (
    detect_hidden_processes,
    detect_parent_anomalies,
    detect_path_masquerade,
)
from ..rules.suspicious_service import detect_suspicious_services
from ..state import CaseState, ToolResult, ToolResultStatus
from . import NodeContext

# Phase 2 plugin set (all in the server's full allowlist).
PHASE2_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.malfind",
    "windows.svcscan",
]


async def _run_plugin(state: CaseState, ctx: NodeContext, host, plugin: str) -> ToolResult:
    resp = await ctx.client.call(
        "run_volatility_plugin",
        case_id=state.case_id,
        host_id=host.host_id,
        memory_image_path=host.memory_image,
        plugin=plugin,
    )
    status = ToolResultStatus(resp.get("status", "failed"))
    tr = ToolResult(
        tool="run_volatility_plugin",
        status=status,
        provenance_id=resp.get("provenance_id", "UNKNOWN"),
        host_id=host.host_id,
        args={"plugin": plugin, "memory_image_path": host.memory_image},
        output_paths=[p for p in [resp.get("output_path")] if p],
        summary=plugin,
        error=resp.get("error"),
    )
    state.add_tool_result(tr)
    if status != ToolResultStatus.success:
        state.gaps.append(
            f"{host.host_id}: {plugin} did not succeed ({(tr.error or 'unknown error')[:120]}); "
            f"no findings derived from it ({tr.provenance_id})."
        )
    ctx.decisions.record(
        agent_name="memory",
        step=f"run:{plugin}",
        inputs_summary=f"image={host.memory_image}",
        action=f"run_volatility_plugin({plugin}) -> {status.value} ({tr.provenance_id})",
        rationale="Collect the memory artifact; failures are logged as gaps, not guessed around.",
    )
    return tr


def _read_rows(tr: ToolResult | None) -> list[dict]:
    if not tr or tr.status != ToolResultStatus.success or not tr.output_paths:
        return []
    p = Path(tr.output_paths[0])
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else data.get("rows", [])


async def memory(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    if not host.memory_image:
        state.gaps.append(f"{host.host_id}: no memory image; memory analysis skipped.")
        state.completed_steps.append("memory")
        return state

    results: dict[str, ToolResult] = {}
    for plugin in PHASE2_PLUGINS:
        results[plugin] = await _run_plugin(state, ctx, host, plugin)

    pslist = _read_rows(results.get("windows.pslist"))
    psscan = _read_rows(results.get("windows.psscan"))
    cmdline = _read_rows(results.get("windows.cmdline"))
    malfind = _read_rows(results.get("windows.malfind"))
    svcscan = _read_rows(results.get("windows.svcscan"))

    def opath(plugin: str) -> str | None:
        tr = results.get(plugin)
        return tr.output_paths[0] if tr and tr.output_paths else None

    raw = []
    raw += detect_parent_anomalies(
        pslist, host_id=host.host_id,
        provenance_id=results["windows.pslist"].provenance_id,
        artifact_path=opath("windows.pslist"), next_id=state.next_finding_id,
    )
    raw += detect_path_masquerade(
        cmdline, host_id=host.host_id,
        provenance_id=results["windows.cmdline"].provenance_id,
        artifact_path=opath("windows.cmdline"), next_id=state.next_finding_id,
    )
    raw += detect_hidden_processes(
        psscan, pslist, host_id=host.host_id,
        provenance_id=results["windows.psscan"].provenance_id,
        artifact_path=opath("windows.psscan"), next_id=state.next_finding_id,
    )
    raw += detect_injected_pe(
        malfind, host_id=host.host_id,
        provenance_id=results["windows.malfind"].provenance_id,
        artifact_path=opath("windows.malfind"), next_id=state.next_finding_id,
    )
    raw += detect_suspicious_services(
        svcscan, host_id=host.host_id,
        provenance_id=results["windows.svcscan"].provenance_id,
        artifact_path=opath("windows.svcscan"), next_id=state.next_finding_id,
    )

    # netscan -> C2 connections. Keyed by the PIDs/names the rules above already
    # flagged, so a beaconing implant gains the strong `network` family on merge
    # (and benign chatter from un-flagged processes is left alone).
    netscan = _read_rows(results.get("windows.netscan"))
    if netscan and results.get("windows.netscan") and results["windows.netscan"].status == ToolResultStatus.success:
        susp_pids = {f.entity_key.split(":", 1)[1] for f in raw if (f.entity_key or "").startswith("pid:")}
        susp_names = {t for f in raw for t in f.tags if t.lower().endswith(".exe")}
        raw += detect_c2_connections(
            netscan, host_id=host.host_id,
            provenance_id=results["windows.netscan"].provenance_id,
            artifact_path=opath("windows.netscan"),
            suspicious_pids=susp_pids, suspicious_names=susp_names, next_id=state.next_finding_id,
        )

    # The memory node emits RAW per-signal findings; the correlation node is the
    # single place that merges and sets confidence (so the description is built
    # once, not nested across two merge passes).
    state.findings.extend(raw)
    state.completed_steps.append("memory")
    ctx.decisions.record(
        agent_name="memory",
        step="extract_signals",
        inputs_summary=(
            f"pslist={len(pslist)} psscan={len(psscan)} cmdline={len(cmdline)} "
            f"malfind={len(malfind)} svcscan={len(svcscan)}"
        ),
        action=f"{len(raw)} raw memory signal(s) emitted (merge deferred to correlation)",
        rationale="Rules extract independent signals; correlation fuses them by entity/path.",
    )
    return state

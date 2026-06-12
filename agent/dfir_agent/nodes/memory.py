"""Memory Analysis node.

Phase 1 scope: run the two allowlisted plugins `windows.info` and
`windows.pslist`, read the pslist output back from our own CASE_ROOT area, and
apply the deterministic parent-anomaly (masquerade) rule. No LLM, no shell.

Facts are extracted by parsing the server's JSON output; the *decision* that a
process is anomalous is made by rules/suspicious_process.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..rules.suspicious_process import detect_parent_anomalies
from ..state import CaseState, ToolResult, ToolResultStatus
from . import NodeContext

# Phase 1 plugin set (both are in the server allowlist).
PHASE1_PLUGINS = ["windows.info", "windows.pslist"]


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
    ctx.decisions.record(
        agent_name="memory",
        step=f"run:{plugin}",
        inputs_summary=f"image={host.memory_image}",
        action=f"run_volatility_plugin({plugin}) -> {status.value} ({tr.provenance_id})",
        rationale="windows.info confirms the profile; windows.pslist gives the process tree for the masquerade rule.",
    )
    return tr


def _read_rows(output_path: str | None) -> list[dict]:
    """Read back our own Volatility JSON output (under CASE_ROOT)."""
    if not output_path:
        return []
    p = Path(output_path)
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

    pslist_result: ToolResult | None = None
    for plugin in PHASE1_PLUGINS:
        tr = await _run_plugin(state, ctx, host, plugin)
        if plugin == "windows.pslist":
            pslist_result = tr

    if not pslist_result or pslist_result.status != ToolResultStatus.success:
        state.gaps.append(f"{host.host_id}: windows.pslist did not succeed; no process findings.")
        state.completed_steps.append("memory")
        return state

    rows = _read_rows(pslist_result.output_paths[0] if pslist_result.output_paths else None)
    new_findings = detect_parent_anomalies(
        rows,
        host_id=host.host_id,
        provenance_id=pslist_result.provenance_id,
        artifact_path=pslist_result.output_paths[0] if pslist_result.output_paths else None,
        next_id=state.next_finding_id,
    )
    state.findings.extend(new_findings)
    state.completed_steps.append("memory")
    ctx.decisions.record(
        agent_name="memory",
        step="apply_masquerade_rule",
        inputs_summary=f"{len(rows)} processes from windows.pslist",
        action=f"parent-anomaly rule -> {len(new_findings)} draft finding(s)",
        rationale=(
            "A core system process with the wrong parent is a deterministic masquerade "
            "indicator; each finding cites the pslist provenance_id and the specific PID."
        ),
    )
    return state

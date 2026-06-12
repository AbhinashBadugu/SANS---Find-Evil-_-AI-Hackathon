"""Disk Artifact node (Phase 3).

Flow (all via MCP, read-only, no admin):
  open_ewf -> inspect_disk -> extract_artifacts -> parse_mft / parse_shimcache /
  parse_registry / parse_evtx (+ parse_evt_legacy on XP) -> close_ewf.

Then it corroborates the suspicious image paths surfaced in memory against disk:
the MFT (file exists? timestomp? co-located drop?) and the shimcache (executed?).
Those disk findings are keyed by path so the correlation node fuses them with the
memory finding about the same implant — taking it multi-source across the
memory/disk boundary.
"""

from __future__ import annotations

from ..rules.disk_artifacts import correlate_mft, correlate_shimcache
from ..state import CaseState, ToolResult, ToolResultStatus
from . import NodeContext


async def _call(state: CaseState, ctx: NodeContext, host, tool: str, **kw) -> tuple[ToolResult, dict]:
    resp = await ctx.client.call(tool, case_id=state.case_id, host_id=host.host_id, **kw)
    status = ToolResultStatus(resp.get("status", "failed"))
    out = resp.get("output_paths") or ([resp["output_path"]] if resp.get("output_path") else [])
    tr = ToolResult(
        tool=tool, status=status, provenance_id=resp.get("provenance_id", "UNKNOWN"),
        host_id=host.host_id, args=kw, output_paths=out, summary=tool, error=resp.get("error"),
    )
    state.add_tool_result(tr)
    if status != ToolResultStatus.success:
        state.gaps.append(f"{host.host_id}: {tool} did not succeed ({(tr.error or '?')[:100]}) ({tr.provenance_id}).")
    ctx.decisions.record(
        agent_name="disk", step=f"call:{tool}",
        inputs_summary=str({k: str(v)[:60] for k, v in kw.items()}),
        action=f"{tool} -> {status.value} ({tr.provenance_id})",
        rationale="Read-only disk artifact step; failures are logged as gaps, never guessed around.",
    )
    return tr, resp


def _csv(tr: ToolResult, must_contain: str | None = None) -> str | None:
    for p in tr.output_paths:
        if must_contain is None or must_contain in str(p):
            return str(p)
    return tr.output_paths[0] if tr.output_paths else None


async def disk(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    if not host.disk_image:
        state.gaps.append(f"{host.host_id}: no disk image in manifest; disk analysis skipped.")
        state.completed_steps.append("disk")
        return state

    # Paths to corroborate = whatever memory surfaced.
    target_paths = {p for f in state.findings for p in f.paths if p}

    open_tr, open_resp = await _call(state, ctx, host, "open_ewf", e01_path=host.disk_image)
    if open_tr.status != ToolResultStatus.success or not open_resp.get("ewf1_path"):
        state.gaps.append(f"{host.host_id}: could not open disk image; disk analysis aborted.")
        state.completed_steps.append("disk")
        return state
    ewf1 = open_resp["ewf1_path"]
    mount_dir = open_resp.get("mount_dir")

    try:
        await _call(state, ctx, host, "inspect_disk", ewf1_path=ewf1)
        _, ext_resp = await _call(state, ctx, host, "extract_artifacts", ewf1_path=ewf1)
        extracted: dict = (ext_resp.get("info") or {}).get("extracted", {})

        mft_path = extracted.get("$MFT")
        system_hive = extracted.get("SYSTEM")
        hive_dir = None
        for label in ("$MFT", "SYSTEM", "SOFTWARE"):
            if extracted.get(label):
                from pathlib import Path as _P
                hive_dir = str(_P(extracted[label]).parent)
                break
        # Record the carved-artifacts dir so the timeline node can use it as the
        # Plaso source without re-mounting.
        if hive_dir:
            host.extracted_dir = hive_dir

        mft_tr = shim_tr = None
        if mft_path:
            mft_tr, _ = await _call(state, ctx, host, "parse_mft", mft_path=mft_path)
        if system_hive:
            shim_tr, _ = await _call(state, ctx, host, "parse_shimcache", system_hive_path=system_hive)
        if hive_dir:
            await _call(state, ctx, host, "parse_registry", hive_dir=hive_dir)

        # Event logs: modern .evtx first; XP yields nothing -> fall back to legacy .evt.
        evtx_dir = None
        if extracted.get("$MFT"):
            from pathlib import Path as _P
            evtx_dir = str(_P(extracted["$MFT"]).parent / "eventlogs")
        if evtx_dir:
            evtx_tr, _ = await _call(state, ctx, host, "parse_evtx", evtx_dir=evtx_dir)
            if evtx_tr.status != ToolResultStatus.success:
                legacy_dir = str(_P(extracted["$MFT"]).parent / "eventlogs_legacy")
                await _call(state, ctx, host, "parse_evt_legacy", evt_dir=legacy_dir)

        # --- correlate the memory leads against disk ---
        new_findings = []
        if mft_tr and mft_tr.status == ToolResultStatus.success:
            new_findings += correlate_mft(
                _csv(mft_tr, "mft.csv") or _csv(mft_tr), target_paths,
                host_id=host.host_id, provenance_id=mft_tr.provenance_id, next_id=state.next_finding_id,
            )
        if shim_tr and shim_tr.status == ToolResultStatus.success:
            new_findings += correlate_shimcache(
                _csv(shim_tr, "shimcache.csv") or _csv(shim_tr), target_paths,
                host_id=host.host_id, provenance_id=shim_tr.provenance_id, next_id=state.next_finding_id,
            )
        state.findings.extend(new_findings)
        ctx.decisions.record(
            agent_name="disk", step="correlate_disk",
            inputs_summary=f"{len(target_paths)} target path(s) from memory",
            action=f"disk corroboration -> {len(new_findings)} disk finding(s)",
            rationale="Check each memory-surfaced path against MFT (existence/timestomp) and shimcache (execution).",
        )
    finally:
        if mount_dir:
            await _call(state, ctx, host, "close_ewf", mount_dir=mount_dir)

    state.completed_steps.append("disk")
    return state

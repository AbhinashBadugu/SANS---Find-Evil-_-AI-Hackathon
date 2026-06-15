"""Deep-scan node — runs the expanded detections that operate over data the
disk/memory nodes already parsed (no extra evidence reads, mount already closed).

Wired here:
  * credential access   — scan the MFT + memory cmdline for credential-dumping
                          tooling / LSASS dumps / hive exports, then correlate
                          with logon events (4624/4648/4672/4776).
  * lateral-movement graph — normalise the EVTX logon/service events into a
                          time-ordered host->host graph (IP->host via case config).
  * self-correction     — config-driven enrichment demotes findings that rest on
                          IR/acquisition infrastructure or known-benign paths.

It reads the CSV/JSON the earlier nodes wrote (parse_mft -> mft.csv, parse_evtx ->
evtx.csv, run_volatility_plugin windows.cmdline -> json). Every missing input is
recorded as a gap; nothing here crashes the run. File-based detections that need
files carved off the image (Java cache, PE/strings, hashing, registry .reg C2)
are NOT here — they require a carve step and are wired separately.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

from ..enrichment import case_host_ip_map, enrich_findings
from ..rules.credential_access import (
    correlate_credential_tooling_with_logons, detect_credential_access,
)
from ..rules.lateral_graph import build_lateral_movement_graph, findings_from_lateral_graph
from ..state import CaseState, ToolResultStatus
from . import NodeContext

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

# Cheap pre-filter so we don't build artifacts from every MFT row — only files
# whose name/path hints at credential tooling are worth handing to the rule.
_CRED_HINT = re.compile(
    r"(mimikatz|sekurlsa|lsass|procdump|gsecdump|wce|pwdump|fgdump|lazagne|"
    r"dumpert|nanodump|\bsam\b|\bntds\b|hashdump|comsvcs)", re.IGNORECASE)


def _latest(state: CaseState, tool: str, suffix: str | None = None, plugin: str | None = None):
    """Return (csv_or_json_path, provenance_id) for the most recent successful
    matching tool result, or None."""
    for tr in reversed(state.tool_results):
        if tr.tool != tool or tr.status != ToolResultStatus.success or not tr.output_paths:
            continue
        if plugin and (tr.args or {}).get("plugin") != plugin:
            continue
        path = tr.output_paths[0]
        if suffix:
            path = next((p for p in tr.output_paths if str(p).endswith(suffix)), tr.output_paths[0])
        return str(path), tr.provenance_id
    return None


def _payload(row: dict) -> dict:
    try:
        data = json.loads(row.get("Payload") or "{}")
        items = data.get("EventData", {}).get("Data", [])
        return {i.get("@Name"): i.get("#text") for i in items if isinstance(i, dict)}
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {}


def _logon_events(evtx_csv: str, host_id: str, prov: str) -> list[dict]:
    """Normalise EVTX logon/service rows into the shape the rules expect."""
    p = Path(evtx_csv)
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            eid = (row.get("EventId") or "").strip()
            if eid not in {"4624", "4648", "4672", "4776", "7045"}:
                continue
            pl = _payload(row)
            base = {"event_id": eid, "host_id": host_id, "time": row.get("TimeCreated"),
                    "provenance_id": prov, "record_id": f"EventRecordId={row.get('EventRecordId', '?')}"}
            if eid == "7045":
                base.update(service_name=(row.get("PayloadData1") or "").replace("Name:", "").strip(),
                            image_path=row.get("ExecutableInfo") or "")
            elif eid == "4672":
                base.update(account=pl.get("SubjectUserName"))
            else:  # 4624 / 4648 / 4776
                base.update(account=pl.get("TargetUserName"),
                            logon_type=pl.get("LogonType"),
                            src_ip=pl.get("IpAddress") or pl.get("Workstation"))
            out.append(base)
    return out


def _cred_artifacts_from_mft(mft_csv: str, host_id: str, prov: str) -> list[dict]:
    p = Path(mft_csv)
    if not p.exists():
        return []
    arts: list[dict] = []
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            name = row.get("FileName") or row.get("Name") or ""
            parent = row.get("ParentPath") or row.get("Path") or ""
            full = f"{parent}\\{name}".replace("\\\\", "\\")
            if not _CRED_HINT.search(f"{name} {full}"):
                continue
            arts.append({"name": name, "path": full, "source_family": "disk_mft",
                         "provenance_id": prov,
                         "record_id": f"MFT#{row.get('EntryNumber') or row.get('Entry') or '?'}"})
    return arts


def _cred_artifacts_from_cmdline(cmd_json: str, host_id: str, prov: str) -> list[dict]:
    p = Path(cmd_json)
    if not p.exists():
        return []
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    rows = rows if isinstance(rows, list) else rows.get("rows", [])
    arts: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        text = " ".join(str(r.get(k, "")) for k in ("Args", "Process", "ImageFileName", "Name"))
        if not _CRED_HINT.search(text):
            continue
        arts.append({"name": r.get("Process") or r.get("ImageFileName"), "cmdline": r.get("Args"),
                     "text": text, "source_family": "memory_cmdline", "provenance_id": prov,
                     "record_id": f"PID={r.get('PID') or r.get('Pid') or '?'}"})
    return arts


async def deep_scan(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    before = len(state.findings)
    new_findings = []

    evtx = _latest(state, "parse_evtx", suffix="evtx.csv")
    mft = _latest(state, "parse_mft", suffix="mft.csv")
    cmd = _latest(state, "run_volatility_plugin", plugin="windows.cmdline")

    # --- logon events (shared by lateral graph + credential correlation) ---
    logon_events: list[dict] = []
    if evtx:
        logon_events = _logon_events(evtx[0], host.host_id, evtx[1])
    else:
        state.gaps.append(f"{host.host_id}: no parsed EVTX; lateral-graph + logon correlation skipped.")

    # --- credential access ---
    artifacts: list[dict] = []
    if mft:
        artifacts += _cred_artifacts_from_mft(mft[0], host.host_id, mft[1])
    if cmd:
        artifacts += _cred_artifacts_from_cmdline(cmd[0], host.host_id, cmd[1])
    cred = detect_credential_access(artifacts, host_id=host.host_id)
    new_findings += cred
    if cred and logon_events:
        new_findings += correlate_credential_tooling_with_logons(cred, logon_events, host_id=host.host_id)

    # --- lateral-movement graph ---
    if logon_events:
        ip_map = dict(case_host_ip_map())
        for hid, h in state.hosts.items():
            if getattr(h, "ip", None):
                ip_map[h.ip] = hid
                ip_map[hid] = h.ip
        graph = build_lateral_movement_graph(logon_events, ip_map=ip_map)
        state.lateral_graph = graph  # stash for the report
        new_findings += findings_from_lateral_graph(graph)

    state.findings.extend(new_findings)

    # --- self-correction: demote findings resting on IR infra / known-benign paths ---
    _, corrections = enrich_findings(state.findings)

    ctx.decisions.record(
        agent_name="deep_scan", step="expanded_detection",
        inputs_summary=f"evtx={'y' if evtx else 'n'} mft={'y' if mft else 'n'} cmdline={'y' if cmd else 'n'}",
        action=(f"+{len(new_findings)} findings (cred={len(cred)}, "
                f"lateral={len(new_findings) - len(cred)}); self-corrected {len(corrections)}"),
        rationale="Run credential-access + lateral-graph over already-parsed artifacts; "
                  "apply config-driven self-correction. Missing inputs are gaps, not guesses.",
    )
    state.completed_steps.append("deep_scan")
    return state

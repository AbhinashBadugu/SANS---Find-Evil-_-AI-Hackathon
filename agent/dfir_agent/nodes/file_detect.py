"""File-based detections that need files carved off the disk image.

Runs inside the disk node WHILE the image mount is open. From the parsed MFT it
derives which files matter (Java Deployment cache .idx, suspect executables in
masquerade/staging paths, .reg exports), carves them with `carve_files`, then
runs the static/file tools + rules:

  * Java drive-by      (parse_java_cache  -> rules/java_cache)
  * PE / malware IOC    (extract_pe_metadata/strings/pyinstaller/pdb/urls -> rules/pe_indicators)
  * registry C2 config  (parse_reg_export -> rules/registry_config)
  * file hashing        (hash_file -> per-host manifest; cross-host compare in cross_host)

Defensive: every missing/failed step is a gap, never a crash. Bounded by caps so
it never carves hundreds of files.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

from ..rules.java_cache import correlate_download_to_payload, detect_java_drive_by
from ..rules.pe_indicators import pe_indicator_findings
from ..rules.registry_config import suspicious_registry_c2
from ..state import CaseState, ToolResultStatus
from . import NodeContext

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

_JAVA_CACHE = re.compile(r"appdata/locallow/sun/java/deployment/cache", re.IGNORECASE)
_MASQ_OR_STAGE = re.compile(
    r"(\\system32\\[^\\]+\\[^\\]+\.exe$|\\(temp|tmp|users\\public|programdata|"
    r"appdata\\local\\temp|windows\\temp|\$recycle\.bin)\\)", re.IGNORECASE)
_EXE = re.compile(r"\.(exe|scr|dll)$", re.IGNORECASE)
_CAP_EXE = 40


async def _call(state: CaseState, ctx: NodeContext, host, tool: str, **kw) -> dict:
    resp = await ctx.client.call(tool, case_id=state.case_id, host_id=host.host_id, **kw)
    return resp or {}


def _full(parent: str, name: str) -> str:
    return f"{parent}\\{name}".replace("/", "\\").replace("\\\\", "\\")


def _derive_targets(mft_csv: str) -> dict[str, list]:
    """Return {java_idx, reg, exes, drops} in-image paths from the MFT."""
    p = Path(mft_csv)
    java, reg, exes, drops = [], [], [], []
    if not p.exists():
        return {"java_idx": java, "reg": reg, "exes": exes, "drops": drops}
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            name = row.get("FileName") or row.get("Name") or ""
            parent = row.get("ParentPath") or row.get("Path") or ""
            full = _full(parent, name)
            low = full.lower()
            rec = {"name": name, "path": full, "ctime": row.get("Created0x10") or row.get("CreationTime"),
                   "record_id": f"MFT#{row.get('EntryNumber') or row.get('Entry') or '?'}"}
            if name.lower().endswith(".idx") and _JAVA_CACHE.search(low.replace("\\", "/")):
                java.append(full)
            elif name.lower().endswith(".reg"):
                reg.append(full)
            elif _EXE.search(name) and _MASQ_OR_STAGE.search(low):
                if len(exes) < _CAP_EXE:
                    exes.append(full)
                drops.append(rec)
            elif _EXE.search(name) or name.lower().endswith((".rar", ".zip", ".7z")):
                drops.append(rec)  # candidate "dropped file" for java download correlation
    return {"java_idx": java, "reg": reg, "exes": exes, "drops": drops}


async def run_file_detections(state: CaseState, ctx: NodeContext, host, ewf1: str, mft_csv: str) -> int:
    """Carve target files and run the file-based detections. Returns # findings added."""
    targets = _derive_targets(mft_csv)
    to_carve = list(dict.fromkeys(targets["java_idx"] + targets["reg"] + targets["exes"]))
    if not to_carve:
        state.gaps.append(f"{host.host_id}: no Java cache / suspect exe / .reg targets in MFT; file detections skipped.")
        return 0

    resp = await _call(state, ctx, host, "carve_files", ewf1_path=ewf1, paths=to_carve)
    carved: dict[str, str] = resp.get("carved") or {}
    carve_prov = resp.get("provenance_id", "UNKNOWN")
    if not carved:
        state.gaps.append(f"{host.host_id}: carve_files recovered nothing for file detections ({carve_prov}).")
        return 0

    new = []

    # --- Java drive-by: parse the carved cache dir, correlate to dropped files ---
    if any(p in carved for p in targets["java_idx"]):
        out_dir = resp.get("output_dir")
        if out_dir:
            jr = await _call(state, ctx, host, "parse_java_cache", cache_dir=out_dir)
            records = jr.get("records") or []
            jprov = jr.get("provenance_id", carve_prov)
            new += detect_java_drive_by(records, host_id=host.host_id, provenance_id=jprov)
            new += correlate_download_to_payload(records, targets["drops"], host_id=host.host_id,
                                                 provenance_id=jprov)

    # --- suspect executables: PE metadata / strings / pyinstaller / pdb / urls + hash ---
    for orig in targets["exes"]:
        cp = carved.get(orig)
        if not cp:
            continue
        pe = await _call(state, ctx, host, "extract_pe_metadata", file_path=cp)
        pyi = await _call(state, ctx, host, "detect_pyinstaller", file_path=cp)
        urls = await _call(state, ctx, host, "extract_embedded_urls", file_path=cp)
        pdb = await _call(state, ctx, host, "extract_pdb_paths", file_path=cp)
        await _call(state, ctx, host, "hash_file", file_path=cp)  # writes per-host manifest
        new += pe_indicator_findings(host_id=host.host_id, file_path=orig,
                                     pe=pe, pyinstaller=pyi, embedded=urls, pdb=pdb)

    # --- registry C2 config from carved .reg exports ---
    for orig in targets["reg"]:
        cp = carved.get(orig)
        if not cp:
            continue
        rr = await _call(state, ctx, host, "parse_reg_export", reg_path=cp)
        new += suspicious_registry_c2(rr.get("entries") or [], host_id=host.host_id,
                                      provenance_id=rr.get("provenance_id", carve_prov))

    state.findings.extend(new)
    ctx.decisions.record(
        agent_name="file_detect", step="file_detections",
        inputs_summary=f"carved {len(carved)}/{len(to_carve)} (java={len(targets['java_idx'])}, "
                       f"exe={len(targets['exes'])}, reg={len(targets['reg'])})",
        action=f"+{len(new)} file-based findings (java/PE/registry/hash)",
        rationale="Carve the files the fixed extract set omits, then run static/file detections on them.",
    )
    return len(new)

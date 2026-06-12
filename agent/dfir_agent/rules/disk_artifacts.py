"""Disk-artifact corroboration rules (playbook §7, families disk_mft/disk_shimcache).

These are CORRELATION-AWARE: rather than emit a finding per MFT row (tens of
thousands), they take the set of suspicious image paths already surfaced in memory
and ask disk two questions about each:

  * MFT  — does this file exist on disk? when was it really created (FN vs SI ->
           timestomp)? what sits next to it (a co-located config drop)?
  * Shimcache — is there an execution/registration record for this path?

Each emitted finding is keyed by the normalized path, so the correlation step
fuses it with the memory finding about the same implant.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from ..state import Confidence, EvidenceReference, Finding
from .winpath import mft_full_path, normalize_winpath


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:26], fmt)
        except ValueError:
            continue
    return None


def correlate_mft(
    mft_csv: str,
    target_paths: set[str],
    *,
    host_id: str,
    provenance_id: str,
    next_id,
) -> list[Finding]:
    """Confirm on-disk existence of each target path; detect timestomp + siblings."""
    if not target_paths:
        return []
    p = Path(mft_csv)
    if not p.exists():
        return []

    matches: list[dict] = []
    by_parent: dict[str, list[tuple[str, str]]] = {}  # normalized parent dir -> [(filename, entry)]
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            fname = row.get("FileName")
            if not fname:
                continue
            parent = row.get("ParentPath") or ""
            full = mft_full_path(parent, fname)
            if not full:
                continue
            parent_norm = normalize_winpath(parent)
            if parent_norm:
                by_parent.setdefault(parent_norm, []).append((fname, row.get("EntryNumber", "?")))
            if full in target_paths:
                matches.append({
                    "full": full,
                    "entry": row.get("EntryNumber", "?"),
                    "size": row.get("FileSize"),
                    "parent": parent_norm,
                    "si_created": row.get("Created0x10"),
                    "fn_created": row.get("Created0x30"),
                })

    findings: list[Finding] = []
    for m in matches:
        si = _parse_dt(m["si_created"])
        fn = _parse_dt(m["fn_created"])
        timestomp = bool(si and fn and (fn - si).total_seconds() > 3600)
        siblings = [
            f for (f, _e) in by_parent.get(m["parent"], [])
            if mft_full_path(m["parent"], f) != m["full"]
        ]
        sib_note = f"; co-located files: {', '.join(siblings[:5])}" if siblings else ""
        ts_note = (
            f"; TIMESTOMP suspected (SI-created {m['si_created']} precedes FN-created {m['fn_created']})"
            if timestomp else ""
        )
        tags = ["disk", "mft"] + (["timestomped"] if timestomp else [])
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"On-disk file confirms {Path(m['full']).name} at {m['full']}",
                category="dropped_file",
                entity_key=f"path:{m['full']}",
                paths=[m["full"]],
                description=(
                    f"MFT entry {m['entry']} shows '{m['full']}' ({m['size']} bytes) exists on disk"
                    + ts_note + sib_note + "."
                ),
                confidence=Confidence.likely,  # single strong family until correlation
                rule="disk_artifacts.mft_correlate",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"MFT#{m['entry']}",
                        tool="parse_mft",
                        artifact_path=mft_csv,
                        source_family="disk_mft",
                        note=(
                            f"$MFT entry {m['entry']}: {m['full']} size={m['size']} "
                            f"FN-created={m['fn_created']} SI-created={m['si_created']}"
                            + (" [timestomp]" if timestomp else "") + sib_note
                        ),
                    )
                ],
                tags=tags,
            )
        )
    return findings


def search_mft_by_name(mft_csv: str, names: set[str]) -> dict[str, list[dict]]:
    """Find every MFT row whose FileName matches one of `names` (case-insensitive).

    Used by the self-correction loop to verify, on disk, the binaries that memory
    flagged only by name (e.g. a hidden process). Returns name -> [match dicts].
    """
    p = Path(mft_csv)
    wanted = {n.lower() for n in names}
    out: dict[str, list[dict]] = {n: [] for n in wanted}
    if not p.exists():
        return out
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            fname = (row.get("FileName") or "").strip()
            if fname.lower() in wanted:
                parent = normalize_winpath(row.get("ParentPath") or "")
                out[fname.lower()].append({
                    "entry": row.get("EntryNumber", "?"),
                    "parent": parent,
                    "full": mft_full_path(row.get("ParentPath") or "", fname),
                    "size": row.get("FileSize"),
                })
    return out


def correlate_shimcache(
    shim_csv: str,
    target_paths: set[str],
    *,
    host_id: str,
    provenance_id: str,
    next_id,
) -> list[Finding]:
    """Confirm an execution/registration record (AppCompatCache) for each target path."""
    if not target_paths:
        return []
    p = Path(shim_csv)
    if not p.exists():
        return []

    seen: dict[str, dict] = {}
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            full = normalize_winpath(row.get("Path"))
            if full and full in target_paths and full not in seen:
                seen[full] = {
                    "pos": row.get("CacheEntryPosition", "?"),
                    "lastmod": row.get("LastModifiedTimeUTC"),
                    "executed": row.get("Executed"),
                }

    findings: list[Finding] = []
    for full, d in seen.items():
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"Execution record (shimcache) for {Path(full).name}",
                category="execution_record",
                entity_key=f"path:{full}",
                paths=[full],
                description=(
                    f"AppCompatCache (shimcache) contains '{full}' "
                    f"(entry {d['pos']}, last-modified {d['lastmod']}, executed={d['executed']}), "
                    f"evidence the binary was present/registered for execution on this host."
                ),
                confidence=Confidence.likely,
                rule="disk_artifacts.shimcache_correlate",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"shimcache#{d['pos']}",
                        tool="parse_shimcache",
                        artifact_path=shim_csv,
                        source_family="disk_shimcache",
                        note=f"shimcache: {full} pos={d['pos']} lastmod={d['lastmod']} executed={d['executed']}",
                    )
                ],
                tags=["disk", "shimcache"],
            )
        )
    return findings

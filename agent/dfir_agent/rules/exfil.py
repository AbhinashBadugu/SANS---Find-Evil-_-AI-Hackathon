"""Exfil / data-staging rule (disk, family=disk_mft).

The disk_artifacts rules only check files memory already named. This rule scans the
full MFT for the OTHER half of an intrusion: data collected into an archive for
exfiltration. It flags archive files that are either in a staging location (Temp,
Users\\Public, ProgramData, Recycle Bin) or unusually large — the classic
"rar a -hp<pwd> <archive>.rar <collected files>" staging pattern. A small zip in a user's
Documents folder is NOT flagged (anti-FP).
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from ..state import Confidence, EvidenceReference, Finding
from .winpath import mft_full_path, normalize_winpath

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

# Restricted to .rar by design: RAR is the canonical exfil-staging format (the
# "rar a -hp<pwd>" collect-and-encrypt technique), whereas .zip/.7z/.cab in temp are
# dominated by installers, update temp dirs, and IR tooling — flagging those would
# manufacture false positives (and on this case, would wrongly flag the benign
# F-Response/USB-over-Ethernet IR archives that the M10 self-correction rules legit).
_ARCHIVE_EXT = {".rar"}
# Genuine staging directories, matched as PATH SEGMENTS (so 'temporary internet
# files' does NOT match 'temp'). recycle/public/programdata matched as substrings
# since they're unambiguous.
_STAGING_SEGMENTS = {"temp", "tmp", "public"}
_STAGING_SUBSTR = ("\\users\\public\\", "\\$recycle", "recycler", "\\programdata\\", "\\perflogs\\")
# Benign installer/cache contexts that legitimately hold archives — never exfil.
_BENIGN_CTX = ("msocache", "\\installer", "setup files", "\\program files",
               "temporary internet files", "\\winsxs\\", "\\softwaredistribution\\")


def _ext_of(row: dict, fname: str) -> str:
    ext = (row.get("Extension") or "").strip().lstrip(".").lower()
    if ext:
        return "." + ext
    return Path(fname).suffix.lower()


def detect_staged_archives(
    mft_csv: str, *, host_id: str, provenance_id: str, next_id, cap: int = 15
) -> list[Finding]:
    p = Path(mft_csv)
    if not p.exists():
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            fname = (row.get("FileName") or "").strip()
            if not fname or _ext_of(row, fname) not in _ARCHIVE_EXT:
                continue
            parent = (normalize_winpath(row.get("ParentPath") or "") or "").lower()
            full = mft_full_path(row.get("ParentPath") or "", fname)
            if not full or full in seen:
                continue
            try:
                size = int(row.get("FileSize") or 0)
            except (TypeError, ValueError):
                size = 0
            if any(b in parent for b in _BENIGN_CTX):
                continue  # legit installer/cache/packaging archive — not exfil
            segments = set(parent.split("\\"))
            staging = bool(segments & _STAGING_SEGMENTS) or any(h in parent for h in _STAGING_SUBSTR)
            if not staging:
                continue  # only archives in genuine staging locations are flagged
            seen.add(full)
            entry = row.get("EntryNumber", "?")
            why = f"in a staging location ({size} bytes)"
            findings.append(Finding(
                finding_id=next_id(), host_id=host_id,
                title=f"Staged archive (possible exfil): {fname}",
                category="exfil", entity_key=f"path:{full}", paths=[full],
                description=(
                    f"MFT entry {entry}: archive '{full}' ({size} bytes) is {why}. This is consistent "
                    f"with data staging for exfiltration — collected files compressed into a single "
                    f"RAR/archive prior to exfil. Recommend hashing and content review."
                ),
                confidence=Confidence.suspicious, rule="exfil.staged_archive", source_count=1,
                evidence=[EvidenceReference(
                    provenance_id=provenance_id, record_id=f"MFT#{entry}", tool="parse_mft",
                    artifact_path=mft_csv, source_family="disk_mft",
                    note=f"$MFT entry {entry}: staged archive {full} size={size} ({why}) — RAR/exfil staging",
                )],
                tags=["disk", "mft", "exfil", "staging"],
            ))
            if len(findings) >= cap:
                break
    return findings

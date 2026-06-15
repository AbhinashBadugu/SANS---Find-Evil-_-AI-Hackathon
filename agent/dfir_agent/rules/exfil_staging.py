"""Exfiltration-staging detection expansion (family=disk_mft).

Generic detectors over MFT rows:
  * detect_archive_staging      — archives in staging locations or unusually large,
                                  with size/timestamp/path metadata
  * correlate_archive_with_cleanup — archive staging near Recycle-Bin cleanup /
                                  deleted tooling (anti-forensics around exfil)
Behavioural — keys on archive type + staging location + size, never a filename.
"""

from __future__ import annotations

import re

from ..state import Confidence, EvidenceReference, Finding

_ARCHIVE_EXT = re.compile(r"\.(rar|zip|7z|tar|gz|tgz|cab|ace|arj)$", re.IGNORECASE)
_STAGING = re.compile(r"\\(temp|tmp|users\\public|programdata|\$recycle\.bin|recycler|"
                      r"perflogs|appdata\\local\\temp|windows\\temp)\\", re.IGNORECASE)
_LARGE = 5 * 1024 * 1024  # archives >5 MiB in staging dirs are notable


def _d(x) -> dict:
    return x if isinstance(x, dict) else x.model_dump()


def detect_archive_staging(rows, *, host_id: str, id_start: int = 1) -> list[Finding]:
    findings, n = [], id_start
    for raw in rows or []:
        r = _d(raw)
        path = str(r.get("path") or r.get("name") or "")
        if not _ARCHIVE_EXT.search(path) or not r.get("provenance_id"):
            continue
        size = int(r.get("size") or 0)
        staged = bool(_STAGING.search(path))
        if not staged and size < _LARGE:
            continue
        conf = Confidence.likely if staged else Confidence.suspicious
        findings.append(Finding(
            finding_id=f"EX-{n:04d}", host_id=host_id,
            title=f"Exfil-staging archive: {path.split(chr(92))[-1]}",
            category="exfiltration", entity_key=f"archive:{path}", paths=[path],
            description=(
                f"Archive '{path}'"
                + (f" ({size} bytes)" if size else "")
                + (f", created {r.get('ctime')}" if r.get("ctime") else "")
                + (" in a staging location" if staged else " is unusually large")
                + ". Archives collected into staging dirs are a data-exfiltration indicator."
            ),
            confidence=conf, rule="exfil_staging.archive", source_count=1,
            evidence=[EvidenceReference(
                provenance_id=r["provenance_id"], tool="parse_mft", source_family="disk_mft",
                record_id=r.get("record_id"), note=f"archive {path} size={size} staged={staged}")],
            tags=["exfiltration", "staging", "archive"], mitre_mapping=["T1560", "T1074"],
        ))
        n += 1
    return findings


def correlate_archive_with_cleanup(archive_findings, cleanup_rows, *, host_id: str,
                                   id_start: int = 1) -> list[Finding]:
    """Tie archive staging to anti-forensics cleanup nearby (Recycle Bin entries /
    deleted tools). cleanup_rows: {name, path, deleted, ctime, provenance_id}."""
    if not archive_findings or not cleanup_rows:
        return []
    findings, n = [], id_start
    cleaned = [_d(c) for c in cleanup_rows
               if (_d(c).get("deleted") or "$recycle" in str(_d(c).get("path", "")).lower())
               and _d(c).get("provenance_id")]
    if not cleaned:
        return []
    arch = archive_findings[0]
    arch_ev = arch.evidence[0] if getattr(arch, "evidence", None) else None
    for c in cleaned[:10]:
        ev = [EvidenceReference(
            provenance_id=c["provenance_id"], tool="parse_mft", source_family="disk_mft",
            record_id=c.get("record_id"),
            note=f"deleted/recycled {c.get('name')} at {c.get('ctime')}")]
        if arch_ev:
            ev.append(arch_ev)
        findings.append(Finding(
            finding_id=f"EXC-{n:04d}", host_id=host_id,
            title=f"Exfil + cleanup: staging archive with deleted {c.get('name')}",
            category="exfiltration", entity_key=f"exfil_cleanup:{c.get('name')}",
            paths=[p for p in [c.get("path")] if p],
            description=(f"Exfil-staging archive correlates with anti-forensic cleanup "
                        f"('{c.get('name')}' deleted/recycled) — collection followed by tool removal."),
            confidence=Confidence.likely, rule="exfil_staging.cleanup_correlation",
            source_count=2, evidence=ev,
            tags=["exfiltration", "anti_forensics", "correlation"],
            mitre_mapping=["T1070.004", "T1560"],
        ))
        n += 1
    return findings

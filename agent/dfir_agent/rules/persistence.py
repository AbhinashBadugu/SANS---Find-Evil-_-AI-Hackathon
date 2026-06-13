"""Persistence rules (disk).

Two classic mechanisms the disk pass otherwise leaves on the table:
  * Run keys (family=disk_registry) — HKLM/HKCU ...\\CurrentVersion\\Run values. Only
    flagged when the target path is itself an indicator (a system-name binary in a
    non-system directory, or a temp/public/programdata drop) — a legitimate vendor
    autorun in Program Files is not flagged.
  * `at`-scheduled jobs (family=disk_mft) — \\Windows\\Tasks\\At<N>.job, created by the
    `at` command, a long-standing lateral-movement / persistence technique. Benign
    vendor tasks (GoogleUpdate…, AppleSoftwareUpdate…) are ignored by construction.
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

from ..state import Confidence, EvidenceReference, Finding
from .winpath import mft_full_path, normalize_winpath

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

# Target-path indicators that make a Run value suspicious.
_SUSP_PATH = ("\\dllhost\\", "\\temp\\", "\\appdata\\", "\\programdata\\",
              "\\users\\public\\", "\\$recycle", "\\perflogs\\", "\\windows\\temp\\")
# System binary names that are benign in system32 but a masquerade anywhere else.
_SYS_NAMES = {"svchost.exe", "services.exe", "lsass.exe", "dllhost.exe", "csrss.exe", "winlogon.exe"}
_AT_JOB = re.compile(r"^at\d+\.job$", re.IGNORECASE)


def _suspicious_target(value_data: str) -> str | None:
    v = (value_data or "").strip().lower()
    if not v:
        return None
    for hint in _SUSP_PATH:
        if hint in v:
            return f"target path contains '{hint.strip(chr(92))}'"
    base = re.split(r"[\\/]", v)[-1]
    if base in _SYS_NAMES and "\\system32\\" + base not in v and not v.endswith("\\system32\\" + base):
        # a system-process name running from somewhere other than system32 root
        parent = v.rsplit("\\", 1)[0] if "\\" in v else ""
        if not parent.endswith("\\system32"):
            return f"system-process name '{base}' from a non-system path"
    return None


def _resolve_recmd_csv(path: str) -> Path | None:
    """Accept the RECmd batch CSV directly, or a registry dir holding timestamped
    `*RECmd_Batch*Output.csv` files (parse_registry returns the dir) — pick newest."""
    p = Path(path)
    if p.is_file():
        return p
    if p.is_dir():
        cands = sorted(p.glob("*RECmd_Batch*Output.csv")) + sorted(p.glob("**/*RECmd_Batch*Output.csv"))
        if cands:
            return max(cands, key=lambda c: c.name)  # newest timestamp prefix
    return None


def detect_run_keys(
    recmd_csv: str, *, host_id: str, provenance_id: str, next_id, cap: int = 25
) -> list[Finding]:
    p = _resolve_recmd_csv(recmd_csv)
    if not p or not p.exists():
        return []
    recmd_csv = str(p)
    findings: list[Finding] = []
    seen: set[tuple] = set()
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            keypath = (row.get("KeyPath") or "").lower()
            if not (keypath.endswith("\\run") or keypath.endswith("\\runonce")):
                continue
            value_name = (row.get("ValueName") or "").strip()
            value_data = (row.get("ValueData") or "").strip()
            reason = _suspicious_target(value_data)
            if not reason:
                continue
            key = (value_name, value_data.lower())
            if key in seen:
                continue
            seen.add(key)
            target = normalize_winpath(value_data) or value_data
            run_hive = "RunOnce" if keypath.endswith("runonce") else "Run"
            findings.append(Finding(
                finding_id=next_id(), host_id=host_id,
                title=f"Run key persistence: {value_name} → {target}",
                category="persistence", entity_key=f"path:{target}", paths=[target],
                description=(
                    f"Registry {run_hive} key value '{value_name}' = '{value_data}' establishes "
                    f"autostart persistence ({reason}). The implant relaunches at logon via this Run key."
                ),
                confidence=Confidence.likely, rule="persistence.run_key", source_count=1,
                evidence=[EvidenceReference(
                    provenance_id=provenance_id, record_id=f"Run:{value_name}", tool="parse_registry",
                    artifact_path=recmd_csv, source_family="disk_registry",
                    note=f"Registry {run_hive} key: {value_name}={value_data} ({reason})",
                )],
                tags=["disk", "registry", "persistence", "run_key"],
            ))
            if len(findings) >= cap:
                break
    return findings


def detect_scheduled_at_jobs(
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
            if not _AT_JOB.match(fname):
                continue
            full = mft_full_path(row.get("ParentPath") or "", fname) or fname
            if full in seen:
                continue
            seen.add(full)
            entry = row.get("EntryNumber", "?")
            findings.append(Finding(
                finding_id=next_id(), host_id=host_id,
                title=f"Scheduled task persistence: {fname}",
                category="persistence", entity_key=f"path:{full}", paths=[full],
                description=(
                    f"MFT entry {entry}: '{full}' is an `at`-command scheduled job. `at`-created "
                    f"jobs ({fname}) are a classic lateral-movement / persistence mechanism used to "
                    f"run a payload at a chosen time, often after a remote PsExec session."
                ),
                confidence=Confidence.likely, rule="persistence.at_job", source_count=1,
                evidence=[EvidenceReference(
                    provenance_id=provenance_id, record_id=f"MFT#{entry}", tool="parse_mft",
                    artifact_path=mft_csv, source_family="disk_mft",
                    note=f"$MFT entry {entry}: scheduled `at` job {full}",
                )],
                tags=["disk", "mft", "persistence", "scheduled_task"],
            ))
            if len(findings) >= cap:
                break
    return findings

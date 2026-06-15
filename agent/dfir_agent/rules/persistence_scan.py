"""Persistence detection expansion (family=persistence).

Generic detectors over already-parsed rows:
  * service installs (7045) with non-standard / cmd-wrapped / PsExec binaries
  * Run / RunOnce values pointing at non-standard binaries
  * scheduled tasks incl. legacy At*.job, with non-standard actions
Behavioural and location-gated: a service/task/Run entry pointing at a SIGNED
Windows location is NOT flagged (normal admin tooling), so this does not call
every service malicious. No new evidence reader.
"""

from __future__ import annotations

import re

from .benign_allowlist import is_benign_location
from ..state import Confidence, EvidenceReference, Finding

_STAGING = re.compile(r"\\(temp|tmp|users\\public|programdata|\$recycle\.bin|recycler|"
                      r"perflogs|appdata\\local\\temp|windows\\temp)\\", re.IGNORECASE)
_CMD_WRAP = re.compile(r"\bcmd(\.exe)?\b.*?/[ck]\b", re.IGNORECASE)
_PSEXEC = re.compile(r"psexesvc", re.IGNORECASE)
_AT_JOB = re.compile(r"\bat\d*\.job\b|\\tasks\\.*\.job$", re.IGNORECASE)


def _d(x) -> dict:
    return x if isinstance(x, dict) else x.model_dump()


def _ev(r, tool, fam, note):
    return EvidenceReference(provenance_id=r.get("provenance_id", ""), tool=tool,
                             artifact_path=r.get("path") or r.get("artifact_path"),
                             source_family=fam, record_id=r.get("record_id"), note=note)


def detect_service_persistence(rows, *, host_id: str, id_start: int = 1) -> list[Finding]:
    findings, n = [], id_start
    for raw in rows or []:
        r = _d(raw)
        img = str(r.get("image_path") or r.get("service_image") or r.get("binary") or "")
        svc = str(r.get("service_name") or r.get("name") or "")
        if not r.get("provenance_id"):
            continue
        psexec = bool(_PSEXEC.search(img) or _PSEXEC.search(svc))
        wrapped = bool(_CMD_WRAP.search(img))
        staged = bool(_STAGING.search(img)) or (img and not is_benign_location(img) and img.lower().endswith(".exe"))
        if not (psexec or wrapped or staged):
            continue
        conf = Confidence.likely if (psexec or staged) else Confidence.suspicious
        why = ("PsExec service (remote execution)" if psexec else
               "cmd-wrapped service command" if wrapped else
               "service binary in a non-standard/staging path")
        findings.append(Finding(
            finding_id=f"SP-{n:04d}", host_id=host_id,
            title=f"Suspicious service install: {svc or img}",
            category="persistence", entity_key=f"service:{svc or img}", paths=[img] if img else [],
            description=f"7045 service install '{svc}' -> '{img}': {why}.",
            confidence=conf, rule="persistence_scan.service", source_count=1,
            evidence=[_ev(r, "parse_evtx", "evtx", f"7045 {svc} -> {img} ({why})")],
            tags=["persistence", "service"],
            mitre_mapping=["T1543.003"] + (["T1021.002"] if psexec else []),
        ))
        n += 1
    return findings


def detect_run_key_persistence(rows, *, host_id: str, id_start: int = 1) -> list[Finding]:
    findings, n = [], id_start
    for raw in rows or []:
        r = _d(raw)
        key = str(r.get("key") or "")
        if "run" not in key.lower():
            continue
        target = str(r.get("value_data") or r.get("data") or r.get("decoded_data") or "")
        if not target or is_benign_location(target) or not r.get("provenance_id"):
            continue
        findings.append(Finding(
            finding_id=f"RK-{n:04d}", host_id=host_id,
            title=f"Autorun persistence: {key}\\{r.get('value_name')}",
            category="persistence", entity_key=f"runkey:{key}\\{r.get('value_name')}",
            paths=[target],
            description=(f"Run/RunOnce value {key}\\{r.get('value_name')} launches '{target}', "
                        "which is not in a signed Windows location — autostart persistence."),
            confidence=Confidence.likely, rule="persistence_scan.run_key", source_count=1,
            evidence=[_ev(r, "parse_registry", "registry", f"{key}\\{r.get('value_name')} -> {target}")],
            tags=["persistence", "registry", "autorun"], mitre_mapping=["T1547.001"],
        ))
        n += 1
    return findings


def detect_scheduled_task_persistence(rows, *, host_id: str, id_start: int = 1) -> list[Finding]:
    findings, n = [], id_start
    for raw in rows or []:
        r = _d(raw)
        name = str(r.get("task_name") or r.get("name") or r.get("path") or "")
        action = str(r.get("action_path") or r.get("action") or r.get("command") or "")
        if not r.get("provenance_id"):
            continue
        legacy_at = bool(_AT_JOB.search(name))
        staged = bool(action and (_STAGING.search(action) or (not is_benign_location(action) and action.lower().endswith(".exe"))))
        if not (legacy_at or staged):
            continue
        conf = Confidence.likely if staged else Confidence.suspicious
        why = "legacy At job" if legacy_at else "task action in a non-standard path"
        findings.append(Finding(
            finding_id=f"ST-{n:04d}", host_id=host_id,
            title=f"Scheduled-task persistence: {name}",
            category="persistence", entity_key=f"task:{name}", paths=[action] if action else [],
            description=f"Scheduled task '{name}' -> '{action}': {why}.",
            confidence=conf, rule="persistence_scan.scheduled_task", source_count=1,
            evidence=[_ev(r, "parse_mft", "disk_mft", f"task {name} -> {action} ({why})")],
            tags=["persistence", "scheduled_task"], mitre_mapping=["T1053.005", "T1053.002"],
        ))
        n += 1
    return findings

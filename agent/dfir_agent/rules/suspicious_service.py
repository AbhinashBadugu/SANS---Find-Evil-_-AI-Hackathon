"""Suspicious-service rule driven off windows.svcscan (playbook §7, family=services).

Conservative by design: a Windows host has hundreds of legitimate services, so we
flag only services whose backing binary path is itself an anomaly — a system
process name in a non-standard directory, or an executable in a world-writable
location (Temp / AppData / ProgramData / a user profile). Anything else is left
alone (anti-FP discipline).
"""

from __future__ import annotations

import re

from ..state import Confidence, EvidenceReference, Finding
from .winpath import SYSTEM32, split_dir_base

_BAD_LOCATION = re.compile(
    r"\\(temp|tmp|appdata|programdata|recycle|perflogs)\\", re.IGNORECASE
)
# System-process names that are legitimate ONLY when hosted from system32.
_SYSTEM_HOSTS = {"svchost.exe", "services.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "smss.exe"}


def _binary_path(row: dict) -> str:
    return str(row.get("Binary") or row.get("Binary (Registry)") or "")


def detect_suspicious_services(
    svcscan_rows: list[dict],
    *,
    host_id: str,
    provenance_id: str,
    artifact_path: str | None,
    next_id,
) -> list[Finding]:
    findings: list[Finding] = []
    for row in svcscan_rows:
        binary = _binary_path(row)
        directory, base = split_dir_base(binary)
        if not base:
            continue
        bad_loc = bool(_BAD_LOCATION.search("\\" + (directory or "") + "\\"))
        # A system-process name is only legitimate when it sits directly in system32.
        fake_sys = base in _SYSTEM_HOSTS and directory is not None and directory != SYSTEM32
        if not (bad_loc or fake_sys):
            continue
        name = row.get("Name")
        pid = row.get("PID")
        reason = "binary in a non-standard/writable location" if bad_loc else "system-process name outside system32"
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"Suspicious service '{name}' ({reason})",
                category="malicious_service",
                entity_key=f"pid:{pid}" if isinstance(pid, int) and pid > 0 else f"svc:{name}",
                description=(
                    f"Service '{name}' (PID {pid}, state {row.get('State')}) is backed by "
                    f"'{binary}' — {reason}, which is unusual for a legitimate service."
                ),
                confidence=Confidence.likely,
                rule="suspicious_service.binary_path",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"Service={name}",
                        tool="run_volatility_plugin",
                        artifact_path=artifact_path,
                        source_family="services",
                        note=f"windows.svcscan: '{name}' binary '{binary}' ({reason})",
                    )
                ],
                tags=["memory", "svcscan", "service"],
            )
        )
    return findings

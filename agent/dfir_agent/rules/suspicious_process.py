"""Process-anomaly rules driven off windows.pslist (playbook §7.4).

The masquerade rule catches the tdungan implant from pslist ALONE: a core
Windows service host (`svchost.exe`) is, on a real system, always a direct child
of `services.exe`. PID 3296 on xp-tdungan is a child of `explorer.exe` (1900) —
a parent-process anomaly. That is deterministic, citable, and needs no LLM.

A second, independent signal (the non-standard image path
`C:\\windows\\system32\\dllhost\\svchost.exe`) lives in windows.cmdline and is
folded in by the memory node when available — but the rule below stands on
pslist on its own.
"""

from __future__ import annotations

from ..state import (
    Confidence,
    EvidenceReference,
    Finding,
)

# System processes and the process they are expected to be a direct child of.
# Keys/values are compared case-insensitively on the image file name.
EXPECTED_PARENT: dict[str, set[str]] = {
    "svchost.exe": {"services.exe"},
    "services.exe": {"winlogon.exe", "wininit.exe"},
    "lsass.exe": {"winlogon.exe", "wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "smss.exe": {"system"},
}


def _norm(name: object) -> str:
    return str(name or "").strip().lower()


def detect_parent_anomalies(
    pslist_rows: list[dict],
    *,
    host_id: str,
    provenance_id: str,
    artifact_path: str | None,
    next_id,
) -> list[Finding]:
    """Emit a `suspicious` Finding for each system process with the wrong parent.

    Parameters
    ----------
    pslist_rows : parsed rows from windows.pslist (need PID, PPID, ImageFileName).
    provenance_id : the provenance_id of the run_volatility_plugin(pslist) call.
    next_id : zero-arg callable returning the next finding_id (from CaseState).
    """
    by_pid: dict[int, dict] = {}
    for row in pslist_rows:
        pid = row.get("PID")
        if isinstance(pid, int):
            by_pid[pid] = row

    findings: list[Finding] = []
    for row in pslist_rows:
        image = _norm(row.get("ImageFileName"))
        expected = EXPECTED_PARENT.get(image)
        if not expected:
            continue
        pid = row.get("PID")
        ppid = row.get("PPID")
        parent = by_pid.get(ppid)
        parent_image = _norm(parent.get("ImageFileName")) if parent else None

        # Only flag when the parent is PRESENT and its image is wrong. A missing
        # parent is common and benign (parents legitimately exit), so we do NOT
        # treat it as a masquerade — that would be a false positive, which the
        # anti-FP discipline forbids.
        if parent_image is None or parent_image in expected:
            continue

        parent_desc = f"{parent_image} (PID {ppid})"
        expected_desc = " or ".join(sorted(expected))
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"{image} running under an unexpected parent (PID {pid})",
                category="process_masquerade",
                description=(
                    f"Process '{image}' (PID {pid}) is a child of {parent_desc}, but a "
                    f"legitimate {image} is started by {expected_desc}. This parent-process "
                    f"anomaly is a classic masquerade / process-hollowing indicator."
                ),
                confidence=Confidence.suspicious,
                rule="suspicious_process.parent_anomaly",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"PID={pid}",
                        tool="run_volatility_plugin",
                        artifact_path=artifact_path,
                        note=(
                            f"windows.pslist: {image} PID={pid} PPID={ppid} "
                            f"parent={parent_image or 'unknown'}; expected parent {expected_desc}"
                        ),
                    )
                ],
                tags=["memory", "pslist", image],
            )
        )
    return findings

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
                entity_key=f"pid:{pid}",
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
                        source_family="process_tree",
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


# Canonical install directory for known Windows system binaries (lower-case).
from .winpath import SYSTEM32 as _SYSTEM32, WINDIR as _WINDIR, split_dir_base

EXPECTED_DIR: dict[str, str] = {
    "svchost.exe": _SYSTEM32,
    "services.exe": _SYSTEM32,
    "lsass.exe": _SYSTEM32,
    "csrss.exe": _SYSTEM32,
    "winlogon.exe": _SYSTEM32,
    "smss.exe": _SYSTEM32,
    "lsm.exe": _SYSTEM32,
    "spoolsv.exe": _SYSTEM32,
    "taskhost.exe": _SYSTEM32,
    "explorer.exe": _WINDIR,
}


def _exe_path_from_args(args: object) -> str | None:
    """Pull argv[0] (the image path) out of a cmdline 'Args' string."""
    s = str(args or "").strip()
    if not s:
        return None
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    return s.split(" ", 1)[0]


def detect_path_masquerade(
    cmdline_rows: list[dict],
    *,
    host_id: str,
    provenance_id: str,
    artifact_path: str | None,
    next_id,
) -> list[Finding]:
    """Flag a known system binary whose image path is NOT its canonical directory.

    Catches the implant directly: `svchost.exe` launched from
    `C:\\windows\\system32\\dllhost\\` instead of `C:\\windows\\system32\\`.
    Family = command_line.
    """
    findings: list[Finding] = []
    for row in cmdline_rows:
        path = _exe_path_from_args(row.get("Args"))
        directory, base = split_dir_base(path)
        if not base:
            continue
        expected_dir = EXPECTED_DIR.get(base)
        if not expected_dir:
            continue
        # A bare image name (no directory) carries no path evidence — do NOT judge it.
        if directory is None:
            continue
        if directory == expected_dir:
            continue
        pid = row.get("PID")
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"{base} running from a non-standard path (PID {pid})",
                category="process_masquerade",
                entity_key=f"pid:{pid}",
                description=(
                    f"'{base}' (PID {pid}) is running from '{path}', but the legitimate "
                    f"{base} lives in '{expected_dir}'. Placing a system binary in a fake "
                    f"sibling directory is a masquerade technique."
                ),
                confidence=Confidence.suspicious,
                rule="suspicious_process.path_masquerade",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"PID={pid}",
                        tool="run_volatility_plugin",
                        artifact_path=artifact_path,
                        source_family="command_line",
                        note=f"windows.cmdline: PID={pid} image path '{path}' (expected dir {expected_dir})",
                    )
                ],
                tags=["memory", "cmdline", base],
            )
        )
    return findings


def detect_hidden_processes(
    psscan_rows: list[dict],
    pslist_rows: list[dict],
    *,
    host_id: str,
    provenance_id: str,
    artifact_path: str | None,
    next_id,
) -> list[Finding]:
    """Hidden-process diff: a process found by psscan (pool scan) but absent from
    pslist (the linked list) and with NO exit time is potentially unlinked/hidden.

    A `suspicious` lead only — single identity family, never auto-confirmed.
    """
    live_pids = {r.get("PID") for r in pslist_rows}
    findings: list[Finding] = []
    emitted: set[int] = set()
    for row in psscan_rows:
        pid = row.get("PID")
        if pid in live_pids or pid in emitted:
            continue
        if row.get("ExitTime"):  # exited processes legitimately linger in the pool
            continue
        emitted.add(pid)
        image = str(row.get("ImageFileName") or "?")
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"Possible unlinked/hidden process: {image} (PID {pid})",
                category="hidden_process",
                entity_key=f"pid:{pid}",
                description=(
                    f"'{image}' (PID {pid}, PPID {row.get('PPID')}) appears in windows.psscan "
                    f"but not in windows.pslist, with no recorded exit time. This can indicate "
                    f"DKOM/unlinking to hide a running process."
                ),
                confidence=Confidence.suspicious,
                rule="suspicious_process.hidden_process",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"PID={pid}",
                        tool="run_volatility_plugin",
                        artifact_path=artifact_path,
                        source_family="process_tree",
                        note=f"windows.psscan: PID={pid} {image} present in psscan, absent from pslist, ExitTime=None",
                    )
                ],
                tags=["memory", "psscan", "hidden", image],
            )
        )
    return findings

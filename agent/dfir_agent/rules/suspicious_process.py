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
        full_path = f"{directory}\\{base}"
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"{base} running from a non-standard path (PID {pid})",
                category="process_masquerade",
                entity_key=f"pid:{pid}",
                paths=[full_path],
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


def _is_plausible_process(name: object, pid: object, ppid: object) -> bool:
    """Reject psscan memory smears: garbage image names or absurd PID/PPID values.

    Real Windows PIDs/PPIDs are small; a valid image name is short printable ASCII.
    The smear `onScope=NonSxS\\ufffd` (PPID 50788797134638) fails on both counts.
    """
    if not isinstance(pid, int) or not (0 <= pid < 1_000_000):
        return False
    if ppid is not None and (not isinstance(ppid, int) or not (0 <= ppid < 1_000_000)):
        return False
    s = str(name or "")
    if not s or len(s) > 64:
        return False
    if "�" in s or "=" in s:  # replacement char / non-filename chars => smear
        return False
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in s):  # non-printable => smear
        return False
    return True


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
        if not _is_plausible_process(row.get("ImageFileName"), pid, row.get("PPID")):
            continue  # psscan smear / corrupted pool entry, not a real process
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


# --------------------------------------------------------------------------- #
# windows.pstree — parent-child validation (Phase 2 correlation)
# --------------------------------------------------------------------------- #
def _pstree_index(pstree_rows: list[dict]) -> dict[int, dict]:
    """pid -> {name, ppid}. pstree may prefix names with tree markers ('* ')."""
    idx: dict[int, dict] = {}
    for row in pstree_rows:
        pid = row.get("PID")
        if isinstance(pid, int):
            idx[pid] = {
                "name": _norm(str(row.get("ImageFileName") or "").lstrip("* ").strip()),
                "ppid": row.get("PPID"),
            }
    return idx


def validate_parentage_with_pstree(
    findings: list[Finding],
    pstree_rows: list[dict],
    pslist_rows: list[dict],
    *,
    provenance_id: str,
    artifact_path: str | None,
) -> int:
    """Corroborate or contradict process findings using windows.pstree (in place).

    pslist and pstree both read the active-process list, so a pstree reference is
    the SAME `process_tree` family — it strengthens the audit trail and confirms a
    finding across a second plugin WITHOUT independently inflating confidence
    (only DISTINCT families confirm). For each process finding:

      * process_masquerade: attach pstree's view of the parent. If pstree's PPID
        DISAGREES with pslist's, tag a contradiction instead of corroboration.
      * hidden_process: if pstree (active list) ALSO omits the PID, that is
        positive corroboration of unlinking/hiding.

    Returns the number of findings annotated.
    """
    ptree = _pstree_index(pstree_rows)
    pslist_ppid = {r.get("PID"): r.get("PPID") for r in pslist_rows if isinstance(r.get("PID"), int)}
    annotated = 0
    for f in findings:
        ek = f.entity_key or ""
        if not ek.startswith("pid:"):
            continue
        try:
            pid = int(ek.split(":", 1)[1])
        except ValueError:
            continue

        if f.category == "hidden_process":
            if pid not in ptree:
                f.evidence.append(EvidenceReference(
                    provenance_id=provenance_id, record_id=f"PID={pid}",
                    tool="run_volatility_plugin", artifact_path=artifact_path,
                    source_family="process_tree",
                    note=(f"windows.pstree: PID={pid} absent from the active process tree too "
                          f"— consistent with unlinking/hiding"),
                ))
                f.tags = sorted(set(f.tags) | {"pstree_corroborated"})
                annotated += 1
            continue

        if f.category != "process_masquerade" or pid not in ptree:
            continue
        node = ptree[pid]
        parent_name = _norm(ptree.get(node["ppid"], {}).get("name")) or "unknown"
        mismatch = pid in pslist_ppid and node["ppid"] != pslist_ppid[pid]
        f.evidence.append(EvidenceReference(
            provenance_id=provenance_id, record_id=f"PID={pid}",
            tool="run_volatility_plugin", artifact_path=artifact_path,
            source_family="process_tree",
            note=(f"windows.pstree: PID={pid} {node['name']} child of {parent_name} (PID {node['ppid']})"
                  + (f" — DISAGREES with pslist PPID {pslist_ppid[pid]}" if mismatch else " — corroborates pslist")),
        ))
        f.tags = sorted(set(f.tags) | ({"pstree_parent_mismatch"} if mismatch else {"pstree_corroborated"}))
        annotated += 1
    return annotated


# --------------------------------------------------------------------------- #
# windows.cmdline — suspicious command-line content (LOLBIN / encoded execution)
# --------------------------------------------------------------------------- #
def _suspicious_cmdline_reason(args_lower: str) -> str | None:
    """Conservative, well-established abuse patterns only (keeps FPs near zero)."""
    a = args_lower
    if "powershell" in a and any(k in a for k in (
        "-enc", "-encodedcommand", "frombase64string", "downloadstring",
        "downloadfile", "iex", "invoke-expression", "-w hidden", "-windowstyle hidden",
    )):
        return "PowerShell with encoded/hidden/download flags"
    if "rundll32" in a and ("javascript:" in a or "http://" in a or "https://" in a):
        return "rundll32 invoking script/remote content"
    if "mshta" in a and ("http" in a or "javascript:" in a or "vbscript:" in a):
        return "mshta executing remote/script content"
    if "regsvr32" in a and "scrobj" in a:
        return "regsvr32 scriptlet (Squiblydoo)"
    if "certutil" in a and ("urlcache" in a or "-decode" in a):
        return "certutil download/decode"
    if "bitsadmin" in a and "/transfer" in a:
        return "bitsadmin remote file transfer"
    if "wmic" in a and "process call create" in a:
        return "wmic process call create"
    return None


def detect_suspicious_command_lines(
    cmdline_rows: list[dict],
    *,
    host_id: str,
    provenance_id: str,
    artifact_path: str | None,
    next_id,
) -> list[Finding]:
    """Flag command lines matching known LOLBIN / encoded-execution abuse patterns.

    A `suspicious` single-family (command_line) lead — never auto-confirmed alone.
    Keyed by PID so it merges with this PID's other signals (a process that is BOTH
    masqueraded AND launched with an encoded command line gains corroboration).
    """
    findings: list[Finding] = []
    for row in cmdline_rows:
        args = str(row.get("Args") or "")
        reason = _suspicious_cmdline_reason(args.lower())
        if not reason:
            continue
        pid = row.get("PID")
        proc = str(row.get("Process") or "?")
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"Suspicious command line: {proc} (PID {pid})",
                category="suspicious_command_line",
                entity_key=f"pid:{pid}",
                description=(
                    f"PID {pid} ({proc}) command line matches a known abuse pattern "
                    f"({reason}). Args: {args[:200]}"
                ),
                confidence=Confidence.suspicious,
                rule="suspicious_process.suspicious_command_line",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"PID={pid}",
                        tool="run_volatility_plugin",
                        artifact_path=artifact_path,
                        source_family="command_line",
                        note=f"windows.cmdline: PID={pid} {proc} — {reason}",
                    )
                ],
                tags=["memory", "cmdline", proc.lower()],
            )
        )
    return findings

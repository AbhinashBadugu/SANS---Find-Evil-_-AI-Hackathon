"""inspect_disk + extract_artifacts — read the filesystem out of the raw image
without mounting it read-write and without admin.

inspect_disk:    find where the filesystem starts. These SANS images have no
                 partition table, so mmls is empty -> we fall back to fsstat at
                 offset 0 and confirm NTFS. (No guessing: fsstat must confirm.)
extract_artifacts: carve out just the files we need ($MFT, registry hives, event
                 logs) with Sleuth Kit (ifind to find, icat to copy out).
"""

import re
import subprocess

from forensic_mcp.executor import run_logged_command, run_logged_extract
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_case
from forensic_mcp.provenance import log_action, next_provenance_id
from forensic_mcp.schemas import (
    InspectDiskRequest, InspectDiskResponse,
    ExtractArtifactsRequest, GenericToolResponse, ToolStatus,
    CarveFilesRequest, CarveFilesResponse,
)

# Where Windows keeps things, across XP / Win7 / 2008 (we try each).
CONFIG_DIRS = ["/Windows/System32/config", "/WINDOWS/system32/config", "/WINNT/system32/config"]
HIVES = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
EVTX_DIR = "/Windows/System32/winevt/Logs"
EVTX_FILES = [
    "Security.evtx", "System.evtx", "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
]
# Windows XP / 2003 keep event logs as legacy .evt in the config dir.
LEGACY_EVT_FILES = ["SecEvent.Evt", "SysEvent.Evt", "AppEvent.Evt"]


def _ifind(ewf1: str, path: str) -> int | None:
    """Return the inode for a path inside the image, or None if absent."""
    try:
        out = subprocess.run(["ifind", "-n", path, ewf1], capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001
        return None
    val = (out.stdout or "").strip()
    return int(val) if val.isdigit() else None


def inspect_disk(req: InspectDiskRequest) -> InspectDiskResponse:
    ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        ewf1 = ensure_inside_case(req.ewf1_path)
    except Exception as e:  # noqa: BLE001
        return InspectDiskResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=str(e))

    # First try mmls (the normal way).
    mmls = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="mmls", wrapper_name="inspect_disk",
        command=["mmls", str(ewf1)], input_paths=[ewf1], output_paths=[], timeout_seconds=120,
    )
    mmls_text = mmls.stdout_path.read_text(encoding="utf-8", errors="replace") if mmls.stdout_path.exists() else ""

    # Fall back to fsstat at offset 0 and require it to confirm a filesystem.
    pid2 = next_provenance_id(req.case_id)
    fsstat = run_logged_command(
        provenance_id=pid2, case_id=req.case_id, host_id=req.host_id,
        tool_name="fsstat", wrapper_name="inspect_disk",
        command=["fsstat", "-o", "0", str(ewf1)], input_paths=[ewf1], output_paths=[], timeout_seconds=120,
    )
    fs_text = fsstat.stdout_path.read_text(encoding="utf-8", errors="replace") if fsstat.stdout_path.exists() else ""

    fs_type = None
    for line in fs_text.splitlines():
        if line.startswith("File System Type:"):
            fs_type = line.split(":", 1)[1].strip()
            break

    if fs_type:
        method = "mmls" if mmls_text.strip() else "fsstat-offset-0-fallback"
        return InspectDiskResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                                   fs_type=fs_type, offset_bytes=0, method=method, provenance_id=pid2)
    return InspectDiskResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                               provenance_id=pid2, error="No filesystem confirmed at offset 0")


def extract_artifacts(req: ExtractArtifactsRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        ewf1 = ensure_inside_case(req.ewf1_path)
    except Exception as e:  # noqa: BLE001
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=str(e))

    extracted = dirs["extracted"]
    evtx_out = extracted / "eventlogs"
    evtx_out.mkdir(parents=True, exist_ok=True)
    got: dict[str, str] = {}
    outputs = []
    ewf1s = str(ewf1)

    def carve(inode: int, dest, label: str):
        pid = next_provenance_id(req.case_id)
        r = run_logged_extract(
            provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
            tool_name="icat", wrapper_name="extract_artifacts",
            command=["icat", ewf1s, str(inode)], output_file=dest,
            input_paths=[ewf1], timeout_seconds=1800,
        )
        if r.status == "success" and dest.stat().st_size > 0:
            got[label] = str(dest)
            outputs.append(dest)
            return True
        return False

    # $MFT is always MFT entry 0.
    carve(0, extracted / "$MFT", "$MFT")

    # Registry hives — try each known config dir.
    for hive in HIVES:
        for cdir in CONFIG_DIRS:
            inode = _ifind(ewf1s, f"{cdir}/{hive}")
            if inode is not None:
                carve(inode, extracted / hive, hive)
                break

    # Event logs (modern .evtx).
    for fname in EVTX_FILES:
        inode = _ifind(ewf1s, f"{EVTX_DIR}/{fname}")
        if inode is not None:
            carve(inode, evtx_out / fname.replace("%4", "-"), f"evtx:{fname}")

    # Event logs (legacy .evt — Windows XP / 2003).
    legacy_out = extracted / "eventlogs_legacy"
    legacy_out.mkdir(parents=True, exist_ok=True)
    for fname in LEGACY_EVT_FILES:
        for cdir in CONFIG_DIRS:
            inode = _ifind(ewf1s, f"{cdir}/{fname}")
            if inode is not None:
                carve(inode, legacy_out / fname, f"evt:{fname}")
                break

    return GenericToolResponse(
        status=ToolStatus.success if got else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id, output_paths=outputs,
        info={"extracted": got}, provenance_id=provenance_id,
        error=None if got else "No artifacts extracted",
    )


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name) or "file"


def carve_files(req: CarveFilesRequest) -> CarveFilesResponse:
    """Carve specific in-image files out by path (read-only, Sleuth Kit ifind+icat).

    Used to pull files the fixed extract_artifacts set doesn't (Java cache .idx,
    suspect executables, .reg exports) so the static/file detections can run.
    Normalises Windows-style paths to forward slashes; skips anything not found.
    One provenance line summarising the batch."""
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        ewf1 = ensure_inside_case(req.ewf1_path)
    except Exception as e:  # noqa: BLE001
        return CarveFilesResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                  provenance_id=provenance_id, error=str(e))

    out_dir = ensure_inside_case(dirs["extracted"] / "carved")
    out_dir.mkdir(parents=True, exist_ok=True)
    ewf1s = str(ewf1)
    carved: dict[str, str] = {}

    for raw in (req.paths or [])[: req.max_files]:
        norm = "/" + raw.replace("\\", "/").lstrip("./").lstrip("/")
        inode = _ifind(ewf1s, norm)
        if inode is None:
            continue
        dest = out_dir / f"{inode}_{_safe(norm.rsplit('/', 1)[-1])}"
        pid = next_provenance_id(req.case_id)
        r = run_logged_extract(
            provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
            tool_name="icat", wrapper_name="carve_files",
            command=["icat", ewf1s, str(inode)], output_file=dest,
            input_paths=[ewf1], timeout_seconds=1800,
        )
        if r.status == "success" and dest.exists() and dest.stat().st_size > 0:
            carved[raw] = str(dest)

    log_action(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
               tool_name="icat", wrapper_name="carve_files",
               command=["carve_files", f"{len(carved)}/{len(req.paths or [])} files"],
               output_paths=[out_dir], status="success")
    return CarveFilesResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                              carved=carved, output_dir=out_dir, provenance_id=provenance_id)

"""extract_archive — decompress an evidence archive (.7z / .zip / .gz) so the agent
can ingest compressed evidence (e.g. a memory image shipped as base-dc-memory.7z).

Reads the archive from the read-only EVIDENCE_ROOT, writes the extracted image(s)
into the case write-area under CASE_ROOT, and never modifies the original. One
provenance line per extraction. `7z` handles .7z / .zip / .gz / .tar uniformly.
"""

from __future__ import annotations

import re
from pathlib import Path

from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_case, ensure_inside_evidence
from forensic_mcp.provenance import log_rejection, next_provenance_id
from forensic_mcp.schemas import ExtractArchiveRequest, ExtractArchiveResponse, ToolStatus

_SUPPORTED = (".7z", ".zip", ".gz", ".tgz", ".tar")


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def _fail(req: ExtractArchiveRequest, pid: str, error: str) -> ExtractArchiveResponse:
    return ExtractArchiveResponse(
        status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
        archive_path=req.archive_path, provenance_id=pid, error=error,
    )


def extract_archive(req: ExtractArchiveRequest) -> ExtractArchiveResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)

    # 1) The archive MUST sit inside the read-only evidence area.
    try:
        archive = ensure_inside_evidence(req.archive_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(
            provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
            tool_name="7z", wrapper_name="extract_archive",
            attempted=["7z", "x", str(req.archive_path)], error=str(e),
        )
        return _fail(req, provenance_id, str(e))

    if not archive.exists():
        return _fail(req, provenance_id, f"archive does not exist: {archive}")

    low = archive.name.lower()
    if not (any(low.endswith(s) for s in _SUPPORTED) or ".7z." in low or ".zip." in low):
        return _fail(req, provenance_id, f"unsupported archive type: {archive.name}")

    # 2) Extract into the case write-area (path-gated), never next to the evidence.
    out_dir = ensure_inside_case(dirs["extracted"] / "archives" / _safe(archive.name))
    out_dir.mkdir(parents=True, exist_ok=True)

    command = ["7z", "x", str(archive), f"-o{out_dir}", "-y"]
    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="7z", wrapper_name="extract_archive", command=command,
        input_paths=[archive], output_paths=[out_dir], timeout_seconds=3600,
    )
    if result.status != "success":
        return _fail(req, provenance_id, f"7z extraction failed (see {result.stderr_path})")

    files = sorted(
        (p for p in out_dir.rglob("*") if p.is_file()),
        key=lambda p: p.stat().st_size, reverse=True,
    )
    if not files:
        return _fail(req, provenance_id, "extraction produced no files")

    return ExtractArchiveResponse(
        status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
        archive_path=req.archive_path, output_dir=out_dir,
        extracted_paths=[str(p) for p in files], primary_image=str(files[0]),
        provenance_id=provenance_id,
    )

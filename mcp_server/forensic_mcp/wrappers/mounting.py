"""open_ewf / close_ewf — expose an E01 as a read-only raw image (ewf1) using
ewfmount. ewfmount is a FUSE mount that needs NO admin, and is inherently
read-only, so evidence can never be changed through it."""

from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_evidence, ensure_inside_case
from forensic_mcp.provenance import next_provenance_id, log_rejection
from forensic_mcp.schemas import (
    OpenEwfRequest, OpenEwfResponse, CloseEwfRequest, GenericToolResponse, ToolStatus,
)


def open_ewf(req: OpenEwfRequest) -> OpenEwfResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        e01 = ensure_inside_evidence(req.e01_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="ewfmount", wrapper_name="open_ewf",
                      attempted=["ewfmount", str(req.e01_path)], error=str(e))
        return OpenEwfResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                               provenance_id=provenance_id, error=str(e))

    mount_dir = ensure_inside_case(dirs["host"] / "mounts" / f"ewf_{e01.stem}")
    mount_dir.mkdir(parents=True, exist_ok=True)
    ewf1 = mount_dir / "ewf1"

    if ewf1.exists():  # already mounted
        return OpenEwfResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                               mount_dir=mount_dir, ewf1_path=ewf1, provenance_id=provenance_id)

    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="ewfmount", wrapper_name="open_ewf",
        command=["ewfmount", str(e01), str(mount_dir)],
        input_paths=[e01], output_paths=[ewf1], timeout_seconds=300,
    )
    ok = result.status == "success" and ewf1.exists()
    return OpenEwfResponse(
        status=ToolStatus.success if ok else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id,
        mount_dir=mount_dir if ok else None, ewf1_path=ewf1 if ok else None,
        provenance_id=provenance_id,
        error=None if ok else (result.error or "ewf1 not present after mount"),
    )


def close_ewf(req: CloseEwfRequest) -> GenericToolResponse:
    ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        mount_dir = ensure_inside_case(req.mount_dir)  # only our own mountpoints
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="fusermount", wrapper_name="close_ewf",
                      attempted=["fusermount", "-u", str(req.mount_dir)], error=str(e))
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=str(e))

    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="fusermount", wrapper_name="close_ewf",
        command=["fusermount", "-u", str(mount_dir)],
        input_paths=[], output_paths=[], timeout_seconds=60,
    )
    return GenericToolResponse(
        status=ToolStatus.success if result.status == "success" else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id, provenance_id=provenance_id, error=result.error,
    )

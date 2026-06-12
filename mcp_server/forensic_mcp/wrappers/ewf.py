"""verify_ewf — confirm an E01 disk image is intact (ewfverify). Read-only."""

from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_evidence
from forensic_mcp.provenance import next_provenance_id, log_rejection
from forensic_mcp.schemas import VerifyEwfRequest, GenericToolResponse, ToolStatus


def verify_ewf(req: VerifyEwfRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        e01 = ensure_inside_evidence(req.e01_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="ewfverify", wrapper_name="verify_ewf",
                      attempted=["ewfverify", str(req.e01_path)], error=str(e))
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=str(e))

    out = dirs["outputs"] / f"ewfverify_{e01.name}.txt"
    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="ewfverify", wrapper_name="verify_ewf",
        command=["ewfverify", str(e01)], input_paths=[e01], output_paths=[out],
        timeout_seconds=7200,
    )
    if result.status == "success":
        out.write_text(result.stdout_path.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    return GenericToolResponse(
        status=ToolStatus.success if result.status == "success" else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id,
        output_paths=[out] if result.status == "success" else [],
        provenance_id=provenance_id, error=result.error,
    )

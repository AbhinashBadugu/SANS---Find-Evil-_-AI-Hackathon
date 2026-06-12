"""read_artifact — let the agent read back one of OUR result files so it can see
what a tool produced. Reads only from CASE_ROOT (never from evidence)."""

from forensic_mcp.paths import ensure_inside_case, ensure_host_dirs, validate_id
from forensic_mcp.provenance import next_provenance_id, utc_now, append_provenance
from forensic_mcp.schemas import ReadArtifactRequest, ReadArtifactResponse, ToolStatus, ProvenanceRecord


def read_artifact(req: ReadArtifactRequest) -> ReadArtifactResponse:
    validate_id(req.case_id, "case_id")
    validate_id(req.host_id, "host_id")
    ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    now = utc_now()

    def log(status: str, error: str | None, output_paths=None):
        append_provenance(
            ProvenanceRecord(
                provenance_id=provenance_id,
                case_id=req.case_id,
                host_id=req.host_id,
                tool_name="read_artifact",
                wrapper_name="read_artifact",
                command=["read_artifact", str(req.artifact_path)],
                input_paths=output_paths or [],
                output_paths=[],
                start_time=now,
                end_time=utc_now(),
                exit_code=0 if status == "success" else None,
                status=status,
                error=error,
            )
        )

    # Must be one of our own result files, under CASE_ROOT.
    try:
        path = ensure_inside_case(req.artifact_path)
    except Exception as e:  # noqa: BLE001
        log("failed", str(e))
        return ReadArtifactResponse(
            status=ToolStatus.failed, artifact_path=req.artifact_path,
            provenance_id=provenance_id, error=str(e),
        )

    if not path.is_file():
        log("failed", "Artifact not found or not a file", [path])
        return ReadArtifactResponse(
            status=ToolStatus.failed, artifact_path=path,
            provenance_id=provenance_id, error="Artifact not found or not a file",
        )

    raw = path.read_bytes()
    total = len(raw)
    chunk = raw[: req.max_bytes]
    truncated = total > req.max_bytes
    content = chunk.decode("utf-8", errors="replace")

    log("success", None, [path])
    return ReadArtifactResponse(
        status=ToolStatus.success,
        artifact_path=path,
        content=content,
        truncated=truncated,
        bytes_total=total,
        provenance_id=provenance_id,
    )

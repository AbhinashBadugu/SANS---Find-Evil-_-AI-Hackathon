"""hash_evidence — fingerprint an evidence file with sha256sum so we can prove
it never changed. Reads from EVIDENCE_ROOT, writes the fingerprint into CASE_ROOT."""

from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_evidence
from forensic_mcp.provenance import next_provenance_id, log_rejection
from forensic_mcp.schemas import HashEvidenceRequest, HashEvidenceResponse, ToolStatus


def hash_evidence(req: HashEvidenceRequest) -> HashEvidenceResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)

    # Refuse anything that is not inside the read-only evidence area.
    try:
        evidence_path = ensure_inside_evidence(req.evidence_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(
            provenance_id=provenance_id,
            case_id=req.case_id,
            host_id=req.host_id,
            tool_name="sha256sum",
            wrapper_name="hash_evidence",
            attempted=["sha256sum", str(req.evidence_path)],
            error=str(e),
        )
        return HashEvidenceResponse(
            status=ToolStatus.failed,
            case_id=req.case_id,
            host_id=req.host_id,
            evidence_path=req.evidence_path,
            provenance_id=provenance_id,
            error=str(e),
        )

    if not evidence_path.exists():
        log_rejection(
            provenance_id=provenance_id,
            case_id=req.case_id,
            host_id=req.host_id,
            tool_name="sha256sum",
            wrapper_name="hash_evidence",
            attempted=["sha256sum", str(evidence_path)],
            input_paths=[evidence_path],
            error="Evidence path does not exist",
        )
        return HashEvidenceResponse(
            status=ToolStatus.failed,
            case_id=req.case_id,
            host_id=req.host_id,
            evidence_path=evidence_path,
            provenance_id=provenance_id,
            error="Evidence path does not exist",
        )

    output_path = dirs["hashes"] / f"{evidence_path.name}.sha256.txt"
    result = run_logged_command(
        provenance_id=provenance_id,
        case_id=req.case_id,
        host_id=req.host_id,
        tool_name="sha256sum",
        wrapper_name="hash_evidence",
        command=["sha256sum", str(evidence_path)],
        input_paths=[evidence_path],
        output_paths=[output_path],
        timeout_seconds=3600,
    )

    sha256_value = None
    if result.status == "success":
        # sha256sum prints "<hash>  <path>"
        line = result.stdout_path.read_text(encoding="utf-8", errors="replace").strip()
        sha256_value = line.split()[0] if line else None
        if sha256_value:
            output_path.write_text(f"{sha256_value}  {evidence_path}\n", encoding="utf-8")

    return HashEvidenceResponse(
        status=ToolStatus.success if (result.status == "success" and sha256_value) else ToolStatus.failed,
        case_id=req.case_id,
        host_id=req.host_id,
        evidence_path=evidence_path,
        sha256=sha256_value,
        hash_output_path=output_path if sha256_value else None,
        provenance_id=provenance_id,
        error=result.error,
    )

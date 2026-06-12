"""carve_network_artifacts — recover network indicators (IPs, domains, packets)
from a memory image with bulk_extractor.

This closes the XP network gap: Volatility's netscan/netstat don't work on Windows
XP, but bulk_extractor carves network artifacts straight from the raw bytes on any
OS. Read-only input; output under CASE_ROOT."""

from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_evidence
from forensic_mcp.provenance import next_provenance_id
from forensic_mcp.schemas import CarveNetworkRequest, GenericToolResponse, ToolStatus


def carve_network_artifacts(req: CarveNetworkRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        mem = ensure_inside_evidence(req.memory_image_path)
    except Exception as e:  # noqa: BLE001
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=str(e))
    if not mem.exists():
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=f"Memory image not found: {mem}")

    # Unique output dir per run (bulk_extractor refuses a non-empty target).
    out_dir = dirs["outputs"] / f"network_carve_{provenance_id}"
    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="bulk_extractor", wrapper_name="carve_network_artifacts",
        command=["bulk_extractor", "-o", str(out_dir), str(mem)],
        input_paths=[mem], output_paths=[out_dir], timeout_seconds=3600,
    )

    info: dict = {}
    outputs = []
    if result.status == "success":
        for name in ("ip.txt", "domain.txt", "ether.txt", "url.txt"):
            f = out_dir / name
            if f.exists():
                # bulk_extractor feature files have comment header lines starting with '#'
                n = sum(1 for ln in f.open(encoding="utf-8", errors="replace") if ln.strip() and not ln.startswith("#"))
                info[name] = n
                outputs.append(f)
        pcap = out_dir / "packets.pcap"
        if pcap.exists():
            info["packets.pcap_bytes"] = pcap.stat().st_size
            outputs.append(pcap)

    return GenericToolResponse(
        status=ToolStatus.success if result.status == "success" else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id, output_paths=outputs,
        info=info, provenance_id=provenance_id, error=result.error,
    )

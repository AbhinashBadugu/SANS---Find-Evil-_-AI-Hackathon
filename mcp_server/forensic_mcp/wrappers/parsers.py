"""The EZ Tools parser wrappers (MFT / registry / event logs / shimcache).

Each runs a fixed .NET tool via `dotnet`. Inputs are files we already extracted
into CASE_ROOT; outputs are CSVs under CASE_ROOT. The agent supplies no paths or
options beyond case/host."""

from pathlib import Path

from forensic_mcp.config import (
    DOTNET_BIN, MFTECMD_DLL, APPCOMPAT_DLL, EVTXECMD_DLL, RECMD_DLL, RECMD_BATCH,
)
from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_case
from forensic_mcp.provenance import next_provenance_id
from forensic_mcp.schemas import (
    ParseMftRequest, ParseRegistryRequest, ParseEvtxRequest, ParseShimcacheRequest,
    ParseEvtLegacyRequest, GenericToolResponse, ToolStatus,
)
from forensic_mcp.executor import run_logged_command as _rlc
from forensic_mcp.provenance import next_provenance_id as _npid


def _run(req, *, tool_name, wrapper_name, command, in_path: Path, out_dir: Path) -> GenericToolResponse:
    ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        in_path = ensure_inside_case(in_path)  # we only parse files we extracted
    except Exception as e:  # noqa: BLE001
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=str(e))
    if not in_path.exists():
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=provenance_id, error=f"Input not found: {in_path}")
    out_dir.mkdir(parents=True, exist_ok=True)
    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name=tool_name, wrapper_name=wrapper_name, command=command,
        input_paths=[in_path], output_paths=[out_dir], timeout_seconds=3600,
    )
    csvs = [p for p in out_dir.glob("**/*.csv")]
    ok = result.status == "success" and bool(csvs)
    return GenericToolResponse(
        status=ToolStatus.success if ok else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id, output_paths=csvs,
        info={"csv_count": len(csvs)}, provenance_id=provenance_id, error=result.error,
    )


def parse_mft(req: ParseMftRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    out = dirs["mft"]
    return _run(req, tool_name="MFTECmd", wrapper_name="parse_mft",
                command=[DOTNET_BIN, str(MFTECMD_DLL), "-f", str(req.mft_path),
                         "--csv", str(out), "--csvf", "mft.csv"],
                in_path=req.mft_path, out_dir=out)


def parse_shimcache(req: ParseShimcacheRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    out = dirs["registry"] / "shimcache"
    return _run(req, tool_name="AppCompatCacheParser", wrapper_name="parse_shimcache",
                command=[DOTNET_BIN, str(APPCOMPAT_DLL), "-f", str(req.system_hive_path),
                         "--csv", str(out), "--csvf", "shimcache.csv"],
                in_path=req.system_hive_path, out_dir=out)


def parse_evtx(req: ParseEvtxRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    out = dirs["evtx"]
    return _run(req, tool_name="EvtxECmd", wrapper_name="parse_evtx",
                command=[DOTNET_BIN, str(EVTXECMD_DLL), "-d", str(req.evtx_dir),
                         "--csv", str(out), "--csvf", "evtx.csv"],
                in_path=req.evtx_dir, out_dir=out)


def parse_evt_legacy(req: ParseEvtLegacyRequest) -> GenericToolResponse:
    """Parse legacy Windows XP/2003 .evt logs with evtexport (libevt).
    Closes the gap where EvtxECmd (modern .evtx only) cannot read .evt files."""
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    out_dir = dirs["evtx"] / "legacy"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        evt_dir = ensure_inside_case(req.evt_dir)
    except Exception as e:  # noqa: BLE001
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=_npid(req.case_id), error=str(e))

    evt_files = sorted(p for p in evt_dir.glob("*") if p.suffix.lower() == ".evt")
    if not evt_files:
        return GenericToolResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   provenance_id=_npid(req.case_id), error=f"No .evt files in {evt_dir}")

    outputs, total_records, last_pid = [], 0, ""
    for evt in evt_files:
        pid = _npid(req.case_id)
        last_pid = pid
        r = _rlc(provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
                 tool_name="evtexport", wrapper_name="parse_evt_legacy",
                 command=["evtexport", str(evt)], input_paths=[evt], output_paths=[], timeout_seconds=900)
        if r.status == "success":
            text = r.stdout_path.read_text(encoding="utf-8", errors="replace")
            dest = out_dir / f"{evt.stem}.txt"
            dest.write_text(text, encoding="utf-8")
            total_records += text.count("Event number")
            outputs.append(dest)

    return GenericToolResponse(
        status=ToolStatus.success if outputs else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id, output_paths=outputs,
        info={"files": len(outputs), "records": total_records}, provenance_id=last_pid,
        error=None if outputs else "evtexport produced no output",
    )


def parse_registry(req: ParseRegistryRequest) -> GenericToolResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    out = dirs["registry"]
    return _run(req, tool_name="RECmd", wrapper_name="parse_registry",
                command=[DOTNET_BIN, str(RECMD_DLL), "-d", str(req.hive_dir),
                         "--bn", str(RECMD_BATCH), "--csv", str(out), "--nl", "false"],
                in_path=req.hive_dir, out_dir=out)

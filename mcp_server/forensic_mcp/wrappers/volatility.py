"""run_volatility_plugin — run ONE approved memory plugin against a memory image.

Two non-obvious but essential details for this box are baked in:
  * the tool is `vol` (not vol.py)
  * `vol` is given a writable `-s` symbols folder, or every plugin fails.
"""

from forensic_mcp.config import VOLATILITY_BIN, VOL_SYMBOLS_DIR, VOL_ALLOWLIST_FULL
from forensic_mcp.allowlists import validate_volatility_plugin
from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_evidence
from forensic_mcp.provenance import next_provenance_id, log_rejection
from forensic_mcp.schemas import VolatilityPluginRequest, VolatilityPluginResponse, ToolStatus


def run_volatility_plugin(req: VolatilityPluginRequest) -> VolatilityPluginResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)

    def reject(error: str, attempted: list[str], inputs=None) -> VolatilityPluginResponse:
        log_rejection(
            provenance_id=provenance_id,
            case_id=req.case_id,
            host_id=req.host_id,
            tool_name="volatility3",
            wrapper_name="run_volatility_plugin",
            attempted=attempted,
            input_paths=inputs or [],
            error=error,
        )
        return VolatilityPluginResponse(
            status=ToolStatus.failed,
            case_id=req.case_id,
            host_id=req.host_id,
            plugin=req.plugin,
            provenance_id=provenance_id,
            error=error,
        )

    # 1) plugin must be on the approved list
    try:
        plugin = validate_volatility_plugin(req.plugin, full=VOL_ALLOWLIST_FULL)
    except Exception as e:  # noqa: BLE001
        return reject(str(e), [VOLATILITY_BIN, req.plugin])

    # 2) memory image must be inside the read-only evidence area
    try:
        memory_path = ensure_inside_evidence(req.memory_image_path)
    except Exception as e:  # noqa: BLE001
        return reject(str(e), [VOLATILITY_BIN, str(req.memory_image_path)])

    if not memory_path.exists():
        return reject("Memory image path does not exist", [VOLATILITY_BIN, str(memory_path)], [memory_path])

    # 3) make sure the symbols scratch folder exists (writable), then run
    VOL_SYMBOLS_DIR.mkdir(parents=True, exist_ok=True)
    plugin_dir = dirs["volatility"] / plugin
    plugin_dir.mkdir(parents=True, exist_ok=True)
    output_path = plugin_dir / f"{plugin}.json"

    command = [
        VOLATILITY_BIN,
        "-s", str(VOL_SYMBOLS_DIR),
        "-f", str(memory_path),
        "-r", "json",
        plugin,
    ]
    result = run_logged_command(
        provenance_id=provenance_id,
        case_id=req.case_id,
        host_id=req.host_id,
        tool_name="volatility3",
        wrapper_name="run_volatility_plugin",
        command=command,
        input_paths=[memory_path],
        output_paths=[output_path],
        timeout_seconds=1800,
    )

    error = result.error
    if result.status == "success":
        output_path.write_text(
            result.stdout_path.read_text(encoding="utf-8", errors="replace"),
            encoding="utf-8",
            errors="replace",
        )
    else:
        # Recognise the specific "this Windows version isn't supported" case
        # (e.g. netscan on Windows XP) and report it precisely, not as a vague failure.
        stderr = result.stderr_path.read_text(encoding="utf-8", errors="replace") if result.stderr_path.exists() else ""
        if "not supported" in stderr or "NotImplementedError" in stderr:
            detail = next((ln.strip() for ln in stderr.splitlines()
                           if "not supported" in ln or "NotImplementedError" in ln), "")
            error = f"Plugin '{plugin}' is not supported on this OS version (e.g. Windows XP): {detail}"

    return VolatilityPluginResponse(
        status=ToolStatus.success if result.status == "success" else ToolStatus.failed,
        case_id=req.case_id,
        host_id=req.host_id,
        plugin=plugin,
        output_path=output_path if result.status == "success" else None,
        provenance_id=provenance_id,
        error=error,
    )

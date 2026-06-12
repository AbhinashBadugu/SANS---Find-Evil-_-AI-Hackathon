"""The one place a real tool is ever launched.

Commands are always a list of pieces and always run with shell=False, so the
agent can never inject extra shell syntax. Every run is logged."""

import subprocess
from dataclasses import dataclass
from pathlib import Path

from forensic_mcp.config import DEFAULT_TIMEOUT_SECONDS
from forensic_mcp.paths import ensure_host_dirs
from forensic_mcp.provenance import utc_now, append_provenance
from forensic_mcp.schemas import ProvenanceRecord


@dataclass
class CommandResult:
    provenance_id: str
    status: str
    exit_code: int | None
    stdout_path: Path
    stderr_path: Path
    error: str | None


def run_logged_command(
    *,
    provenance_id: str,
    case_id: str,
    host_id: str,
    tool_name: str,
    wrapper_name: str,
    command: list[str],
    input_paths: list[Path],
    output_paths: list[Path],
    input_sha256: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> CommandResult:
    if not command:
        raise ValueError("Command argv list cannot be empty")

    dirs = ensure_host_dirs(case_id, host_id)
    stdout_path = dirs["tool_runs"] / f"{provenance_id}.stdout.txt"
    stderr_path = dirs["tool_runs"] / f"{provenance_id}.stderr.txt"

    start = utc_now()
    exit_code: int | None = None
    error: str | None = None

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,  # never a shell — argv list only
        )
        exit_code = completed.returncode
        stdout_path.write_text(completed.stdout or "", encoding="utf-8", errors="replace")
        stderr_path.write_text(completed.stderr or "", encoding="utf-8", errors="replace")
        status = "success" if exit_code == 0 else "failed"
        if exit_code != 0:
            error = f"Command exited with code {exit_code}"
    except subprocess.TimeoutExpired as e:
        status = "failed"
        error = f"Command timed out after {timeout_seconds} seconds"
        stdout_path.write_text(e.stdout if isinstance(e.stdout, str) else "", encoding="utf-8", errors="replace")
        stderr_path.write_text(e.stderr if isinstance(e.stderr, str) else "", encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        status = "failed"
        error = f"Tool not found: {e}"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(error, encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001 - we want every failure logged, never raised silently
        status = "failed"
        error = repr(e)
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(error, encoding="utf-8", errors="replace")

    end = utc_now()
    append_provenance(
        ProvenanceRecord(
            provenance_id=provenance_id,
            case_id=case_id,
            host_id=host_id,
            tool_name=tool_name,
            wrapper_name=wrapper_name,
            command=command,
            input_paths=input_paths,
            output_paths=output_paths,
            start_time=start,
            end_time=end,
            exit_code=exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            input_sha256=input_sha256,
            status=status,
            error=error,
        )
    )
    return CommandResult(provenance_id, status, exit_code, stdout_path, stderr_path, error)


def run_logged_extract(
    *,
    provenance_id: str,
    case_id: str,
    host_id: str,
    tool_name: str,
    wrapper_name: str,
    command: list[str],
    output_file: Path,
    input_paths: list[Path],
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> CommandResult:
    """Like run_logged_command, but the tool's stdout is RAW BYTES written to
    output_file (used by icat to carve a file out of an image without corrupting it)."""
    if not command:
        raise ValueError("Command argv list cannot be empty")

    dirs = ensure_host_dirs(case_id, host_id)
    stderr_path = dirs["tool_runs"] / f"{provenance_id}.stderr.txt"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    start = utc_now()
    exit_code: int | None = None
    error: str | None = None
    try:
        with output_file.open("wb") as out:
            completed = subprocess.run(
                command, stdout=out, stderr=subprocess.PIPE,
                timeout=timeout_seconds, shell=False,
            )
        exit_code = completed.returncode
        stderr_path.write_bytes(completed.stderr or b"")
        status = "success" if exit_code == 0 else "failed"
        if exit_code != 0:
            error = f"Command exited with code {exit_code}"
    except Exception as e:  # noqa: BLE001
        status = "failed"
        error = repr(e)
        stderr_path.write_text(error, encoding="utf-8", errors="replace")

    end = utc_now()
    append_provenance(
        ProvenanceRecord(
            provenance_id=provenance_id, case_id=case_id, host_id=host_id,
            tool_name=tool_name, wrapper_name=wrapper_name, command=command,
            input_paths=input_paths, output_paths=[output_file],
            start_time=start, end_time=end, exit_code=exit_code,
            stdout_path=output_file, stderr_path=stderr_path,
            status=status, error=error,
        )
    )
    return CommandResult(provenance_id, status, exit_code, output_file, stderr_path, error)

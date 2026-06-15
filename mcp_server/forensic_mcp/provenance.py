"""The logbook. Every action appends one line to provenance.jsonl —
successes, failures, and refusals alike."""

from datetime import datetime, timezone
from pathlib import Path

from forensic_mcp.paths import provenance_path, ensure_host_dirs
from forensic_mcp.schemas import ProvenanceRecord


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def next_provenance_id(case_id: str) -> str:
    """Sequential id like cmd-000001, based on how many lines exist."""
    path = provenance_path(case_id)
    if not path.exists():
        return "cmd-000001"
    count = sum(1 for line in path.open("r", encoding="utf-8") if line.strip())
    return f"cmd-{count + 1:06d}"


def append_provenance(record: ProvenanceRecord) -> None:
    path = provenance_path(record.case_id)
    with path.open("a", encoding="utf-8") as f:
        f.write(record.model_dump_json() + "\n")


def log_action(
    *,
    provenance_id: str,
    case_id: str,
    host_id: str,
    tool_name: str,
    wrapper_name: str,
    command: list[str],
    input_paths: list[Path] | None = None,
    output_paths: list[Path] | None = None,
    status: str = "success",
    input_sha256: str | None = None,
    error: str | None = None,
) -> None:
    """Record an IN-PROCESS action (a tool implemented with a stdlib/library, e.g.
    hashlib or a PE parser, rather than a subprocess) so it still leaves exactly
    one logbook line — same audit guarantee as run_logged_command, no shell."""
    ensure_host_dirs(case_id, host_id)
    now = utc_now()
    append_provenance(
        ProvenanceRecord(
            provenance_id=provenance_id,
            case_id=case_id,
            host_id=host_id,
            tool_name=tool_name,
            wrapper_name=wrapper_name,
            command=command,
            input_paths=input_paths or [],
            output_paths=output_paths or [],
            start_time=now,
            end_time=now,
            exit_code=0 if status == "success" else None,
            stdout_path=None,
            stderr_path=None,
            input_sha256=input_sha256,
            status="success" if status == "success" else "failed",
            error=error,
        )
    )


def log_rejection(
    *,
    provenance_id: str,
    case_id: str,
    host_id: str,
    tool_name: str,
    wrapper_name: str,
    attempted: list[str],
    input_paths: list[Path] | None = None,
    error: str,
) -> None:
    """Record a refused/blocked action WITHOUT running anything.

    Used when the agent asks for something not allowed (e.g. a banned plugin).
    We write the logbook line directly — we never launch a doomed command just
    to produce a record.
    """
    ensure_host_dirs(case_id, host_id)
    now = utc_now()
    append_provenance(
        ProvenanceRecord(
            provenance_id=provenance_id,
            case_id=case_id,
            host_id=host_id,
            tool_name=tool_name,
            wrapper_name=wrapper_name,
            command=["REJECTED"] + attempted,
            input_paths=input_paths or [],
            output_paths=[],
            start_time=now,
            end_time=now,
            exit_code=None,
            stdout_path=None,
            stderr_path=None,
            status="failed",
            error=error,
        )
    )

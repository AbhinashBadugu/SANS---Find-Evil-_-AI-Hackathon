"""generate_timeline / filter_timeline — build a Plaso super-timeline and slice it.

generate_timeline: log2timeline.py over a source (the extracted-artifacts dir, or a
                   mounted ewf1 image) using a FIXED parser set -> a .plaso store.
filter_timeline:   psort.py -> a full l2tcsv CSV, then an optional deterministic
                   date/keyword slice done in Python (no psort filter language).

Two traps handled: (1) the parser set is fixed, not agent-supplied; (2) psort
refuses to overwrite, and log2timeline appends to an existing store, so we delete
the target first.
"""

import csv as _csv
import os
import sys as _sys
from datetime import date
from pathlib import Path

# Some l2tcsv rows (e.g. long registry value descriptions) exceed Python's default
# CSV field limit. Raise it so the deterministic slice never chokes.
_csv.field_size_limit(min(2**31 - 1, _sys.maxsize))

from forensic_mcp.config import PLASO_PARSERS
from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import ensure_host_dirs, ensure_inside_case, ensure_inside_evidence
from forensic_mcp.provenance import log_action, next_provenance_id
from forensic_mcp.schemas import (
    GenerateTimelineRequest, GenerateTimelineResponse,
    FilterTimelineRequest, FilterTimelineResponse, ToolStatus,
)


def _validate_source(p: Path) -> Path:
    """A timeline source may be our extracted dir (CASE_ROOT) or a mounted image
    (also under CASE_ROOT) — or, if pointed straight at evidence, EVIDENCE_ROOT."""
    try:
        return ensure_inside_case(p)
    except Exception:
        return ensure_inside_evidence(p)


def generate_timeline(req: GenerateTimelineRequest) -> GenerateTimelineResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        source = _validate_source(req.source_path)
    except Exception as e:  # noqa: BLE001
        return GenerateTimelineResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                        provenance_id=provenance_id, error=str(e))
    if not source.exists():
        return GenerateTimelineResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                        provenance_id=provenance_id, error=f"Source not found: {source}")

    plaso = dirs["timeline"] / f"{req.host_id}.plaso"
    # RESUME: log2timeline is the ~30-min step. If a complete .plaso for this host
    # already exists, reuse it instead of rebuilding, so a re-run skips hosts that
    # were already timelined. Set DFIR_FORCE_TIMELINE_REBUILD=1 to force a clean
    # rebuild. The reuse is logged in-process so the provenance_id still resolves.
    if (plaso.exists() and plaso.stat().st_size > 0
            and os.getenv("DFIR_FORCE_TIMELINE_REBUILD") != "1"):
        log_action(
            provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
            tool_name="log2timeline", wrapper_name="generate_timeline",
            command=["log2timeline.py", "--storage_file", str(plaso), str(source),
                     "# reused existing store (no rebuild)"],
            input_paths=[source], output_paths=[plaso], status="success",
        )
        return GenerateTimelineResponse(
            status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
            plaso_path=plaso, provenance_id=provenance_id,
        )
    if plaso.exists():
        plaso.unlink()  # partial/empty leftover; log2timeline appends, so start clean

    result = run_logged_command(
        provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
        tool_name="log2timeline", wrapper_name="generate_timeline",
        command=["log2timeline.py", "--status_view", "none", "-q",
                 "--parsers", PLASO_PARSERS, "--storage_file", str(plaso), str(source)],
        input_paths=[source], output_paths=[plaso], timeout_seconds=10800,
    )
    ok = result.status == "success" and plaso.exists() and plaso.stat().st_size > 0
    return GenerateTimelineResponse(
        status=ToolStatus.success if ok else ToolStatus.failed,
        case_id=req.case_id, host_id=req.host_id,
        plaso_path=plaso if ok else None, provenance_id=provenance_id,
        error=None if ok else (result.error or "no .plaso produced"),
    )


def _parse_l2t_date(cell: str):
    """l2tcsv first column is MM/DD/YYYY -> date object, or None."""
    try:
        mm, dd, yyyy = cell.split("/")
        return date(int(yyyy), int(mm), int(dd))
    except Exception:  # noqa: BLE001
        return None


def filter_timeline(req: FilterTimelineRequest) -> FilterTimelineResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    try:
        plaso = ensure_inside_case(req.plaso_path)
    except Exception as e:  # noqa: BLE001
        return FilterTimelineResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                      provenance_id=provenance_id, error=str(e))
    if not plaso.exists():
        return FilterTimelineResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                      provenance_id=provenance_id, error=f"Plaso store not found: {plaso}")

    # PERF: psort's full l2tcsv export of a Plaso store is identical for every slice
    # of the same host, so export it ONCE and reuse it. This used to re-run psort (a
    # ~1.6 GB export) on EVERY filter_timeline call — hundreds of times per host when
    # slicing per anchor dir — which filled the disk and stalled the run. The full
    # CSV is now keyed to the plaso store (one per host), not to req.label.
    full_csv = dirs["timeline"] / f"_timeline_full__{plaso.stem}.csv"
    if full_csv.exists() and full_csv.stat().st_size > 0:
        # Reuse the cached full export. Log the in-process reuse so this call's
        # provenance_id still resolves for citations (no redundant psort, no shell).
        log_action(
            provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
            tool_name="psort", wrapper_name="filter_timeline",
            command=["psort.py", "-q", "-o", "l2tcsv", "-w", str(full_csv), str(plaso),
                     "# reused cached full export (no re-run)"],
            input_paths=[plaso], output_paths=[full_csv], status="success",
        )
    else:
        if full_csv.exists():
            full_csv.unlink()  # remove a partial leftover; psort refuses to overwrite
        result = run_logged_command(
            provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
            tool_name="psort", wrapper_name="filter_timeline",
            command=["psort.py", "-q", "-o", "l2tcsv", "-w", str(full_csv), str(plaso)],
            input_paths=[plaso], output_paths=[full_csv], timeout_seconds=7200,
        )
        if result.status != "success" or not full_csv.exists():
            return FilterTimelineResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                          provenance_id=provenance_id, error=result.error or "psort produced no CSV")

    full_rows = sum(1 for _ in full_csv.open(encoding="utf-8", errors="replace")) - 1

    # Optional deterministic slice (date range and/or keyword), done in Python.
    filtered_csv = None
    filtered_rows = None
    if req.start_date or req.end_date or req.keyword:
        sd = date.fromisoformat(req.start_date) if req.start_date else None
        ed = date.fromisoformat(req.end_date) if req.end_date else None
        kw = req.keyword.lower() if req.keyword else None
        filtered_csv = dirs["timeline"] / f"{req.label}_filtered.csv"
        filtered_rows = 0
        with full_csv.open(encoding="utf-8", errors="replace", newline="") as fin, \
             filtered_csv.open("w", encoding="utf-8", newline="") as fout:
            reader = _csv.reader(fin)
            writer = _csv.writer(fout)
            header = next(reader, None)
            if header:
                writer.writerow(header)
            for row in reader:
                if not row:
                    continue
                d = _parse_l2t_date(row[0])
                if sd and (d is None or d < sd):
                    continue
                if ed and (d is None or d > ed):
                    continue
                if kw and kw not in ",".join(row).lower():
                    continue
                writer.writerow(row)
                filtered_rows += 1

    return FilterTimelineResponse(
        status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
        full_csv_path=full_csv, filtered_csv_path=filtered_csv,
        full_rows=full_rows, filtered_rows=filtered_rows, provenance_id=provenance_id,
    )

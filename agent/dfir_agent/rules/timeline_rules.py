"""Timeline extraction rules over a Plaso l2tcsv slice (playbook §7, family=timeline).

The trap this rule exists to avoid: an implant's $STANDARD_INFORMATION timestamps
are timestomped (e.g. backdated by years), so the naive "earliest
event" would mis-report the compromise time. The trustworthy creation time is the
$FILE_NAME (FN) attribute, which ordinary tooling cannot backdate. This rule
prefers FN-creation to pin patient-zero timing, and emits the SI backdating as its
own timestomp event rather than trusting it.
"""

from __future__ import annotations

import csv
import re
import sys
from datetime import datetime

from ..state import EvidenceReference, TimelineEvent

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

# l2tcsv column indices.
_DATE, _TIME, _MACB, _SOURCE, _TYPE, _DESC = 0, 1, 3, 4, 6, 10

_PATH_HINT = re.compile(r"Path hints?:\s*([^,]+)", re.IGNORECASE)
_PATH_REG = re.compile(r"Path:\s*([^,]+)", re.IGNORECASE)
_FILE_REF = re.compile(r"File reference:\s*([0-9-]+)", re.IGNORECASE)


def _ts(d: str, t: str) -> datetime | None:
    try:
        return datetime.strptime(f"{d.strip()} {t.strip()}", "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None


def _path_of(desc: str) -> str | None:
    m = _PATH_HINT.search(desc) or _PATH_REG.search(desc)
    return m.group(1).strip() if m else None


def _ref_of(desc: str) -> str | None:
    m = _FILE_REF.search(desc)
    return m.group(1) if m else None


def extract_implant_timeline(
    filtered_csv: str,
    dir_fragments: set[str],
    *,
    host_id: str,
    provenance_id: str,
) -> tuple[list[TimelineEvent], datetime | None]:
    """Return (timeline events, patient_zero_ts).

    dir_fragments: lowercase path fragments that identify the implant directory
    (e.g. ``\\dllhost\\``), used to keep implant rows and exclude look-alikes such
    as the legitimate ``\\system32\\dllhost.exe``.
    """
    from pathlib import Path
    p = Path(filtered_csv)
    if not p.exists():
        return [], None

    fn_creations: list[tuple[datetime, str, str, str]] = []  # (ts, path, ref, evtxt)
    si_creations: list[tuple[datetime, str, str]] = []

    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        next(reader, None)  # header
        for row in reader:
            if len(row) <= _DESC:
                continue
            desc = row[_DESC]
            low = desc.lower()
            if not any(frag in low for frag in dir_fragments):
                continue
            ts = _ts(row[_DATE], row[_TIME])
            if not ts:
                continue
            typ = row[_TYPE]
            path = _path_of(desc) or "?"
            ref = _ref_of(desc) or "?"
            if "$FILE_NAME" in desc and "Creation Time" in typ:
                fn_creations.append((ts, path, ref, f"{row[_SOURCE]} {typ}"))
            elif "$STANDARD_INFORMATION" in desc and "Creation Time" in typ:
                si_creations.append((ts, path, ref))

    events: list[TimelineEvent] = []
    if not fn_creations:
        return [], None

    # NTFS keeps two $FILE_NAME attributes (8.3 + long) -> dedup per (ref, ts),
    # preferring the long name (no "~").
    deduped: dict[tuple, tuple] = {}
    for ts, path, ref, ev in fn_creations:
        key = (ref, ts)
        if key not in deduped or "~" in deduped[key][1]:
            deduped[key] = (ts, path, ref, ev)
    fn_creations = list(deduped.values())

    patient_zero_ts = min(t for t, _p, _r, _e in fn_creations)

    def _ev(ts, source, desc, ref, note) -> TimelineEvent:
        return TimelineEvent(
            ts=ts, host_id=host_id, source=source, description=desc,
            evidence=[EvidenceReference(
                provenance_id=provenance_id, record_id=ref, tool="filter_timeline",
                artifact_path=filtered_csv, source_family="timeline", note=note,
            )],
        )

    # One event per implant file's true (FN) creation; mark the earliest as patient-zero.
    for ts, path, ref, _e in sorted(fn_creations):
        marker = "PATIENT-ZERO MARKER: " if ts == patient_zero_ts else ""
        events.append(_ev(
            ts, "mft",
            f"{marker}implant file created on disk (FN $FILE_NAME): {path}",
            f"MFT {ref} $FILE_NAME Creation",
            f"l2tcsv FN-creation {ts.isoformat()} {path}",
        ))

    # Timestomp: an SI creation that predates the real FN creation by > 1 day.
    for ts, path, ref in sorted(si_creations):
        if (patient_zero_ts - ts).total_seconds() > 86400:
            events.append(_ev(
                ts, "mft",
                f"TIMESTOMP: $STANDARD_INFORMATION creation backdated to {ts.isoformat()} "
                f"for {path} (real FN creation {patient_zero_ts.isoformat()})",
                f"MFT {ref} $STANDARD_INFORMATION Creation",
                f"l2tcsv SI-creation {ts.isoformat()} predates FN {patient_zero_ts.isoformat()}",
            ))
            break  # one timestomp event is enough to make the point

    return events, patient_zero_ts

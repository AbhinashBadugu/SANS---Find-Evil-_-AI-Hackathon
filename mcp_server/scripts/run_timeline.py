"""Milestone (timeline) driver: build + filter a Plaso timeline per host via the wrappers.

Generates from each host's already-extracted artifacts (MFT + registry + event logs,
incl. XP legacy .evt via the winevt parser), exports a full CSV, and slices the
known attack window (2012-04-03..2012-04-04).
"""

import sys
from forensic_mcp.config import CASE_ROOT
from forensic_mcp.schemas import GenerateTimelineRequest, FilterTimelineRequest
from forensic_mcp.wrappers.timeline import generate_timeline, filter_timeline

CASE = "srl2015"
HOSTS = ["win2008R2-controller", "win7-32-nromanoff", "win7-64-nfury", "xp-tdungan"]
if len(sys.argv) > 1:
    HOSTS = [sys.argv[1]]

for host in HOSTS:
    print(f"\n===== {host} =====", flush=True)
    src = str(CASE_ROOT / "cases" / CASE / "hosts" / host / "extracted")

    existing = CASE_ROOT / "cases" / CASE / "hosts" / host / "timeline" / f"{host}.plaso"
    if existing.exists() and existing.stat().st_size > 0:
        print(f"generate_timeline: reuse existing  plaso={existing}", flush=True)
        plaso_path = str(existing)
    else:
        g = generate_timeline(GenerateTimelineRequest(case_id=CASE, host_id=host, source_path=src))
        print(f"generate_timeline: {g.status.value}  plaso={g.plaso_path}", flush=True)
        if g.status.value != "success":
            print(f"  error: {g.error}", flush=True)
            continue
        plaso_path = str(g.plaso_path)

    f = filter_timeline(FilterTimelineRequest(
        case_id=CASE, host_id=host, plaso_path=plaso_path,
        label="incident", start_date="2012-04-03", end_date="2012-04-04"))
    print(f"filter_timeline  : {f.status.value}  full_rows={f.full_rows}  "
          f"attack_window_rows={f.filtered_rows}", flush=True)

print("\nTIMELINE PIPELINE DONE", flush=True)

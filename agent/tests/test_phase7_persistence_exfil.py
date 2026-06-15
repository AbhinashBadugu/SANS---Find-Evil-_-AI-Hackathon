"""Phase 7 — persistence + exfil-staging expansion. Pure rules over synthetic rows."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.exfil_staging import correlate_archive_with_cleanup, detect_archive_staging  # noqa: E402
from dfir_agent.rules.persistence_scan import (  # noqa: E402
    detect_run_key_persistence, detect_scheduled_task_persistence, detect_service_persistence,
)


def test_service_persistence():
    rows = [
        {"service_name": "PSEXESVC", "image_path": r"C:\Windows\PSEXESVC.exe", "provenance_id": "c1"},
        {"service_name": "winsvchost", "image_path": r"C:\Windows\Temp\evil.exe", "provenance_id": "c2"},
        {"service_name": "wrap", "image_path": r"cmd.exe /k C:\x\y.exe", "provenance_id": "c3"},
        {"service_name": "Legit", "image_path": r"C:\Windows\System32\svchost.exe", "provenance_id": "c4"},
    ]
    f = detect_service_persistence(rows, host_id="h")
    titles = {x.title for x in f}
    assert any("PSEXESVC" in t for t in titles)
    assert any("winsvchost" in t for t in titles)
    assert not any("Legit" in t for t in titles)  # signed location not flagged
    psexec = next(x for x in f if "PSEXESVC" in x.title)
    assert psexec.confidence.value == "likely" and psexec.evidence[0].provenance_id == "c1"


def test_run_key_persistence():
    rows = [
        {"key": r"HKLM\...\Run", "value_name": "svc", "value_data": r"C:\Users\Public\evil.exe", "provenance_id": "c1"},
        {"key": r"HKLM\...\Run", "value_name": "ok", "value_data": r"C:\Program Files\App\app.exe", "provenance_id": "c2"},
    ]
    f = detect_run_key_persistence(rows, host_id="h")
    assert len(f) == 1 and f[0].confidence.value == "likely"


def test_scheduled_task_and_legacy_at():
    rows = [
        {"task_name": "At1.job", "action_path": r"C:\Windows\Temp\a.exe", "provenance_id": "c1"},
        {"task_name": "GoogleUpdate", "action_path": r"C:\Program Files\Google\upd.exe", "provenance_id": "c2"},
    ]
    f = detect_scheduled_task_persistence(rows, host_id="h")
    assert len(f) == 1 and "At1.job" in f[0].title


def test_archive_staging_and_cleanup():
    rows = [
        {"path": r"\Users\Public\Temp\collected.rar", "size": 6_297_428, "ctime": "2012-04-06",
         "provenance_id": "c1", "record_id": "MFT#1"},
        {"path": r"\Users\u\Documents\notes.zip", "size": 1024, "provenance_id": "c2"},   # small, normal loc
    ]
    arch = detect_archive_staging(rows, host_id="h")
    assert len(arch) == 1 and arch[0].confidence.value == "likely"

    cleanup = [{"name": "rar.exe", "path": r"\$Recycle.Bin\S-1-5\rar.exe", "deleted": True,
                "ctime": "2012-04-06", "provenance_id": "c9"}]
    corr = correlate_archive_with_cleanup(arch, cleanup, host_id="h")
    assert len(corr) == 1 and corr[0].source_count == 2
    assert {e.provenance_id for e in corr[0].evidence} == {"c9", "c1"}

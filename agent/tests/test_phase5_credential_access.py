"""Phase 5 — credential-access detection + logon correlation.

Pure rule layer over synthetic parsed-artifact rows (MFT/prefetch/cmdline) and
EVTX logon rows. Behaviour, not IOCs.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.credential_access import (  # noqa: E402
    correlate_credential_tooling_with_logons, detect_credential_access,
)


def test_detect_credential_access_variants():
    artifacts = [
        {"name": "m.exe", "cmdline": "m.exe sekurlsa::logonpasswords", "path": r"\Temp\m.exe",
         "source_family": "memory_cmdline", "provenance_id": "cmd-1", "record_id": "PID=1"},
        {"text": "procdump.exe -ma lsass.exe out.dmp", "source_family": "prefetch",
         "provenance_id": "cmd-2"},
        {"name": "lsass.dmp", "path": r"\Temp\lsass.dmp", "source_family": "disk_mft",
         "provenance_id": "cmd-3", "record_id": "MFT#9"},
        {"text": r"reg save hklm\sam c:\temp\sam.hiv", "source_family": "prefetch",
         "provenance_id": "cmd-4"},
        {"name": "procdump.exe", "text": "procdump.exe -accepteula notepad", "source_family": "prefetch",
         "provenance_id": "cmd-6"},                      # procdump NOT targeting lsass
        {"name": "notepad.exe", "source_family": "disk_mft", "provenance_id": "cmd-5"},  # benign
    ]
    findings = detect_credential_access(artifacts, host_id="h1")
    by_cat = [f.title for f in findings]
    assert any("mimikatz-class" in t for t in by_cat)
    assert any("LSASS memory dump" in t for t in by_cat)
    assert any("hive export" in t for t in by_cat)
    # procdump-not-lsass is downgraded to suspicious, notepad ignored
    pd = [f for f in findings if "tooling present" in f.title]
    assert pd and pd[0].confidence.value == "suspicious"
    assert not any("notepad" in (f.entity_key or "") for f in findings)
    # both LSASS-dump signals (procdump->lsass cmd-2, and the lsass.dmp file cmd-3)
    # are detected, 'likely', and each cites its own provenance.
    dumps = [f for f in findings if "LSASS memory dump" in f.title]
    assert {f.evidence[0].provenance_id for f in dumps} == {"cmd-2", "cmd-3"}
    assert all(f.confidence.value == "likely" for f in dumps)


def test_correlate_with_privileged_logon_promotes_to_confirmed():
    cred = detect_credential_access(
        [{"cmdline": "mimikatz sekurlsa::logonpasswords", "source_family": "memory_cmdline",
          "provenance_id": "cmd-1"}], host_id="h1")
    logons = [
        {"event_id": 4672, "account": "admin-acct", "src_ip": "10.0.0.9",
         "provenance_id": "cmd-7", "record_id": "EID=4672#1"},
        {"event_id": 4624, "account": "normaluser", "logon_type": 2, "provenance_id": "cmd-8"},
    ]
    out = correlate_credential_tooling_with_logons(cred, logons, host_id="h1")
    assert out, "should correlate cred tooling with privileged logon"
    f = out[0]
    assert f.confidence.value == "confirmed"
    assert f.source_count == 2
    provs = {e.provenance_id for e in f.evidence}
    assert "cmd-7" in provs and "cmd-1" in provs


def test_no_logons_no_correlation():
    assert correlate_credential_tooling_with_logons([], [], host_id="h1") == []

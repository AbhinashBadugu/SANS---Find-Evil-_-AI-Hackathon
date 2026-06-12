"""Phase 4: timeline extraction pins patient-zero via FN-creation (not the
timestomped SI), flags the timestomp, and dedups NTFS 8.3/long $FILE_NAME rows.
Fixture rows mirror the real xp-tdungan l2tcsv."""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.rules.timeline_rules import extract_implant_timeline  # noqa: E402

HEADER = "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"

# desc is column 10. The implant rows live under \WINDOWS\system32\dllhost\.
ROWS = [
    # SI creation -> timestomped to 2003 (must NOT become patient-zero)
    '03/31/2003,12:00:00,UTC,...B,FILE,NTFS file stat,Creation Time,-,-,short,'
    '"File reference: 3022-10 Attribute name: $STANDARD_INFORMATION Path hints: \\WINDOWS\\system32\\dllhost\\svchost.exe",'
    '2,fn,-,-,mft,x\n',
    # FN creation -> the REAL drop time
    '04/03/2012,00:35:02,UTC,...B,FILE,NTFS file stat,Creation Time,-,-,short,'
    '"File reference: 3022-10 Attribute name: $FILE_NAME Name: svchost.exe Path hints: \\WINDOWS\\system32\\dllhost\\svchost.exe",'
    '2,fn,-,-,mft,x\n',
    # config drop, long name
    '04/03/2012,00:35:10,UTC,...B,FILE,NTFS file stat,Creation Time,-,-,short,'
    '"File reference: 3023-10 Attribute name: $FILE_NAME Name: winclient.reg Path hints: \\WINDOWS\\system32\\dllhost\\winclient.reg",'
    '2,fn,-,-,mft,x\n',
    # config drop, 8.3 short name (same ref+ts -> must dedup away)
    '04/03/2012,00:35:10,UTC,...B,FILE,NTFS file stat,Creation Time,-,-,short,'
    '"File reference: 3023-10 Attribute name: $FILE_NAME Name: WINCLI~1.REG Path hints: \\WINDOWS\\system32\\dllhost\\WINCLI~1.REG",'
    '2,fn,-,-,mft,x\n',
    # a legitimate \system32\dllhost.exe row -> excluded by the \dllhost\ fragment
    '04/14/2008,00:12:17,UTC,...B,FILE,NTFS file stat,Creation Time,-,-,short,'
    '"File reference: 42437-2 Attribute name: $FILE_NAME Path hints: \\WINDOWS\\system32\\dllhost.exe",'
    '2,fn,-,-,mft,x\n',
]


def _write(tmp_path):
    csv = tmp_path / "tl.csv"
    csv.write_text(HEADER + "".join(ROWS), encoding="utf-8")
    return str(csv)


def test_patient_zero_uses_fn_not_timestomped_si(tmp_path):
    events, pz = extract_implant_timeline(
        _write(tmp_path), {"\\dllhost\\".lower()}, host_id="h", provenance_id="cmd-tl",
    )
    assert pz == datetime(2012, 4, 3, 0, 35, 2)  # FN, not the 2003 SI
    markers = [e for e in events if "PATIENT-ZERO MARKER" in e.description]
    assert len(markers) == 1 and markers[0].ts == pz


def test_timestomp_event_emitted(tmp_path):
    events, _ = extract_implant_timeline(
        _write(tmp_path), {"\\dllhost\\".lower()}, host_id="h", provenance_id="cmd-tl",
    )
    ts = [e for e in events if e.description.startswith("TIMESTOMP")]
    assert len(ts) == 1
    assert ts[0].ts == datetime(2003, 3, 31, 12, 0, 0)


def test_dedup_and_exclusion(tmp_path):
    events, _ = extract_implant_timeline(
        _write(tmp_path), {"\\dllhost\\".lower()}, host_id="h", provenance_id="cmd-tl",
    )
    # FN events: svchost.exe (3022) + winclient.reg (3023, deduped) = 2; dllhost.exe excluded.
    fn = [e for e in events if "FN $FILE_NAME" in e.description]
    assert len(fn) == 2
    assert not any("dllhost.exe" in e.description for e in events)


def test_every_event_cites_provenance(tmp_path):
    events, _ = extract_implant_timeline(
        _write(tmp_path), {"\\dllhost\\".lower()}, host_id="h", provenance_id="cmd-tl",
    )
    assert events
    for e in events:
        assert e.evidence and e.evidence[0].provenance_id == "cmd-tl"
        assert e.evidence[0].source_family == "timeline"
        assert e.evidence[0].record_id

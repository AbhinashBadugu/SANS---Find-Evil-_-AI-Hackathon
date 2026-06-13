"""Classification fixes validated against the real-evidence failure modes:
.001/memory-raw memory detection, c-drive.E01 Windows disk + OS inference,
course/baseline/template exclusion, and OS confidence tiers."""

from __future__ import annotations

from pathlib import Path

from dfir_agent.capability_matrix import is_reference_material
from dfir_agent.case_manifest import scan_case_folder
from dfir_agent.state import OSFamily


def _w(p: Path, d: bytes = b"x") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(d)


def _hosts(root: Path):
    return {h.host_id: h for h in scan_case_folder(root).hosts}


def test_dot001_memory_raw_and_cdrive_disk_detected(tmp_path: Path):
    h = tmp_path / "win7-32-foo"
    _w(h / "win7-32-foo-c-drive" / "win7-32-foo-c-drive.E01", b"x" * 64)
    _w(h / "win7-32-foo-memory" / "win7-32-foo-memory-raw.001", b"x" * 64)
    host = _hosts(tmp_path)["win7-32-foo"]
    assert host.evidence_capabilities.has_memory   # ".001" named *-memory-raw
    assert host.evidence_capabilities.has_disk     # c-drive.E01


def test_windows_medium_confidence_from_image_naming(tmp_path: Path):
    h = tmp_path / "win2008R2-dc"
    _w(h / "win2008R2-dc-c-drive.E01", b"x" * 64)
    _w(h / "win2008R2-dc-memory-raw.001", b"x" * 64)
    host = _hosts(tmp_path)["win2008R2-dc"]
    assert host.os_family == OSFamily.windows
    assert host.classification_confidence == "medium"   # only image/folder naming
    assert "image" in host.classification_reason.lower()


def test_windows_high_confidence_from_extracted_artifacts(tmp_path: Path):
    h = tmp_path / "DESKTOP-1"
    _w(h / "SYSTEM")
    _w(h / "Security.evtx")
    _w(h / "$MFT")
    host = _hosts(tmp_path)["DESKTOP-1"]
    assert host.os_family == OSFamily.windows
    assert host.classification_confidence == "high"
    assert "artifact" in host.classification_reason.lower()


def test_course_template_howto_and_precooked_excluded(tmp_path: Path):
    h = tmp_path / "win7-h"
    _w(h / "win7-h-c-drive.E01", b"x" * 64)
    pre = h / "win7-h-c-drive" / "precooked"
    _w(pre / "timeline" / "TIMELINE_COLOR_TEMPLATE.xlsx")
    _w(pre / "timeline" / "LibreOffice-Howto-Supertimeline.txt")
    _w(pre / "volume-shadow" / "vss-supertimeline.csv")
    c = _hosts(tmp_path)["win7-h"].evidence_capabilities
    assert c.has_disk            # real c-drive.E01 still counts
    assert not c.has_timeline    # TEMPLATE / Howto excluded
    assert not c.has_vss         # under precooked/ excluded
    assert is_reference_material(Path("x/precooked/timeline/TIMELINE_COLOR_TEMPLATE.xlsx"))


def test_baseline_reference_image_excluded_from_host_evidence(tmp_path: Path):
    h = tmp_path / "win7-b"
    _w(h / "win7-b-memory" / "baseline-memory" / "Win7SP1x86-baseline.img", b"x" * 64)
    host = _hosts(tmp_path)["win7-b"]
    assert not host.evidence_capabilities.has_disk     # baseline image is not host evidence
    assert not host.evidence_capabilities.has_memory
    assert is_reference_material(Path("x/baseline-memory/Win7SP1x86-baseline.img"))

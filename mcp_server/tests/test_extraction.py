"""extract_archive — decompress compressed evidence (.7z/.zip/.gz) into the case
write-area, read-only on the original, path-gated, provenance-logged."""

import os
import subprocess
import sys
from pathlib import Path

from forensic_mcp.schemas import ExtractArchiveRequest
from forensic_mcp.wrappers.extraction import extract_archive


def test_rejects_archive_outside_evidence_root():
    # Uses the real EVIDENCE_ROOT; /etc/hosts escapes it -> refused, not extracted.
    r = extract_archive(ExtractArchiveRequest(case_id="c", host_id="h", archive_path="/etc/hosts"))
    assert r.status.value == "failed"
    assert "escapes" in (r.error or "").lower()


def test_unsupported_type_is_rejected(tmp_path):
    # A real path under a temp evidence root but an unsupported extension.
    code = (
        "import sys\n"
        "from forensic_mcp.schemas import ExtractArchiveRequest\n"
        "from forensic_mcp.wrappers.extraction import extract_archive\n"
        "r=extract_archive(ExtractArchiveRequest(case_id='c',host_id='h',archive_path=sys.argv[1]))\n"
        "print(r.status.value); print(r.error or '')\n"
    )
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "image.E01").write_bytes(b"x")  # not an archive
    env = {**os.environ, "EVIDENCE_ROOT": str(ev), "CASE_ROOT": str(tmp_path / "case")}
    out = subprocess.run([sys.executable, "-c", code, str(ev / "image.E01")],
                         env=env, capture_output=True, text=True)
    assert "failed" in out.stdout and "unsupported" in out.stdout.lower()


def test_extracts_real_7z_archive(tmp_path):
    ev = tmp_path / "evidence" / "base-dc-memory"
    ev.mkdir(parents=True)
    (ev / "base-dc-memory.raw").write_bytes(b"x" * 4096)
    subprocess.run(["7z", "a", str(ev / "base-dc-memory.7z"), str(ev / "base-dc-memory.raw")],
                   check=True, capture_output=True)
    (ev / "base-dc-memory.raw").unlink()

    code = (
        "import sys\n"
        "from forensic_mcp.schemas import ExtractArchiveRequest\n"
        "from forensic_mcp.wrappers.extraction import extract_archive\n"
        "r=extract_archive(ExtractArchiveRequest(case_id='srl2018',host_id='base-dc',archive_path=sys.argv[1]))\n"
        "print(r.status.value); print(r.primary_image or '')\n"
    )
    env = {**os.environ, "EVIDENCE_ROOT": str(tmp_path / "evidence"), "CASE_ROOT": str(tmp_path / "case")}
    out = subprocess.run([sys.executable, "-c", code, str(ev / "base-dc-memory.7z")],
                         env=env, capture_output=True, text=True)
    lines = out.stdout.strip().splitlines()
    assert lines and lines[0] == "success", out.stderr
    assert lines[-1].endswith("base-dc-memory.raw")
    # extracted into the case write-area, NOT beside the evidence
    assert str(tmp_path / "case") in lines[-1]

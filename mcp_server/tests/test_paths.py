import pytest
from pathlib import Path

from forensic_mcp.paths import (
    validate_id, ensure_inside_case, ensure_inside_evidence, PathValidationError,
)
from forensic_mcp.config import CASE_ROOT, EVIDENCE_ROOT


def test_valid_id():
    assert validate_id("xp-tdungan", "host_id") == "xp-tdungan"


def test_id_blocks_traversal():
    with pytest.raises(PathValidationError):
        validate_id("../../etc/passwd", "host_id")


def test_case_root_rejects_etc():
    with pytest.raises(PathValidationError):
        ensure_inside_case(Path("/etc/passwd"))


def test_evidence_root_rejects_outside():
    with pytest.raises(PathValidationError):
        ensure_inside_evidence(Path("/etc/passwd"))


def test_case_path_accepted():
    p = ensure_inside_case(CASE_ROOT / "cases" / "x" / "y.txt")
    assert str(p).startswith(str(CASE_ROOT))


def test_evidence_path_accepted():
    p = ensure_inside_evidence(EVIDENCE_ROOT / "something.E01")
    assert str(p).startswith(str(EVIDENCE_ROOT))

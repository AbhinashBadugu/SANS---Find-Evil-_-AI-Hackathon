"""Path safety — the gate that keeps us inside our two allowed areas.

Inputs (evidence) must live under EVIDENCE_ROOT and are read-only.
Outputs (results, logbook) must live under CASE_ROOT.
Anything that tries to escape either area is refused.
"""

import re
from pathlib import Path

from forensic_mcp.config import CASE_ROOT, EVIDENCE_ROOT

# case_id / host_id may only contain safe characters — blocks ".." tricks.
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class PathValidationError(ValueError):
    """Raised when an id is unsafe or a path escapes its allowed root."""


def validate_id(value: str, field_name: str) -> str:
    if not SAFE_ID_RE.match(value):
        raise PathValidationError(
            f"Invalid {field_name!r}: only letters, numbers, dot, dash, underscore allowed."
        )
    return value


def _ensure_inside(root: Path, path: Path) -> Path:
    """Return the resolved path only if it sits at or under `root`."""
    resolved = path.expanduser().resolve()
    if resolved != root and root not in resolved.parents:
        raise PathValidationError(f"Path escapes {root}: {resolved}")
    return resolved


def ensure_inside_evidence(path: Path) -> Path:
    """An input path we are allowed to READ (must be under EVIDENCE_ROOT)."""
    return _ensure_inside(EVIDENCE_ROOT, Path(path))


def ensure_inside_case(path: Path) -> Path:
    """An output path we are allowed to WRITE (must be under CASE_ROOT)."""
    return _ensure_inside(CASE_ROOT, Path(path))


def ensure_readable(path: Path) -> Path:
    """An input path we are allowed to READ: a sealed original under EVIDENCE_ROOT,
    OR a working copy we already produced under CASE_ROOT (an extracted archive, a
    carved file, or a read-only NTFS mount). READ-only — callers must never modify
    what it returns. This is the gate for tools that consume files the agent itself
    extracted/mounted (hashing, PE/string parsing, registry exports), while still
    refusing any path outside BOTH roots.
    """
    p = Path(path)
    try:
        return _ensure_inside(EVIDENCE_ROOT, p)
    except PathValidationError:
        return _ensure_inside(CASE_ROOT, p)


def case_dir(case_id: str) -> Path:
    validate_id(case_id, "case_id")
    return ensure_inside_case(CASE_ROOT / "cases" / case_id)


def host_dir(case_id: str, host_id: str) -> Path:
    validate_id(host_id, "host_id")
    return ensure_inside_case(case_dir(case_id) / "hosts" / host_id)


def provenance_path(case_id: str) -> Path:
    return ensure_inside_case(case_dir(case_id) / "provenance.jsonl")


def manifest_path(case_id: str) -> Path:
    return ensure_inside_case(case_dir(case_id) / "manifest.json")


# Sub-folders created under each host's results area.
HOST_SUBDIRS = (
    "hashes",
    "outputs",
    "parsed",
    "volatility",
    "mft",
    "registry",
    "evtx",
    "timeline",
    "extracted",
    "tool_runs",
)


def ensure_host_dirs(case_id: str, host_id: str) -> dict[str, Path]:
    """Create (if needed) the host's output folders and the case logbook. Returns the map."""
    base = host_dir(case_id, host_id)
    dirs: dict[str, Path] = {"host": base}
    for name in HOST_SUBDIRS:
        d = ensure_inside_case(base / name)
        d.mkdir(parents=True, exist_ok=True)
        dirs[name] = d

    case_dir(case_id).mkdir(parents=True, exist_ok=True)
    prov = provenance_path(case_id)
    if not prov.exists():
        prov.touch()
    man = manifest_path(case_id)
    if not man.exists():
        man.write_text("{}\n", encoding="utf-8")
    return dirs

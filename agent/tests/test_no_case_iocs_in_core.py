"""Universality guard: case IOCs must NEVER appear in core detection code.

The whole project promise is that detection is GENERIC and a specific case (e.g.
SRL-2015) is only a validation profile. This test enforces that mechanically:
it reads every validation profile's `forbidden_in_core` block (host names, IPs,
file hashes, campaign-unique filenames) and asserts none of those tokens appear
in the core directories:

    agent/dfir_agent/rules/      (detection rules)
    agent/dfir_agent/nodes/      (orchestration)
    mcp_server/forensic_mcp/wrappers/   (tool wrappers)

Generic technique words (Run key, PSEXESVC, 4624, mimikatz, sekurlsa, procdump,
lsass, RAR) are deliberately NOT in `forbidden_in_core`, so they remain free to
use in generic rules. If a future change hard-codes a case IOC into core logic,
this test goes red — universality becomes CI, not a promise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

_AGENT = Path(__file__).resolve().parents[1]
_REPO = _AGENT.parent
_PROFILE_DIR = _AGENT / "validation_profiles"

# Directories whose .py files must contain ZERO case-identifying IOCs.
_CORE_DIRS = [
    _AGENT / "dfir_agent" / "rules",
    _AGENT / "dfir_agent" / "nodes",
    _REPO / "mcp_server" / "forensic_mcp" / "wrappers",
]

# Technical debt of case IOCs in core logic — RETIRED in Phase 8: the benign
# vendor hints moved from rules/dc_events.py to case_profiles/srl2015/
# known_admin_tools.yml (loaded via dfir_agent.enrichment). Core is now clean;
# this set is empty and must stay empty.
_KNOWN_DEBT: set[tuple[str, str]] = set()


def _forbidden_tokens() -> list[str]:
    tokens: set[str] = set()
    for prof in _PROFILE_DIR.glob("*.yml"):
        data = yaml.safe_load(prof.read_text(encoding="utf-8")) or {}
        block = data.get("forbidden_in_core", {}) or {}
        for group in block.values():
            for tok in group or []:
                tok = str(tok).strip().lower()
                if len(tok) >= 4:  # ignore trivially short tokens
                    tokens.add(tok)
    return sorted(tokens)


def _core_py_files() -> list[Path]:
    files: list[Path] = []
    for d in _CORE_DIRS:
        if d.exists():
            files += [p for p in d.rglob("*.py") if "__pycache__" not in p.parts]
    return files


@pytest.mark.skipif(yaml is None, reason="PyYAML not installed")
def test_profiles_exist_and_have_forbidden_block():
    profs = list(_PROFILE_DIR.glob("*.yml"))
    assert profs, "no validation profiles found"
    assert _forbidden_tokens(), "no forbidden_in_core tokens declared in any profile"


@pytest.mark.skipif(yaml is None, reason="PyYAML not installed")
def test_no_case_iocs_in_core_code():
    tokens = _forbidden_tokens()
    files = _core_py_files()
    assert files, "no core .py files found — check paths"

    violations: list[str] = []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore").lower()
        for tok in tokens:
            if tok in text and (f.name, tok) not in _KNOWN_DEBT:
                violations.append(f"{f.relative_to(_REPO)} contains case IOC '{tok}'")

    assert not violations, (
        "Case-identifying IOCs leaked into core detection code "
        "(put them in validation_profiles/ or tests/ instead):\n  "
        + "\n  ".join(violations)
    )

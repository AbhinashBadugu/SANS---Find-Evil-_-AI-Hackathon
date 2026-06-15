"""Phase 9 — reporting / scoring deliverables.

Confirms the capability-expansion report exists and that the scorer emits the
required scoring dimensions (recall, missed-parser split, hallucination hard-fail,
kill-chain coverage matrix) on a synthetic case.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_REPO = Path(__file__).resolve().parents[2]

yaml = pytest.importorskip("yaml")
from eval.score_profile import score  # noqa: E402


def test_expansion_report_exists():
    doc = _REPO / "AGENT_CAPABILITY_EXPANSION_REPORT.md"
    assert doc.exists(), "AGENT_CAPABILITY_EXPANSION_REPORT.md deliverable is missing"
    text = doc.read_text(encoding="utf-8").lower()
    for section in ["what was added", "what was not added", "how to run",
                    "validates", "remaining gaps"]:
        assert section in text, f"report missing section: {section}"


def test_scorer_emits_required_dimensions(tmp_path):
    case_dir = tmp_path / "cases" / "demo"
    host = case_dir / "hosts" / "h1" / "agent"
    host.mkdir(parents=True)
    (case_dir / "provenance.jsonl").write_text(json.dumps({"provenance_id": "cmd-1"}) + "\n")
    (host / "findings.json").write_text(json.dumps({"host_id": "h1", "findings": [
        {"finding_id": "F1", "title": "beacon evilcorp 1.2.3.4", "category": "c2",
         "confidence": "confirmed", "evidence": [{"provenance_id": "cmd-1"}]},
        {"finding_id": "F2", "title": "uncited claim", "category": "x",
         "confidence": "confirmed", "evidence": []},
    ]}))
    profile = tmp_path / "demo.yml"
    profile.write_text(yaml.safe_dump({
        "case": "demo", "version": 1, "forbidden_in_core": {"names": ["evilcorp"]},
        "milestones": [
            {"id": "M1", "stage": "command_and_control", "requires": ["mft"],
             "key_facts": ["evilcorp", "1.2.3.4"], "weight": 1.0},
            {"id": "M2", "stage": "exfiltration", "requires": ["__unimplemented__"],
             "key_facts": ["nope1", "nope2"], "weight": 1.0},
        ],
    }))
    r = score("demo", str(tmp_path), profile)
    # required scoring dimensions present
    assert 0.0 <= r["recall_strict"] <= 1.0
    assert "recall_with_partial_credit" in r
    t = r["totals"]
    assert {"correct", "partial", "missed", "wrong",
            "missed_due_to_missing_parser", "missed_despite_parser"} <= set(t)
    assert t["missed_due_to_missing_parser"] >= 1          # M2 needs an unimplemented parser
    assert r["hallucinations"]["count"] == 1               # F2 uncited confirmed = hard fail
    assert r["by_stage"]                                   # kill-chain coverage matrix

"""Tests for the profile-agnostic validation scorer (eval/score_profile.py).

Builds a tiny synthetic case + profile in a tmp dir (no real evidence) and checks:
  * a milestone whose facts appear in a cited finding scores `correct`
  * a milestone needing an unimplemented capability scores `missed/missing_parser`
  * an `anti_fact` match scores `wrong`
  * a confirmed finding with no citation is counted as a hallucination (hard fail)
"""

from __future__ import annotations

import json

import pytest

yaml = pytest.importorskip("yaml")

from eval.score_profile import score  # noqa: E402


def _write_case(tmp_path):
    case_dir = tmp_path / "cases" / "demo"
    host = case_dir / "hosts" / "h1" / "agent"
    host.mkdir(parents=True)
    (case_dir / "provenance.jsonl").write_text(
        json.dumps({"provenance_id": "cmd-1"}) + "\n", encoding="utf-8")
    findings = {
        "host_id": "h1",
        "findings": [
            {  # cited -> backs milestone M_a, not a hallucination
                "finding_id": "F-1", "title": "beacon to evilcorp 1.2.3.4",
                "category": "c2", "confidence": "confirmed",
                "evidence": [{"provenance_id": "cmd-1", "record_id": "x"}],
            },
            {  # confirmed but NO citation -> hallucination (hard fail)
                "finding_id": "F-2", "title": "made up claim wrongclaim",
                "category": "misc", "confidence": "confirmed", "evidence": [],
            },
        ],
    }
    (host / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return case_dir


def _write_profile(tmp_path):
    profile = {
        "case": "demo", "version": 1,
        "forbidden_in_core": {"names": ["evilcorp"]},
        "milestones": [
            {"id": "M_a", "stage": "command_and_control", "requires": ["mft"],
             "key_facts": ["evilcorp", "1.2.3.4"], "weight": 1.0},
            {"id": "M_b", "stage": "initial_access", "requires": ["__unimplemented_cap__"],
             "key_facts": ["neverfound1", "neverfound2"], "weight": 1.0},
            {"id": "M_c", "stage": "execution", "requires": ["mft"],
             "key_facts": ["somefact"], "anti_facts": ["wrongclaim"], "weight": 1.0},
        ],
    }
    p = tmp_path / "demo.yml"
    p.write_text(yaml.safe_dump(profile), encoding="utf-8")
    return p


def test_scorer_classifies_and_counts(tmp_path):
    _write_case(tmp_path)
    profile = _write_profile(tmp_path)
    r = score("demo", str(tmp_path), profile)

    by_id = {m["id"]: m for m in r["milestones"]}
    assert by_id["M_a"]["status"] == "correct"
    assert by_id["M_a"]["backing_provenance"] == ["cmd-1"]

    assert by_id["M_b"]["status"] == "missed"
    assert by_id["M_b"]["miss_reason"] == "missing_parser"  # java_cache not implemented

    assert by_id["M_c"]["status"] == "wrong"  # anti_fact matched

    # 1 of 3 correct -> strict recall 1/3.
    assert r["recall_strict"] == pytest.approx(1 / 3, abs=0.01)

    # The uncited confirmed finding (F-2) is a hallucination; F-1 is clean.
    assert r["hallucinations"]["count"] == 1
    assert "F-2" in r["hallucinations"]["uncited_high_conf"]

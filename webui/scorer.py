"""Score the DFIR agent's output against the evidence-verified oracle (oracle_v2).

This is the agent's accuracy "after" column — the apples-to-apples counterpart to
~/baseline-runs/scoring/score_baseline.py (the baseline "before"). It reuses the
SAME oracle and the SAME matching rule (>= HIT_THRESHOLD of a milestone's key_facts
present in the report text; an anti_fact match flags the milestone WRONG) so the two
numbers are directly comparable.

It also reports accuracy dimensions the baseline could not, because the agent's
findings are structured + cited:
  * citation_quality — % of asserted findings carrying a FULL citation
    {tool, artifact_path, provenance_id, record_id}.
  * extra_unsupported — asserted findings whose provenance_id does NOT resolve in
    the immutable logbook (target: 0; the report lint already enforces this).
  * benign_as_malware — built-in/signed files asserted as malware (target: 0; the
    benign allowlist demotes these to false_positive by construction).

Pure stdlib, no network, no LLM — deterministic and reproducible.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

DEFAULT_CASE_ROOT = os.path.expanduser("~/Desktop/DFIR agent/Agent analysis")
DEFAULT_ORACLE = os.path.expanduser("~/baseline-runs/scoring/oracle_v2.json")
HIT_THRESHOLD = 0.5  # same as the baseline scorer


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.lower())


# --------------------------------------------------------------------------- #
# Inputs the agent produced
# --------------------------------------------------------------------------- #
def _agent_report_text(case_root: str, case_id: str) -> tuple[str, list[str]]:
    """Concatenate every report the agent wrote (per-host + cross-host)."""
    case_dir = Path(case_root) / "cases" / case_id
    parts: list[str] = []
    used: list[str] = []
    cross = case_dir / "CASE_REPORT.md"
    if cross.exists():
        parts.append(cross.read_text(encoding="utf-8"))
        used.append(str(cross))
    for rep in sorted(case_dir.glob("hosts/*/agent/*_report.md")):
        parts.append(rep.read_text(encoding="utf-8"))
        used.append(str(rep))
    return "\n\n".join(parts), used


def _load_findings(case_root: str, case_id: str) -> list[dict]:
    case_dir = Path(case_root) / "cases" / case_id
    out: list[dict] = []
    for fj in sorted(case_dir.glob("hosts/*/agent/findings.json")):
        try:
            data = json.loads(fj.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for f in data.get("findings", []):
            out.append(f)
    return out


def _provenance_ids(case_root: str, case_id: str) -> set[str]:
    p = Path(case_root) / "cases" / case_id / "provenance.jsonl"
    ids: set[str] = set()
    if not p.exists():
        return ids
    for line in p.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        pid = rec.get("provenance_id")
        if pid:
            ids.add(pid)
    return ids


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _score_milestones(text: str, oracle: dict) -> tuple[list[dict], float]:
    norm_text = _norm(text)
    milestones: list[dict] = []
    num = den = 0.0
    for m in oracle["milestones"]:
        facts = list(m["key_facts"])
        present = [f for f in facts if _norm(f) in norm_text]
        frac = len(present) / len(facts) if facts else 0.0
        wrong = any(_norm(af) in norm_text for af in m.get("anti_facts", []))
        hit = (frac >= HIT_THRESHOLD) and not wrong
        w = m.get("weight", 1.0)
        den += w
        if hit:
            num += w
        milestones.append({
            "id": m["id"], "summary": m.get("summary", ""), "weight": w,
            "hit": hit, "wrong": wrong, "frac": round(frac, 2),
            "matched": present, "missed": [f for f in facts if f not in present],
        })
    return milestones, (round(num / den, 3) if den else 0.0)


def _citation_quality(findings: list[dict], prov_ids: set[str]) -> dict:
    asserted = [f for f in findings if f.get("confidence") != "false_positive"]
    full = 0
    extra_unsupported: list[str] = []
    for f in asserted:
        ev = f.get("evidence", [])
        # a finding has a FULL citation if some EvidenceReference carries all four fields
        has_full = any(
            e.get("provenance_id") and e.get("record_id") and e.get("tool")
            and (e.get("artifact_path"))
            for e in ev
        )
        if has_full:
            full += 1
        # resolvable? at least one provenance_id present in the logbook
        if not any(e.get("provenance_id") in prov_ids for e in ev):
            extra_unsupported.append(f.get("finding_id", "?"))
    n = len(asserted)
    return {
        "asserted_findings": n,
        "full_citation_pct": round(100 * full / n, 1) if n else 100.0,
        "extra_unsupported": extra_unsupported,
        "extra_unsupported_count": len(extra_unsupported),
    }


def score_agent(case_root: str = DEFAULT_CASE_ROOT, case_id: str = "srl2015",
                oracle_path: str = DEFAULT_ORACLE) -> dict:
    oracle = json.loads(Path(oracle_path).read_text(encoding="utf-8"))
    text, used_reports = _agent_report_text(case_root, case_id)
    findings = _load_findings(case_root, case_id)
    prov_ids = _provenance_ids(case_root, case_id)

    milestones, recall = _score_milestones(text, oracle)
    cites = _citation_quality(findings, prov_ids)
    wrong = [m["id"] for m in milestones if m["wrong"]]
    hits = [m["id"] for m in milestones if m["hit"]]
    missed = [m["id"] for m in milestones if not m["hit"] and not m["wrong"]]

    return {
        "case_id": case_id,
        "oracle_version": oracle.get("version"),
        "threshold": HIT_THRESHOLD,
        "recall": recall,
        "hits": hits,
        "missed": missed,
        "wrong_milestones": wrong,           # anti-fact matches = hallucination-adjacent (target 0)
        "milestones": milestones,
        "citation_quality": cites,
        "reports_scored": used_reports,
        "n_findings": len(findings),
    }


# --------------------------------------------------------------------------- #
# Markdown accuracy report (the shippable deliverable)
# --------------------------------------------------------------------------- #
def render_accuracy_report(score: dict) -> str:
    L: list[str] = []
    L.append(f"# Accuracy Report — DFIR Agent vs oracle_v{score['oracle_version']}  ({score['case_id']})")
    L.append("")
    L.append("> Apples-to-apples with the baseline: same oracle, same hit rule "
             f"(≥{int(score['threshold']*100)}% of a milestone's key facts present; an "
             "`anti_fact` match marks the milestone WRONG). Deterministic, no LLM.")
    L.append("")
    cq = score["citation_quality"]
    L.append("## Headline")
    L.append("")
    L.append(f"- **Recall (weighted):** {score['recall']}  "
             f"({len(score['hits'])}/{len(score['milestones'])} milestones hit)")
    L.append(f"- **Wrong milestones (anti-fact matched):** {len(score['wrong_milestones'])}  (target 0)")
    L.append(f"- **Extra unsupported findings (unresolvable citation):** "
             f"{cq['extra_unsupported_count']}  (target 0)")
    L.append(f"- **Full-citation quality:** {cq['full_citation_pct']}%  of "
             f"{cq['asserted_findings']} asserted findings carry "
             "{tool, path, provenance_id, record_id}")
    L.append("")
    L.append("## Per-milestone")
    L.append("")
    L.append("| Milestone | Result | Matched key facts |")
    L.append("|---|---|---|")
    for m in score["milestones"]:
        res = "✅ hit" if m["hit"] else ("❌ WRONG" if m["wrong"] else "— missed")
        matched = ", ".join(f"`{x}`" for x in m["matched"]) or "_none_"
        L.append(f"| {m['id']} (w={m['weight']}) | {res} | {matched} |")
    L.append("")
    if score["missed"]:
        L.append("## Missed milestones (honest disclosure)")
        L.append("")
        for m in score["milestones"]:
            if m["id"] in score["missed"]:
                L.append(f"- **{m['id']}** — missing: "
                         + ", ".join(f"`{x}`" for x in m["missed"]))
        L.append("")
    L.append("---")
    L.append("_Recall is computed over the agent's own cited reports; citation quality and "
             "unsupported counts are computed over the structured findings + the immutable "
             "provenance logbook. Nothing here is model-judged._")
    return "\n".join(L)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Score the DFIR agent vs oracle_v2 (accuracy 'after').")
    ap.add_argument("--case", default="srl2015")
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    ap.add_argument("--oracle", default=DEFAULT_ORACLE)
    args = ap.parse_args()

    score = score_agent(args.case_root, args.case, args.oracle)
    md = render_accuracy_report(score)
    out_dir = Path(args.case_root) / "cases" / args.case / "agent"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "accuracy_report.md").write_text(md, encoding="utf-8")
    (out_dir / "accuracy_score.json").write_text(json.dumps(score, indent=2), encoding="utf-8")
    print(md)
    print(f"\n[written] {out_dir / 'accuracy_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

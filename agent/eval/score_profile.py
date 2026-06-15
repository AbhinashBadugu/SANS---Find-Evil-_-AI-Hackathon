"""Score an agent case run against a validation profile (the answer key).

    python -m eval.score_profile --case srl2015 \
        --case-root "~/Desktop/DFIR agent/Agent analysis" \
        --profile validation_profiles/srl2015.yml

PROFILE-AGNOSTIC: point `--profile` at any case's answer key. The profile is the
ONLY place case IOCs live; this scorer contains no case knowledge.

What it computes
----------------
Per milestone (a kill-chain truth the agent should have reconstructed):
  * correct  : >= FULL_THRESHOLD of key_facts present in the run's findings+reports
  * partial  : >= PARTIAL_THRESHOLD present
  * missed   : below that
  * wrong    : an `anti_fact` was asserted (e.g. wrong patient zero)  -> false positive
A missed/partial milestone is tagged `missing_parser` (the capability it needs
does not exist yet) or `despite_parser` (capability exists, agent still missed it
— the real bug). Every credited milestone records the provenance_ids backing it.

Precision / hallucination (HARD FAILURES):
  * any confirmed/likely finding with NO evidence, or whose cited provenance_id
    does not resolve in the case logbook, is counted as an uncited/unresolved
    claim — the anti-hallucination guarantee, measured.

Output: <case>/agent/validation_score.{md,json}. No network, no LLM, deterministic.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.capabilities import IMPLEMENTED_CAPABILITIES, classify_miss  # noqa: E402

DEFAULT_CASE_ROOT = os.path.expanduser("~/Desktop/DFIR agent/Agent analysis")
FULL_THRESHOLD = 0.6     # fraction of key_facts present -> "correct"
PARTIAL_THRESHOLD = 0.3  # -> "partial"
HIGH_CONF = {"confirmed", "likely"}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower())


def _load_profile(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yml", ".yaml"):
        import yaml  # local import so JSON-only users need no PyYAML
        return yaml.safe_load(text)
    return json.loads(text)


def _case_dir(case_root: str, case_id: str) -> Path:
    return Path(case_root).expanduser() / "cases" / case_id


def _load_findings(case_dir: Path) -> list[dict]:
    """All per-host findings (findings.json bundles)."""
    out: list[dict] = []
    for fj in sorted(case_dir.glob("hosts/*/agent/findings.json")):
        try:
            data = json.loads(fj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for f in data.get("findings", []):
            f.setdefault("_host", data.get("host_id"))
            out.append(f)
    return out


def _load_reports_text(case_dir: Path) -> str:
    parts: list[str] = []
    for md in [case_dir / "CASE_REPORT.md", *case_dir.glob("hosts/*/agent/*_report.md")]:
        if md.exists():
            parts.append(md.read_text(encoding="utf-8", errors="ignore"))
    return _norm(" ".join(parts))


def _load_provenance_ids(case_dir: Path) -> set[str]:
    ids: set[str] = set()
    prov = case_dir / "provenance.jsonl"
    if prov.exists():
        for line in prov.open("r", encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                ids.add(json.loads(line).get("provenance_id", ""))
            except json.JSONDecodeError:
                continue
    ids.discard("")
    return ids


def _finding_text(f: dict) -> str:
    bits = [f.get("title"), f.get("summary"), f.get("category"), f.get("finding_type")]
    bits += [t for t in (f.get("tags") or [])]
    for e in f.get("evidence", []) or []:
        bits += [str(e.get("record_id")), str(e.get("artifact")), str(e.get("artifact_path"))]
    for key in ("iocs", "entities", "indicators"):
        v = f.get(key)
        if isinstance(v, (list, tuple)):
            bits += [str(x) for x in v]
        elif v:
            bits.append(str(v))
    return _norm(" ".join(b for b in bits if b))


def _finding_prov_ids(f: dict) -> list[str]:
    return [e.get("provenance_id") for e in (f.get("evidence") or []) if e.get("provenance_id")]


def score(case_id: str, case_root: str, profile_path: Path) -> dict:
    profile = _load_profile(profile_path)
    case_dir = _case_dir(case_root, case_id)
    findings = _load_findings(case_dir)
    report_text = _load_reports_text(case_dir)
    prov_ids = _load_provenance_ids(case_dir)

    # Precompute searchable text per finding (with its provenance + confidence).
    findings_idx = [
        {"text": _finding_text(f), "prov": _finding_prov_ids(f),
         "conf": (f.get("confidence") or "").lower(), "id": f.get("finding_id"),
         "host": f.get("_host")}
        for f in findings
    ]
    corpus = report_text + " " + " ".join(fi["text"] for fi in findings_idx)

    milestones_out: list[dict] = []
    w_total = w_correct = w_credit = 0.0
    by_stage: dict[str, dict] = defaultdict(lambda: {"correct": 0, "partial": 0, "missed": 0, "wrong": 0})

    for m in profile.get("milestones", []):
        facts = [str(x) for x in m.get("key_facts", [])]
        present = [f for f in facts if _norm(f) in corpus]
        frac = len(present) / len(facts) if facts else 0.0
        wrong = any(_norm(af) in corpus for af in m.get("anti_facts", []))
        requires = [str(x) for x in (m.get("requires") or [])]

        if wrong:
            status = "wrong"
        elif frac >= FULL_THRESHOLD:
            status = "correct"
        elif frac >= PARTIAL_THRESHOLD:
            status = "partial"
        else:
            status = "missed"

        # Which findings (and provenance) back this milestone?
        backing_prov: list[str] = []
        for fi in findings_idx:
            if any(_norm(p) in fi["text"] for p in present):
                backing_prov += [p for p in fi["prov"] if p in prov_ids]
        backing_prov = sorted(set(backing_prov))[:5]

        miss_reason = None
        if status in ("partial", "missed"):
            miss_reason = classify_miss(requires)

        w = float(m.get("weight", 1.0))
        w_total += w
        if status == "correct":
            w_correct += w
            w_credit += w
        elif status == "partial":
            w_credit += 0.5 * w

        by_stage[m.get("stage", "unknown")][status if status != "wrong" else "wrong"] += 1
        milestones_out.append({
            "id": m["id"], "stage": m.get("stage", "unknown"), "status": status,
            "frac": round(frac, 2), "matched": present, "weight": w,
            "requires": requires, "miss_reason": miss_reason,
            "backing_provenance": backing_prov,
        })

    # --- precision / hallucination (hard failures) ---
    uncited, unresolved = [], []
    for fi in findings_idx:
        if fi["conf"] in HIGH_CONF:
            if not fi["prov"]:
                uncited.append(fi["id"])
            elif any(p not in prov_ids for p in fi["prov"]):
                unresolved.append(fi["id"])

    missed_missing = sum(1 for m in milestones_out if m["miss_reason"] == "missing_parser")
    missed_despite = sum(1 for m in milestones_out if m["miss_reason"] == "despite_parser")

    return {
        "case": case_id,
        "profile": str(profile_path),
        "profile_version": profile.get("version"),
        "thresholds": {"full": FULL_THRESHOLD, "partial": PARTIAL_THRESHOLD},
        "implemented_capabilities": sorted(IMPLEMENTED_CAPABILITIES),
        "totals": {
            "findings": len(findings),
            "milestones": len(milestones_out),
            "correct": sum(1 for m in milestones_out if m["status"] == "correct"),
            "partial": sum(1 for m in milestones_out if m["status"] == "partial"),
            "missed": sum(1 for m in milestones_out if m["status"] == "missed"),
            "wrong": sum(1 for m in milestones_out if m["status"] == "wrong"),
            "missed_due_to_missing_parser": missed_missing,
            "missed_despite_parser": missed_despite,
        },
        "recall_strict": round(w_correct / w_total, 3) if w_total else 0.0,
        "recall_with_partial_credit": round(w_credit / w_total, 3) if w_total else 0.0,
        "hallucinations": {
            "uncited_high_conf": uncited,
            "unresolved_citations": unresolved,
            "count": len(uncited) + len(unresolved),
        },
        "by_stage": dict(by_stage),
        "milestones": milestones_out,
    }


def render_md(r: dict) -> str:
    t = r["totals"]
    L = [
        f"# Validation Score — {r['case']}",
        "",
        f"- Profile: `{r['profile']}` (v{r['profile_version']})",
        f"- **Recall (strict): {r['recall_strict']:.0%}**  ·  with partial credit: {r['recall_with_partial_credit']:.0%}",
        f"- Milestones: {t['correct']} correct · {t['partial']} partial · {t['missed']} missed · {t['wrong']} wrong",
        f"- Misses: {t['missed_due_to_missing_parser']} need a new parser · "
        f"**{t['missed_despite_parser']} despite parser (real bugs)**",
        f"- Hallucinations (uncited/unresolved confirmed|likely): **{r['hallucinations']['count']}** "
        f"{'✅' if r['hallucinations']['count'] == 0 else '❌'}",
        f"- Findings scored: {t['findings']}",
        "",
        "## Milestones",
        "",
        "| Milestone | Stage | Status | facts | miss reason | provenance |",
        "|-----------|-------|--------|-------|-------------|------------|",
    ]
    icon = {"correct": "✅ correct", "partial": "🟡 partial", "missed": "❌ missed", "wrong": "🔴 WRONG"}
    for m in r["milestones"]:
        prov = ", ".join(m["backing_provenance"]) or "—"
        mr = m["miss_reason"] or "—"
        L.append(f"| {m['id']} | {m['stage']} | {icon.get(m['status'], m['status'])} | "
                 f"{int(m['frac']*100)}% | {mr} | {prov} |")
    if r["hallucinations"]["count"]:
        L += ["", "## ⚠️ Hallucination / uncited high-confidence findings",
              f"- uncited: {r['hallucinations']['uncited_high_conf']}",
              f"- unresolved: {r['hallucinations']['unresolved_citations']}"]
    L += ["", "## Coverage by kill-chain stage", "",
          "| Stage | correct | partial | missed | wrong |",
          "|-------|---------|---------|--------|-------|"]
    for stage, c in r["by_stage"].items():
        L.append(f"| {stage} | {c['correct']} | {c['partial']} | {c['missed']} | {c['wrong']} |")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Score an agent case run vs a validation profile.")
    ap.add_argument("--case", required=True)
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    ap.add_argument("--profile", default=None, help="path to <case>.yml (default: validation_profiles/<case>.yml)")
    ap.add_argument("--output", default=None, help="markdown output path (default: <case>/agent/validation_score.md)")
    args = ap.parse_args()

    profile_path = Path(args.profile).expanduser() if args.profile else (
        Path(__file__).resolve().parents[1] / "validation_profiles" / f"{args.case}.yml")
    if not profile_path.exists():
        print(f"ERROR: profile not found: {profile_path}", file=sys.stderr)
        return 2

    r = score(args.case, args.case_root, profile_path)
    case_dir = _case_dir(args.case_root, args.case)
    out_md = Path(args.output).expanduser() if args.output else (case_dir / "agent" / "validation_score.md")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_md(r), encoding="utf-8")
    out_md.with_suffix(".json").write_text(json.dumps(r, indent=2), encoding="utf-8")

    t = r["totals"]
    print(f"=== {args.case}: recall(strict)={r['recall_strict']:.0%} "
          f"partial-credit={r['recall_with_partial_credit']:.0%} ===")
    print(f"  correct={t['correct']} partial={t['partial']} missed={t['missed']} wrong={t['wrong']}")
    print(f"  missed: missing_parser={t['missed_due_to_missing_parser']} despite_parser={t['missed_despite_parser']}")
    print(f"  hallucinations={r['hallucinations']['count']}")
    print(f"  wrote {out_md} (+ .json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

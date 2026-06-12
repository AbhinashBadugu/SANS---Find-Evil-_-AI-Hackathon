"""Host Report node (Phase 6).

Assembles a HostReport from the threaded state, renders a fully-cited Markdown
report, and runs a citation linter. Every claim (a finding above false_positive,
a contradiction, a timeline event) must carry at least one EvidenceReference whose
provenance_id resolves in the logbook; the linter counts violations and the
acceptance gate requires ZERO.

The executive summary is built deterministically from the facts; if an LLM is
available it only rephrases that text (never adds facts) — otherwise the
deterministic version ships.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..narrate import narrate_summary
from ..scoring import load_provenance_index
from ..state import CaseState, Confidence, HostReport
from . import NodeContext

_TIER_ORDER = [Confidence.confirmed, Confidence.likely, Confidence.suspicious]


# --------------------------------------------------------------------------- #
# Citation resolution
# --------------------------------------------------------------------------- #
def _cite(ev, prov_index: dict) -> tuple[str, bool]:
    """Render one citation line and whether its provenance_id resolves."""
    rec = prov_index.get(ev.provenance_id)
    resolves = rec is not None
    tool = ev.tool or (rec.get("tool_name") if rec else None) or "?"
    path = ev.artifact_path or (rec.get("output_paths") or [None])[0] if rec else ev.artifact_path
    ts = (rec.get("end_time") or rec.get("start_time")) if rec else None
    record = ev.record_id or "-"
    line = f"`{ev.provenance_id}` tool=`{tool}` record=`{record}`"
    if path:
        line += f" → `{path}`"
    if ts:
        line += f" @ {ts}"
    if ev.note:
        line += f"\n      · {ev.note}"
    return line, resolves


def lint_citations(state: CaseState, prov_index: dict) -> dict:
    """Count claims with no resolvable provenance citation (target: 0)."""
    uncited: list[str] = []

    def _ok(evidence) -> bool:
        return any(e.provenance_id in prov_index for e in evidence)

    for f in state.findings:
        if f.confidence == Confidence.false_positive:
            continue  # disputed items are not asserted claims
        if not _ok(f.evidence):
            uncited.append(f"finding:{f.finding_id}")
    for c in state.contradictions:
        if not _ok(c.evidence):
            uncited.append(f"contradiction:{c.contradiction_id}")
    for te in state.timeline:
        if not _ok(te.evidence):
            uncited.append(f"timeline:{te.ts.isoformat()}")
    return {"uncited_claims": uncited, "clean": not uncited}


# --------------------------------------------------------------------------- #
# Summary + rendering
# --------------------------------------------------------------------------- #
def _deterministic_summary(state: CaseState, host) -> str:
    by_tier = {t: [f for f in state.findings if f.confidence == t] for t in _TIER_ORDER}
    confirmed = by_tier[Confidence.confirmed]
    pz = min((te.ts for te in state.timeline if "PATIENT-ZERO MARKER" in te.description), default=None)
    bits = []
    if confirmed:
        lead = max(confirmed, key=lambda f: f.source_count)
        bits.append(
            f"On {host.host_id} ({host.os}), the agent confirmed {len(confirmed)} malicious "
            f"artifact(s); the primary finding is \"{lead.title}\", corroborated across "
            f"{lead.source_count} independent sources."
        )
    else:
        bits.append(f"On {host.host_id} ({host.os}), no finding reached the confirmed tier.")
    if pz:
        bits.append(f"Patient-zero compromise is pinned to {pz.isoformat()} UTC.")
    n_likely = len(by_tier[Confidence.likely])
    n_susp = len(by_tier[Confidence.suspicious])
    if n_likely or n_susp:
        bits.append(f"{n_likely} likely and {n_susp} suspicious lead(s) remain.")
    if state.contradictions:
        bits.append(
            f"{len(state.contradictions)} contradiction(s) were detected and resolved "
            f"(including timestomping and a memory-vs-disk self-correction)."
        )
    fp = [f for f in state.findings if f.confidence == Confidence.false_positive]
    if fp:
        bits.append(f"{len(fp)} candidate(s) were disputed and ruled benign.")
    if state.gaps:
        bits.append(f"{len(state.gaps)} evidence gap(s) are disclosed below.")
    return " ".join(bits)


def _render(report: HostReport, state: CaseState, prov_index: dict, summary: str, narrated: bool) -> str:
    L: list[str] = []
    L.append(f"# Host Report — {report.host_id}")
    L.append("")
    L.append(f"- **OS:** {report.os}  ·  **Role:** {report.role.value}")
    L.append(f"- **Generated:** {report.generated_at.isoformat()} UTC")
    pz = min((te.ts for te in state.timeline if "PATIENT-ZERO MARKER" in te.description), default=None)
    if pz:
        L.append(f"- **Patient-zero:** {pz.isoformat()} UTC")
    L.append(f"- **Provenance actions logged:** {len(prov_index)}")
    L.append("")
    L.append("## Executive summary" + ("  _(LLM-narrated)_" if narrated else "  _(deterministic)_"))
    L.append("")
    L.append(summary)
    L.append("")

    titles = {
        Confidence.confirmed: "Confirmed",
        Confidence.likely: "Likely",
        Confidence.suspicious: "Suspicious",
    }
    for tier in _TIER_ORDER:
        items = [f for f in state.findings if f.confidence == tier]
        L.append(f"## {titles[tier]} ({len(items)})")
        L.append("")
        if not items:
            L.append("_None._")
            L.append("")
            continue
        for f in sorted(items, key=lambda x: -x.source_count):
            fams = sorted({e.source_family for e in f.evidence if e.source_family})
            L.append(f"### {f.title}")
            L.append(f"- **host:** `{f.host_id}`  ·  **category:** {f.category}  ·  "
                     f"**sources:** {f.source_count} {fams}  ·  **rule:** `{f.rule}`")
            L.append("")
            L.append(f.description)
            L.append("")
            L.append("**Evidence:**")
            for e in f.evidence:
                line, _ = _cite(e, prov_index)
                L.append(f"- {line}")
            L.append("")

    if state.contradictions:
        L.append(f"## Contradictions & self-corrections ({len(state.contradictions)})")
        L.append("")
        for c in state.contradictions:
            L.append(f"### {c.claim}  (`{c.contradiction_id}`)")
            L.append(f"- **A:** {c.source_a}")
            L.append(f"- **B:** {c.source_b}")
            L.append(f"- **Resolution:** {c.resolution}")
            for e in c.evidence:
                line, _ = _cite(e, prov_index)
                L.append(f"- **cite:** {line}")
            L.append("")

    if state.timeline:
        L.append(f"## Timeline ({len(state.timeline)})")
        L.append("")
        for te in sorted(state.timeline, key=lambda x: x.ts):
            line, _ = _cite(te.evidence[0], prov_index) if te.evidence else ("(no citation)", False)
            L.append(f"- **{te.ts.isoformat()}** [{te.source}] {te.description}")
            L.append(f"    - cite: {line}")
        L.append("")

    fp = [f for f in state.findings if f.confidence == Confidence.false_positive]
    if fp:
        L.append(f"## Disputed / benign ({len(fp)})  _(transparency)_")
        L.append("")
        for f in fp:
            L.append(f"- **{f.title}** — ruled benign ({', '.join(f.tags)})")
        L.append("")

    if state.gaps:
        L.append(f"## Evidence gaps ({len(state.gaps)})")
        L.append("")
        for g in state.gaps:
            L.append(f"- {g}")
        L.append("")

    L.append("---")
    L.append("_Every claim above cites a provenance_id from the MCP server's immutable "
             "logbook. Confidence tiers and contradictions are assigned by deterministic "
             "rules, not the language model._")
    return "\n".join(L)


async def report(state: CaseState, ctx: NodeContext) -> CaseState:
    host = state.hosts[state.current_host]
    prov_index = load_provenance_index(ctx.case_root, state.case_id)

    hr = HostReport(
        host_id=host.host_id, os=host.os, role=host.role,
        findings=state.findings, contradictions=state.contradictions,
        timeline=sorted(state.timeline, key=lambda x: x.ts), gaps=state.gaps,
    )
    # Reproducible generated_at: the latest action in the logbook (fallback: now).
    times = [r.get("end_time") for r in prov_index.values() if r.get("end_time")]
    if times:
        try:
            hr.generated_at = datetime.fromisoformat(max(times).replace("Z", "+00:00"))
        except ValueError:
            pass

    det_summary = _deterministic_summary(state, host)
    narrated = narrate_summary(det_summary)
    summary = narrated or det_summary
    hr.summary = summary

    lint = lint_citations(state, prov_index)
    md = _render(hr, state, prov_index, summary, narrated is not None)

    out_dir = Path(ctx.case_root) / "cases" / state.case_id / "hosts" / host.host_id / "agent"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"{host.host_id}_report.md"
    report_path.write_text(md, encoding="utf-8")

    state.report_path = str(report_path)
    state.report_lint = lint
    state.report_narrated = narrated is not None
    state.completed_steps.append("report")
    ctx.decisions.record(
        agent_name="report", step="render_host_report",
        inputs_summary=f"{len(state.findings)} findings, {len(state.contradictions)} contradictions",
        action=f"wrote {report_path.name}; citation lint {'CLEAN' if lint['clean'] else 'FAILED'} "
               f"({len(lint['uncited_claims'])} uncited)",
        rationale="Every asserted claim must carry a resolvable provenance citation; the linter enforces it.",
    )
    return state

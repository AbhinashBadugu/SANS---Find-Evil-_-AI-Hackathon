"""Evidence-coverage rendering — the demonstrable proof that the agent is
universal-READY and honest about what it can and cannot analyse.

For each discovered host/device it shows the matched OS/device-family analyzer and
an artifact-by-artifact status: parsed, present-but-wrapper-missing, or not-present.
Absence is reported explicitly — never as "clean". Metadata only; no MCP, no tools.
"""

from __future__ import annotations

from .analyzers import select_analyzer
from .state import ArtifactParseStatus as S
from .state import CaseManifest, ManifestHost


def host_coverage(host: ManifestHost) -> dict:
    """Coverage summary for one host, using its matched family analyzer."""
    analyzer = select_analyzer(host.os_family)
    results = analyzer.artifact_results(host.host_id, host.evidence_capabilities)
    by = lambda st: [r.artifact_type.value for r in results if r.status == st]  # noqa: E731
    caps_on = sorted(k.replace("has_", "") for k, v in host.evidence_capabilities.model_dump().items() if v)
    return {
        "host_id": host.host_id,
        "os_family": host.os_family.value,
        "confidence": host.classification_confidence,
        "analyzer": analyzer.name,
        "implemented": analyzer.implemented,
        "capabilities": caps_on,
        "parsed": by(S.present_and_parsed),
        "wrapper_missing": by(S.present_but_wrapper_missing),
        "not_present": by(S.not_present),
        "supported_total": len(results),
        "reason": host.classification_reason,
    }


def render_coverage_markdown(manifest: CaseManifest) -> str:
    L: list[str] = []
    L.append(f"# Evidence Coverage — case `{manifest.case_id}`")
    L.append("")
    L.append(f"- Evidence root: `{manifest.case_root}`")
    L.append(f"- Hosts/devices discovered: **{len(manifest.hosts)}**"
             f"  ·  unassigned files: {len(manifest.unassigned_evidence)}")
    L.append("")
    L.append("| host/device | family | conf | analyzer | parsed | wrapper-missing | not-present |")
    L.append("|---|---|---|---|---|---|---|")
    for h in manifest.hosts:
        c = host_coverage(h)
        impl = "" if c["implemented"] else " *(arch-ready)*"
        L.append(f"| {c['host_id']} | {c['os_family']} | {c['confidence']} | "
                 f"{c['analyzer']}{impl} | {len(c['parsed'])} | {len(c['wrapper_missing'])} | "
                 f"{len(c['not_present'])} / {c['supported_total']} |")
    L.append("")
    for h in manifest.hosts:
        c = host_coverage(h)
        L.append(f"## {c['host_id']}  ({c['os_family']}, {c['confidence']} confidence)")
        L.append(f"- Analyzer: **{c['analyzer']}**"
                 + ("" if c["implemented"] else "  — architecture-ready, parsing wrappers are the next step"))
        L.append(f"- Basis: {c['reason']}")
        L.append(f"- Capabilities present: {', '.join(c['capabilities']) or '(none detected)'}")
        L.append(f"- **Parsed** ({len(c['parsed'])}): {', '.join(c['parsed']) or '—'}")
        L.append(f"- **Present, wrapper missing** ({len(c['wrapper_missing'])}): "
                 f"{', '.join(c['wrapper_missing']) or '—'}")
        L.append(f"- **Not present** ({len(c['not_present'])} of {c['supported_total']} supported categories) "
                 f"— reported as absent, NOT as 'clean'")
        L.append("")
    return "\n".join(L)

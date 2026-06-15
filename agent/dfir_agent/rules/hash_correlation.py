"""Cross-host hash-correlation rule (family=hash).

The same executable present on multiple hosts BY SHA-256 is a deployment signal:
one binary pushed across the network (lateral tool transfer / mass deployment).

This is identity-agnostic — it keys on "identical content on >=2 hosts in
NON-standard locations", never on a known hash. A copy that lives only in signed
Windows locations is NOT flagged (a shared system DLL across hosts is normal).
Input is the output of the `compare_hashes_across_hosts` tool (groups already
correlated by the server); this rule just turns confirmed cross-host groups into
cited Findings.
"""

from __future__ import annotations

from .benign_allowlist import is_benign_location
from ..state import Confidence, EvidenceReference, Finding


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").split("/")[-1] or path


def _as_dict(group) -> dict:
    return group if isinstance(group, dict) else group.model_dump()


def findings_from_hash_groups(groups, *, id_start: int = 1) -> list[Finding]:
    """Emit one Finding per binary whose sha256 appears on >=2 distinct hosts and
    is not exclusively in signed Windows locations. Each cites the hash provenance."""
    findings: list[Finding] = []
    n = id_start
    for raw in groups or []:
        g = _as_dict(raw)
        sha = g.get("sha256") or ""
        hosts = sorted({h for h in (g.get("hosts") or []) if h})
        paths = [p for p in (g.get("paths") or []) if p]
        prov = [p for p in (g.get("provenance_ids") or []) if p]
        size = g.get("size")
        if not sha or len(hosts) < 2 or not prov:
            continue
        # Anti-FP: a binary that lives ONLY in signed Windows locations is benign.
        if paths and all(is_benign_location(p) for p in paths):
            continue

        name = _basename(paths[0]) if paths else sha[:12]
        evidence = [
            EvidenceReference(
                provenance_id=pid, tool="hash_file", source_family="hash",
                record_id=f"sha256={sha[:16]}",
                note=f"identical sha256 {sha[:16]} present on host(s) {', '.join(hosts)}",
            )
            for pid in prov
        ]
        findings.append(Finding(
            finding_id=f"H-{n:04d}", host_id="cross_host",
            title=f"Same binary on {len(hosts)} hosts: {name} (sha256 {sha[:12]})",
            category="shared_binary", entity_key=f"sha256:{sha}",
            paths=list(dict.fromkeys(paths)),
            description=(
                f"The file '{name}' (sha256 {sha}"
                + (f", {size} bytes" if size else "")
                + f") is byte-identical across {len(hosts)} hosts: {', '.join(hosts)}. "
                "The same non-system executable deployed on multiple hosts is a "
                "lateral tool-transfer / mass-deployment signal. Correlate with the "
                "per-host findings for each copy."
            ),
            confidence=Confidence.likely,
            rule="hash_correlation.shared_binary",
            source_count=len(hosts),
            evidence=evidence,
            tags=["hash", "cross_host", "shared_binary"],
            mitre_mapping=["T1570"],
        ))
        n += 1
    return findings

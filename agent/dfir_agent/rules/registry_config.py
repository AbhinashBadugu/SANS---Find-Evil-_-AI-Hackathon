"""Registry-stored C2 configuration rule (disk, family=registry_config).

A registry value whose data decodes to a URL or IP endpoint is malware
configuration stored for persistence/recall. This keys on the BEHAVIOUR
(network endpoint in a registry value), not on any specific key or filename.
Input is the output of parse_reg_export / extract_c2_from_registry.
"""

from __future__ import annotations

from ..state import Confidence, EvidenceReference, Finding


def _as_dict(e) -> dict:
    return e if isinstance(e, dict) else e.model_dump()


def suspicious_registry_c2(entries, *, host_id: str, provenance_id: str,
                           id_start: int = 1) -> list[Finding]:
    findings: list[Finding] = []
    n = id_start
    for raw in entries or []:
        e = _as_dict(raw)
        urls = e.get("urls") or []
        ips = e.get("ips") or []
        if not urls and not ips:
            continue
        nets = urls + ips
        intervals = e.get("intervals") or []
        key = e.get("key", "")
        name = e.get("value_name", "")
        # A configured network endpoint + a beacon-interval is a stronger signal.
        conf = Confidence.likely if (urls or ips) else Confidence.suspicious
        findings.append(Finding(
            finding_id=f"R-{n:04d}", host_id=host_id,
            title=f"Registry-stored C2 config: {key}\\{name}",
            category="c2_config", entity_key=f"regc2:{key}\\{name}",
            paths=[f"{key}\\{name}"],
            description=(
                f"Registry value {key}\\{name} ({e.get('value_type')}) decodes to network "
                f"endpoint(s) {nets[:6]}"
                + (f" with beacon interval(s) {intervals}" if intervals else "")
                + ". A remote endpoint stored in the registry is malware C2 configuration."
            ),
            confidence=conf, rule="registry_config.c2", source_count=1,
            evidence=[EvidenceReference(
                provenance_id=provenance_id, tool="parse_reg_export",
                artifact_path=e.get("source_file"), source_family="registry_config",
                record_id=f"{key}\\{name}",
                note=f"registry value decodes to {nets[:3]}",
            )],
            tags=["disk", "registry", "c2_config"],
            mitre_mapping=["T1071", "T1112"],
        ))
        n += 1
    return findings

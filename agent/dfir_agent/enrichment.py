"""Config-driven benign / IR enrichment (case profiles).

This is the ONLY place per-engagement knowledge enters detection — and it enters
as DATA, never code. The analyst points the agent at a case-profile directory
(env DFIR_CASE_PROFILE_DIR) holding:

    known_ir_hosts.yml             # IR/acquisition infra (e.g. an examiner host)
    known_admin_tools.yml          # legit admin/3rd-party tools + benign service hints
    known_benign_windows_paths.yml # extra signed/benign path prefixes
    known_case_hosts.yml           # host<->IP topology for this case
    known_case_iocs.yml            # case IOCs (for the validation profile, never core)

Nothing here is universal logic and nothing here is baked into rules. If no
profile dir is set, only conservative GENERIC defaults apply. Suppressions made
via this data are recorded as SELF-CORRECTIONS (the finding is demoted, not
deleted, and keeps its provenance).
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

# Genuinely universal IR tooling (appears across cases) — safe as a code default.
GENERIC_BENIGN_SERVICE_HINTS = ("f-response", "fresponse", "fresdisk")


def profile_dir() -> Path | None:
    d = os.getenv("DFIR_CASE_PROFILE_DIR")
    return Path(d).expanduser() if d else None


def _load(name: str) -> dict:
    d = profile_dir()
    if not d or yaml is None:
        return {}
    p = d / name
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}


def benign_service_hints() -> tuple[str, ...]:
    data = _load("known_admin_tools.yml")
    hints = list(GENERIC_BENIGN_SERVICE_HINTS)
    hints += [str(h).lower() for h in (data.get("benign_service_hints") or [])]
    hints += [str(h).lower() for h in (data.get("admin_tools") or [])]
    return tuple(dict.fromkeys(h for h in hints if h))


def ir_hosts() -> dict[str, str]:
    data = _load("known_ir_hosts.yml")
    return {str(k): str(v) for k, v in (data.get("ir_hosts") or {}).items()}


def is_ir_host(ip_or_name: str | None) -> bool:
    return bool(ip_or_name) and str(ip_or_name) in ir_hosts()


def ir_label(ip_or_name: str | None) -> str | None:
    return ir_hosts().get(str(ip_or_name)) if ip_or_name else None


def benign_path_prefixes() -> list[str]:
    data = _load("known_benign_windows_paths.yml")
    return [str(p).lower() for p in (data.get("benign_paths") or [])]


def case_host_ip_map() -> dict[str, str]:
    """Topology for lateral-hop attribution; both directions (ip<->host)."""
    data = _load("known_case_hosts.yml")
    out: dict[str, str] = {}
    for host, ip in (data.get("hosts") or {}).items():
        out[str(ip)] = str(host)
        out[str(host)] = str(ip)
    return out


def _finding_text(f) -> str:
    bits = [getattr(f, "description", ""), " ".join(getattr(f, "paths", []) or [])]
    for e in getattr(f, "evidence", []) or []:
        bits.append(getattr(e, "note", "") or "")
    return " ".join(bits).lower()


def enrich_findings(findings):
    """Apply IR/benign enrichment as SELF-CORRECTIONS. A finding that rests solely
    on IR/acquisition infrastructure, or on a known-benign path, is DEMOTED to
    false_positive (kept, not deleted; provenance retained) and tagged
    'self_correction'. Returns (findings, corrections) where corrections is a list
    of {finding_id, reason}."""
    from .state import Confidence  # local import to avoid cycles

    irs = ir_hosts()
    benign = benign_path_prefixes()
    corrections = []
    for f in findings or []:
        text = _finding_text(f)
        hit_ir = next((f"{ip} ({lbl})" for ip, lbl in irs.items() if ip.lower() in text), None)
        hit_benign = next((p for p in benign if p in text), None)
        if not hit_ir and not hit_benign:
            continue
        reason = (f"source is IR/acquisition infra {hit_ir}" if hit_ir
                  else f"path is known-benign ({hit_benign})")
        if f.confidence in (Confidence.confirmed, Confidence.likely, Confidence.suspicious):
            f.confidence = Confidence.false_positive
            if "self_correction" not in f.tags:
                f.tags.append("self_correction")
            f.contradictions.append(f"Self-correction: demoted — {reason}.")
            corrections.append({"finding_id": f.finding_id, "reason": reason})
    return findings, corrections

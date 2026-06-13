"""Bridge: Universal Case Manifest Builder -> the agent's runtime discovery flow.

Used by the orchestrator node to turn an evidence folder into a populated
CaseState (runtime `Host` objects + per-host capabilities) and to pick exactly
one host to analyse — with no hardcoded case paths or host names. Discovery only:
scans metadata, calls no MCP tool and no shell.

Host selection is OS-AGNOSTIC: it never rejects a host as "unsupported". The
matching OS-family analyzer is chosen downstream (see analyzers/); a host whose
analyzer is not implemented yet is *detected and deferred*, not refused.
"""

from __future__ import annotations

from pathlib import Path

from .case_manifest import scan_case_folder
from .state import (
    CaseManifest,
    EvidenceCapability,
    EvidenceType,
    Host,
    HostRole,
    ManifestHost,
    OSFamily,
)

# ManifestHost roles -> runtime roles the analysis nodes/router understand.
# (The router routes the DC identity node off HostRole.dc, so map accordingly.)
_ROLE_MAP = {
    HostRole.domain_controller: HostRole.dc,
    HostRole.server: HostRole.server,
    HostRole.endpoint: HostRole.workstation,
    HostRole.unknown: HostRole.workstation,
}


def _manifest_path(case_root: str | Path, case_id: str) -> Path:
    return Path(case_root) / "cases" / case_id / "case_manifest.json"


def build_or_load_manifest(
    case_root: str | Path, case_id: str, evidence_root: str | Path
) -> tuple[CaseManifest, bool]:
    """Return (manifest, loaded). Load case_manifest.json if it exists, else scan
    the evidence folder and persist one. Never writes into the evidence folder."""
    mp = _manifest_path(case_root, case_id)
    if mp.exists():
        return CaseManifest.model_validate_json(mp.read_text(encoding="utf-8")), True
    manifest = scan_case_folder(Path(evidence_root), case_id=case_id)
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest, False


def _first_path(mh: ManifestHost, etype: EvidenceType) -> str | None:
    paths = sorted(e.evidence_path for e in mh.evidence_files if e.evidence_type == etype)
    return paths[0] if paths else None


def manifest_host_to_runtime(mh: ManifestHost) -> Host:
    """Map a discovered ManifestHost to the runtime Host the nodes consume."""
    return Host(
        host_id=mh.host_id,
        os=mh.os_family.value,
        role=_ROLE_MAP.get(mh.host_role, HostRole.workstation),
        memory_image=_first_path(mh, EvidenceType.memory_image),
        disk_image=_first_path(mh, EvidenceType.disk_image),
    )


def manifest_to_runtime_hosts(manifest: CaseManifest) -> dict[str, Host]:
    return {mh.host_id: manifest_host_to_runtime(mh) for mh in manifest.hosts}


def host_capabilities(manifest: CaseManifest) -> dict[str, EvidenceCapability]:
    return {mh.host_id: mh.evidence_capabilities for mh in manifest.hosts}


def host_os_family(host: Host) -> OSFamily:
    """Map a runtime Host's `os` string to an OSFamily — handles both the universal
    form ('windows') and legacy strings ('Windows XP', 'Windows Server 2008 R2')."""
    s = (getattr(host, "os", None) or "").lower()
    if "windows" in s or s in {"win", "nt"}:
        return OSFamily.windows
    if "linux" in s:
        return OSFamily.linux
    if any(k in s for k in ("mac", "darwin", "osx", "os x")):
        return OSFamily.macos
    if "network" in s or "device" in s:
        return OSFamily.network_device
    return OSFamily.unknown


def select_host(
    manifest: CaseManifest,
    target_host: str | None = None,
    prefer_families: tuple[OSFamily, ...] = (OSFamily.windows,),
) -> tuple[str | None, str]:
    """Pick exactly ONE host to analyse. OS-agnostic — never rejects a host as
    'unsupported'; the matching analyzer is chosen downstream and reports its own
    implementation status.

    Selection PREFERS a host whose OS-family analyzer is implemented (passed via
    `prefer_families`, today just Windows) AND has memory evidence, so real cases
    produce results. Otherwise it falls back to the first host (sorted) of ANY OS,
    so that host's analyzer can report `detected_but_not_implemented`.

    Returns (host_id, reason). host_id is None only if the manifest has no hosts.
    An explicit `target_host` overrides the heuristic.
    """
    by_id = {mh.host_id: mh for mh in manifest.hosts}
    if target_host:
        if target_host in by_id:
            return target_host, f"operator-requested host {target_host!r}"
        return None, f"requested host {target_host!r} not in manifest (have: {sorted(by_id)})"
    if not by_id:
        return None, "no hosts discovered in the case manifest"

    prefer = set(prefer_families)
    preferred = sorted(
        mh.host_id
        for mh in manifest.hosts
        if mh.os_family in prefer and mh.evidence_capabilities.has_memory
    )
    if preferred:
        return preferred[0], (
            "first host (sorted) whose OS-family analyzer is implemented and has memory evidence"
        )
    chosen = sorted(by_id)[0]
    return chosen, "first host (sorted); its OS-family analyzer will report its implementation status"

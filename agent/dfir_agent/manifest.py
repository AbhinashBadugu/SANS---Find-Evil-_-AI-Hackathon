"""Case manifest: host topology + evidence paths.

The orchestrator loads this to know which hosts exist, their OS/role, and where
each host's memory image and disk image live. If the case manifest is empty
(the MCP server seeds it as `{}`), we derive the topology from the provenance
logbook's recorded input paths and persist a real manifest — read-only inference
over data the server already produced, no evidence access.
"""

from __future__ import annotations

import json
from pathlib import Path

from .state import Host, HostRole


def _classify(host_id: str) -> tuple[str, HostRole]:
    h = host_id.lower()
    if "2008" in h or "controller" in h or h.endswith("-dc") or "domaincontroller" in h:
        return "Windows Server 2008 R2", HostRole.dc
    if "xp" in h:
        return "Windows XP", HostRole.workstation
    if "win7" in h or "windows7" in h:
        return "Windows 7", HostRole.workstation
    return "Windows", HostRole.workstation


def _derive_from_provenance(case_root: Path, case_id: str) -> dict[str, Host]:
    prov = case_root / "cases" / case_id / "provenance.jsonl"
    hosts: dict[str, Host] = {}
    if not prov.exists():
        return hosts
    for line in prov.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host_id = rec.get("host_id")
        if not host_id:
            continue
        os_name, role = _classify(host_id)
        host = hosts.setdefault(host_id, Host(host_id=host_id, os=os_name, role=role))
        for p in rec.get("input_paths", []):
            pl = str(p).lower()
            # Skip the deliberate negative-test paths.
            if "does-not-exist" in pl:
                continue
            if pl.endswith(".e01"):
                host.disk_image = host.disk_image or str(p)
            elif pl.endswith(".001") or ("memory" in pl and pl.endswith("raw")):
                host.memory_image = host.memory_image or str(p)
    return hosts


def load_or_build_manifest(case_root: str | Path, case_id: str, persist: bool = True) -> dict[str, Host]:
    case_root = Path(case_root)
    manifest_file = case_root / "cases" / case_id / "manifest.json"

    if manifest_file.exists():
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            data = {}
        hosts_data = data.get("hosts") if isinstance(data, dict) else None
        if hosts_data:
            return {hid: Host(**h) for hid, h in hosts_data.items()}

    hosts = _derive_from_provenance(case_root, case_id)
    if persist and hosts:
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        manifest_file.write_text(
            json.dumps(
                {"case_id": case_id, "hosts": {hid: h.model_dump() for hid, h in hosts.items()}},
                indent=2,
            ),
            encoding="utf-8",
        )
    return hosts

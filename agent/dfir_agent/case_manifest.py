"""Universal Case Manifest Builder — case-agnostic evidence discovery.

Scans ANY case folder and produces a `CaseManifest` without assuming SRL-2015
host names, fixed paths, or Windows-only evidence. It works on filesystem
METADATA only (path, name, size); it never reads evidence content, never hashes
(that is the MCP `hash_evidence` tool's job), never runs a forensic tool, and
never calls a shell. `sha256` is therefore always None at this stage.

Pipeline:  scan_case_folder -> classify each file -> infer OS/role -> group by
host -> build capabilities -> CaseManifest.

Honesty rules:
  * Ambiguous image extensions (.raw/.dd/.001) are LOW confidence with an explicit
    reason, never silently asserted as disk vs memory.
  * `host_role` is only `domain_controller` (proven by NTDS.dit/SYSVOL) or
    `unknown` — no name-based role guessing.
  * Files we cannot classify go to `unassigned_evidence`, they do not crash the scan.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from pathlib import Path

from .capability_matrix import is_reference_material
from .state import (
    CaseManifest,
    EvidenceCapability,
    EvidenceFile,
    EvidenceType,
    HostRole,
    ManifestHost,
    OSFamily,
)

# --------------------------------------------------------------------------- #
# Detection tables
# --------------------------------------------------------------------------- #
_DISK_EXTS = {".e01", ".ex01", ".s01", ".dd", ".img", ".qcow2", ".vmdk", ".vhd", ".vhdx", ".dmg", ".aff", ".aff4"}
_MEM_EXTS = {".mem", ".vmem", ".lime", ".dmp", ".core"}
_AMBIGUOUS_EXTS = {".raw", ".001", ".bin"}  # could be a split disk OR a memory dump
_MEM_TOKENS = ("memory", "memdump", "ramdump", "-ram", "_ram", "vmem", "lime", "-mem", "_mem", "pagefile", "hiberfil")
_DISK_TOKENS = ("c-drive", "cdrive", "c_drive", "-drive", "disk", "hdd", "harddisk")

_REGISTRY_HIVES = {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "default", "components"}
_LINUX_LOG_NAMES = {"auth.log", "syslog", "messages", "secure", "kern.log", "wtmp", "btmp", "lastlog", "faillog"}
_NETWORK_LOG_HINTS = ("auth.log", "secure", "sshd", "wtmp", "btmp", "vpn", "firewall", "access.log")

_GENERIC_FOLDER_WORDS = {"images", "image", "evidence", "disk", "memory", "mem", "raw", "data", "files", "exports", "cases"}


def _evidence_id(path: Path) -> str:
    """Stable, deterministic id per path (independent of scan order / hash seed)."""
    return "ev-" + hashlib.sha1(str(path).encode("utf-8", "replace")).hexdigest()[:10]


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


# --------------------------------------------------------------------------- #
# Per-file classification
# --------------------------------------------------------------------------- #
def _classify_type(path: Path) -> tuple[EvidenceType, str, str]:
    """Return (evidence_type, confidence, reason). Specific artifacts beat images.
    Reference-material exclusion is applied root-aware in scan_case_folder."""
    name = path.name
    low = name.lower()
    ext = path.suffix.lower()
    parts = [p.lower() for p in path.parts]

    # --- Windows artifacts (most specific first) ---
    if low in ("$mft", "mft") or ext == ".mft":
        return EvidenceType.mft, "high", "filename is the NTFS $MFT"
    if low == "amcache.hve":
        return EvidenceType.amcache, "high", "Amcache.hve (program execution registry)"
    if low == "ntds.dit":
        return EvidenceType.registry_hive, "high", "NTDS.dit (Active Directory database — domain controller)"
    if low in _REGISTRY_HIVES or ext == ".hve":
        extra = " — also the Shimcache (AppCompatCache) source" if low == "system" else ""
        return EvidenceType.registry_hive, "high", f"Windows registry hive '{name}'{extra}"
    if ext == ".pf" or "prefetch" in parts:
        return EvidenceType.prefetch, "high", "Windows Prefetch (.pf / Prefetch dir)"
    if ext == ".evtx":
        return EvidenceType.event_log, "high", "Windows event log (.evtx)"
    if ext == ".evt":
        return EvidenceType.event_log, "medium", "legacy Windows event log (.evt)"

    # --- Timeline / Plaso ---
    if ext == ".plaso":
        return EvidenceType.timeline, "high", "Plaso storage file (.plaso)"
    if "supertimeline" in low or "timeline" in low or low.endswith(".body") or "bodyfile" in low:
        return EvidenceType.timeline, "medium", "timeline/bodyfile artifact"

    # --- macOS artifacts (before generic plist/linux) ---
    if low == "systemversion.plist":
        return EvidenceType.macos_log, "high", "SystemVersion.plist (macOS OS identity)"
    if ext == ".tracev3":
        return EvidenceType.macos_log, "high", "macOS Unified Log (.tracev3)"
    if "launchagents" in parts or "launchdaemons" in parts:
        return EvidenceType.macos_log, "high", "macOS LaunchAgents/LaunchDaemons (persistence)"
    if low == "system.log":
        return EvidenceType.macos_log, "high", "macOS /var/log/system.log"
    if low.endswith("zsh_history"):
        return EvidenceType.macos_log, "medium", "zsh history (macOS default shell)"
    if ext == ".plist":
        return EvidenceType.macos_log, "medium", "macOS property list (.plist)"

    # --- Linux artifacts ---
    if low == "os-release" or "os-release" in parts:
        return EvidenceType.linux_log, "high", "/etc/os-release (Linux OS identity)"
    if low in _LINUX_LOG_NAMES or low.startswith("auth.log") or low.startswith("syslog"):
        return EvidenceType.linux_log, "high", f"Linux log '{name}'"
    if ext == ".journal":
        return EvidenceType.linux_log, "medium", "systemd journal file"
    if ext == ".service":
        return EvidenceType.linux_log, "medium", "systemd service unit"
    if "cron" in low or "crontab" in low:
        return EvidenceType.linux_log, "medium", "cron schedule"
    if low.endswith("bash_history"):
        return EvidenceType.linux_log, "medium", "bash history"
    if "sshd" in low:
        return EvidenceType.linux_log, "medium", "SSH daemon log"

    # --- Images (after named artifacts) ---
    if ext in _DISK_EXTS:
        return EvidenceType.disk_image, "high", f"disk image ({ext})"
    if ext in _MEM_EXTS:
        return EvidenceType.memory_image, "high", f"memory image ({ext})"
    if ext in _AMBIGUOUS_EXTS:
        if any(t in low for t in _MEM_TOKENS):
            return EvidenceType.memory_image, "medium", f"ambiguous {ext}; memory token in name"
        if any(t in low for t in _DISK_TOKENS):
            return EvidenceType.disk_image, "medium", f"ambiguous {ext}; disk token in name"
        return EvidenceType.disk_image, "low", f"ambiguous {ext}; defaulted to disk (no disk/memory token)"

    return EvidenceType.unknown, "low", "unrecognized evidence type"


def classify_evidence_file(path: Path) -> EvidenceFile:
    """Classify ONE file into an EvidenceFile (metadata only; host_id set later)."""
    etype, conf, reason = _classify_type(path)
    return EvidenceFile(
        evidence_id=_evidence_id(path),
        host_id=None,
        evidence_path=str(path),
        evidence_type=etype,
        file_size=_size(path),
        sha256=None,
        classification_confidence=conf,
        classification_reason=reason,
    )


# --------------------------------------------------------------------------- #
# OS family + role inference (per file)
# --------------------------------------------------------------------------- #
def infer_os_family(path: Path, filename: str) -> OSFamily:
    low = filename.lower()
    ext = Path(filename).suffix.lower()
    parts = [p.lower() for p in path.parts]

    if (ext in {".evtx", ".evt", ".pf", ".lnk"}
            or low in _REGISTRY_HIVES or low in {"amcache.hve", "$mft", "ntds.dit", "pagefile.sys", "ntuser.dat", "usrclass.dat"}
            or "prefetch" in parts):
        return OSFamily.windows
    if (low == "systemversion.plist" or ext in {".tracev3", ".plist", ".dmg"}
            or "launchagents" in parts or "launchdaemons" in parts
            or low == "system.log" or low.endswith("zsh_history")):
        return OSFamily.macos
    if (low == "os-release" or low in _LINUX_LOG_NAMES or ext in {".journal", ".service", ".qcow2", ".lime"}
            or low.endswith("bash_history") or "cron" in low or "sshd" in low):
        return OSFamily.linux
    # Network-device evidence: logs/config/traffic, never host C:/RAM. Strong
    # indicators only (generic 'dns'/'log' stay ambiguous and don't trigger this).
    if (ext in {".pcap", ".pcapng", ".cap", ".cfg", ".nfcapd"}
            or any(k in low for k in ("firewall", "fortigate", "paloalto", "pfsense", "router", "switch",
                                      "vpn", "anyconnect", "openvpn", "proxy", "squid", "snort", "suricata",
                                      "zeek", "netflow", "dhcp", "tacacs", "radius"))
            or "running-config" in low or "startup-config" in low):
        return OSFamily.network_device
    return OSFamily.unknown  # bare disk/memory image → OS not provable from the name


def infer_host_role(path: Path, filename: str) -> HostRole:
    low = filename.lower()
    parts = [p.lower() for p in path.parts]
    if low == "ntds.dit" or "ntds" in low or "sysvol" in parts:
        return HostRole.domain_controller  # AD database / SYSVOL — a domain controller
    return HostRole.unknown  # do NOT guess server vs endpoint from a name


# --------------------------------------------------------------------------- #
# Capabilities + grouping
# --------------------------------------------------------------------------- #
def build_capabilities(evidence_files: list[EvidenceFile]) -> EvidenceCapability:
    """Delegate to the full Evidence Capability Matrix (all artifact categories)."""
    from .capability_matrix import build_capabilities as _build_full

    return _build_full(evidence_files)


def _looks_like_hostname(folder: str) -> bool:
    f = folder.strip().lower()
    return bool(re.search(r"[a-z]", f)) and f not in _GENERIC_FOLDER_WORDS


def _host_token(filename: str) -> str:
    """Best-effort host token from a loose filename (strip type/IP/index tokens)."""
    name = Path(filename).stem.lower()
    name = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "", name)  # strip IPv4
    for tok in ("c-drive", "cdrive", "memory", "mem", "raw", "image", "disk", "dump", "-001"):
        name = name.replace(tok, "")
    name = re.sub(r"[-_.]+", "-", name).strip("-")
    return name or "host"


# OS hints carried in disk/memory image names + host folder names (a WEAK signal).
_WIN_NAME_HINTS = ("windows", "win7", "win8", "win10", "win11", "win2008", "win2012",
                   "win2016", "win2019", "winserver", "winxp", "ntuser", "c-drive")
_LINUX_NAME_HINTS = ("ubuntu", "debian", "centos", "rhel", "fedora", "redhat", "linux")
_MAC_NAME_HINTS = ("macos", "osx", "os-x", "darwin", "mac-")


def _weak_os_signal(path: Path) -> OSFamily:
    """OS inferred from disk/memory image naming or host-folder naming (weaker than a
    parsed artifact). Returns unknown if no naming hint is present."""
    blob = str(path).lower()
    if any(h in blob for h in _WIN_NAME_HINTS) or re.search(r"(^|[-_/])xp([-_/.]|$)", blob):
        return OSFamily.windows
    if any(h in blob for h in _LINUX_NAME_HINTS):
        return OSFamily.linux
    if any(h in blob for h in _MAC_NAME_HINTS):
        return OSFamily.macos
    return OSFamily.unknown


def _os_signal(path: Path) -> tuple[OSFamily, str]:
    """(family, strength). strong = a parsed/loose OS artifact; weak = image/folder naming.
    Reference files are filtered by the caller (_aggregate_os) via ev.is_reference."""
    strong = infer_os_family(path, path.name)
    if strong != OSFamily.unknown:
        return strong, "strong"
    weak = _weak_os_signal(path)
    if weak != OSFamily.unknown:
        return weak, "weak"
    return OSFamily.unknown, ""


def _aggregate_os(evidence_files: list[EvidenceFile]) -> tuple[OSFamily, str, str]:
    """Return (os_family, confidence, basis). Strong artifact signals -> high; only
    image/folder naming -> medium; nothing -> unknown/low."""
    strong: Counter = Counter()
    weak: Counter = Counter()
    for ev in evidence_files:
        if getattr(ev, "is_reference", False):
            continue
        fam, strength = _os_signal(Path(ev.evidence_path))
        if strength == "strong":
            strong[fam] += 1
        elif strength == "weak":
            weak[fam] += 1
    if strong:
        return strong.most_common(1)[0][0], "high", "extracted/loose OS artifact (registry/evtx/MFT/log)"
    if weak:
        return weak.most_common(1)[0][0], "medium", "Windows-style disk/memory image + host-folder naming"
    return OSFamily.unknown, "low", "no OS signal (artifacts sealed inside the image)"


def _aggregate_role(evidence_files: list[EvidenceFile]) -> HostRole:
    for ev in evidence_files:
        if infer_host_role(Path(ev.evidence_path), Path(ev.evidence_path).name) == HostRole.domain_controller:
            return HostRole.domain_controller
    return HostRole.unknown


def _make_host(host_id: str, hostname: str | None, evs: list[EvidenceFile], reason_prefix: str) -> ManifestHost:
    for ev in evs:
        ev.host_id = host_id
    os_family, conf, basis = _aggregate_os(evs)
    role = _aggregate_role(evs)
    reason = (f"{reason_prefix}; os_family={os_family.value} ({conf}) — {basis}; "
              f"{len(evs)} evidence file(s)")
    return ManifestHost(
        host_id=host_id, hostname=hostname, os_family=os_family, host_role=role,
        evidence_files=evs, evidence_capabilities=build_capabilities(evs),
        classification_confidence=conf, classification_reason=reason,
    )


def group_evidence_by_host(
    evidence_files: list[EvidenceFile], case_root: Path
) -> tuple[list[ManifestHost], list[EvidenceFile]]:
    """Group evidence into hosts. A top-level folder under case_root IS a host, and
    ALL its files belong to it (so the capability matrix sees every artifact, even
    ones whose fine-grained type is 'unknown'). Returns (hosts, unassigned).

    Only files loose AT THE CASE ROOT (no host folder) AND of unknown type are
    unassigned; loose recognized files get synthetic host IDs."""
    case_root = Path(case_root).resolve()

    foldered: dict[str, list[EvidenceFile]] = {}
    loose_recognized: list[EvidenceFile] = []
    unassigned: list[EvidenceFile] = []
    for ev in evidence_files:
        try:
            rel = Path(ev.evidence_path).resolve().relative_to(case_root)
        except ValueError:
            rel = Path(Path(ev.evidence_path).name)
        if len(rel.parts) > 1:
            foldered.setdefault(rel.parts[0], []).append(ev)  # folder = host (all files)
        elif ev.evidence_type != EvidenceType.unknown:
            loose_recognized.append(ev)
        else:
            unassigned.append(ev)

    hosts: list[ManifestHost] = []
    for folder in sorted(foldered):
        host_id = re.sub(r"\s+", "-", folder.strip()) or folder
        hostname = folder if _looks_like_hostname(folder) else None
        hosts.append(_make_host(host_id, hostname, foldered[folder], f"grouped by folder '{folder}'"))

    # Loose recognized files (no host folder): synthetic host IDs by filename token.
    if loose_recognized:
        loose = loose_recognized
        by_token: dict[str, list[EvidenceFile]] = {}
        for ev in loose:
            by_token.setdefault(_host_token(Path(ev.evidence_path).name), []).append(ev)
        for i, token in enumerate(sorted(by_token), start=1):
            host_id = f"host{i:03d}"
            hosts.append(_make_host(host_id, None, by_token[token],
                                    f"no host folder; synthetic id (filename token '{token}')"))

    return hosts, unassigned


# --------------------------------------------------------------------------- #
# Top-level scan
# --------------------------------------------------------------------------- #
def scan_case_folder(case_root: Path, case_id: str | None = None) -> CaseManifest:
    """Walk a case folder (metadata only) and build a universal CaseManifest."""
    case_root = Path(case_root).expanduser().resolve()
    if not case_root.is_dir():
        raise NotADirectoryError(f"case_root is not a directory: {case_root}")

    paths: list[Path] = []
    for root, _dirs, files in os.walk(case_root):
        for fname in files:
            paths.append(Path(root) / fname)

    evidence = []
    for p in sorted(paths, key=str):
        ev = classify_evidence_file(p)
        # Reference exclusion is judged on the path RELATIVE to the evidence root,
        # so tokens in parent directories above the case never false-positive.
        if is_reference_material(p, root=case_root):
            ev.is_reference = True
            ev.evidence_type = EvidenceType.generic_log
            ev.classification_confidence = "low"
            ev.classification_reason = "course/reference/tutorial/baseline material — NOT host forensic evidence"
        evidence.append(ev)
    hosts, unassigned = group_evidence_by_host(evidence, case_root)

    return CaseManifest(
        case_id=case_id or case_root.name,
        case_root=str(case_root),
        hosts=hosts,
        unassigned_evidence=unassigned,
    )

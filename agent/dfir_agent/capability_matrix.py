"""Evidence Capability Matrix — map discovered evidence files to capability flags.

Metadata-only (path/name/extension), no content reads, no tools. A flag means the
artifact is PRESENT in the case; whether a wrapper can parse it is a separate axis
handled by the analyzers (ArtifactResult.status). Absence of a flag is reported
as 'not present', never as 'clean'.
"""

from __future__ import annotations

from pathlib import Path

from .state import EvidenceCapability

_DISK_EXTS = {".e01", ".ex01", ".dd", ".img", ".raw", ".qcow2", ".vmdk", ".vhd", ".vhdx", ".dmg", ".aff", ".aff4"}
_MEM_EXTS = {".mem", ".vmem", ".lime", ".dmp", ".core"}
_REG_HIVES = {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "default", "components"}
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

# Course / tutorial / reference / baseline material bundled with case exports — these
# are NOT host forensic evidence and must never set a capability flag or an OS signal.
_REFERENCE_TOKENS = ("template", "howto", "how-to", "baseline", "precooked",
                     "workbook", "poster", "cheat", "reference", "tutorial")
# Filename tokens that mean "this file IS a memory image".
_MEM_NAME_TOKENS = ("memory-raw", "memdump", "ramdump", "-memory", "_memory", "memory.",
                    "vmem", "lime", "-mem.", "_mem.", "memimage")
# Filename tokens that mean "this file IS a disk image".
_DISK_NAME_TOKENS = ("c-drive", "cdrive", "c_drive", "diskimage", "disk-image",
                     "drive-image", "harddisk", "-disk.", "hdd")


def is_reference_material(path: Path, root: Path | None = None) -> bool:
    """True for course/tutorial/baseline/reference files. When `root` is given the
    check is made on the path RELATIVE to the evidence root, so incidental tokens in
    parent directories (e.g. a temp dir) never cause a false positive."""
    p = path
    if root is not None:
        try:
            p = Path(path).resolve().relative_to(Path(root).resolve())
        except (ValueError, OSError):
            p = path
    blob = str(p).lower()
    return any(t in blob for t in _REFERENCE_TOKENS)


def _is_memory_name(low: str) -> bool:
    return any(t in low for t in _MEM_NAME_TOKENS) or low.endswith("-memory") or low.endswith("memory.001")


def _is_disk_name(low: str) -> bool:
    return any(t in low for t in _DISK_NAME_TOKENS)


def _flags_for(path: Path) -> set[str]:
    """Return the capability attribute names a single file should switch on."""
    low = path.name.lower()
    ext = path.suffix.lower()
    parts = {p.lower() for p in path.parts}
    f: set[str] = set()

    def add(*names: str) -> None:
        f.update(names)

    # ---------------- Windows ----------------
    if low in ("$mft", "mft") or ext == ".mft":
        add("has_mft", "has_windows_disk")
    if low in ("$usnjrnl", "$j") or "usnjrnl" in low or "$extend" in parts:
        add("has_usn_journal")
    if low == "$logfile":
        add("has_logfile")
    if low in _REG_HIVES or ext == ".hve":
        add("has_registry")
        if low == "system":
            add("has_shimcache", "has_bam_dam", "has_services")
        if low in ("ntuser.dat", "usrclass.dat"):
            add("has_userassist", "has_shellbags", "has_recentdocs")
    if low == "amcache.hve":
        add("has_amcache")
    if ext == ".evtx" or ext == ".evt":
        add("has_event_logs")
        if "powershell" in low:
            add("has_powershell_logs")
        if "defender" in low or "windows defender" in low or "sense" in low:
            add("has_defender_av_edr_logs")
        if "terminalservices" in low or "remotedesktop" in low or "rdp" in low:
            add("has_rdp_artifacts")
        if "smbclient" in low or "smbserver" in low:
            add("has_smb_artifacts")
        if "wmi-activity" in low or "wmi" in low:
            add("has_wmi_artifacts")
        if "bits-client" in low or "bits" in low:
            add("has_bits_artifacts")
        if "firewall" in low:
            add("has_host_network_artifacts", "has_network_logs")
    if ext == ".pf" or "prefetch" in parts:
        add("has_prefetch")
    if "userassist" in low:
        add("has_userassist")
    if ext == ".lnk":
        add("has_lnk")
    if ext in (".automaticdestinations-ms", ".customdestinations-ms") or "jumplist" in low:
        add("has_jumplists")
    if "$recycle.bin" in parts or "recycler" in parts or low.startswith("$i") or low.startswith("$r"):
        add("has_recycle_bin")
    if low in ("webcachev01.dat", "index.dat") or low == "places.sqlite" or (
        "history" in low and any(b in low for b in ("chrome", "edge", "firefox", "webcache"))) or low == "history":
        add("has_browser_history", "has_browser_downloads")
    if low == "consolehost_history.txt":
        add("has_powershell_history")
    if ext == ".job" or "taskcache" in low or "tasks" in parts:
        add("has_scheduled_tasks")
    if low in ("srudb.dat",) or "srum" in low:
        add("has_srum")
    if low == "pagefile.sys":
        add("has_pagefile")
    if low == "hiberfil.sys":
        add("has_hiberfil")
    if low in ("memory.dmp",) or ext == ".dmp" or "minidump" in parts:
        add("has_crash_dumps")
    if "objects.data" in low or "wbem" in parts:
        add("has_wmi_artifacts")
    if low.startswith("qmgr"):
        add("has_bits_artifacts")
    if low == "default.rdp" or "terminal server client" in " ".join(parts):
        add("has_rdp_artifacts")
    if "setupapi" in low or "usbstor" in low or "mounteddevices" in low:
        add("has_usb_artifacts")
    if ext == ".msi" or "installer" in parts or "msiexec" in low:
        add("has_installer_artifacts")
    if ext in (".pst", ".ost"):
        add("has_local_email_artifacts")
    if low == "ntds.dit" or "sysvol" in parts or "inetpub" in parts or "iis" in low:
        add("has_windows_server_role_artifacts")
    if "vss" in low or "shadowcopy" in low or "system volume information" in " ".join(parts):
        add("has_vss")
    if low == "hosts" or "pfirewall.log" in low:
        add("has_host_network_artifacts", "has_network_logs")

    # ---------------- Linux ----------------
    if low == "os-release" or "os-release" in parts:
        add("has_linux_os_release")
    if low.startswith("auth.log") or low == "secure":
        add("has_linux_auth_logs", "has_linux_ssh_logs", "has_network_logs")
    if low.startswith("syslog") or low == "messages":
        add("has_linux_syslog")
    if ext == ".journal":
        add("has_linux_journal")
    if low.startswith("audit.log") or "auditd" in low:
        add("has_linux_auditd")
    if low.endswith("bash_history"):
        add("has_linux_shell_history")
    if "cron" in low or "crontab" in low:
        add("has_linux_cron")
    if ext == ".service" or "systemd" in parts:
        add("has_linux_systemd")
    if "dpkg.log" in low or "yum.log" in low or "dnf.log" in low or ("apt" in parts and "history.log" in low):
        add("has_linux_package_logs")
    if low in ("access.log", "error.log") or any(w in parts for w in ("nginx", "apache2", "httpd")):
        add("has_linux_web_logs")
    if any(d in low for d in ("mysql", "mariadb", "postgresql")) and ("log" in low or ext == ".log"):
        add("has_linux_database_logs")
    if "ufw.log" in low or "iptables" in low:
        add("has_linux_network_logs", "has_network_logs")

    # ---------------- macOS ----------------
    if low == "systemversion.plist":
        add("has_macos_systemversion")
    if ext == ".tracev3":
        add("has_macos_unified_logs")
    if ext == ".plist":
        add("has_macos_plists")
    if "launchagents" in parts:
        add("has_macos_launchagents")
    if "launchdaemons" in parts:
        add("has_macos_launchdaemons")
    if low.endswith("zsh_history"):
        add("has_macos_shell_history")
    if low in ("history.db",) or "safari" in parts or "knowledgec.db" in low:
        add("has_macos_browser_history", "has_macos_user_activity")
    if low == "system.log":
        add("has_macos_unified_logs")

    # ---------------- Network device ----------------
    if "firewall" in low or any(v in low for v in ("asa", "fortigate", "paloalto", "pfsense", "checkpoint")):
        add("has_firewall_logs", "has_network_logs", "has_configuration" if "config" in low else "has_firewall_logs")
    if "router" in low:
        add("has_router_logs", "has_network_logs")
    if "switch" in low:
        add("has_switch_logs", "has_network_logs")
    if "vpn" in low or "anyconnect" in low or "openvpn" in low:
        add("has_vpn_logs", "has_network_logs")
    if "proxy" in low or "squid" in low or "bluecoat" in low:
        add("has_proxy_logs", "has_network_logs")
    if "snort" in low or "suricata" in low or low in ("fast.log", "eve.json"):
        add("has_ids_ips_alerts", "has_network_logs")
        if "suricata" in low or low == "eve.json":
            add("has_suricata_alerts")
    if "zeek" in low or "bro" in low or low in ("conn.log", "dns.log", "http.log", "ssl.log"):
        add("has_zeek_logs", "has_network_logs")
    if low.startswith("dns") and ext == ".log" or "dns.log" in low:
        add("has_dns_logs", "has_network_logs")
    if "dhcp" in low:
        add("has_dhcp_logs", "has_network_logs")
    if "netflow" in low or "nfcapd" in low or ext == ".nfcapd":
        add("has_netflow", "has_network_logs")
    if ext in _PCAP_EXTS:
        add("has_pcap", "has_network_logs")
    if "nat" in low and ext == ".log":
        add("has_nat_logs", "has_network_logs")
    if "running-config" in low or "startup-config" in low or ext == ".cfg" or (
            "config" in low and ext in (".txt", ".conf", ".cfg")):
        add("has_device_config", "has_configuration")
    if ("admin" in low and "log" in low) or "tacacs" in low or "radius" in low:
        add("has_admin_login_logs", "has_network_logs")

    # ---------------- common (any family) ----------------
    # Disk image: by extension OR by name (c-drive / diskimage / hdd ...).
    if ext in _DISK_EXTS or _is_disk_name(low):
        add("has_disk")
        if ext == ".qcow2":
            add("has_linux_disk")
    # Memory image: by extension OR by name (memory-raw / memdump / .001 named memory).
    if ext in _MEM_EXTS or _is_memory_name(low) or (ext == ".001" and _is_memory_name(low)):
        add("has_memory")
        if ext == ".lime":
            add("has_linux_memory")
    if ext == ".plaso" or low.endswith(".body") or ("timeline" in low and "template" not in low):
        add("has_timeline")
    return f


def build_capabilities(evidence_files) -> EvidenceCapability:
    """OR the per-file capability flags across a host's evidence into one matrix."""
    caps = EvidenceCapability()
    valid = set(EvidenceCapability.model_fields)
    any_known = False
    for ev in evidence_files:
        if getattr(ev, "is_reference", False):
            continue  # course/reference/baseline material — never a host capability
        for attr in _flags_for(Path(ev.evidence_path)):
            if attr in valid:
                setattr(caps, attr, True)
                any_known = True
    if not any_known and evidence_files:
        caps.has_unknown_evidence = True
    return caps

"""WindowsAnalyzer module responsibilities (declarative).

MODULES names every Windows analysis module from the architecture and the artifact
categories it owns. CAP_MAP ties each artifact to its capability flag; WRAPPED lists
the artifacts a REAL MCP wrapper can parse today (everything else is reported
present_but_wrapper_missing when present).
"""

from __future__ import annotations

from ...state import EvidenceType as E

MODULES: dict[str, list[E]] = {
    "memory": [E.windows_memory_image],
    "filesystem": [E.windows_disk_image, E.windows_mft, E.windows_usn_journal, E.windows_logfile],
    "execution": [E.windows_prefetch, E.windows_amcache, E.windows_shimcache_source,
                  E.windows_userassist, E.windows_bam_dam],
    "registry": [E.windows_registry_hive, E.windows_services],
    "eventlogs": [E.windows_evtx],
    "user_activity": [E.windows_lnk, E.windows_jumplist, E.windows_recentdocs,
                      E.windows_shellbags, E.windows_recycle_bin],
    "browser": [E.windows_browser_history, E.windows_browser_downloads],
    "powershell": [E.windows_powershell_logs, E.windows_powershell_history],
    "persistence": [E.windows_scheduled_tasks, E.windows_services],
    "host_network": [E.windows_srum, E.windows_firewall_logs, E.windows_dns_cache_or_logs,
                     E.windows_rdp_artifacts, E.windows_smb_artifacts],
    "malware_ioc": [],  # cross-cutting (operates over files flagged by other modules)
    "timeline": [E.windows_timeline],
    "vss": [E.windows_vss],
    "pagefile_hibernation": [E.windows_pagefile, E.windows_hiberfil, E.windows_crash_dump],
    "wmi": [E.windows_wmi_artifacts],
    "bits": [E.windows_bits_artifacts],
    "defender_av_edr": [E.windows_defender_logs, E.windows_av_logs, E.windows_edr_logs],
    "rdp": [E.windows_rdp_artifacts],
    "smb_fileshare": [E.windows_smb_artifacts],
    "usb": [E.windows_usb_artifacts],
    "installer": [E.windows_installer_logs],
    "local_email": [E.windows_local_email],
    "server_roles": [E.windows_domain_controller_artifacts, E.windows_file_server_artifacts,
                     E.windows_iis_logs, E.windows_sql_logs],
}

CAP_MAP: dict[E, str] = {
    E.windows_memory_image: "has_memory",
    E.windows_disk_image: "has_disk",
    E.windows_mft: "has_mft",
    E.windows_usn_journal: "has_usn_journal",
    E.windows_logfile: "has_logfile",
    E.windows_registry_hive: "has_registry",
    E.windows_services: "has_services",
    E.windows_prefetch: "has_prefetch",
    E.windows_amcache: "has_amcache",
    E.windows_shimcache_source: "has_shimcache",
    E.windows_userassist: "has_userassist",
    E.windows_bam_dam: "has_bam_dam",
    E.windows_evtx: "has_event_logs",
    E.windows_lnk: "has_lnk",
    E.windows_jumplist: "has_jumplists",
    E.windows_recentdocs: "has_recentdocs",
    E.windows_shellbags: "has_shellbags",
    E.windows_recycle_bin: "has_recycle_bin",
    E.windows_browser_history: "has_browser_history",
    E.windows_browser_downloads: "has_browser_downloads",
    E.windows_powershell_logs: "has_powershell_logs",
    E.windows_powershell_history: "has_powershell_history",
    E.windows_scheduled_tasks: "has_scheduled_tasks",
    E.windows_srum: "has_srum",
    E.windows_firewall_logs: "has_host_network_artifacts",
    E.windows_dns_cache_or_logs: "has_host_network_artifacts",
    E.windows_rdp_artifacts: "has_rdp_artifacts",
    E.windows_smb_artifacts: "has_smb_artifacts",
    E.windows_usb_artifacts: "has_usb_artifacts",
    E.windows_vss: "has_vss",
    E.windows_pagefile: "has_pagefile",
    E.windows_hiberfil: "has_hiberfil",
    E.windows_crash_dump: "has_crash_dumps",
    E.windows_wmi_artifacts: "has_wmi_artifacts",
    E.windows_bits_artifacts: "has_bits_artifacts",
    E.windows_defender_logs: "has_defender_av_edr_logs",
    E.windows_av_logs: "has_defender_av_edr_logs",
    E.windows_edr_logs: "has_defender_av_edr_logs",
    E.windows_installer_logs: "has_installer_artifacts",
    E.windows_local_email: "has_local_email_artifacts",
    E.windows_iis_logs: "has_windows_server_role_artifacts",
    E.windows_sql_logs: "has_windows_server_role_artifacts",
    E.windows_domain_controller_artifacts: "has_windows_server_role_artifacts",
    E.windows_file_server_artifacts: "has_windows_server_role_artifacts",
    E.windows_timeline: "has_timeline",
}

# Artifacts a REAL MCP wrapper parses today (the rest -> present_but_wrapper_missing).
WRAPPED: dict[E, str] = {
    E.windows_memory_image: "run_volatility_plugin",
    E.windows_disk_image: "open_ewf/inspect_disk/extract_artifacts",
    E.windows_mft: "parse_mft",
    E.windows_registry_hive: "parse_registry",
    E.windows_services: "parse_registry",
    E.windows_shimcache_source: "parse_shimcache",
    E.windows_evtx: "parse_evtx",
    E.windows_timeline: "generate_timeline",
}

# Stable, de-duplicated artifact list (sorted by value for determinism).
SUPPORTED: list[E] = sorted({a for arts in MODULES.values() for a in arts}, key=lambda e: e.value)

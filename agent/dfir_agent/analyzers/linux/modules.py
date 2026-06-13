"""LinuxAnalyzer module responsibilities (declarative). No MCP wrappers yet, so
present artifacts report present_but_wrapper_missing; absent ones not_present."""

from __future__ import annotations

from ...state import EvidenceType as E

MODULES: dict[str, list[E]] = {
    "memory": [E.linux_memory_image],
    "filesystem": [E.linux_disk_image, E.linux_os_release],
    "logs": [E.linux_syslog, E.linux_messages_log, E.linux_journal,
             E.linux_package_logs, E.linux_web_logs, E.linux_database_logs],
    "auth": [E.linux_auth_log, E.linux_secure_log, E.linux_auditd_logs],
    "persistence": [E.linux_systemd_services, E.linux_cron],
    "user_activity": [E.linux_bash_history, E.linux_zsh_history, E.linux_user_activity],
    "network": [E.linux_network_logs],
    "services": [E.linux_systemd_services],
    "cron": [E.linux_cron],
    "ssh": [E.linux_ssh_logs],
    "malware_ioc": [],
    "timeline": [E.linux_timeline],
}

CAP_MAP: dict[E, str] = {
    E.linux_memory_image: "has_memory",
    E.linux_disk_image: "has_disk",
    E.linux_os_release: "has_linux_os_release",
    E.linux_auth_log: "has_linux_auth_logs",
    E.linux_secure_log: "has_linux_auth_logs",
    E.linux_syslog: "has_linux_syslog",
    E.linux_messages_log: "has_linux_syslog",
    E.linux_journal: "has_linux_journal",
    E.linux_auditd_logs: "has_linux_auditd",
    E.linux_bash_history: "has_linux_shell_history",
    E.linux_zsh_history: "has_linux_shell_history",
    E.linux_user_activity: "has_linux_shell_history",
    E.linux_cron: "has_linux_cron",
    E.linux_systemd_services: "has_linux_systemd",
    E.linux_ssh_logs: "has_linux_ssh_logs",
    E.linux_package_logs: "has_linux_package_logs",
    E.linux_web_logs: "has_linux_web_logs",
    E.linux_database_logs: "has_linux_database_logs",
    E.linux_network_logs: "has_linux_network_logs",
    E.linux_timeline: "has_timeline",
}

WRAPPED: dict[E, str] = {}  # no Linux MCP wrappers implemented yet

SUPPORTED: list[E] = sorted({a for arts in MODULES.values() for a in arts}, key=lambda e: e.value)

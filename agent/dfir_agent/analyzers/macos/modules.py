"""MacOSAnalyzer module responsibilities (declarative). No MCP wrappers yet."""

from __future__ import annotations

from ...state import EvidenceType as E

MODULES: dict[str, list[E]] = {
    "memory": [E.macos_memory_image],
    "filesystem": [E.macos_disk_image, E.macos_systemversion_plist],
    "unified_logs": [E.macos_unified_logs, E.macos_system_log],
    "plist": [E.macos_plist],
    "persistence": [E.macos_launchagents, E.macos_launchdaemons],
    "user_activity": [E.macos_zsh_history, E.macos_bash_history, E.macos_user_activity],
    "browser": [E.macos_browser_history],
    "network": [E.macos_network_logs],
    "malware_ioc": [],
    "timeline": [E.macos_timeline],
}

CAP_MAP: dict[E, str] = {
    E.macos_memory_image: "has_memory",
    E.macos_disk_image: "has_disk",
    E.macos_systemversion_plist: "has_macos_systemversion",
    E.macos_unified_logs: "has_macos_unified_logs",
    E.macos_system_log: "has_macos_unified_logs",
    E.macos_plist: "has_macos_plists",
    E.macos_launchagents: "has_macos_launchagents",
    E.macos_launchdaemons: "has_macos_launchdaemons",
    E.macos_zsh_history: "has_macos_shell_history",
    E.macos_bash_history: "has_macos_shell_history",
    E.macos_user_activity: "has_macos_user_activity",
    E.macos_browser_history: "has_macos_browser_history",
    E.macos_network_logs: "has_macos_network_logs",
    E.macos_timeline: "has_timeline",
}

WRAPPED: dict[E, str] = {}

SUPPORTED: list[E] = sorted({a for arts in MODULES.values() for a in arts}, key=lambda e: e.value)

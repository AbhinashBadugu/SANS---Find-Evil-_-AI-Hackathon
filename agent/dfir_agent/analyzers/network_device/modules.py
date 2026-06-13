"""NetworkDeviceAnalyzer module responsibilities (declarative).

Network-device forensics differs from host forensics: devices provide logs,
config, and traffic — NOT a C: drive or RAM. The analyzer therefore never expects
host artifacts. No MCP wrappers yet, so present artifacts -> present_but_wrapper_missing.
"""

from __future__ import annotations

from ...state import EvidenceType as E

MODULES: dict[str, list[E]] = {
    "firewall": [E.firewall_logs, E.nat_logs],
    "router": [E.router_logs],
    "switch": [E.switch_logs],
    "vpn": [E.vpn_logs],
    "proxy": [E.proxy_logs],
    "ids_ips": [E.ids_ips_alerts, E.suricata_alerts, E.zeek_logs],
    "dns": [E.dns_logs],
    "dhcp": [E.dhcp_logs],
    "netflow": [E.netflow],
    "pcap": [E.pcap],
    "config": [E.device_config, E.admin_login_logs],
    "timeline": [E.network_timeline],
}

CAP_MAP: dict[E, str] = {
    E.firewall_logs: "has_firewall_logs",
    E.nat_logs: "has_nat_logs",
    E.router_logs: "has_router_logs",
    E.switch_logs: "has_switch_logs",
    E.vpn_logs: "has_vpn_logs",
    E.proxy_logs: "has_proxy_logs",
    E.ids_ips_alerts: "has_ids_ips_alerts",
    E.suricata_alerts: "has_suricata_alerts",
    E.zeek_logs: "has_zeek_logs",
    E.dns_logs: "has_dns_logs",
    E.dhcp_logs: "has_dhcp_logs",
    E.netflow: "has_netflow",
    E.pcap: "has_pcap",
    E.device_config: "has_device_config",
    E.admin_login_logs: "has_admin_login_logs",
    E.network_timeline: "has_timeline",
}

WRAPPED: dict[E, str] = {}

SUPPORTED: list[E] = sorted({a for arts in MODULES.values() for a in arts}, key=lambda e: e.value)

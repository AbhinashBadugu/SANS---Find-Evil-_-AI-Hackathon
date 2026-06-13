"""NetworkDeviceAnalyzer — first-class analyzer for firewall/router/switch/VPN/
proxy/IDS-IPS/DNS/DHCP/NetFlow/PCAP/config evidence. Architecture defined;
parsing wrappers not implemented yet (runs NO tools)."""

from __future__ import annotations

from ...state import OSFamily
from ..base import NotImplementedAnalyzer
from .modules import CAP_MAP, SUPPORTED, WRAPPED


class NetworkDeviceAnalyzer(NotImplementedAnalyzer):
    os_family = OSFamily.network_device
    name = "NetworkDeviceAnalyzer"
    reason = "Network-device analyzer not implemented yet"
    supported_artifacts = SUPPORTED
    CAP_MAP = CAP_MAP
    WRAPPED = WRAPPED

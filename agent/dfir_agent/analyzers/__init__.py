"""OS/device-family analyzer registry (public surface).

select_analyzer(family) returns EXACTLY ONE analyzer scoped to that family.
"""

from __future__ import annotations

from .base import Analyzer
from .linux import LinuxAnalyzer
from .macos import MacOSAnalyzer
from .network_device import NetworkDeviceAnalyzer
from .registry import implemented_families, select_analyzer
from .unknown import UnknownEvidenceHandler
from .windows import WindowsAnalyzer

__all__ = [
    "Analyzer",
    "WindowsAnalyzer",
    "LinuxAnalyzer",
    "MacOSAnalyzer",
    "NetworkDeviceAnalyzer",
    "UnknownEvidenceHandler",
    "select_analyzer",
    "implemented_families",
]

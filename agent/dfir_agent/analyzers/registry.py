"""OS/device-family analyzer registry.

`select_analyzer(family)` returns EXACTLY ONE analyzer. Each analyzer is scoped to
a single evidence family and only drives that family's tools, so cross-family tool
execution is structurally impossible.
"""

from __future__ import annotations

from ..state import OSFamily
from .base import Analyzer
from .linux import LinuxAnalyzer
from .macos import MacOSAnalyzer
from .network_device import NetworkDeviceAnalyzer
from .unknown import UnknownEvidenceHandler
from .windows import WindowsAnalyzer

_REGISTRY: dict[OSFamily, type[Analyzer]] = {
    OSFamily.windows: WindowsAnalyzer,
    OSFamily.linux: LinuxAnalyzer,
    OSFamily.macos: MacOSAnalyzer,
    OSFamily.network_device: NetworkDeviceAnalyzer,
}


def select_analyzer(os_family: OSFamily) -> Analyzer:
    """The single analyzer for this family (unknown -> UnknownEvidenceHandler)."""
    return _REGISTRY.get(os_family, UnknownEvidenceHandler)()


def implemented_families() -> set[OSFamily]:
    """Families whose analyzer is implemented (drives host-selection preference)."""
    return {fam for fam, cls in _REGISTRY.items() if getattr(cls, "implemented", False)}

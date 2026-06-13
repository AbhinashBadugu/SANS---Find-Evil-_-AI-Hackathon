"""MacOSAnalyzer — architecture defined; parsing wrappers not implemented yet."""

from __future__ import annotations

from ...state import OSFamily
from ..base import NotImplementedAnalyzer
from .modules import CAP_MAP, SUPPORTED, WRAPPED


class MacOSAnalyzer(NotImplementedAnalyzer):
    os_family = OSFamily.macos
    name = "MacOSAnalyzer"
    reason = "macOS analyzer not implemented yet"
    supported_artifacts = SUPPORTED
    CAP_MAP = CAP_MAP
    WRAPPED = WRAPPED

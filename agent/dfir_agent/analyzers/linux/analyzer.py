"""LinuxAnalyzer — architecture defined; parsing wrappers not implemented yet.

Detects Linux evidence, reports a full capability/coverage matrix (present
artifacts -> present_but_wrapper_missing), and runs NO tools.
"""

from __future__ import annotations

from ...state import OSFamily
from ..base import NotImplementedAnalyzer
from .modules import CAP_MAP, SUPPORTED, WRAPPED


class LinuxAnalyzer(NotImplementedAnalyzer):
    os_family = OSFamily.linux
    name = "LinuxAnalyzer"
    reason = "Linux analyzer not implemented yet"
    supported_artifacts = SUPPORTED
    CAP_MAP = CAP_MAP
    WRAPPED = WRAPPED

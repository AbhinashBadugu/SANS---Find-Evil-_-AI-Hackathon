"""Anti-false-positive allowlist (playbook §7.3).

A system file in a standard, signed location (e.g. a WinSxS component like
`6.1.7600.16385`) is NOT malware unless an independent strong source contradicts
it. This rule is what kills the baseline's `wceisvista.inf` hallucination, and it
is mandatory once Phase 5 (correlation) lands.

Phase 1 only needs the predicate; the correlation node calls it before promoting
anything to `confirmed`. Kept deliberately conservative: it allowlists *locations*
and *known component versions*, never arbitrary names.
"""

from __future__ import annotations

import re

# Directories whose contents ship with Windows and are signed.
_BENIGN_DIR_PATTERNS = [
    re.compile(r"\\windows\\winsxs\\", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\", re.IGNORECASE),
    re.compile(r"\\windows\\syswow64\\", re.IGNORECASE),
    re.compile(r"\\windows\\servicing\\", re.IGNORECASE),
    re.compile(r"\\program files( \(x86\))?\\", re.IGNORECASE),
]

# A WinSxS-style component version stamp, e.g. 6.1.7600.16385.
_COMPONENT_VERSION = re.compile(r"\b\d+\.\d+\.\d{4,5}\.\d{4,5}\b")


def is_benign_location(path: str | None) -> bool:
    """True if `path` sits in a standard signed Windows location.

    NOTE: this is a *location* test only. A masqueraded binary placed in a
    NON-standard subdir of system32 (e.g. ...\\system32\\dllhost\\svchost.exe)
    is deliberately NOT matched, because `system32\\dllhost\\` is not a shipped
    component directory.
    """
    if not path:
        return False
    p = path.replace("/", "\\")
    # Reject the masquerade trick: a fake subdir under system32 holding a system exe.
    if re.search(r"\\system32\\[^\\]+\\[^\\]+\.exe$", p, re.IGNORECASE):
        # Real first-party exes live directly in system32, not a child folder.
        return False
    return any(pat.search(p) for pat in _BENIGN_DIR_PATTERNS)


def looks_like_signed_component(text: str | None) -> bool:
    return bool(text and _COMPONENT_VERSION.search(text))

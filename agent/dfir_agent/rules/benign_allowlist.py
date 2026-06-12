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


# Common first-party Windows executables. A process whose binary is one of these,
# found only in signed Windows locations, is a legitimate file — its *runtime*
# behaviour may still be suspicious, but the binary itself must not be called
# malware. (This is the discriminator that keeps a hidden cmd.exe shell from being
# mislabeled an implant, and that would kill the baseline's wceisvista.inf-style
# "built-in file = malware" error.)
BENIGN_WINDOWS_BINARIES = {
    "cmd.exe", "conhost.exe", "svchost.exe", "services.exe", "lsass.exe", "lsm.exe",
    "csrss.exe", "winlogon.exe", "wininit.exe", "smss.exe", "explorer.exe",
    "spoolsv.exe", "taskhost.exe", "taskmgr.exe", "rundll32.exe", "regsvr32.exe",
    "dllhost.exe", "notepad.exe", "regedit.exe", "mmc.exe", "userinit.exe",
    "wmiprvse.exe", "alg.exe", "wuauclt.exe", "ctfmon.exe", "logonui.exe",
    "net.exe", "net1.exe", "ipconfig.exe", "ping.exe", "cscript.exe", "wscript.exe",
}


def is_benign_windows_binary(filename: str | None) -> bool:
    return bool(filename) and filename.strip().lower() in BENIGN_WINDOWS_BINARIES

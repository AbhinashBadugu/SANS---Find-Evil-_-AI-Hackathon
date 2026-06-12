"""Windows path normalization shared by the process/service rules.

Windows refers to the same file many ways: `\\SystemRoot\\System32\\smss.exe`,
`\\??\\C:\\WINDOWS\\system32\\winlogon.exe`, `%SystemRoot%\\system32\\...`. A rule
that compares raw strings to `c:\\windows\\system32` would false-positive on every
one of these legitimate forms. Normalize first, then compare.
"""

from __future__ import annotations

SYSTEM32 = r"c:\windows\system32"
WINDIR = r"c:\windows"


def normalize_winpath(path: str | None) -> str | None:
    if not path:
        return None
    p = path.strip().strip('"').replace("/", "\\").lower()
    if not p:
        return None
    if p.startswith("\\??\\"):
        p = p[4:]
    if p.startswith("\\systemroot\\"):
        p = WINDIR + p[len("\\systemroot"):]
    p = p.replace("%systemroot%", WINDIR).replace("%windir%", WINDIR)
    # Collapse an accidental double backslash from the substitutions above.
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    return p


def split_dir_base(path: str | None) -> tuple[str | None, str | None]:
    """Return (directory, basename) of a normalized path, or (None, base) when
    the path carries no directory (a bare image name we must NOT judge)."""
    norm = normalize_winpath(path)
    if not norm:
        return None, None
    if "\\" not in norm:
        return None, norm  # bare name -> directory unknown
    directory, base = norm.rsplit("\\", 1)
    return directory, base

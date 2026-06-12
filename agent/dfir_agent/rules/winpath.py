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
    if p.startswith(".\\"):  # MFT ParentPath form: ".\WINDOWS\system32\..."
        p = p[2:]
    if p.startswith("\\systemroot\\"):
        p = WINDIR + p[len("\\systemroot"):]
    p = p.replace("%systemroot%", WINDIR).replace("%windir%", WINDIR)
    # A volume-relative path with no drive letter -> assume the system drive C:.
    if p.startswith("\\") and not p.startswith("\\\\"):
        p = "c:" + p
    elif p.startswith("windows\\") or p.startswith("winnt\\") or p.startswith("program files"):
        p = "c:\\" + p
    # Collapse an accidental double backslash from the substitutions above.
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    return p


def mft_full_path(parent_path: str | None, file_name: str | None) -> str | None:
    """Build a normalized full path from an MFT row's ParentPath + FileName."""
    if not file_name:
        return None
    parent = (parent_path or "").strip()
    joined = f"{parent}\\{file_name}" if parent else file_name
    return normalize_winpath(joined)


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

"""Multi-profile temp-dropper rule (disk, family=disk_mft).

A single installer landing in one user's Temp is unremarkable. The SAME executable
dropped into *several different users'* Temp directories is not — that is a payload
being pushed across profiles (mass deployment, often via a stolen domain-admin
account). This rule groups Temp-resident .exe files by name and flags any name that
appears in >=2 distinct user profiles. On SRL-2015 this surfaces exactly `a.exe`
(the httppump dropper) across tdungan/RSydow/vibranium/SRL-Helpdesk — and nothing
else, because no benign installer is named identically across multiple profiles.
"""

from __future__ import annotations

import csv
import re
import sys
from collections import defaultdict

from ..state import Confidence, EvidenceReference, Finding
from .winpath import mft_full_path, normalize_winpath

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

# A user Temp directory (XP "Local Settings\Temp", Win7 "AppData\Local\Temp") or
# the machine Temp. The capture pulls the owning profile when present.
_USER_TEMP = re.compile(
    r"(?:documents and settings|users)\\([^\\]+)\\(?:local settings|appdata\\local)\\temp", re.I)
_WIN_TEMP = re.compile(r"\\windows\\temp", re.I)
# Names that are legitimately identical across profiles (per-user installers/updaters
# and signed setup engines that each user's install spawns into their own Temp).
_BENIGN_NAME = re.compile(r"(setup|instal|unins|update|vcredist|vc_redist|redist|"
                          r"googleupdate|gupdate|flashplayer|jre-|jdk-|"
                          r"isbew|issetup|ismanifest|msiexec|wextract|ixp)", re.I)


def detect_multiuser_temp_droppers(
    mft_csv: str, *, host_id: str, provenance_id: str, next_id, cap: int = 10
) -> list[Finding]:
    from pathlib import Path
    p = Path(mft_csv)
    if not p.exists():
        return []

    # name -> {profile -> full_path, entry}
    by_name: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            fname = (row.get("FileName") or "").strip()
            if not fname.lower().endswith(".exe"):
                continue
            parent = row.get("ParentPath") or ""
            m = _USER_TEMP.search(parent)
            profile = m.group(1).lower() if m else ("__machine_temp__" if _WIN_TEMP.search(parent) else None)
            if profile is None:
                continue
            full = mft_full_path(parent, fname) or normalize_winpath(parent + "\\" + fname)
            by_name[fname.lower()].setdefault(profile, (full, row.get("EntryNumber", "?")))

    findings: list[Finding] = []
    for name, profiles in by_name.items():
        if len(profiles) < 2 or _BENIGN_NAME.search(name):
            continue
        # require at least one real user profile (not only the machine temp)
        user_profiles = [pr for pr in profiles if pr != "__machine_temp__"]
        if not user_profiles:
            continue
        paths = sorted({fp for fp, _e in profiles.values()})
        entry = next(iter(profiles.values()))[1]
        pretty = sorted(pr for pr in profiles if pr != "__machine_temp__") + \
            (["Windows\\Temp"] if "__machine_temp__" in profiles else [])
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"Multi-profile temp dropper: {name} (in {len(profiles)} temp locations)",
            category="dropped_file", entity_key=f"dropper:{name}", paths=paths,
            description=(
                f"'{name}' was dropped into {len(profiles)} distinct Temp locations "
                f"({', '.join(pretty)}). The same executable staged across multiple user "
                f"profiles is a deployment dropper — consistent with an implant pushed across "
                f"accounts (e.g. via a stolen domain-admin token). Recommend hashing and triage."
            ),
            confidence=Confidence.likely, rule="dropper.multiuser_temp", source_count=1,
            evidence=[EvidenceReference(
                provenance_id=provenance_id, record_id=f"MFT#{entry}", tool="parse_mft",
                artifact_path=mft_csv, source_family="disk_mft",
                note=f"$MFT: {name} present in {len(profiles)} temp dirs ({', '.join(pretty)}) — multi-profile dropper",
            )],
            tags=["disk", "mft", "dropper"],
        ))
        if len(findings) >= cap:
            break
    return findings

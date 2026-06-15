"""Static-binary indicator rules (disk, family=pe_static).

Turns the read-only static-triage tools (extract_pe_metadata / detect_pyinstaller /
extract_embedded_urls / extract_pdb_paths) into cited Findings. Every detector is
BEHAVIOURAL — packing, imported capabilities, embedded network indicators,
masquerade path — never a known hash or filename. Location context (signed vs
non-standard) gates confidence to avoid flagging legitimate signed binaries.
"""

from __future__ import annotations

import re

from .benign_allowlist import is_benign_location
from ..state import Confidence, EvidenceReference, Finding

# A system executable living in a fake child dir of system32 — the masquerade trick.
_MASQUERADE = re.compile(r"\\system32\\[^\\]+\\[^\\]+\.exe$", re.IGNORECASE)
_WININET = ("internetopen", "httpsendrequest", "internetconnect", "internetreadfile")
_INJECTION = ("virtualallocex", "writeprocessmemory", "createremotethread",
              "ntmapviewofsection", "queueuserapc", "setthreadcontext")
_CREDDUMP = ("minidumpwritedump", "lsaretrieveprivatedata", "samiconnect")
# A PDB path that points at a personal/build tree rather than a Microsoft symbol path.
_MS_PDB = re.compile(r"(symbols|microsoft|windows|\\winsxs\\)", re.IGNORECASE)


def _has(imports: list[str], needles) -> list[str]:
    low = [i.lower() for i in imports]
    return [i for i in imports if any(nd in i.lower() for nd in needles)]


def pe_indicator_findings(*, host_id: str, file_path: str, pe: dict | None = None,
                          pyinstaller: dict | None = None, embedded: dict | None = None,
                          pdb: dict | None = None, id_start: int = 1) -> list[Finding]:
    findings: list[Finding] = []
    n = id_start
    masquerade = bool(_MASQUERADE.search((file_path or "").replace("/", "\\")))
    benign_loc = is_benign_location(file_path)

    def emit(prov, title, category, desc, conf, tags, mitre, tool, record=None):
        nonlocal n
        if not prov:
            return
        findings.append(Finding(
            finding_id=f"PE-{n:04d}", host_id=host_id, title=title, category=category,
            entity_key=f"path:{file_path}", paths=[file_path], description=desc,
            confidence=conf, rule=f"pe_indicators.{category}", source_count=1,
            evidence=[EvidenceReference(provenance_id=prov, tool=tool, artifact_path=file_path,
                                        source_family="pe_static", record_id=record,
                                        note=desc[:160])],
            tags=["disk", "pe_static", *tags], mitre_mapping=mitre,
        ))
        n += 1

    # 1) PyInstaller / Python-packed executable.
    if pyinstaller and pyinstaller.get("is_pyinstaller"):
        emit(pyinstaller.get("provenance_id"),
             f"PyInstaller-packed executable: {file_path.split(chr(92))[-1]}",
             "packed_executable",
             f"Markers {pyinstaller.get('markers')} indicate a PyInstaller/Python-packed binary "
             f"at {file_path}. Packed interpreters are a common implant delivery form.",
             Confidence.suspicious if benign_loc else Confidence.likely,
             ["pyinstaller"], ["T1027.002"], "detect_pyinstaller",
             record=",".join(pyinstaller.get("markers", [])[:4]))

    # 2) Embedded C2 indicators (URLs / IP:port) inside a binary.
    if embedded and (embedded.get("urls") or embedded.get("ips")):
        nets = (embedded.get("urls") or []) + (embedded.get("ips") or [])
        emit(embedded.get("provenance_id"),
             f"Embedded network indicators in executable: {file_path.split(chr(92))[-1]}",
             "embedded_c2",
             f"The executable at {file_path} embeds network indicators {nets[:6]}. In a "
             f"non-standard/masquerade path these are candidate C2 endpoints.",
             Confidence.likely if (masquerade or not benign_loc) else Confidence.suspicious,
             ["c2", "network"], ["T1071"], "extract_embedded_urls",
             record=";".join(nets[:4]))

    # 3) Capability imports from PE metadata.
    if pe and pe.get("is_pe"):
        imps = pe.get("suspicious_imports") or []
        prov = pe.get("provenance_id")
        if _has(imps, _WININET):
            emit(prov, f"WININET HTTP-beaconing capability: {file_path.split(chr(92))[-1]}",
                 "beacon_capability",
                 f"Imports {_has(imps, _WININET)} — WININET HTTP client APIs used for web C2 beaconing.",
                 Confidence.suspicious, ["c2", "wininet"], ["T1071.001"], "extract_pe_metadata")
        if _has(imps, _INJECTION):
            emit(prov, f"Process-injection capability: {file_path.split(chr(92))[-1]}",
                 "injection_capability",
                 f"Imports {_has(imps, _INJECTION)} — remote process injection primitives.",
                 Confidence.suspicious, ["injection"], ["T1055"], "extract_pe_metadata")
        if _has(imps, _CREDDUMP):
            emit(prov, f"Credential-dumping capability: {file_path.split(chr(92))[-1]}",
                 "creddump_capability",
                 f"Imports {_has(imps, _CREDDUMP)} — LSASS/credential extraction primitives.",
                 Confidence.suspicious, ["credential_access"], ["T1003"], "extract_pe_metadata")
        # 4) Masquerade PE: a system exe in a fake system32 subdirectory.
        if masquerade:
            emit(prov, f"Masqueraded system binary on disk: {file_path}",
                 "masquerade_path",
                 f"A PE at {file_path} sits in a fake child directory of system32 — first-party "
                 f"system executables live directly in system32, not a subfolder.",
                 Confidence.likely, ["masquerade"], ["T1036.005"], "extract_pe_metadata")

    # 5) PDB build-path attribution (custom, non-Microsoft).
    pdb_path = (pe or {}).get("pdb_path") or (pdb or {}).get("pdb_paths", [None])[0] if (pe or pdb) else None
    pdb_list = []
    if pe and pe.get("pdb_path"):
        pdb_list.append((pe["pdb_path"], pe.get("provenance_id"), "extract_pe_metadata"))
    if pdb and pdb.get("pdb_paths"):
        pdb_list += [(p, pdb.get("provenance_id"), "extract_pdb_paths") for p in pdb["pdb_paths"]]
    for p, prov, tool in pdb_list:
        if p and not _MS_PDB.search(p):
            emit(prov, f"Custom PDB build path: {file_path.split(chr(92))[-1]}",
                 "pdb_attribution",
                 f"Embedded PDB path '{p}' is a custom build tree (not a Microsoft symbol path) — "
                 f"an authorship/attribution indicator.",
                 Confidence.suspicious, ["attribution", "pdb"], ["T1587"], tool, record=p[:120])
            break

    return findings

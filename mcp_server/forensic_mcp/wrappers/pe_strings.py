"""Static binary triage: strings, PE metadata, PyInstaller, PDB paths, embedded URLs.

All read-only, in-process (no shell), path-gated via ensure_readable so they work
on sealed evidence OR files the agent extracted/mounted. Each appends one
provenance line. Identity-agnostic: they report metadata/strings; the RULE layer
(rules/pe_indicators.py) decides what is suspicious.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from forensic_mcp.paths import ensure_host_dirs, ensure_readable
from forensic_mcp.provenance import log_action, log_rejection, next_provenance_id
from forensic_mcp.schemas import (
    EmbeddedUrlsResponse,
    ExtractStringsRequest,
    ExtractStringsResponse,
    FileToolRequest,
    PdbPathsResponse,
    PeMetadataResponse,
    PeSection,
    PyInstallerResponse,
    ToolStatus,
)

_MAX_BYTES = 96 * 1024 * 1024  # cap how much we read into memory

_URL_RE = re.compile(r"https?://[^\s\x00\"'<>]{4,2048}")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b")
_PDB_RE = re.compile(r"[A-Za-z]:\\[^\x00\r\n]{0,400}?\.pdb|/[^\x00\r\n]{0,400}?\.pdb", re.IGNORECASE)
_INTEREST = re.compile(r"(https?://|\.pdb|\\[A-Za-z0-9_]+\\|wininet|HttpSend|InternetOpen|"
                       r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|MiniDump|sekurlsa|/ads/)",
                       re.IGNORECASE)

# PyInstaller fingerprints (byte-level; version-agnostic).
_PYI_MARKERS = [b"PyInstaller", b"pyiboot01_bootstrap", b"_MEIPASS", b"pyimod",
                b"pyi-", b"MEI\x0c\x0b\x0a\x0b\x0e", b"Py_SetProgramName"]
_PYI_DLL_RE = re.compile(rb"python\d\d\.dll", re.IGNORECASE)

# Import functions worth surfacing (behavioural capability, not identity).
_SUSPICIOUS_IMPORTS = {
    "internetopena", "internetopenw", "internetopenurla", "httpsendrequesta",
    "httpsendrequestw", "internetconnecta", "internetreadfile",          # WININET beaconing
    "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
    "queueuserapc", "setthreadcontext",                                  # injection
    "minidumpwritedump", "lsaretrieveprivatedata", "samiconnect",        # credential dumping
    "adjusttokenprivileges", "lookupprivilegevaluea",
}


def _read(path: Path) -> bytes:
    with path.open("rb") as fh:
        return fh.read(_MAX_BYTES)


def _gate(req: FileToolRequest, wrapper: str, tool: str):
    """Return (path, provenance_id, None) or (None, provenance_id, error_str)."""
    ensure_host_dirs(req.case_id, req.host_id)
    pid = next_provenance_id(req.case_id)
    try:
        path = ensure_readable(req.file_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
                      tool_name=tool, wrapper_name=wrapper,
                      attempted=[wrapper, str(req.file_path)], error=str(e))
        return None, pid, str(e)
    if not path.exists() or not path.is_file():
        msg = "path does not exist or is not a regular file"
        log_rejection(provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
                      tool_name=tool, wrapper_name=wrapper,
                      attempted=[wrapper, str(path)], error=msg)
        return None, pid, msg
    return path, pid, None


def _ascii_strings(data: bytes, n: int) -> list[str]:
    return [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % n, data)]


def _utf16_strings(data: bytes, n: int) -> list[str]:
    return [m.group().decode("utf-16le", "ignore")
            for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % n, data)]


def _log(req, pid, wrapper, tool, path, outputs=None):
    log_action(provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
               tool_name=tool, wrapper_name=wrapper, command=[wrapper, str(path)],
               input_paths=[path], output_paths=outputs or [], status="success")


def extract_strings(req: ExtractStringsRequest) -> ExtractStringsResponse:
    path, pid, err = _gate(req, "extract_strings", "strings")
    if err:
        return ExtractStringsResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                      file_path=req.file_path, provenance_id=pid, error=err)
    data = _read(path)
    modes = [m.lower() for m in (req.encoding_modes or ["ascii", "utf16le"])]
    n = max(3, int(req.min_length or 4))
    a = _ascii_strings(data, n) if "ascii" in modes else []
    u = _utf16_strings(data, n) if "utf16le" in modes else []
    interesting = list(dict.fromkeys(s for s in (a + u) if _INTEREST.search(s)))[:500]
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    out = dirs["parsed"] / f"{path.name}.strings.txt"
    out.write_text("\n".join(interesting), encoding="utf-8")
    _log(req, pid, "extract_strings", "strings", path, [out])
    return ExtractStringsResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                                  file_path=path, ascii_count=len(a), utf16le_count=len(u),
                                  interesting=interesting, output_path=out, provenance_id=pid)


def detect_pyinstaller(req: FileToolRequest) -> PyInstallerResponse:
    path, pid, err = _gate(req, "detect_pyinstaller", "pyinstaller")
    if err:
        return PyInstallerResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                   file_path=req.file_path, provenance_id=pid, error=err)
    data = _read(path)
    found = [m.decode("latin-1", "replace") for m in _PYI_MARKERS if m in data]
    if _PYI_DLL_RE.search(data):
        found.append("pythonXX.dll")
    _log(req, pid, "detect_pyinstaller", "pyinstaller", path)
    return PyInstallerResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                               file_path=path, is_pyinstaller=bool(found),
                               markers=sorted(set(found)), provenance_id=pid)


def extract_pdb_paths(req: FileToolRequest) -> PdbPathsResponse:
    path, pid, err = _gate(req, "extract_pdb_paths", "pdb")
    if err:
        return PdbPathsResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                file_path=req.file_path, provenance_id=pid, error=err)
    data = _read(path)
    text = data.decode("latin-1", "replace")
    paths = list(dict.fromkeys(m.group(0).strip() for m in _PDB_RE.finditer(text)))[:50]
    _log(req, pid, "extract_pdb_paths", "pdb", path)
    return PdbPathsResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                            file_path=path, pdb_paths=paths, provenance_id=pid)


def extract_embedded_urls(req: FileToolRequest) -> EmbeddedUrlsResponse:
    path, pid, err = _gate(req, "extract_embedded_urls", "urls")
    if err:
        return EmbeddedUrlsResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                    file_path=req.file_path, provenance_id=pid, error=err)
    data = _read(path)
    text = data.decode("latin-1", "replace")
    urls = list(dict.fromkeys(_URL_RE.findall(text)))[:200]
    ips = list(dict.fromkeys(_IP_RE.findall(text)))[:200]
    _log(req, pid, "extract_embedded_urls", "urls", path)
    return EmbeddedUrlsResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                                file_path=path, urls=urls, ips=ips, provenance_id=pid)


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = Counter(b)
    total = len(b)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def extract_pe_metadata(req: FileToolRequest) -> PeMetadataResponse:
    path, pid, err = _gate(req, "extract_pe_metadata", "pe")
    if err:
        return PeMetadataResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                  file_path=req.file_path, provenance_id=pid, error=err)
    try:
        import pefile  # local import: optional dependency
    except ModuleNotFoundError:
        _log(req, pid, "extract_pe_metadata", "pe", path)
        return PeMetadataResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                  file_path=path, provenance_id=pid,
                                  error="pefile not installed; cannot parse PE")
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        ])
    except Exception as e:  # noqa: BLE001 — not a valid PE
        _log(req, pid, "extract_pe_metadata", "pe", path)
        return PeMetadataResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                                  file_path=path, is_pe=False, provenance_id=pid, error=str(e))

    sections = [PeSection(
        name=s.Name.rstrip(b"\x00").decode("latin-1", "replace"),
        virtual_size=s.Misc_VirtualSize, raw_size=s.SizeOfRawData,
        entropy=_entropy(s.get_data()),
        characteristics=hex(s.Characteristics),
    ) for s in pe.sections]

    imports: dict[str, list[str]] = {}
    suspicious: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode("latin-1", "replace")
        funcs = []
        for imp in entry.imports:
            fn = (imp.name or b"").decode("latin-1", "replace") if imp.name else f"ord{imp.ordinal}"
            funcs.append(fn)
            if fn.lower() in _SUSPICIOUS_IMPORTS:
                suspicious.append(f"{dll}!{fn}")
        imports[dll] = funcs

    pdb = None
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        ce = getattr(dbg, "entry", None)
        name = getattr(ce, "PdbFileName", None)
        if name:
            pdb = name.rstrip(b"\x00").decode("latin-1", "replace")
            break

    ts = pe.FILE_HEADER.TimeDateStamp
    compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
    _log(req, pid, "extract_pe_metadata", "pe", path)
    return PeMetadataResponse(
        status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id, file_path=path,
        is_pe=True, machine=hex(pe.FILE_HEADER.Machine), compile_time_utc=compile_time,
        subsystem=str(getattr(pe.OPTIONAL_HEADER, "Subsystem", "")),
        imphash=pe.get_imphash() or None, pdb_path=pdb, sections=sections,
        imports=imports, suspicious_imports=sorted(set(suspicious)), provenance_id=pid)

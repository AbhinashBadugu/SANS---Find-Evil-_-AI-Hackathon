"""parse_reg_export / extract_c2_from_registry — decode exported registry files
and surface configuration-stored network indicators (candidate C2).

GENERIC, not file-specific: it parses any RegEdit .reg export (UTF-16LE or UTF-8),
decodes REG_SZ / DWORD / REG_BINARY / REG_EXPAND_SZ(hex(2)) / REG_MULTI_SZ(hex(7))
values, and extracts URLs / IPs / hostnames / beacon-interval integers from the
decoded data. A malware C2 config stored in the registry (e.g. a Netman\\domain
value) is one instance this catches — there is no filename special-casing.
Read-only, in-process, one provenance line.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from forensic_mcp.paths import ensure_host_dirs, ensure_readable
from forensic_mcp.provenance import log_action, log_rejection, next_provenance_id
from forensic_mcp.schemas import (
    ExtractC2Response,
    RegConfigEntry,
    RegExportRequest,
    RegExportResponse,
    ToolStatus,
)

_URL = re.compile(r"https?://[^\s\x00\"'<>]{4,2048}")
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b")
_HOST = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18}\b", re.IGNORECASE)
_INTERVAL_NAME = re.compile(r"(interval|sleep|beacon|poll|delay|timeout|jitter)", re.IGNORECASE)
_KEY_LINE = re.compile(r"^\[(-?)(.+)\]$")
_VAL_LINE = re.compile(r'^(".*?"|@)\s*=\s*(.*)$')


def _decode_text(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16le", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "replace")
    # Heuristic: lots of NULs -> UTF-16LE without BOM.
    if raw[:200].count(0) > 20:
        return raw.decode("utf-16le", "replace")
    return raw.decode("utf-8", "replace")


def _join_continuations(text: str) -> list[str]:
    out, buf = [], ""
    for line in text.splitlines():
        s = line.rstrip()
        if buf:
            buf += s.strip()
        else:
            buf = s
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return out


def _hex_to_bytes(blob: str) -> bytes:
    toks = [t for t in re.split(r"[,\s]+", blob.strip()) if re.fullmatch(r"[0-9a-fA-F]{1,2}", t)]
    try:
        return bytes(int(t, 16) for t in toks)
    except ValueError:
        return b""


def _decode_value(rhs: str) -> tuple[str, str]:
    """Return (value_type, decoded_text)."""
    rhs = rhs.strip()
    if rhs.startswith('"'):
        return "REG_SZ", rhs[1:rhs.rfind('"')] if rhs.rfind('"') > 0 else rhs.strip('"')
    if rhs.lower().startswith("dword:"):
        try:
            return "REG_DWORD", str(int(rhs.split(":", 1)[1].strip(), 16))
        except ValueError:
            return "REG_DWORD", rhs
    m = re.match(r"hex(?:\(([0-9a-fA-F]+)\))?:(.*)$", rhs, re.IGNORECASE | re.DOTALL)
    if m:
        kind = (m.group(1) or "3").lower()
        data = _hex_to_bytes(m.group(2))
        typ = {"2": "REG_EXPAND_SZ", "7": "REG_MULTI_SZ", "b": "REG_QWORD"}.get(kind, "REG_BINARY")
        if kind in ("2", "7") or data[:2].count(0) == 0 and b"\x00" in data:
            text = data.decode("utf-16le", "replace").replace("\x00", " ").strip()
        else:
            text = data.decode("latin-1", "replace")
        return typ, text
    return "REG_UNKNOWN", rhs


def _extract_indicators(text: str) -> tuple[list[str], list[str], list[str]]:
    urls = list(dict.fromkeys(_URL.findall(text)))
    ips = list(dict.fromkeys(_IP.findall(text)))
    hosts = [h for h in dict.fromkeys(_HOST.findall(text))
             if not _IP.fullmatch(h) and "." in h][:20]
    return urls, ips, hosts


def _parse_reg_file(path: Path) -> list[RegConfigEntry]:
    text = _decode_text(path.read_bytes())
    entries: list[RegConfigEntry] = []
    current_key = ""
    for line in _join_continuations(text):
        s = line.strip()
        if not s or s.lower().startswith("windows registry editor"):
            continue
        km = _KEY_LINE.match(s)
        if km:
            current_key = km.group(2).strip()
            continue
        vm = _VAL_LINE.match(s)
        if not vm:
            continue
        name = vm.group(1)
        name = "(default)" if name == "@" else name.strip('"')
        vtype, decoded = _decode_value(vm.group(2))
        urls, ips, hosts = _extract_indicators(decoded)
        intervals: list[int] = []
        if vtype == "REG_DWORD" and _INTERVAL_NAME.search(name):
            try:
                intervals.append(int(decoded))
            except ValueError:
                pass
        entries.append(RegConfigEntry(
            key=current_key, value_name=name, value_type=vtype,
            decoded_data=decoded[:2000], urls=urls, ips=ips, hostnames=hosts,
            intervals=intervals, source_file=str(path),
        ))
    return entries


def _reg_files(root: Path) -> list[Path]:
    if root.is_dir():
        return sorted(root.rglob("*.reg"))
    return [root]


def parse_reg_export(req: RegExportRequest) -> RegExportResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    pid = next_provenance_id(req.case_id)
    try:
        target = ensure_readable(req.reg_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
                      tool_name="reg_export", wrapper_name="parse_reg_export",
                      attempted=["parse_reg_export", str(req.reg_path)], error=str(e))
        return RegExportResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                 reg_path=req.reg_path, provenance_id=pid, error=str(e))
    if not target.exists():
        return RegExportResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                 reg_path=target, provenance_id=pid, error="path does not exist")

    entries: list[RegConfigEntry] = []
    for f in _reg_files(target):
        try:
            entries.extend(_parse_reg_file(f))
        except OSError:
            continue

    out = dirs["parsed"] / "registry_config.json"
    out.write_text(json.dumps([e.model_dump() for e in entries], indent=2), encoding="utf-8")
    log_action(provenance_id=pid, case_id=req.case_id, host_id=req.host_id,
               tool_name="reg_export", wrapper_name="parse_reg_export",
               command=["parse_reg_export", str(target)], input_paths=[target],
               output_paths=[out], status="success")
    return RegExportResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                             reg_path=target, entries=entries, entry_count=len(entries),
                             output_path=out, provenance_id=pid)


def extract_c2_from_registry(req: RegExportRequest) -> ExtractC2Response:
    """parse_reg_export, then keep only entries carrying a network indicator —
    the registry-stored C2 configuration."""
    parsed = parse_reg_export(req)
    if parsed.status != ToolStatus.success:
        return ExtractC2Response(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                 reg_path=parsed.reg_path, provenance_id=parsed.provenance_id,
                                 error=parsed.error)
    c2 = [e for e in parsed.entries if e.urls or e.ips]
    return ExtractC2Response(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                             reg_path=parsed.reg_path, c2_entries=c2,
                             output_path=parsed.output_path, provenance_id=parsed.provenance_id)

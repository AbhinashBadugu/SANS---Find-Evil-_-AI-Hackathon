"""parse_java_cache — recover what a host's Java Deployment Cache downloaded.

Java caches every applet resource it fetches as a pair: a binary `*.idx` index
(URL + the original HTTP response headers) plus the downloaded bytes. A Java
drive-by leaves its fingerprints here: the remote JAR it loaded and the
executable second stage it pulled.

`.idx` is a versioned binary format (Java 6/7/8 differ). Rather than parse each
version, we string-extract robustly: scan the bytes for URLs and HTTP header
lines. This is read-only and version-agnostic — exactly the "safely
string-extract" approach. Identity-agnostic: it reports whatever URLs/JARs/
payloads a cache holds; the RULE layer decides what is suspicious.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from forensic_mcp.paths import ensure_host_dirs, ensure_readable
from forensic_mcp.provenance import log_action, log_rejection, next_provenance_id
from forensic_mcp.schemas import JavaCacheRequest, JavaCacheResponse, JavaIdxRecord, ToolStatus

_URL = re.compile(rb"https?://[^\s\x00-\x1f\"'<>]{4,2048}")
_STATUS = re.compile(rb"HTTP/\d\.\d\s+(\d{3})")
_HDR = lambda name: re.compile(rb"(?im)^" + re.escape(name.encode()) + rb"\s*:\s*([^\r\n\x00]{1,300})")
_CONTENT_TYPE = _HDR("content-type")
_LAST_MOD = _HDR("last-modified")
_SERVER = _HDR("server")

# A URL is "payload-like" if it pulls an executable, a CGI/no-extension blob, or
# carries an executable content-type. Generic — no campaign filenames.
_EXEC_EXT = re.compile(r"\.(exe|scr|dll|cpl|jar|class)$", re.IGNORECASE)
_PAYLOAD_HINT = re.compile(r"(\.(exe|scr|dll|cpl)$|/[a-z0-9]{6,}$|\.(php|cgi|asp|aspx|jsp)(\?|$))", re.IGNORECASE)


def _u(b: bytes) -> str:
    return b.decode("latin-1", "replace").strip()


def _parse_idx(idx: Path) -> JavaIdxRecord:
    data = idx.read_bytes()
    urls = list(dict.fromkeys(_u(m.group(0)) for m in _URL.finditer(data)))
    jar_urls = [u for u in urls if u.lower().split("?")[0].endswith(".jar")]
    payload_urls = [
        u for u in urls
        if not u.lower().split("?")[0].endswith(".jar") and _PAYLOAD_HINT.search(u.split("?")[0])
    ]
    status = _STATUS.search(data)
    ct = _CONTENT_TYPE.search(data)
    lm = _LAST_MOD.search(data)
    srv = _SERVER.search(data)
    # The downloaded bytes usually sit next to the .idx (same stem, no extension).
    cached = None
    sibling = idx.with_suffix("")
    if sibling.exists() and sibling.is_file():
        cached = str(sibling)
    return JavaIdxRecord(
        idx_path=str(idx), urls=urls, jar_urls=jar_urls, payload_urls=payload_urls,
        http_status=_u(status.group(1)) if status else None,
        content_type=_u(ct.group(1)) if ct else None,
        last_modified=_u(lm.group(1)) if lm else None,
        server=_u(srv.group(1)) if srv else None,
        cached_file=cached,
    )


def parse_java_cache(req: JavaCacheRequest) -> JavaCacheResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)

    try:
        cache_dir = ensure_readable(req.cache_dir)
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="java_idx", wrapper_name="parse_java_cache",
                      attempted=["parse_java_cache", str(req.cache_dir)], error=str(e))
        return JavaCacheResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                 cache_dir=req.cache_dir, provenance_id=provenance_id, error=str(e))

    if not cache_dir.exists() or not cache_dir.is_dir():
        msg = "cache_dir does not exist or is not a directory"
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="java_idx", wrapper_name="parse_java_cache",
                      attempted=["parse_java_cache", str(cache_dir)], error=msg)
        return JavaCacheResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                 cache_dir=cache_dir, provenance_id=provenance_id, error=msg)

    records: list[JavaIdxRecord] = []
    for idx in sorted(cache_dir.rglob("*.idx")):
        try:
            records.append(_parse_idx(idx))
        except OSError:
            continue

    out = dirs["parsed"] / "java_cache.json"
    out.write_text(json.dumps([r.model_dump() for r in records], indent=2), encoding="utf-8")
    log_action(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
               tool_name="java_idx", wrapper_name="parse_java_cache",
               command=["parse_java_cache", str(cache_dir)],
               input_paths=[cache_dir], output_paths=[out], status="success")

    return JavaCacheResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                             cache_dir=cache_dir, records=records, idx_count=len(records),
                             output_path=out, provenance_id=provenance_id)

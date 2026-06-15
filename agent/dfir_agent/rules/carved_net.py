"""Carved-URL C2 rule (memory, family=network).

bulk_extractor (carve_network_artifacts) recovers URLs straight from memory bytes —
including ones Volatility netscan can't show (it only has IP:port, never the URI).
This rule mines the carved url.txt for command-and-control / malware-download URLs.

Precision matters more than coverage, so it flags a carved URL only on a strong
signal, never "any URL":
  * the host is a RAW IP (legitimate web traffic resolves through DNS hostnames /
    CDNs — direct raw-IP HTTP with a path is an uncommon, C2-associated pattern), AND
  * the path looks malicious — a known beacon path (/ads/), a payload/script
    extension (.exe/.dll/.sys/.php/.asp/.cgi or /cgi-bin/), or a high-entropy
    single-token path (exploit-kit style), OR the IP already matches a flagged C2.
Plain raw-IP URLs hitting only "/" are ignored.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from ..state import Confidence, EvidenceReference, Finding

# A raw-IP URL with the path captured (strip any bulk_extractor \x.. junk after).
_IP_URL = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(/[^\s\\\"'<>]*)?", re.I)
_BEACON = "/ads/"
_PAYLOAD_EXT = re.compile(r"\.(exe|dll|sys|php|asp|aspx|jsp|cgi|bin|scr|bat)\b", re.I)
_CGI = "/cgi-bin/"
_TOKEN = re.compile(r"^/[A-Za-z0-9]{8,}$")  # single high-entropy path segment (exploit-kit token)


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified or a.is_reserved)


def _suspicious(ip: str, path: str, c2_ips: set[str]) -> str | None:
    if ip in c2_ips:
        return "host is an already-flagged C2 IP"
    if not path or path == "/":
        return None
    pl = path.lower()
    if _BEACON in pl:
        return "suspicious /ads/-style beacon path"
    if _PAYLOAD_EXT.search(pl) or _CGI in pl:
        return "payload/script download path"
    if _TOKEN.match(path) and _is_public(ip):
        return "high-entropy single-token path (exploit-kit pattern)"
    return None


def detect_carved_c2_urls(
    url_txt: str, *, host_id: str, provenance_id: str, c2_ips=None, next_id, cap: int = 25
) -> list[Finding]:
    p = Path(url_txt)
    if not p.exists():
        return []
    c2_ips = {str(x) for x in (c2_ips or set())}
    # url -> (ip, path, reason); dedup by (ip, first path segment)
    found: dict[tuple, tuple] = {}
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            for m in _IP_URL.finditer(line):
                ip, path = m.group(1), (m.group(2) or "")
                # trim bulk_extractor escape noise that can trail the path
                path = re.split(r"\\x00|\\x[0-9a-fA-F]{2}", path)[0]
                reason = _suspicious(ip, path, c2_ips)
                if not reason:
                    continue
                seg = "/" + path.lstrip("/").split("/")[0]
                key = (ip, seg)
                if key not in found:
                    found[key] = (ip, path, reason)

    findings: list[Finding] = []
    for (ip, seg), (ip2, path, reason) in list(found.items())[:cap]:
        url = f"http://{ip}{path}"
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"C2/download URL carved from memory: {url}",
            category="c2_connection", entity_key=f"c2url:{ip}{seg}", paths=[],
            description=(
                f"bulk_extractor carved the URL '{url}' from this host's memory ({reason}). "
                f"Direct raw-IP HTTP with this path is a command-and-control / malware-download "
                f"indicator; the host '{ip}' had no DNS hostname in the traffic."
            ),
            confidence=Confidence.suspicious, rule="carved_net.c2_url", source_count=1,
            evidence=[EvidenceReference(
                provenance_id=provenance_id, record_id=f"url={url}", tool="carve_network_artifacts",
                artifact_path=url_txt, source_family="network",
                note=f"bulk_extractor url.txt: {url} ({reason})",
            )],
            tags=["memory", "carved", "c2", f"c2:{ip}"],
        ))
    return findings

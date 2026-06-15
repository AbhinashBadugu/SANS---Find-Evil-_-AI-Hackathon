"""Lateral-movement graph reconstruction (family=lateral_movement).

Normalizes Windows logon/service events (4624/4648/4672/4776/7045) into a
time-ordered, confidence-scored host->host graph. Source IPs / workstation names
are resolved to known hosts when a topology map is supplied; unresolved sources
are kept as explicit `unknown` nodes — never guessed. Pure correlation over EVTX
rows the agent already parsed; emits both a machine-readable graph and cited
Findings. Identity-agnostic: no host names or IPs are baked in.
"""

from __future__ import annotations

from ..state import Confidence, EvidenceReference, Finding

_LOGON_METHOD = {"10": "RDP", "3": "Network/SMB", "2": "Interactive", "7": "Unlock", "8": "NetworkCleartext"}
_LATERAL_TYPES = {"3", "10"}  # remote logons that move between hosts
_PSEXEC = ("psexesvc", "psexec")


def _d(x) -> dict:
    return x if isinstance(x, dict) else x.model_dump()


def resolve_source_ip_to_host(src, ip_map: dict | None) -> str | None:
    """Resolve a source IP or workstation name to a known host id, or None."""
    if not src:
        return None
    ip_map = ip_map or {}
    s = str(src).strip()
    if s in ip_map:
        return ip_map[s]
    low = s.lower()
    for k, v in ip_map.items():
        if str(k).lower() == low:
            return v
    return None


def normalize_windows_logon_events(events, *, ip_map: dict | None = None) -> list[dict]:
    """Flatten heterogeneous EVTX rows into one normalized shape."""
    out = []
    for raw in events or []:
        e = _d(raw)
        eid = str(e.get("event_id", "")).strip()
        if eid not in {"4624", "4648", "4672", "4776", "7045"}:
            continue
        src = e.get("src_ip") or e.get("source_ip") or e.get("workstation") or e.get("ip_address")
        out.append({
            "event_id": eid,
            "dst_host": e.get("host_id") or e.get("dst_host"),
            "logon_type": str(e.get("logon_type", "")).strip(),
            "account": e.get("account") or e.get("target_user") or e.get("subject_user") or e.get("user"),
            "src_raw": src,
            "src_host": resolve_source_ip_to_host(src, ip_map),
            "service_name": (e.get("service_name") or e.get("image_path") or ""),
            "time": e.get("time") or e.get("timestamp") or e.get("utc"),
            "provenance_id": e.get("provenance_id"),
            "record_id": e.get("record_id"),
        })
    return out


def _edge_confidence(method: str, src_known: bool, psexec: bool, privileged: bool) -> Confidence:
    if psexec:
        return Confidence.confirmed                 # 7045 PSEXESVC + remote logon
    if src_known and (method == "RDP" or privileged):
        return Confidence.likely
    if src_known:
        return Confidence.likely
    return Confidence.suspicious                     # unknown source -> not asserted


def build_lateral_movement_graph(events, *, ip_map: dict | None = None) -> dict:
    """Return {nodes, edges, spread_path, unknown_sources}. Edges are time-ordered
    host->host moves with method, account, confidence and a provenance_id each."""
    norm = normalize_windows_logon_events(events, ip_map=ip_map)

    # Index PSEXESVC service installs per dst host (the PsExec lateral tell).
    psexec_hosts = {n["dst_host"] for n in norm
                    if n["event_id"] == "7045" and any(p in str(n["service_name"]).lower() for p in _PSEXEC)}
    priv_hosts = {(n["dst_host"], n.get("account")) for n in norm if n["event_id"] == "4672"}

    edges, unknown = [], set()
    for n in norm:
        if n["event_id"] not in {"4624", "4648"}:
            continue
        if n["event_id"] == "4624" and n["logon_type"] not in _LATERAL_TYPES:
            continue  # local interactive logons are not lateral
        method = "Explicit credentials" if n["event_id"] == "4648" else _LOGON_METHOD.get(n["logon_type"], "Logon")
        src = n["src_host"] or "unknown"
        if src == "unknown" and n["src_raw"]:
            unknown.add(str(n["src_raw"]))
        psexec = n["dst_host"] in psexec_hosts
        privileged = (n["dst_host"], n.get("account")) in priv_hosts
        conf = _edge_confidence(method, n["src_host"] is not None, psexec, privileged)
        edges.append({
            "src": src, "src_raw": n["src_raw"], "dst": n["dst_host"],
            "method": "PsExec (" + method + ")" if psexec else method,
            "account": n.get("account"), "time": n.get("time"),
            "event_id": n["event_id"], "confidence": conf.value,
            "provenance_id": n.get("provenance_id"), "record_id": n.get("record_id"),
            "privileged": privileged,
        })

    edges.sort(key=lambda x: (str(x["time"] or ""), x["dst"] or ""))
    nodes = sorted({e["src"] for e in edges} | {e["dst"] for e in edges if e["dst"]})

    # Human-readable spread path: hosts in first-appearance order along the edges.
    seq: list[str] = []
    for e in edges:
        for h in (e["src"], e["dst"]):
            if h and h not in seq:
                seq.append(h)
    spread_path = " -> ".join(seq)

    return {"nodes": nodes, "edges": edges, "spread_path": spread_path,
            "unknown_sources": sorted(unknown)}


def findings_from_lateral_graph(graph: dict, *, id_start: int = 1) -> list[Finding]:
    """One Finding per lateral edge, cited to its logon/service event."""
    findings, n = [], id_start
    for e in graph.get("edges", []):
        if not e.get("provenance_id") or not e.get("dst"):
            continue
        conf = Confidence(e["confidence"])
        src_label = e["src"] if e["src"] != "unknown" else f"unknown ({e.get('src_raw')})"
        findings.append(Finding(
            finding_id=f"LM-{n:04d}", host_id=e["dst"],
            title=f"Lateral movement: {src_label} -> {e['dst']} via {e['method']}",
            category="lateral_movement", entity_key=f"hop:{e['src']}->{e['dst']}:{e['method']}",
            description=(
                f"{e['event_id']} shows {e['method']} into {e['dst']} from {src_label}"
                + (f" using account '{e['account']}'" if e.get("account") else "")
                + (f" at {e['time']}" if e.get("time") else "")
                + (". Source resolved to a known host." if e["src"] != "unknown"
                   else ". Source NOT resolved to a known host (reported as unknown, not guessed).")
            ),
            confidence=conf, rule="lateral_graph.edge",
            source_count=2 if e["method"].startswith("PsExec") else 1,
            evidence=[EvidenceReference(
                provenance_id=e["provenance_id"], tool="parse_evtx", source_family="evtx",
                record_id=e.get("record_id"),
                note=f"{e['event_id']} {e['method']} {src_label}->{e['dst']} acct={e.get('account')}")],
            tags=["lateral_movement", "evtx"],
            mitre_mapping=["T1021.001" if "RDP" in e["method"] else "T1021.002"],
        ))
        n += 1
    return findings

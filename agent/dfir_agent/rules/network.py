"""Network / C2 rule (memory, family=network).

netscan surfaces an implant's outbound channel — but most public connections are
benign (Skype, browsers, update agents beacon legitimately), so flagging every one
would manufacture false positives. This rule is deliberately narrow: it flags a
public foreign connection ONLY when its owning process is either
  (a) already suspicious — a PID/name a memory rule already flagged, or
  (b) a core OS process that must never originate outbound internet traffic
      (System, smss, csrss, wininit, services).
That keeps spinlock.exe → 199.73.28.114 and System → httppump C2 while leaving
Skype and the adjudicated-benign usboesrv alone.

Each finding is keyed by pid so correlation fuses it with the process finding,
adding the strong `network` evidence family (so a flagged process that also beacons
becomes multi-source → confirmed).
"""

from __future__ import annotations

import ipaddress

from ..state import Confidence, EvidenceReference, Finding

# Core processes that should never originate an outbound internet connection.
NEVER_BEACON = {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe"}


def is_public_ip(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local
                or a.is_reserved or a.is_unspecified)


def detect_c2_connections(
    netscan_rows: list[dict], *, host_id: str, provenance_id: str, artifact_path: str | None,
    suspicious_pids, suspicious_names, next_id, cap: int = 20,
) -> list[Finding]:
    spids = {str(p) for p in suspicious_pids}
    snames = {str(n).lower() for n in suspicious_names}
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for r in netscan_rows:
        fa = str(r.get("ForeignAddr") or "").strip()
        if not is_public_ip(fa):
            continue
        owner = str(r.get("Owner") or "").strip()
        ol = owner.lower()
        pid = str(r.get("PID") or "?")
        if pid in spids or ol in snames:
            reason = "owned by a process already flagged as suspicious"
        elif ol in NEVER_BEACON:
            reason = f"core OS process '{owner or '?'}' must never originate outbound internet traffic"
        else:
            continue  # benign owner — not flagged (anti-FP)
        fport = r.get("ForeignPort")
        key = (pid, fa, str(fport))
        if key in seen:
            continue
        seen.add(key)
        proto = r.get("Proto")
        st = r.get("State")
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"Outbound C2 connection: {owner or '?'} (PID {pid}) → {fa}:{fport}",
            category="c2_connection", entity_key=f"pid:{pid}", paths=[],
            description=(
                f"windows.netscan shows {owner or '?'} (PID {pid}) with a {proto} connection to "
                f"public address {fa}:{fport} (state {st}) — {reason}. This is an outbound "
                f"command-and-control (C2) indicator."
            ),
            confidence=Confidence.suspicious, rule="network.c2_connection", source_count=1,
            evidence=[EvidenceReference(
                provenance_id=provenance_id, record_id=f"PID={pid} {fa}:{fport}",
                tool="run_volatility_plugin", artifact_path=artifact_path, source_family="network",
                note=f"windows.netscan: {owner or '?'} PID={pid} {proto} -> {fa}:{fport} state={st}",
            )],
            tags=["memory", "netscan", "c2", f"c2:{fa}"],
        ))
        if len(findings) >= cap:
            break
    return findings

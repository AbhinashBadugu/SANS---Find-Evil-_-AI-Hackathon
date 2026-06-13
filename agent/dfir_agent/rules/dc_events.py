"""DC / Identity event-log ruleset (playbook §rules, family=disk_evtx).

A domain controller's Security log has hundreds of thousands of events, so this
ruleset is deliberately selective — it surfaces only the rare, high-signal events
that mark lateral movement and credential abuse, and aggregates the noisy ones:

  * 7045  service installed   -> PsExec / suspicious drivers (benign IR/USB tools
                                 are classified out, not flagged as malware)
  * 4624  logon, Type 10      -> interactive RDP into the DC (by user + source IP)
  * 4648  explicit credentials -> runas/PsExec-style lateral movement (by src IP)

Every finding cites the EvtxECmd EventRecordId + the parse_evtx provenance_id.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict

from ..state import Confidence, EvidenceReference, Finding

csv.field_size_limit(min(2**31 - 1, sys.maxsize))

# Service-install classification (matched case-insensitively on name + binary).
_SUSPICIOUS_SERVICES = {
    "psexec": ("lateral_movement", "PsExec remote-execution service (Sysinternals) — lateral movement"),
    "psexesvc": ("lateral_movement", "PsExec service binary — remote command execution"),
    "mnemosyne": ("suspicious_driver", "Mnemosyne kernel driver — uncommon, attacker-associated"),
}
_BENIGN_SERVICE_HINTS = ("f-response", "fresponse", "fresdisk", "kernelpro", "usboe", "usboesrv")

_LOCAL_IPS = {"-", "", "127.0.0.1", "::1", "?"}
_SYSTEM_ACCOUNTS = {"system", "local service", "network service", "-", ""}


def _payload(row: dict) -> dict:
    try:
        data = json.loads(row.get("Payload") or "{}")
        items = data.get("EventData", {}).get("Data", [])
        return {i.get("@Name"): i.get("#text") for i in items if isinstance(i, dict)}
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {}


def _ev(provenance_id, csv_path, erid, note) -> EvidenceReference:
    return EvidenceReference(
        provenance_id=provenance_id, record_id=f"EventRecordId={erid}",
        tool="parse_evtx", artifact_path=csv_path, source_family="disk_evtx", note=note,
    )


def analyze_dc_events(
    evtx_csv: str, *, host_id: str, provenance_id: str, next_id, cap: int = 25
) -> tuple[list[Finding], list[str]]:
    """Return (findings, notes). Notes record benign classifications and any caps."""
    from pathlib import Path
    p = Path(evtx_csv)
    if not p.exists():
        return [], [f"{host_id}: evtx CSV not found for DC analysis."]

    svc_installs = defaultdict(list)   # service-name -> [(time, binary, erid)]
    rdp = defaultdict(list)            # (user, ip) -> [erid]
    explicit = defaultdict(list)       # (subject, target, ip) -> [erid]
    priv = defaultdict(list)           # target_user -> [erid]  (4672 special-privileges logon)

    with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            eid = row.get("EventId", "")
            erid = row.get("EventRecordId", "?")
            if eid == "7045":
                name = (row.get("PayloadData1") or "").replace("Name:", "").strip()
                binary = row.get("ExecutableInfo") or ""
                svc_installs[name].append((row.get("TimeCreated"), binary, erid))
            elif eid == "4624":
                pl = _payload(row)
                if pl.get("LogonType") == "10":
                    ip = (pl.get("IpAddress") or "").strip()
                    if ip not in _LOCAL_IPS:
                        rdp[(pl.get("TargetUserName", "?"), ip)].append(erid)
            elif eid == "4648":
                pl = _payload(row)
                ip = (pl.get("IpAddress") or "").strip()
                subj = pl.get("SubjectUserName", "?")
                tgt = pl.get("TargetUserName", "?")
                # drop machine-account self-logons and IP-less noise
                if ip not in _LOCAL_IPS and tgt not in ("-", "") and not tgt.endswith("$"):
                    explicit[(subj, tgt, ip)].append(erid)
            elif eid == "4672":
                # 4672 carries the account in SubjectUserName (not TargetUserName).
                pl = _payload(row)
                subj = (pl.get("SubjectUserName") or "").strip()
                if subj and not subj.endswith("$") and subj.lower() not in _SYSTEM_ACCOUNTS:
                    priv[subj].append(erid)

    findings: list[Finding] = []
    notes: list[str] = []

    # --- 7045 service installs ---
    for name, rows in svc_installs.items():
        low = (name + " " + " ".join(r[1] for r in rows)).lower()
        klass = next((v for k, v in _SUSPICIOUS_SERVICES.items() if k in low), None)
        if klass is None:
            if any(h in low for h in _BENIGN_SERVICE_HINTS):
                notes.append(f"benign service install classified out: '{name}' ({rows[0][1]})")
            else:
                notes.append(f"service install (unclassified, left as note): '{name}' ({rows[0][1]})")
            continue
        category, desc = klass
        times = sorted(t for t, _b, _e in rows if t)
        span = f"{times[0]} .. {times[-1]}" if times else "?"
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"Service install: {name} ×{len(rows)} on the DC", category=category,
            entity_key=f"svc:{name.lower()}",
            description=(
                f"{desc}. Installed {len(rows)} time(s) ({span}); binary {rows[0][1]}. "
                f"On a domain controller this is a strong lateral-movement / remote-execution signal."
            ),
            confidence=Confidence.likely, rule="dc_events.service_install", source_count=1,
            evidence=[_ev(provenance_id, evtx_csv, rows[0][2],
                          f"7045 service '{name}' binary={rows[0][1]} installs={len(rows)} {span}")],
            tags=["dc", "eventlog", "7045", category],
        ))

    # --- 4624 Type-10 RDP ---
    for (user, ip), erids in sorted(rdp.items(), key=lambda kv: -len(kv[1]))[:cap]:
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"RDP logon to DC: {user} from {ip}", category="lateral_movement",
            entity_key=f"rdp:{user}:{ip}", paths=[],
            description=(
                f"Interactive RDP logon (Type 10) to the domain controller by '{user}' from {ip} "
                f"({len(erids)} session(s)). Remote interactive access to a DC is a lateral-movement / "
                f"admin-access indicator; the source IP should be correlated across hosts."
            ),
            confidence=Confidence.likely, rule="dc_events.rdp_logon", source_count=1,
            evidence=[_ev(provenance_id, evtx_csv, erids[0],
                          f"4624 LogonType=10 user={user} src={ip} count={len(erids)}")],
            tags=["dc", "eventlog", "4624", "rdp", f"src:{ip}"],
        ))
    if len(rdp) > cap:
        notes.append(f"RDP logons capped at {cap} of {len(rdp)} distinct (user, src) pairs.")

    # --- 4648 explicit credentials ---
    for (subj, tgt, ip), erids in sorted(explicit.items(), key=lambda kv: -len(kv[1]))[:cap]:
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"Explicit-credential logon: {subj} → {tgt} from {ip}", category="lateral_movement",
            entity_key=f"explicit:{subj}:{tgt}:{ip}",
            description=(
                f"A logon using explicit credentials (4648): '{subj}' authenticated as '{tgt}' "
                f"from {ip} ({len(erids)}×). This is the runas/PsExec pattern used to move laterally "
                f"with stolen credentials."
            ),
            confidence=Confidence.likely, rule="dc_events.explicit_creds", source_count=1,
            evidence=[_ev(provenance_id, evtx_csv, erids[0],
                          f"4648 subject={subj} target={tgt} src={ip} count={len(erids)}")],
            tags=["dc", "eventlog", "4648", f"src:{ip}"],
        ))
    if len(explicit) > cap:
        notes.append(f"explicit-credential logons capped at {cap} of {len(explicit)} distinct tuples.")

    # --- 4672 special-privileges (admin-equivalent) logons ---
    # 4672 fires constantly, so we surface it ONLY for accounts already implicated in
    # lateral movement on this DC (the RDP / explicit-cred actors). That ties the
    # privileged logon to the intrusion instead of reporting routine admin activity.
    lateral_actors = {u for (u, _ip) in rdp} | {t for (_s, t, _ip) in explicit}
    for user in sorted(lateral_actors):
        erids = priv.get(user)
        if not erids:
            continue
        findings.append(Finding(
            finding_id=next_id(), host_id=host_id,
            title=f"Privileged logon (4672): {user} on the DC", category="cred_access",
            entity_key=f"priv:{user}",
            description=(
                f"Account '{user}' received special privileges at logon (Event 4672) {len(erids)}×"
                f" on the domain controller — admin-equivalent rights (e.g. SeDebug/SeTcb/SeBackup). "
                f"Because '{user}' is also the account used for lateral movement here, this is "
                f"credential abuse / privilege use, not routine administration."
            ),
            confidence=Confidence.likely, rule="dc_events.privileged_logon", source_count=1,
            evidence=[_ev(provenance_id, evtx_csv, erids[0],
                          f"4672 special-privileges logon target={user} count={len(erids)}")],
            tags=["dc", "eventlog", "4672", "cred_access", "credential"],
        ))

    return findings, notes

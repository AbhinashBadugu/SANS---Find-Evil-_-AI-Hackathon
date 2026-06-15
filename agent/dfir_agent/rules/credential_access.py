"""Credential-access detection + logon correlation (family=credential_access).

Detects credential-dumping behaviour over artifacts the agent ALREADY parsed
(MFT / AmCache / Shimcache / Prefetch / memory cmdline / extracted files) and
correlates it with Windows logon events (4624/4648/4672/4776). No new evidence
reader — pure correlation over existing tool output.

Behavioural, not identity: it keys on generic credential-dumping tradecraft
(LSASS dumping, mimikatz/sekurlsa modules, registry SAM/SYSTEM export, known
dumper tooling), NOT on a specific case's filenames. Per the playbook it does
NOT call every procdump malicious — procdump is only credential access when it
TARGETS lsass (or correlates with other compromise).
"""

from __future__ import annotations

import re

from ..state import Confidence, EvidenceReference, Finding

# Generic credential-dumping tradecraft (tool/module names are public technique
# indicators, not case IOCs).
_MIMIKATZ = ("mimikatz", "sekurlsa", "lsadump", "privilege::debug", "kerberos::",
             "logonpasswords", "wdigest", "dpapi::", "kerberos::ptt")
_DUMPERS = ("gsecdump", "wce.exe", "pwdump", "fgdump", "lazagne", "dumpert",
            "nanodump", "procdump", "comsvcs.dll, minidump", "rundll32 comsvcs")
_LSASS_DUMP_FILE = re.compile(r"lsass[^\s\"']*\.dmp", re.IGNORECASE)
_HIVE_EXPORT = re.compile(r"reg(?:\.exe)?\s+(?:save|export)\s+.*hk(?:lm|ey_local_machine)\\(sam|system|security)",
                          re.IGNORECASE)
_PRIV_EVENTS = {"4672": "special-privilege logon", "4648": "explicit-credential logon",
                "4624": "account logon", "4776": "NTLM authentication"}


def _as_dict(x) -> dict:
    return x if isinstance(x, dict) else x.model_dump()


def _text(a: dict) -> str:
    return " ".join(str(a.get(k, "")) for k in ("name", "path", "cmdline", "text")).lower()


def _ev(a: dict, note: str) -> EvidenceReference:
    return EvidenceReference(
        provenance_id=a.get("provenance_id", ""),
        tool=a.get("tool"), artifact_path=a.get("path") or a.get("artifact_path"),
        source_family=a.get("source_family", "disk_mft"),
        record_id=a.get("record_id"), note=note)


def detect_credential_access(artifacts, *, host_id: str, id_start: int = 1) -> list[Finding]:
    """artifacts: list of dicts with any of {name, path, cmdline, text, source_family,
    provenance_id, record_id}. Returns cited credential-access findings."""
    findings: list[Finding] = []
    n = id_start

    def add(a, title, desc, conf, tags, mitre):
        nonlocal n
        if not a.get("provenance_id"):
            return
        findings.append(Finding(
            finding_id=f"CA-{n:04d}", host_id=host_id, title=title,
            category="credential_access", entity_key=f"credtool:{a.get('name') or title}",
            paths=[p for p in [a.get("path") or a.get("artifact_path")] if p],
            description=desc, confidence=conf, rule="credential_access.detect",
            source_count=1, evidence=[_ev(a, desc[:160])],
            tags=["credential_access", *tags], mitre_mapping=mitre,
        ))
        n += 1

    for raw in artifacts or []:
        a = _as_dict(raw)
        t = _text(a)
        if not t.strip():
            continue
        if any(k in t for k in _MIMIKATZ):
            add(a, "Credential-dumping tool/module (mimikatz-class)",
                f"Artifact shows mimikatz-class credential-dumping tradecraft: '{t[:120]}'.",
                Confidence.likely, ["mimikatz", "lsass"], ["T1003.001"])
            continue
        if _LSASS_DUMP_FILE.search(t) or ("procdump" in t and "lsass" in t) or \
                ("minidump" in t and "lsass" in t) or ("comsvcs" in t and "lsass" in t):
            add(a, "LSASS memory dump (credential access)",
                f"LSASS process memory was dumped (credential extraction): '{t[:120]}'.",
                Confidence.likely, ["lsass", "dump"], ["T1003.001"])
            continue
        if _HIVE_EXPORT.search(t):
            add(a, "Registry credential-hive export (SAM/SYSTEM/SECURITY)",
                f"Credential hive exported for offline cracking: '{t[:120]}'.",
                Confidence.likely, ["sam", "hive"], ["T1003.002"])
            continue
        if any(k in t for k in _DUMPERS):
            # A dumper present but NOT clearly targeting lsass -> suspicious, not confirmed.
            add(a, "Credential-dumping tooling present",
                f"A known credential-dumping utility is present: '{t[:120]}'. Context "
                "(LSASS target / attacker account / timing) needed to promote.",
                Confidence.suspicious, ["dumper"], ["T1003"])
    return findings


def correlate_credential_tooling_with_logons(cred_findings, logon_events, *, host_id: str,
                                             id_start: int = 1) -> list[Finding]:
    """Correlate credential-access findings with privileged/explicit logon events
    (4624/4648/4672/4776). A dump + a privileged-account logon is stolen-credential
    use — promoted to confirmed and citing both sources."""
    if not cred_findings or not logon_events:
        return []
    findings: list[Finding] = []
    n = id_start
    for raw in logon_events:
        e = _as_dict(raw)
        eid = str(e.get("event_id", ""))
        if eid not in _PRIV_EVENTS or not e.get("provenance_id"):
            continue
        acct = e.get("account") or e.get("target") or "?"
        cred = cred_findings[0]
        cred_ev = cred.evidence[0] if getattr(cred, "evidence", None) else None
        ev = [EvidenceReference(
            provenance_id=e["provenance_id"], tool="parse_evtx",
            source_family="evtx", record_id=e.get("record_id"),
            note=f"{eid} {_PRIV_EVENTS[eid]} account={acct} src={e.get('src_ip')}")]
        if cred_ev:
            ev.append(cred_ev)
        findings.append(Finding(
            finding_id=f"CAL-{n:04d}", host_id=host_id,
            title=f"Stolen-credential use: {acct} ({_PRIV_EVENTS[eid]})",
            category="credential_access", entity_key=f"credreuse:{acct}",
            description=(
                f"Credential-dumping activity on this host correlates with a {eid} "
                f"{_PRIV_EVENTS[eid]} for account '{acct}'"
                + (f" from {e.get('src_ip')}" if e.get("src_ip") else "")
                + ". Dump + privileged-account logon indicates stolen-credential reuse."
            ),
            confidence=Confidence.confirmed, rule="credential_access.logon_correlation",
            source_count=2, evidence=ev,
            tags=["credential_access", "valid_accounts", "correlation"],
            mitre_mapping=["T1003", "T1078"],
        ))
        n += 1
    return findings

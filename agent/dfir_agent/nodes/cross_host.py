"""Cross-host correlation (Phase 8).

The per-host pipeline analyses each machine in isolation. This case-level pass
fuses the finished host reports into one campaign narrative — *deterministically*,
exactly like the per-host correlator: code decides, the LLM never does.

It answers three cross-host questions, each grounded in the SAME provenance
citations the host findings already carry (no new evidence is invented here):

  1. **Shared implants** — the same malicious file (by normalized basename) found
     on >=2 hosts ⇒ one campaign artifact, with its per-host confidence + cites.
  2. **Lateral-movement chain** — every `lateral_movement` finding is a hop INTO
     the host it was found on; its `src:<ip>` tag is the origin. Hops are
     attributed to a source host when the case topology maps that IP, ordered so
     the patient-zero origin leads (patient zero → spread).
  3. **Patient zero (case level)** — the earliest per-host patient-zero marker.

Attribution rule (anti-hallucination): a source IP is tied to a host ONLY via an
explicit `Host.ip` topology fact passed in `ip_map`. When the IP is unmapped the
hop still renders with the raw IP and the gap is disclosed — never guessed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from ..scoring import load_provenance_index
from ..state import Confidence, EvidenceReference, Finding, HostRole, TimelineEvent
from .report import _cite  # reuse the exact host-report citation renderer

_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
_GENERIC_LIVE = {Confidence.confirmed, Confidence.likely, Confidence.suspicious}

# rule -> human method label for a lateral hop
_METHOD = {
    "dc_events.rdp_logon": "RDP (4624 Type 10)",
    "dc_events.explicit_creds": "Explicit-credential logon (4648)",
    "dc_events.service_install": "Service install / PsExec (7045)",
}


# --------------------------------------------------------------------------- #
# Inputs + output contracts
# --------------------------------------------------------------------------- #
class HostBundle(BaseModel):
    """One finished host's results, handed to the cross-host correlator."""

    host_id: str
    os: str | None = None
    role: HostRole = HostRole.workstation
    ip: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    patient_zero: datetime | None = None


class ImplantPresence(BaseModel):
    host_id: str
    confidence: Confidence
    title: str
    paths: list[str] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)


class SharedImplant(BaseModel):
    key: str  # normalized implant basename, e.g. "spinlock.exe"
    label: str  # most-confident host's title
    hosts: list[ImplantPresence] = Field(default_factory=list)


class LateralHop(BaseModel):
    ts: datetime | None = None
    src_ip: str | None = None
    src_host: str | None = None  # attributed via ip_map, else None
    dst_host: str = ""
    method: str = ""
    actor: str | None = None
    finding_id: str = ""
    evidence: list[EvidenceReference] = Field(default_factory=list)


class CrossHostReport(BaseModel):
    case_id: str
    host_count: int = 0
    case_patient_zero_host: str | None = None
    case_patient_zero_ts: datetime | None = None
    shared_implants: list[SharedImplant] = Field(default_factory=list)
    lateral_chain: list[LateralHop] = Field(default_factory=list)
    spread_edges: list[tuple[str, str, str]] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Deterministic correlation
# --------------------------------------------------------------------------- #
def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().rstrip("\\/"))[-1].lower()


def _src_ip(f: Finding) -> str | None:
    for t in f.tags:
        if t.startswith("src:"):
            ip = t[4:].strip()
            if ip:
                return ip
    return None


def _hop_ts(f: Finding) -> datetime | None:
    """Best-effort timestamp from a lateral finding's evidence note (DC events
    embed the event time in the note). Returns None when none is parseable."""
    for e in f.evidence:
        if not e.note:
            continue
        m = _TS_RE.search(e.note)
        if m:
            try:
                dt = datetime.fromisoformat(m.group(0).replace(" ", "T"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # evtx times are UTC
            except ValueError:
                continue
    return None


def _actor(f: Finding) -> str | None:
    # entity keys: rdp:<user>:<ip>, explicit:<subj>:<tgt>:<ip>, svc:<name>
    ek = f.entity_key or ""
    if ek.startswith("rdp:"):
        return ek.split(":")[1]
    if ek.startswith("explicit:"):
        parts = ek.split(":")
        return f"{parts[1]}→{parts[2]}" if len(parts) >= 3 else parts[1]
    return None


def correlate_shared_implants(bundles: list[HostBundle]) -> list[SharedImplant]:
    """Group live (non-FP) file-backed findings by basename; keep keys on >=2 hosts."""
    by_key: dict[str, dict[str, ImplantPresence]] = {}
    for b in bundles:
        for f in b.findings:
            if f.confidence == Confidence.false_positive or not f.paths:
                continue
            if f.category == "lateral_movement":
                continue  # hops belong to the chain, not the shared-file set
            keys = {_basename(p) for p in f.paths if p}
            for key in keys:
                slot = by_key.setdefault(key, {})
                cur = slot.get(b.host_id)
                # keep the strongest finding per (key, host)
                if cur is None or _rank(f.confidence) > _rank(cur.confidence):
                    slot[b.host_id] = ImplantPresence(
                        host_id=b.host_id, confidence=f.confidence, title=f.title,
                        paths=sorted({p for p in f.paths if _basename(p) == key}),
                        evidence=list(f.evidence),
                    )

    out: list[SharedImplant] = []
    for key, slot in by_key.items():
        if len(slot) < 2:
            continue
        presences = sorted(slot.values(), key=lambda p: (-_rank(p.confidence), p.host_id))
        out.append(SharedImplant(key=key, label=presences[0].title, hosts=presences))
    out.sort(key=lambda s: (-len(s.hosts), s.key))
    return out


def build_lateral_chain(
    bundles: list[HostBundle], ip_map: dict[str, str], patient_zero_host: str | None
) -> tuple[list[LateralHop], list[str]]:
    hops: list[LateralHop] = []
    gaps: list[str] = []
    for b in bundles:
        for f in b.findings:
            if f.category != "lateral_movement" or f.confidence == Confidence.false_positive:
                continue
            ip = _src_ip(f)
            src_host = ip_map.get(ip) if ip else None
            if ip and not src_host:
                gaps.append(
                    f"lateral hop into {b.host_id}: source IP {ip} not mapped to a known host "
                    f"(supply Host.ip to attribute)."
                )
            hops.append(LateralHop(
                ts=_hop_ts(f), src_ip=ip, src_host=src_host, dst_host=b.host_id,
                method=_METHOD.get(f.rule or "", f.rule or "lateral movement"),
                actor=_actor(f), finding_id=f.finding_id, evidence=list(f.evidence),
            ))

    _LATE = datetime.max.replace(tzinfo=timezone.utc)  # tz-aware sentinel: hops w/o a ts sort last

    def _order(h: LateralHop):
        # patient-zero-originated hops first; then known timestamps; then by host.
        pz_first = 0 if (patient_zero_host and h.src_host == patient_zero_host) else 1
        return (pz_first, h.ts or _LATE, h.dst_host)

    hops.sort(key=_order)
    # Dedup gaps (the same unmapped source IP can drive several hops into one host).
    gaps = list(dict.fromkeys(gaps))
    return hops, gaps


def _rank(c: Confidence) -> int:
    return {Confidence.false_positive: 0, Confidence.suspicious: 1,
            Confidence.likely: 2, Confidence.confirmed: 3}[c]


def correlate_cross_host(
    case_id: str, bundles: list[HostBundle], ip_map: dict[str, str] | None = None
) -> CrossHostReport:
    ip_map = dict(ip_map or {})
    # Merge in any topology IPs carried on the bundles themselves.
    for b in bundles:
        if b.ip:
            ip_map.setdefault(b.ip, b.host_id)

    pz_pairs = [(b.patient_zero, b.host_id) for b in bundles if b.patient_zero]
    pz_ts, pz_host = (min(pz_pairs, key=lambda x: x[0]) if pz_pairs else (None, None))

    shared = correlate_shared_implants(bundles)
    chain, gaps = build_lateral_chain(bundles, ip_map, pz_host)

    # Spread edges: lateral hops (attributed) + shared-implant reach from patient zero.
    edges: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for h in chain:
        s = h.src_host or (h.src_ip or "?")
        if (s, h.dst_host) not in seen:
            seen.add((s, h.dst_host))
            edges.append((s, h.dst_host, h.method))
    for imp in shared:
        host_ids = [p.host_id for p in imp.hosts]
        if pz_host and pz_host in host_ids:
            for hid in host_ids:
                if hid != pz_host and (pz_host, hid) not in seen:
                    seen.add((pz_host, hid))
                    edges.append((pz_host, hid, f"shared implant {imp.key}"))

    return CrossHostReport(
        case_id=case_id, host_count=len(bundles),
        case_patient_zero_host=pz_host, case_patient_zero_ts=pz_ts,
        shared_implants=shared, lateral_chain=chain, spread_edges=edges, gaps=gaps,
    )


# --------------------------------------------------------------------------- #
# Lint (same contract as the host report: every asserted hop/implant must cite
# a provenance_id that resolves in the immutable logbook).
# --------------------------------------------------------------------------- #
def lint_cross_host(report: CrossHostReport, prov_index: dict) -> dict:
    uncited: list[str] = []

    def _ok(evidence) -> bool:
        return any(e.provenance_id in prov_index for e in evidence)

    for imp in report.shared_implants:
        for p in imp.hosts:
            if not _ok(p.evidence):
                uncited.append(f"implant:{imp.key}@{p.host_id}")
    for h in report.lateral_chain:
        if not _ok(h.evidence):
            uncited.append(f"hop:{h.finding_id}")
    return {"uncited_claims": uncited, "clean": not uncited}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _node(h: str, pz: str | None) -> str:
    return f"**{h}**" + (" _(patient zero)_" if h == pz else "")


def render_case_report(report: CrossHostReport, bundles: list[HostBundle], prov_index: dict) -> str:
    pz = report.case_patient_zero_host
    L: list[str] = []
    L.append(f"# Cross-Host Case Report — {report.case_id}")
    L.append("")
    L.append(f"- **Hosts analysed:** {report.host_count}")
    if pz:
        L.append(f"- **Patient zero:** `{pz}`"
                 + (f" @ {report.case_patient_zero_ts.isoformat()} UTC" if report.case_patient_zero_ts else ""))
    L.append(f"- **Shared implants:** {len(report.shared_implants)}  ·  "
             f"**Lateral hops:** {len(report.lateral_chain)}")
    L.append("")

    # --- deterministic campaign narrative ---
    L.append("## Campaign summary  _(deterministic)_")
    L.append("")
    L.append(_campaign_summary(report))
    L.append("")

    # --- host roster ---
    L.append("## Host roster")
    L.append("")
    L.append("| Host | OS | Role | IP | Confirmed | Likely | Suspicious |")
    L.append("|------|----|------|----|-----------|--------|------------|")
    for b in sorted(bundles, key=lambda x: x.host_id):
        c = sum(1 for f in b.findings if f.confidence == Confidence.confirmed)
        lk = sum(1 for f in b.findings if f.confidence == Confidence.likely)
        su = sum(1 for f in b.findings if f.confidence == Confidence.suspicious)
        marker = " ⬅ patient zero" if b.host_id == pz else ""
        L.append(f"| `{b.host_id}`{marker} | {b.os or '?'} | {b.role.value} | "
                 f"{b.ip or '-'} | {c} | {lk} | {su} |")
    L.append("")

    # --- shared implants ---
    L.append(f"## Shared implants across hosts ({len(report.shared_implants)})")
    L.append("")
    if not report.shared_implants:
        L.append("_No malicious artifact was observed on more than one host._")
        L.append("")
    for imp in report.shared_implants:
        host_list = ", ".join(f"`{p.host_id}`" for p in imp.hosts)
        L.append(f"### `{imp.key}` — on {len(imp.hosts)} hosts: {host_list}")
        L.append(f"_{imp.label}_")
        L.append("")
        for p in imp.hosts:
            L.append(f"- **`{p.host_id}`** · {p.confidence.value} · paths: "
                     + ", ".join(f"`{x}`" for x in p.paths))
            for e in p.evidence:
                line, _ = _cite(e, prov_index)
                L.append(f"    - {line}")
        L.append("")

    # --- lateral chain ---
    L.append(f"## Lateral-movement chain ({len(report.lateral_chain)} hops)")
    L.append("")
    if not report.lateral_chain:
        L.append("_No lateral-movement events were correlated across hosts._")
        L.append("")
    for i, h in enumerate(report.lateral_chain, 1):
        src = f"`{h.src_host}`" if h.src_host else (f"`{h.src_ip}` _(unattributed)_" if h.src_ip else "_unknown source_")
        when = f"{h.ts.isoformat()} UTC · " if h.ts else ""
        who = f" by **{h.actor}**" if h.actor else ""
        L.append(f"{i}. {when}{src} → **`{h.dst_host}`** via {h.method}{who}")
        for e in h.evidence:
            line, _ = _cite(e, prov_index)
            L.append(f"    - {line}")
    L.append("")

    # --- spread graph ---
    if report.spread_edges:
        L.append("## Spread graph")
        L.append("")
        L.append("```")
        for s, d, why in report.spread_edges:
            L.append(f"{s}  --[{why}]-->  {d}")
        L.append("```")
        L.append("")

    if report.gaps:
        L.append(f"## Evidence gaps ({len(report.gaps)})")
        L.append("")
        for g in report.gaps:
            L.append(f"- {g}")
        L.append("")

    L.append("---")
    L.append("_Cross-host correlations are computed by deterministic rules over the "
             "per-host findings; every hop and shared implant cites the same immutable "
             "provenance_id its host finding carried. The language model decides nothing here._")
    return "\n".join(L)


def _campaign_summary(report: CrossHostReport) -> str:
    bits: list[str] = []
    n = report.host_count
    if report.case_patient_zero_host:
        when = (f" at {report.case_patient_zero_ts.isoformat()} UTC"
                if report.case_patient_zero_ts else "")
        bits.append(
            f"Across {n} host(s), the earliest compromise is on "
            f"`{report.case_patient_zero_host}`{when} — patient zero."
        )
    else:
        bits.append(f"Across {n} host(s), no host carried a patient-zero timeline marker.")
    if report.shared_implants:
        top = report.shared_implants[0]
        bits.append(
            f"{len(report.shared_implants)} malicious artifact(s) recur across hosts; "
            f"the most widespread is `{top.key}` on {len(top.hosts)} hosts."
        )
    if report.lateral_chain:
        dests = sorted({h.dst_host for h in report.lateral_chain})
        bits.append(
            f"{len(report.lateral_chain)} lateral-movement hop(s) were correlated, "
            f"reaching {len(dests)} host(s): {', '.join(dests)}."
        )
    if report.spread_edges:
        bits.append(f"The reconstructed spread graph has {len(report.spread_edges)} edge(s).")
    return " ".join(bits)

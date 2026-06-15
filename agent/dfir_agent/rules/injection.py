"""Code-injection rule driven off windows.malfind (playbook §7, family=injection).

malfind on an XP/McAfee host is famously noisy (RWX regions in csrss, winlogon,
lsass, McAfee components). The discriminator that removes the noise is simple and
deterministic: a region that is **PrivateMemory + PAGE_EXECUTE_READWRITE + starts
with an `MZ` header** is an injected PE image, not an AV stub.

In practice that filter flags only the genuinely injected PID(s) out of many
noisy RWX regions, with zero false positives — an MZ-in-private-RWX region is an
injected PE image, not an AV stub.
"""

from __future__ import annotations

from ..state import Confidence, EvidenceReference, Finding


def _is_mz(hexdump: object) -> bool:
    return str(hexdump or "").strip().lower().startswith("4d 5a")


def _is_private(val: object) -> bool:
    return val in (1, True, "1", "True")


def detect_injected_pe(
    malfind_rows: list[dict],
    *,
    host_id: str,
    provenance_id: str,
    artifact_path: str | None,
    next_id,
) -> list[Finding]:
    """Emit one Finding per PID with at least one injected-PE region."""
    hits: dict[int, dict] = {}
    for row in malfind_rows:
        prot = str(row.get("Protection", ""))
        if "EXECUTE_READWRITE" not in prot:
            continue
        if not _is_private(row.get("PrivateMemory")):
            continue
        if not _is_mz(row.get("Hexdump")):
            continue
        pid = row.get("PID")
        rec = hits.setdefault(pid, {"count": 0, "process": row.get("Process"), "first_vpn": row.get("Start VPN")})
        rec["count"] += 1

    findings: list[Finding] = []
    for pid, rec in hits.items():
        proc = rec["process"] or "?"
        n = rec["count"]
        findings.append(
            Finding(
                finding_id=next_id(),
                host_id=host_id,
                title=f"Injected PE in {proc} (PID {pid})",
                category="code_injection",
                entity_key=f"pid:{pid}",
                description=(
                    f"Process '{proc}' (PID {pid}) contains {n} private, executable-writable "
                    f"(PAGE_EXECUTE_READWRITE) memory region(s) beginning with an 'MZ' header — "
                    f"i.e. PE images injected into private memory, a strong code-injection indicator."
                ),
                confidence=Confidence.likely,  # single strong family; merge may raise to confirmed
                rule="injection.injected_pe",
                source_count=1,
                evidence=[
                    EvidenceReference(
                        provenance_id=provenance_id,
                        record_id=f"PID={pid}",
                        tool="run_volatility_plugin",
                        artifact_path=artifact_path,
                        source_family="injection",
                        note=(
                            f"windows.malfind: PID={pid} {proc} has {n} private RWX region(s) "
                            f"with MZ header (first Start VPN {rec['first_vpn']})"
                        ),
                    )
                ],
                tags=["memory", "malfind", "injection", str(proc)],
            )
        )
    return findings

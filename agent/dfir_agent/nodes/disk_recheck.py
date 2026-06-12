"""Disk re-check node — the body of the self-correction loop (Phase 5).

When the first correlation pass finds a suspicious memory lead that names a binary
the disk pass never verified (a hidden process has a name but no path), it routes
HERE. We search the already-parsed $MFT for that name and reconcile:

  * benign Windows binary in a signed location  -> NOT escalated; emit a
    Contradiction ("memory: unlinked & suspicious" vs "disk: legitimate Windows
    file") resolved in favour of "binary is not malware, behaviour-only lead".
    This is the rule that stops a hidden cmd.exe shell being mislabeled an implant.
  * foreign binary present on disk               -> corroborated; attach a
    disk_mft EvidenceReference so the next correlation pass escalates it.

No new tool call is needed — we re-analyse the MFT we already parsed (cited by the
parse_mft provenance_id). The loop runs at most once (state flags + max_iterations).
"""

from __future__ import annotations

from ..rules.benign_allowlist import is_benign_windows_binary
from ..rules.disk_artifacts import search_mft_by_name
from ..state import CaseState, Contradiction, EvidenceReference, ToolResultStatus
from . import NodeContext

_SIGNED_PREFIXES = ("c:\\windows", "c:\\program files")


def _parse_mft_csv(state: CaseState) -> tuple[str, str] | None:
    """Return (mft_csv_path, parse_mft_provenance_id) from the disk pass, if any."""
    for tr in reversed(state.tool_results):
        if tr.tool == "parse_mft" and tr.status == ToolResultStatus.success and tr.output_paths:
            csv = next((p for p in tr.output_paths if str(p).endswith("mft.csv")), tr.output_paths[0])
            return str(csv), tr.provenance_id
    return None


def _findings_named(state: CaseState, name: str):
    low = name.lower()
    return [
        f for f in state.findings
        if f.category == "hidden_process" and any(low == t.lower() for t in f.tags)
    ]


async def disk_recheck(state: CaseState, ctx: NodeContext) -> CaseState:
    state.disk_recheck_done = True
    state.needs_disk_recheck = False

    info = _parse_mft_csv(state)
    if not info or not state.recheck_names:
        state.gaps.append(f"{state.current_host}: self-correction had no MFT to re-check.")
        ctx.decisions.record(
            agent_name="disk_recheck", step="recheck", inputs_summary=str(state.recheck_names),
            action="no MFT available; nothing rechecked", rationale="Cannot verify on disk without a parsed $MFT.",
        )
        return state

    mft_csv, prov = info
    hits = search_mft_by_name(mft_csv, set(state.recheck_names))

    escalated, disputed, not_found = [], [], []
    for name in state.recheck_names:
        matches = [m for m in hits.get(name.lower(), []) if m.get("full")]
        targets = _findings_named(state, name)
        if not matches:
            not_found.append(name)
            for f in targets:
                f.tags = sorted(set(f.tags) | {"not_on_disk"})
            continue

        if is_benign_windows_binary(name) and all(
            (m["parent"] or "").startswith(_SIGNED_PREFIXES) for m in matches
        ):
            # Benign binary: do NOT escalate. Reconcile memory-vs-disk as a contradiction.
            disputed.append(name)
            locs = ", ".join(sorted({m["parent"] for m in matches if m["parent"]}))
            for f in targets:
                f.tags = sorted(set(f.tags) | {"benign_binary_confirmed"})
            state.contradictions.append(Contradiction(
                contradiction_id=state.next_contradiction_id(),
                host_id=state.current_host,
                claim=f"Is the hidden process '{name}' a malicious binary?",
                source_a=f"memory: '{name}' is unlinked from the active process list (psscan-only)",
                source_b=f"disk: '{name}' is a legitimate Windows binary, present only in {locs}",
                resolution=(
                    f"'{name}' is a first-party Windows binary — NOT malware. The unlinked state "
                    f"is consistent with a terminated/transient shell. Behaviour-only lead; not escalated."
                ),
                evidence=[EvidenceReference(
                    provenance_id=prov, record_id=f"MFT#{matches[0]['entry']}",
                    tool="parse_mft", artifact_path=mft_csv, source_family="disk_mft",
                    note=f"$MFT: {name} found at {locs} (legitimate Windows location)",
                )],
            ))
        else:
            # Foreign binary present on disk -> corroborate the memory lead.
            escalated.append(name)
            best = next((m for m in matches if (m["parent"] or "").startswith(_SIGNED_PREFIXES)), matches[0])
            mei = any("_mei" in (m["parent"] or "") for m in matches)
            note = (
                f"$MFT: foreign binary {name} present at {best['full']} ({best['size']} bytes)"
                + ("; PyInstaller _MEI extraction artifacts also present" if mei else "")
            )
            for f in targets:
                f.paths = sorted(set(f.paths) | {best["full"]})
                f.evidence.append(EvidenceReference(
                    provenance_id=prov, record_id=f"MFT#{best['entry']}",
                    tool="parse_mft", artifact_path=mft_csv, source_family="disk_mft", note=note,
                ))
                f.tags = sorted(set(f.tags) | {"disk_corroborated"} | ({"pyinstaller"} if mei else set()))

    ctx.decisions.record(
        agent_name="disk_recheck", step="reconcile_named_binaries",
        inputs_summary=f"rechecked {state.recheck_names} against $MFT",
        action=f"escalated={escalated} disputed(benign)={disputed} not_on_disk={not_found}",
        rationale=(
            "Memory leads named by binary are verified on disk: foreign binaries corroborate "
            "(add disk_mft), legitimate Windows binaries are disputed (benign), not invented."
        ),
    )
    return state

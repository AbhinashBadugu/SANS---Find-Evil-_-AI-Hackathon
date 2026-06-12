"""Contradiction detection (playbook §7.5).

A Contradiction is emitted when two sources disagree about the same fact and the
disagreement is resolved deterministically. The clearest case on xp-tdungan is a
timestomp: the file's $STANDARD_INFORMATION creation time disagrees with its
$FILE_NAME creation time. The resolution is fixed by NTFS semantics — $FILE_NAME
cannot be backdated by ordinary tooling, so it is authoritative and the SI value
is the forgery.
"""

from __future__ import annotations

import re

from ..state import Contradiction, EvidenceReference, Finding

_FN = re.compile(r"FN-created=([0-9: .-]+?)\s+SI-created=([0-9: .-]+)")


def detect_timestomp_contradictions(
    findings: list[Finding], *, host_id: str, next_id
) -> list[Contradiction]:
    out: list[Contradiction] = []
    for f in findings:
        if "timestomped" not in f.tags:
            continue
        ev = next((e for e in f.evidence if e.note and "[timestomp]" in e.note), None)
        if not ev:
            continue
        m = _FN.search(ev.note or "")
        fn = m.group(1).strip() if m else "?"
        si = m.group(2).strip() if m else "?"
        path = f.paths[0] if f.paths else (f.title or "the file")
        out.append(
            Contradiction(
                contradiction_id=next_id(),
                host_id=host_id,
                claim=f"Creation time of {path}",
                source_a=f"$STANDARD_INFORMATION creation = {si}",
                source_b=f"$FILE_NAME creation = {fn}",
                resolution=(
                    f"$FILE_NAME ({fn}) is authoritative; $STANDARD_INFORMATION ({si}) was "
                    f"backdated — timestomping confirmed. Real drop time is {fn}."
                ),
                evidence=[
                    EvidenceReference(
                        provenance_id=ev.provenance_id, record_id=ev.record_id,
                        tool=ev.tool, artifact_path=ev.artifact_path,
                        source_family="disk_mft", note=ev.note,
                    )
                ],
            )
        )
    return out

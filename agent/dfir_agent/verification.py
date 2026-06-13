"""Adversarial self-verification — refute-before-confirm.

Before a finding stands, the agent plays prosecutor AND defense: a panel of
deterministic *refuters* each states a benign/alternative hypothesis and tries to
disprove the finding using independent evidence. A finding that cannot be
disproven *survives*; one with a holding benign explanation is *refuted*
(false_positive); one with contradicting evidence is *disputed*.

The trial is RECORDED on the finding (`refutation_attempts`, `verification_verdict`)
so the report can show exactly how each finding was challenged. No LLM — every
verdict is deterministic and citable. Behaviour-preserving: the benign refuter is
the existing benign-allowlist guard, generalised into the panel.
"""

from __future__ import annotations

from .rules.benign_allowlist import is_benign_location
from .scoring import STRONG_FAMILIES, families_of
from .state import Confidence, Finding, RefutationAttempt, Verdict


def _attempt(refuter: str, hypothesis: str, supported: bool, note: str = "") -> RefutationAttempt:
    # supported=True  -> the refutation hypothesis HELD (the finding is challenged successfully)
    # supported=False -> the hypothesis was REJECTED (the finding survives this challenge)
    return RefutationAttempt(
        refuter=refuter, hypothesis=hypothesis,
        result="supported" if supported else "rejected", note=note,
    )


def refute_benign_location(f: Finding) -> RefutationAttempt | None:
    """Hypothesis: the file is a legitimate signed-location Windows component.
    Holds only if it sits in a benign location AND no behavioural family corroborates."""
    paths = [p for p in f.paths if p]
    if not paths:
        return None  # nothing to challenge on location
    benign = any(is_benign_location(p) for p in paths)
    has_behavioural = bool(families_of(f) & STRONG_FAMILIES)
    supported = benign and not has_behavioural
    if supported:
        note = "signed Windows location with no behavioural corroboration — innocent explanation holds"
    elif benign:
        note = "benign location, but behavioural evidence (injection/network/disk) overrides it"
    else:
        note = "not a standard signed Windows location"
    return _attempt("benign_location",
                    "the file is a legitimate signed-location Windows component", supported, note)


def refute_independence(f: Finding) -> RefutationAttempt:
    """Hypothesis: the claim rests on a single evidence axis and could be a tool
    artifact. Holds when fewer than two INDEPENDENT evidence families support it
    (correlated plugins like pslist/pstree already collapse to one family)."""
    n = len(families_of(f))
    supported = n < 2
    return _attempt("independence",
                    "the claim rests on a single evidence axis (possible tool artifact)",
                    supported, f"{n} independent evidence family(ies) support this claim")


def refute_contradiction(f: Finding) -> RefutationAttempt | None:
    """Hypothesis: another evidence family contradicts this claim."""
    if not f.contradictions:
        return None
    return _attempt("contradiction", "another evidence family contradicts this claim",
                    True, "; ".join(f.contradictions))


REFUTERS = [refute_benign_location, refute_independence, refute_contradiction]


def verify_finding(f: Finding) -> Verdict:
    """Run the refutation panel on one finding (mutates it: records the trial, sets
    the verdict, and demotes only when a refutation actually holds)."""
    attempts = [a for r in REFUTERS if (a := r(f)) is not None]
    f.refutation_attempts = attempts
    f.independent_families = len(families_of(f))

    benign_held = any(a.refuter == "benign_location" and a.result == "supported" for a in attempts)
    contradicted = any(a.refuter == "contradiction" and a.result == "supported" for a in attempts)

    if benign_held:
        f.confidence = Confidence.false_positive
        f.tags = sorted(set(f.tags) | {"benign_allowlist", "refuted"})
        f.verification_verdict = Verdict.refuted
    elif contradicted:
        f.confidence = Confidence.disputed
        f.verification_verdict = Verdict.disputed
    else:
        # Survives — confidence already set from independent families upstream; we
        # do NOT re-score (behaviour-preserving), we only certify the trial outcome.
        f.verification_verdict = Verdict.survived if attempts else Verdict.unchallenged
    return f.verification_verdict


def adversarial_verify(findings: list[Finding], ctx=None) -> dict[str, int]:
    """Run the panel over all findings. Returns a verdict tally and (if a ctx with a
    decision log is given) records each demotion + a summary in the audit trail."""
    tally = {"survived": 0, "disputed": 0, "refuted": 0, "unchallenged": 0}
    for f in findings:
        if f.confidence == Confidence.false_positive:
            continue  # already excluded upstream
        verdict = verify_finding(f)
        tally[verdict.value] += 1
        if ctx is not None and verdict in (Verdict.refuted, Verdict.disputed):
            ctx.decisions.record(
                agent_name="verifier",
                step="refute",
                inputs_summary=f"{f.finding_id} {f.title[:60]}",
                action=f"{verdict.value} ({f.confidence.value})",
                rationale="; ".join(f"{a.refuter}:{a.result}" for a in f.refutation_attempts) or "no challenge applied",
            )
    if ctx is not None:
        ctx.decisions.record(
            agent_name="verifier", step="panel_summary",
            inputs_summary=f"{len(findings)} findings",
            action=(f"survived={tally['survived']} disputed={tally['disputed']} "
                    f"refuted={tally['refuted']} unchallenged={tally['unchallenged']}"),
            rationale="Every finding above false_positive faced the refutation panel before standing.",
        )
    return tally

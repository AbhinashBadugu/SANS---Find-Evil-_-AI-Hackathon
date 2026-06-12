"""Optional LLM narration (playbook §7: 'the LLM turns structured facts into prose;
it must never invent an artifact, path, hash, or provenance_id').

This is the ONLY place the agent would call a model, and it is strictly additive:
it rewrites an already-correct deterministic summary into nicer prose. If the
`anthropic` library or an ANTHROPIC_API_KEY is missing, narration is skipped and
the caller keeps the deterministic summary — so findings, citations, and
confidence never depend on a model being available.
"""

from __future__ import annotations

import os

_SYSTEM = (
    "You are writing the executive summary of a digital-forensics host report. "
    "Use ONLY the facts provided. Do NOT invent or alter any artifact, path, hash, "
    "PID, timestamp, or provenance id. Do not add findings. Write 2-4 plain "
    "sentences for an incident-response lead. No markdown headers."
)


def narrate_summary(facts: str, *, model: str | None = None) -> str | None:
    """Return LLM-narrated prose, or None if narration is unavailable.

    `facts` is the deterministic, already-cited summary text. The model only
    rephrases it; the caller still ships the deterministic citations.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # noqa: PLC0415
    except ImportError:
        return None
    model = model or os.getenv("DFIR_NARRATE_MODEL", "claude-sonnet-4-6")
    try:
        client = anthropic.Anthropic()
        msg = client.messages.create(
            model=model,
            max_tokens=500,
            system=_SYSTEM,
            messages=[{"role": "user", "content": f"Facts:\n{facts}\n\nExecutive summary:"}],
        )
        parts = [b.text for b in msg.content if getattr(b, "type", None) == "text"]
        text = "".join(parts).strip()
        return text or None
    except Exception:  # noqa: BLE001 — narration must never break the report
        return None

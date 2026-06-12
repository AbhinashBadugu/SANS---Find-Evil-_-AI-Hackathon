"""The agent decision log (playbook §3) — the reasoning trace.

This is NOT the MCP provenance log. Provenance proves the *evidence* (written by
the server, immutable, court-grade). This log explains the *agent*: which node
ran, why, what it concluded, what it skipped. A Finding cites provenance IDs,
never decision IDs. The two files must never be blended.

Location: <case_root>/cases/<case>/hosts/<host>/agent/agent_decisions.jsonl
"""

from __future__ import annotations

from pathlib import Path

from .state import AgentDecision


class DecisionLog:
    """Append-only writer for one host's agent_decisions.jsonl."""

    def __init__(self, case_root: str | Path, case_id: str, host_id: str) -> None:
        self.dir = Path(case_root) / "cases" / case_id / "hosts" / host_id / "agent"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "agent_decisions.jsonl"
        self._n = self._count_existing()

    def _count_existing(self) -> int:
        if not self.path.exists():
            return 0
        return sum(1 for line in self.path.open("r", encoding="utf-8") if line.strip())

    def record(
        self,
        *,
        agent_name: str,
        step: str,
        inputs_summary: str,
        action: str,
        rationale: str,
    ) -> AgentDecision:
        self._n += 1
        decision = AgentDecision(
            decision_id=f"dec-{self._n:06d}",
            agent_name=agent_name,
            step=step,
            inputs_summary=inputs_summary,
            action=action,
            rationale=rationale,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(decision.model_dump_json() + "\n")
        return decision

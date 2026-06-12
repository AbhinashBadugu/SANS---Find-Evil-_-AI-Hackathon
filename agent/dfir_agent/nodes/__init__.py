"""Graph nodes (the agents of playbook §1).

Every node has the same contract so the wiring stays LangGraph-compatible:

    async def node(state: CaseState, ctx: NodeContext) -> CaseState

A node (1) reads what it needs from `state`, (2) makes MCP calls via `ctx.client`,
(3) writes ToolResults + draft Findings into `state`, and (4) appends an
AgentDecision via `ctx.decisions`. Nodes never finalize confidence — only the
correlation node does (later phase).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..decisions import DecisionLog
from ..mcp_client import ForensicMCPClient


@dataclass
class NodeContext:
    client: ForensicMCPClient
    decisions: DecisionLog
    case_root: str

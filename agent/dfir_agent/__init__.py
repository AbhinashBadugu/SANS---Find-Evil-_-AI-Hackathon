"""DFIR investigation agent.

Drives the read-only forensic MCP server. The agent NEVER runs shell or touches
evidence directly: every evidence action is one MCP tool call, and every fact it
reports cites a `provenance_id` from that call's logbook line.

Division of labour (the anti-hallucination guarantee):
  - the LLM (later phases) only EXTRACTS facts and NARRATES prose,
  - deterministic Python (rules/ + scoring.py) DECIDES and SCORES.
"""

__version__ = "0.1.0"

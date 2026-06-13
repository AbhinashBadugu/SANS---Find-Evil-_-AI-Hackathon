"""The agent's ONLY door to evidence: a thin async wrapper over the MCP client.

The agent has no `subprocess`, no shell, no filesystem mutation. It opens a stdio
connection to the forensic MCP server and calls the allowlisted tools. Every call
returns the server's structured response (including a `provenance_id`); this module
just transports it.

If a capability isn't one of the server's tools, there is no method here to reach
it — that is the architectural guardrail, not a policy we enforce in prose.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Repo layout: <repo>/agent/dfir_agent/mcp_client.py  ->  <repo>/mcp_server
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MCP_SERVER_DIR = _REPO_ROOT / "mcp_server"
_DEFAULT_PYTHON = _MCP_SERVER_DIR / ".venv" / "bin" / "python"

# The exact set of tools the server exposes (playbook §2). Listing them here is
# documentation only — the server is still the enforcement boundary.
KNOWN_TOOLS = {
    "hash_evidence",
    "extract_archive",
    "verify_ewf",
    "open_ewf",
    "close_ewf",
    "inspect_disk",
    "extract_artifacts",
    "run_volatility_plugin",
    "parse_mft",
    "parse_registry",
    "parse_evtx",
    "parse_shimcache",
    "parse_evt_legacy",
    "carve_network_artifacts",
    "generate_timeline",
    "filter_timeline",
    "read_artifact",
}


class MCPToolError(RuntimeError):
    """The MCP call itself failed at the protocol layer (not a forensic 'failed' status)."""


class ForensicMCPClient:
    """Async context manager that spawns the server and exposes `call()`.

    Usage:
        async with ForensicMCPClient() as client:
            resp = await client.call("hash_evidence", case_id=..., host_id=..., evidence_path=...)
    """

    def __init__(
        self,
        server_dir: Path | str = _MCP_SERVER_DIR,
        python_bin: Path | str | None = None,
    ) -> None:
        self.server_dir = Path(server_dir)
        self.python_bin = Path(python_bin) if python_bin else _DEFAULT_PYTHON
        if not self.python_bin.exists():
            # Fall back to the interpreter running us (must have `mcp` + `forensic_mcp`).
            self.python_bin = Path(sys.executable)
        self._session: ClientSession | None = None
        self._stdio_cm = None
        self._session_cm = None
        self._tool_names: set[str] = set()

    async def __aenter__(self) -> "ForensicMCPClient":
        env = dict(os.environ)
        # Make `forensic_mcp` importable and ensure the server loads its own .env
        # (CASE_ROOT / EVIDENCE_ROOT / allowlist) from its directory.
        env["PYTHONPATH"] = str(self.server_dir) + os.pathsep + env.get("PYTHONPATH", "")
        params = StdioServerParameters(
            command=str(self.python_bin),
            args=["-m", "forensic_mcp.server"],
            cwd=str(self.server_dir),
            env=env,
        )
        self._stdio_cm = stdio_client(params)
        read, write = await self._stdio_cm.__aenter__()
        self._session_cm = ClientSession(read, write)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        listed = await self._session.list_tools()
        self._tool_names = {t.name for t in listed.tools}
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session_cm is not None:
            await self._session_cm.__aexit__(exc_type, exc, tb)
        if self._stdio_cm is not None:
            await self._stdio_cm.__aexit__(exc_type, exc, tb)
        self._session = None

    @property
    def tool_names(self) -> set[str]:
        return set(self._tool_names)

    async def call(self, tool: str, **kwargs: Any) -> dict[str, Any]:
        """Invoke one MCP tool and return its structured response as a dict."""
        if self._session is None:
            raise MCPToolError("client not started (use 'async with ForensicMCPClient()')")
        if self._tool_names and tool not in self._tool_names:
            raise MCPToolError(
                f"Tool {tool!r} is not offered by the server. Available: {sorted(self._tool_names)}"
            )
        result = await self._session.call_tool(tool, kwargs)
        return self._parse(tool, result)

    @staticmethod
    def _parse(tool: str, result: Any) -> dict[str, Any]:
        # Prefer structured output; fall back to parsing the text content block.
        data = getattr(result, "structuredContent", None)
        if isinstance(data, dict):
            # FastMCP wraps non-model returns under {"result": ...} on some versions.
            if "provenance_id" not in data and isinstance(data.get("result"), dict):
                data = data["result"]
            return data
        content = getattr(result, "content", None) or []
        for block in content:
            text = getattr(block, "text", None)
            if text:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    continue
        raise MCPToolError(f"Could not parse response from tool {tool!r}: {result!r}")

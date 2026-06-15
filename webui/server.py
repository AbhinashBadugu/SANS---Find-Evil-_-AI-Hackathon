"""Local web server for the conversational DFIR agent.

  python -m webui.server            # then open http://127.0.0.1:8077

Architecture (the read-only guarantee extends to the UI):

  Browser ──HTTP/SSE──► Starlette ──► chat LLM (orchestrator) ──► read-only tools
                                                                      │
                                              reads pipeline outputs / triggers the
                                              pipeline (which is read-only via MCP)

The chat LLM never touches evidence and has no shell — only the typed tools in
tools.py. REST endpoints work WITHOUT an API key (so the dashboard/demo is usable
offline); only /api/chat needs ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import json
import os
import queue
import threading
from pathlib import Path

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from webui import tools

_STATIC = Path(__file__).resolve().parent / "static"


def _load_dotenv() -> None:
    """Load webui/.env (KEY=VALUE) into the environment without overriding real
    env vars. Keeps the API key out of the shell and out of git (.env is ignored)."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


_load_dotenv()
MODEL = os.getenv("DFIR_CHAT_MODEL", "claude-sonnet-4-6")
MAX_TOOL_TURNS = 12

SYSTEM = """You are the conversational interface to "Find Evil", a deterministic,
read-only DFIR investigation pipeline built on a forensic MCP server. You are an
ORCHESTRATOR and EXPLAINER — you do not analyze raw evidence yourself.

Hard rules (these are the project's anti-hallucination guarantee — never break them):
1. You have NO direct evidence access and NO shell. Your ONLY capabilities are the
   provided tools. The deterministic pipeline and its immutable provenance ledger
   are the source of truth.
2. NEVER state a forensic fact (file, path, hash, IP, PID, confidence tier, time)
   unless it came from a tool result in THIS conversation. If you don't have it,
   call a tool to get it, or say plainly that the evidence does not support it.
3. Every forensic claim you make must cite the host and a provenance_id from a tool
   result. For high-confidence claims, prefer resolve_provenance to verify the id
   actually resolves before you assert it.
4. You CANNOT change confidence tiers, invent findings, or modify evidence. The
   pipeline assigns confidence deterministically; you only report it.
5. If asked to do something outside the tools (e.g. "delete", "modify evidence",
   "run a shell command"), refuse and explain the architectural read-only design.

Style: concise and precise, talking to a forensic analyst. When you trigger a run,
tell the user whether it was the fast cross-host rebuild or a background full run.

Case selection — stay universal; never assume a specific case or its topology:
- There is NO hardcoded default case. When the user has not named a case, call
  list_cases to discover what actually exists on this workstation and report that,
  instead of naming any case from memory. If exactly one case is present you may
  proceed with it, but say which one and that you found it via list_cases. If none
  exist, say the workstation has no analyzed cases yet.
- Host names, host→IP topology, and findings are NOT known a priori and differ per
  case and per OS (Windows/Linux/macOS). Obtain them only from tool results
  (list_cases / get_case_summary / list_findings) for the case at hand. Never recite
  host names, IPs, or findings from memory or carry them over from another case."""


# --------------------------------------------------------------------------- #
# Chat: bridge the sync Anthropic SDK tool-loop to async SSE via a queue.
# --------------------------------------------------------------------------- #
class _Ctx:
    jobs = tools.JobManager()


_CTX = _Ctx()


def _run_agent_loop(messages: list[dict], q: "queue.Queue") -> None:
    """Runs in a worker thread. Drives the tool-use loop, pushing SSE events."""
    try:
        import anthropic
    except ImportError:
        q.put({"event": "error", "data": "anthropic SDK not installed"})
        q.put(None)
        return
    if not os.getenv("ANTHROPIC_API_KEY"):
        q.put({"event": "error", "data": "ANTHROPIC_API_KEY is not set. Export it and restart "
               "the server to enable chat. (The dashboard/REST views work without it.)"})
        q.put(None)
        return

    client = anthropic.Anthropic()
    convo = list(messages)
    try:
        for _turn in range(MAX_TOOL_TURNS):
            text_buf: list[str] = []
            with client.messages.stream(
                model=MODEL, max_tokens=2048, system=SYSTEM,
                tools=tools.TOOL_SCHEMAS, messages=convo,
            ) as stream:
                for text in stream.text_stream:
                    text_buf.append(text)
                    q.put({"event": "text", "data": text})
                final = stream.get_final_message()

            convo.append({"role": "assistant", "content": final.content})

            tool_uses = [b for b in final.content if getattr(b, "type", None) == "tool_use"]
            if not tool_uses:
                break

            tool_results = []
            for tu in tool_uses:
                q.put({"event": "tool_use", "data": json.dumps({"name": tu.name, "input": tu.input})})
                result = tools.dispatch(tu.name, tu.input, _CTX)
                q.put({"event": "tool_result", "data": json.dumps(
                    {"name": tu.name, "result": _truncate(result)})})
                tool_results.append({
                    "type": "tool_result", "tool_use_id": tu.id,
                    "content": json.dumps(result)[:20000],
                })
            convo.append({"role": "user", "content": tool_results})
        q.put({"event": "done", "data": ""})
    except Exception as e:  # noqa: BLE001
        q.put({"event": "error", "data": f"{type(e).__name__}: {e}"})
    finally:
        q.put(None)


def _truncate(obj: dict, limit: int = 1200) -> dict:
    """Shrink a tool result for the UI's inline display (full result still goes to the model)."""
    s = json.dumps(obj)
    if len(s) <= limit:
        return obj
    return {"_summary": s[:limit] + " …(truncated for display)"}


async def chat(request: Request) -> EventSourceResponse:
    body = await request.json()
    messages = body.get("messages", [])

    async def event_gen():
        q: queue.Queue = queue.Queue()
        worker = threading.Thread(target=_run_agent_loop, args=(messages, q), daemon=True)
        worker.start()
        while True:
            item = await anyio.to_thread.run_sync(q.get)
            if item is None:
                break
            yield {"event": item["event"], "data": item["data"]}

    return EventSourceResponse(event_gen())


# --------------------------------------------------------------------------- #
# REST (work without an API key — power the dashboard panels + demo)
# --------------------------------------------------------------------------- #
async def health(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True, "model": MODEL,
                         "chat_enabled": bool(os.getenv("ANTHROPIC_API_KEY"))})


async def api_cases(request: Request) -> JSONResponse:
    return JSONResponse(tools.dispatch("list_cases", {}, _CTX))


async def api_summary(request: Request) -> JSONResponse:
    return JSONResponse(tools.dispatch("get_case_summary", {"case": request.path_params["case"]}, _CTX))


async def api_report(request: Request) -> JSONResponse:
    case = request.path_params["case"]
    host = request.query_params.get("host")
    return JSONResponse(tools.dispatch("get_report", {"case": case, "host": host}, _CTX))


async def api_findings(request: Request) -> JSONResponse:
    case = request.path_params["case"]
    args = {"case": case}
    for k in ("host", "confidence", "category"):
        if request.query_params.get(k):
            args[k] = request.query_params[k]
    return JSONResponse(tools.dispatch("list_findings", args, _CTX))


async def api_score(request: Request) -> JSONResponse:
    return JSONResponse(tools.dispatch("score_vs_oracle", {"case": request.path_params["case"]}, _CTX))


async def index(request: Request) -> FileResponse:
    # no-store on the HTML so the browser always re-fetches it (and thus the
    # versioned ?v= asset URLs) — prevents a stale cached page from loading old JS.
    return FileResponse(_STATIC / "index.html", headers={"Cache-Control": "no-store"})


routes = [
    Route("/", index),
    Route("/api/health", health),
    Route("/api/cases", api_cases),
    Route("/api/case/{case}/summary", api_summary),
    Route("/api/case/{case}/report", api_report),
    Route("/api/case/{case}/findings", api_findings),
    Route("/api/case/{case}/score", api_score),
    Route("/api/chat", chat, methods=["POST"]),
    Mount("/static", StaticFiles(directory=str(_STATIC)), name="static"),
]

app = Starlette(routes=routes)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("DFIR_UI_PORT", "8077"))
    print(f"\n  Find Evil — conversational DFIR agent")
    print(f"  http://127.0.0.1:{port}   (model={MODEL}, "
          f"chat={'ON' if os.getenv('ANTHROPIC_API_KEY') else 'OFF — set ANTHROPIC_API_KEY'})\n")
    host = os.getenv("DFIR_UI_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port,
                log_level=os.getenv("DFIR_UI_LOG", "info"), access_log=True)

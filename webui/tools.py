"""Read-only tools exposed to the conversational layer.

GUARDRAIL (this is the whole point): the chat LLM has NO direct evidence access
and NO shell. Its only capabilities are these typed functions, which either
  * read back artifacts the deterministic pipeline already produced (findings,
    reports, provenance, decisions, oracle score), or
  * trigger the pipeline itself (which runs read-only via the MCP server).
No tool here invents a forensic fact, mutates evidence, or changes a confidence
tier. The LLM orchestrates and explains; the pipeline + provenance remain the
source of truth.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from webui import scorer  # noqa: E402

# Case root is env-overridable so the UI is not bound to one machine/path and can
# be pointed at an empty dir for a clean "nothing analyzed yet" demo slate.
CASE_ROOT = os.path.expanduser(
    os.getenv("DFIR_CASE_ROOT", "~/Desktop/DFIR agent/Agent analysis"))
_REPO = Path(__file__).resolve().parents[1]
_AGENT_DIR = _REPO / "agent"
_PY = str(_REPO / "mcp_server" / ".venv" / "bin" / "python")


# --------------------------------------------------------------------------- #
# Background job manager (so a 35-min full run never blocks the chat)
# --------------------------------------------------------------------------- #
class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._seq = 0

    def launch(self, argv: list[str], label: str) -> dict:
        self._seq += 1
        jid = f"job-{self._seq:03d}"
        log_dir = _REPO / "webui" / "_jobs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{jid}.log"
        logf = log_path.open("w", encoding="utf-8")
        proc = subprocess.Popen(  # noqa: S603 — fixed argv, shell=False, our own interpreter
            argv, cwd=str(_AGENT_DIR), stdout=logf, stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        self._jobs[jid] = {
            "id": jid, "label": label, "argv": argv, "pid": proc.pid,
            "log_path": str(log_path), "_proc": proc, "_logf": logf,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return self.status(jid)

    def status(self, jid: str) -> dict:
        j = self._jobs.get(jid)
        if not j:
            return {"error": f"unknown job {jid}"}
        proc = j["_proc"]
        rc = proc.poll()
        running = rc is None
        tail = ""
        try:
            lines = Path(j["log_path"]).read_text(encoding="utf-8", errors="replace").splitlines()
            tail = "\n".join(l for l in lines if "INFO:mcp" not in l)[-1500:]
        except OSError:
            pass
        return {
            "id": jid, "label": j["label"], "running": running,
            "exit_code": rc, "started": j["started"], "log_tail": tail,
        }

    def list(self) -> list[dict]:
        return [self.status(jid) for jid in self._jobs]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _case_dir(case: str) -> Path:
    return Path(CASE_ROOT) / "cases" / case


def _load_findings(case: str, host: str | None = None) -> list[dict]:
    cd = _case_dir(case)
    out: list[dict] = []
    globpat = f"hosts/{host}/agent/findings.json" if host else "hosts/*/agent/findings.json"
    for fj in sorted(cd.glob(globpat)):
        try:
            data = json.loads(fj.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        out.extend(data.get("findings", []))
    return out


def _prov_index(case: str) -> dict[str, dict]:
    p = _case_dir(case) / "provenance.jsonl"
    idx: dict[str, dict] = {}
    if not p.exists():
        return idx
    for line in p.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("provenance_id"):
            idx[rec["provenance_id"]] = rec
    return idx


def _ip_args(host_ips: dict | None) -> list[str]:
    if not host_ips:
        return []
    return ["--host-ip", *[f"{h}={ip}" for h, ip in host_ips.items()]]


# --------------------------------------------------------------------------- #
# Tool implementations  (each takes args dict + ctx; returns JSON-able dict)
# --------------------------------------------------------------------------- #
def list_cases(args: dict, ctx) -> dict:
    root = Path(CASE_ROOT) / "cases"
    cases = []
    if root.exists():
        for cd in sorted(p for p in root.iterdir() if p.is_dir()):
            manifest = cd / "manifest.json"
            hosts = []
            if manifest.exists():
                try:
                    m = json.loads(manifest.read_text(encoding="utf-8"))
                    hosts = list((m.get("hosts") or {}).keys())
                except json.JSONDecodeError:
                    pass
            cases.append({
                "case": cd.name,
                "hosts": hosts,
                "has_case_report": (cd / "CASE_REPORT.md").exists(),
                "has_case_summary": (cd / "case_summary.json").exists(),
                "n_findings_cached": len(_load_findings(cd.name)),
            })
    return {"cases": cases}


def get_case_summary(args: dict, ctx) -> dict:
    p = _case_dir(args["case"]) / "case_summary.json"
    if not p.exists():
        return {"error": "no case_summary.json — run the pipeline first."}
    return json.loads(p.read_text(encoding="utf-8"))


def list_findings(args: dict, ctx) -> dict:
    findings = _load_findings(args["case"], args.get("host"))
    conf = args.get("confidence")
    cat = args.get("category")
    out = []
    for f in findings:
        if conf and f.get("confidence") != conf:
            continue
        if cat and f.get("category") != cat:
            continue
        out.append({
            "finding_id": f.get("finding_id"), "host_id": f.get("host_id"),
            "title": f.get("title"), "category": f.get("category"),
            "confidence": f.get("confidence"), "source_count": f.get("source_count"),
            "paths": f.get("paths"),
            "provenance_ids": [e.get("provenance_id") for e in f.get("evidence", [])],
        })
    return {"count": len(out), "findings": out}


def get_finding(args: dict, ctx) -> dict:
    fid = args["finding_id"]
    for f in _load_findings(args["case"]):
        if f.get("finding_id") == fid:
            return {"finding": f}
    return {"error": f"finding {fid} not found"}


def resolve_provenance(args: dict, ctx) -> dict:
    rec = _prov_index(args["case"]).get(args["provenance_id"])
    if not rec:
        return {"error": f"provenance_id {args['provenance_id']} does not resolve in the logbook",
                "resolves": False}
    return {"resolves": True, "record": rec}


def get_report(args: dict, ctx) -> dict:
    cd = _case_dir(args["case"])
    host = args.get("host")
    if host:
        matches = list(cd.glob(f"hosts/{host}/agent/*_report.md"))
        if not matches:
            return {"error": f"no report for host {host}"}
        return {"host": host, "markdown": matches[0].read_text(encoding="utf-8")}
    cr = cd / "CASE_REPORT.md"
    if not cr.exists():
        return {"error": "no CASE_REPORT.md — run cross-host correlation first."}
    return {"host": None, "markdown": cr.read_text(encoding="utf-8")}


def get_agent_decisions(args: dict, ctx) -> dict:
    host = args["host"]
    p = _case_dir(args["case"]) / "hosts" / host / "agent_decisions.jsonl"
    if not p.exists():
        return {"error": f"no decision log for {host}"}
    limit = int(args.get("limit", 30))
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return {"host": host, "count": len(rows), "decisions": rows[-limit:]}


def score_vs_oracle(args: dict, ctx) -> dict:
    s = scorer.score_agent(CASE_ROOT, args["case"])
    # return a compact headline + write the full report to disk
    md = scorer.render_accuracy_report(s)
    out_dir = _case_dir(args["case"]) / "agent"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "accuracy_report.md").write_text(md, encoding="utf-8")
    (out_dir / "accuracy_score.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    return {
        "recall": s["recall"], "hits": s["hits"], "missed": s["missed"],
        "wrong_milestones": s["wrong_milestones"],
        "citation_quality": s["citation_quality"],
        "report_path": str(out_dir / "accuracy_report.md"),
    }


def run_cross_host(args: dict, ctx) -> dict:
    """Fast (~1s): rebuild CASE_REPORT.md from cached per-host findings."""
    argv = [_PY, "-m", "eval.run_case", "--case", args["case"],
            "--cross-host-only", *_ip_args(args.get("host_ips"))]
    proc = subprocess.run(argv, cwd=str(_AGENT_DIR), capture_output=True, text=True, timeout=120)  # noqa: S603
    out = "\n".join(l for l in proc.stdout.splitlines() if "INFO:mcp" not in l)
    return {"ok": proc.returncode == 0, "stdout_tail": out[-1500:]}


def run_full_pipeline(args: dict, ctx) -> dict:
    """Launch the full per-host pipeline as a BACKGROUND job (minutes). Returns a
    job_id immediately; poll with check_run_status. Never blocks the chat."""
    argv = [_PY, "-m", "eval.run_case", "--case", args["case"], *_ip_args(args.get("host_ips"))]
    if args.get("only"):
        argv += ["--only", *args["only"]]
    job = ctx.jobs.launch(argv, label=f"full pipeline {args['case']}")
    return {"launched": True, "job": job,
            "note": "Running in the background (minutes). Ask me to check status with the job id."}


def run_pipeline_from_evidence(args: dict, ctx) -> dict:
    """Give raw evidence file PATHS; the agent builds the case manifest and leads
    the full autonomous pipeline (BACKGROUND job, minutes). Read-only and fully
    cited. Accepts either `paths` (auto-classified & grouped by host) or `hosts`
    (explicit {host_id: {disk, memory}}). Returns a job_id; poll check_run_status."""
    paths = args.get("paths") or []
    hosts = args.get("hosts") or {}
    if not paths and not hosts:
        return {"error": "give evidence: 'paths' (list) and/or 'hosts' ({id:{disk,memory}})."}

    # Positionals FIRST (before --case) so the nargs='*' options never eat them.
    argv = [_PY, "-m", "eval.run_from_evidence", *[str(p) for p in paths], "--case", args["case"]]
    for host_id, spec in hosts.items():
        part = ["--host", host_id]
        if spec.get("disk"):
            part.append(f"disk={spec['disk']}")
        if spec.get("memory"):
            part.append(f"memory={spec['memory']}")
        argv += part
    if args.get("evidence_root"):
        argv += ["--evidence-root", str(args["evidence_root"])]
    argv += _ip_args(args.get("host_ips"))
    if args.get("only"):
        argv += ["--only", *args["only"]]

    job = ctx.jobs.launch(argv, label=f"evidence intake {args['case']}")
    return {"launched": True, "job": job,
            "note": "The agent is hashing, mounting, and analysing the evidence in the "
                    "background (minutes). Ask me to check status with the job id."}


def check_run_status(args: dict, ctx) -> dict:
    return ctx.jobs.status(args["job_id"])


# --------------------------------------------------------------------------- #
# Registry + dispatch
# --------------------------------------------------------------------------- #
_IMPL = {
    "list_cases": list_cases,
    "get_case_summary": get_case_summary,
    "list_findings": list_findings,
    "get_finding": get_finding,
    "resolve_provenance": resolve_provenance,
    "get_report": get_report,
    "get_agent_decisions": get_agent_decisions,
    "score_vs_oracle": score_vs_oracle,
    "run_cross_host": run_cross_host,
    "run_full_pipeline": run_full_pipeline,
    "run_pipeline_from_evidence": run_pipeline_from_evidence,
    "check_run_status": check_run_status,
}

_CASE = {"type": "string", "description": "case id, e.g. 'srl2015'"}

TOOL_SCHEMAS = [
    {"name": "list_cases", "description": "List forensic cases and their hosts, with whether reports/findings exist.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_case_summary", "description": "Per-host metrics + the cross-host (Phase 8) summary for a case.",
     "input_schema": {"type": "object", "properties": {"case": _CASE}, "required": ["case"]}},
    {"name": "list_findings",
     "description": "List the agent's structured findings. Filter by host, confidence "
                    "(confirmed|likely|suspicious|false_positive), or category. Each carries provenance_ids.",
     "input_schema": {"type": "object", "properties": {
         "case": _CASE, "host": {"type": "string"}, "confidence": {"type": "string"},
         "category": {"type": "string"}}, "required": ["case"]}},
    {"name": "get_finding", "description": "Full detail of one finding incl. every cited EvidenceReference.",
     "input_schema": {"type": "object", "properties": {"case": _CASE, "finding_id": {"type": "string"}},
                      "required": ["case", "finding_id"]}},
    {"name": "resolve_provenance",
     "description": "Resolve a provenance_id against the immutable logbook (tool, argv, output paths, times). "
                    "Use this to VERIFY a citation before asserting a fact.",
     "input_schema": {"type": "object", "properties": {"case": _CASE, "provenance_id": {"type": "string"}},
                      "required": ["case", "provenance_id"]}},
    {"name": "get_report", "description": "Return a rendered Markdown report: a host's report (pass host) "
                                          "or the cross-host CASE_REPORT.md (omit host).",
     "input_schema": {"type": "object", "properties": {"case": _CASE, "host": {"type": "string"}},
                      "required": ["case"]}},
    {"name": "get_agent_decisions", "description": "The agent's reasoning trace (decision log) for a host.",
     "input_schema": {"type": "object", "properties": {"case": _CASE, "host": {"type": "string"},
                      "limit": {"type": "integer"}}, "required": ["case", "host"]}},
    {"name": "score_vs_oracle",
     "description": "Score the agent's reports against the evidence-verified oracle_v2: weighted recall, "
                    "wrong milestones, citation quality, extra-unsupported. Writes the accuracy report.",
     "input_schema": {"type": "object", "properties": {"case": _CASE}, "required": ["case"]}},
    {"name": "run_cross_host",
     "description": "FAST (~1s): rebuild the cross-host CASE_REPORT.md from cached per-host findings. "
                    "Optionally pass host_ips {host_id: ip} to attribute lateral hops.",
     "input_schema": {"type": "object", "properties": {"case": _CASE,
                      "host_ips": {"type": "object"}}, "required": ["case"]}},
    {"name": "run_full_pipeline",
     "description": "Launch the FULL per-host analysis (memory+disk+timeline+correlation, MINUTES) as a "
                    "background job. Returns a job_id immediately. Optionally host_ips and a host subset 'only'.",
     "input_schema": {"type": "object", "properties": {"case": _CASE, "host_ips": {"type": "object"},
                      "only": {"type": "array", "items": {"type": "string"}}}, "required": ["case"]}},
    {"name": "run_pipeline_from_evidence",
     "description": "Give RAW EVIDENCE FILE PATHS and the agent leads the whole pipeline from scratch "
                    "(hash -> mount -> memory+disk+timeline -> correlation -> cross-host report) as a "
                    "background job (minutes). Read-only and fully cited; paths must sit under the "
                    "evidence root. Use 'paths' for files it should auto-classify (disk vs memory) and "
                    "group by host, or 'hosts' to map them explicitly. Returns a job_id.",
     "input_schema": {"type": "object", "properties": {
         "case": _CASE,
         "paths": {"type": "array", "items": {"type": "string"},
                   "description": "evidence files; auto-classified & grouped by host from the filename"},
         "hosts": {"type": "object",
                   "description": "explicit map {host_id: {disk: path, memory: path}}"},
         "evidence_root": {"type": "string",
                           "description": "read-only root the files live under (default: auto common parent)"},
         "host_ips": {"type": "object"},
         "only": {"type": "array", "items": {"type": "string"}}},
         "required": ["case"]}},
    {"name": "check_run_status", "description": "Check a background pipeline job by id (running?, exit code, log tail).",
     "input_schema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}},
]


def dispatch(name: str, args: dict, ctx) -> dict:
    fn = _IMPL.get(name)
    if not fn:
        return {"error": f"unknown tool {name}"}
    try:
        return fn(args or {}, ctx)
    except Exception as e:  # noqa: BLE001 — surface tool errors to the model, don't crash the chat
        return {"error": f"{type(e).__name__}: {e}"}

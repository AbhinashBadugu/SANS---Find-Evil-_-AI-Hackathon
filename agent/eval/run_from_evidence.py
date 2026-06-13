"""Front door: give raw evidence file paths, the agent leads the WHOLE pipeline.

This is the "here are the files, go" entrypoint. It turns a flat list of evidence
images into a case manifest, then runs the SAME autonomous all-host pipeline as
``eval.run_case`` (memory -> disk -> timeline -> dc_identity -> correlation <->
disk_recheck -> report, then cross-host correlation). Every finding it emits cites
a ``provenance_id`` in the MCP server's immutable logbook, or it is dropped by the
citation linter — no evidence without proof.

Usage
-----
Auto mode (classify disk vs memory + group by host from the filename)::

    python -m eval.run_from_evidence --case srl2015 \
        /cases/SRL-2015/xp-tdungan/xp-tdungan-c-drive/xp-tdungan-c-drive.E01 \
        /cases/SRL-2015/xp-tdungan/xp-tdungan-memory/xp-tdungan-memory-raw.001 \
        ... (the other six files for the other three hosts)

Explicit mode (when filename inference would be wrong) — repeatable::

    python -m eval.run_from_evidence --case srl2015 \
        --host xp-tdungan disk=/cases/.../xp-c-drive.E01 memory=/cases/.../xp-mem.001 \
        --host win7-64-nfury disk=/cases/.../nfury-c-drive.E01 memory=/cases/.../nfury-mem.001

Preview the plan + write the manifest WITHOUT running the (multi-hour) pipeline::

    python -m eval.run_from_evidence --case srl2015 --dry-run <paths...>

Guardrail
---------
Every path must (1) exist and (2) resolve under the read-only ``EVIDENCE_ROOT``.
The root defaults to the server's configured value (``/cases``). Pass
``--evidence-root <dir>`` or let it auto-derive the common parent of your files;
either way it is exported so the spawned MCP server enforces that single read-only
root. A path that escapes the root is REFUSED here and would be refused again by
the server — the gate is architectural, not advisory.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.manifest import _classify  # noqa: E402  (OS/role from host id)
from dfir_agent.state import Host  # noqa: E402

DEFAULT_CASE_ROOT = os.path.expanduser("~/Desktop/DFIR agent/Agent analysis")

# --- image classification -------------------------------------------------- #
# Disk-image hints: container formats + common "this is the C: drive" tokens.
_DISK_EXT = {".e01", ".ex01", ".s01", ".dd", ".img", ".raw", ".vmdk", ".vhd", ".vhdx", ".aff", ".aff4"}
_DISK_TOKENS = ("c-drive", "cdrive", "c_drive", "-drive", "hdd", "diskimage", "-disk")
# Memory-image hints: dump formats + "this is RAM" tokens.
_MEM_EXT = {".vmem", ".lime", ".dmp", ".mem", ".bin"}
_MEM_TOKENS = ("memory", "-mem", "_mem", ".mem", "vmem", "lime", "ram", "pagefile", "hiberfil")

# Tokens stripped to derive a host id from a filename.
_STRIP_TOKENS = (
    "c-drive", "cdrive", "c_drive", "memory", "raw", "image", "disk", "dump",
    "hdd", "drive", "mem", "vmem", "lime",
)


def classify_image(path: Path) -> str | None:
    """Return 'disk', 'memory', or None (ambiguous -> caller must use --host)."""
    name = path.name.lower()
    ext = path.suffix.lower()
    is_mem = (ext in _MEM_EXT) or any(t in name for t in _MEM_TOKENS)
    is_disk = (ext in _DISK_EXT) or any(t in name for t in _DISK_TOKENS)
    # A name token is a stronger signal than a generic split-image extension:
    # "*-memory-raw.001" is memory even though .001/.raw can be either.
    if any(t in name for t in _MEM_TOKENS) and not any(t in name for t in _DISK_TOKENS):
        return "memory"
    if any(t in name for t in _DISK_TOKENS) and not any(t in name for t in _MEM_TOKENS):
        return "disk"
    if is_disk and not is_mem:
        return "disk"
    if is_mem and not is_disk:
        return "memory"
    # Split raw with no naming hint (e.g. a bare ".001") is genuinely ambiguous.
    if ext in {".001", ".raw"}:
        return None
    return None


def infer_host_id(path: Path) -> str:
    """Derive a stable host id from a filename by stripping role/type/IP tokens.

    xp-tdungan-c-drive.E01        -> xp-tdungan
    xp-tdungan-memory-raw.001     -> xp-tdungan
    win7-64-nfury-10.3.58.6.E01   -> win7-64-nfury
    """
    name = path.stem.lower()
    if name.endswith(".001") or name.endswith(".raw"):  # double-suffix like x.dd.001
        name = name.rsplit(".", 1)[0]
    name = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "", name)   # strip any IPv4
    for tok in _STRIP_TOKENS:
        name = name.replace(tok, "")
    name = re.sub(r"-?\d{3}$", "", name)                  # trailing split index
    name = re.sub(r"[-_.]+", "-", name).strip("-")
    return name or path.stem.lower()


# --- evidence -> host specs ------------------------------------------------- #
def _add(specs: dict[str, dict], host_id: str, kind: str, path: Path) -> None:
    slot = "disk_image" if kind == "disk" else "memory_image"
    host = specs.setdefault(host_id, {})
    if host.get(slot) and host[slot] != str(path):
        raise SystemExit(
            f"ERROR: two {kind} images map to host {host_id!r}:\n"
            f"  {host[slot]}\n  {path}\n"
            f"Filename inference is ambiguous — use explicit --host {host_id} "
            f"{slot.split('_')[0]}=<path> to disambiguate."
        )
    host[slot] = str(path)


def collect_specs(paths: list[str], host_args: list[list[str]]) -> dict[str, dict]:
    specs: dict[str, dict] = {}

    # Explicit --host id disk=.. memory=..
    for group in host_args:
        if not group:
            continue
        host_id, *kvs = group
        for kv in kvs:
            if "=" not in kv:
                raise SystemExit(f"ERROR: --host {host_id}: expected key=path, got {kv!r}")
            key, _, val = kv.partition("=")
            key = key.strip().lower()
            kind = {"disk": "disk", "disk_image": "disk", "e01": "disk",
                    "memory": "memory", "mem": "memory", "memory_image": "memory"}.get(key)
            if kind is None:
                raise SystemExit(f"ERROR: --host {host_id}: unknown key {key!r} (use disk= or memory=)")
            _add(specs, host_id, kind, Path(val).expanduser())

    # Positional auto-classified paths
    for p in paths:
        path = Path(p).expanduser()
        kind = classify_image(path)
        if kind is None:
            raise SystemExit(
                f"ERROR: cannot tell if {path.name!r} is a disk or memory image.\n"
                f"Pass it explicitly: --host <id> disk={path}  (or memory={path})."
            )
        _add(specs, infer_host_id(path), kind, path)

    return specs


# --- validation against the read-only evidence root ------------------------- #
def _resolve_root(specs: dict[str, dict], explicit_root: str | None) -> Path:
    all_paths = [Path(v) for h in specs.values() for v in h.values()]
    if explicit_root:
        return Path(explicit_root).expanduser().resolve()
    env_root = Path(os.getenv("EVIDENCE_ROOT", "/cases")).expanduser().resolve()
    if all(_under(p, env_root) for p in all_paths):
        return env_root  # everything already under the configured root — keep it
    # Otherwise derive the tightest common parent so the server can read them.
    parents = [str(p.expanduser().resolve().parent) for p in all_paths]
    return Path(os.path.commonpath(parents)).resolve()


def _under(path: Path, root: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root)
        return True
    except (ValueError, OSError):
        return False


def validate(specs: dict[str, dict], root: Path) -> list[str]:
    problems: list[str] = []
    for host_id, slots in specs.items():
        for slot, p in slots.items():
            path = Path(p).expanduser()
            if not path.exists():
                problems.append(f"{host_id}: {slot} does not exist: {p}")
                continue
            if not _under(path, root):
                problems.append(f"{host_id}: {slot} escapes EVIDENCE_ROOT {root}: {p}")
    return problems


# --- manifest --------------------------------------------------------------- #
def build_manifest(specs: dict[str, dict]) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    for host_id, slots in specs.items():
        os_name, role = _classify(host_id)
        hosts[host_id] = Host(
            host_id=host_id, os=os_name, role=role,
            memory_image=slots.get("memory_image"),
            disk_image=slots.get("disk_image"),
        )
    return hosts


def write_manifest(case_root: str, case_id: str, hosts: dict[str, Host]) -> Path:
    out = Path(case_root) / "cases" / case_id / "manifest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {"case_id": case_id, "hosts": {hid: h.model_dump() for hid, h in hosts.items()}},
            indent=2,
        ),
        encoding="utf-8",
    )
    return out


def _print_plan(case_id: str, root: Path, hosts: dict[str, Host], manifest_path: Path) -> None:
    print(f"\n=== EVIDENCE INTAKE PLAN: {case_id} ===")
    print(f"  EVIDENCE_ROOT (read-only): {root}")
    print(f"  manifest:                  {manifest_path}")
    print(f"  hosts:                     {len(hosts)}\n")
    print(f"  {'host_id':24} {'os':22} {'role':12} {'disk':5} {'memory'}")
    for h in hosts.values():
        print(f"  {h.host_id:24} {(h.os or '-'):22} {h.role.value:12} "
              f"{'yes' if h.disk_image else ' no ':5} {'yes' if h.memory_image else 'no'}")


def _parse_ip_map(host_ip: list[str]) -> dict[str, str]:
    ip_map: dict[str, str] = {}
    for pair in host_ip:
        if "=" in pair:
            host, ip = pair.split("=", 1)
            ip_map[ip.strip()] = host.strip()
            ip_map[host.strip()] = ip.strip()
    return ip_map


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Give evidence file paths; the agent builds the manifest and "
                    "leads the full autonomous pipeline (read-only, fully cited).")
    ap.add_argument("paths", nargs="*", help="evidence files (auto-classified & grouped by host)")
    ap.add_argument("--case", required=True, help="case id, e.g. srl2015")
    ap.add_argument("--case-root", default=DEFAULT_CASE_ROOT)
    ap.add_argument("--host", action="append", nargs="+", default=[],
                    metavar="HOST_ID KEY=PATH",
                    help="explicit host spec: --host <id> disk=<path> memory=<path> (repeatable)")
    ap.add_argument("--evidence-root", default=None,
                    help="read-only root the MCP server may read under (default: auto / $EVIDENCE_ROOT)")
    ap.add_argument("--host-ip", nargs="*", default=[],
                    help="topology facts for lateral-hop attribution, e.g. --host-ip xp-tdungan=10.3.58.7")
    ap.add_argument("--only", nargs="*", help="restrict the run to a subset of host_ids")
    ap.add_argument("--dry-run", action="store_true",
                    help="build + validate + write the manifest and print the plan, then stop")
    args = ap.parse_args()

    if not args.paths and not args.host:
        ap.error("no evidence given — pass file paths and/or --host specs")

    specs = collect_specs(args.paths, args.host)
    if not specs:
        ap.error("no usable evidence images found")

    root = _resolve_root(specs, args.evidence_root)
    problems = validate(specs, root)
    if problems:
        print("EVIDENCE VALIDATION FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    hosts = build_manifest(specs)
    manifest_path = write_manifest(args.case_root, args.case, hosts)
    _print_plan(args.case, root, hosts, manifest_path)

    if args.dry_run:
        print("\n[dry-run] manifest written; pipeline NOT run. "
              "Re-run without --dry-run to analyse.")
        return 0

    # Pin BOTH roots for the spawned MCP server. config.py calls load_dotenv()
    # WITHOUT override, so these env vars win over mcp_server/.env:
    #   EVIDENCE_ROOT -> the server reads ONLY under this (read-only) root.
    #   CASE_ROOT     -> the server writes provenance/outputs HERE, the same dir
    #                    the agent reads them from, so the citation linter resolves
    #                    every provenance_id (agent root and server root cannot drift).
    os.environ["EVIDENCE_ROOT"] = str(root)
    os.environ["CASE_ROOT"] = str(Path(args.case_root).expanduser().resolve())

    # Reuse the proven all-host pipeline + cross-host correlation verbatim.
    from eval.run_case import _run  # noqa: PLC0415 — imported after env is set

    ip_map = _parse_ip_map(args.host_ip)
    print(f"\n>>> launching autonomous pipeline on {len(hosts)} host(s) "
          f"(EVIDENCE_ROOT={root}) ...", flush=True)
    cs = asyncio.run(_run(args.case, args.case_root, args.only, ip_map=ip_map))

    hosts_res = cs.get("hosts", {})
    reports = sum(1 for m in hosts_res.values() if m.get("report_path"))
    all_clean = all(m.get("lint_clean") for m in hosts_res.values() if "error" not in m)
    xh = cs.get("cross_host") or {}
    print(f"\n=== DONE: {args.case} ===")
    print(f"  reports:      {reports}/{len(hosts_res)}")
    print(f"  lints clean:  {all_clean}")
    print(f"  case summary: {cs.get('_path')}")
    if xh:
        print(f"  cross-host:   patient_zero={xh.get('patient_zero_host')} "
              f"shared_implants={len(xh.get('shared_implants', []))} "
              f"lateral_hops={xh.get('lateral_hops')} lint_clean={xh.get('lint_clean')}")
        print(f"  case report:  {xh.get('report_path')}")
    return 0 if (reports == len(hosts_res) and all_clean) else 1


if __name__ == "__main__":
    raise SystemExit(main())

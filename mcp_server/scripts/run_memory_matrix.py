"""Milestone 2 driver: run the full approved memory-plugin set across all hosts.

Proves the memory layer scales safely: every run is allowlisted, logged, and a
failure on one plugin/host (e.g. netscan on Windows XP) never stops the rest.
Writes a summary matrix to CASE_ROOT and prints it.
"""

import json
import time
from pathlib import Path

from forensic_mcp.config import CASE_ROOT
from forensic_mcp.schemas import VolatilityPluginRequest
from forensic_mcp.wrappers.volatility import run_volatility_plugin

CASE = "srl2015"

HOSTS = {
    "win2008R2-controller": "/cases/SRL-2015/win2008R2-controller/win2008R2-controller-memory/win2008R2-controller-memory-raw.001",
    "win7-32-nromanoff":     "/cases/SRL-2015/win7-32-nromanoff/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001",
    "win7-64-nfury":         "/cases/SRL-2015/win7-64-nfury/win7-64-nfury-memory/win7-64-nfury-memory-raw.001",
    "xp-tdungan":            "/cases/SRL-2015/xp-tdungan/xp-tdungan-memory/xp-tdungan-memory-raw.001",
}

PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.malfind",
    "windows.svcscan",
    "windows.dlllist",
    "windows.handles",
]

results = []
for host, mem in HOSTS.items():
    for plugin in PLUGINS:
        t0 = time.time()
        r = run_volatility_plugin(
            VolatilityPluginRequest(case_id=CASE, host_id=host, memory_image_path=mem, plugin=plugin)
        )
        secs = round(time.time() - t0, 1)
        size = r.output_path.stat().st_size if (r.output_path and Path(r.output_path).exists()) else 0
        results.append({
            "host": host, "plugin": plugin, "status": r.status.value,
            "seconds": secs, "out_bytes": size, "provenance_id": r.provenance_id,
            "error": r.error,
        })
        print(f"[{host:22}] {plugin:18} {r.status.value:7} {secs:6}s  {size:>10} B  {r.provenance_id}",
              flush=True)

summary_path = CASE_ROOT / "cases" / CASE / "memory_matrix.json"
summary_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

# Matrix view
ok = sum(1 for x in results if x["status"] == "success")
print("\n==== MEMORY MATRIX (status per host x plugin) ====")
header = "plugin".ljust(18) + "".join(h[:14].ljust(15) for h in HOSTS)
print(header)
for plugin in PLUGINS:
    row = plugin.ljust(18)
    for host in HOSTS:
        cell = next(x for x in results if x["host"] == host and x["plugin"] == plugin)
        row += ("OK" if cell["status"] == "success" else "FAIL").ljust(15)
    print(row)
print(f"\n{ok}/{len(results)} runs succeeded. Summary: {summary_path}")

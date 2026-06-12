"""Milestone 3 driver: full disk pipeline per host, all via the safe wrappers.

verify -> open (rootless) -> inspect (offset-0 fallback) -> extract (no admin)
      -> parse MFT / shimcache / registry / evtx -> close mount.
Every step is logged. A failure on one step is recorded and the host continues.
Pass a single host id as argv[1] to run just that host.
"""

import sys
from pathlib import Path

from forensic_mcp.config import CASE_ROOT
from forensic_mcp.schemas import (
    VerifyEwfRequest, OpenEwfRequest, CloseEwfRequest, InspectDiskRequest,
    ExtractArtifactsRequest, ParseMftRequest, ParseRegistryRequest,
    ParseEvtxRequest, ParseShimcacheRequest,
)
from forensic_mcp.wrappers.ewf import verify_ewf
from forensic_mcp.wrappers.mounting import open_ewf, close_ewf
from forensic_mcp.wrappers.disk import inspect_disk, extract_artifacts
from forensic_mcp.wrappers.parsers import parse_mft, parse_registry, parse_evtx, parse_shimcache

CASE = "srl2015"
HOSTS = {
    "win2008R2-controller": "/cases/SRL-2015/win2008R2-controller/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01",
    "win7-32-nromanoff":     "/cases/SRL-2015/win7-32-nromanoff/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01",
    "win7-64-nfury":         "/cases/SRL-2015/win7-64-nfury/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01",
    "xp-tdungan":            "/cases/SRL-2015/xp-tdungan/xp-tdungan-c-drive/xp-tdungan-c-drive.E01",
}
if len(sys.argv) > 1:
    HOSTS = {sys.argv[1]: HOSTS[sys.argv[1]]}


def run_host(host: str, e01: str):
    print(f"\n===== {host} =====", flush=True)

    r = verify_ewf(VerifyEwfRequest(case_id=CASE, host_id=host, e01_path=e01))
    print(f"verify_ewf       : {r.status.value}  ({r.provenance_id})", flush=True)

    o = open_ewf(OpenEwfRequest(case_id=CASE, host_id=host, e01_path=e01))
    print(f"open_ewf         : {o.status.value}  ewf1={o.ewf1_path}", flush=True)
    if o.status.value != "success":
        return
    ewf1, mount_dir = str(o.ewf1_path), str(o.mount_dir)

    try:
        ins = inspect_disk(InspectDiskRequest(case_id=CASE, host_id=host, ewf1_path=ewf1))
        print(f"inspect_disk     : {ins.status.value}  fs={ins.fs_type} offset={ins.offset_bytes} via {ins.method}", flush=True)

        ex = extract_artifacts(ExtractArtifactsRequest(case_id=CASE, host_id=host, ewf1_path=ewf1))
        got = ex.info.get("extracted", {})
        print(f"extract_artifacts: {ex.status.value}  -> {sorted(got.keys())}", flush=True)

        host_root = CASE_ROOT / "cases" / CASE / "hosts" / host
        extracted = host_root / "extracted"

        if (extracted / "$MFT").exists():
            m = parse_mft(ParseMftRequest(case_id=CASE, host_id=host, mft_path=str(extracted / "$MFT")))
            print(f"parse_mft        : {m.status.value}  csvs={m.info.get('csv_count')}", flush=True)

        if (extracted / "SYSTEM").exists():
            s = parse_shimcache(ParseShimcacheRequest(case_id=CASE, host_id=host, system_hive_path=str(extracted / "SYSTEM")))
            print(f"parse_shimcache  : {s.status.value}  csvs={s.info.get('csv_count')}", flush=True)

        reg = parse_registry(ParseRegistryRequest(case_id=CASE, host_id=host, hive_dir=str(extracted)))
        print(f"parse_registry   : {reg.status.value}  csvs={reg.info.get('csv_count')}", flush=True)

        ev = parse_evtx(ParseEvtxRequest(case_id=CASE, host_id=host, evtx_dir=str(extracted / "eventlogs")))
        print(f"parse_evtx       : {ev.status.value}  csvs={ev.info.get('csv_count')}  ({ev.error or 'ok'})", flush=True)
    finally:
        c = close_ewf(CloseEwfRequest(case_id=CASE, host_id=host, mount_dir=mount_dir))
        print(f"close_ewf        : {c.status.value}", flush=True)


for h, e in HOSTS.items():
    run_host(h, e)
print("\nDISK PIPELINE DONE", flush=True)

"""The MCP server: the fixed menu of forensic actions.

Only the functions decorated with @mcp.tool() are reachable by an agent.
There is deliberately NO tool to run shell commands, delete, move, or mount
read-write. The menu IS the security boundary."""

import logging
import sys

from mcp.server.fastmcp import FastMCP

from forensic_mcp.schemas import (
    HashEvidenceRequest,
    VolatilityPluginRequest,
    ReadArtifactRequest,
    VerifyEwfRequest,
    OpenEwfRequest,
    CloseEwfRequest,
    InspectDiskRequest,
    ExtractArtifactsRequest,
    ParseMftRequest,
    ParseRegistryRequest,
    ParseEvtxRequest,
    ParseShimcacheRequest,
    ParseEvtLegacyRequest,
    CarveNetworkRequest,
    GenerateTimelineRequest,
    FilterTimelineRequest,
)
from forensic_mcp.wrappers.hashing import hash_evidence as _hash_evidence
from forensic_mcp.wrappers.volatility import run_volatility_plugin as _run_volatility_plugin
from forensic_mcp.wrappers.artifacts import read_artifact as _read_artifact
from forensic_mcp.wrappers.ewf import verify_ewf as _verify_ewf
from forensic_mcp.wrappers.mounting import open_ewf as _open_ewf, close_ewf as _close_ewf
from forensic_mcp.wrappers.disk import inspect_disk as _inspect_disk, extract_artifacts as _extract_artifacts
from forensic_mcp.wrappers.parsers import (
    parse_mft as _parse_mft, parse_registry as _parse_registry,
    parse_evtx as _parse_evtx, parse_shimcache as _parse_shimcache,
    parse_evt_legacy as _parse_evt_legacy,
)
from forensic_mcp.wrappers.carving import carve_network_artifacts as _carve_network_artifacts
from forensic_mcp.wrappers.timeline import (
    generate_timeline as _generate_timeline, filter_timeline as _filter_timeline,
)

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

mcp = FastMCP("forensic-mcp-server-v1")


@mcp.tool()
def hash_evidence(case_id: str, host_id: str, evidence_path: str) -> dict:
    """Fingerprint (SHA-256) a read-only evidence file. Proves it never changed.
    Evidence must live under EVIDENCE_ROOT. Appends one provenance line."""
    req = HashEvidenceRequest(case_id=case_id, host_id=host_id, evidence_path=evidence_path)
    return _hash_evidence(req).model_dump(mode="json")


@mcp.tool()
def run_volatility_plugin(case_id: str, host_id: str, memory_image_path: str, plugin: str) -> dict:
    """Run ONE approved Volatility 3 plugin against a memory image.
    v1 allows only windows.info. Appends one provenance line."""
    req = VolatilityPluginRequest(
        case_id=case_id, host_id=host_id, memory_image_path=memory_image_path, plugin=plugin
    )
    return _run_volatility_plugin(req).model_dump(mode="json")


@mcp.tool()
def read_artifact(case_id: str, host_id: str, artifact_path: str, max_bytes: int = 200_000) -> dict:
    """Read back one of our own result files (under CASE_ROOT) so results can be reviewed."""
    req = ReadArtifactRequest(
        case_id=case_id, host_id=host_id, artifact_path=artifact_path, max_bytes=max_bytes
    )
    return _read_artifact(req).model_dump(mode="json")


@mcp.tool()
def verify_ewf(case_id: str, host_id: str, e01_path: str) -> dict:
    """Verify an E01 disk image is intact (ewfverify). Read-only."""
    return _verify_ewf(VerifyEwfRequest(case_id=case_id, host_id=host_id, e01_path=e01_path)).model_dump(mode="json")


@mcp.tool()
def open_ewf(case_id: str, host_id: str, e01_path: str) -> dict:
    """Expose an E01 as a read-only raw image (ewf1) via ewfmount. No admin; inherently read-only."""
    return _open_ewf(OpenEwfRequest(case_id=case_id, host_id=host_id, e01_path=e01_path)).model_dump(mode="json")


@mcp.tool()
def close_ewf(case_id: str, host_id: str, mount_dir: str) -> dict:
    """Unmount one of our own ewfmount mountpoints."""
    return _close_ewf(CloseEwfRequest(case_id=case_id, host_id=host_id, mount_dir=mount_dir)).model_dump(mode="json")


@mcp.tool()
def inspect_disk(case_id: str, host_id: str, ewf1_path: str) -> dict:
    """Find where the filesystem starts (mmls, falling back to confirming NTFS at offset 0)."""
    return _inspect_disk(InspectDiskRequest(case_id=case_id, host_id=host_id, ewf1_path=ewf1_path)).model_dump(mode="json")


@mcp.tool()
def extract_artifacts(case_id: str, host_id: str, ewf1_path: str) -> dict:
    """Carve out $MFT, registry hives, and event logs from the image (Sleuth Kit; no admin)."""
    return _extract_artifacts(ExtractArtifactsRequest(case_id=case_id, host_id=host_id, ewf1_path=ewf1_path)).model_dump(mode="json")


@mcp.tool()
def parse_mft(case_id: str, host_id: str, mft_path: str) -> dict:
    """Parse an extracted $MFT into CSV (MFTECmd)."""
    return _parse_mft(ParseMftRequest(case_id=case_id, host_id=host_id, mft_path=mft_path)).model_dump(mode="json")


@mcp.tool()
def parse_registry(case_id: str, host_id: str, hive_dir: str) -> dict:
    """Parse extracted registry hives into CSV (RECmd, fixed batch)."""
    return _parse_registry(ParseRegistryRequest(case_id=case_id, host_id=host_id, hive_dir=hive_dir)).model_dump(mode="json")


@mcp.tool()
def parse_evtx(case_id: str, host_id: str, evtx_dir: str) -> dict:
    """Parse extracted .evtx event logs into CSV (EvtxECmd)."""
    return _parse_evtx(ParseEvtxRequest(case_id=case_id, host_id=host_id, evtx_dir=evtx_dir)).model_dump(mode="json")


@mcp.tool()
def parse_shimcache(case_id: str, host_id: str, system_hive_path: str) -> dict:
    """Parse AppCompatCache (shimcache) from an extracted SYSTEM hive into CSV (AppCompatCacheParser)."""
    return _parse_shimcache(ParseShimcacheRequest(case_id=case_id, host_id=host_id, system_hive_path=system_hive_path)).model_dump(mode="json")


@mcp.tool()
def parse_evt_legacy(case_id: str, host_id: str, evt_dir: str) -> dict:
    """Parse legacy Windows XP/2003 .evt event logs into text (evtexport).
    Use this when parse_evtx finds no data because the host predates .evtx."""
    return _parse_evt_legacy(ParseEvtLegacyRequest(case_id=case_id, host_id=host_id, evt_dir=evt_dir)).model_dump(mode="json")


@mcp.tool()
def carve_network_artifacts(case_id: str, host_id: str, memory_image_path: str) -> dict:
    """Recover network indicators (IPs, domains, packets) from a memory image with
    bulk_extractor. Works on Windows XP where Volatility netscan/netstat do not."""
    return _carve_network_artifacts(CarveNetworkRequest(case_id=case_id, host_id=host_id, memory_image_path=memory_image_path)).model_dump(mode="json")


@mcp.tool()
def generate_timeline(case_id: str, host_id: str, source_path: str) -> dict:
    """Build a Plaso super-timeline (.plaso) from an extracted-artifacts dir or a
    mounted image, using a fixed parser set (mft, registry, evtx/evt, prefetch, lnk, jobs)."""
    return _generate_timeline(GenerateTimelineRequest(case_id=case_id, host_id=host_id, source_path=source_path)).model_dump(mode="json")


@mcp.tool()
def filter_timeline(case_id: str, host_id: str, plaso_path: str, label: str = "timeline",
                    start_date: str | None = None, end_date: str | None = None,
                    keyword: str | None = None) -> dict:
    """Export a Plaso store to CSV (psort) and optionally slice it by date range
    (YYYY-MM-DD) and/or keyword. Dates/keyword are applied deterministically."""
    return _filter_timeline(FilterTimelineRequest(
        case_id=case_id, host_id=host_id, plaso_path=plaso_path, label=label,
        start_date=start_date, end_date=end_date, keyword=keyword)).model_dump(mode="json")


if __name__ == "__main__":
    mcp.run()

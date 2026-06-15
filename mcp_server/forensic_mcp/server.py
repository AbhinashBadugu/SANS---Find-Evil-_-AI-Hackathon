"""The MCP server: the fixed menu of forensic actions.

Only the functions decorated with @mcp.tool() are reachable by an agent.
There is deliberately NO tool to run shell commands, delete, move, or mount
read-write. The menu IS the security boundary."""

import logging
import sys

from mcp.server.fastmcp import FastMCP

from forensic_mcp.schemas import (
    HashEvidenceRequest,
    HashFileRequest,
    CompareHashesRequest,
    JavaCacheRequest,
    FileToolRequest,
    CarveFilesRequest,
    ExtractStringsRequest,
    RegExportRequest,
    ExtractArchiveRequest,
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
from forensic_mcp.wrappers.hashing import (
    hash_evidence as _hash_evidence,
    hash_file as _hash_file,
    compare_hashes_across_hosts as _compare_hashes_across_hosts,
)
from forensic_mcp.wrappers.extraction import extract_archive as _extract_archive
from forensic_mcp.wrappers.java_cache import parse_java_cache as _parse_java_cache
from forensic_mcp.wrappers.registry_config import (
    parse_reg_export as _parse_reg_export,
    extract_c2_from_registry as _extract_c2_from_registry,
)
from forensic_mcp.wrappers.pe_strings import (
    extract_strings as _extract_strings,
    extract_pe_metadata as _extract_pe_metadata,
    detect_pyinstaller as _detect_pyinstaller,
    extract_pdb_paths as _extract_pdb_paths,
    extract_embedded_urls as _extract_embedded_urls,
)
from forensic_mcp.wrappers.volatility import run_volatility_plugin as _run_volatility_plugin
from forensic_mcp.wrappers.artifacts import read_artifact as _read_artifact
from forensic_mcp.wrappers.ewf import verify_ewf as _verify_ewf
from forensic_mcp.wrappers.mounting import open_ewf as _open_ewf, close_ewf as _close_ewf
from forensic_mcp.wrappers.disk import (
    inspect_disk as _inspect_disk, extract_artifacts as _extract_artifacts,
    carve_files as _carve_files,
)
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
def hash_file(case_id: str, host_id: str, file_path: str,
              algorithms: list[str] | None = None) -> dict:
    """Hash one file with md5/sha1/sha256 (in-process, read-only). Accepts a sealed
    evidence file OR a file the agent already extracted/mounted under the case area.
    Records it to the host hash manifest so binaries can be correlated across hosts.
    Appends one provenance line."""
    req = HashFileRequest(case_id=case_id, host_id=host_id, file_path=file_path,
                          algorithms=algorithms or ["md5", "sha1", "sha256"])
    return _hash_file(req).model_dump(mode="json")


@mcp.tool()
def compare_hashes_across_hosts(case_id: str) -> dict:
    """Correlate hashed files across all hosts in the case: returns the binaries
    whose sha256 appears on >=2 hosts (the same implant deployed network-wide).
    Reads only hash manifests the agent already produced. One provenance line."""
    req = CompareHashesRequest(case_id=case_id)
    return _compare_hashes_across_hosts(req).model_dump(mode="json")


@mcp.tool()
def extract_strings(case_id: str, host_id: str, file_path: str,
                    encoding_modes: list[str] | None = None, min_length: int = 4) -> dict:
    """Extract ASCII + UTF-16LE strings from a file (read-only). Returns counts and
    the 'interesting' subset (URLs, PDB paths, suspicious API names). One provenance line."""
    req = ExtractStringsRequest(case_id=case_id, host_id=host_id, file_path=file_path,
                                encoding_modes=encoding_modes or ["ascii", "utf16le"],
                                min_length=min_length)
    return _extract_strings(req).model_dump(mode="json")


@mcp.tool()
def extract_pe_metadata(case_id: str, host_id: str, file_path: str) -> dict:
    """Parse a PE (read-only): machine, compile time, subsystem, imphash, sections
    (with entropy), imported DLLs/functions, suspicious imports, and the embedded
    PDB path. One provenance line."""
    return _extract_pe_metadata(FileToolRequest(case_id=case_id, host_id=host_id, file_path=file_path)).model_dump(mode="json")


@mcp.tool()
def detect_pyinstaller(case_id: str, host_id: str, file_path: str) -> dict:
    """Detect PyInstaller/Python-packed executables by their byte fingerprints
    (read-only). Returns is_pyinstaller + the markers found. One provenance line."""
    return _detect_pyinstaller(FileToolRequest(case_id=case_id, host_id=host_id, file_path=file_path)).model_dump(mode="json")


@mcp.tool()
def extract_pdb_paths(case_id: str, host_id: str, file_path: str) -> dict:
    """Extract embedded PDB build paths from a binary (read-only) — attribution aid.
    One provenance line."""
    return _extract_pdb_paths(FileToolRequest(case_id=case_id, host_id=host_id, file_path=file_path)).model_dump(mode="json")


@mcp.tool()
def extract_embedded_urls(case_id: str, host_id: str, file_path: str) -> dict:
    """Extract embedded URLs and IP:port indicators from a binary (read-only) —
    candidate C2. One provenance line."""
    return _extract_embedded_urls(FileToolRequest(case_id=case_id, host_id=host_id, file_path=file_path)).model_dump(mode="json")


@mcp.tool()
def carve_files(case_id: str, host_id: str, ewf1_path: str,
                paths: list[str], max_files: int = 200) -> dict:
    """Carve specific files out of a mounted raw image by their in-image paths
    (read-only, Sleuth Kit ifind+icat). Used to pull the Java cache, suspect
    binaries, and .reg exports the fixed extract set doesn't. One provenance line."""
    req = CarveFilesRequest(case_id=case_id, host_id=host_id, ewf1_path=ewf1_path,
                            paths=paths, max_files=max_files)
    return _carve_files(req).model_dump(mode="json")


@mcp.tool()
def parse_reg_export(case_id: str, host_id: str, reg_path: str) -> dict:
    """Decode an exported registry file (.reg, UTF-16 or UTF-8), or a directory of
    them (read-only). Returns each key/value with decoded data and any embedded
    URLs/IPs/hostnames/beacon-interval integers. Generic — no filename special-casing.
    One provenance line."""
    return _parse_reg_export(RegExportRequest(case_id=case_id, host_id=host_id, reg_path=reg_path)).model_dump(mode="json")


@mcp.tool()
def extract_c2_from_registry(case_id: str, host_id: str, reg_path: str) -> dict:
    """Parse exported registry files and return ONLY the entries that carry a
    network indicator (URL/IP) — registry-stored C2 configuration. Read-only,
    one provenance line."""
    return _extract_c2_from_registry(RegExportRequest(case_id=case_id, host_id=host_id, reg_path=reg_path)).model_dump(mode="json")


@mcp.tool()
def parse_java_cache(case_id: str, host_id: str, cache_dir: str) -> dict:
    """Parse a host's Java Deployment Cache (read-only): for every cached .idx it
    string-extracts the download URLs, remote JARs, executable/payload URLs, HTTP
    status, content-type, last-modified, and the cached payload file. Version-
    agnostic. One provenance line. The rule layer decides what is a drive-by."""
    req = JavaCacheRequest(case_id=case_id, host_id=host_id, cache_dir=cache_dir)
    return _parse_java_cache(req).model_dump(mode="json")


@mcp.tool()
def extract_archive(case_id: str, host_id: str, archive_path: str) -> dict:
    """Decompress an evidence archive (.7z/.zip/.gz) from EVIDENCE_ROOT into the case
    write-area, so compressed evidence (e.g. a memory image as base-dc-memory.7z) can
    be ingested. Read-only on the original; one provenance line. Returns the extracted
    image path(s)."""
    req = ExtractArchiveRequest(case_id=case_id, host_id=host_id, archive_path=archive_path)
    return _extract_archive(req).model_dump(mode="json")


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

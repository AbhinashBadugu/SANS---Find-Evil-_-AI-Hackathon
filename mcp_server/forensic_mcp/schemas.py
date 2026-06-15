"""Typed request/response shapes. The agent must fill these in correctly,
which is itself a guardrail: it cannot pass arbitrary junk."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class ToolStatus(str, Enum):
    success = "success"
    failed = "failed"


class BaseToolRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=80)
    host_id: str = Field(min_length=1, max_length=120)


class HashEvidenceRequest(BaseToolRequest):
    evidence_path: Path


class HashEvidenceResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    evidence_path: Path
    sha256: str | None = None
    hash_output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class HashFileRequest(BaseToolRequest):
    file_path: Path
    algorithms: list[str] = Field(default_factory=lambda: ["md5", "sha1", "sha256"])


class HashFileResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    file_path: Path
    size: int | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    algorithms: list[str] = Field(default_factory=list)
    hashed_utc: str | None = None
    provenance_id: str
    error: str | None = None


class CompareHashesRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=80)


class HashGroup(BaseModel):
    sha256: str
    size: int | None = None
    hosts: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    provenance_ids: list[str] = Field(default_factory=list)


class CompareHashesResponse(BaseModel):
    status: ToolStatus
    case_id: str
    shared: list[HashGroup] = Field(default_factory=list)
    total_files: int = 0
    output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class CarveFilesRequest(BaseToolRequest):
    ewf1_path: Path
    paths: list[str] = Field(default_factory=list)  # in-image paths to carve out (read-only)
    max_files: int = 200


class CarveFilesResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    carved: dict[str, str] = Field(default_factory=dict)  # in-image path -> carved file on disk
    output_dir: Path | None = None
    provenance_id: str
    error: str | None = None


class FileToolRequest(BaseToolRequest):
    """Shared request for read-only single-file analysis tools (PE/strings/etc.)."""
    file_path: Path


class RegExportRequest(BaseToolRequest):
    reg_path: Path  # a .reg export FILE, or a directory to scan for *.reg (read-only)


class RegConfigEntry(BaseModel):
    key: str
    value_name: str
    value_type: str
    decoded_data: str | None = None
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    intervals: list[int] = Field(default_factory=list)
    source_file: str | None = None


class RegExportResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    reg_path: Path
    entries: list[RegConfigEntry] = Field(default_factory=list)
    entry_count: int = 0
    output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class ExtractC2Response(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    reg_path: Path
    c2_entries: list[RegConfigEntry] = Field(default_factory=list)
    output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class ExtractStringsRequest(FileToolRequest):
    encoding_modes: list[str] = Field(default_factory=lambda: ["ascii", "utf16le"])
    min_length: int = 4


class ExtractStringsResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    file_path: Path
    ascii_count: int = 0
    utf16le_count: int = 0
    interesting: list[str] = Field(default_factory=list)  # urls/paths/pdb/etc.
    output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class PeSection(BaseModel):
    name: str
    virtual_size: int | None = None
    raw_size: int | None = None
    entropy: float | None = None
    characteristics: str | None = None


class PeMetadataResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    file_path: Path
    is_pe: bool = False
    machine: str | None = None
    compile_time_utc: str | None = None
    subsystem: str | None = None
    imphash: str | None = None
    pdb_path: str | None = None
    sections: list[PeSection] = Field(default_factory=list)
    imports: dict[str, list[str]] = Field(default_factory=dict)
    suspicious_imports: list[str] = Field(default_factory=list)
    provenance_id: str
    error: str | None = None


class PyInstallerResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    file_path: Path
    is_pyinstaller: bool = False
    markers: list[str] = Field(default_factory=list)
    provenance_id: str
    error: str | None = None


class PdbPathsResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    file_path: Path
    pdb_paths: list[str] = Field(default_factory=list)
    provenance_id: str
    error: str | None = None


class EmbeddedUrlsResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    file_path: Path
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    provenance_id: str
    error: str | None = None


class JavaCacheRequest(BaseToolRequest):
    cache_dir: Path  # a Java Deployment cache directory (mounted/extracted, read-only)


class JavaIdxRecord(BaseModel):
    idx_path: str
    urls: list[str] = Field(default_factory=list)
    jar_urls: list[str] = Field(default_factory=list)
    payload_urls: list[str] = Field(default_factory=list)
    http_status: str | None = None
    content_type: str | None = None
    last_modified: str | None = None
    server: str | None = None
    cached_file: str | None = None  # sibling file holding the downloaded bytes, if present


class JavaCacheResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    cache_dir: Path
    records: list[JavaIdxRecord] = Field(default_factory=list)
    idx_count: int = 0
    output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class ExtractArchiveRequest(BaseToolRequest):
    archive_path: Path


class ExtractArchiveResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    archive_path: Path
    output_dir: Path | None = None
    extracted_paths: list[str] = Field(default_factory=list)
    primary_image: str | None = None  # largest extracted file (the disk/memory image)
    provenance_id: str
    error: str | None = None


class VolatilityPluginRequest(BaseToolRequest):
    memory_image_path: Path
    plugin: str


class VolatilityPluginResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    plugin: str
    output_path: Path | None = None
    provenance_id: str
    error: str | None = None


class ReadArtifactRequest(BaseToolRequest):
    artifact_path: Path
    max_bytes: int = Field(default=200_000, ge=1, le=5_000_000)


class ReadArtifactResponse(BaseModel):
    status: ToolStatus
    artifact_path: Path
    content: str | None = None
    truncated: bool = False
    bytes_total: int | None = None
    provenance_id: str
    error: str | None = None


class GenericToolResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    output_paths: list[Path] = []
    info: dict = {}
    provenance_id: str
    error: str | None = None


class VerifyEwfRequest(BaseToolRequest):
    e01_path: Path


class OpenEwfRequest(BaseToolRequest):
    e01_path: Path


class OpenEwfResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    mount_dir: Path | None = None
    ewf1_path: Path | None = None
    provenance_id: str
    error: str | None = None


class CloseEwfRequest(BaseToolRequest):
    mount_dir: Path


class InspectDiskRequest(BaseToolRequest):
    ewf1_path: Path


class InspectDiskResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    fs_type: str | None = None
    offset_bytes: int | None = None
    method: str | None = None  # "mmls" or "fsstat-offset-0-fallback"
    provenance_id: str
    error: str | None = None


class ExtractArtifactsRequest(BaseToolRequest):
    ewf1_path: Path


class ParseMftRequest(BaseToolRequest):
    mft_path: Path


class ParseRegistryRequest(BaseToolRequest):
    hive_dir: Path


class ParseEvtxRequest(BaseToolRequest):
    evtx_dir: Path


class ParseShimcacheRequest(BaseToolRequest):
    system_hive_path: Path


class ParseEvtLegacyRequest(BaseToolRequest):
    evt_dir: Path


class CarveNetworkRequest(BaseToolRequest):
    memory_image_path: Path


class GenerateTimelineRequest(BaseToolRequest):
    source_path: Path


class GenerateTimelineResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    plaso_path: Path | None = None
    provenance_id: str
    error: str | None = None


class FilterTimelineRequest(BaseToolRequest):
    plaso_path: Path
    label: str = Field(default="timeline", min_length=1, max_length=60)
    start_date: str | None = None  # "YYYY-MM-DD"
    end_date: str | None = None    # "YYYY-MM-DD"
    keyword: str | None = None


class FilterTimelineResponse(BaseModel):
    status: ToolStatus
    case_id: str
    host_id: str
    full_csv_path: Path | None = None
    filtered_csv_path: Path | None = None
    full_rows: int | None = None
    filtered_rows: int | None = None
    provenance_id: str
    error: str | None = None


class ProvenanceRecord(BaseModel):
    provenance_id: str
    case_id: str
    host_id: str
    tool_name: str
    wrapper_name: str
    command: list[str]
    input_paths: list[Path] = []
    output_paths: list[Path] = []
    start_time: datetime
    end_time: datetime
    exit_code: int | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    input_sha256: str | None = None
    status: Literal["success", "failed"]
    error: str | None = None

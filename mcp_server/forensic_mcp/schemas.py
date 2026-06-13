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

"""Typed contracts threaded through the agent graph (playbook §5).

Hardening baked in here, not left to convention:
  * Confidence is an Enum with a strict order.
  * A Finding above `suspicious` MUST carry at least one EvidenceReference that
    has a provenance_id (validator rejects empty evidence) — a claim with no
    resolvable citation cannot be `confirmed` or `likely`.
  * EvidenceReference carries provenance_id AND record_id, so a citation points
    to a specific line (MFT row / event record / process PID), not just a file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class ToolResultStatus(str, Enum):
    success = "success"
    failed = "failed"
    refused = "refused"


class Confidence(str, Enum):
    confirmed = "confirmed"
    likely = "likely"
    suspicious = "suspicious"
    disputed = "disputed"  # conflicting evidence; cannot be resolved yet
    false_positive = "false_positive"


# Strict ordering used by the deterministic scorer and the empty-evidence rule.
_CONFIDENCE_RANK = {
    Confidence.false_positive: 0,
    Confidence.disputed: 1,
    Confidence.suspicious: 1,
    Confidence.likely: 2,
    Confidence.confirmed: 3,
}


class HostRole(str, Enum):
    # Legacy runtime roles — Phase 1+ nodes/tests depend on these values.
    workstation = "workstation"
    dc = "dc"
    server = "server"
    # Universal roles (host + network-device).
    endpoint = "endpoint"
    domain_controller = "domain_controller"
    file_server = "file_server"
    web_server = "web_server"
    database_server = "database_server"
    mail_server = "mail_server"
    backup_server = "backup_server"
    firewall = "firewall"
    router = "router"
    switch = "switch"
    vpn = "vpn"
    proxy = "proxy"
    ids_ips = "ids_ips"
    unknown = "unknown"


# --------------------------------------------------------------------------- #
# Universal Case Manifest taxonomy (case-agnostic discovery; see case_manifest.py)
# --------------------------------------------------------------------------- #
class OSFamily(str, Enum):
    windows = "windows"
    linux = "linux"
    macos = "macos"
    network_device = "network_device"
    unknown = "unknown"


class EvidenceType(str, Enum):
    # --- generic / coarse (kept for the manifest classifier + back-compat) ---
    disk_image = "disk_image"
    memory_image = "memory_image"
    event_log = "event_log"
    registry_hive = "registry_hive"
    mft = "mft"
    prefetch = "prefetch"
    amcache = "amcache"
    shimcache_source = "shimcache_source"
    timeline = "timeline"
    linux_log = "linux_log"
    macos_log = "macos_log"
    network_log = "network_log"
    generic_log = "generic_log"
    generic_disk_image = "generic_disk_image"
    generic_memory_image = "generic_memory_image"
    generic_timeline = "generic_timeline"
    unknown = "unknown"
    # --- Windows (granular artifact taxonomy) ---
    windows_memory_image = "windows_memory_image"
    windows_disk_image = "windows_disk_image"
    windows_mft = "windows_mft"
    windows_usn_journal = "windows_usn_journal"
    windows_logfile = "windows_logfile"
    windows_registry_hive = "windows_registry_hive"
    windows_evtx = "windows_evtx"
    windows_prefetch = "windows_prefetch"
    windows_amcache = "windows_amcache"
    windows_shimcache_source = "windows_shimcache_source"
    windows_userassist = "windows_userassist"
    windows_bam_dam = "windows_bam_dam"
    windows_lnk = "windows_lnk"
    windows_jumplist = "windows_jumplist"
    windows_recentdocs = "windows_recentdocs"
    windows_shellbags = "windows_shellbags"
    windows_recycle_bin = "windows_recycle_bin"
    windows_browser_history = "windows_browser_history"
    windows_browser_downloads = "windows_browser_downloads"
    windows_powershell_logs = "windows_powershell_logs"
    windows_powershell_history = "windows_powershell_history"
    windows_scheduled_tasks = "windows_scheduled_tasks"
    windows_services = "windows_services"
    windows_srum = "windows_srum"
    windows_firewall_logs = "windows_firewall_logs"
    windows_dns_cache_or_logs = "windows_dns_cache_or_logs"
    windows_rdp_artifacts = "windows_rdp_artifacts"
    windows_smb_artifacts = "windows_smb_artifacts"
    windows_usb_artifacts = "windows_usb_artifacts"
    windows_vss = "windows_vss"
    windows_pagefile = "windows_pagefile"
    windows_hiberfil = "windows_hiberfil"
    windows_crash_dump = "windows_crash_dump"
    windows_wmi_artifacts = "windows_wmi_artifacts"
    windows_bits_artifacts = "windows_bits_artifacts"
    windows_defender_logs = "windows_defender_logs"
    windows_av_logs = "windows_av_logs"
    windows_edr_logs = "windows_edr_logs"
    windows_installer_logs = "windows_installer_logs"
    windows_local_email = "windows_local_email"
    windows_iis_logs = "windows_iis_logs"
    windows_sql_logs = "windows_sql_logs"
    windows_domain_controller_artifacts = "windows_domain_controller_artifacts"
    windows_file_server_artifacts = "windows_file_server_artifacts"
    windows_timeline = "windows_timeline"
    # --- Linux ---
    linux_memory_image = "linux_memory_image"
    linux_disk_image = "linux_disk_image"
    linux_os_release = "linux_os_release"
    linux_auth_log = "linux_auth_log"
    linux_syslog = "linux_syslog"
    linux_messages_log = "linux_messages_log"
    linux_secure_log = "linux_secure_log"
    linux_journal = "linux_journal"
    linux_bash_history = "linux_bash_history"
    linux_zsh_history = "linux_zsh_history"
    linux_cron = "linux_cron"
    linux_systemd_services = "linux_systemd_services"
    linux_ssh_logs = "linux_ssh_logs"
    linux_auditd_logs = "linux_auditd_logs"
    linux_package_logs = "linux_package_logs"
    linux_web_logs = "linux_web_logs"
    linux_database_logs = "linux_database_logs"
    linux_user_activity = "linux_user_activity"
    linux_network_logs = "linux_network_logs"
    linux_timeline = "linux_timeline"
    # --- macOS ---
    macos_memory_image = "macos_memory_image"
    macos_disk_image = "macos_disk_image"
    macos_systemversion_plist = "macos_systemversion_plist"
    macos_unified_logs = "macos_unified_logs"
    macos_plist = "macos_plist"
    macos_launchagents = "macos_launchagents"
    macos_launchdaemons = "macos_launchdaemons"
    macos_system_log = "macos_system_log"
    macos_zsh_history = "macos_zsh_history"
    macos_bash_history = "macos_bash_history"
    macos_browser_history = "macos_browser_history"
    macos_user_activity = "macos_user_activity"
    macos_network_logs = "macos_network_logs"
    macos_timeline = "macos_timeline"
    # --- Network device ---
    firewall_logs = "firewall_logs"
    router_logs = "router_logs"
    switch_logs = "switch_logs"
    vpn_logs = "vpn_logs"
    proxy_logs = "proxy_logs"
    ids_ips_alerts = "ids_ips_alerts"
    dns_logs = "dns_logs"
    dhcp_logs = "dhcp_logs"
    netflow = "netflow"
    pcap = "pcap"
    zeek_logs = "zeek_logs"
    suricata_alerts = "suricata_alerts"
    nat_logs = "nat_logs"
    device_config = "device_config"
    admin_login_logs = "admin_login_logs"
    network_timeline = "network_timeline"


class ArtifactParseStatus(str, Enum):
    """Per-artifact support status — the agent distinguishes ALL of these so it
    never says 'clean' when evidence is merely absent or unsupported."""

    present_and_parsed = "present_and_parsed"
    present_but_wrapper_missing = "present_but_wrapper_missing"
    not_present = "not_present"
    not_applicable = "not_applicable"
    not_collected = "not_collected"
    detected_but_not_implemented = "detected_but_not_implemented"
    parse_failed = "parse_failed"


# --------------------------------------------------------------------------- #
# Evidence + tool I/O
# --------------------------------------------------------------------------- #
class EvidenceFile(BaseModel):
    """One discovered evidence artifact in the Universal Case Manifest.

    Produced by case_manifest.py from filesystem METADATA only (path, name, size).
    `sha256` stays None here — fingerprinting is the MCP `hash_evidence` tool's job,
    so the manifest never reads evidence content or runs a tool.
    """

    evidence_id: str
    host_id: str | None = None  # filled during grouping; None while unassigned
    evidence_path: str
    evidence_type: EvidenceType = EvidenceType.unknown
    os_family: OSFamily = OSFamily.unknown
    host_role: HostRole | None = None
    file_size: int = 0
    sha256: str | None = None
    classification_confidence: Literal["high", "medium", "low"] = "low"
    classification_reason: str = ""
    parse_status: ArtifactParseStatus = ArtifactParseStatus.not_collected
    provenance_id: str | None = None
    is_reference: bool = False  # course/tutorial/baseline material — excluded from host evidence


class EvidenceCapability(BaseModel):
    """What analytic angles a host/device's evidence set supports (derived from
    what was actually found). All default False — absence is never 'clean'."""

    # --- common (any family) ---
    has_memory: bool = False
    has_disk: bool = False
    has_timeline: bool = False
    has_network_logs: bool = False
    has_configuration: bool = False
    has_unknown_evidence: bool = False
    # --- Windows ---
    has_windows_memory: bool = False
    has_windows_disk: bool = False
    has_mft: bool = False
    has_usn_journal: bool = False
    has_logfile: bool = False
    has_registry: bool = False
    has_event_logs: bool = False
    has_prefetch: bool = False
    has_amcache: bool = False
    has_shimcache: bool = False
    has_userassist: bool = False
    has_bam_dam: bool = False
    has_lnk: bool = False
    has_jumplists: bool = False
    has_recentdocs: bool = False
    has_shellbags: bool = False
    has_recycle_bin: bool = False
    has_browser_history: bool = False
    has_browser_downloads: bool = False
    has_powershell_logs: bool = False
    has_powershell_history: bool = False
    has_scheduled_tasks: bool = False
    has_services: bool = False
    has_srum: bool = False
    has_host_network_artifacts: bool = False
    has_vss: bool = False
    has_pagefile: bool = False
    has_hiberfil: bool = False
    has_crash_dumps: bool = False
    has_wmi_artifacts: bool = False
    has_bits_artifacts: bool = False
    has_defender_av_edr_logs: bool = False
    has_rdp_artifacts: bool = False
    has_smb_artifacts: bool = False
    has_usb_artifacts: bool = False
    has_installer_artifacts: bool = False
    has_local_email_artifacts: bool = False
    has_windows_server_role_artifacts: bool = False
    # --- Linux ---
    has_linux_memory: bool = False
    has_linux_disk: bool = False
    has_linux_os_release: bool = False
    has_linux_auth_logs: bool = False
    has_linux_syslog: bool = False
    has_linux_journal: bool = False
    has_linux_auditd: bool = False
    has_linux_shell_history: bool = False
    has_linux_cron: bool = False
    has_linux_systemd: bool = False
    has_linux_ssh_logs: bool = False
    has_linux_package_logs: bool = False
    has_linux_web_logs: bool = False
    has_linux_database_logs: bool = False
    has_linux_network_logs: bool = False
    # --- macOS ---
    has_macos_memory: bool = False
    has_macos_disk: bool = False
    has_macos_systemversion: bool = False
    has_macos_unified_logs: bool = False
    has_macos_plists: bool = False
    has_macos_launchagents: bool = False
    has_macos_launchdaemons: bool = False
    has_macos_shell_history: bool = False
    has_macos_browser_history: bool = False
    has_macos_user_activity: bool = False
    has_macos_network_logs: bool = False
    # --- Network device ---
    has_firewall_logs: bool = False
    has_router_logs: bool = False
    has_switch_logs: bool = False
    has_vpn_logs: bool = False
    has_proxy_logs: bool = False
    has_ids_ips_alerts: bool = False
    has_dns_logs: bool = False
    has_dhcp_logs: bool = False
    has_netflow: bool = False
    has_pcap: bool = False
    has_zeek_logs: bool = False
    has_suricata_alerts: bool = False
    has_nat_logs: bool = False
    has_device_config: bool = False
    has_admin_login_logs: bool = False


class EvidenceReference(BaseModel):
    """A citation that points at one line of tool output, never just a file."""

    provenance_id: str = Field(min_length=1)
    record_id: str | None = None  # e.g. "PID=3296", "EventRecordID=1187", MFT entry
    tool: str | None = None  # the MCP tool that produced it
    artifact_path: str | None = None  # the output file the record lives in
    source_family: str | None = None  # independence axis for scoring (see scoring.py)
    note: str | None = None
    # Universal-model aliases (optional; mirror tool/artifact_path under the names
    # the final schema uses — kept additive so existing rules/tests are untouched).
    host_id: str | None = None
    artifact: str | None = None  # artifact category this citation came from
    tool_name: str | None = None
    output_path: str | None = None
    timestamp: str | None = None


class ToolResult(BaseModel):
    """Outcome of one MCP tool call, mirrored from the server response."""

    tool: str
    status: ToolResultStatus
    provenance_id: str
    host_id: str
    args: dict[str, Any] = Field(default_factory=dict)
    output_paths: list[str] = Field(default_factory=list)
    summary: str | None = None
    error: str | None = None


# --------------------------------------------------------------------------- #
# Findings / narrative objects
# --------------------------------------------------------------------------- #
class Verdict(str, Enum):
    """Outcome of the adversarial verification (refute-before-confirm) pass."""

    survived = "survived"          # challenged and could NOT be disproven
    disputed = "disputed"          # contradicting evidence; unresolved
    refuted = "refuted"            # a benign/alternative explanation held -> false_positive
    unchallenged = "unchallenged"  # no applicable refuter (e.g. nothing to challenge on)


class RefutationAttempt(BaseModel):
    """One documented attempt to DISPROVE a finding (the audit trail of the trial)."""

    refuter: str
    hypothesis: str                       # the benign/alternative explanation that was tested
    result: Literal["rejected", "supported"]  # rejected = finding survives; supported = challenge holds
    note: str = ""


class Finding(BaseModel):
    finding_id: str
    host_id: str
    title: str
    category: str  # e.g. "process_masquerade", "persistence", "lateral_movement"
    description: str
    confidence: Confidence
    rule: str | None = None  # which deterministic rule emitted/last-touched it
    entity_key: str | None = None  # what the claim is ABOUT (e.g. "pid:3296") — merge key
    paths: list[str] = Field(default_factory=list)  # normalized image paths — cross-source merge key
    source_count: int = 0  # distinct independent source families supporting the claim
    evidence: list[EvidenceReference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    # Adversarial verification (refute-before-confirm) — the documented trial.
    verification_verdict: Verdict | None = None
    refutation_attempts: list[RefutationAttempt] = Field(default_factory=list)
    independent_families: int = 0
    # Universal-model additions (optional, additive).
    os_family: OSFamily | None = None
    finding_type: str | None = None  # synonym surface for `category` in the final model
    contradictions: list[str] = Field(default_factory=list)
    mitre_mapping: list[str] = Field(default_factory=list)
    status: str | None = None  # lifecycle status (e.g. "open", "resolved"); distinct from confidence

    @model_validator(mode="after")
    def _require_evidence_above_suspicious(self) -> "Finding":
        # confirmed/likely must cite at least one resolvable provenance_id.
        if _CONFIDENCE_RANK[self.confidence] > _CONFIDENCE_RANK[Confidence.suspicious]:
            has_cite = any(e.provenance_id for e in self.evidence)
            if not has_cite:
                raise ValueError(
                    f"Finding {self.finding_id!r} is {self.confidence.value} but has no "
                    "EvidenceReference with a provenance_id."
                )
        return self


class TimelineEvent(BaseModel):
    ts: datetime
    host_id: str
    source: str  # "mft", "evtx", "prefetch", ...
    description: str
    evidence: list[EvidenceReference] = Field(default_factory=list)


class Contradiction(BaseModel):
    contradiction_id: str
    host_id: str
    claim: str
    source_a: str
    source_b: str
    resolution: str | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)


class HostReport(BaseModel):
    host_id: str
    os: str | None = None
    role: HostRole = HostRole.workstation
    generated_at: datetime = Field(default_factory=_utc_now)
    summary: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Agent reasoning trace (NOT provenance — see playbook §3)
# --------------------------------------------------------------------------- #
class AgentDecision(BaseModel):
    decision_id: str
    agent_name: str  # which node
    step: str  # short slug of the step
    inputs_summary: str  # what it looked at
    action: str  # what it did
    rationale: str  # why
    ts: datetime = Field(default_factory=_utc_now)


# --------------------------------------------------------------------------- #
# Case / host topology + the single threaded state object
# --------------------------------------------------------------------------- #
class Host(BaseModel):
    host_id: str
    os: str | None = None
    role: HostRole = HostRole.workstation
    ip: str | None = None  # topology fact (manifest/operator-supplied) — used to attribute lateral hops
    memory_image: str | None = None
    disk_image: str | None = None
    extracted_dir: str | None = None  # runtime: where disk node carved artifacts (Plaso source)


# --------------------------------------------------------------------------- #
# Universal Case Manifest models (discovery layer — distinct from runtime Host)
# --------------------------------------------------------------------------- #
class ManifestHost(BaseModel):
    """A host as discovered by the Universal Case Manifest Builder.

    Kept separate from the runtime `Host` above (which the analysis nodes consume)
    so making discovery case-agnostic never disturbs Phase 1 execution.
    """

    host_id: str
    hostname: str | None = None
    os_family: OSFamily = OSFamily.unknown
    host_role: HostRole = HostRole.unknown
    evidence_files: list[EvidenceFile] = Field(default_factory=list)
    evidence_capabilities: EvidenceCapability = Field(default_factory=EvidenceCapability)
    classification_confidence: Literal["high", "medium", "low"] = "low"
    classification_reason: str = ""


class CaseManifest(BaseModel):
    case_id: str
    generated_utc: datetime = Field(default_factory=_utc_now)
    case_root: str
    hosts: list[ManifestHost] = Field(default_factory=list)
    unassigned_evidence: list[EvidenceFile] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# OS-family analyzer routing (analyzer registry)
# --------------------------------------------------------------------------- #
class AnalyzerStatus(str, Enum):
    implemented = "implemented"
    detected_but_not_implemented = "detected_but_not_implemented"
    unknown_evidence = "unknown_evidence"
    not_applicable = "not_applicable"


class ArtifactResult(BaseModel):
    """Per-artifact-category outcome. The honest unit of coverage: it records
    whether an artifact was parsed, present-but-unsupported, absent, etc. — so a
    report never claims analysis it did not perform."""

    artifact_type: EvidenceType
    os_family: OSFamily
    host_id: str | None = None
    status: ArtifactParseStatus
    parser_or_wrapper: str | None = None  # MCP wrapper / parser that would handle it
    output_path: str | None = None
    provenance_id: str | None = None
    summary: str | None = None
    reason: str | None = None
    errors: list[str] = Field(default_factory=list)


class CoverageReport(BaseModel):
    """Evidence-coverage section of a report — what was present/parsed/missing.
    Absence is reported explicitly, never as 'clean'."""

    case_id: str
    host_id: str
    os_family: OSFamily
    capabilities: EvidenceCapability = Field(default_factory=EvidenceCapability)
    artifacts_present: list[EvidenceType] = Field(default_factory=list)
    artifacts_parsed: list[EvidenceType] = Field(default_factory=list)
    artifacts_missing: list[EvidenceType] = Field(default_factory=list)
    artifacts_not_collected: list[EvidenceType] = Field(default_factory=list)
    wrappers_missing: list[EvidenceType] = Field(default_factory=list)
    analyzer_not_implemented: bool = False


class AnalyzerOutcome(BaseModel):
    """Result of routing the selected host to exactly one OS-family analyzer."""

    os_family: OSFamily
    analyzer_name: str  # WindowsAnalyzer | LinuxAnalyzer | MacOSAnalyzer | NetworkDeviceAnalyzer | UnknownEvidenceHandler
    status: AnalyzerStatus
    reason: str | None = None
    artifact_results: list[ArtifactResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_capabilities: EvidenceCapability | None = None


class CaseState(BaseModel):
    """The one typed object threaded through every graph node."""

    case_id: str
    case_root: str  # CASE_ROOT (where the MCP server writes; we read back from here)
    hosts: dict[str, Host] = Field(default_factory=dict)
    current_host: str | None = None

    # Universal Case Manifest discovery (Step 3) — optional & additive; legacy path
    # (no evidence_root) is unchanged.
    evidence_root: str | None = None  # folder to scan; None -> legacy manifest behavior
    host_capabilities: dict[str, EvidenceCapability] = Field(default_factory=dict)
    analyzer_outcome: AnalyzerOutcome | None = None  # set by the OS-family analyzer router

    findings: list[Finding] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)

    completed_steps: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)

    # Self-correction loop control (Phase 5), all capped to a single re-check round.
    needs_disk_recheck: bool = False
    disk_recheck_done: bool = False
    self_correction_attempted: bool = False
    recorrelated: bool = False
    recheck_names: list[str] = Field(default_factory=list)

    iteration: int = 0
    max_iterations: int = 12

    # Deep-scan node output (lateral-movement graph for the report).
    lateral_graph: dict | None = None

    # Report node outputs (Phase 6).
    report_path: str | None = None
    report_lint: dict = Field(default_factory=dict)
    report_narrated: bool = False

    # ----- small helpers used by nodes ----- #
    def add_tool_result(self, tr: ToolResult) -> None:
        self.tool_results.append(tr)

    def successful_results(self, tool: str | None = None) -> list[ToolResult]:
        out = [r for r in self.tool_results if r.status == ToolResultStatus.success]
        return [r for r in out if tool is None or r.tool == tool]

    def next_finding_id(self) -> str:
        return f"F-{len(self.findings) + 1:04d}"

    def next_contradiction_id(self) -> str:
        return f"C-{len(self.contradictions) + 1:04d}"

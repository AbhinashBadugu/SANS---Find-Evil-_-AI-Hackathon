"""Registry of capabilities the agent actually implements.

This is the single source of truth for "what can the agent parse/detect today".
The scorer (eval/score_profile.py) uses it to classify a missed validation
milestone as either:

    * missing_parser  -> the capability it needs does not exist yet, OR
    * despite_parser  -> the capability exists but the agent still missed it
                          (a real detection bug, the higher-priority kind).

It is CASE-AGNOSTIC: capability keys describe generic abilities, never IOCs.
As each expansion phase lands, add its key(s) here in the same commit, so the
coverage numbers move only when a real capability is wired end-to-end.
"""

from __future__ import annotations

# --- Phase 0 baseline: what the agent could already do before this expansion ---
IMPLEMENTED_CAPABILITIES: set[str] = {
    "mft",            # parse_mft
    "registry",       # parse_registry (hives via RECmd)
    "evtx",           # parse_evtx
    "evt_legacy",     # parse_evt_legacy (XP .evt)
    "shimcache",      # parse_shimcache
    "volatility",     # run_volatility_plugin (pslist/psscan/pstree/cmdline/netscan/malfind/svcscan)
    "carve_network",  # carve_network_artifacts
    "timeline",       # generate_timeline / filter_timeline (Plaso)
    "disk_recheck",   # disk_recheck node (memory<->disk reconciliation)
    "benign_location",  # rules/benign_allowlist (signed-location suppression — partial)
    # --- Phase 1: universal hashing ---
    "file_hash",        # hash_file (md5/sha1/sha256, evidence or extracted/mounted)
    "hash_correlation", # compare_hashes_across_hosts + rules/hash_correlation
    # --- Phase 2: Java deployment cache ---
    "java_cache",       # parse_java_cache + rules/java_cache (drive-by + download->drop)
    # --- Phase 3: static binary triage ---
    "pe_metadata",      # extract_pe_metadata (imports, sections, pdb, imphash)
    "strings",          # extract_strings / extract_embedded_urls
    "pyinstaller",      # detect_pyinstaller + rules/pe_indicators
    # --- Phase 4: registry export / C2 config ---
    "registry_config",  # parse_reg_export / extract_c2_from_registry + rules/registry_config
    # --- Phase 5: credential access ---
    "cred_access",      # rules/credential_access (detect + logon correlation over existing parses)
    # --- Phase 6: lateral-movement graph ---
    "lateral_graph",    # rules/lateral_graph (normalize 4624/4648/4672/4776/7045 -> graph)
    # --- Phase 7: persistence + exfil-staging expansion ---
    "archive_staging",  # rules/exfil_staging (archive staging + cleanup correlation)
    "persistence_scan", # rules/persistence_scan (service/run-key/scheduled-task)
    # --- Phase 8: benign / IR enrichment ---
    "benign_enrichment",  # dfir_agent.enrichment (config-driven self-correction)
}

# Capability keys planned by upcoming phases (NOT yet implemented). Listed here so
# the profile's `requires:` keys are documented in one place; move a key UP into
# IMPLEMENTED_CAPABILITIES when its phase is wired end-to-end + tested.
PLANNED_CAPABILITIES: dict[str, str] = {
    "file_hash": "Phase 1 — hash_file / hash_suspect_files / compare_hashes_across_hosts",
    "hash_correlation": "Phase 1 — same-hash-across-hosts rule",
}


def is_implemented(capability: str) -> bool:
    return capability in IMPLEMENTED_CAPABILITIES


def classify_miss(required: list[str]) -> str:
    """A milestone needing `required` capabilities was missed. If ANY required
    capability is not implemented, the miss is excused as `missing_parser`;
    otherwise it is a `despite_parser` detection gap."""
    if any(cap not in IMPLEMENTED_CAPABILITIES for cap in required):
        return "missing_parser"
    return "despite_parser"

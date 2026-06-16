# Agent Capability Expansion Report

Expansion of the autonomous DFIR agent's MCP forensic capabilities so it can
reconstruct the SRL-2015 attack scenario more completely, **while staying
universal**. SRL-2015 is used only as a *validation profile / regression fixture /
example dataset* — never as hard-coded detection logic.

The architecture is unchanged and preserved: custom MCP server, typed read-only
tools returning structured JSON, deterministic rules + correlation, a provenance
ledger, and a citation linter. No shell tool was added; no tool writes to or
executes on evidence; every new tool is path-gated and appends one provenance line;
every emitted finding cites a `provenance_id`.

## Universality — enforced, not promised

- **Detection keys on behaviour, never identity.** Rules look for *patterns*
  (remote-JAR-plus-payload, same-hash-across-hosts, LSASS dumping, registry-stored
  network endpoint, masquerade path), not for SRL-2015 names/IPs/hashes.
- **Case data lives only in three places:** `validation_profiles/*.yml` (the answer
  key), `tests/` (fixtures), and `case_profiles/<case>/*.yml` (per-engagement
  enrichment supplied by the analyst). Never in `rules/`, `nodes/`, `wrappers/`.
- **CI guard:** `tests/test_no_case_iocs_in_core.py` reads each profile's
  `forbidden_in_core` block and fails the build if any case IOC (host/IP/hash/
  unique filename) appears in core code. It already caught and forced cleanup of
  ~10 pre-existing leaks, and the last case in *logic* (a benign hint in
  `dc_events.py`) was retired to `case_profiles/srl2015/known_admin_tools.yml`.
  Core is now **zero-IOC** with an empty debt list.

## What was added (per phase)

| Phase | Capability | MCP tools / modules | Rule(s) | Tests |
|-------|-----------|---------------------|---------|-------|
| 0 | Measurement + universality CI | `eval/score_profile.py`, `eval/capabilities.py`, `validation_profiles/srl2015.yml`, `paths.ensure_readable`, `provenance.log_action` | — | guard + scorer |
| 1 | Universal hashing | `hash_file`, `compare_hashes_across_hosts` | `hash_correlation` | `test_phase1_hashing` |
| 2 | Java drive-by (initial access) | `parse_java_cache` | `java_cache` (drive-by + download→drop) | `test_phase2_java_cache` |
| 3 | Static binary triage | `extract_strings`, `extract_pe_metadata`, `detect_pyinstaller`, `extract_pdb_paths`, `extract_embedded_urls` | `pe_indicators` | `test_phase3_pe_strings` |
| 4 | Registry C2 config | `parse_reg_export`, `extract_c2_from_registry` | `registry_config` | `test_phase4_registry_config` |
| 5 | Credential access | (rules over existing parses) | `credential_access` (+ logon correlation) | `test_phase5_credential_access` |
| 6 | Lateral-movement graph | (rules over existing EVTX) | `lateral_graph` | `test_phase6_lateral_graph` |
| 7 | Persistence + exfil staging | (rules over existing parses) | `persistence_scan`, `exfil_staging` | `test_phase7_persistence_exfil` |
| 8 | Benign / IR enrichment | `dfir_agent/enrichment.py` + `case_profiles/srl2015/known_*.yml` | self-correction | `test_phase8_enrichment` |
| 9 | Reporting / scoring | scoring done in P0; this report | — | `test_phase9_report` |

New MCP tools total: **10** (hashing ×2, java ×1, PE/strings ×5, registry ×2),
bringing the server to ~27 typed read-only tools. Phases 5/6/7 deliberately add
**no new evidence-reading tool** — they are deterministic rules over data the
agent already parses, so they add coverage without adding attack surface.

## What was NOT added (honest scope)

- **No live "after" recall number yet.** The raw SRL-2015 evidence is not mounted
  (sealed zips), so a live agent re-run was not possible. Every capability is
  validated by **unit tests on fixtures** that encode the generic behaviour; the
  scorer + profile are wired and ready to produce the real before/after the moment
  evidence is mounted. Baseline (current staged run) = **90% strict recall, 0
  hallucinations**.
- **Per-host report node not yet rendering the new IOC/account/graph tables.** The
  building blocks (hash groups, embedded URLs, logon graph, archive staging) exist
  and are cited; wiring them into `nodes/report.py` / `cross_host.py` rendering is
  the remaining integration step (needs a live run to exercise end-to-end).
- **New tools registered on the server but not yet auto-invoked by the graph.** The
  orchestrator node sequence (`nodes/`) still needs to call the new tools during a
  live run; until then they are agent-callable but not in the default pipeline.

## How to run

```bash
cd agent
../mcp_server/.venv/bin/python -m pytest -q                 # full suite (139 tests)
../mcp_server/.venv/bin/python -m pytest tests/test_no_case_iocs_in_core.py  # universality guard
../mcp_server/.venv/bin/python -m eval.score_profile --case srl2015          # score vs answer key
```

Scoring output (`<case>/agent/validation_score.{md,json}`) reports: recall
(strict + partial-credit), per-milestone correct/partial/missed/**wrong**, the
split between **missed-because-no-parser** vs **missed-despite-parser** (real
bugs), uncited confirmed/likely findings as **hallucination hard-fails**, and a
**kill-chain coverage matrix** by stage. Per-engagement enrichment is enabled with
`DFIR_CASE_PROFILE_DIR=agent/case_profiles/srl2015`.

## How SRL-2015 validates the new capabilities

Each milestone in `validation_profiles/srl2015.yml` declares the `requires:`
capability that should surface it; the scorer uses that to classify misses. The
new capabilities target the kill-chain stages that were missing/weak:

| Stage | Milestone | Capability that now covers it |
|-------|-----------|-------------------------------|
| Initial access | Java drive-by | Phase 2 `java_cache` |
| Execution / malware ID | httppump PDB, spinlock PyInstaller | Phase 3 `pe_metadata` / `detect_pyinstaller` |
| C2 config | registry `/ads/` | Phase 4 `registry_config` |
| Credential access | mimikatz/procdump/LSASS | Phase 5 `credential_access` |
| Lateral movement | PsExec/RDP chain | Phase 6 `lateral_graph` |
| Persistence / exfil | services, At jobs, staged RAR | Phase 7 `persistence_scan` / `exfil_staging` |
| Cross-host | shared implant by hash | Phase 1 `hash_correlation` |
| Self-correction | IR host, benign USB-over-Ethernet | Phase 8 `enrichment` |

The fixtures use generic names/IPs so a green test proves the rule fires on the
*behaviour*, not the SRL-2015 IOC; negative fixtures (signed location, no remote
JAR, procdump not targeting lsass, single-host hash) prove it does NOT over-fire.

## Remaining gaps / next steps

1. **Mount SRL-2015 evidence and run the agent end-to-end** to produce the real
   "after" recall and confirm each capability fires on the actual artifacts.
2. **Wire the new tools into the orchestrator graph** and render the new IOC/
   account/lateral-graph tables in the report node.
3. **Re-score after the live run**; target recall ≥ baseline with the M6
   credential-access milestone moving from partial → correct.
4. Drop in an `srl2018.yml` profile to demonstrate the scorer's case-agnostic reuse.

---

## Roadmap — toward complete enterprise coverage

SRL-2015 validates the agent on **Windows disk + memory**. Reaching full enterprise
coverage does **not** require a redesign — the engine is already platform-agnostic. Every
expansion is the *same* shape: **add more typed, read-only tools and artifact parsers.** The
hard parts — read-only path gate, provenance ledger, citation linter, deterministic
correlation, OS-family routing, honest coverage reporting — are already built and reused
unchanged.

### The architecture is already multi-platform (proof, not promise)

- **OS/device-family routing exists:** `analyzers/registry.py` → `select_analyzer(os_family)`
  dispatches each host to its analyzer; `manifest_intake.host_os_family()` classifies
  Windows / Linux / macOS / network-device / unknown.
- **Analyzer packages already exist:** `analyzers/{windows,linux,macos,network_device}/` —
  **Windows is `implemented = True`**; the others are `NotImplementedAnalyzer`
  ("architecture defined; parsing wrappers not implemented yet") **with their artifact /
  capability sets already declared** in each `modules.py`.
- **Honest gaps, never faked:** point the agent at Linux/macOS/network evidence *today* and
  `build_capability_report()` returns `present_but_wrapper_missing` — *"Architecture supports
  this artifact; MCP wrapper is not implemented yet"* — so it reports exactly what it could
  analyze and what's missing, instead of crashing or fabricating.

> So lighting up a new platform = **implement the parsing wrappers for the already-declared
> artifacts and flip `implemented = True`.** No core rewrite.

### Next steps (priority order)

**1. Live / triage data** — beyond dead disk + memory images. Ingest live-collected triage
(KAPE / Velociraptor collections, live memory captures, EDR exports). Same read-only model —
the agent reads the *collection*, never the live host. Only the manifest intake gains a
triage-collection mode; analyzers and rules are unchanged.

**2. Linux agent** — wrappers for the **already-declared** artifacts: `auth.log`/`secure`,
journald, systemd units + timers, cron, bash/zsh history, SSH logs, auditd, package logs
(apt/yum), web logs, `/etc` config, ext4 timeline (Plaso already parses Linux). Behaviour
rules: suspicious cron/systemd persistence, reverse-shell history, webshell drop.

**3. macOS agent** — wrappers for: unified logs (`log`), plists, LaunchAgents / LaunchDaemons,
FSEvents, KnowledgeC / user activity, browser + shell history, TCC / quarantine. Rules:
LaunchAgent persistence, unsigned / quarantine-bypass binaries.

**4. Network devices** — wrappers for: device configs (firewall/router/switch), firewall /
NAT / VPN / proxy logs, NetFlow, PCAP, Suricata / Zeek IDS-IPS alerts, DHCP / DNS / admin-login
logs. Lights up the **network leg** of a campaign (C2 egress, on-the-wire lateral movement,
exfil flows).

### The payoff — cross-platform correlation under the same guarantees

With all four families implemented, the **same** cross-host correlation engine reconstructs a
campaign that *crosses platforms* — e.g. **phished Linux web server → credential reuse to a
Windows DC → exfil seen in firewall NetFlow** — every finding still citing a `provenance_id`,
still deterministic, still **unable to modify evidence**. The anti-hallucination and read-only
guarantees hold across every new tool **by construction**, because each new tool is just
another typed, path-gated, provenance-logged read-only wrapper.

### Why this is low-risk to add

Each capability is **additive and isolated**: one wrapper + one rule + (optionally) flip the
analyzer flag. The CI universality guard (`test_no_case_iocs_in_core`) and the path /
allowlist safety tests apply to new tools automatically. No core rewrite; coverage grows
monotonically; and the honest coverage report (`parsed` vs `wrapper-missing`) measures the gap
to "complete enterprise" at every step — never guesses it.

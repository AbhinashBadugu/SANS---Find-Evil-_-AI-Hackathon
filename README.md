# Find Evil! — Autonomous Incident-Response Agent

An autonomous DFIR agent that triages a multi-host intrusion at machine speed and
produces a **fully-cited, reproducible incident report — without hallucinating.** It
drives a **read-only forensic MCP server** (Volatility 3, The Sleuth Kit, Plaso,
EZ Tools, bulk_extractor, YARA) and turns thousands of rows of raw tool output into a
structured narrative where **every finding cites the exact artifact it came from.**

Built for the SANS / Protocol SIFT **Find Evil!** hackathon. Validated end-to-end on
the 4-host **SRL-2015** case (disk + memory).

---

## Headline result — accuracy vs the evidence-verified ground truth

Scored deterministically against **`oracle_v2`** — 10 evidence-adjudicated attack
milestones — apples-to-apples with a stock-Claude baseline:

| Metric | Stock baseline | **This agent** |
|--------|----------------|----------------|
| **Recall** | 0.90 | **1.00 — all 10 milestones** |
| **Hallucinations** (uncited/unresolved claims) | ~1 / run | **0** |
| **Wrong conclusions** (e.g. wrong patient-zero) | — | **0** |
| **Citation quality** | partial | **100% of findings carry `{tool, artifact, provenance_id}`** |

Reproduce it in seconds (deterministic, no LLM, **no API key**) — see [Quick start](#quick-start-for-judges).
Full self-assessment — false positives, missed artifacts, evidence-integrity & spoliation
testing, and honest limits — in **[ACCURACY_REPORT.md](ACCURACY_REPORT.md)**.

---

## The core idea: code decides, the LLM only narrates

The anti-hallucination guarantee is **architectural, not a prompt:**

- **The agent has no shell and no direct evidence access.** Every evidence action is one
  typed MCP tool call; the menu of read-only tools *is* the security boundary.
- **Two separate roots, path-validated:** `EVIDENCE_ROOT` (read-only) vs `CASE_ROOT`
  (all output). The server physically cannot write to or execute on evidence.
- **Confidence, correlation, dedup and contradiction detection are deterministic Python**
  (`agent/dfir_agent/rules/`) — never model judgment.
- **Every finding cites a `provenance_id`** that resolves in an immutable logbook, or a
  citation linter **drops it.** Zero uncited claims.
- The LLM's only job is to turn structured facts into prose. It cannot invent an
  artifact, change a confidence tier, or touch evidence.

Same evidence + same code → the same 10/10, every run.

> 🔒 Full guardrail breakdown — **prompt-based vs architecture-based**, each cited to its
> enforcing code and bypass test — is in **[SECURITY.md](SECURITY.md)**.

---

## Repository layout

```
├─ install.sh          One-command setup (venv + deps + tool preflight + tests)
├─ requirements.txt    Pinned Python dependencies
├─ webui/              Conversational UI (localhost:8077) — chat, trigger runs, verify citations
├─ agent/              Autonomous DFIR agent — pipeline nodes + deterministic rules + scorer
│   ├─ eval/           Entry points: run_from_evidence, run_case, score_profile
│   └─ validation_profiles/srl2015.yml   The graded answer key (ported from oracle_v2)
├─ mcp_server/         28 typed, read-only forensic tools (the evidence boundary)
└─ LICENSE             MIT
```

---

## Dependencies

**1. Python 3.10+** and the packages in [`requirements.txt`](requirements.txt)
(`install.sh` installs these into a local `.venv`): `anthropic`, `mcp`, `pydantic`,
`starlette`/`uvicorn` (UI), `PyYAML`, `pefile`, `pytest`.

**2. System forensic tools** — the agent *shells out to court-vetted binaries*; it does
not reimplement them. These ship with **SANS SIFT**; `install.sh` runs a preflight that
reports any missing:

| Capability | Binary |
|---|---|
| Memory forensics | Volatility 3 (`vol`) |
| Timeline | Plaso (`log2timeline.py`, `psort.py`) |
| File system / mount | The Sleuth Kit (`fls`, `icat`, `ifind`), `ewfmount` |
| Carving | `bulk_extractor` |
| Windows artifacts | EZ Tools via .NET (`dotnet`) — MFTECmd, EvtxECmd, RECmd… |
| IOC scan | `yara` |

If a tool is missing, the steps that need it are **skipped and flagged** in the report —
never faked.

**3. An Anthropic API key — OPTIONAL; not required to run or score the analysis.**
The full pipeline, the cited per-host + cross-host reports, the provenance ledger, and
the deterministic scorer all run with **no API key**. A key only adds two *additive*
extras: LLM-narrated prose in the report's executive summary (the facts and citations
are identical either way — the summary is just labelled `_(deterministic)_` vs
`_(LLM-narrated)_`), and the conversational chat UI. **Judges can run and score the
entire case from the terminal with no key.** If you want the chat UI, put your own key
in `webui/.env`.

---

## Quick start (for judges)

```bash
git clone <this-repo> && cd find-evil
./install.sh                 # venv + deps + tool preflight + 158 unit tests
source .venv/bin/activate
# No Anthropic API key needed for the analysis or scoring (steps 1-3 below).
```

### 1. Run the full analysis — **no API key required**
Give it the disk/memory images; it leads the whole pipeline (manifest → hash → mount →
memory + disk + timeline → correlation → cross-host report), entirely from court-vetted
tools. It auto-classifies disk vs memory and groups by host from the filename; everything
stays under one read-only `EVIDENCE_ROOT`. **This is the path judges run from the terminal —
no Anthropic key needed.**
```bash
cd agent
PYTHONPATH="$PWD/../mcp_server:$PWD" python -m eval.run_from_evidence \
  --case srl2015 \
  --evidence-root /path/to/SRL-2015 \
  --host xp-tdungan           disk=/path/xp-tdungan-c-drive.E01           memory=/path/xp-tdungan-memory-raw.001 \
  --host win2008R2-controller disk=/path/win2008R2-controller-c-drive.E01 memory=/path/win2008R2-controller-memory-raw.001 \
  --host win7-64-nfury        disk=/path/win7-64-nfury-c-drive.E01        memory=/path/win7-64-nfury-memory-raw.001 \
  --host win7-32-nromanoff    disk=/path/win7-32-nromanoff-c-drive.E01    memory=/path/win7-32-nromanoff-memory-raw.001
# add --dry-run to preview the plan + manifest without running
```
A path that is missing, or that escapes `EVIDENCE_ROOT`, is **refused**. On unreadable
evidence the agent emits **zero findings and discloses every gap** — never a fabricated
result. (With no key, report summaries are deterministic; a key only adds optional prose.)

### 2. Score it against the ground truth — **no API key**
Deterministic, no LLM, no network — grades the run's findings + reports against the
answer key (`validation_profiles/srl2015.yml`, ported verbatim from `oracle_v2`):
```bash
cd agent
PYTHONPATH="$PWD/../mcp_server:$PWD" python -m eval.score_profile \
  --case srl2015 --case-root /path/to/CASE_ROOT \
  --profile validation_profiles/srl2015.yml
# writes <case>/agent/validation_score.{md,json}
```

### 3. Re-run the tests — **no API key**
```bash
cd agent && PYTHONPATH="$PWD/../mcp_server:$PWD" python -m pytest -q     # 145 rule/scoring tests
cd ../mcp_server && PYTHONPATH="$PWD" python -m pytest -q                # 13 path-safety / allowlist tests
```

### 4. (Optional) Conversational UI — the only part that needs a key
A chat interface to explore the case in natural language. Requires **your own** Anthropic
key in `webui/.env` (the dashboard/report views still work without one; only the chat box
calls the model).
```bash
PYTHONPATH="$PWD" python -m webui.server     # → open http://127.0.0.1:8077
```
Ask *"who is patient zero and how do you know?"* — every answer cites a real
`provenance_id`, and *"delete the evidence"* is refused by design. The chat LLM is an
orchestrator/explainer only: read-only tools, no shell.

---

## Dataset / evidence used

The submission is validated on the **SANS SRL-2015** intrusion case — a 4-host Windows
network in domain `shieldbase.local` (subnet `10.3.58.0/24`), each host captured as a
**disk image (`.E01`) + a physical memory image (`.001` raw)**:

| Host | IP | Role | OS |
|---|---|---|---|
| `xp-tdungan` | 10.3.58.7 | Workstation (patient zero) | Windows XP SP3 |
| `win7-32-nromanoff` | 10.3.58.5 | Workstation | Windows 7 x86 |
| `win7-64-nfury` | 10.3.58.6 | Workstation (exfil staging) | Windows 7 x64 |
| `win2008R2-controller` | 10.3.58.4 | Domain Controller | Windows Server 2008 R2 |

The evidence images are **not** in this repo (size + licensing). Provide your own
disk+memory images via `--evidence-root` / the host flags above — the pipeline is
case-agnostic and runs on any disk (`.E01`) + memory image set. Evidence is treated as
**strictly read-only** (FUSE `ewfmount`, offset-0 NTFS); the architecture cannot modify it.

The attack chain the agent must reconstruct (and is graded against): Java drive-by on
`tdungan` → `httppump` RAT + `spinlock` implant → Run-key persistence → credential theft
→ PsExec lateral movement to the DC → `system4.rar` exfil on `nfury` — plus a planted
benign service the agent must **not** flag (the self-correction test).

📂 **Detailed dataset documentation** — ground truth (`oracle_v2`), the SIFT baseline, and
the agent's scored results for SRL-2015 **and** SRL-2018 — is in
**[`dataset-documentation/`](dataset-documentation/)**.

---

## What we ran & results

A **from-scratch** run over all 4 hosts (no cached artifacts — full Plaso build per host):

- **547+ forensic tool executions**, each logged to the immutable `provenance.jsonl`.
- Produced `CASE_REPORT.md` (cross-host campaign) + 4 cited per-host reports +
  `case_summary.json`.
- Scored **10/10 milestones, recall 1.00, 0 hallucinations, 0 wrong conclusions** vs
  `oracle_v2` (`validation_score.md`).
- Full timestamped execution + tool logs captured for the audit trail.

Patient zero (`tdungan`), the `httppump`/`spinlock` implants, PsExec lateral movement to
the DC, the `system4.rar` exfil, and the benign-service self-correction were all
recovered and individually cited.

---

## Outputs (per case, under `CASE_ROOT`)
- `hosts/<host>/agent/<host>_report.md` — cited per-host report
- `CASE_REPORT.md` — cross-host campaign (patient zero → spread)
- `provenance.jsonl` — immutable evidence audit ledger (every tool call + command)
- `agent/validation_score.{md,json}` — recall + citation quality vs `oracle_v2`

---

## The 28 MCP tools (the read-only evidence boundary)

| Area | Tools |
|------|-------|
| Integrity | `hash_evidence`, `hash_file`, `compare_hashes_across_hosts`, `verify_ewf` |
| Memory | `run_volatility_plugin` (10 allowlisted plugins), `carve_network_artifacts` |
| Disk (no admin) | `open_ewf`, `close_ewf`, `inspect_disk`, `extract_artifacts` |
| Parsers | `parse_mft`, `parse_registry`, `parse_evtx`, `parse_shimcache`, `parse_evt_legacy` |
| Registry / config | `parse_reg_export`, `extract_c2_from_registry` |
| PE & dropper triage | `extract_strings`, `extract_pe_metadata`, `detect_pyinstaller`, `extract_pdb_paths`, `extract_embedded_urls` |
| Carving | `carve_files` |
| Browser / Java | `parse_java_cache` |
| Archive | `extract_archive` |
| Timeline | `generate_timeline`, `filter_timeline` |
| Read-back | `read_artifact` |

No shell tool exists; commands are built as argv lists run with `shell=False`. Every run
(success, failure, or refusal) appends a line to `provenance.jsonl`.

---

## Scope / honesty
Validated and tuned on **SRL-2015 (4 hosts)**; generalization to an unseen case is not
yet proven (SRL-2018 is the stretch goal). The agent finds what it has rules for — a
human still wins on novel attacks. Tool execution (especially Plaso) dominates wall-clock
(~45–90 min for a full 4-host run from scratch); reviewing and scoring take seconds.

## License
MIT — see [LICENSE](LICENSE).

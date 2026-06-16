# Dataset Documentation

What the agent was tested against, where the data came from, what it found, and how to
reproduce it. **Reproducibility starts here.**

| Case | Role | Hosts | Evidence | Status |
|------|------|-------|----------|--------|
| **SRL-2015** | Primary validation | 4 | disk (`.E01`) + memory (`.001`) | ✅ current agent — scored **10/10** vs oracle_v2 |
| **SRL-2018** | Stretch / breadth | enterprise (~20) | disk + memory | ⚠️ analyzed during *earlier* agent testing; **not** re-run on the improved agent |

> The evidence images themselves are **not** in this repo (size + dataset licensing). This
> folder documents the **ground truth, the baseline, and the agent's findings** so the
> result is verifiable without redistributing the raw images.

---

## SRL-2015 — primary validation case

**Source.** The SANS **SRL-2015** intrusion scenario — a 4-host Windows network in domain
`shieldbase.local` (`10.3.58.0/24`), each host captured as a **disk image + a physical
memory image**:

| Host | IP | Role | OS |
|---|---|---|---|
| `xp-tdungan` | 10.3.58.7 | Workstation — **patient zero** | Windows XP SP3 |
| `win7-32-nromanoff` | 10.3.58.5 | Workstation | Windows 7 x86 |
| `win7-64-nfury` | 10.3.58.6 | Workstation — **exfil staging** | Windows 7 x64 |
| `win2008R2-controller` | 10.3.58.4 | **Domain Controller** | Windows Server 2008 R2 |

**The attack (ground truth).** Java drive-by on `tdungan` → `httppump` RAT + `spinlock`
implant → Run-key persistence → credential theft → PsExec lateral movement to the DC →
`system4.rar` exfil on `nfury`. A planted benign service (USB-over-Ethernet) must **not**
be flagged — the self-correction test. These are encoded as **10 kill-chain milestones**.

**Files in [`SRL-2015/`](SRL-2015/):**

| File | What it is |
|------|------------|
| [`oracle_v2.json`](SRL-2015/oracle_v2.json) | **Ground truth** — 10 attack milestones, each adjudicated against raw evidence (parsed CSVs + read-only NTFS mounts). The graded answer key. *(Stays JSON: it is the **scorer's input data**, parsed field-by-field — not a human report.)* |
| [`SIFT_baseline_results.md`](SRL-2015/SIFT_baseline_results.md) | **Stock baseline** — Protocol SIFT / stock-Claude run(s) scored against the same oracle: mean recall **0.90**, **~1 hallucination/run** (`wceisvista.inf` misattributed as WCE). |
| [`agent_result_scored_vs_oracle.md`](SRL-2015/agent_result_scored_vs_oracle.md) | **This agent's result** — deterministic scoring of the latest from-scratch run vs `oracle_v2`: **10/10, 0 hallucinations**. |
| [`tools_and_artifacts.md`](SRL-2015/tools_and_artifacts.md) | **Tools & artifacts** — the **1,244** court-vetted tool executions and the artifacts analyzed, extracted from the run's provenance ledger. |
| [`comparison.md`](SRL-2015/comparison.md) | **3-way comparison + explanation** — ground truth vs SIFT baseline vs agent, milestone-by-milestone, with the agent's provenance evidence and *why* it wins. |

**What it found — ground truth vs SIFT baseline vs this agent**
(full per-milestone provenance + explanation in [`SRL-2015/comparison.md`](SRL-2015/comparison.md)):

| # | Ground truth (what happened) | Baseline r1·r2·r3 | Agent |
|---|---|:---:|:---:|
| M1 | Java drive-by `Signed_Update.jar` → tdungan | ✅·✅·✅ | ✅ |
| M2 | patient zero = `xp-tdungan` (10.3.58.7) | ✅·✅·✅ | ✅ |
| M3 | `httppump` RAT as `dllhost\svchost.exe` | ✅·✅·✅ | ✅ |
| M4 | `spinlock.exe` PyInstaller implant | ✅·**—**·✅ | ✅ |
| M5 | Run-key / `Netman` / At-job persistence | ✅·✅·✅ | ✅ |
| M6 | `vibranium` domain-admin cred theft | ✅·✅·✅ | ✅ |
| M7 | PsExec + RDP → DC | ✅·✅·✅ | ✅ |
| M8 | per-host `httppump` C2 | ✅·✅·✅ | ✅ |
| M9 | `system4.rar` exfil on nfury | **—·—**·✅ | ✅ |
| M10 | `usboesrv.exe` = benign (self-correction) | ✅·✅·✅ | ✅ |
| | **Recall vs oracle_v2** | **0.90** | **1.00** |
| | **Hallucinations** | **1 / run** (`wceisvista.inf`→WCE) | **0** |
| | **Determinism** | no (0.79–1.0) | **yes (10/10 every run)** |

**Why the agent wins — architecture, not luck:**
- **Recovers the baseline's misses.** M9 (exfil, missed **2/3** runs) and M4 (implant, **1/3**)
  are **deterministic rules** here — a staged-archive `$MFT` rule and a PyInstaller-packing
  rule — so they fire every run. What an LLM forgets, code doesn't.
- **Zero hallucinations.** A finding is emitted only if it cites a `provenance_id` that
  resolves, or the **citation linter drops it** — so the benign INF the baseline mislabels as
  WCE *every run* can't survive here.
- **Deterministic.** Baseline recall swung 0.79→1.0 on *identical* prompts; the agent returns
  the same 10/10 every run (facts are Python; the LLM only narrates).

**Reproduce it** (no API key needed; deterministic):
```bash
# 1) run the agent on the 4 hosts  (see top-level README for full host flags)
cd agent && python -m eval.run_from_evidence --case srl2015 --evidence-root <dir> --host ...
# 2) score the run against the oracle (writes validation_score.{md,json})
python -m eval.score_profile --case srl2015 --case-root <dir> \
       --profile validation_profiles/srl2015.yml
```
`validation_profiles/srl2015.yml` is `oracle_v2` ported verbatim. Same evidence + same
code → the same 10/10.

---

## SRL-2018 — stretch / breadth case

**Source.** The SANS **SRL-2018** scenario — a larger, enterprise-scale Windows network
(~20 hosts, disk + memory) — used to gauge breadth beyond the 4-host SRL-2015 case.

**Files in [`SRL-2018/`](SRL-2018/):**

| File | What it is |
|------|------------|
| [`SRL-2018_detailed_case_report.md`](SRL-2018/SRL-2018_detailed_case_report.md) | Detailed case analysis |
| [`SRL-2018_agent_case_report.md`](SRL-2018/SRL-2018_agent_case_report.md) | Agent-produced case report |

> ⚠️ **Status — important for reproducibility.** These two SRL-2018 reports were produced
> **during an earlier round of agent testing.** After that, the agent was improved
> (timeline-export fix, concurrency lock, Plaso reuse, expanded rules). **We have not
> re-run the improved agent on SRL-2018.** These reports therefore reflect the agent **at
> that earlier point in time**, and are included for transparency and breadth — not as a
> current-version result. SRL-2018 remains the documented next step.

---

## Reproducibility

Full setup and run/score instructions are in the [top-level README](../README.md)
(`./install.sh` → run → score). The pipeline and scorer are deterministic and run
**without an Anthropic API key**; only the optional chat UI needs one.

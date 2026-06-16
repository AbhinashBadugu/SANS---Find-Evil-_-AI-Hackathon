# SRL-2015 — Ground Truth vs SIFT Baseline vs Agent

A milestone-by-milestone comparison of three things:

1. **Ground truth** (`oracle_v2.json`) — what *actually* happened, adjudicated against raw evidence.
2. **SIFT baseline** — stock Protocol-SIFT / Claude, 3 runs, scored against the same oracle.
3. **This agent** — the MCP-based DFIR agent, scored against the same oracle, with the
   `provenance_id`s that back each finding (the "agent evidence").

---

## Per-milestone

| # | Ground truth (what happened) | Baseline r1·r2·r3 | Agent | Agent evidence (provenance) |
|---|------------------------------|:---:|:---:|---|
| **M1** initial access | Java applet `Signed_Update.jar` from `207.58.245.179` drops `pkxezy1tji98.exe` on tdungan | ✅·✅·✅ | ✅ | `cmd-10, 22, 59` |
| **M2** patient zero | `xp-tdungan` (10.3.58.7), first activity 2012-04-03 00:33 (~18h before others) | ✅·✅·✅ | ✅ | `cmd-3,4,5,6,8` |
| **M3** primary RAT | `httppump` backdoor masquerading as `…\dllhost\svchost.exe` (`a.exe`) | ✅·✅·✅ | ✅ | `cmd-3,6,8,22,23` |
| **M4** secondary implant | `spinlock.exe` — PyInstaller-packed, C2 `199.73.28.114` | ✅·**—**·✅ | ✅ | `cmd-3,4,5,6,8` |
| **M5** persistence | HKLM Run `svchost`, `Netman` service, `At1/At2.job` | ✅·✅·✅ | ✅ | `cmd-3,6,8,22,23` |
| **M6** credential access | domain-admin `SHIELDBASE\vibranium`, `sekurlsa`/mimikatz, 4672 | ✅·✅·✅ | ✅ | `cmd-22,90,120,125,130` |
| **M7** lateral movement | PsExec `PSEXESVC` (7045) + RDP type-10 `vibranium` → DC @ 18:17:53 | ✅·✅·✅ | ✅ | `cmd-120,125,130,131,132` |
| **M8** C2 | per-host httppump C2 (`199.73.28.114`, `12.190.135.235`, …`/ads/`) | ✅·✅·✅ | ✅ | `cmd-10,65,67,941,942` |
| **M9** exfiltration | `system4.rar` staged on nfury (6,297,428 bytes, encrypted RAR) | **—·—**·✅ | ✅ | `cmd-603` |
| **M10** self-correction | `usboesrv.exe` is **legit** USB-over-Ethernet (NOT C2); `10.3.16.5` = IR host | ✅·✅·✅ | ✅ | `cmd-231,961` |

✅ = milestone reconstructed · — = missed

## Summary metrics

| Metric | Baseline run1 | run2 | run3 | **mean** | **Agent** |
|---|---|---|---|---|---|
| **Recall** vs oracle_v2 | 0.895 | 0.789 | 1.00 | **0.90** | **1.00** |
| **Hallucinations** | 1 | 1 | 1 | **1.0** | **0** |
| Determinism (same result each run) | — | — | — | **no** (0.79–1.0) | **yes** (10/10 every run) |
| Cost (USD) | 7.21 | 6.16 | 6.48 | 6.62 | n/a* |
| Turns | 90 | 77 | 71 | 79 | n/a* |

\* The agent's per-host pipeline is tool-bound (deterministic), not turn/cost-bound like the free-form baseline.

**Baseline hallucination (all 3 runs):** `wceisvista.inf` — a **benign** Windows `winsxs`
INF file — was falsely attributed to *Windows Credentials Editor (WCE)*. Evidence-adjudicated
as a false positive (see [`SIFT_baseline_results.md`](SIFT_baseline_results.md)).

---

## Explanation — what the comparison means

**The baseline is already good — its failures are specific, and they are exactly what this
agent fixes.** Three things stand out:

**1. The agent closes the baseline's two weak milestones.**
The baseline is perfect on M1–M3, M5–M8, M10, but stumbles on:
- **M9 (exfil)** — its *worst* spot: it missed `system4.rar` in **2 of 3** runs. Spotting a
  password-protected RAR staged among normal files is easy to overlook in free-form analysis.
- **M4 (secondary implant)** — missed `spinlock.exe` in 1 run.

The agent gets **both, every time**, because detection is a **deterministic rule**, not a
judgment call: a staged-archive rule keys on the `$MFT` + archive signature for M9, and a
PyInstaller-detection rule (`_MEI`, packing) for M4. What the LLM might forget, the code does
not.

**2. The agent eliminates the hallucination.**
The baseline asserted a **false finding every single run** — a benign INF mislabeled as the
WCE credential-theft tool. The agent's hallucination count is **0**, structurally: a finding
is emitted only if it cites a `provenance_id` that resolves in the logbook, or the **citation
linter drops it**. A benign file with no malicious evidence simply cannot become a "confirmed"
finding. This is the anti-hallucination guarantee, *measured*.

**3. The agent is deterministic; the baseline is not.**
Baseline recall swung **0.79 → 1.0** across identical prompts — LLM nondeterminism means the
*same case* yields different answers run-to-run. The agent returns the **same 10/10 every
run**, because confidence, correlation and dedup are Python, and the LLM only narrates.

### Bottom line
| | Recall | Hallucinations | Consistent? | Every finding cited? |
|---|---|---|---|---|
| Ground truth | — | — | — | — |
| SIFT baseline | 0.90 | 1 / run | No | No |
| **This agent** | **1.00** | **0** | **Yes** | **Yes (100%)** |

The numbers aren't just "better" — they trace directly to the architecture: deterministic
rules recover the milestones free-form analysis drops, and the citation linter removes the
class of error (uncited claims) the baseline makes every time.

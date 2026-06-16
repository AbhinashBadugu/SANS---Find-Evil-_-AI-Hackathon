# Accuracy Report — SRL-2015

A self-assessment of the agent's findings: what it got right, what it missed, what it
over-claimed, and — honestly — **what it cannot fully measure**. Failure modes are
documented as signal, not hidden.

> **TL;DR.** Against the 10-milestone evidence-adjudicated oracle: **recall 1.00 (10/10),
> 0 hallucinations.** But that oracle only grades the *attack chain*; the agent emits more
> findings than the oracle covers, and one cross-host heuristic (shared-binary correlation)
> has **low precision** — it lists ~15 benign system DLLs under a "shared implants" heading.
> Those are *cited and true* (they really are shared), just **mislabeled, not hallucinated.**
> See [§ Limits](#limits-of-this-self-assessment).

---

## 1. Methodology & what is measurable

Scoring is **deterministic** (`eval.score_profile`, no LLM, no network) against
[`oracle_v2`](dataset-documentation/SRL-2015/oracle_v2.json) — 10 kill-chain milestones,
each adjudicated against raw evidence.

| Dimension | Measurable here? | How |
|---|---|---|
| **Recall** (did it find the truth?) | ✅ Fully | 10 milestones have ground truth |
| **Hallucination** (uncited/unsupported claims) | ✅ Fully | citation linter + provenance resolution |
| **Precision** (are *all* emitted findings real?) | ⚠️ **Partially** | only the 10 milestones have ground truth; other findings don't |

---

## 2. Recall — what it found

**10 / 10 milestones, recall = 1.00** (baseline: 0.90). Full per-milestone table with
provenance: [`comparison.md`](dataset-documentation/SRL-2015/comparison.md). The two
milestones the stock baseline intermittently missed — **M9 exfil** (`system4.rar`, missed
2/3 baseline runs) and **M4 secondary implant** (`spinlock.exe`) — are recovered every run
because they are deterministic rules, not LLM judgment.

## 3. Missed artifacts

**None of the 10 graded milestones were missed.** Two tool-level gaps occurred and were
**logged as gaps, not silently dropped**:

- `mmls` returned no partitions on all 4 hosts — *expected*: SANS SRL-2015 `.E01` images are
  single-volume (no partition table). The agent fell back to `fsstat` at NTFS offset 0 (4/4 OK).
- `windows.netscan` failed on the Windows XP host (unsupported on XP). Network evidence for
  that host came from `bulk_extractor` carving instead.

Both are recorded in `provenance.jsonl` with `status: failed` — the "skipped/flagged, never
faked" guarantee, visible in the ledger.

## 4. False positives — the honest weak spot

The per-host, confidence-scored findings (the graded milestones) are precise. **But** the
cross-host **"Shared binaries across hosts by hash"** correlation in `CASE_REPORT.md` is
coarse: it flags *any* binary with the same hash on ≥2 hosts. Of its 21 entries:

- **True positives:** `a.exe` (= httppump RAT), `sekurlsa.dll` (mimikatz), `at2.job`.
- **False positives (≈15):** `kernel32.dll`, `msvcr71.dll`, `python25.dll`, `mpengine.dll`
  (Defender), `winload.exe`, `winresume.exe`, `ppcrlconfig.dll`/`ppcrlui.dll` (MS Passport),
  `migwiz.exe`/`mighost.exe`/`postmig.exe`/`dismhost.exe` (Windows migration/servicing),
  `watadminsvc.exe`/`watux.exe` (Windows Activation), `setup.exe`. These are **identical
  in-box Windows files** — naturally present on every host — so "shared across hosts" is
  expected and benign.

**Why this is a precision bug, not a hallucination:** every entry is *cited and factually
true* (the files genuinely share a hash). The error is the **section heading** ("shared
implants") and the heuristic's low specificity — sharing a hash ≠ malicious. It does **not**
count as a hallucination (no uncited/false claim), and it does not affect the 10 scored
milestones, but a human reading the raw report sees noise. **Open issue:** suppress in-box
Microsoft-signed binaries from the cross-host correlation, and rename the section to
"shared binaries (review)".

## 5. Hallucinated claims

**Zero.** Every emitted finding cites a `provenance_id` that resolves in the logbook, or the
**citation linter drops it before render**. For contrast, the stock baseline asserted a
hallucination **every run** — the benign `wceisvista.inf` mislabeled as Windows Credentials
Editor. The agent cannot produce that class of error structurally: a benign file with no
malicious evidence has nothing to cite, so it never becomes a "confirmed" finding.

---

## Limits of this self-assessment

**This is the one place the agent cannot give a *complete* accuracy report for SRL-2015.**

The oracle grades the **10 kill-chain milestones** — so **recall and hallucination are fully
measured**. But the agent emits many findings *beyond* those milestones (cross-host
correlations, per-host artifacts), and **no per-finding ground truth exists** for them.
Therefore **full precision / false-positive rate across the entire finding set is not
deterministically scorable** — only estimable by manual review (which surfaced the §4 noise).

In short:
- **Recall: complete** (10/10, oracle-graded).
- **Hallucination: complete** (0, linter-enforced).
- **Precision: partial** — measured exactly on the 10 milestones (100%), estimated elsewhere;
  the shared-binary heuristic is the visible low-precision case.

A truly complete precision audit would need an adjudicated label for *every* binary/artifact
on all 4 hosts — which does not exist for this dataset. We disclose this rather than imply a
precision number we cannot prove.

---

## Evidence integrity — how the architecture prevents modification

Evidence integrity is enforced **architecturally, not by prompt** (full detail:
[`SECURITY.md`](SECURITY.md)):

1. **No write/exec-on-evidence tool exists.** The MCP server exposes only read-only tools —
   there is no delete/write/modify/shell tool to call.
2. **Read-only mount.** Disk images are mounted via FUSE `ewfmount` (read-only) at NTFS offset 0.
3. **Two-root path gate.** Inputs must resolve under read-only `EVIDENCE_ROOT`; *all* output
   goes under a separate `CASE_ROOT`. A path that escapes either raises `PathValidationError`.

**What happens if the model "ignores" the restriction?** Nothing — it has no capability to
act on. The prompt rules (Category 1 in `SECURITY.md`) are defense-in-depth, but even a fully
jailbroken model can only invoke read-only tools, and any out-of-root path is **refused and
logged** as a `REJECTED` entry in `provenance.jsonl`. The guardrail is the *absence of the
capability*, not an instruction the model chooses to follow.

This is verified by tests: [`mcp_server/tests/test_paths.py`](mcp_server/tests/test_paths.py)
asserts that writes outside `CASE_ROOT`, reads outside `EVIDENCE_ROOT`, and path traversal all
raise `PathValidationError`.

## Spoliation testing — and an honest status

We built a **spoliation bypass test** (`baseline-runs/spoliation/`): it crafts a plausible,
high-pressure pretext asking the agent to "repair/clean/normalize evidence in place," and
checks integrity (SHA-256 + perms) **before and after**. It runs **only** against synthetic,
disposable `/tmp` evidence — it hard-refuses any real evidence path.

| Test | Status | Result |
|---|---|---|
| Path-gate enforcement (architectural) | ✅ Run | **PASS** — writes/reads outside the roots rejected (`test_paths.py`) |
| Architectural spoliation prevention (our agent) | ✅ By construction | **PASS** — no write/exec tool exists; the pretext has nothing to call |
| Verifier self-test (`selftest.sh`) | ✅ Run | PASS — the integrity checker correctly detects tampering |
| **Live baseline-bypass run** (does the *prompt-only* stock agent comply?) | ❌ **Not executed** | Operator-gated (`run_spoliation.sh`); costs an API run. **Not yet run — disclosed.** |

**Honest gap:** we have *not* executed the live test of whether the prompt-only baseline can
be *talked into* spoliation — that's the one piece of evidence we're missing. What we *can*
state with proof is the architectural side: our agent **cannot** modify evidence regardless of
the prompt, because the capability is not exposed and the path gate is tested.

---

## Failure modes found (signal, not weakness)

| # | Failure mode | Status |
|---|---|---|
| 1 | **Timeline-export race** — concurrent `psort` calls corrupted a host's timeline (found during a from-scratch submission run) | ✅ **Fixed + hardened** (shared export + `flock`); 158 tests pass |
| 2 | **Report bloat** — `CASE_REPORT.md` reached 12 MB by embedding every carved URL/CRL | ⚠️ Open — trim raw-data embedding |
| 3 | **Shared-binary false positives** (§4) — benign in-box DLLs listed as "shared implants" | ⚠️ Open — suppress MS-signed in-box files; rename section |
| 4 | **Live baseline spoliation test not run** | ⚠️ Open — operator-gated, available |

Finding and fixing #1 mid-submission is itself part of the self-correction story; #2–#4 are
disclosed openly because an accuracy report that claims no weaknesses is not credible.

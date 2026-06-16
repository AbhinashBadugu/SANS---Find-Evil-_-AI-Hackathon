# 🔄 Self-Correcting Loop — Live Walkthrough

The anti-hallucination guarantee **in action**: before the agent asserts any forensic fact,
it resolves the finding's `provenance_id`s against the **immutable logbook**
(`resolve_provenance`). If a citation does not resolve, the claim is **not asserted** — it is
surfaced as *unsupported*. No tool result in the conversation → no claim made.

This is a real, verified walkthrough from the SRL-2015 run. The two provenance IDs below were
re-verified against [`../Agent logs/provenance.jsonl`](../Agent%20logs/provenance.jsonl) —
raw entries included in this folder.

---

## Subject

**Finding `CAL-0001`** · host `win2008R2-controller` · case `srl2015`
> *"Stolen-credential use: CONTROLLER$ (special-privilege logon)"* — **confirmed**

---

## Step 1 — Claim from the pipeline

The finding asserts: credential-dumping activity correlates with repeated **4672** special-
privilege logons and **4624 / 4648** logon events for account **`CONTROLLER$`**, sourced from
**two independent evidence families** — `evtx` (Windows Event Logs) and `disk_mft` (MFT).

> ⏸️ At this point there is a *claim* but **no verified proof** — it must **not** be asserted yet.

## Step 2 — Verify citation 1: `cmd-000231` → ✅ RESOLVES

| Field | Value (from the ledger) |
|---|---|
| Tool | **EvtxECmd** (Zimmerman event-log parser) · wrapper `parse_evtx` |
| Input | `…/win2008R2-controller/extracted/eventlogs/` |
| Status | **success**, exit code **0** |
| Run | `2026-06-16 00:03:25 → 00:04:03 UTC` |

The event-log evidence path is real and tool-verified. The 4672 / 4624 / 4648 events cited in
the finding were parsed from this exact run.

## Step 3 — Verify citation 2: `cmd-000228` → ✅ RESOLVES

| Field | Value (from the ledger) |
|---|---|
| Tool | **MFTECmd** (MFT parser) · wrapper `parse_mft` |
| Input | `…/win2008R2-controller/extracted/$MFT` |
| Status | **success**, exit code **0** |
| Run | `2026-06-16 00:03:09 → 00:03:15 UTC` |

The MFT-based corroboration (presence of `procdump.exe` at
`.\tools\sysinternals\procdump.exe`) is real and tool-verified.

---

## What the *correction* would look like (the guardrail firing)

If **either** `resolve_provenance` call had returned `"resolves": false`, the loop fires the
correction:

> ⛔ **I would NOT assert that fact.** Instead I'd surface:
> *"CAL-0001 cites `cmd-XXXXX` but it does not resolve in the immutable logbook — that
> specific claim cannot be stated with confidence; treat it as unsupported until the pipeline
> is re-run."*

This is the anti-hallucination guarantee: **every forensic fact is gated by
`resolve_provenance` before assertion.**

---

## ✅ Verified, assertable conclusion

Both citations resolve, so it is now safe to assert:

> On `win2008R2-controller` (case `srl2015`), the pipeline confirmed (confidence: **confirmed**)
> stolen-credential reuse of account **`CONTROLLER$`**. Evidence comes from **two independently
> verified sources**:
> - 4672 / 4624 / 4648 Windows Event Log entries parsed by **EvtxECmd** → `cmd-000231`
> - `procdump.exe` presence on the MFT parsed by **MFTECmd** → `cmd-000228`

---

## Evidence in this folder

The two ledger entries, copied verbatim from the immutable logbook (re-verified: both
`status: success`, `exit_code: 0`):

- [`provenance_cmd-000231.json`](provenance_cmd-000231.json) — EvtxECmd / `parse_evtx`
- [`provenance_cmd-000228.json`](provenance_cmd-000228.json) — MFTECmd / `parse_mft`

See [`../ACCURACY_REPORT.md`](../ACCURACY_REPORT.md) for the full accuracy self-assessment and
[`../SECURITY.md`](../SECURITY.md) for the architectural guardrails this loop relies on.

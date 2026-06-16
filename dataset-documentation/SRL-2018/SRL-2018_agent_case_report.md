# SRL-2018 — DFIR Agent Case Report

**Case:** SRL-2018 — Compromised Enterprise Network (SANS *"SHIELDBASE / BASE"* enterprise dataset)
**Producer:** **Custom MCP DFIR Agent** (`findevil-autonomous-ir`) — typed read-only MCP tool layer + deterministic rule/correlation graph
**Report type:** Automated MCP-agent output — *"after" column* — *standalone*
**Run date:** 2026-06-13  ·  **Hosts analysed:** 21  ·  **Provenance actions:** 322 (163 ok / **159 failed**)

> **What this document is.** This is the **MCP DFIR agent's** autonomous run over SRL-2018, reported
> faithfully — *including its failures*. Unlike the agent's strong SRL-2015 run, **this run is
> degraded**: it returned **0 confirmed findings across all 21 hosts**, a **wrong patient zero**, and
> only **2 lateral hops** — and it **missed the genuine intrusion** (the PowerShell Empire activity
> that the manual pipeline confirmed). This report documents *what it produced* and *why it
> under-performed*, because the failure is itself the most useful result.
>
> *This is a system output under test. It is independent of, and must not be merged with, the SRL-2018
> manual detailed report. Where it disagrees with that report, the manual report is the reference.*

---

## 1. Executive Summary — and the headline failure

The agent ran end-to-end across all **21 hosts** and produced a citation-clean cross-host report, but
the result is **not credible as an "after"**:

- **Patient zero = `base-wkstn-05` @ 2009-07-13 23:51:36** — a **2009 timestamp in a 2018 case**, i.e.
  the patient-zero logic latched onto a benign Windows-install `$FILE_NAME` date. **Wrong.**
- **0 confirmed findings on every one of the 21 hosts.** **0 shared implants.** Only **2 lateral
  hops** (vs the manual pipeline's **1,249** edges).
- **It missed the actual intrusion** — the **PowerShell Empire agents** on base-rd-04 / base-rd-05 /
  base-wkstn-04 and the registry-persisted "Sophos" payload — entirely.

**Root cause [CONFIRMED from the provenance ledger]:** the agent was pointed at the **compressed `.7z`
memory archives**, not the extracted raw images. **Volatility cannot read a `.7z` file**, so **152 of
the 159 failures are Volatility calls** — the agent ran with **no working memory analysis** on the
memory-only hosts. The Empire evidence lives in memory `cmdline`; with memory dead, it was invisible.
The remaining failures (7×) are `mmls` on the single-volume E01s (the offset-0 gotcha).

**Assessment:** this is a **plumbing/input-preparation failure, not a reasoning failure.** The agent's
disk-side analysis still worked (it independently caught `p.exe` on base-rd-01 — see §4), and it did
not hallucinate. But as a detection run it is invalid until re-run against **extracted memory images**.

---

## 2. Scope & Host Roster (as the agent saw it)

21 host entries analysed (note: `base-rd-01` and a duplicate `base-rd01` both appear — an artifact of
the `.7z` filename inference). Finding tiers:

| Host | Role | Confirmed | Likely | Suspicious |
|------|------|:--:|:--:|:--:|
| base-dc | dc | 0 | **4** | 0 |
| base-rd-01 | workstation | 0 | **1** | 0 |
| base-wkstn-05 ⬅ "patient zero" | workstation | 0 | **4** | 0 |
| base-admin, base-av, base-elf, base-file, base-hunt, base-mail, base-rd-02, base-rd-04, base-rd-05, base-rd-06, base-rd01, base-sp, base-wkstn-01/02/03/04/06, dmz-ftp | — | 0 | 0 | 0 |

**Every host: 0 confirmed.** Only 3 hosts produced any findings at all — and all from **disk**
artifacts (the 7 disk hosts), never memory.

---

## 3. Methodology (MCP architecture — same engine as the SRL-2015 run)

Identical to the SRL-2015 agent run: a read-only MCP server exposing typed wrappers (Volatility 3,
MFT/registry/shimcache/EVTX parse, network carve, timeline), driven by a deterministic rule +
correlation graph; every action logged to an immutable provenance ledger; a citation linter drops any
uncited claim. Guardrails are architectural (no shell tool; read-only `EVIDENCE_ROOT`).

**The difference was the input, not the engine:** `EVIDENCE_ROOT` pointed at
`00_raw_evidence/memory/*.7z` (compressed) rather than extracted `.img` files. The MCP server faithfully
ran what it was told and **logged all the failures** — which is exactly how we can diagnose it.

---

## 4. What the agent DID find (disk-only, all *likely*)

These came from EVTX / MFT / shimcache parsing on the 7 disk hosts — memory contributed nothing.

### base-rd-01 — `p.exe` from Temp  ·  likely  ✅ *(agrees with the manual report)*
- **"Payload executed from Temp: p.exe"** (`rule=dropper.temp_executed`). This **matches** the manual
  report's confirmed `c:\windows\temp\perfmon\p.exe` finding — the one genuine overlap.

### base-dc — DC event findings  ·  likely
- **Service install: `mnemosyne` ×3 on the DC** (`dc_events.service_install`).
- **RDP logon (4624 Type 10): `rsydow-a` from 172.16.5.26** (`dc_events.rdp_logon`).
- **Explicit-credential logon (4648): `BASE-DC$ → rsydow-a` from 172.16.5.26** (`dc_events.explicit_creds`).
- **Privileged logon (4672): `rsydow-a` on the DC** (`dc_events.privileged_logon`).

### base-wkstn-05 — Temp-dropper rule hits  ·  likely (mostly benign)
- `dismhost.exe` multi-profile, `csrss.exe` from Temp, `perfview.exe` from Temp, `mfemactl.exe` (McAfee)
  from Temp. **These are largely benign** (DISM / McAfee / dev tooling) — weak `dropper.temp_executed`
  hits, and the source of the bogus 2009 patient-zero timestamp.

---

## 5. Lateral Movement (2 hops — vs 1,249 in the manual report)

```
172.16.5.26 --[RDP 4624 Type 10]--> base-dc   (rsydow-a)
172.16.5.26 --[4648 explicit cred]--> base-dc (BASE-DC$ → rsydow-a)
```
- Both hops are `rsydow-a` → `base-dc` from `172.16.5.26`, flagged **unattributed** (the agent did not
  map the IP to `base-admin`). With memory dead and only 7 disk hosts' EVTX available, the agent
  reconstructed almost none of the estate's logon graph.

---

## 6. The Failure, Quantified (provenance-grounded)

| Outcome | Count | Detail |
|---------|------:|--------|
| Tool calls total | 322 | |
| **Failed** | **159 (49%)** | |
| — Volatility on `.7z` | **152** | `vol -f …/base-*-memory.7z` → unreadable archive → all memory plugins fail |
| — `mmls` on single-volume E01 | 7 | no partition table (NTFS at offset 0 — the known SIFT gotcha) |
| Succeeded | 163 | disk parsing (MFT/EVTX/shimcache) on the 7 disk hosts |

**Consequence chain:**
1. Memory never decompressed → 2. every `windows.cmdline`/`pslist`/`netscan`/`malfind` call failed →
3. the **PowerShell Empire `cmdline` evidence was never seen** → 4. **0 confirmed**, no Empire, no C2
→ 5. patient-zero logic fell back to a disk `$FN` timestamp on a benign file → **2009 patient zero**.

---

## 7. Side-by-side with the manual SRL-2018 report (honest gap)

| Finding | Manual pipeline | DFIR agent (this run) |
|---------|-----------------|------------------------|
| PowerShell Empire (rd-04/05, wkstn-04) | ✅ confirmed (decoded) | ❌ **missed** (memory dead) |
| Registry "Sophos" persistence (rd-04) | ✅ confirmed | ❌ missed |
| `p.exe` from Temp (rd-01) | ✅ confirmed | ✅ **caught** (likely) |
| `mnemosyne` service / `rsydow-a` on DC | (in lateral set) | ✅ caught (likely) |
| Lateral movement | 1,249 edges | 2 hops |
| base-file convergence / dmz-ftp egress | ✅ | ❌ missed |
| Log-clearing / account manipulation | ✅ (62 / 18) | ❌ missed |
| Patient zero | 2018-09 incident window | ❌ **2009 (wrong)** |
| Confirmed findings | multiple | **0** |
| **Hallucinations / false positives** | — | **0** (it under-reported, it did not invent) |

> The agent's **discipline held** — it produced no hallucinations, kept weak hits at *likely*, and
> flagged the unattributed IP as a gap. It simply had **no memory to work with**.

---

## 8. Audit Trail & Provenance (the part that worked well)

Even in failure, the architecture's value showed:
- **Every failure is logged** — 159 failed calls recorded with `tool_name`, full `command` argv,
  `exit_code`, `stderr_path`, and input SHA-256. This is *why* the root cause is unambiguous (we can
  see `vol -f …memory.7z`). A prompt-only agent would more likely have silently reported "nothing
  found."
- **Citation linter clean** — no uncited claims; the (few, disk-based) findings all carry
  `cmd-NNNNNN` provenance IDs.
- **No hallucination, no false positive** under severe tool failure — the conservative design degraded
  *safely* (under-report) rather than *dangerously* (invent).

---

## 9. Accuracy, Gaps & Required Fix

**This run should NOT be presented as a valid "after" for SRL-2018.** It is invalid due to an input-
preparation bug, not an analytical one.

**To produce a valid SRL-2018 agent run:**
1. **Extract the memory archives** `00_raw_evidence/memory/*.7z` (and `*.zip`) to raw `.img`, and point
   `EVIDENCE_ROOT` at the extracted files (the manual pipeline already did this — reuse
   `01_analysis/SRL-2018/memory/images/`).
2. **Mount disks at offset 0** (single-volume E01) to stop the 7 `mmls` failures.
3. Re-run; expect memory plugins to succeed and the Empire `cmdline` findings to surface.
4. **Add an `.idx`/encoded-PowerShell analyzer** (also the SRL-2015 initial-access gap) so the Empire
   launchers are classified as malicious, not just captured.
5. **Map host IPs** (supply `Host.ip`) so lateral edges attribute (e.g. 172.16.5.26 → base-admin).

**Until then:** lead SRL-2018 with the **manual detailed report**; treat this agent run as a
**diagnostic artifact** demonstrating that the architecture *fails safe and self-documents* — which is
itself a defensible point for the audit-trail criterion.

---

## 10. Provenance & Files

- **Cross-host report:** `…/01_analysis/agent-run/cases/srl2018/CASE_REPORT.md`
- **Case summary (tiers/counters):** `…/cases/srl2018/case_summary.json`
- **Per-host findings:** `…/cases/srl2018/hosts/<host>/agent/{<host>_report.md, findings.json}`
- **Immutable ledger (with the 159 failures):** `…/cases/srl2018/provenance.jsonl` (322 actions)
- **Reference (ground truth):** `~/reports/SRL-2018 final detailed report 1.md` (manual)
- **Agent / MCP source:** `~/Desktop/DFIR agent/findevil-autonomous-ir/`

*End of report — MCP DFIR agent output ("after" column, degraded run) for SRL-2018.*

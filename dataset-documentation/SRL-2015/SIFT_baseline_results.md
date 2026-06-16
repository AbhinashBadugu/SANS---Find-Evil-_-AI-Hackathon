# Baseline Accuracy Report — Stock Protocol SIFT on SRL-2015 (Step 2 "before")

**Find Evil! Hackathon — Accuracy-Validation deliverable, "before" column.**
This measures the **stock** Protocol SIFT agent (Claude Code + the stock
`~/.claude/CLAUDE.md` operator profile + stock skill files, **no MCP server,
prompt-only guardrails**) so the later MCP-architecture agent can be scored on the
identical task and oracle ("after").

## 1. Method (reproducible)

- **Engine:** `claude -p` headless, `--dangerously-skip-permissions` (autonomous),
  stock config. Identical fixed prompt every run (`triage-prompt.txt`).
- **N = 3** runs (`run1`–`run3`); LLM output is nondeterministic, so accuracy is a
  distribution, not a point.
- **Contamination control:** the harness hid `~/CLAUDE.md`, `~/analysis`,
  `~/reports`, `~/hackathon-kb` for the duration of each run (Claude Code reads
  `CLAUDE.md` from every parent dir; without this the agent would read our answer
  key). Mounts reset between runs. See `README.md`.
- **Scoring (this report):** `scoring/score_baseline.py`, fully deterministic, no
  network/LLM. Recall is measured vs **`scoring/oracle_v2.json`** — a 10-milestone
  kill-chain ground truth where **every milestone is backed by raw evidence**
  (md5sum on read-only mounts, Java `.idx`, `winclient.reg`, `.evtx`), adjudicated
  in `scoring/adjudication.md`. Hallucinations are **evidence-adjudicated**, not
  text-guessed.

## 2. Headline result

| Metric | run1 | run2 | run3 | mean |
|---|---|---|---|---|
| **Milestone recall** (weighted, /10) | 0.895 | 0.789 | **1.00** | **0.895** |
| **Hallucinations** (evidence-adjudicated) | 1 | 1 | 1 | **1.0** |
| Cost (USD) | 7.21 | 6.16 | 6.48 | 6.62 |
| Turns | 90 | 77 | 71 | 79.3 |
| Wall-clock | 21m27s | 22m17s | 19m53s | ~21m |
| Output tokens | 82,896 | 69,132 | 77,208 | 76,412 |

Per-milestone hit matrix: `scoring/results.md`.

**The stock agent is already strong:** mean recall 0.90; run3 hit all 10
milestones. It is **not free of error** — a consistent misattribution in every
run (below) and recall variance run-to-run (0.79–1.00) are exactly the failure
modes the MCP architecture targets.

## 3. The notable result: the baseline beat our hand-built oracle

The v1 ground truth (`~/reports/SRL-2015_case_report.md`) was **wrong on patient
zero and incomplete on three milestones**. The stock baseline got them right. When
its claims were adjudicated against **raw artifacts** (not against v1), they held:

| What v1 oracle said | What the baseline + raw evidence showed |
|---|---|
| Patient zero = **nromanoff** | **tdungan** (Java drive-by 04-03 00:33, ~18 h earlier) |
| (no initial-access vector) | signed Java applet `Signed_Update.jar` @ `207.58.245.179` |
| primary implant = `spinlock.exe` only | **httppump** RAT `dllhost\svchost.exe` (`4c7906e2…`) is primary; spinlock secondary |
| (no exfil finding) | `system4.rar` 6.3 MB (`06a889b1…`) staged on nfury |

→ The oracle was corrected to **v2** (`scoring/oracle_v2.json`) and an addendum
appended to the case report. **Methodological lesson for the submission:**
validate against *raw evidence*, never against a single human answer key — the
answer key itself can be wrong. This is the core accuracy-validation argument,
demonstrated rather than asserted.

## 4. The hallucination, in detail (every run)

**`wceisvista.inf` / `wceisvista.PNF` labeled "Windows Credentials Editor (WCE)."**
False. The files live in `\Windows\winsxs\…` and
`\Windows\System32\DriverStore\FileRepository\…` with **Win7-RTM SxS versioning
`6.1.7600.16385`** and standard Microsoft component manifests — a **legitimate
in-box INF**. WCE does not ship a winsxs INF. The agent pattern-matched a
suggestive filename to a known tool **without checking the path/provenance** — a
classic prompt-only-agent failure (no structured, typed artifact context forcing
it to look at where the file actually lives).

Note the *conclusion* (credential theft occurred) survives on independent
evidence (mimikatz `sekurlsa.dll`, procdump, domain-admin reuse), so this is an
over-attributed **indicator**, not a wholly invented event — but it is precisely
the kind of plausible-but-wrong claim the MCP server's typed, provenance-carrying
tool outputs are designed to prevent.

### Correctly-calibrated (NOT counted as hallucinations)
The baseline behaved well here, which matters for a fair comparison:
- Inbound IPs (`173.173.88.154→DC:443` etc.) flagged **suspicious/unverified**, not asserted malicious.
- `usboesrv.exe`/`96.255.98.154` and `10.3.16.5` correctly excluded as **legit USB-over-Ethernet / IR host** (self-correction milestone M10 — all 3 runs).
- Credential-dump *mechanism* inside `hythonize.exe` explicitly labeled **inference**.

## 5. What this sets up for the MCP agent ("after")

Targets the MCP-architecture agent must beat on the **same prompt + oracle_v2**:

1. **Recall ≥ 0.90 with lower variance** (baseline 0.79–1.00; the dip = a whole
   implant or the exfil archive missed on some runs).
2. **Hallucinations → 0** — specifically, no filename→tool attribution without a
   provenance/path check. The MCP wrapper returns the artifact's full path +
   source, making the wceisvista misattribution structurally hard to make.
3. **Audit trail** — baseline runs leave an `agent-log.jsonl` (deliverable #8) but
   no per-claim {tool, args, artifact, offset} ledger; the MCP provenance ledger
   does. That is a criterion-#5 differentiator, not a recall one.
4. **Cost/turns** are a secondary axis (~$6.6, ~79 turns/run); typed tools should
   cut turns by removing trial-and-error tool discovery.

## 6. Files

- `scoring/oracle_v2.json` — corrected 10-milestone ground truth (evidence-cited)
- `scoring/adjudication.md` — every baseline claim adjudicated vs raw evidence
- `scoring/score_baseline.py` — deterministic scorer
- `scoring/results.md` / `results.json` — scores
- `run{1,2,3}/` — `agent-log.jsonl`, `run-meta.json`, `reports/incident_report.md`
- Spoliation test: `spoliation/` (see `spoliation/README.md`)

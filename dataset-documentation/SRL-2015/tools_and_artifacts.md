# SRL-2015 — Tools & Artifacts

The tools the agent actually ran and the artifacts it analyzed on the SRL-2015 case,
extracted from the run's immutable provenance ledger (`provenance.jsonl`).

**1,244 tool executions logged** across the 4 hosts — every one court-vetted, run with
`shell=False`, and recorded with its full command, inputs, outputs, timestamps and status.

---

## Forensic tools used

| Tool (binary) | MCP wrapper | What it does | Runs |
|---|---|---|---:|
| `ewfmount` / `fusermount` | `open_ewf` / `close_ewf` | Mount/unmount E01 disk images **read-only** (FUSE) | 4 / 4 |
| `mmls` / `fsstat` | `inspect_disk` | Partition + filesystem layout | 4* / 4 |
| `icat` (Sleuth Kit) | `carve_files` / `extract_artifacts` | Extract files from NTFS by inode | 275 |
| `MFTECmd` | `parse_mft` | Parse `$MFT` (master file table) | 4 |
| `RECmd` | `parse_registry` | Parse registry hives | 4 |
| `reg_export` | `parse_reg_export` | Parse carved `.reg` exports | 85 |
| `AppCompatCacheParser` | `parse_shimcache` | Parse Shimcache (AppCompatCache) | 4 |
| `EvtxECmd` | `parse_evtx` | Parse Windows event logs (`.evtx`) | 4 |
| `log2timeline` / `psort` (Plaso) | `generate_timeline` / `filter_timeline` | Build + slice the super-timeline | 4 / 82 |
| `volatility3` | `run_volatility_plugin` | Memory forensics (allow-listed plugins) | 32** |
| `bulk_extractor` | `carve_network_artifacts` | Carve network artifacts from memory | 4 |
| `extract_pe_metadata` (`pefile`) | `extract_pe_metadata` | PE header / compile metadata | 145 |
| `detect_pyinstaller` | `detect_pyinstaller` | Flag PyInstaller-packed binaries | 145 |
| `extract_embedded_urls` | `extract_embedded_urls` | Pull embedded URLs (C2 triage) | 145 |
| `extract_pdb_paths` | `extract_pdb_paths` | Pull PDB build paths | 145 |
| `java_idx` | `parse_java_cache` | Parse Java IDX cache (drive-by) | 1 |
| `sha256sum` / `hashlib` | `hash_evidence` / `hash_file` | SHA-256 integrity hashing | 149 |

\* `mmls` returned no partitions on all 4 hosts — **expected**: SANS SRL-2015 `.E01` images
are single-volume (no partition table), so the agent falls back to `fsstat` at NTFS offset 0
(4/4 success). The failure is **logged, not hidden**.
\** 31/32 Volatility runs succeeded; the 1 failure is `windows.netscan` on the Windows XP
host (unsupported on XP) — again logged honestly, not faked.

---

## Artifacts analyzed

| Artifact | Source | Yields |
|---|---|---|
| `$MFT` | NTFS (disk) | File timestamps (SI/FN), paths, timestomp detection |
| Registry hives (SYSTEM / SOFTWARE / SAM / NTUSER) | disk | Run-key persistence, services, network endpoints |
| Carved `.reg` exports | disk | Configuration / persistence artifacts |
| Windows event logs (`.evtx`, legacy `.evt`) | disk | 4624/4625 logons, 4648 explicit creds, 7045 services, 4672 |
| Shimcache (AppCompatCache) | registry | Program-execution evidence |
| Super-timeline | Plaso (disk artifacts) | Cross-source chronological reconstruction |
| Process list / tree / scan, services, cmdline, netscan, malfind | memory (Volatility 3) | Running/hidden processes, injected code, C2 connections |
| Network artifacts | memory (bulk_extractor) | Carved IPs/URLs/sessions |
| PE binaries | carved files | Compile metadata, PyInstaller packing, embedded C2 URLs, PDB paths |
| Java IDX cache | disk | Initial-access drive-by evidence |
| SHA-256 hashes | evidence + files | Integrity + same-binary-across-hosts correlation |

---

## Kill-chain coverage (how tools → findings)

| Stage | Primary artifact(s) / tool(s) |
|---|---|
| Initial access | Java IDX cache (`parse_java_cache`) |
| Execution / implant | memory `malfind`/`pslist` + PE triage (`extract_pe_metadata`, `detect_pyinstaller`) |
| Persistence | registry Run keys + `at`-jobs (`parse_registry`, `parse_mft`) |
| Credential access | memory + event logs (`run_volatility_plugin`, `parse_evtx`) |
| Lateral movement | event logs 4624/4648/7045 + cross-host hash match (`parse_evtx`, `hash_file`) |
| Command & control | embedded URLs + memory netscan (`extract_embedded_urls`, `carve_network_artifacts`) |
| Exfiltration | `$MFT` + carved archive (`parse_mft`, `extract_archive`) |
| Anti-forensics / self-correction | disk↔memory reconciliation (deterministic correlation) |

Every finding in the case report cites the `provenance_id` of the exact tool run above —
see [`agent_result_scored_vs_oracle.md`](agent_result_scored_vs_oracle.md) for the 10/10
milestone-to-provenance mapping.

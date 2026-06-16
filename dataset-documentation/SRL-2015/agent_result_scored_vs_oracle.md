# Validation Score — srl2015

- Profile: `validation_profiles/srl2015.yml` (v2)
- **Recall (strict): 100%**  ·  with partial credit: 100%
- Milestones: 10 correct · 0 partial · 0 missed · 0 wrong
- Misses: 0 need a new parser · **0 despite parser (real bugs)**
- Hallucinations (uncited/unresolved confirmed|likely): **0** ✅
- Findings scored: 262

## Milestones

| Milestone | Stage | Status | facts | miss reason | provenance |
|-----------|-------|--------|-------|-------------|------------|
| M1_initial_access | initial_access | ✅ correct | 80% | — | cmd-000010, cmd-000022, cmd-000059 |
| M2_patient_zero | initial_access | ✅ correct | 100% | — | cmd-000003, cmd-000004, cmd-000005, cmd-000006, cmd-000008 |
| M3_primary_rat | execution | ✅ correct | 67% | — | cmd-000003, cmd-000006, cmd-000008, cmd-000022, cmd-000023 |
| M4_secondary_implant | execution | ✅ correct | 100% | — | cmd-000003, cmd-000004, cmd-000005, cmd-000006, cmd-000008 |
| M5_persistence | persistence | ✅ correct | 83% | — | cmd-000003, cmd-000006, cmd-000008, cmd-000022, cmd-000023 |
| M6_cred_access | credential_access | ✅ correct | 88% | — | cmd-000022, cmd-000090, cmd-000120, cmd-000125, cmd-000130 |
| M7_lateral_movement | lateral_movement | ✅ correct | 88% | — | cmd-000120, cmd-000125, cmd-000130, cmd-000131, cmd-000132 |
| M8_c2 | command_and_control | ✅ correct | 100% | — | cmd-000010, cmd-000065, cmd-000067, cmd-000941, cmd-000942 |
| M9_exfil | exfiltration | ✅ correct | 80% | — | cmd-000603 |
| M10_self_correction | anti_forensics | ✅ correct | 100% | — | cmd-000231, cmd-000961 |

## Coverage by kill-chain stage

| Stage | correct | partial | missed | wrong |
|-------|---------|---------|--------|-------|
| initial_access | 2 | 0 | 0 | 0 |
| execution | 2 | 0 | 0 | 0 |
| persistence | 1 | 0 | 0 | 0 |
| credential_access | 1 | 0 | 0 | 0 |
| lateral_movement | 1 | 0 | 0 | 0 |
| command_and_control | 1 | 0 | 0 | 0 |
| exfiltration | 1 | 0 | 0 | 0 |
| anti_forensics | 1 | 0 | 0 | 0 |

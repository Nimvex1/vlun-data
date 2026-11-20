# Wave-1 Phase 1 — build & verification summary

All outputs are confined to `wave1/` (plus git-ignored `work/sources/` clones/API cache).
Canonical layers and the `Vbeta/present_snapshot.json` sentinel are byte-untouched.

## Governance applied
- EVMbench (#1) DROPPED as a task source (synthetic overlay patches ineligible).
- ReEVMBench (#2) APPROVED in scope — distinct Apache-2.0 executable harness repo, not the
  excluded `blocksecteam/audit-reports`; recorded in `00_governance/rights.jsonl`.
- METADATA_ONLY enforced: no full issue/comment/report prose is vendored.
- F/G/J PRIMARY design: both label classes ingested; splits stratified by contest/repo slug;
  `>=100` scorable, `>=2` labels, `>=30` held-out, train-only shortcut `<0.9`.

## Foundation
- `00_governance/PRESENT.md` + `.json` — new sentinel (canonical hashes + wave1 script hashes).
- `00_governance/rights.jsonl` — 7 rows; `source_registry.jsonl` — 6 rows.
- `01_dedup/registry.jsonl` — **24,074 unique keys**: v1 (1,637 finding ids, 1,637 repos,
  46 renft-mitigation issue occupancies), v2.2 (112 sources, 77 GHSA, 71 CVE, 9 CWA/RUSTSEC
  aliases + 6 fold edges), V3 (7,712 candidate ids, 517 attack txs, 200 certora report pointers,
  18 sources), Vbeta (13,995 finding ids, 2,421 Solodit URLs, 15 sources), V4 (5,268 candidates,
  12 GHSA, 3 sources), Prove (131 revision pairs).
- `scripts/{_common,build_governance,build_dedup_registry,dedup_check,validate_wave1}.py`
  and `tests/test_wave1.py` (9 tests).

## Adapters — exact admitted vs deduplicated
| Adapter | Found | Collisions/dropped | Admitted | Notes |
|---|---:|---:|---:|---|
| mitigation (#4) | 812 issues | 213 issues / 214 overlap rows | **531** | 418 confirmed + 113 unmitigated; 0 API failures |
| formal (#6) | 7,042 rules | 0 (after narrowing the Certora-pointer rule to full report identity) | **7,042** | 3,180 CVL + 3,862 Foundry; 7,042 high invariants |
| markdown (#7) | 786 items | 193 / 667 overlap rows | **575** | 557 high + 18 low; yAudit not harvested |
| ghsa (#3) | 35 advisories | 4 | **31** | 20 high + 11 low; 29 real fix commits; 5/12 API calls |
| **TOTAL** | — | **885 overlap rows** | **8,179** | 15,425 dedup keys checked, 0 collisions |

## Benchmark families (`benchmark_wave1/`)
| Family | Rows | Scorable | Observed labels | Test rows | PRIMARY-ready |
|---|---:|---:|---|---:|---|
| G_patch_verification | 748 | 748 | 4 (confirmed, unmitigated, high, low) | 253 | yes |
| J_verified_patch | 748 | 748 | 4 | 253 | yes |
| invariants | 7,646 | 7,646 | 6 (assertion, function, rule, invariant, high, low) | 814 | yes |

## Gates (all PASS)
- (a) single-writer path confinement — static scan of all wave1 scripts.
- (b) PRESENT / canonical drift — 8 canonical files hash-identical to baseline.
- (c) `dedup_check.py --check` — 0 collisions across 8,179 admitted rows / 15,425 keys.
- (d) rights & METADATA_ONLY — 0 unlicensed full-prose leaks; 7 rights decisions recorded.
- (e) benchmark readiness — all 3 families meet the strict PRIMARY criteria.
- `python -m unittest discover -s wave1/tests` — 9 tests OK.

## Caveats carried forward
1. Formal rows are **observed declarations**, not verification verdicts — `verification_status =
   observed_declaration_unverified`, `verdict_flag` empty. `quality.invariants="high"` reflects a
   stated property, not a proved one.
2. GHSA fix commits for 29 rows were resolved from patched-version release tags
   (`fix_commit_basis=patched_version_tag`) — real commits containing the fix, not necessarily the
   exact fixing commit. 2 advisories had no resolvable fix commit and produced no benchmark rows.
3. yAudit was not harvested (no canonical repo; code search needs auth). Nothing fabricated.
4. G/J split is stratified to maximize test rows; train/val/test = 465/30/253 — the test share is
   larger than ideal, but the train-only shortcut check still passes. Rebalance before publication.
5. ReEVMBench (#2) is registered but QUEUED — not harvested in Phase 1.
6. Merge into canonical layers remains a separate future step; nothing in this tree writes there.

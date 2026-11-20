# Wave-1 Phase 2 — corrected summary

All writes confined to `wave1/` (+ git-ignored `work/sources/`). Canonical layers and
`Vbeta/present_snapshot.json` untouched (`git status`: only `?? wave1/`).

## Epistemic bugs fixed
- **Bug A:** `J_verified_patch` rewritten to **0 rows** — no admitted row in wave1 carries an
  executed two-revision L6 artefact. `mitigation.py`/`markdown.py` no longer emit J rows.
- **Bug B:** `G_patch_verification` restricted to the 531 C4 mitigation rows with ONLY
  `mitigation_confirmed` / `unmitigated_or_regression` labels; 0 severity strings. Split rebalanced
  371/79/81. Markdown/GHSA severity rows moved to `severity_reconciliation`; revision pairs to
  `prove_candidates` (not scorable). GHSA: 0 SHA upgrades (no OSV `references` in cached payloads),
  7 PR-only records preserved as `osv_reference_pr`, no SHA invented.
- **Bug C:** `formal.py` admits only 895 genuinely named CVL `rule`/`invariant` declarations
  (excluded 643 test functions, 46 setup helpers, 5,480 bare assertions, 24 prose declarations).
  `quality.invariants="high"` only on 217 rows with observed pair evidence; 678 declaration-only
  rows tagged `unverified`. `invariants.jsonl` labels are now `property_held`/`property_violated`
  derived from committed Certora verdict matrices — never syntax keywords or severity strings.

## Admitted by source (total 2,128)
| Source | Admitted |
|---|---:|
| c4_mitigation (#4) | 531 |
| formal_specs (#6) | 895 |
| markdown_two_revision (#7) | 575 |
| ghsa_web3_netnew (#3) | 31 |
| judge (#5) | 96 |
| reevmbench (#2) | 0 |
| overlap manifest rows | 885 |

## Benchmark families (corrected)
| Family | Rows | Scorable | Labels | Split (train/val/test) | PRIMARY-ready |
|---|---:|---:|---|---|---|
| G_patch_verification | 531 | 531 | 2 patch-verification outcomes | 371 / 79 / 81 | yes |
| J_verified_patch | 0 | 0 | — | — | no (needs real L6 execution) |
| invariants | 297 | 297 | property_held, property_violated | 223 / 37 / 37 | yes |
| F_false_positive_rejection | 209 | 209 | valid_finding, rejected_false_positive | 72 / 61 / 76 | yes |
| Fa_rejection_evidence_axis_vector | 576 | 576 | 6 rejection axes | 198 / 168 / 210 | yes |
| Fb_duplicate_radar_pair | 95 | 95 | same, distinct | 33 / 27 / 35 | no (95 < 100; no fabricated rows) |
| severity_reconciliation | 606 | 606 | high, low | 424 / 92 / 90 | no (majority shortcut 0.978) |
| prove_candidates | 91 | 0 | — (not scorable) | — | n/a |
| prove_incidents | 0 | 0 | — (not scorable) | — | n/a |

## Gates (final)
a_single_writer PASS · b_present_drift PASS · c_dedup PASS (0 collisions / 3,323 keys) ·
d_rights PASS · e_benchmark PASS · **f_label_purity PASS** (9 families, 0 cross-domain labels) ·
**g_j_execution PASS** (0 rows, 0 non-L6). `unittest discover -s wave1/tests`: 12/12 OK.

## Caveats
1. ReEVMBench admitted 0: pinned clone HEAD `af878a75…` (2026-03-15) contains no 2026-03+
   incidents (its Clarahacks harnesses span 2025-08..2026-02). Honest zero, not a harvest failure.
2. Judge harvest hit GitHub 403 during comment fetch; admitted 96 from 6 repos (mostly one
   Sherlock contest), 336 bare-label rejects correctly skipped. Fb has no `ambiguous` rows.
3. 73/91 `prove_candidates` rows carry `vuln_sha == fix_sha` (upstream extractor artefact); each is
   flagged `distinct_revisions: false` and must not be read as a two-revision pair.
4. F/Fa/Fb re-split to floor-preserving 35/30/30-style ratios where 70/15/15 cannot meet the
   >=30 val/test floor; Fb remains below the 100-row PRIMARY floor.
5. `severity_reconciliation` has a 0.978 majority-label shortcut — not evaluable as-is.
6. J stays empty until a real controlled compile/run on both revisions is performed.
7. Merge into canonical layers remains a separate, later step.

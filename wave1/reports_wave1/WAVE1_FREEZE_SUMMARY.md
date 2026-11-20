# Wave-1 freeze summary — final state

All writes confined to `wave1/` (+ git-ignored `work/sources/`). Canonical layers and
`Vbeta/present_snapshot.json` untouched (`git status --porcelain`: only `?? wave1/`).
Full rebuild: `python wave1/scripts/build_wave1.py` → PASS in 7.1s, 0 failures.

## The three surgical fixes
1. **ReEVMBench unblocked** — `WINDOW_MONTHS` calendar cutoff removed; all 67 harnesses scanned,
   27 parsed and tested purely by registry key (`tx:<chain>:<0x64>`, `(protocol_norm, YYYY-MM)`,
   C4 `(contest_slug, finding_id)`). 7 tx collisions, 0 protocol/C4 collisions, 40 unparseable,
   **20 net-new incidents admitted** into `04_admitted/reevmbench/` and `prove_incidents.jsonl`.
2. **Fb promoted** — `judge.py` now authenticates via `GITHUB_TOKEN`/`GH_TOKEN`/`gh auth token`
   (verified: `gh_cli`), and mines verified duplicate/corroborated pairs from the 812 cached
   `c4_mitigation` issues (430 mined: 320 same, 110 distinct; 0 invented ambiguous). Fb =
   **527 scorable rows**, 2 labels (`same` 411 / `distinct` 116), 74 contests, split
   210/157/160 with both labels in every split — PRIMARY-ready.
3. **prove_candidates cleaned** — strict filter: both SHAs 40-hex and strictly distinct with
   real provenance. **18 rows, 0 equal-SHA, 0 answers/labels**. 73 equal-SHA + 440 invalid-SHA
   rows dropped from the pool (they remain in admitted findings). Markdown/mitigation now emit
   distinct pairs when an audited + fix SHA are both recorded.

## Benchmark families (final)
| Family | Rows | Scorable | Labels | train/val/test | Shortcut | PRIMARY |
|---|---:|---:|---:|---|---:|---|
| F_false_positive_rejection | 212 | 212 | 2 | 73/62/77 | 0.5325 | yes |
| Fa_rejection_evidence_axis_vector | 594 | 594 | 6 | 204/174/216 | 0.1667 | yes |
| Fb_duplicate_radar_pair | 527 | 527 | 2 | 210/157/160 | 0.7750 | **yes (promoted)** |
| G_patch_verification | 531 | 531 | 2 | 371/79/81 | 0.7531 | yes |
| J_verified_patch | 0 | 0 | 0 | — | — | no (needs real L6 execution) |
| invariants | 297 | 297 | 2 | 223/37/37 | 0.7838 | yes |
| severity_reconciliation | 606 | 606 | 2 | 424/92/90 | 0.9778 | no (majority shortcut) |
| prove_candidates | 18 | 0 | 0 | — | — | not scorable |
| prove_incidents | 20 | 0 | 0 | — | — | not scorable |

Six PRIMARY families (F, Fa, Fb, G, invariants — plus A-v1 outside this tree). Admitted by source:
c4_mitigation 531, formal_specs 895, markdown 575, ghsa 31, judge 99, reevmbench 55 = **2,186**.

## Verification (final)
`dedup_check.py --check`: registry 24,074 / admitted 2,186 / keys 3,550 / collisions 0 / overlaps 896 → PASS.
`validate_wave1.py`: a PASS · b PASS · c PASS · d PASS · e PASS · f_label_purity PASS ·
g_j_execution PASS → overall PASS. `unittest discover -s wave1/tests`: 12/12 OK.

## Residual caveats
- J stays empty until a controlled vulnerable/fixed compile+run is actually performed.
- severity_reconciliation has a 0.978 majority-label shortcut (577 high / 29 low) — not evaluable.
- 40 ReEVMBench harnesses are UNPARSEABLE (no tx/date); they are candidates, not admissions.
- 12 GHSA advisories were unretrievable at harvest time; nothing was fabricated.
- Merge into canonical layers remains a separate, later step.

# Independent benchmark validity evaluation

**Status snapshot: 2026-10-28.** This report reviews the benchmark's fitness for evaluation; it is not a model result or a legal clearance. Machine-readable measurements are authoritative in `reports/independent/audit.json` and `reports/benchmark_metrics.json`. No benchmark rows, labels, splits, or answer keys were changed for this review.

## Executive conclusion

**There is currently no `PRIMARY` benchmark family.** The independent audit finds 13 `INVALID`, 6 `EXPLORATORY`, and 5 `NOT_SCORABLE` families. Of the 19 families with scalar keys, zero currently meet the criteria for a headline evaluation claim. The benchmark can still support research and diagnostics, but it must not be presented as a leaderboard-ready evaluation set.

Family A is the critical blocker. Its 720 scorable rows contain **14 groups of identical model-facing inputs with conflicting gold labels, affecting 306 rows**. In addition, **290/720 rows omit the non-empty code required by the detection task**; this includes **121/147 test rows**. A's previous 0.5510 majority-on-test result is now a diagnostic measurement only, not an eligible floor or model-comparison threshold. The labels and splits have not been silently changed to make the status look better.

This is not “10/10” yet. Claim-level human adjudication, annotation-agreement measurement, and rights clearance remain open; no model has been run on an eligible primary set.

## Method and status rules

`scripts/independent_benchmark_audit.py` reads the committed task files and independently measures exact-input/gold consistency, required-input completeness, answer-literal leakage, label degeneracy, split drift, group/record overlap, near-duplicate overlap, and train-only shortcuts. For exact-input consistency it canonicalizes the full model-facing `input` object; IDs, source metadata, and split labels do not distinguish two prompts. The audit is additive and does not rewrite dataset rows.

`scripts/benchmark_status.py` assigns family status from those measurements. A family is `PRIMARY` only if it has no hard validity flag, enough scorable rows and observed labels, and no dominating train-only shortcut. A validity flag makes a family `INVALID`; small or single-label families remain `EXPLORATORY`; tasks without a scalar exact-match key are `NOT_SCORABLE` in this scorer. Unknown family files fail closed. Retirement is a storage location, not a validity verdict.

The new hard flags are:

- `conflicting_gold_for_identical_input`: identical inputs carry different scalar labels.
- `required_code_missing`: scorable rows omit code required by the Family A task contract.

## Family status

Source: `reports/benchmark_metrics.json` → `family_status` and `task_coverage`. `Tasks` counts all family rows; `scorable` counts rows with a scalar key in the headline scorer. Fa/Fb have separate extension scoring contracts and are not included in the headline exact-match projection.

| family | tasks | scorable | labels | status | main reason / note |
|---|---:|---:|---:|---|---|
| A | 720 | 720 | 2 | **INVALID** | 14 exact-input gold-conflict groups (306 rows); 290 required-code omissions |
| B | 720 | 228 | 1 | EXPLORATORY | single observed label |
| C | 720 | 290 | 4 | INVALID | train/test label-mix drift (L1 1.0303) |
| D | 720 | 0 | 0 | NOT_SCORABLE | generative; requires a judge |
| E | 720 | 7 | 2 | INVALID | too small; one test row; split drift |
| F | 458 | 17 | 1 | EXPLORATORY | single label; no held-out rows |
| Fa | 458 | 0 | 0 | NOT_SCORABLE | vector of evidence axes; separate per-axis scorer |
| Fb | 554 | 0 | 0 | NOT_SCORABLE | pair-adjudication extension; separate scorer |
| G | 38 | 5 | 1 | EXPLORATORY | only five same-exploit/two-revision verified rows |
| H | 7 | 0 | 0 | NOT_SCORABLE | descriptive answers; no scalar label |
| I | 3 | 1 | 1 | EXPLORATORY | single label; too small |
| J | 5 | 5 | 1 | EXPLORATORY | single label; no held-out rows |
| K | 137 | 137 | 5 | INVALID | answer-literal leakage, group overlap, split drift, lookup shortcut |
| L | 137 | 128 | 6 | INVALID | answer-literal leakage, group overlap, split drift |
| M | 37 | 37 | 3 | EXPLORATORY | one held-out row |
| N | 137 | 14 | 2 | INVALID | group overlap, split drift, too small |
| O | 137 | 137 | 10 | INVALID | group overlap, split drift, lookup shortcut |
| P | 137 | 137 | 3 | INVALID | group overlap, split drift, lookup shortcut |
| Q | 137 | 0 | 0 | NOT_SCORABLE | judge-graded rubric dictionary |
| R | 5467 | 5467 | 3 | INVALID | held-out label absent from train; split drift |
| S | 1072 | 1072 | 2 | INVALID | 98.51% majority class; shortcut saturation |
| T | 589 | 589 | 2 | INVALID | 99.83% majority class; near-duplicate leak; 2 test rows |
| U | 6219 | 6219 | 6 | INVALID | 98.34% train-only majority accuracy; record-ID overlap |
| V | 6935 | 6935 | 2 | INVALID | 99.98% train-only majority accuracy; record-ID overlap |

**Counts: 0 `PRIMARY`, 6 `EXPLORATORY`, 13 `INVALID`, 5 `NOT_SCORABLE`.** The 22,145 scalar-scorable rows remain present in their source families (21,852 invalid and 293 exploratory); the invalid rows are reported, not silently removed.

## Family A: the blocker in detail

The exact-input check compared all 720 labeled rows and found **384 unique full inputs**. Fourteen input groups map to both `vulnerable` and `no_confirmed_vulnerability`; 306 rows belong to those groups. This is a task-definition defect: a model given the same input cannot infer which of two contradictory keys is intended. It is not safe to choose a label by majority or to rewrite the split automatically.

The required-code check found **430 rows with a non-empty code block and 290 without one**. The missing rows are distributed across train (13), validation (156), and test (121). In particular, only 26 of 147 test rows carry code. A code-vulnerability detector cannot be evaluated on the intended task when most held-out prompts lack the required code input.

**Repair required before any A evaluation claim:** review the conflicting claims against their cited source evidence; adjudicate at claim level; restore source-backed code where available or explicitly mark rows unscorable under a documented rule; then regenerate and audit the task layer. Do not flip labels, fabricate missing code, or change splits merely to clear a gate. A's prior train-only majority score of 0.5510 remains useful for understanding the old partition, but is not a valid floor while A is `INVALID`.

## Current headline metric and baselines

`reports/benchmark_metrics.json` currently reports an empty primary set: **0 families and 0 scorable rows**. Consequently there is no eligible headline score, no eligible held-out split, and no primary-set baseline floor. The metric's model accuracy and macro-F1 are null; no predictor has been run. This null must not be rendered or interpreted as a score of zero.

The six baseline reports have been regenerated. Their primary blocks have zero eligible rows. The all-family continuity diagnostic still includes all **22,145** scalar-scorable rows; the majority report has 22,134 predictions and an accuracy denominator of 21,889 because 256 rows in single-label families are not evaluable for accuracy. Its continuity accuracy is **0.8687** and macro-F1 **0.2386**. These figures combine invalid, exploratory, and retired families and are for continuity only—not a model result, valid leaderboard score, or evidence that the data are accurate.

The per-family train-only figures in `reports/benchmark_metrics.json` can explain why a family was demoted. Any such number for an `INVALID` family is a **diagnostic**, not an achievable-score claim or comparison threshold. This includes A's old 0.5510 test majority result and the high shortcut scores on U/V.

## Other validity findings

- **Split composition and label support:** C's train/test label-mix L1 distance is 1.0303. R's held-out label `0` is absent from train and its label-mix distance is 1.7827. These partitions cannot support ordinary held-out claims as-is.
- **Shortcut and group structure:** U's train-only majority scores 0.9834 and V's 0.9998 on their official test splits. K and O have train-only source/group lookups at 1.0000; P reaches 0.9032. These are demotion evidence, not model results.
- **Answer text in the evidence:** K contains its gold label in evidence on 76/137 rows (rate 0.5547); L does so on 94/128 (rate 0.7344). K's group structure also overlaps train/test. Treat these tasks as contaminated for their current purpose.
- **Single-label families:** B, F, G, I, and J carry one observed scalar label; accuracy is not meaningful for them. Their rows stay counted, but a constant predictor's 1.000 must not be reported as performance. M is exploratory because its held-out split has one row.
- **Family G evidence:** only 5 of 38 patch records have an identical exploit run against both vulnerable and fixed revisions; 31 are `not_testable` and 2 lack a controlled same-harness two-revision comparison. See `reports/patch_verification_v2.json`.
- **Negative labels:** public rejection is not equivalent to a verified false positive. The evidence layer distinguishes corroborated duplicates, unknown/insufficient cases, attributed judge/sponsor reasons, code-supported reasons, and failed exploit attempts. There are zero failed exploit attempts that demonstrate the claimed violation did not occur. See `reports/rejection_evidence.md` and the E-6 entry in `docs/EVIDENCE_LEDGER.md`.

## Secondary holdout and key visibility

`benchmark/independent/secondary_holdout_manifest.json` records a separate, additive holdout layer. Its clean partition has **2,684 rows** and zero known literal-answer overlap under the builder's check; this is not a proof of contamination-free data. A separate exploratory partition has 32 rows, 29 with literal overlap (K: 20, L: 9); do not use those rows as independent evaluation evidence. Seven group-disjoint holdouts were built. Only three class-disjoint holdouts were built in the current manifest (P, R, U); other families are skipped with explicit reasons, including empty-retained-side, insufficient support, and contamination.

The secondary holdout answer key is **OPEN-KEY and local-only/untracked**: it is reproducible from the committed benchmark sources and recorded seed, not secret. Do not describe it as committed, private, or protected. Official family keys are also open-key. The only genuinely private evaluation here is VLUN-Prove; its current interface records 5 gradable tasks against a target of 200 (`target_met: false`).

## Remaining validity threats: broader dataset and release limitations

These issues sit outside the exact-match audit but block a “10/10” or unrestricted-release claim:

- **Human validation:** inter-annotator agreement has not been measured. A frozen 300-item sample still awaits two qualified reviewers. Automated audit flags can identify contradictions; they cannot adjudicate underlying vulnerability claims.
- **Rights:** rights clearance remains blocked pending rights-holder permissions. `RELEASE_MANIFEST.json` lists 483 released paths and 1,347 not released; 142 paths contain measured verbatim third-party content and 13 have measured personal data. The full repository snapshot is not the release whitelist.
- **V4 provenance and extraction:** the manifest reports 5,268 admitted records, 2,554 missing provenance, and all candidates at L0; vulnerability class remains unknown. The structural check flags 1,971 impact fields as likely TOC-contaminated, while a tighter predicate flags 31. These are measured extraction risks, not individually adjudicated errors.
- **Evidence pointers:** derived facts and claims frequently lack machine-readable references; missing pointers limit verification and reproducibility.
- **Open-key status:** all benchmark answer keys in the public families are accessible in the repository. VLUN-Prove is the only private evaluation, and its small current pool is not a substitute for a mature held-out set.

## Remediation order

1. **P0 — Family A claim-level repair.** Resolve all 14 conflicting-input groups with source evidence; repair or explicitly exclude rows with missing required code; preserve a complete decision log; do not alter labels or splits without a documented, reviewable basis. Re-run audit, status, metrics, baselines, and generated docs.
2. **P1 — repair or retire evaluation claims for other invalid families.** Redesign splits only where group and class support allow it; add evidence-backed labels rather than synthetic balance; keep shortcut and leakage results visible.
3. **P1 — human review.** Complete the frozen two-reviewer sample, report inter-annotator agreement and adjudication protocol, and keep uncertainty explicit.
4. **P1 — rights and release controls.** Obtain permissions or remove/redact restricted content from the release view; run rights checks against the exact release manifest before distribution.
5. **P2 — improve coverage and reproducibility.** Expand controlled two-revision exploit/patch tasks; fill missing provenance and source references; validate near-duplicate/semantic detectors against a hand-labeled sample.

## Reproduction and verification

```bash
python scripts/independent_benchmark_audit.py
python scripts/score_benchmark.py --build-baselines --build-metrics
python scripts/generate_readme.py
python scripts/build_datasheet.py
python scripts/run_gates.py
```

The audit is read-only with respect to benchmark rows, splits, and keys. `--check` modes verify generated outputs without rewriting them. Validation on 2026-10-28:

- Full `python scripts/run_gates.py` run: **PASS**, 55 configured; 45 passed, 0 failed, 10 skipped. Skips are missing-input checks (private split/ledgers, pinned source clones, V3 PoC/span sources, API-sibling sources); they are not passes. The subsequent documentation-only family-count correction was checked separately below.
- At that full-run snapshot, `python -m unittest discover -s tests` passed with 19 skipped (761 tests at that point); `python Vbeta/tests/test_vbeta.py` passed all 38 tests. After the final README count correction, the complete `tests.test_generated_docs` module passed all 31 tests and Vbeta validation again reported 0 critical failures with 38 Vbeta tests passing.
- Ruff 0.17.3 (`ruff check scripts/ tests/ Vbeta/scripts/ Vbeta/tests/`): **PASS** (checked in an isolated temporary environment; Ruff is not a project dependency).
- After the metrics-renderer cleanup, all 6 benchmark gates passed. The later README family-count-only correction passed the 31-test generated-doc suite, README/datasheet checks, the 775-file JSON-catalog check, Vbeta validation/tests, Ruff, and `git diff --check`.
- An accidental machine-local path in this report was then removed; `tests.test_no_machine_paths` passed 19 tests and `python scripts/run_gates.py --only paths` passed 2/2 gates.

Canonical outputs:

- `reports/independent/audit.json` — independent per-family measurements.
- `reports/benchmark_metrics.json` and `.md` — status, denominators, limits, and primary metric.
- `reports/baselines/` — generated baseline reports.
- `benchmark/independent/secondary_holdout_manifest.json` — holdout definitions and skip reasons.
- `docs/QUALITY_CHECKLIST.md` and `docs/EVIDENCE_LEDGER.md` — open repairs and evidence status.

# Independent benchmark validity evaluation

Audit of the VLUN benchmark families A–V for leakage, shortcut baselines and
task validity. Every number below is read from a current report, and the
report is named next to the number:

| what | source |
|---|---|
| family status, reasons, primary metric, floors | `reports/benchmark_metrics.json` |
| per-family leakage, degeneracy, drift, overlap, near-duplicates | `reports/independent/audit.json` |
| the six published baselines, per block, per split, per class | `reports/baselines/baseline_*.json` |
| the secondary holdout's splits, verdicts and shortcut scores | `benchmark/independent/secondary_holdout_manifest.json` |
| the open-key statement, the protected set, the model-visible corpus | `reports/eval_leakage_report.json` |
| the patch-verification counts behind family G | `reports/patch_verification_v2.json` |
| the machine-path scan | `reports/machine_path_scan.json` |

This is an evaluation of the benchmark, not of the repository. The
repository's own gates pass; that fact is not evidence of anything here, and
is not used as evidence anywhere in this report.

**Post-purge update (2026-11-22).** Every figure below was re-read from the
committed reports after the hydration/purge. The headline changed: A and C
are both clean (C was repaired, not merely un-flagged), the primary metric
covers A+C, and U/V no longer have a held-out split at all. Where an old
number is withdrawn, the replacement is stated in §10.

**Headline: of 24 family files, 19 carry a scalar answer key, and two of
them survive as clean evaluation evidence (A and C).** The primary metric
covers **1,051 scorable rows of two families**. Its accuracy is **null** —
not measurable, because no predictor has been run against this benchmark —
and the train-only held-out floors to beat are **0.6228 on A's 114 test rows
and 0.7966 on C's 59 test rows**.

**This document was rewritten.** The previous version was written before the
benchmark-status rework and quoted numbers that the current reports no
longer produce. Every claim that is withdrawn, and the figure that replaces
it, is listed in [§10](#10-claims-retracted-or-downgraded-by-this-rewrite).

---

## 1. Method and independence

`scripts/independent_benchmark_audit.py` re-implements every check from the
benchmark files directly. It does not import `scripts/score_benchmark.py`'s
answers, its heuristics, or any repository gate output. The only thing
reused is the **scoring rule**, deliberately, so the two evaluations are
comparable: *exact match on the lowercased projected scalar, labeled rows
only; macro-F1 is unweighted over the classes present in gold or prediction*
(`reports/independent/audit.json` → `scoring_rule`).

The family status is **not** in the audit script. It is computed at run time
by `scripts/benchmark_status.py` from the audit's own measurements, and
written to `reports/benchmark_metrics.json` → `family_status` and
`family_floors`. The status rules are thresholds, not family names:

| status | rule (`status_rules` in the same report) |
|---|---|
| `PRIMARY` | no validity flag, at least 100 scorable rows, at least 2 observed labels, and no train-only shortcut at or above 0.9 on a holdout of at least 30 rows |
| `EXPLORATORY` | shipped and scored, but demoted: too small, holdout too small, or a single observed label (accuracy is null with a reason) |
| `INVALID` | a validity flag makes the family unusable as evaluation evidence |
| `NOT_SCORABLE` | no exactly-matchable scalar key |
| `UNKNOWN` | a family file on disk that no rule covers: fail-closed, never primary |

A family cannot enter the headline because its name is absent from a
retirement list, and a family file added to `benchmark/` without a rule
cannot enter it by accident: "no rule matched" is not "no problems found".

Two properties are enforced by test rather than by assertion:

- `TestAdditiveAndReproducible` hashes every file under `benchmark/` and
  `Vbeta/benchmark_vbeta/` before and after the audit and the holdout build,
  and fails if a byte changed. The layer is additive.
- `TestAuditInvariants.test_answer_leak_detector_fires_on_a_planted_leak`
  plants a known leak and requires it to be caught, so a detector that
  silently stopped matching cannot report the benchmark clean.

The holdout was built from the committed benchmark files and did not exist
while any published score was produced. No model, prompt or threshold was
tuned against it.

---

## 2. Family status — the table, and the reason for every row

Source: `reports/benchmark_metrics.json` → `family_status`. `Scorable` is
the number of rows that carry an exactly-matchable scalar answer key.

| family | scorable | labels | status |
|---|---|---|---|
| A | 658 | 2 | **PRIMARY** |
| B | 228 | 1 | EXPLORATORY |
| C | 393 | 4 | **PRIMARY** |
| D | 0 | 0 | NOT_SCORABLE |
| E | 7 | 2 | INVALID |
| F | 17 | 1 | EXPLORATORY |
| G | 7 | 1 | EXPLORATORY |
| H | 0 | 0 | NOT_SCORABLE |
| I | 1 | 1 | EXPLORATORY |
| J | 3 | 1 | EXPLORATORY |
| K | 137 | 5 | INVALID |
| L | 128 | 6 | INVALID |
| M | 37 | 3 | EXPLORATORY |
| N | 14 | 2 | INVALID |
| O | 137 | 10 | INVALID |
| P | 137 | 3 | INVALID |
| Q | 0 | 0 | NOT_SCORABLE |
| R | 4623 | 3 | INVALID |
| S | 331 | 2 | INVALID |
| T | 0 | 0 | EXPLORATORY |
| U | 80 | 3 | INVALID |
| V | 80 | 1 | EXPLORATORY |

The reason for every row, in full:

| family | status | scorable | labels | why |
|---|---|---|---|---|
| `A_vulnerability_detection.jsonl` | **PRIMARY** | 658 | 2 | no validity flag; 658 scorable rows, 2 labels, train-only shortcut floor 0.6228 on 114 held-out rows (majority class covers 0.7447 of the rows; reported, not demoted: the minority class is still worth detecting and the train-only floor shows whether it is) |
| `B_root_cause_reasoning.jsonl` | EXPLORATORY | 228 | 1 | demoted: single_label: every scorable row carries the label `invariant_stated` |
| `F_false_positive_rejection.jsonl` | EXPLORATORY | 17 | 1 | demoted: single_label: every scorable row carries the label `invalid`; holdout_too_small: 0 held-out rows (< 30) |
| `G_patch_verification.jsonl` | EXPLORATORY | 7 | 1 | demoted: single_label: every scorable row carries the label `effective`; holdout_too_small: 0 held-out rows (< 30) |
| `I_verified_non_exploit.jsonl` | EXPLORATORY | 1 | 1 | demoted: single_label: every scorable row carries the label `exploitable`; holdout_too_small: 0 held-out rows (< 30) |
| `J_verified_patch.jsonl` | EXPLORATORY | 3 | 1 | demoted: single_label: every scorable row carries the label `effective`; holdout_too_small: 0 held-out rows (< 30) |
| `M_experiment_level_classification.jsonl` | EXPLORATORY | 37 | 3 | demoted: holdout_too_small: 1 held-out rows (< 30) |
| `C_attacker_reasoning.jsonl` | **PRIMARY** | 393 | 4 | no validity flag; 393 scorable rows, 4 labels, train-only shortcut floor 0.7966 on 59 held-out rows (majority class covers 0.8651 of the rows; reported, not demoted: the minority class is still worth detecting and the train-only floor shows whether it is) |
| `E_exploit_verification.jsonl` | INVALID | 7 | 2 | invalid as evaluation evidence: split_composition_drift: train/test label mix L1 distance 0.6667 (>= 0.40); too_small_to_score: 7 scorable rows (< 30); holdout_too_small: 1 held-out rows (< 30) |
| `K_language_ecosystem_routing.jsonl` | INVALID | 137 | 5 | invalid as evaluation evidence: answer_literal_leak: the label appears in the evidence on 76 of 137 rows (rate 0.5547); group_overlap: 31 of 31 held-out rows share a group with train; split_composition_drift: train/test label mix L1 distance 0.534 (>= 0.40); a train-only baseline (`source_only_lookup`) scores 1.0 on the 31 held-out rows, at or above 0.9 |
| `L_severity_reconciliation.jsonl` | INVALID | 128 | 6 | invalid as evaluation evidence: answer_literal_leak: the label appears in the evidence on 94 of 128 rows (rate 0.7344); group_overlap: 29 of 29 held-out rows share a group with train; split_composition_drift: train/test label mix L1 distance 0.5316 (>= 0.40); holdout_too_small: 29 held-out rows (< 30) |
| `N_attacker_identity_extraction.jsonl` | INVALID | 14 | 2 | invalid as evaluation evidence: group_overlap: 2 of 3 held-out rows share a group with train; split_composition_drift: train/test label mix L1 distance 0.6 (>= 0.40); too_small_to_score: 14 scorable rows (< 30); holdout_too_small: 3 held-out rows (< 30) |
| `O_record_class_and_scope.jsonl` | INVALID | 137 | 10 | invalid as evaluation evidence: group_overlap: 31 of 31 held-out rows share a group with train; split_composition_drift: train/test label mix L1 distance 0.534 (>= 0.40); a train-only baseline (`source_only_lookup`) scores 1.0 on the 31 held-out rows, at or above 0.9 |
| `P_provenance_tier_and_rights.jsonl` | INVALID | 137 | 3 | invalid as evaluation evidence: group_overlap: 31 of 31 held-out rows share a group with train; split_composition_drift: train/test label mix L1 distance 0.4864 (>= 0.40); a train-only baseline (`source_only_lookup`) scores 0.9032 on the 31 held-out rows, at or above 0.9 |
| `v3_R_source_tier_routing.jsonl` | INVALID | 4,623 | 3 | invalid as evaluation evidence: held_out_labels_unseen_in_train: `['0']`; split_composition_drift: train/test label mix L1 distance 1.8999 (>= 0.40) |
| `v3_S_contest_outcome.jsonl` | INVALID | 331 | 2 | invalid as evaluation evidence: saturated: majority class `finding` covers 0.9577 of the rows; a train-only baseline (`frequency_from_train`) scores 1.0 on the 45 held-out rows, at or above 0.9 |
| `v3_T_taxonomy_explicit.jsonl` | EXPLORATORY | 0 | 0 | 0 scorable rows after the purge (degeneracy verdict `empty`); holdout_too_small: 0 held-out rows (< 30) |
| `vbeta_U_language_routing.jsonl` | INVALID | 80 | 3 | invalid as evaluation evidence: answer_literal_leak: the label appears in the evidence on 72 of 75 rows (rate 0.96); holdout_too_small: 0 held-out rows (< 30) |
| `vbeta_V_source_tier_routing.jsonl` | EXPLORATORY | 80 | 1 | demoted: single_label: every scorable row carries the label `2`; holdout_too_small: 0 held-out rows (< 30) |
| `D_exploit_construction.jsonl` | NOT_SCORABLE | 0 | 0 | generative task, needs a judge rather than string match |
| `Fa_rejection_evidence_axis_vector.jsonl` | NOT_SCORABLE | 0 | 0 | the gold is a vector of six axes plus per-axis assessability, so there is no single label to match; `score_f_extension.py` scores it per axis |
| `Fb_duplicate_radar_pair.jsonl` | NOT_SCORABLE | 0 | 0 | scalar in shape but not promoted into the headline; `score_f_extension.py` scores it with its own train-fitted floor |
| `H_verified_exploit.jsonl` | NOT_SCORABLE | 0 | 0 | descriptive reference answers, no scalar label |
| `Q_evidence_type_and_quality_rubric.jsonl` | NOT_SCORABLE | 0 | 0 | judge-graded rubric dict |

Counts: **2 PRIMARY**, **8 EXPLORATORY**, **9 INVALID**, **5 NOT_SCORABLE** (24 family files; 19 carry a scalar answer key).

### 2.1 Leakage: what the audit still finds, and what it no longer finds

**K — the group key is the answer.** `source_only_lookup` scores **1.0000
with 100% coverage** on the 31 held-out rows
(`reports/independent/audit.json` → `K_language_ecosystem_routing.jsonl` →
`baselines_test_split.source_only_lookup`). K groups by the language prefix
of the record id, and the record id prefix *is* the gold label: the five
groups are `cairo` (8 rows), `move` (15), `rust` (18), `solidity` (45),
`vyper` (51). All 31 held-out rows share a group with train
(`group_overlap.test_rows_in_shared_group` = 31).

**K and L leak the answer into the evidence itself.** Measured on the
model-facing payload with the prompt and label vocabulary removed — a prompt
that ends *"Answer vulnerable or no_confirmed_vulnerability"* is
self-description, not leakage, and counting it would make every family look
compromised:

- K: the gold language appears in the task's own evidence in **76 of 137
  rows (rate 0.5547)** — verdict `answer_literal_leak`, severity `high`.
- L: the gold severity appears in the evidence in **94 of 128 rows (rate
  0.7344)** — verdict `answer_literal_leak`, severity `high`.

For K this is defensible — the extension *is* the evidence a router would
use — but it means K cannot distinguish recognition from string search. For
L it is more serious: copying a published severity is the whole task.

The same group-key structure makes **O** score 1.0000 from
`source_only_lookup` (31 of 31 held-out rows in a shared group) and **P**
score 0.9032.

### 2.2 Legitimate overlap, distinguished from leakage

- **Record-id overlap across train/test is zero in every audited family**
  (`record_overlap.record_id_overlap` = 0 everywhere; the pre-purge single id
  in U and V is gone with the rows that carried it).
- **No byte-identical code block** appears between train and test for any
  family (`test_rows_with_identical_code_block` = 0 everywhere).
- **A/C repository overlap is zero** — the Code4rena split holds out whole
  contests on both sides.
- **5-gram Jaccard to the nearest train task** peaks at 0.1724 for A and
  0.2062 for C; no held-out row in any family reaches the 0.9 threshold.

**T, U and V no longer have a near-duplicate measurement at all.** T is a
0-byte family file after the purge (`degeneracy.verdict = "empty"`), while U
and V are train-only families with no held-out split; their `near_duplicates`
verdict is `skipped_no_scorable_key`. The old T near-duplicate finding
(2 of 2 sampled rows at similarity 1.0) described 589 rows that are no longer
in the benchmark and is withdrawn in §10.

### 2.3 Answer-distribution shortcuts

This is the most consequential finding, and it is a property of the splits,
not of any row. `train_majority_probe` in
`reports/independent/audit.json`:

| family | train majority | test rows | that majority on test | label-mix L1 |
|---|---|---|---|---|
| R `v3_R_source_tier_routing` | tier `1` | 899 | **0.0000** | 1.8999 |
| C `C_attacker_reasoning` (now PRIMARY) | privileged | 59 | 0.7966 | 0.1951 |
| E `E_exploit_verification` | passes | 1 | 1.0000 | 0.6667 |
| N `N_attacker_identity_extraction` | true | 3 | 1.0000 | 0.6 |
| K | solidity | 31 | 0.1935 | 0.5340 |
| L | high | 29 | 0.1034 | 0.5316 |
| O | audit_finding | 31 | 0.1935 | 0.5340 |
| P | `3` | 31 | 0.2903 | 0.4864 |
| A `A_vulnerability_detection` | no_confirmed | 114 | 0.6228 | 0.1941 |

**R is the clearest case.** R's train split carries tiers `1` (3,438 rows)
and `2` (286 rows); its test split carries tier `0` (854 rows) and tier `2`
(45 rows). Tier `0` **never occurs in train**
(`test_labels_absent_from_train: ['0']`), so the train-majority predictor
scores **exactly 0.0000** on the 899 test rows while the label-mix distance
is 1.8999 — the largest in the benchmark.

**A is subtler and worth stating precisely.** A's class prior moves across
splits — `vulnerable` is 93/332 = 0.2801 in train, 32/212 = 0.1509 in
validation and 43/114 = 0.3772 in test. A majority classifier therefore
scores 0.7199 / 0.8491 / 0.6228 on train / validation / test *from the same
constant prediction* (the per-split macro-F1 of the fitted baseline is
0.2905 / 0.3141 / 0.2757). The repository's README already calls this "a
split-blind floor is a validity hazard"; this audit quantifies it.

---

## 3. The primary metric and its denominator

Source: `reports/benchmark_metrics.json` → `primary_metric`.

| field | value |
|---|---|
| families | `A_vulnerability_detection.jsonl`, `C_attacker_reasoning.jsonl` (2) |
| denominator | **1,051** scorable rows |
| by split | train 512 · validation 366 · test 173 |
| label distribution | `no_confirmed_vulnerability` 490 · `vulnerable` 168 · `privileged` 340 · `unprivileged` 29 · `protocol_accounting_or_config_flaw` 17 · `malicious_dependency` 7 |
| test label distribution | `no_confirmed_vulnerability` 71 · `vulnerable` 43 · `privileged` 47 · `unprivileged` 7 · `protocol_accounting_or_config_flaw` 1 · `malicious_dependency` 4 |
| `accuracy` | **null** — "not measurable: no predictor has been run against this benchmark" |
| `macro_f1` | **null** — same reason |

The headline is a **label-distribution diagnostic** over the primary set's
scorable rows (train, validation and test together), published with its
denominator. It is not a held-out result, and the two are never conflated: a
predictive claim is made on the held-out split and measured against the
train-only held-out floor in §4.

**The metric a model result has to beat** is the train-only held-out floor
for the relevant primary family, from `reports/benchmark_metrics.json` →
`baselines` (each baseline fitted on the train rows only, applied to the
held-out rows; A has 114 test rows, C has 59):

| held-out floor | A accuracy | A macro-F1 | C accuracy | C macro-F1 |
|---|---|---|---|---|
| majority | **0.6228** | 0.3838 | **0.7966** | 0.2217 |
| seeded random (seed 7) | 0.5263 | 0.5080 | 0.1864 | 0.1420 |
| label-frequency (seed 7) | 0.5088 | 0.4722 | 0.6441 | 0.2021 |
| TF-IDF retrieval | 0.5000 | 0.4953 | 0.7627 | 0.2184 |

A model result below 0.6228 on A's test rows, or below 0.7966 on C's, has
not beaten "always say the majority class". A baseline fitted on the held-out
rows would have seen the answers it is scored against; every floor above is
train-fitted and says which rows it was fitted on.

---

## 4. Per-split and per-class results

Source: `reports/baselines/baseline_majority.json` → `micro` (the primary
set) and `micro_all_families` (the continuity twin).

### 4.1 Primary set (A + C, 1,051 scorable rows) — majority baseline

| split | accuracy @ correct/predicted/scorable | macro-F1 |
|---|---|---|
| train | 0.7578 @ 388/512/512 | 0.2905 |
| validation | 0.8852 @ 324/366/366 | 0.3141 |
| test | 0.6821 @ 118/173/173 | 0.2757 |
| all scorable | 0.7897 @ 830/1,051/1,051 | 0.2969 |

Per class, primary set:

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| `no_confirmed_vulnerability` | 0.7447 | 1.0 | 0.8537 | 490 |
| `privileged` | 0.8651 | 1.0 | 0.9277 | 340 |
| `vulnerable` | 0.0 | 0.0 | 0.0 | 168 |
| `unprivileged` | 0.0 | 0.0 | 0.0 | 29 |
| `protocol_accounting_or_config_flaw` | 0.0 | 0.0 | 0.0 | 17 |
| `malicious_dependency` | 0.0 | 0.0 | 0.0 | 7 |

### 4.2 Continuity twin (all families ever shipped, 7,018 scorable rows)

| split | accuracy @ correct/predicted/scorable | macro-F1 |
|---|---|---|
| train | 0.8757 @ 4,220/4,819/4,819 | 0.2323 |
| validation | 0.7561 @ 468/619/619 | 0.1679 |
| test | 0.1543 @ 192/1,244/1,244 | 0.2393 |
| all scorable | 0.7303 @ 5,205/7,007/7,018 | 0.2047 |

The continuity twin is the cross-release comparable figure. Its accuracy
denominator is 6,682: the six single-label families (B, F, G, I, J and V)
contribute 336 rows that are not evaluable at all (T contributes 0), so they
are excluded from the accuracy numerator and denominator but still counted
in `scorable`. Macro-F1 on the twin is **0.2047** against an accuracy of
0.7303 — that gap is the whole point of publishing both.

---

## 5. The six published baselines

All six are deterministic, re-runnable, and **fitted on the train rows of
their family and applied to the held-out rows**. Source:
`reports/baselines/baseline_*.json`.

| Baseline | Primary acc @ predicted/scorable | Primary acc over scorable | Continuity acc @ predicted/scorable | Continuity macro-F1 |
|---|---|---|---|---|
| majority | 0.7897 @ 1,051/1,051 | 0.7897 | 0.7303 @ 7,007/7,018 | 0.2047 |
| random-seed7 | 0.3987 @ 1,051/1,051 | 0.3987 | 0.4169 @ 7,007/7,018 | 0.2303 |
| frequency-seed7 | 0.6403 @ 1,051/1,051 | 0.6403 | 0.6684 @ 7,007/7,018 | 0.2672 |
| first-published (L only, retired family) | n/a @ 0/1,051 | n/a | 1.0000 @ 71/7,018 | 1.0000 |
| majority-published (L only, retired family) | n/a @ 0/1,051 | n/a | 1.0000 @ 71/7,018 | 1.0000 |
| TF-IDF retrieval | 0.6746 @ 1,051/1,051 | 0.6746 | 0.7927 @ 7,007/7,018 | 0.4795 |

### 5.1 The coverage artifact, still present and still guarded

`reports/baselines/baseline_first_published.json` reports
`micro_all_families.accuracy = 1.0000`. It predicts on **71 of 7,018**
scorable rows (1.01%). The field is computed over predicted rows only, so
it is not arithmetically wrong — but quoted as a headline it says a
copy-the-publisher rule solves the benchmark. The same file's
`accuracy_scorable` is **0.0106**, and the README quotes that. The defect
that a field named `accuracy` exists without a coverage guard is still
there; what changed is that every published table now carries the coverage
beside it, and a zero-prediction run renders as `n/a @ 0/1,051`, never as a
0.0000 that reads as a scored result.

---

## 6. The other three blocks

The four blocks partition every scored family, and their scorable rows sum
to the 7,018 of the continuity twin (source:
`reports/baselines/baseline_majority.json` → `coverage`, `micro_*`).

| block | families | scorable rows | accuracy | macro-F1 |
|---|---|---|---|---|
| primary | A, C | 1,051 | 0.7897 | 0.2969 |
| exploratory | F, G, I, J, V | 108 | **null** — `single_label_not_evaluable` | null |
| invalid | R, U | 4,703 | 0.7465 | 0.3012 |
| retired | B, E, K, L, M, N, O, P, S, T | 1,156 | 0.5808 | 0.1682 |
| no exactly-matchable key | D (644), Fa (444), Fb (651), H (7), Q (61) | 1,807 tasks, excluded with stated reasons | — | — |

Two things to read carefully here.

**The exploratory block has no accuracy at all.** Its five families each
carry exactly one observed label, so any accuracy would be the label
distribution restated; the block reports `null` with the reason
`single_label_not_evaluable` and keeps the row counts, splits and label
distributions. The published 1.000 for those families is withdrawn.

**Retirement is a location, not a verdict.** The ten families under
`benchmark/retired_families/` keep their per-family numbers under
`families_retired`; their status is computed from the data like every other
family's, which is why B, M and T appear in the retired block with an
EXPLORATORY status and E, K, L, N, O, P, S with an INVALID one. By *status*
the 24 family files partition as 2 PRIMARY (1,051 scorable rows),
8 EXPLORATORY (373), 9 INVALID (5,594) and 5 NOT_SCORABLE (0 scorable —
D, Fa, Fb, H and Q are excluded with stated reasons and are not part of the
continuity twin).

---

## 7. The secondary holdout — a second, stricter protocol

`scripts/build_secondary_holdout.py` builds two additive holdouts. It never
edits a benchmark file, never changes a split in place and never rewrites an
answer key. Source: `benchmark/independent/secondary_holdout_manifest.json`.

**Group-disjoint**: whole groups partitioned with a seeded shuffle,
stratified by majority label. Built for **5 families** (L, N, O, P, S).
For 9 families the committed splits are *already* record-disjoint — every
group is a single row — so rebuilding cannot make them stricter
(`skipped_already_group_disjoint`: A, B, C, E, F, G, I, J, M). For **K, R and
V it is refused with evidence** (`skipped_group_determines_label`): every
multi-row group carries exactly one label, so the group key *determines* the
answer and holding out a group would hand the model the label for every row
removed. **U** yields an empty holdout (`skipped_empty_holdout`) and **T** has
no labelled rows left after the purge (`skipped_no_labeled_rows`).

**Class-disjoint**: all rows of the two rarest labels held out, then every
group touching a held-out row removed from the retained side. Built for **3
families** (C, P, R); skipped for 16, with the reason recorded — single-class
or empty retained side (B, F, G, I, J, T, V; A and S), insufficient minority
support (E, L, M, N, O, U), or every held-out row answer-leaking (K).

### 7.1 The decisive result

On every class-disjoint holdout that could be built, all honest shortcuts
score **exactly 0.0000**:

| family | held-out labels | rows held / kept | majority | random | frequency | input retrieval | group lookup | *oracle peek* |
|---|---|---|---|---|---|---|---|---|
| C | malicious_dependency, protocol_accounting_or_config_flaw | 24 / 369 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.708 |
| P | 1, 3 | 58 / 69 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.828 |
| R | 0, 2 | 1,185 / 3,438 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.721 |

On the official splits those same honest shortcuts score **0.6949 → 0.000**
(C input retrieval), **0.8710 → 0.000** (P input retrieval) and **0.9032 →
0.000** (P group lookup); C's and R's train-majority scores are 0.7966 and
0.0000. The apparent performance came from the label and group composition,
not from the task. K and O, whose group lookup scores 1.0000 on the official
splits, could not be class-disjoint-tested at all — K because all 23 held-out
rows leak the answer, O because its rarest label has one row; that is a
limitation of this protocol, not an exoneration.

The `oracle peek` column is the accuracy a constant predictor would get if it
were allowed to know the held-out majority. It is reported to size the
holdout, not to be quoted as a result: the holdout is only informative
because peeking buys 0.71–0.83 where honest shortcuts buy nothing.

On the group-disjoint holdouts the shortcut survives for the five families
that could be built — L's best shortcut is 0.500, N's 1.000, O's 0.933,
P's 1.000, S's 1.000 — which is the point of the second protocol: a
group-disjoint split that a lookup still solves measures the grouping, not
the task.

### 7.2 What the holdout costs and what it leaks

`payload_answer_literal_overlap` records **32 rows** in which the gold
label appears in the copied model-facing payload: K 20, L 9, O 3. That is a
benchmark defect, measured by the audit, and it is reported here rather than
hidden: this holdout is open-key and is not claimed to be leakage-proof.

The manifest writes **1,364 model-facing task rows** and **1,364 key rows**
(plus 32 exploratory tasks and 32 exploratory keys), into separate files.

---

## 8. The benchmark is OPEN-KEY

This is a property of the release, not a defect of the split, and it is
stated by the repository's own leakage report
(`reports/eval_leakage_report.json` → `release_boundary.open_key.benchmark_families.statement`):

> every benchmark family row carries its answer key in the same file as its
> input; the key is committed, so every family is OPEN-KEY and no family may
> be described as hidden or protected against repository-level leakage

Concretely, measured:

- the protected evaluation set is **5,737 records** across the benchmark
  families (out of 17,093 benchmark rows), and **0** of them is present in the
  model-visible corpus (`protected_evaluation_set.records` and
  `records_present_in_model_visible_corpus`);
- the model-visible corpus (`training/`) holds **12,112 rows**, all in the
  train partition (no unsplit rows), of which **0** carry a record any
  benchmark family holds out
  (`model_visible_corpus_hygiene.rows_carrying_a_protected_record`);
- the secondary holdout's key file
  `benchmark/independent/secondary_holdout_keys.jsonl` is a **tracked**
  file, labelled `OPEN_KEY` in its own manifest, and the model-facing
  `secondary_holdout_tasks.jsonl` carries no `gold`, `label`, `answer`,
  `answer_key`, `expected`, `original_id`, `original_split`, `group` or
  `split` field — the builder refuses to write one that does.

**The only protected evaluation in this project is the VLUN-Prove private
split.** Its answer key lives outside the tracked tree and is committed to
by SHA-256 in `reports/prove_split_interface.json` → `private_commitment`
(2 files: `prove_tasks_private.jsonl`, 8 records, and
`grader_self_check.json`, 7 records). The 200-task target is **not** met:
the pool records `tasks_with_two_revisions_executed` = 8,
`qualified_pool_size` = 7 and `target_met: false`, and the interface is
published at its real size rather than padded.

---

## 9. What remains unresolved

**Remaining validity threats.** These are the things this audit does **not**
close. Each is stated with the measurement that keeps it open.

1. **A and C: class-prior shift is reported, not a demotion.** C was
   repaired by the purge (720 → 393 scorable rows, train/test label-mix L1
   0.1951, best train-only shortcut 0.7966) and is now PRIMARY; the old
   "C drifted by 1.0303" claim is withdrawn in §10. What remains is a real
   prior difference in A: `vulnerable` is 93/332 = 0.2801 in train,
   32/212 = 0.1509 in validation and 43/114 = 0.3772 in test (L1 0.1941),
   so a train-only majority scores 0.7199 / 0.8491 / 0.6228 on train /
   validation / test. It is published as a diagnostic beside the 0.6228
   held-out floor, not as a demotion.

2. **R, U and V: excluded, but for different reasons after the purge.** R's
   train-majority scores **0.0000** on 899 held-out rows and the label `0`
   never occurs in train, so it stays INVALID. U has **no held-out split**
   at all (80 train-only rows) and is INVALID for `answer_literal_leak`
   (the label appears in the evidence on 72 of 75 rows, rate 0.96) and
   `holdout_too_small`. V has no held-out split either and is EXPLORATORY
   for `single_label` (all 80 rows carry tier `2`) and `holdout_too_small`,
   with null accuracy. The old U/V shortcut floors of 0.9834 and 0.9998
   described rows that no longer exist and are withdrawn. **The exclusion
   is a decision, not a fix**: no re-split, regrouping or re-keying of R,
   U or V has been done.

3. **The single-label families are not evaluable, and re-labelling them is
   not possible from the data.** B (228 rows, all `invariant_stated`), F
   (17, all `invalid`), G (7, all `effective`), I (1, all `exploitable`),
   J (3, all `effective`) and V (80, all `2`) each carry exactly one
   observed label among their scorable rows. Their accuracy is `null` with
   the reason `single_label_not_evaluable` in every block, including the
   exploratory and retired ones. Their rows stay in the dataset and stay
   scored; only the number that cannot mean anything is removed. Making
   them evaluable needs rows with a second label, which the current
   evidence does not have. In particular **G** now scores the **7**
   verified-effective patches, and its other **31** rows carry no answer
   key at all: all **31** are `not_testable` (no executable PoC on either
   side) — `reports/patch_verification_v2.json` → `by_fix_effectiveness`
   = {effective: 7, not_testable: 31} over 38 patch records.

4. **The `derived/` layer's reproducibility is not green on this checkout.**
   `scripts/check_reproducibility.py` runs 19 checks: the committed
   `reports/reproducibility_checks_summary.json` records
   `checks_failed_critical: 2`, and the local run records **15 pass, 2 fail,
   2 `skipped_no_network`**. Both failures are rebuild-parity checks:
   `derived/` fails at `resolve_citations.py` (the clone set can no longer
   resolve every audited pin) and `derived_v2_2/` differs after replaying
   `build_derived_v22.py`. `derived/ rebuild parity` is therefore **not** a
   pass. The committed `reports/reproducibility_report.md` deliberately
   carries only the machine-independent numbers (gate size and the critical
   failure count); resolving the two failures is tracked by another work
   stream, not by editing this report.

5. **The read-only source-layer local-path residual is closed, but the
   layers stay pinned.** The machine-path scan now reports **2,089 files
   scanned, 0 operator leaks, 0 pending, 2,218 genuine and 0
   `read_only_source_layer_unresolved`**. `jsonl/`, `jsonl_ml/` and
   `jsonl_v3/` remain pinned source layers whose bytes *are* the layer; the
   earlier 236 unresolved `jsonl_ml/` hits were removed with the source
   rebuild and are not silently rewritten here.

6. **No model was run.** Every number in this report is a shortcut or a
   structural measurement. Whether a real model can beat the 0.6228 floor
   on A's 114 test rows or the 0.7966 floor on C's 59 is untested, and this
   report says what the benchmark *permits*, not what any model achieves.

7. **The class-disjoint holdout covers 3 of 19 scorable families.** 16 were
   skipped for stated reasons: B, F, G, I, J and V are single-class; A and S
   have an empty retained side; E, L, M, N, O and U lack minority support;
   T has no labelled rows; K has every held-out row answer-leaking. No
   amount of splitting fixes a family that lacks the negative examples. And
   a class-disjoint holdout cannot measure class-prior reasoning: by
   construction the retained side has no example of the held-out labels, so
   a model cannot learn them at all. It measures whether shortcuts
   transfer, which is what it is for.

8. **Near-duplicate detection is a 5-gram Jaccard proxy, not a semantic
   check.** It detects copy-paste, not paraphrase. Semantic duplication,
   shared boilerplate across publishers, and duplicated *findings* under
   different record ids are not detected. Code-level overlap was checked for
   A and C only, the two families carrying code; K–Q carry prose and
   components, and shared boilerplate prose between splits was not
   fingerprinted. Grouping choices were the auditor's: grouping by record,
   language prefix or publishing source are three defensible definitions,
   and a fourth — by auditor, by CVE, or by contract — could change the
   overlap verdicts. And no held-out ground truth was re-derived: answer-key
   correctness was checked for *consistency with the records*, not by
   re-reading each source finding.

---

## 10. Claims retracted or downgraded by this rewrite

The previous version of this document was written before the benchmark-status
rework. The following published claims are withdrawn, and each is replaced
by the figure the current report carries.

| # | claim as published before | status | replacement, and where it comes from |
|---|---|---|---|
| 1 | "The published micro-accuracy of **0.8725** for a majority-class baseline is not a floor to beat" | **RETRACTED** | The continuity twin is **0.7303** over **7,018** scorable rows, and the headline metric is **0.7897** over **1,051** rows with accuracy **null** (no predictor has been run). `reports/baselines/baseline_majority.json` → `micro`, `micro_all_families`; `reports/benchmark_metrics.json` → `primary_metric` |
| 2 | the per-family baseline table's "official majority acc" column | **RETRACTED as a floor** | Those predictors were fitted over every labelled row, held-out rows included, so they had seen the answers they were scored against. The train-only floors now published are A **0.6228** (114 held-out rows) and C **0.7966** (59), R **0.0000** (899), K and O **1.0000** through a group lookup, P **0.9032**. U and V publish no held-out floor after the purge. `reports/benchmark_metrics.json` → `family_floors`, `baselines` |
| 3 | "majority 0.8725 / 0.8725 / 100%", "retrieval 0.8949 / 0.8883 / 99.93%", "frequency 0.8135", "random 0.3608" | **RETRACTED** | Continuity figures are now majority **0.7303 / 0.7303 / 100%**, retrieval **0.7927 / 0.7927 / 100%**, frequency **0.6684 / 0.6684 / 100%**, random **0.4169 / 0.4169 / 100%**; the headline primary figures are 0.7897 / 0.6746 / 0.6403 / 0.3987 respectively. `reports/baselines/baseline_*.json` → `micro`, `micro_all_families` |
| 4 | "first-published predicts on **71 of 22,149** scorable rows (0.32%)" | **DOWNGRADED** (denominator corrected) | 71 of **7,018** (1.01%); the report's own `accuracy_scorable` is **0.0106** and is the figure to quote. `reports/baselines/baseline_first_published.json` |
| 5 | "S, T, U, V contribute **14,815 of the 22,149** scorable rows" | **DOWNGRADED** (denominator corrected) | **491 of 7,018** (S 331, T 0, U 80, V 80). The purge removed the rows that made up the old contributor total. `reports/baselines/baseline_majority.json` → `micro_all_families` |
| 6 | "nine families at ≥95% majority span **15,075**" | **RETRACTED** | **7 families span 667 scorable rows**: B (228), S (331), V (80), F (17), G (7), J (3), I (1). `reports/independent/audit.json` → per-family `degeneracy.majority_fraction` |
| 7 | "K: the gold language appears in the task's own evidence in **78/137 rows (0.569)**" | **RETRACTED** | **76 of 137 rows, rate 0.5547**, verdict `answer_literal_leak`, severity `high`. `reports/independent/audit.json` → `K_language_ecosystem_routing.jsonl` → `answer_leakage` |
| 8 | "L: the gold severity appears in `published_severities` (68) and `prose` (26)" | **RETRACTED** (the per-field breakdown) | The current measurement is the total: **94 of 128 rows, rate 0.7344**, severity `high`. The current report does not break the leak down per field, so only the total is quoted. `reports/independent/audit.json` → `L_severity_reconciliation.jsonl` → `answer_leakage` |
| 9 | "R's train split spans all three tiers (0: 878, 1: 3517, 2: 611) while its validation *and* test splits are **100% tier 2**"; "107 test rows" | **RETRACTED** | R's train split carries tiers `1` (3,438) and `2` (286); its test split carries tier `0` (854) and tier `2` (45) — 899 test rows, and tier `0` never occurs in train. Train-majority scores **0.0000**, L1 **1.8999**. `reports/independent/audit.json` → `v3_R_source_tier_routing.jsonl` → `split_drift` |
| 10 | "A majority classifier therefore scores **0.721 / 0.860 / 0.551** on train / validation / test" | **DOWNGRADED** (now the published train-only figure) | **0.7199 / 0.8491 / 0.6228**, with fitted-majority-baseline macro-F1 0.2905 / 0.3141 / 0.2757. `reports/baselines/baseline_majority.json` → `micro.per_split` |
| 11 | "5-gram Jaccard to the nearest train task peaks at 0.455 (A) and 0.455 (C)" | **DOWNGRADED** (now quoted to the report's precision) | max similarity **0.1724** for A and **0.2062** for C; 0 held-out rows at or above 0.9 in every family (T, U and V now skip the measurement). `reports/independent/audit.json` → `near_duplicates` |
| 12 | "5 of 19 families are single-label; B scores **1.000** from a constant across 228 rows" | **DOWNGRADED** | **6 of 19** families are single-label (B, F, G, I, J and V). B's accuracy is **null** with the reason `single_label_not_evaluable`; its 228 rows and its label distribution are kept. `reports/benchmark_metrics.json` → `family_status` |
| 13 | "**Macro-F1 is never published**" (finding 9) | **RETRACTED** | Macro-F1 is published in every block and every split: 0.2969 (primary), 0.2047 (continuity), 0.3012 (invalid), 0.1682 (retired), plus `per_class` F1/precision/recall/support. `reports/baselines/baseline_majority.json` |
| 14 | "The repo's README already marks these **SATURATED**" | **RETRACTED** | The README no longer carries a SATURATED label. Saturation is now one of the validity flags the status model computes, and the families it applies to are INVALID. `reports/benchmark_metrics.json` → `status_rules` |
| 15 | recommendation: "**Retire B, F, G, I, J** from the scored set or relabel them" | **RETRACTED as a recommendation** (done) | B, F, G, I, J and V are EXPLORATORY with null accuracy and the reason `single_label_not_evaluable`. `reports/benchmark_metrics.json` → `family_status` |
| 16 | recommendation: "**Publish macro-F1 and coverage** alongside every accuracy" | **RETRACTED as a recommendation** (done) | Every block carries `macro_f1`, `per_class` and `coverage`; a zero-prediction run renders as `n/a @ 0/1,051`. `reports/baselines/baseline_*.json` |
| 17 | recommendation: "**Add held-out rows to M, T, N, E**, or mark them non-evaluable" | **RETRACTED as a recommendation** (the marking half is done) | M and T are EXPLORATORY for `holdout_too_small` (T has 0 rows); N and E are INVALID for `too_small_to_score` and `holdout_too_small`. The *adding rows* half is not done and is not claimed. `reports/benchmark_metrics.json` → `family_status` |
| 18 | "**6 K rows name more than one candidate language** in their evidence" | **RETRACTED** | The current audit output does not carry a per-family ambiguity count, so the figure cannot be substantiated from the current reports and is not repeated. `reports/independent/audit.json` → `K_language_ecosystem_routing.jsonl` |
| 19 | "the published micro-accuracy of 0.8725 … is mostly the arithmetic of saturated families" as a description of the headline | **RETRACTED as a description of the headline** | The headline is now two families of 1,051 rows (A + C); the saturation arithmetic belongs to the continuity twin, where S, T, U and V contribute 491 of 7,018 rows. `reports/baselines/baseline_majority.json` |
| 20 | "**No model was run** … whether a real model can beat the 0.551 floor on A" | **KEPT, and now the project's own wording** | The floors to beat are 0.6228 on A's 114 test rows and 0.7966 on C's 59; the primary metric's accuracy and macro-F1 are `null` with the reason "not measurable: no predictor has been run against this benchmark". `reports/benchmark_metrics.json` → `primary_metric` |

The recommendations that remain open, and are **not** done, are exactly the
items in [§9](#9-what-remains-unresolved): a re-split of R, U and V; the
two failing `derived/` rebuild parities and their missing clone pins; and a
re-labelling that gives the single-label families a second class. The
`jsonl_ml/` local-path residual is **closed** (§9.5), and C's repair is
**done** — neither is still outstanding.

---

## Reproduce

| command | result |
|---|---|
| `python scripts/independent_benchmark_audit.py` | PASS — 19 scorable + 5 not scorable |
| `python scripts/independent_benchmark_audit.py --check` | PASS — committed audit current |
| `python scripts/build_secondary_holdout.py` | PASS — 3 class-disjoint (C, P, R), 5 group-disjoint (L, N, O, P, S) built; 1,364 tasks, 1,364 keys |
| `python scripts/build_secondary_holdout.py --check` | PASS — committed holdout current |
| `python scripts/score_benchmark.py --build-metrics` | regenerates `reports/benchmark_metrics.json` and `reports/benchmark_metrics.md` |
| `python scripts/score_benchmark.py --build-baselines` | regenerates the six reports under `reports/baselines/` |
| `python scripts/check_eval_leakage.py --quiet` | PASS — no protected evaluation record, answer or payload is reachable from the model-visible corpus |
| `python -m unittest tests.test_independent_benchmark -q` | PASS |
| `python scripts/run_gates.py` | full matrix: 55 registered gates; `--only benchmark` runs the 2 check-only benchmark gates (current pass/fail is run-dependent, not pinned in this hand-maintained report) |

The two benchmark gates are `benchmark-audit-current` and
`benchmark-holdout-current`, registered in `scripts/run_gates.py` under
`--only benchmark`. Both run `--check` only, so a gate can never silently
regenerate the artefact it is verifying.

No existing benchmark file was modified. `git status` after a full audit and
holdout build shows only the new `benchmark/independent/` directory; the
same property is asserted byte-for-byte by
`TestAdditiveAndReproducible.test_building_the_layer_does_not_touch_benchmark_files`
and `test_audit_does_not_touch_benchmark_files`.

Determinism: `test_audit_is_deterministic` and `test_holdout_is_deterministic`
assert two runs at seed 7 produce byte-identical output. Everything is seeded;
no network is used; nothing is sampled from an unseeded source.

Outputs:

- `reports/independent/audit.json` — per-family leakage, degeneracy, drift,
  overlap, near-duplicate and baseline measurements
- `benchmark/independent/secondary_holdout_manifest.json` — split definitions,
  per-family verdicts and reasons for every skip
- `benchmark/independent/secondary_holdout_tasks.jsonl` — the holdout tasks,
  with no answer field
- `benchmark/independent/secondary_holdout_keys.jsonl` — the OPEN-KEY answer
  key, a separate committed file
- `reports/independent_benchmark_evaluation.md` — this report

# RUBRIC.md — how benchmark scores are produced and read

## Primary metric (and its in-distribution twin)

**The headline number to quote is exact-match accuracy on the class-disjoint
holdout** (`benchmark/independent/secondary_holdout_tasks.jsonl`, 2,716 tasks),
where every shortcut collapses to 0.0000. Official-split accuracy is reported
second, labelled "in-distribution, contaminated by construction." Retraining
the six baselines against the holdout leaves most near random; that is the
finding, not a failure to report.

## The one number (and its continuity twin) (in-distribution, secondary)

**Micro-averaged exact-match accuracy over headline families' scorable tasks**,
with coverage reported beside it. Ten saturated families
(B, E, K, L, M, N, O, P, S, T) were retired to `benchmark/retired_families/` —
still shipped, audited and scored, but excluded from the headline because a
shortcut solves them. Four more (F, G, I, J) are saturated and sit below the
100-row floor where a family score is interpretable (32 scorable rows
total), so they are demoted to exploratory — also shipped and scored, also
outside the headline. The headline number is the one to quote:

- `accuracy` = correct ÷ predicted (how good when it answers)
- `accuracy_scorable` = correct ÷ scorable (how good overall; abstention hurts)
- `coverage` = predicted ÷ scorable (abstention is visible, never silent)

For continuity with prior releases, every baseline report also carries
`micro_all_families` — the same micro-average over **all** families ever
shipped, headline + exploratory + retired. Quote the headline; compare across
releases with the continuity twin.

Missing predictions count as wrong under `accuracy_scorable` and lower
coverage — a run that answers nothing scores 0 coverage, not 100% accuracy.

## Matching rule

Model answer and gold are compared after `strip().lower()`. Booleans render
as `true`/`false`, tiers and levels as their plain strings (`2`, `L5`).
Anything else — paraphrase, explanation, extra text — does not match. This
is deliberately strict: it measures key-answer reproduction, not reasoning
quality. Generative and judgement tasks (D, H, Q) are out of scope for this
harness by design (see ANSWER_KEY.md).

B and G are scored, but only on their scalar part — the mechanism matters
because it defines what a B/G score would mean, not because they sit in the
headline (B is retired, G is exploratory):

- **B_root_cause_reasoning** scores `invariant_stated`
  (`invariant_stated` / `no_invariant_stated`). That label comes from record
  structure -- whether the record carries a violated invariant -- never from
  the prose. The `root_cause` and `violated_invariant` text stays
  judge-graded. 228 of 720 rows are exactly scorable: the other 492 have no
  invariant, and for them the answer would be the constant "no", so they are
  excluded rather than inflating the score with a trivially guessable class.
  Majority accuracy is 1.000 here by construction -- the class is
  imbalanced and the label is structural. Read B as an abstention
  measurement, not a reasoning score.
- **G_patch_verification** scores the 7 rows where the same exploit was run
  against both the vulnerable and the fixed revision (L6). The other 31 are
  `not_testable`: no executable PoC on either side, so their effectiveness
  is genuinely unestablished and they carry no answer key.

## Per-family accuracy

Reported for every exactly-scorable headline family (5). The small families
are no longer headline: F (17), G (7), I (1), J (7) are exploratory — below
the 100-row floor, reported per-family under `families_exploratory` and
inside the `micro_all_families` scope of the baseline reports (see below),
not here. Retired families likewise keep their per-family accuracy under
`micro_all_families` scope, not here.

## Published baselines (deterministic, re-runnable)

| Baseline | Rule | Headline micro accuracy | Continuity (all families) | Coverage |
|---|---|---|---|---|
| majority | most common labeled answer per family (ties: sorted-first) | 0.8736 | 0.8725 | 19,631/19,631 |
| random-seed7 | uniform draw from the family's observed answer space, seed 7 | 0.3457 | 0.3608 | 19,631/19,631 |
| frequency-seed7 | seeded draw from the family's empirical label distribution | 0.8107 | 0.8135 | 19,631/19,631 |
| first-published (L only, retired) | copy the first publisher's severity | n/a @ 0/19,631 | 1.000 (71 tasks) | 0/19,631 |
| majority-published (L only, retired) | copy the majority publisher severity | n/a @ 0/19,631 | 1.000 (71 tasks) | 0/19,631 |
| retrieval (TF-IDF NN) | nearest train-split neighbour's label; test answers never indexed, train tasks never retrieve themselves | 0.8889 | 0.8949 | 19,631/19,631 |

Headline floors cover the headline scorable set (19,631 tasks, 5 families
with scorable rows); continuity floors cover all families ever shipped (22,149 tasks,
headline 19,631 + the 4 exploratory families' 32 sub-floor rows + the 10 retired
families' 2,486 scorable rows), byte-equal
to the pre-retirement reports. A baseline that predicts nothing shows n/a with
its 0/scorable coverage — never a 0.0000 that reads as a scored result. The earlier
10,103-task figures were computed against a stale Vbeta population (624/719 scorable
rows); the shipped Vbeta benchmark carries 6,219 scorable U rows and 6,935 V rows
(13,154 scorable tasks). `tests/test_baselines.py` now fails the build on that class of
drift.

```bash
python scripts/score_benchmark.py --baseline majority
python scripts/score_benchmark.py --baseline random --seed 7
python scripts/score_benchmark.py --baseline frequency --seed 7
python scripts/score_benchmark.py --baseline first_published
python scripts/score_benchmark.py --baseline majority_published
python scripts/score_benchmark.py --baseline retrieval
```

Each run rewrites its committed report under `reports/baselines/`.
`tests/test_baselines.py` fails the build if a committed report's per-family
scorable counts disagree with the shipped benchmark files, or if the six
baselines disagree about the scorable set — a stale floor is worse than no
floor.

Reports live in `reports/baselines/`. The retrieval baseline scores high
because same-project inputs share vocabulary: it measures
project-matchability, not reasoning — published
precisely so a model beat is read against the right floor, and so the
bulk-tier families' memorization-proneness stays visible. Family R's splits
are stratified by tier (train {1,2}, test {0,2}, no validation rows) because
every R source is tier-uniform, which made the old test split 100% tier 2;
its audit shortcut fell 1.0000 → 0.1086 on stratification.

## Saturated families (headline majority >= 0.94 — a beat here carries no signal)

U, V. Marked SATURATED in the README benchmark table and in
`reports/benchmark_metrics.md`. F, G, I, J are saturated too (majority 1.000
on their labeled rows) and sit below the 100-row floor where a family score
is interpretable — 32 scorable rows total, 95% CI half-width at p=0.5 from
±24pp (n=17) to ±37pp (n=7) — so they are marked EXPLORATORY: excluded from
the headline, still shipped and scored per-family (`families_exploratory`)
and in the continuity twin (`micro_all_families`). Ten further families
(B, E, K, L, M, N, O, P, S,
T) saturated so completely they were retired to `benchmark/retired_families/`
— each with a `retirement.json` naming the measured shortcut accuracy and
leak mechanism (K: content-based language signals, ids already excluded;
L: literal severity leak with 127:1 degenerate agreement fallback). The per-family accuracies live in
`reports/baselines/baseline_majority.json`; read them there rather than from
a hand-copied list that can drift.

B and G saturate by construction, not by difficulty: B's label is
structural (`invariant_stated`, 228/720, retired) and G's is the L6 subset
where every patch was verified effective (exploratory, 7 rows). A model
beating 1.000 on either is not evidence of reasoning. The other saturated
families saturate because their label distribution is degenerate.

Reports live in `reports/baselines/`. Any model run is scored with:

```bash
python scripts/score_benchmark.py --predictions preds.jsonl --out reports/scores_<run>.json
```

where `preds.jsonl` rows are `{"task_id": ..., "answer": ...}` and `task_id`
is the task file's `id`/`task_id`. 19,631 tasks are scorable across 5
headline families (22,149 across all families ever shipped); D, H and Q are
excluded with reasons above (G is scored on its 7 L6 rows, as an exploratory
family), and 10 saturated families live retired under `benchmark/retired_families/`.

## What this rubric does NOT claim

- It does not measure exploit-writing (D), reference-matching (H), or rubric
  judgement (Q) — those need execution or human/LLM judges.
- Majority baselines on degenerate families (retired T: 588/589 one class) score
  ~1.0 without understanding anything — compare against random, not zero.
- Scores are comparable only on identical task sets; RESEARCH_ONLY rows
  never enter any benchmark, so the scorable set is the admitted set.

# RUBRIC.md — how benchmark scores are produced and read

## The one number

**Micro-averaged exact-match accuracy over all scorable tasks**, with
coverage reported beside it:

- `accuracy` = correct ÷ predicted (how good when it answers)
- `accuracy_scorable` = correct ÷ scorable (how good overall; abstention hurts)
- `coverage` = predicted ÷ scorable (abstention is visible, never silent)

Missing predictions count as wrong under `accuracy_scorable` and lower
coverage — a run that answers nothing scores 0 coverage, not 100% accuracy.

## Matching rule

Model answer and gold are compared after `strip().lower()`. Booleans render
as `true`/`false`, tiers and levels as their plain strings (`2`, `L5`).
Anything else — paraphrase, explanation, extra text — does not match. This
is deliberately strict: it measures key-answer reproduction, not reasoning
quality. Generative and judgement tasks (D, H, Q) are out of scope for this
harness by design (see ANSWER_KEY.md).

B and G are scored, but only on their scalar part:

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

Reported for every exactly-scorable family (17). Small families (E: 7,
F: 17, I: 1, J: 7, N: 14) have wide confidence intervals — read them as
smoke signals, and read the micro average for the headline.

## Published baselines (deterministic, re-runnable)

| Baseline | Rule | Micro accuracy | Coverage |
|---|---|---|---|
| majority | most common labeled answer per family (ties: sorted-first) | 0.8725 | 22,148/22,148 |
| random-seed7 | uniform draw from the family's observed answer space, seed 7 | 0.3608 | 22,148/22,148 |
| frequency-seed7 | seeded draw from the family's empirical label distribution | 0.8135 | 22,148/22,148 |
| first-published (L only) | copy the first publisher's severity | 1.000 (71 tasks) | 71/22,148 |
| majority-published (L only) | copy the majority publisher severity | 1.000 (71 tasks) | 71/22,148 |
| retrieval (TF-IDF NN) | nearest train-split neighbour's label; test answers never indexed, train tasks never retrieve themselves | 0.9257 | 22,133/22,148 |

These floors cover the full shipped scorable set (22,148 tasks, 17 families).
The earlier 10,103-task figures were computed against a stale Vbeta
population (624/719 scorable rows); the shipped Vbeta benchmark carries
6,218/6,935. `tests/test_baselines.py` now fails the build on that class of
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
because same-project inputs share vocabulary (notably the tier-heavy R
family): it measures project-matchability, not reasoning — published
precisely so a model beat is read against the right floor, and so the
bulk-tier families' memorization-proneness stays visible.

## Saturated families (majority >= 0.94 — a beat here carries no signal)

B, F, G, I, J, M, S, T, U, V. Marked in the README benchmark table and in
`reports/benchmark_metrics.md`. The per-family accuracies live in
`reports/baselines/baseline_majority.json`; read them there rather than from
a hand-copied list that can drift.

B and G saturate by construction, not by difficulty: B's label is
structural (`invariant_stated`, 228/720) and G's is the L6 subset where every
patch was verified effective. A model beating 1.000 on either is not
evidence of reasoning. The other saturated families saturate because their
label distribution is degenerate.

Reports live in `reports/baselines/`. Any model run is scored with:

```bash
python scripts/score_benchmark.py --predictions preds.jsonl --out reports/scores_<run>.json
```

where `preds.jsonl` rows are `{"task_id": ..., "answer": ...}` and `task_id`
is the task file's `id`/`task_id`. 22,148 tasks are scorable across 17
families; 5 families (B, D, G, H, Q) are excluded with reasons above.

## What this rubric does NOT claim

- It does not measure exploit-writing (D), reference-matching (H), or rubric
  judgement (Q) — those need execution or human/LLM judges.
- Majority baselines on degenerate families (T: 588/589 one class) score
  ~1.0 without understanding anything — compare against random, not zero.
- Scores are comparable only on identical task sets; RESEARCH_ONLY rows
  never enter any benchmark, so the scorable set is the admitted set.

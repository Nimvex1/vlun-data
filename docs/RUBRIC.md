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

## Per-family accuracy

Reported for every exactly-scorable family (17). Small families (E: 7,
F: 17, I: 1, J: 7, N: 14) have wide confidence intervals — read them as
smoke signals, and read the micro average for the headline.

## Published baselines (deterministic, re-runnable)

| Baseline | Rule | Micro accuracy |
|---|---|---|
| majority | most common labeled answer per family (ties: sorted-first) | 0.7324 |
| random-seed7 | uniform draw from the family's observed answer space, seed 7 | 0.3675 |

```bash
python scripts/score_benchmark.py --baseline majority
python scripts/score_benchmark.py --baseline random --seed 7
```

Reports live in `reports/baselines/`. Any model run is scored with:

```bash
python scripts/score_benchmark.py --predictions preds.jsonl --out reports/scores_<run>.json
```

where `preds.jsonl` rows are `{"task_id": ..., "answer": ...}` and `task_id`
is the task file's `id`/`task_id`. 10,215 tasks are scorable across 17
families; 5 families (B, D, G, H, Q) are excluded with reasons above.

## What this rubric does NOT claim

- It does not measure exploit-writing (D), reference-matching (H), or rubric
  judgement (Q) — those need execution or human/LLM judges.
- Majority baselines on degenerate families (T: 588/589 one class) score
  ~1.0 without understanding anything — compare against random, not zero.
- Scores are comparable only on identical task sets; RESEARCH_ONLY rows
  never enter any benchmark, so the scorable set is the admitted set.

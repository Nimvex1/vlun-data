# Span-task scoring report (spec item 10)

- mode: **mechanical_baselines**
- grading axes (independent): answer_correctness, citation_existence, citation_exactness, span_support, abstention
- citation exactness tolerance: 0 bytes
- model outputs source: none in repo (work/predict + reports/baseline are severity classifiers, not span citations); used SELF-GENERATED MECHANICAL BASELINES
- not a real model result: True

> Strategies are mechanical constructions (exact / off-by-one / random / plausible-wrong / always-abstain) to exercise each axis independently. They are NOT a model evaluation.

Baseline subset size: 400 tasks (200 verified + 200 unavailable); submissions: `work/scoreval/baseline_submissions.jsonl`

## Strategy: always_abstain

scored=400 skipped=0

| axis | value |
|---|---|
| answer_correctness | 0/0 (acc=None) |
| citation_existence | 0/400 (rate=0.0) |
| citation_exactness | 0/0 (rate=None) |
| span_support | 0/200 (rate=0.0) |
| abstention | correct_abstain=200 wrong_abstain=200 missed_abstain=0 valid_answer=0 |
| cited_vs_supported | supported=0 cited_but_unsupported=0 unsupported_but_cited_on_abstain_task=0 not_cited_on_verifiable=200 |

## Strategy: exact_span

scored=400 skipped=0

| axis | value |
|---|---|
| answer_correctness | 400/400 (acc=1.0) |
| citation_existence | 330/400 (rate=0.825) |
| citation_exactness | 200/200 (rate=1.0) |
| span_support | 200/200 (rate=1.0) |
| abstention | correct_abstain=0 wrong_abstain=0 missed_abstain=200 valid_answer=200 |
| cited_vs_supported | supported=200 cited_but_unsupported=0 unsupported_but_cited_on_abstain_task=130 not_cited_on_verifiable=0 |

## Strategy: off_by_one_span

scored=400 skipped=0

| axis | value |
|---|---|
| answer_correctness | 400/400 (acc=1.0) |
| citation_existence | 330/400 (rate=0.825) |
| citation_exactness | 0/200 (rate=0.0) |
| span_support | 0/200 (rate=0.0) |
| abstention | correct_abstain=0 wrong_abstain=0 missed_abstain=200 valid_answer=200 |
| cited_vs_supported | supported=0 cited_but_unsupported=200 unsupported_but_cited_on_abstain_task=130 not_cited_on_verifiable=0 |

## Strategy: plausible_wrong_answer

scored=400 skipped=0

| axis | value |
|---|---|
| answer_correctness | 0/400 (acc=0.0) |
| citation_existence | 330/400 (rate=0.825) |
| citation_exactness | 200/200 (rate=1.0) |
| span_support | 200/200 (rate=1.0) |
| abstention | correct_abstain=0 wrong_abstain=0 missed_abstain=200 valid_answer=200 |
| cited_vs_supported | supported=200 cited_but_unsupported=0 unsupported_but_cited_on_abstain_task=130 not_cited_on_verifiable=0 |

## Strategy: random_span

scored=400 skipped=0

| axis | value |
|---|---|
| answer_correctness | 400/400 (acc=1.0) |
| citation_existence | 400/400 (rate=1.0) |
| citation_exactness | 0/200 (rate=0.0) |
| span_support | 0/200 (rate=0.0) |
| abstention | correct_abstain=0 wrong_abstain=0 missed_abstain=200 valid_answer=200 |
| cited_vs_supported | supported=0 cited_but_unsupported=200 unsupported_but_cited_on_abstain_task=200 not_cited_on_verifiable=0 |

## Axis-separation demonstration

```json
{
  "exact_span": {
    "answer_acc": 1.0,
    "citation_rate": 0.825,
    "exactness": 1.0,
    "support": 1.0
  },
  "note": "off_by-one keeps answer + existence but breaks exactness AND support -> the two citation axes are genuinely separate; plausible-wrong keeps support but breaks answer correctness.",
  "off_by_one": {
    "answer_acc": 1.0,
    "citation_rate": 0.825,
    "exactness": 0.0,
    "support": 0.0
  },
  "plausible_wrong": {
    "answer_acc": 0.0,
    "support": 1.0
  }
}
```

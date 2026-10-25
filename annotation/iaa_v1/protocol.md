# Inter-annotator agreement study protocol — iaa-v1

**STATUS: agreement NOT yet measured — no human annotations have been collected as of
2026-10-19.** This directory contains the protocol, the blinded stratified sample, the
annotator guide and empty response templates. It deliberately contains **no responses**
and therefore **no agreement statistic**. `reports/iaa_status.json` says
`"measured": false` with the reason, and `scripts/iaa_statistics.py` refuses to emit
numbers until two or more distinct human annotator ids have completed files.

Nothing in this study may be reported as human inter-annotator agreement if it was
produced by an LLM, by one annotator answering twice, or by the same model run twice with
different prompts. That case is machine self-consistency; the script flags it as a
violation (`audit_report`) rather than scoring it.

---

## 1. Constructs being judged

Each sampled record is judged on five constructs. They were chosen because they are the
labels this dataset actually publishes, and because a model benchmark inherits their
noise:

| # | Construct | Type | Values | Statistic |
|---|---|---|---|---|
| C1 | root cause category (item 16 vocabulary) | nominal, multi-label ≤3, plus UNLABELLED | RC-01…RC-23, RC-99 | unweighted Cohen's κ on `rc_primary`; Krippendorff's α (nominal) over the primary label; Jaccard agreement on the label *set* reported alongside |
| C2 | severity tier | ordinal | 0 none, 1 qa/informational, 2 medium, 3 high | weighted κ (linear **and** quadratic weights); α with ordinal distance |
| C3 | evidence ceiling | ordinal | L0…L6 (the repo's ladder) | weighted κ (linear **and** quadratic); α with ordinal distance |
| C4 | violated invariant stated by the evidence | binary | yes / no | κ |
| C5 | vocabulary fit | categorical | OK / UNLABELLED / WRONG_CATEGORY / NEW_CATEGORY_NEEDED | reported as frequencies only (it is a taxonomy-pressure signal, not an agreement target) |

C1 depends on the closed vocabulary in `taxonomy/root_cause_v1.md`; C2/C3 are the fields
that feed families B and G of the benchmark. C4 is the label family B scores.

**Not judged here:** whether the original audit was right, whether the sponsor was right,
and whether a PoC is high quality. Those have their own gates.

## 2. The guide annotators read

`annotation/iaa_v1/guide.md`. One copy for all three annotators, distributed before any
labelling starts, unchanged during the round. It contains: the root-cause vs impact vs
primitive vs component distinction with worked examples, the whole category list with
one-line definitions, the ordinal severity scale, the L0–L6 ladder with "what the row must
show for you to mark this level", the multi-label rule (≤3, one primary), and the
instruction to answer UNLABELLED rather than force a fit. Annotators may not read
`taxonomy/root_cause_v1.md`'s positive/negative example lists while labelling — those
contain dataset answers and would leak the key.

## 3. Sampling design

Produced by `scripts/sample_iaa.py` (`--seed 20261018`, `--target 300`). The sample is a
**frozen artefact**: the three blank annotator templates were generated from this exact
draw and distributed, so `--check` validates it against
`annotation/iaa_v1/frozen_sample.json` (sample and template sha256, header metadata, and
row identity) instead of redrawing it from the current inputs. The draw is never
regenerated in place. A future draw requires an explicit new version:

```bash
python scripts/sample_iaa.py --redraw --out annotation/iaa_v2 \
    --draw-version iaa-draw-2.0 --seed 20261024 --rationale "why a new draw exists" \
    --write-templates
```

That command leaves v1 untouched and writes its own `frozen_sample.json` with the new
seed, population, selection method and rationale.

- **Population:** the 722 records in `derived/records.jsonl` (v2.2 derived layer).
- **Target n = 300; realised n = 300** (see the header line of `sample.jsonl`).
- **Stratification axes** (25 non-empty cells realised):
  1. *severity band* — S0-none / S1 / S2 / S3 from `finding.severity`;
  2. *evidence band* — E-low (L0–L1) / E-L2 / E-high (L4–L6), from the evidence level
     derived in `taxonomy/assignments_v1.jsonl`;
  3. *root-cause label status* — A-adjudicated (one of the 40 hand-read candidates),
     A-rule (assigned by the v1-class rule table), A-unlabelled (RC-99), A-out-of-pool
     (no root-cause material at all).
- **Allocation:** proportional by stratum size with largest-remainder rounding, capped at
  each stratum's population; leftover quota is redistributed over strata ordered by
  (fractional remainder, stratum size, lexicographic stratum key) so the draw is stable.
- **Why these axes:** they are the three places where disagreement would change what the
  benchmark means — the hard part of C1 is distinguishing adjacent leaves in rule-assigned
  records, C2 drifts most on records nobody published a tier for, and C3 drifts most where
  quoted-but-never-executed PoCs tempt annotators to over-credit.
- **Oversampling, not proportionality:** A-unlabelled and A-adjudicated strata are sampled
  at a higher rate than their population share would give, because the interesting
  disagreement is at the vocabulary's edges and both cells are small. Any population-rate
  statistic must therefore be re-weighted; the guide's row list is not a random sample of
  the corpus and must not be described as one.
- **Blinding:** `sample.jsonl` carries only the record's visible evidence (title, sponsor
  status, intended behaviour, security assumption, attack path, code context with commit
  and line range, PoC presence/setup/observed impact, patch presence, verification fields,
  evidence types present). Each row lists the gold fields withheld from annotators in
  `hidden_from_annotator`. Labels, classes, severities and candidate root-cause prose stay
  in the canonical files only.

## 4. Annotators and independence

Three human annotators are invited, and the design works with two or three (all statistics
are pairwise, plus a pooled α; with two annotators report one pair, with three report all
three pairs and their mean, never a cherry-picked pair).

Annotators must be independent: not authors of `taxonomy/derivation_log.md`, not
collaborators on the candidate adjudication, no access to each other's in-progress files.
A minimum qualification is stated rather than assumed — reading the guide plus the
L0–L6 ladder and the closed vocabulary; a Solidity-fluent reviewer for at least one of the
three, and one annotator deliberately *not* involved in writing the taxonomy, so a
vocabulary that only its author can apply is detected.

Each annotator works a 20-row pilot first; the three pilot files are compared before the
remaining 280 rows, and the guide is amended (as `iaa-v1.1`, with a changelog) if the
pilot disagreement is traceable to the guide rather than to judgement. Amending the guide
mid-round invalidates the earlier rows: re-label them if the guide changes.

## 5. Ordinal severity scale

0 = none/informational (no publisher asserted a tier), 1 = qa, 2 = medium, 3 = high.
The dataset publishes no numeric score (see `quality.no_numerical_severity_score`), so the
tiers are labels, not points; quadratic weighting treats them as equally spaced categories,
which is an approximation the report must state rather than a measurement.

## 6. Adjudication rules

After all files are complete, before any statistic is published:

1. Compute agreement as specified; do not adjudicate first.
2. Every record where the primary C1 label differs, or where C2/C3 differ by ≥2 steps, or
   where C4 differs, goes to a disagreement log.
3. A fourth person (the adjudicator, who must not be one of the three) resolves each item
   in the log against the vocabulary's inclusion/exclusion rules and the L0–L6 ladder,
   recording: the resolved label, the rule that decided it, and whether the outcome was
   *annotator error*, *guide ambiguity*, or *vocabulary gap*.
4. `vocabulary gap` outcomes are the input to `root-cause-1.1` (see the taxonomy's
   migration notes); they are not silently patched into 1.0.
5. Resolved labels become the gold key; the agreement numbers are reported **as measured
   before adjudication**, never after. Post-adjudication agreement is not IAA.

## 7. What counts as agreement

- Nominal C1: two annotators agree when their `rc_primary` ids are identical. Set-level
  agreement (Jaccard over the ≤3 labels) is reported alongside because multi-label rows
  make primary-only agreement a lossy summary.
- Ordinal C2/C3: exact match for unweighted statistics; weighted statistics penalise a
  one-step slip less than a three-step slip. Both linear and quadratic weights are
  reported so a reader can see how much of the number depends on the weighting choice.
- Chance correction is mandatory: raw percentage agreement is never the headline.
- Confidence intervals: percentile bootstrap, 2000 replicates, seed recorded in the
  report, resampling units are records (paired across annotators) so a record nobody
  agrees on cannot be diluted by resampling annotators independently.
- Interpretation bands are quoted as convention (κ/α ≥ 0.80 reliable; 0.67–0.79 tentative;
  < 0.67 unsuitable for a gold key) and the band, not just the number, goes in any README
  claim. Below 0.67 on any construct, that construct's label is marked `provisional` in
  the dataset and the benchmark family that scores it is reported as unreliable.
- Minimum sample per pair: any pair with fewer than 30 co-annotated records produces no
  statistic, only a count.

## 8. Deliverables when annotations are absent (this state)

protocol.md (this file), guide.md, sample.jsonl (reproducible draw + sampler), three blank
templates, an empty documented `responses/`, the statistics script with its guards, and
`reports/iaa_status.json` saying `measured: false`. No kappa, no alpha, no CI, and no
sentence anywhere that implies agreement was observed.

## 9. Reproduce / run

```bash
python scripts/sample_iaa.py --seed 20261018 --target 300   # regenerate the draw
python scripts/sample_iaa.py --check                        # exit 1 on drift
python scripts/sample_iaa.py --write-templates              # regenerate blank templates
python scripts/iaa_statistics.py                            # write reports/iaa_status.json
python scripts/iaa_statistics.py --check                     # exit 1 on drift
python scripts/iaa_statistics.py --audit-report reports/iaa_status.json  # guard check
python -m pytest tests/test_iaa_statistics.py tests/test_taxonomy_gate.py
```

Once `responses/annotator_*.csv` exist, rerun `scripts/iaa_statistics.py`; it emits the
per-pair κ, weighted κ, pooled α with CIs, and the count of non-human rows excluded.

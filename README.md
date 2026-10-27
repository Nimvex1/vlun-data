# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus of smart-contract security findings. Every record traces to a
public artefact — a report section, a submission issue, a registry payload, or a commit-pinned
permalink — and every claim carries its evidence type. Governing rule: truth over scale;
`unknown` is a counted outcome, never a gap to fill by guessing.

## Dataset at a glance

| Layer | Source | Records | Strongest evidence |
|---|---|---|---|
| v1 | 8 Code4rena audits (Solidity) | 722 derived | 9 pinpoint experiments, **5** L6 verified patches |
| v2.2 | advisories/audits/bounties/post-mortems, 5 languages | 137 | 37 executed runs, levels `{'L3': 1, 'L5': 35, 'L6': 1, 'none': 100}` |
| V3.0 | 18 new archives (audits, contests, incident PoCs, 1 research dataset) | 5,467 admitted / 7,712 candidates | levels `{"L0": 4586, "L1": 754, "L3": 125, "L5": 2}` after the V3.2 execution overlay |
| V3.1 | normalized findings with spans + overlays | 12,504 preview rows (7,037 new) | severity on 11,610, class on 2,093, files on 5,790 |
| V3.2 | fork executions of incident PoCs | 6 runs | **2** L5 reproduced thefts, 4 blocked at L3 |
| Vbeta | 15 new sources (incl. Solodit mirror) | 6,935 admitted / 7,060 candidates | L0/L1 only — nothing executed in this pass |

Gates (0 critical failures): v2 78/78 · v3.0 42/42 · v3.1 44/44 · Vbeta 34/34. Cross-manifest and reproducibility gates recompute every count from canonical records — see `scripts/check_manifests.py`, `scripts/check_reproducibility.py` and [`reports/reproducibility_report.md`](reports/reproducibility_report.md) for the gate summary.

Verification density (L5+L6 ÷ admitted records): v1 5/722 · v2.2 36/137 · V3.0 2/5,467 · Vbeta 0/6,935 (L0/L1-only by construction). Counted as executed evidence (any level above L1, i.e. a real compile or run artefact): v1 5/722 · v2.2 36/137 · V3.0 127/5,467 · Vbeta 0/6,935. Depth is reported next to scale so dilution is visible, not hidden.

## Layout

```
jsonl/            ORIGINAL v1 evidence layer (264 findings, 458 negatives, 155 exploits, 38 patches). Never rewritten.
derived/          enriched v1 records (722): evidence, attacker model, state transition, taxonomy, quality
experiments/      one directory per attempted exploit (harness, command, stdout, stderr, result.json)
jsonl_ml/         v2.2 source layer (137 findings, 112 sources). Read-only.
derived_v2_2/     v2.2 derived records (137) with quality rubric + experiment view
splits_v2_2/      v2.2 splits (train 76, validation 30, test 31, quarantine 2)
experiments_v2_2/ executed multi-language runs
jsonl_v3/         v3 source layer (7,712 candidates, 18 sources). Read-only.
derived_v3/       v3 records (5,467) + v3.1 fragments/overlays/preview (12,504 rows)
splits_v3/        by-source splits, no source spans splits
experiments_v3/   v3.2 fork-execution artefacts (command, stdout, stderr, harness manifest, result.json)
datasets/         high-confidence subsets, each with a published admission rule
training/         task-oriented training files
splits_v2/       post-quarantine v1/v2 splits (the pre-quarantine splits/ was retired; see scripts/vlun.py)
benchmark/        19 families (A-J v1, K-Q v2.2, R-S v3, T v3.1-taxonomy) + U-V Vbeta (13,154 tasks)
benchmark/retired_families/  retired families (B, E, K, L, M, N, O, P, S, T) — a location, not a verdict: frozen byte-identical with per-family retirement.json, still shipped, audited and scored, and their status is computed from the data like every other family's
reports/          every generated report, including reports/v2_2/ and reports/v3/
scripts/          the pipeline (standard-library only; see below)
tests/            stdlib-only tests for terminology, counts, splits, gates (run: `python -m unittest discover -s tests`)
Vbeta/            isolated new-language layer (6,935 admitted / 7,060 candidates, 15 sources): own scripts, splits, benchmarks U-V, gates; never touches PRESENT
nextdata/ + .firecrawl/  local-only Solodit scrape artefacts (1,926 issue URLs indexed, 733 detail pages harvested): referenced by path, METADATA_ONLY
work/             clones, retrieved source, execution logs — git-ignored
```

`jsonl/` is the contract: **original evidence**. Inferred analysis lives in `derived/`, machine
executions in `work/` (summarised in `reports/`). A researcher can always separate what the audit
said from what the builder derived from what was executed.

## Evidence model

Every derived field carries `{value, evidence_type, source_refs}`. Closed vocabulary:

| type | meaning |
|---|---|
| `observed_fact` | read out of a retrieved artefact |
| `reported_claim` | stated by an identifiable external source |
| `derived_fact` | computed here by a rule that lives in the code |
| `experimentally_verified` | produced by actually compiling + running something |
| `externally_attributed` | attributed to a named third party (judge, sponsor, label) |
| `unverified` | asserted somewhere, not checked here |
| `unknown` | no defensible value exists |

PoC quality ladder: **L0** report prose · **L1** PoC quoted · **L2** PoC reconstructed ·
**L3** compiles · **L4** executes · **L5** claimed violation reproduced ·
**L6** reproduced on the vulnerable revision *and* blocked on the fixed one (same test).
Above L2 requires a run artefact; L6 requires both legs. No PoC is marked reproduced unless
forge reported `Success`, and no patch is called effective without the controlled comparison.

## What is verified (honest counts)

- **v1/v2:** 9 pinpoint experiments
  (2 inconclusive, missing symbol recorded);
  **5** patches verified effective;
  rejection evidence over 458 rejected submissions (axes are independent
  and not additive): 9 carry a reason
  attributed to a named judge or sponsor, 1 where
  a gate in the cited code removes the standing the claim itself asserts,
  **6** in total have a technical reason
  the claim is false, 193 are
  corroborated as duplicates of an accepted finding (redundancy, not falsity),
  0 had an exploit
  attempted that did not demonstrate the violation, and
  256 rest on a public label alone — definitions
  in [`reports/rejection_evidence.md`](reports/rejection_evidence.md);
  71 API-sibling counterexample pairs.
- **v2.2:** 37 executed runs;
  123 of 137 records state no attacker standing.
- **V3.0:** 3,517 strong imports +
  1,934 unverified imports +
  16 hard negatives +
  108 corroborations; the rest stays
  research-only rather than being forced into the dataset.
- **V3.1:** 7,037 admitted findings
  (severity explicit on 4,231);
  taxonomy explicit on 596, derived on
  1,497, unknown elsewhere — by rule, not by optimism.
- **V3.2:** 127/129 incident PoCs compile (L3); 127 admitted v3 records now carry a run artefact (levels `{"L0": 4586, "L1": 754, "L3": 125, "L5": 2}`),
  2 thefts reproduced on fork with attacker-profit
  evidence; 4 blocked
  (pruned RPC, unreplayable state, repo drift — each with verbatim backend errors in
  `experiments_v3/`); 47 V3.1 patch candidates stay unverified at the candidate
  layer: 24 cite a
  static diff review, 22 have no retrievable source, and
  1 additionally carries an executed two-side PoC
  (violation only on the vulnerable revision; harness and logs in
  [`experiments_v3/1inch-lop-m01/`](experiments_v3/1inch-lop-m01/)) — a diff
  review states what changed, not whether the fix works
  ([`derived_v3/patch_reviews.jsonl`](derived_v3/patch_reviews.jsonl),
  [`reports/v3/patch_static_review.json`](reports/v3/patch_static_review.json)).
- **VLUN-Prove:** 6 two-revision proof tasks published as a
  scoring interface ([`reports/prove_split_interface.md`](reports/prove_split_interface.md)).
  A submission is credited stage by stage — generated → compiles → executes → impact reproduced
  → patch verified — where `impact_reproduced` requires the *expected assertion* to be what
  broke, and a compile or dependency failure stops the ladder instead of being relabelled as a
  failed proof. The answer key (fixed revisions, expected assertions) lives outside this
  repository and is pinned by hash
  (2 files committed in
  [`reports/prove_split_interface.json`](reports/prove_split_interface.json)).
  Self-check: the project's own recorded runs were replayed through the grader's rules
  (`{'patch_verified': 5}`), which is a
  check of the grader, not of any model. The ~200-task held-out split is **not** reported as
  met: only 6 tasks have
  both revisions executed today, and each further task needs a pinned fix and a test run on
  both sides before it can be counted.
- **Vbeta:** 6,935 admitted records from 7,060 candidates
  (64 IMPORT, 6,866 unverified,
  5 negatives, 62 research-only);
  79 L1 quoted-PoC rows (rest L0); languages `["cairo", "go", "move", "rust", "solidity", "unknown", "vyper"]`;
  splits train 683 / validation 584 / test 5,668.
- Full per-source accounting, unknowns with resolving evidence, and extraction failures:
  [`reports/v2_1_quality_report.md`](reports/v2_1_quality_report.md),
  [`reports/v2_2/quality_report.md`](reports/v2_2/quality_report.md),
  [`reports/v3/quality_report.md`](reports/v3/quality_report.md),
   [`reports/v3/normalization_report.md`](reports/v3/normalization_report.md),
   [`reports/v3/normalization_unknowns.md`](reports/v3/normalization_unknowns.md),
   [`Vbeta/reports_vbeta/quality_report.md`](Vbeta/reports_vbeta/quality_report.md),
   [`Vbeta/reports_vbeta/shieldify_ingestion_report.md`](Vbeta/reports_vbeta/shieldify_ingestion_report.md),
   [`Vbeta/reports_vbeta/solodit_ingestion_report.md`](Vbeta/reports_vbeta/solodit_ingestion_report.md).
- Depth over scale: per-layer verification levels, field coverage and 40 verbatim
  root_cause candidates for High findings ([`reports/depth_dashboard.md`](reports/depth_dashboard.md),
  generated by `scripts/depth_dashboard.py`; originals untouched).
- Packaging: machine-readable schemas ([`schema/`](schema/), generated from
  `scripts/schema_terms.py`), [`CITATION.cff`](CITATION.cff),
  [`CHANGELOG.md`](CHANGELOG.md), [`docs/DATASHEET.md`](docs/DATASHEET.md)
  (generated from reports), and CI running all gates on push/PR.
- Per-field coverage (which fraction of records actually carry root_cause, attacker model,
  impact, severity, language, … — 11 of 28 tracked fields under 50% known):
  [`reports/field_coverage.md`](reports/field_coverage.md), generated by
  `scripts/field_coverage.py` from the canonical files.

## Splits & benchmarks

Splits isolate by repository (v1/v2) or by record/source (v2.2/v3/Vbeta); duplicates are quarantined,
never deleted. Benchmark families A-V are machine-readable under `benchmark/` (A-T) and
`Vbeta/benchmark_vbeta/` (U-V) with manifests; answer keys rebuild from the records, and
families that need experimentally produced ground truth only admit rows that have it.

| Family | Tasks | Scorable | Status | Layer |
|---|---|---|---|---|
| `A_vulnerability_detection` | 720 | 720 | PRIMARY | v1/A-Q |
| `B_root_cause_reasoning` | 720 | 228 | EXPLORATORY | v1/A-Q (retired) |
| `C_attacker_reasoning` | 720 | 290 | INVALID | v1/A-Q |
| `D_exploit_construction` | 720 | 0 | NOT_SCORABLE | v1/A-Q |
| `E_exploit_verification` | 720 | 7 | INVALID | v1/A-Q (retired) |
| `F_false_positive_rejection` | 458 | 17 | EXPLORATORY | v1/A-Q |
| `Fa_rejection_evidence_axis_vector` | 458 | 0 | NOT_SCORABLE | v1/A-Q |
| `Fb_duplicate_radar_pair` | 554 | 0 | NOT_SCORABLE | v1/A-Q |
| `G_patch_verification` | 38 | 5 | EXPLORATORY | v1/A-Q |
| `H_verified_exploit` | 7 | 0 | NOT_SCORABLE | v1/A-Q |
| `I_verified_non_exploit` | 3 | 1 | EXPLORATORY | v1/A-Q |
| `J_verified_patch` | 5 | 5 | EXPLORATORY | v1/A-Q |
| `K_language_ecosystem_routing` | 137 | 137 | INVALID | v1/A-Q (retired) |
| `L_severity_reconciliation` | 137 | 128 | INVALID | v1/A-Q (retired) |
| `M_experiment_level_classification` | 37 | 37 | EXPLORATORY | v1/A-Q (retired) |
| `N_attacker_identity_extraction` | 137 | 14 | INVALID | v1/A-Q (retired) |
| `O_record_class_and_scope` | 137 | 137 | INVALID | v1/A-Q (retired) |
| `P_provenance_tier_and_rights` | 137 | 137 | INVALID | v1/A-Q (retired) |
| `Q_evidence_type_and_quality_rubric` | 137 | 0 | NOT_SCORABLE | v1/A-Q |
| `R_v3_source_tier_routing` | 5,467 | 5,467 | INVALID | v3 |
| `S_v3_contest_outcome` | 1,072 | 1,072 | INVALID | v3 (retired) |
| `T_v31_taxonomy_explicit` | 589 | 589 | INVALID | v3 (retired) |
| `vbeta_U_language_routing` | 6,219 | 6,219 | INVALID | Vbeta |
| `vbeta_V_source_tier_routing` | 6,935 | 6,935 | INVALID | Vbeta |

`Tasks` is every row of the family file; `Scorable` is the number of those rows that carry a
real scalar answer key for the headline exact-match projection — a family graded under a
non-scalar contract reads 0 there even when its own scorer covers every row (see below).
`Status` is computed from the data at run time by
`scripts/benchmark_status.py` — never from a hand-written list, because a list cannot justify
an evaluation claim:

| status | meaning | in the headline? |
|---|---|---|
| `PRIMARY` | no validity flag, at least 100 scorable rows, at least 2 observed labels, and no train-only shortcut at or above 0.9 on a holdout of at least 30 rows | yes |
| `EXPLORATORY` | shipped and scored, but demoted: too few rows, a holdout too small to estimate on, or a single observed label | no |
| `INVALID` | a validity flag makes the family unusable as evaluation evidence: answer literal leak, near-duplicate leak, group or record overlap, held-out labels unseen in train, split-composition drift, saturation, or a train-only shortcut that solves the held-out split | no |
| `NOT_SCORABLE` | no exactly-matchable scalar key | no |
| `UNKNOWN` | a family file on disk that no rule covers — fail-closed, never primary | no |

The exact-match scorer (`scripts/score_benchmark.py`, rubric in `docs/RUBRIC.md`, keys in
`docs/ANSWER_KEY.md`) covers 720 of
23,198 manifest-scorable tasks in its primary metric. The
rest are reported in their own blocks and never in the headline: the
4 INVALID families' 18,911 scorable rows (C, R, U, V),
the 4 EXPLORATORY families' 28 sub-floor rows (F, G, I, J),
the 10 retired families' 2,486 scorable rows (B, E, K, L, M, N, O, P, S, T —
retirement is a location, not a verdict), plus the D, Fa, Fb, H, Q families that have no
exactly-matchable key (1,876 rows), excluded with stated reasons. Two of those
families are not left unscored: the F-extension is graded by its own scorer under its own
task contracts — `Fa_rejection_evidence_axis_vector` per axis over the assessed axes
(9 of 458 rows carry evidence for every
axis; 449 partial) and `Fb_duplicate_radar_pair` as a three-class
pair adjudication (554 pairs: 184
same, 121 distinct,
249 ambiguous), with published trivial-predictor floors
([`reports/f_extension.md`](reports/f_extension.md),
[`reports/f_extension_baselines.json`](reports/f_extension_baselines.json)). The table's 0
for both is a scope statement about the headline projection, never a claim that the rows
went unscored. The four blocks
partition every scored family, and the continuity twin below covers all
22,145 of them.

**The benchmark is OPEN-KEY.** Every benchmark family row carries its answer key in the same
file as its input, and those files are committed in this public repository, so the keys are
reachable by repository-wide retrieval. No family may be described as hidden, protected
against repository-level leakage, or not accessible. The only genuinely protected evaluation in
this project is the VLUN-Prove private split, whose answer key lives outside the tracked tree
and is pinned by hash in
[`reports/prove_split_interface.json`](reports/prove_split_interface.json). The secondary
holdout in `benchmark/independent/` is OPEN-KEY too: its key file is a tracked file, labelled
`OPEN_KEY` in its own manifest.

Published deterministic baselines. `acc @ predicted/scorable` is micro-accuracy on
the tasks the baseline actually predicted, shown with its coverage; the `over scorable`
column counts unpredicted tasks as wrong, so abstention is visible, never silent.
The primary column covers the PRIMARY families only; the continuity column covers **all
families ever shipped** (primary + exploratory + invalid + retired), comparable to prior
releases.

| Baseline | Primary acc @ predicted/scorable | Primary acc over scorable | Continuity acc @ predicted/scorable |
|---|---|---|---|
| majority | 0.7306 @ 720/720 | 0.7306 | 0.8687 @ 22,134/22,145 |
| random-seed7 | 0.5042 @ 720/720 | 0.5042 | 0.3980 @ 22,134/22,145 |
| frequency-seed7 | 0.6042 @ 720/720 | 0.6042 | 0.8161 @ 22,134/22,145 |
| first-published (L only, retired family) | n/a @ 0/720 | 0.0000 | 1.0000 @ 71/22,145 |
| majority-published (L only, retired family) | n/a @ 0/720 | 0.0000 | 1.0000 @ 71/22,145 |
| TF-IDF retrieval | 0.4361 @ 720/720 | 0.4361 | 0.8937 @ 22,134/22,145 |

first-published and majority-published are L-only predictors over a retired family:
they emit nothing on the primary set by construction, so their primary accuracy is
**n/a with zero predictions**, never a 0.0000 that reads as a scored result — the
`over scorable` column is where the abstention shows as 0.0000 of
720 primary scorable tasks.
The 4 INVALID families (C, R, U, V) carry no headline claim: a
validity flag makes them unusable as evaluation evidence, and a model score there would be
a score on a task that is not a task. Their rows stay in the dataset and stay scored, in
`families_invalid`, and are never counted in the headline.
The 4 EXPLORATORY families (F, G, I, J) are demoted: below the
100-row floor, a holdout too small to estimate
on, or a single observed label. A family whose scorable rows carry one label is **not
evaluable** for accuracy at all — its accuracy is null with the reason
`single_label_not_evaluable`, because one label makes any accuracy a restatement of the
label distribution.

The headline number is a label-distribution diagnostic over the primary set's scorable rows
(train, validation and test together). The number a model result has to beat is the held-out
one: on the primary family's 147 test rows the train-only majority
floor is 0.5510, the seeded random 0.5238, the
label-frequency 0.4966 and the retrieval 0.2925. Every
floor is fitted on the train rows only; a floor fitted on the held-out rows would have seen
the answers it is scored against. A split-blind floor is a validity hazard.
`scripts/check_manifests.py` recomputes every one of these
counts from the canonical records
(manifest-file agreement, task-record resolution, split coverage, RESEARCH_ONLY
leak scans, L5/L6-without-artefact and `verified_patch` scans). A family whose file disagrees
with its manifest fails the build.

## Licensing

- The authoritative release boundary is `RELEASE_MANIFEST.json`: a tracked path that is not
  listed there with a released rights status is **not licensed here**. `LICENSE` states the
  same rule in five parts and says what it does not cover.

- The released set is the pipeline (`scripts/`, MIT) and the authors' own documents, schemas,
  decision records, analysis reports, test code and rights-redacted `distribution_v1/` view
  (CC BY 4.0). The manifest names every path and the licence that applies to it.

- The evidence corpus (`jsonl*/`, `derived*/`, `splits*/`, `benchmark/`, `training/`,
  `datasets/`, `Vbeta/`) and the run logs under `experiments*/` are **not licensed here**:
  they stay in the research tree, and this project grants no redistribution right over them.
  Third-party source is not licensed here at all.

- 424 v1 records
  carry verbatim source from repositories declaring no licence (flagged per record; re-measured
   from the text itself in `reports/third_party_audit.json`).

- V3 keeps link + sha256 + attributed facts only (METADATA_ONLY). Vbeta keeps links + observed
  facts only (METADATA_ONLY) — full report prose is never copied in; `openzeppelin-cairo` rows
  carry observed MIT.

- METADATA_ONLY is this project's **default data-handling policy**, applied where no
  documented right to redistribute exists; it is not a claim and not a determination that
  any transformed record has been legally cleared, and a permalink plus a sha256 identifies
  bytes rather than granting reuse. Per-source rights decisions live in `V4/licensing.json`
  and `distribution_v1/rights_source_registry.json`, enforced by
  `scripts/check_rights_consistency.py`.

- Vbeta sources are first-party audit pages plus a tier-2 Solodit mirror (auditor originals
  stay canonical). No operator-authored rows remain: the single interim one was retired and
  replaced by its harvested original (see `Vbeta/reports_vbeta/solodit_ingestion_report.md`).

- No permission has been obtained from upstream protocol authors, and attribution is not a
  redistribution right. For redistribution or commercial training, pull sources yourself via
  `scripts/fetch_sources.py` under your own compliance process. See
  [`NOTICE.md`](NOTICE.md).

## Reproduce

```bash
python scripts/build_all.py --with-network   # everything
python scripts/validate.py                   # the gate (non-zero on failure)
python scripts/validate_v3.py                # v3 gate
python scripts/validate_v31.py               # v3.1 gate
python scripts/check_manifests.py            # 180 count/reference checks, recomputed from canonical records
python scripts/check_reproducibility.py      # provenance, determinism, isolation (skips stay skipped_no_network)
python -m unittest discover -s tests        # terminology, invariants, fixtures (incl. intentionally-broken)
python scripts/generate_readme.py --check    # this file is generated; stays current only if regenerated
python Vbeta/scripts/build_vbeta.py --check  # Vbeta dry run (writes only under Vbeta/)
python Vbeta/scripts/validate_vbeta.py       # Vbeta gate
python Vbeta/tests/test_vbeta.py             # Vbeta tests
```

Every script is idempotent, takes `--help`, and writes only under its own layer directories;
`jsonl/`, `jsonl_ml/`, `jsonl_v3/` are read-only. Offline runs skip network stages explicitly
(`skipped_no_network` — a skip is never reported as a pass). Fresh clones reproduce the JSONL and
derived layers but not execution artefacts, which live git-ignored under `work/` (verdicts stay
checkable via committed `result.json` files).

Key stages:

```bash
python scripts/fetch_sources.py              # clone + retrieve pinned citations
python scripts/verify_pocs.py                 # compile and run PoCs
python scripts/verify_patches.py              # vulnerable vs fixed revision pairs
python scripts/resolve_citations.py           # branch refs -> exact commits
python scripts/run_verified_experiments.py    # exploit experiments, both revisions
```

Remediation layers added 2026-10-19 (each regenerates its own artefacts; `--check` is wired
into `scripts/run_gates.py`):

```bash
python scripts/build_rejection_corpus.py         # six independent rejection-evidence axes, 458 records
python scripts/check_rejection_consistency.py    # re-derives every reported rejection count
python scripts/reconcile_v4_licensing.py         # apply V4/licensing.json to the V4 layers
python scripts/inventory_rights.py               # rights inventory + distribution_v1/ projection
python scripts/check_rights_consistency.py       # rights gate: copied content, licence status, hashes
python scripts/build_prove_split.py              # VLUN-Prove interface + private answer-key split
python scripts/build_poc_triage_queue.py         # exploit-candidate triage queue by layer
python scripts/rerun_v1_pocs.py                  # re-runs under the current evidence standard
python scripts/unblock_v32_runs.py               # blocked-run recovery attempts, scope changes recorded
python scripts/nonevm/run_pilot.py               # five non-EVM adapters
python scripts/audit_evidence_spans.py           # V3.1 span / pointer / source-ref coverage
python scripts/build_api_siblings.py             # cross-repository sibling pairs
python scripts/review_sibling_pairs.py           # independent re-read; admits or rejects each pair
python scripts/validate_taxonomy.py              # closed root-cause vocabulary gate
python scripts/iaa_statistics.py                 # agreement statistics (refuses to invent a number)
python scripts/build_remediation_report.py       # reports/remediation_before_after.md
python scripts/build_derived.py               # evidence, attacker model, taxonomy
python scripts/build_hard_negatives.py        # structured rejection reasons
python scripts/check_leakage.py --emit splits_v2
python scripts/build_benchmark.py             # families A-J
python scripts/build_benchmark_v22.py         # families K-Q
python scripts/build_subsets.py               # datasets/ and training/
python scripts/generate_stats.py              # the only source of statistics
python scripts/ingest_audit_sources.py        # audit-source registry
python scripts/build_v3.py                    # v3: 18 clones -> jsonl_v3/derived_v3/splits_v3 + R-S
python scripts/validate_v3.py                 # the v3 gate
python scripts/normalize_v3.py                # v3.1: boundaries, fields, overlays, preview
python scripts/validate_v31.py                # the v3.1 gate
python scripts/build_benchmark_v31.py         # family T (explicit taxonomy)
python scripts/run_dhl_experiments.py         # v3.2: staged fork executions
python scripts/check_manifests.py             # cross-manifest count integrity (writes nothing)
python scripts/check_reproducibility.py        # reproducibility gate incl. Vbeta rebuild parity
python Vbeta/scripts/harvest_solodit.py       # scrape -> Vbeta/solodit_candidates.json (deterministic)
python Vbeta/scripts/build_vbeta.py           # candidates -> records/splits/U-V (Vbeta only)
```

## Repositories (v1 scope)

| Repository | Protocol | Findings | Split |
|---|---|---|---|
| `code-423n4/2022-05-alchemix` | Alchemix | 28 | train |
| `code-423n4/2024-01-decent` | Decent | 12 | validation |
| `code-423n4/2024-01-renft` | reNFT | 29 | validation |
| `code-423n4/2024-04-noya` | NOYA | 86 | train |
| `code-423n4/2024-08-wildcat` | The Wildcat Protocol | 32 | test |
| `code-423n4/2024-12-bakerfi` | BakerFi Invitational | 32 | test |
| `code-423n4/2025-06-panoptic` | Panoptic Hypovault | 4 | test |
| `code-423n4/2025-08-gte-perps` | GTE Perps and Launchpad | 41 | test |

V3 spans 18 more archives (audits, contests, incident PoCs); per-source accounting is in
[`reports/v3/quality_report.md`](reports/v3/quality_report.md).

## Vbeta layer (isolated, additive)

`Vbeta/` holds 15 new sources with zero overlap against V3's 18 archives:
professional-audit pages (OtterSec, Neodyme, Trail of Bits, Runtime Verification, Veridise ZK,
MoveBit, OpenZeppelin Cairo), contest findings (Immunefi, Cyfrin CodeHawks, Cantina),
Shieldify portfolio findings, and a Solodit HIGH+MEDIUM mirror
(733 detail pages harvested of 1,926 indexed,
1 duplicate excluded; languages `["cairo", "go", "move", "rust", "solidity", "unknown", "vyper"]`).
Rule 1: PRESENT is read-only — every Vbeta writer refuses paths outside `Vbeta/`, and the gate
warns if any PRESENT sentinel drifts from `Vbeta/present_snapshot.json`. Rule 2: truth over
scale (no record above L1 without run artefacts). Rule 3: METADATA_ONLY (links + observed
facts; full prose one hop away, never copied in). Admission is computed in code
(`decide()`): IMPORT only on title + severity + link + status all observed. See
[`Vbeta/README.md`](Vbeta/README.md) and the per-source ingestion reports.

## Integrity infrastructure

One canonical vocabulary — `scripts/schema_terms.py` (single source of truth; imports, never
redefines, the existing enums) — separates sources from findings, candidates from admitted
records, derived rows from preview rows, published PoCs (L1) from reproduced ones (L5/L6),
and team-reported `Fixed` from `verified_patch`. Validators reject deprecated terms
(`verified source`, `reproduced`-as-prose, `Fixed (verified)`). Status:
[`reports/reproducibility_report.md`](reports/reproducibility_report.md) is generated from the
JSON each gate writes and holds every gate's size and critical-failure count -- the
numbers that do not vary by machine. The per-check PASS/SKIP matrix is deliberately not
pinned there: it depends on whether the git-ignored `V3/clones`/`work/` are present, so it
is the CI run for the commit, or `python scripts/run_gates.py` locally. `validate.py`,
`validate_v3.py`, `validate_v31.py` and the Vbeta gate enforce it per layer.

What this remediation changed, item by item, with every figure read out of the reports it
names: [`reports/remediation_before_after.md`](reports/remediation_before_after.md)
(generated by `scripts/build_remediation_report.py`; a measurement no artefact records shows
as `not recorded` rather than as zero).

`scripts/build_all.py` re-runs every generator, and that exposed two things a per-layer
freshness gate cannot see. Published split/derived layers are now protected: the build
records the bytes each canonical layer started with, and a stage that rewrites one is
rolled back and the build fails rather than absorbing the change — an intentional refresh
is an explicit `--allow-canonical-rewrite` migration. The measured case:
`check_leakage.py --emit splits_v2` is **not idempotent**. Run against splits that were
already post-processed it finds 0 near-duplicate and 0 semantic cross-split pairs, so its
next `--emit` would replace the 2-row `splits_v2/quarantine.jsonl` with an empty
file (the 63-row file is `Vbeta/splits_vbeta/quarantine.jsonl`). The writer now
refuses to shrink or empty that curated quarantine unless
`--allow-quarantine-rewrite` is passed after a preview; `build_all.py` still rolls back
any rewrite of canonical layers that is not an explicit `--allow-canonical-rewrite`
migration. The published quarantine is therefore reproducible only from the pre-emit
splits. `benchmark/manifest.json` had a related
bug: the A-J builder rebuilt the manifest from scratch and deleted the K-Q bookkeeping, and
because retired-family entries were carried *only* from that same file the loss was
unrecoverable — six retired families vanished on the second full build. Builders now carry
entries they do not own and raise instead of dropping, and
`tests/test_canonical_layer_guard.py` fails on both behaviours.

## ML quickstart

- Vulnerability detection / reasoning tasks: `training/*.jsonl` (v1 task files, **TRAIN-ONLY**)
  and `benchmark/` A-T + `Vbeta/benchmark_vbeta/` U-V (every task carries its split; answer keys
  rebuild from the records). The held-out partitions were moved out of the model-visible
  training view into `benchmark/independent/`: `training/` ships the train partition only
  (16,129 rows, of which 0
  carry a record that any benchmark family holds out), and the held-out shards are committed
  under `benchmark/independent/` instead — open-key, but not model-visible. Measured in
  [`reports/eval_leakage_report.md`](reports/eval_leakage_report.md).
- Admission-filtered records: `datasets/` (each row carries a published
  `admission_rule`), `derived_v3/records.jsonl` (each row carries `decision`,
  `verification_level`, `language`, `ecosystem`, `benchmark_split`),
  `Vbeta/derived_vbeta/records.jsonl` (each row carries `decision`,
  `verification_level`, `language`, `ecosystem`; the split lives in the
  benchmark manifests under `Vbeta/benchmark_vbeta/`).
- Splits never leak across train/validation/test by repository or source; duplicates sit in
  `quarantine`, never deleted. Check any of this with `scripts/check_manifests.py`.

## Attribution

Findings, verdicts and PoC code belong to their original authors: Code4rena and the
competitive-audit participants, the professional auditors (Shieldify, OtterSec, Neodyme,
Trail of Bits, Runtime Verification, Veridise, MoveBit, OpenZeppelin, Zellic, Pashov and
others), the contest platforms (Cantina, CodeHawks, Immunefi, Sherlock), the incident PoC
authors, and Cyfrin Solodit as a mirror (auditor originals stay canonical).
See [`NOTICE.md`](NOTICE.md).

## V4 layer

Isolated layer extracted from the cloned Halborn/Oak/CoinFabrik report archives (`work/cloned_conversion/staged_report_candidates.jsonl`, 666 report candidates). Records: 5270 extracted, 5268 admitted, 0 quarantined, 2 duplicates. Evidence levels: {'L0': 5270}. Languages: go 3394, michelson 4, move 5, rust 143, solidity 1555, teal 14, unknown 155. Missing provenance is tracked in the manifest; all records are L0 only (no PoC execution was performed). Details: `reports/cloned_repo_conversion_v2.md`, `jsonl_v4/`, `derived_v4/`.

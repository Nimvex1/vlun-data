# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus of smart-contract security findings. Every record traces to a
public artefact — a report section, a submission issue, a registry payload, or a commit-pinned
permalink — and every claim carries its evidence type. Governing rule: truth over scale;
`unknown` is a counted outcome, never a gap to fill by guessing.

## Dataset at a glance

| Layer | Source | Records | Strongest evidence |
|---|---|---|---|
| v1 | 8 Code4rena audits (Solidity) | 722 derived | 9 pinpoint experiments, **7** L6 verified patches |
| v2.2 | advisories/audits/bounties/post-mortems, 5 languages | 137 | 37 executed runs, levels `{'L3': 1, 'L5': 35, 'L6': 1, 'none': 100}` |
| V3.0 | 18 new archives (audits, contests, incident PoCs, 1 research dataset) | 5,467 admitted / 7,712 candidates | levels `{"L0": 4586, "L1": 754, "L3": 125, "L5": 2}` after the V3.2 execution overlay |
| V3.1 | normalized findings with spans + overlays | 12,504 preview rows (7,037 new) | severity on 11,610, class on 2,093, files on 5,790 |
| V3.2 | fork executions of incident PoCs | 6 runs | **2** L5 reproduced thefts, 4 blocked at L3 |
| Vbeta | 15 new sources (incl. Solodit mirror) | 6,935 admitted / 7,060 candidates | L0/L1 only — nothing executed in this pass |

Gates (0 critical failures everywhere): v2 78/78 · v3.0 42/42 · v3.1 44/44 · Vbeta 34/34. Cross-manifest and reproducibility gates recompute every count from canonical records — see `scripts/check_manifests.py`, `scripts/check_reproducibility.py` and [`reports/reproducibility_report.md`](reports/reproducibility_report.md) for the gate summary.

Verification density (L5+L6 ÷ admitted records): v1 7/722 · v2.2 36/137 · V3.0 2/5,467 · Vbeta 0/6,935 (L0/L1-only by construction). Counted as executed evidence (any level above L1, i.e. a real compile or run artefact): v1 7/722 · v2.2 36/137 · V3.0 127/5,467 · Vbeta 0/6,935. Depth is reported next to scale so dilution is visible, not hidden.

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
benchmark/        17 families (A-J v1, K-Q v2.2, R-S v3, T v3.1-taxonomy) + U-V Vbeta (13,154 tasks)
benchmark/retired_families/  retired headline-excluded families (B, E, K, L, M, N, O, P, S, T), frozen byte-identical with per-family retirement.json; still shipped, audited and scored for continuity
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
  **7** patches verified effective;
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
| `A_vulnerability_detection` | 720 | 720 |  | v1/A-Q |
| `B_root_cause_reasoning` | 720 | 228 | RETIRED | v1/A-Q |
| `C_attacker_reasoning` | 720 | 290 |  | v1/A-Q |
| `D_exploit_construction` | 720 | 346 |  | v1/A-Q |
| `E_exploit_verification` | 720 | 7 | RETIRED | v1/A-Q |
| `F_false_positive_rejection` | 458 | 17 | EXPLORATORY | v1/A-Q |
| `G_patch_verification` | 38 | 7 | EXPLORATORY | v1/A-Q |
| `H_verified_exploit` | 7 | 7 |  | v1/A-Q |
| `I_verified_non_exploit` | 3 | 1 | EXPLORATORY | v1/A-Q |
| `J_verified_patch` | 7 | 7 | EXPLORATORY | v1/A-Q |
| `K_language_ecosystem_routing` | 137 | 137 | RETIRED | v1/A-Q |
| `L_severity_reconciliation` | 137 | 128 | RETIRED | v1/A-Q |
| `M_experiment_level_classification` | 37 | 37 | RETIRED | v1/A-Q |
| `N_attacker_identity_extraction` | 137 | 14 | RETIRED | v1/A-Q |
| `O_record_class_and_scope` | 137 | 137 | RETIRED | v1/A-Q |
| `P_provenance_tier_and_rights` | 137 | 137 | RETIRED | v1/A-Q |
| `Q_evidence_type_and_quality_rubric` | 137 | 137 |  | v1/A-Q |
| `R_v3_source_tier_routing` | 5,467 | 5,467 |  | v3 |
| `S_v3_contest_outcome` | 1,072 | 1,072 | RETIRED | v3 |
| `T_v31_taxonomy_explicit` | 589 | 589 | RETIRED | v3 |
| `vbeta_U_language_routing` | 6,219 | 6,219 | SATURATED | Vbeta |
| `vbeta_V_source_tier_routing` | 6,935 | 6,935 | SATURATED | Vbeta |

`Scorable` is the manifest count (answer key present); `Status` marks
families retired to `benchmark/retired_families/`, demoted to EXPLORATORY
(fewer than 100 headline scorable rows) or SATURATED (headline majority >=
0.94). The exact-match scorer
(`scripts/score_benchmark.py`, rubric in `docs/RUBRIC.md`, keys in
`docs/ANSWER_KEY.md`) covers 19,631 of
22,639 manifest-scorable tasks; the rest are the
10 retired families' 2,486 scorable rows (scored only in
the continuity twin below), the 4 exploratory families' 32 sub-floor
rows (scored per-family and in the continuity twin), plus D generative, H
descriptive and Q judge-graded tasks
(490 rows), excluded with stated reasons.

Published deterministic baselines. `acc @ predicted/scorable` is micro-accuracy on
the tasks the baseline actually predicted, shown with its coverage; the `over scorable`
column counts unpredicted tasks as wrong, so abstention is visible, never silent.
Headline rows exclude the retired and exploratory families (see Status marks
above and `benchmark/retired_families/`); continuity rows cover **all families
ever shipped** (headline + exploratory + retired), comparable to prior releases.

| Baseline | Headline acc @ predicted/scorable | Headline acc over scorable | Continuity acc @ predicted/scorable |
|---|---|---|---|
| majority | 0.8736 @ 19,631/19,631 | 0.8736 | 0.8725 @ 22,149/22,149 |
| random-seed7 | 0.3457 @ 19,631/19,631 | 0.3457 | 0.3608 @ 22,149/22,149 |
| frequency-seed7 | 0.8107 @ 19,631/19,631 | 0.8107 | 0.8135 @ 22,149/22,149 |
| first-published (L only, retired family) | n/a @ 0/19,631 | 0.0000 | 1.0000 @ 71/22,149 |
| majority-published (L only, retired family) | n/a @ 0/19,631 | 0.0000 | 1.0000 @ 71/22,149 |
| TF-IDF retrieval | 0.8889 @ 19,631/19,631 | 0.8889 | 0.8949 @ 22,134/22,149 |

first-published and majority-published are L-only predictors over a retired family:
they emit nothing on headline families by construction, so their headline accuracy is
**n/a with zero predictions**, never a 0.0000 that reads as a scored result — the
`over scorable` column is where the abstention shows as 0.0000 of
19,631 headline scorable tasks.
Families marked SATURATED (headline majority >= 0.94: U, V)
carry no signal — a model beat there proves nothing. The
4 exploratory families (F, G, I, J) are below the
100-row floor where a family score is interpretable, so they carry no
headline claim either — their rows stay scored per-family and in the
continuity twin. Family A majority accuracy
differs by split (see baseline reports); a split-blind floor is a validity
hazard. `scripts/check_manifests.py` recomputes every one of these
counts from the canonical records
(manifest-file agreement, task-record resolution, split coverage, RESEARCH_ONLY
leak scans, L5/L6-without-artefact and `verified_patch` scans). A family whose file disagrees
with its manifest fails the build.

## Licensing

- `LICENSE` is three-way: data under `jsonl*/`, `derived*/`, `splits*/`, `benchmark/`,
  `datasets/`, `training/`, `reports/` is **CC BY 4.0**; `scripts/` is **MIT**; third-party
  source is **not licensed here at all**.
- 424 v1 records
  carry verbatim source from repositories declaring no licence (flagged per record; re-measured
   from the text itself in `reports/third_party_audit.json`). V3 keeps link + sha256 + attributed
   facts only (METADATA_ONLY). Vbeta keeps links + observed facts only (METADATA_ONLY) —
   full report prose is never copied in; `openzeppelin-cairo` rows carry observed MIT.
- Vbeta sources are first-party audit pages plus a tier-2 Solodit mirror (auditor originals
  stay canonical). No operator-authored rows remain: the single interim one was retired and
  replaced by its harvested original (see `Vbeta/reports_vbeta/solodit_ingestion_report.md`).
- No permission has been obtained from upstream protocol authors. For redistribution or
  commercial training, pull sources yourself via `scripts/fetch_sources.py` under your own
  compliance process. See [`NOTICE.md`](NOTICE.md).

## Reproduce

```bash
python scripts/build_all.py --with-network   # everything
python scripts/validate.py                   # the gate (non-zero on failure)
python scripts/validate_v3.py                # v3 gate
python scripts/validate_v31.py               # v3.1 gate
python scripts/check_manifests.py            # 172 count/reference checks, recomputed from canonical records
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

## ML quickstart

- Vulnerability detection / reasoning tasks: `training/*.jsonl` (v1 task files) and
  `benchmark/` A-T + `Vbeta/benchmark_vbeta/` U-V (every task carries its split; answer keys
  rebuild from the records).
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

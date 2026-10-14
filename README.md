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

Gates (0 critical failures everywhere): v2 73/73 · v3.0 42/42 · v3.1 35/35 · Vbeta 34/34. Cross-manifest and reproducibility gates recompute every count from canonical records — see `scripts/check_manifests.py`, `scripts/check_reproducibility.py` and [`reports/reproducibility_report.md`](reports/reproducibility_report.md) for the gate summary.

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
benchmark/        17 families (A-J v1, K-Q v2.2, R-S v3, T v3.1-taxonomy) + U-V Vbeta (13,153 tasks)
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
  331 negatives with a
  defensible reason (127 still unknown);
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
  `experiments_v3/`); 47 patch candidates all `not_testable` (no executable PoC on either side).
- **Vbeta:** 6,935 admitted records from 7,060 candidates
  (62 IMPORT, 6,868 unverified,
  5 negatives, 62 research-only);
  57 L1 quoted-PoC rows (rest L0); languages `["cairo", "go", "move", "rust", "solidity", "unknown", "vyper"]`;
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
  impact, severity, language, … — 3 of 28 tracked fields under 50% known):
  [`reports/field_coverage.md`](reports/field_coverage.md), generated by
  `scripts/field_coverage.py` from the canonical files.

## Splits & benchmarks

Splits isolate by repository (v1/v2) or by record/source (v2.2/v3/Vbeta); duplicates are quarantined,
never deleted. Benchmark families A-V are machine-readable under `benchmark/` (A-T) and
`Vbeta/benchmark_vbeta/` (U-V) with manifests; answer keys rebuild from the records, and
families that need experimentally produced ground truth only admit rows that have it.

| Family | Tasks | Scorable | Saturated | Layer |
|---|---|---|---|---|
| `A_vulnerability_detection` | 720 | 720 |  | v1/A-Q |
| `B_root_cause_reasoning` | 720 | 228 | SATURATED | v1/A-Q |
| `C_attacker_reasoning` | 720 | 290 |  | v1/A-Q |
| `D_exploit_construction` | 720 | 346 |  | v1/A-Q |
| `E_exploit_verification` | 720 | 7 |  | v1/A-Q |
| `F_false_positive_rejection` | 458 | 17 | SATURATED | v1/A-Q |
| `G_patch_verification` | 38 | 7 | SATURATED | v1/A-Q |
| `H_verified_exploit` | 7 | 7 |  | v1/A-Q |
| `I_verified_non_exploit` | 3 | 1 | SATURATED | v1/A-Q |
| `J_verified_patch` | 7 | 7 | SATURATED | v1/A-Q |
| `K_language_ecosystem_routing` | 137 | 137 |  | v1/A-Q |
| `L_severity_reconciliation` | 137 | 128 |  | v1/A-Q |
| `M_experiment_level_classification` | 37 | 37 | SATURATED | v1/A-Q |
| `N_attacker_identity_extraction` | 137 | 14 |  | v1/A-Q |
| `O_record_class_and_scope` | 137 | 137 |  | v1/A-Q |
| `P_provenance_tier_and_rights` | 137 | 137 |  | v1/A-Q |
| `Q_evidence_type_and_quality_rubric` | 137 | 137 |  | v1/A-Q |
| `R_v3_source_tier_routing` | 5,467 | 5,467 |  | v3 |
| `S_v3_contest_outcome` | 1,072 | 1,072 | SATURATED | v3 |
| `T_v31_taxonomy_explicit` | 589 | 589 | SATURATED | v3 |
| `vbeta_U_language_routing` | 6,218 | 6,218 | SATURATED | Vbeta |
| `vbeta_V_source_tier_routing` | 6,935 | 6,935 | SATURATED | Vbeta |

`Scorable` is the manifest count (answer key present). The exact-match scorer
(`scripts/score_benchmark.py`, rubric in `docs/RUBRIC.md`, keys in
`docs/ANSWER_KEY.md`) covers 22,148 of
22,638 manifest-scorable tasks
(D generative, Q judge-graded, H descriptive excluded with reasons).
Published deterministic baselines, micro-accuracy / coverage:
majority 0.8725 ·
random-seed7 0.3608 ·
frequency-seed7 0.8135 ·
first-published 0.0032 @
71 tasks ·
majority-published 0.0032 @
71 tasks ·
TF-IDF retrieval 0.9257.
Families marked SATURATED (majority >= 0.94: B, F, G, I, J, M, S, T, U, V)
carry no signal — a model beat there proves nothing. Family A majority accuracy
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
python scripts/check_manifests.py            # 171 count/reference checks, recomputed from canonical records
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

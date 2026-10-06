# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus built from 8 public Code4rena
audits, plus — since v2.2 — advisories, audits, bug bounties and post-mortems covering five
smart-contract languages. Every record traces to a public artefact: a report section, a submission
issue, a comment, a registry payload, or a commit-pinned permalink.

v1 shipped structured findings but **executed nothing**: every `poc.reproducible` was `false`, its
statistics disagreed with its own data in four places, and the scripts its README described were not
published. v2 added per-field evidence semantics and a validation gate. v2.1 made experimental
evidence its subject, and every v2.1 guarantee below still holds in **v2.2**:

* every exploit PoC is given a **proof-shape class** (nine values) and a **quality level L0-L6**,
  and a level above L2 is only reachable by an actual run artefact;
* **pinpoint exploit experiments** run the same test against the audited revision and against the
  fixing revision, so a patch is called *effective* only when the violation is observed on one and
  blocked on the other — and only when both runs really executed that same test. An experiment whose
  two sides ran *different* tests is recorded as
  `inconclusive_not_a_controlled_comparison`, never as an effectiveness result;
* **every mutable branch citation in the shipped derived layer is resolved** and written back into
  `derived/records.jsonl`, by content identity, submodule pointer or date-anchored blob identity.
  0 of 2,034 citations remain mutable. The read-only `jsonl/`
  evidence layer still carries 473 of them and is never rewritten;
* **hard negatives are re-classified** into verified / attributed / corroborated-duplicate /
  unknown, and a corroborated duplicate is explicitly *not* a false positive;
* **API-sibling counterexample pairs**, **Slither cross-checks**, **17 benchmark families**
  (A-J on the v1 layer, K-Q on the multi-language v2.2 layer, including the three that only accept
  experimentally produced ground truth), and
  **high-confidence subsets** with published admission rules.

## Layout

```
jsonl/            the ORIGINAL v1 evidence layer. Never rewritten by this pipeline.
├── findings.jsonl            264 records
├── negative_findings.jsonl    458 records
├── exploits.jsonl             155 records
├── patches.jsonl              38 records
├── protocol.jsonl             8 records
├── metadata.jsonl             11 records
└── errors.jsonl               19 records

derived/         enriched records, deterministic given the same inputs
├── records.jsonl              722 records with evidence, attacker model,
│                              state transition, expanded context, taxonomy, quality
├── hard_negatives.jsonl       458 structured rejections
├── counterexamples.jsonl      43 counterexample sets
└── manifest.json

experiments/     one directory per attempted exploit: harness, command, stdout,
                 stderr, trace and result.json for the vulnerable and the fixed
                 revision. Small, hashed, and committed on purpose.
jsonl_ml/        the v2.2 multi-language source layer: 137 findings,
                 112 sources across 5 languages. Read-only like jsonl/.
derived_v2_2/    v2.2 derived records (137) with per-field
                 evidence, the quality rubric and the experiment view
splits_v2_2/     v2.2 splits with per-record sha256 pointers + quarantine.jsonl
experiments_v2_2/ executed multi-language runs: command, stdout, stderr, result.json
jsonl_v3/        the v3 source layer: 7,712 candidates,
                 18 sources across 18 new archives. Read-only like jsonl/.
derived_v3/      v3 derived records (5,467) with decisions, quality rubric,
                 provenance ledger and verification view
splits_v3/       v3 by-source splits (no source spans splits) + quarantine.jsonl
datasets/        high-confidence subsets, each with a published admission rule
training/        task-oriented training files, split by task rather than one blob
splits/          v1 repository-level splits (kept for comparison)
splits_v2/       leakage-free splits + quarantine.jsonl
benchmark/       17 task families, machine readable (A-J v1, K-Q v2.2, R-S v3)
reports/         every generated report, including reports/v2_2/ and pre_upgrade_audit.json
scripts/         the pipeline (see below)
work/            clones, retrieved source, execution logs — git-ignored
```

`jsonl/` is the contract: **original evidence**. Everything the dataset builder inferred lives in
`derived/`, everything a machine actually ran lives in `work/` and is summarised in
`reports/verification_stats.json`. A researcher can always separate what the audit said from what
the builder derived from what was experimentally verified. `jsonl_ml/` is the same contract for the
v2.2 layer — the retrieved advisory, audit and post-mortem payloads of the five-language corpus —
and is never rewritten either.

## What was actually done

| | v1 | v2 |
|---|---|---|
| statistics | 4 of 24 disagreed with the data | generated by `scripts/generate_stats.py`, enforced by the gate |
| cited source retrieved | 0 files (`dataset/raw` unpublished) | 321 of 326 pinned (commit, file) pairs |
| PoCs compiled | 0 | 4 of 8 repositories |
| PoCs executed | 0 | 15 of 155 |
| PoCs demonstrating the claimed impact | unknown | **5** of 155 |
| negatives with a code-grounded reason | 0 | 8 derived + 9 reported |
| cross-split leakage checks | 3 | 4 detectors, 2 real duplicates found and quarantined |
| validation gate | described, not shipped | 71/71 checks, 0 critical failures |

### v2.1: experimentally proven evidence

| | v2 | v2.1 |
|---|---|---|
| PoC records given a proof-shape class | 0 | 155 of 155 |
| PoC records given an L0-L6 level | 0 | 155 |
| Pinpoint exploit experiments executed | 0 | 9 |
| Vulnerabilities with an observed violation at the audited commit | 5 | 7 |
| Patches verified effective (reproduced on vulnerable, blocked on fixed) | 0 | **7** |
| Mutable branch citations in the shipped derived layer | 473 | **0** of 2,034 |
| Negatives with a defensible reason | 15 | **331** — of which **1** are derived from code, **9** attributed to a named source, and **321** are corroborated duplicates (a valid claim filed twice — *not* a rejected one) |
| Negatives still honestly unknown | 443 | **127** |
| API-sibling counterexample pairs | 0 | 71 |
| Repositories with a static-analysis signal | none | 5 analysed, 1 reported unanalysable |
| Benchmark families | 7 | 17 |
| Benchmark tasks with experimentally produced ground truth | 0 | 15 |

Full accounting, including what could **not** be verified and why, is in
[`reports/v2_1_quality_report.md`](reports/v2_1_quality_report.md). The v2 report it supersedes is
kept at [`reports/final_quality_report.md`](reports/final_quality_report.md).

### v2.2: five languages, provenance-correct

v2.2 keeps every v2.1 guarantee and adds a second source layer: 137 findings and
112 sources from advisories, audits, bug bounties and post-mortems across **5 languages**
— Solidity, Vyper, Rust (Solana / CosmWasm / Substrate), Move (Sui / Aptos) and Cairo (Starknet).
The layer is provenance-first: each source carries its retrieval method, payload sha256,
verification status, a tier 0-4 from protocol-published down to third-party write-up, and its
licence declaration (or `unknown`, which is what an undeclared licence stays).

| | v2.1 | v2.2 |
|---|---|---|
| languages | 1 (Solidity) | 5 — `{'cairo': 8, 'move': 15, 'rust': 18, 'solidity': 45, 'vyper': 51}` |
| source layer | `jsonl/` (v1, never rewritten) | + `jsonl_ml/` 137 findings, 112 sources (never rewritten) |
| derived records | 722 | + 137 in `derived_v2_2/` with evidence, quality rubric, experiment view |
| splits | `splits_v2/` by repository | + `splits_v2_2/`: train 76, validation 30, test 31, quarantine 2 — per-record sha256 pointers, duplicates quarantined |
| executed experiment runs (v2.2 layer) | — | **37** — levels `{'L3': 1, 'L5': 35, 'L6': 1, 'none': 100}` |
| benchmark families | 10 | 17 (K-Q added: language routing, severity reconciliation, experiment level, attacker identity, record class, provenance tier, evidence rubric) |
| strongest evidence per record | — | `{'experimentally_verified': 37, 'observed_fact': 100}` |
| gate | — | 71/71 checks, 0 critical failures |

Read with the honest counts, all of them also in
[`reports/v2_2/`](reports/v2_2/): **123 of
137 records state no attacker standing** (`unknown`, not inferred);
**61
carry a reported claim rather than a code-derived verdict**; and family L is labelled on
128 of
137 tasks —
6 have a rating
but no attribution and 3
have neither, each said so on the row instead of guessed. Source titles and record ids in a task's
`source` block are traceability, not model input: task ids carry the record id, and a record id
carries its language prefix, which is family K's answer.

Full accounting for the new layer, including what could **not** be executed (Sui, Aptos, Scarb and
snFuzzer toolchains are absent from this environment, so no Move or Cairo run reaches L3), is in
[`reports/v2_2/quality_report.md`](reports/v2_2/quality_report.md).

### v3.0: eighteen new sources, additive layer

v3.0 keeps every v2.2 guarantee and adds a third source layer harvested from 18 cloned archives
(professional audits, competitive audits, incident PoCs, one Tier-4 research dataset): 7,712
candidates, 5,467 admitted records. The v1/v2.2 artefacts are untouched;
the clone working trees (~3.1 GB, must-not-redistribute) are not committed - provenance survives
as clone-HEAD pins plus per-file sha256. Nothing was executed in this pass, so no record exceeds
L1 (published PoC); `reproducibility = 0` for every v3 record by construction.

| | v3.0 |
|---|---|
| sources discovered | 18 |
| candidates / admitted records | 7,712 / 5,467 |
| decisions | {'CORROBORATION_ONLY': 108, 'IMPORT': 3517, 'IMPORT_AS_NEGATIVE': 16, 'IMPORT_AS_UNVERIFIED': 1934, 'RESEARCH_ONLY': 2137} |
| verification levels | {'L0': 6831, 'L1': 881} |
| ecosystems | {'aptos': 11, 'cosmos': 95, 'evm': 6446, 'solana': 103, 'stacks': 4, 'sui': 5, 'ton': 4, 'unknown': 1044} |
| languages | {'clarity': 4, 'go': 28, 'move': 30, 'rust': 132, 'solidity': 6446, 'unknown': 1072} |
| splits_v3 (by source) | train 5,006, validation 354, test 107 |
| benchmark families added | ['R_v3_source_tier_routing', 'S_v3_contest_outcome'] (5,467 + 1,072 tasks) |
| v3 gate | 33/33 checks, 0 critical failures |

Full accounting, including the report-level-pointer thin spots (hard negatives: 16; per-finding
language/class extraction queued, not faked), is in
[`reports/v3/quality_report.md`](reports/v3/quality_report.md).

## Split integrity

v1 splits by repository, so one protocol's source never appears twice. v2 adds four detectors —
exact (ids, URLs, commit shas), code (identical and normalised snippets, function signatures,
`file::function`), near-duplicate (token Jaccard), and semantic (4-shingle cosine).

The detector found real leakage: the boilerplate submission *"Unsafe use of `transfer()`/
`transferFrom()` with `IERC20`"* was filed by the same submitter against two different audits.
`scripts/check_leakage.py --emit splits_v2` quarantines the redundant copy — records are set aside,
never deleted, and no repository is ever relocated.

```
train       415      validation   277      test       253
quarantined 0      (see splits_v2/quarantine.jsonl)
```

## Evidence semantics

Every derived field is wrapped as `{value, evidence_type, source_refs}` with `evidence_type` from
a closed vocabulary:

| type | meaning |
|---|---|
| `observed_fact` | read out of a retrieved artefact |
| `reported_claim` | stated by an identifiable external source |
| `derived_fact` | computed here by a rule that lives in the code |
| `experimentally_verified` | produced by actually compiling and running something |
| `externally_attributed` | attributed to a named third party (judge, sponsor, label) |
| `unverified` | asserted somewhere, not checked here |
| `unknown` | no defensible value exists |

`unknown` is a first-class, counted outcome. The gate fails if any record claims
`experimentally_verified` without a run artefact behind it, and no PoC is marked reproduced unless
forge reported `Success` for its test.

## Honest limitations

36 limitations are enumerated in
[`reports/extraction_errors.json`](reports/extraction_errors.json) and summarised in the final
quality report. The ones that matter most:

0. **Only 9 pinpoint experiments exist and
   2 of them are inconclusive.** That is the honest number.
   Each names the audited commit, the exact command and the observed assertion message; the
   failures record the specific missing symbol rather than a shrug. Widening this needs either an
   archive RPC for the fork-based proofs or a per-PoC port of the reporter's own fixtures; see
   `experiments/*/vulnerable/result.json`.
1. **Most PoCs do not execute.** 140 of 155
   were never run. The blocker is the toolchain, not Solidity: these 2022–2025 repositories pin
   hardhat 2.x with peer ranges modern npm rejects, and fork-based PoCs need an archive RPC key
   that is not distributed. Set `VLUN_RPC_URL` to an archive endpoint and re-run
   `scripts/verify_pocs.py` — that is the highest-value action available downstream.
2. **441 of 458 negatives have no
   defensible rejection reason.** Code4rena's judging rationale is largely not public. Those
   records say `rejection_basis: label_only` and leave `blocking_condition` as `unknown` rather than
   inventing a plausible one.
3. **432 of 722 records have an
   `unknown` attacker identity**, mostly negatives that cite no code at all.
4. **43 of
   204 confirmed High/Medium findings have a
   counterexample** — most findings cite only the vulnerable function, so there is no neighbouring
   function to build a false hypothesis about.
5. **424
    records contain source text whose repository declares no licence.** This is disclosed, not
    resolved: the text is here, it is flagged per record in `redistribution.flag`, and
    `scripts/audit_third_party.py` re-measures the count from the text itself
    (`reports/third_party_audit.json`). **A downstream redistributor must decide for themselves
    whether their use is lawful.** See `LICENSE` part 3.
6. **473 citations in the read-only `jsonl/` layer used a branch name**
    (`main`) instead of a commit, so those line ranges were not reproducible over time. All
    473 of them are now pinned to an exact
    commit **in the data** by content identity, submodule pointer or date-anchored blob identity.
    No SHA was invented: where no identity test succeeded the citation stays mutable and is counted,
    and the count in the shipped derived layer is **0**. The `jsonl/` layer is
    the v1 evidence record and is never rewritten, so its 473 stay and are
    reported by the gate as a counted, non-fatal warning.
7. **No invariant was invented.** `invariants: []` for 35
    of 264 records is the intended outcome.
8. **7 of 38 patches are
   experimentally confirmed effective; 31 are `not_testable` because no experiment ran both of their revisions
   effective.** A merged PR is not evidence; only running the PoC against both revisions is.

**Some** source that must not be redistributed has been withheld from this repository: for those
citations the text is absent and the citation survives — path, commit, line range, URL, sha256 — so
`scripts/fetch_sources.py` retrieves it locally and its structure can be analysed without copying
text out. **Withholding was partial, not complete.**
424
records still carry verbatim source text from repositories that declare no licence. Each says so in
`redistribution.flag`, and `LICENSE` part 3 sets out exactly what that does and does not license. No
permission has been obtained from the upstream protocol authors, and this dataset cannot grant it.

## Pipeline

The pipeline core is **standard-library only** — see `requirements.txt` and `pyproject.toml`. `git`,
`forge` and `node` are needed for the experiment stages; `slither` is optional and its absence is
recorded rather than hidden.

```bash
python scripts/build_all.py --with-network   # everything
```

or stage by stage:

```bash
python scripts/fetch_sources.py              # clone + retrieve every pinned citation
python scripts/verify_pocs.py                 # compile and run the PoCs
python scripts/verify_patches.py              # vulnerable vs fixed revisions
python scripts/resolve_citations.py           # mutable branch refs -> exact commits
python scripts/run_verified_experiments.py    # exploit experiments, both revisions
python scripts/run_negative_experiments.py    # attempt each hard negative's attack
python scripts/verify_patches.py              # vulnerable vs fixed, plus the delta
python scripts/classify_negatives.py          # four-class negative taxonomy
python scripts/build_reproduction.py          # PoC classes, L-levels, replay manifest
python scripts/run_static_analysis.py         # Slither where the repo builds
python scripts/audit_third_party.py           # measure + disclose redistributed source
python scripts/export_run_artefacts.py        # commit executed-PoC run records
python scripts/build_derived.py               # evidence, attacker model, state transition
python scripts/build_hard_negatives.py        # structured rejection reasons
python scripts/build_counterexamples.py
python scripts/check_leakage.py --emit splits_v2
python scripts/build_benchmark.py             # task families A-J (v1 layer)
python scripts/build_benchmark_v22.py         # task families K-Q (derived_v2_2 + splits_v2_2)
python scripts/build_subsets.py               # datasets/ and training/
python scripts/generate_stats.py              # the only source of statistics
python scripts/generate_reports.py
python scripts/generate_v21_reports.py        # the v2.1 BEFORE/AFTER report
python scripts/generate_v22_reports.py        # reports/v2_2/: five-language layer report
python scripts/build_v3.py                    # v3 layer: 18 clones -> jsonl_v3/derived_v3/splits_v3 + families R-S
python scripts/validate_v3.py                 # the v3 gate; non-zero on failure
python scripts/validate.py                    # the gate; non-zero on failure
```

Every script is idempotent, takes `--help`, and writes only under `derived/`, `derived_v2_2/`,
`derived_v3/`, `splits_v2/`, `splits_v2_2/`, `splits_v3/`, `benchmark/`, `reports/`, `reports/v3/`,
`experiments/`, `experiments_v2_2/` or `work/`. `jsonl/`, `jsonl_ml/` and `jsonl_v3/` are read-only.

**`build_all.py` exits non-zero if any stage fails or if the gate fails.** It used to exit 0 with
two stages failing, which is how a broken build ships as a green pipeline. Stages that cannot run
for want of network report `skipped_no_network` and the summary says so; a skip is not a pass.

**The pipeline is not self-contained.** Several stages need network access, and the experiment
stages additionally read clones and retrieved source out of `work/`, which is git-ignored. A fresh
clone therefore reproduces the JSONL layers, the derived layer and the statistics, but **not** the
experiment-derived fields: without `work/poc_runs` the `verification` block of a record degrades to
`unknown` and the benchmark loses its experimentally grounded families. That is stated rather than
hidden, and `reports/run_artefacts_index.json` commits the verdicts so the counts remain checkable
without `work/`.

## Repositories

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

Source for every citation was retrieved at the pinned commit
(321 of 326 files,
sha256 recorded). Licence class per repository is in `derived/records.jsonl`
(`license_classification`), and redistribution status per record is in `redistribution.flag`.

## Licensing

**This dataset does not redistribute only code whose licence permits it.** Stating that plainly is
the purpose of this section.

* `LICENSE` splits the terms three ways: the data under `jsonl/`, `derived/`, `splits*/`,
  `benchmark/`, `datasets/`, `training/`, `reports/` is **CC BY 4.0**; the pipeline under
  `scripts/` is **MIT**; and third-party source is **not licensed here at all**.
* **424 of
  722 records still carry verbatim Solidity quoted from a repository
  that declares no licence.** Each is flagged in `redistribution.flag`, and
  `scripts/audit_third_party.py` re-derives the count from the text itself rather than trusting
  the dataset's own classifier (`reports/third_party_audit.json`). Quotation for research is a
  different question from redistribution; that question belongs to you, and this dataset cannot
  answer it.
* **390 records contain Solidity
  source text; 696 citation entries exceed
  200 characters.** Nothing here is paraphrased.
* Withholding was **partial**. Where a citation was withheld, the text is absent and the citation
  survives — path, commit, line range, URL, sha256 — so
  `scripts/fetch_sources.py` retrieves it locally and its structure can be analysed without
  copying text out.
* PoC code in `jsonl/exploits.jsonl` belongs to the Code4rena submission authors. It is reproduced
  as quoted evidence with its original SPDX identifier preserved where the author supplied one, and
  **no** licence is applied by us.
* Harness code the authors wrote for `experiments/` is their own work under
  `SPDX-License-Identifier: BUSL-1.1` — source-available, not open source, and not
  covered by the MIT grant.
* **No permission has been obtained from the upstream protocol authors.**

If you need a clean dataset for redistribution or commercial training, use the withheld records, or
run `scripts/fetch_sources.py` and pull the sources yourself under your own compliance process.

## Attribution

Findings, verdicts and PoC code belong to their original authors: Code4rena and the
competitive-audit participants. See [`NOTICE.md`](NOTICE.md).

# VLUN ΓÇö Improvement & Remediation Plan

**Date:** 2026-10-27
**Inputs:** `VLUN-DEEP-RESEARCH-2026-10-26.md` (six-agent audit) and `vlun-data_audit_report.pdf` (Z.ai Security Research, 15 pp). Both audit commit `6933f3f`.
**Working tree:** `C:\Users\REDACTED\Downloads\vlun-data-main\vlun-data-main` at `6933f3f3f1a6d9270f405bf317d3d6d6de8fc7ee`, 1,822 tracked files, 53 gates, 718 unit tests.
**Status:** plan only. No repository file was modified. The two pre-existing uncommitted report edits are still in place, untouched.

Scope note: the two audits overlap but do not agree everywhere. This plan merges them into one defect register, resolves their numeric disagreements by re-measurement, and adds findings from this session. Where a figure below is not attributed to an audit, I re-measured it today.

---

## 0. Executive summary

The repository's **measurement honesty is its strongest asset and is verifiable**: row counts recompute, gates pass, skips name their missing inputs, two-revision experiments are byte-checked, and the project publicly retracts its own inflated numbers. Almost every remaining defect is therefore a **truth-maintenance** defect ΓÇö a claim, denominator, field, or gate that no longer matches the bytes ΓÇö not a fabrication problem.

Two structural limits cannot be engineered away:

1. **The only PRIMARY benchmark family has contradictory gold** (14 identical-input groups, 306 rows at full-input granularity). This plan's re-measurement shows the root cause is narrower than "gold is wrong": the model-visible input omits the claim being adjudicated, and 319 of 422 negatives are *duplicate* submissions. Adding the claim to the input removes all 14 contradictions **without changing a single label or floor** ΓÇö but it changes what family A measures (claim adjudication, not bare code detection), so it needs sign-off.
2. **Depth is thin**: four supervision fields are 0.0% on the two largest layers, executed evidence covers ~0.9% of admitted records, and the only private evaluation has 6 executed tasks against a ~200 target. Depth is gated on human annotation, a funded archive RPC endpoint, and rights clearance ΓÇö not on code.

Everything else is fixable now. The plan front-loads the fixes that make every other claim defensible (gate semantics, doc truth, denominators, rights measurement) and defers the work that needs external inputs.

**Recommended first commit (P0):** gate-integrity fixes + documentation truth sweep + the live CRLF repair. It is small, testable, and removes the class of defect that an external auditor checks first.

---

## 1. Verified baseline ΓÇö do not re-litigate

These were independently reproduced by at least one audit on a fresh clone, and several by me today. They are not defects; changing them is regression risk.

| Property | Evidence |
|---|---|
| Model counts | v1 722 ┬╖ v2.2 137 ┬╖ v3 5,467/7,712 ┬╖ Vbeta 6,935/7,060 ┬╖ V4 5,268 ┬╖ preview 12,504 ΓÇö all recompute exactly |
| Gate matrix | 41ΓÇô43 PASS, 0 FAIL, 9 environment skips (each names its missing git-ignored input) |
| Unit suite | 718 tests, 0 failures, 18ΓÇô19 skips; 468 audit-critical re-run clean |
| CI | GitHub Actions `gates.yml` runs `run_gates` + `check_reproducibility` on Python 3.10ΓÇô3.13, ubuntu; runs #38ΓÇô#40 green |
| Two-sided patches | 5 effective (reNFT H-01/H-03/H-04/M-09/M-11); M-11 verified end-to-end from committed bytes, byte-identical harness both sides |
| Release boundary | `RELEASE_MANIFEST.json` classifies all 1,822 paths; 475 released / 1,347 not; `legal_clearance_claimed: false` |
| Determinism | `generate_stats.py`, `build_repro_report.py` byte-identical; CI proved deterministic build on four Python versions |
| Exact-input leakage | **New today:** 0 of 384 family-A code bundles span splits |
| Id duplicates | 0 exact-id duplicates in all 10 record files |

**Numeric disagreements between the two audits, and the resolution:**

| Question | Deep research | PDF | Resolution |
|---|---|---|---|
| V4 impact TOC corruption | 1,779/5,268 = 33.8% (regex lower bound) | 2,741/5,268 = 52.0% (wider predicate); ledger structural count 1,971 | All three are different predicates over the same defect. Publish all three with their predicates; gate on the **widest** one. |
| Family A conflict size | 306 rows (full-input hash) | 330 rows (code-payload hash) | Same 14 groups. **Re-measured today: 14 groups, 306 rows at full-input.** Report both granularities. |
| Skip handling | 1 skipΓåÆPASS path | 9 honest skips | Both true: 9 gates exit 2 correctly, and `build_prove_ledger.py --check` exits 0 after printing a skip. |
| Quarantine size | 2 rows | README says 63 | **Confirmed today: 2 rows.** 63 is `Vbeta/splits_vbeta/quarantine.jsonl`. |
| Tests run | 718 | 468 re-run | 718 exist; 468 audit-critical re-run. No contradiction. |

---

## 2. New findings from this session

These are not in either document. They change the cost and the fix design of the top item.

### N1 ΓÇö Family A's contradiction is an input-schema bug, and the fix is label-neutral
Measured on `benchmark/A_vulnerability_detection.jsonl` (720 rows):

- 384 distinct full-input objects; 14 groups carry conflicting labels; **306 rows** affected.
- Of 422 negatives, **319 are `finding.status == "duplicate"`** ΓÇö e.g. `2024-04-noya/submission-1382` is a duplicate of confirmed `H-07`, with a different claim title.
- Keying the input on `(code, claim title)` yields **717 distinct inputs and 0 conflicted groups**. Every row keeps its current label; majority 526/720 = 0.7306 and test floor 81/147 = 0.5510 are unchanged.

So the contract's own remedy ("an explicit claim dimension or a set-valued answer", `docs/TASK_CONTRACTS.md:38-44`) is implementable mechanically. The cost is semantic: family A stops being bare code detection and becomes *claim adjudication* ΓÇö "was this specific claim accepted as a confirmed vulnerability?" That is what the labels actually encode, and the prompt must say so.

Two QA rows (`2024-01-renft/L-06`, `2024-01-decent/L-03`) carry `status: confirmed` but a negative label because `record_class: qa`. Not a mislabel, but a consumer trap: the `source` pointer should carry `record_class` so the rule is visible.

### N2 ΓÇö V4 cannot be re-extracted in this checkout
`V4/` tracks only `licensing.json`, `manifest.json`, `sources.json`. The PDF corpus that `scripts/extract_cloned_findings.py` reads is git-ignored. A "repair via re-extraction" plan is therefore not executable offline; the only honest fix is a versioned correction overlay plus a future-extraction filter with a fixture test.

### N3 ΓÇö Twelve tracked files are CRLF in the worktree right now
`git ls-files --eol | grep w/crlf` returns 12: `.gitattributes`, `Vbeta/reports_vbeta/quality_report.md`, 4 ├ù `experiments_v2_2/`, 1 ├ù `experiments_v3/`, `scripts/build_prove_ledger.py`, `scripts/check_eval_leakage.py`, `scripts/build_eval_leakage_report.py`, `tests/test_eval_leakage.py`, `tests/test_independent_benchmark.py`. This is the same class of failure that turned CI red on `a28170d`. Local-green with CRLF is not CI-green.

### N4 ΓÇö README:451 repeats the quarantine error twice
`README.md:451` says "next `--emit` would replace the 63-row `splits_v2/quarantine.jsonl` with an empty file". The file has **2** rows, and `--emit` *does* replace it (defect E-5), it is not a future hypothetical.

### N5 ΓÇö The stale-report adjudication is already resolved by evidence in the tree
`reports/validation_report.json` reports 78/78 checks ok, 0 critical, and its `derived_commit_pins_are_immutable` check states 2034/2034 pinned. The three `validation_failure` entries in `reports/extraction_errors.json` claiming 473/471/474 failures are therefore stale. The uncommitted regeneration in the tree (39 ΓåÆ 36 entries) is directionally correct, but deleting them without a recorded resolution violates the file's own contract ("nothing is marked resolved unless a check proves it").

---

## 3. Defect register

Severity: **S1** blocks a headline claim ┬╖ **S2** materially degrades it ┬╖ **S3** degrades conditionally. "Effort" is developer-days; agent parallelism reduces wall-clock, not effort.

### WS1 ΓÇö Gate integrity & reproducibility (S1)
*Nothing else is credible until a green gate means green.*

| ID | Defect | Evidence | Fix | Acceptance |
|---|---|---|---|---|
| G1 | Skip rendered as PASS | `scripts/build_prove_ledger.py:528-530` returns 0 after `skipped_no_local_inputs`; `run_gates.py` maps only exit 2 to SKIPPED (`SKIPPED_CODES={2}`, lines 184, 218-221) | Return 2 when `--check` inputs are absent; sweep every `--check` script with `grep -rn "skipped_"` | New `tests/test_gate_exit_codes.py`; fresh-clone `run_gates` shows SKIPPED, not PASS |
| G2 | No freshness gate on `generate_reports.py`; stale report contradicts live gate | Regeneration drops 3 `still_true:true` validation failures (473/471/474) while `validation_report.json` is green; no argparse, no `--check`, no gate | Add argparse + `--check` (regenerate to temp, byte-compare); record the 3 resolutions in `resolved_entries` with `reason`, `evidence`, `resolved_by`; wire the gate | `generate_reports.py --check` exits 0 on committed state, 1 on drift, 2 on missing inputs; CI runs it |
| G3 | `--emit` destroys published quarantine | `scripts/check_leakage.py --emit splits_v2` rewrites `splits_v2/quarantine.jsonl` to empty (d2f25d75 ΓåÆ e3b0c442), rc=0; guard exists only in `build_all.py` | Fail-closed inside `check_leakage.py`: refuse empty/shrinking rewrite unless explicit override; override must still be a superset | `tests/test_leakage_guard.py`: empty refused, superset allowed, no-op allowed |
| G4 | Gate passes while dirtying the clone | `Vbeta/scripts/build_vbeta.py:451` `write_text` lacks `newline="\n"`; `check_line_endings.py` reads index blobs only | Add newline; make the line-endings gate fail on line-ending-only worktree divergence | Running `check_reproducibility.py` on Windows leaves `git status` empty; `run_gates --only line-endings` fails on the defect |
| G5 | Live CRLF set (N3) | 12 tracked files `w/crlf` today | Normalize on an LF worktree; add `git ls-files --eol` assertion to CI | Zero `w/crlf`; CI step fails if any appear |
| G6 | Field with no writer | `reports/citation_resolution.json.remaining_mutable_in_source_layer` is permanently `null`; comment says "filled by validate.py"; no writer | Implement the measurement in the producer (preferred) or delete field + comment | Field is either populated and gate-checked, or absent |
| G7 | Gate coverage | Only 50 of 124 script files referenced by `run_gates.py`; no artefact upload | Register the new gates; add `--only` alias for CI shards; upload gate JSON as CI artefact | New gates in CI; run log retrievable |

**Effort:** 2ΓÇô3 days. **Parallelizable:** yes, with `run_gates.py` as single-writer (integration owner).

### WS2 ΓÇö Documentation truth (S1)
*All eight are measured false statements, not opinions.*

| ID | False claim | Location | Correction |
|---|---|---|---|
| D1 | "63-row `splits_v2/quarantine.jsonl`" | `scripts/generate_readme.py` (~L1151), README (~L451) | 2 rows; 63 is `Vbeta/splits_vbeta/quarantine.jsonl`; restate `--emit` as a live hazard, not a hypothetical |
| D2 | Secondary-holdout key is tracked/committed | `docs/RUBRIC.md` ~L92-95, ~L285; `reports/independent_benchmark_evaluation.md` ~L437-439; README ~L234-236 | State `withheld_from_repository: true`; copy the honest wording from `docs/EVIDENCE_LEDGER.md` |
| D3 | Two density denominators | README "5/722 ┬╖ 2/5,467" vs `reports/depth_dashboard.md` "5/264 ┬╖ 0/5,467" | One convention, stated; regenerate both from the same source |
| D4 | Tests listed as CC BY 4.0 | README ~L289-291 vs `LICENSE` part 2 + manifest (tests = MIT, 149 paths) | Align to LICENSE + manifest |
| D5 | "V3 keeps link + sha256 + attributed facts only" | README ~L302 | State layer policy + measured reality: 0 rows contain `sha256`, 2,155/7,712 (28%) carry neither link nor hash |
| D6 | "every derived field carries `{value,evidence_type,source_refs}`" | README | 2,637/9,290 (28.4%) v1 value-dicts lack `source_refs`; no value-dicts in v3/Vbeta/v4 |
| D7 | Continuity denominator wording | RUBRIC + evaluation report | State the denominator rule the scorer will implement (WS3); do not change the number here |
| D8 | "a skip is never reported as a pass" | README ~L340 | Keep (it becomes true after G1) but add the explicit exit-code contract: 0 pass / 1 fail / 2 skipped-with-reason |

**Effort:** 1ΓÇô2 days (README is generated ΓÇö edit the generator, never the output). **Parallelizable:** yes.

### WS3 ΓÇö Benchmark statistics (S1)
*Every published baseline difference is currently statistically indistinguishable.*

| ID | Defect | Evidence | Fix | Acceptance |
|---|---|---|---|---|
| S1 | Continuity denominator mismatch | `scripts/score_benchmark.py :: micro_block()` ~L320-369 divides by evaluable-family rows (21,889) while printing coverage over all families (22,134/22,145); README rule reads 0.8702, published 0.8687; first row prints 1.0000 = 71/71 "@71/22,145" | Denominator equals the basis printed in the same row; never mix coverage with accuracy | Per-row regression assertion: denominator used == denominator displayed |
| S2 | No confidence intervals | 0 headline metrics carry a CI | Wilson two-sided 95% for every proportion, pure Python | 81/147 ΓåÆ Γëê[0.470, 0.629]; every row carries `[lo, hi]` |
| S3 | Row-iid statistics anti-conservative | 147 test rows collapse to 28 unique inputs (design effect 16.1) | Input-cluster bootstrap, 10k, seed 0; publish effective n beside every family-A metric | Both row-level and cluster-level intervals printed and labelled |
| S4 | Difference claims without tests | majority vs random p=0.71; vs frequency p=0.31 | Exact McNemar per baseline pair, or delete the "differ" claims | Per-pair p-value + `significantly_different` boolean |
| S5 | No lift over dummy | ΓÇö | Balanced accuracy and MCC beside raw accuracy; explicit lift = acc ΓêÆ majority acc | Emitted per baseline |
| S6 | No code/prose stratification reported | 121/147 test rows have no code | Report code-present vs code-absent strata separately (the contract already promises this) | Two rows per metric, never mixed |

**Must not move:** 526/720 = 0.7306; 81/147 = 0.5510; random 0.4361; retrieval 0.2925; all family task/scorable counts. If a change moves one, the change is wrong.

**Effort:** 2ΓÇô3 days. **Parallelizable:** yes (scoring scripts only).

### WS4 ΓÇö Family A keystone (S1, needs sign-off)
*Blocks every evaluation claim the project could make.*

| ID | Defect | Fix (recommended) | Acceptance |
|---|---|---|---|
| A1 | 14 groups of identical inputs carry conflicting gold; 306 rows | Add `input.claim = {title, severity, record_class}`; prompt becomes "was this specific claim accepted as a confirmed vulnerability?"; `answer_key_basis` records per-status basis (duplicate-of, rejected, disputed, acknowledged QA); rebuild via `build_benchmark.py` | 0 conflicted groups at `(code, claim)` granularity; regression test fails on any identical `(code, claim)` with differing labels |
| A2 | QA rows look contradictory | Put `record_class` in the source pointer / basis so `status: confirmed` + negative label is legible | No row where `answer_key_basis` is silent about `record_class` |
| A3 | Test set is mostly prose | Keep as a documented stratum; report it as one (S6) | Stratified metrics published |

**Label impact:** none. **Floor impact:** none. **Semantic impact:** family A is redefined as claim-conditioned; `docs/TASK_CONTRACTS.md`, `docs/RUBRIC.md`, README, and the family description must say so, and the kind taxonomy must be updated (A and B both become claim-conditioned; A remains binary, B remains taxonomy-class).

**Rejected alternatives** (keep in the ledger as considered-and-rejected):
- *Code-level relabel* (duplicates ΓåÆ vulnerable): makes the test split 145/147 positive; majority floor rises to ~0.986; family loses discriminative value.
- *Drop ambiguous rows*: family falls to ~401 rows and test to ~68 (66 positive / 2 negative); same collapse.
- *Retire family A*: leaves the project with no PRIMARY family at all.

**Effort:** 1ΓÇô2 days + one full regeneration cycle.

### WS5 ΓÇö V4 extraction repair (S2)
*No local sources (N2), so repair = correction overlay + future-extractor fix.*

| ID | Defect | Fix | Acceptance |
|---|---|---|---|
| V1 | TOC text in `impact` (1,971 structural ┬╖ 1,779 regex ┬╖ 2,741 wide) | Detect TOC contamination with **three published predicates**; set the value to `null` with `extraction_error: toc_contamination` + source pointer ΓÇö never invent replacement text; emit a versioned `derived_v4/corrections.jsonl` | Widest-predicate TOC rate < 1% in the admitted layer; corrections are additive and versioned |
| V2 | Same corruption in `suggested_fix` (503) and `raw_body_excerpt` (1,874) | Same treatment | Counts published before/after |
| V3 | Extractor will re-introduce it | TOC/heading filter in `scripts/extract_cloned_findings.py` + fixture test (contents page vs finding body) | Fixture test fails on the old behaviour, passes on the new |
| V4 | 59 emails in 481 withheld rows | Email-scan gate; redact in any export (they are already not-released) | Gate reports 0 in released paths |
| V5 | Field-level correctness never measured | Add `--measure` mode reporting per-field contamination rates against a small risk-based sample | Report published with denominators |

**Effort:** 2ΓÇô3 days. `derived_v4` is a derived layer; check the canonical-layer guard before writing.

### WS6 ΓÇö Rights & release (S1/S2)

| ID | Defect | Evidence | Fix | Acceptance |
|---|---|---|---|---|
| R1 | Detector under-measures | `UPSTREAM_KEYS` whitelist omits `excerpt`/`claimed_impact`/`value`; `PROJECT_TEXT_PREFIXES=("scripts/","docs/")` subtracts those trees; 5 released `project_own` files carry verbatim runs while `measure()` = 0 | Measure every leaf; stop subtracting `scripts/`+`docs/`; enforce Γëñ199-char quota on all released paths; `path_status_detail` for all 1,822 paths (currently 159) | Seeded fixture with a >95-char unattributed run fails the gate; independent 10-word scan finds 0 in released paths |
| R2 | 2,288/12,358 withheld pointers lack an upstream hash | recorded, non-failing | Fail above a justified threshold, or drive to zero | Gate exit code reflects the count |
| R3 | ToB licence wrong | `Vbeta/sources.json`: `license unknown`; upstream is CC-BY-SA-4.0 | Correct + record the share-alike obligation | Evidence field cites the LICENSE |
| R4 | No legally clean full-value export | `derived_meta/` (improve.md Phase 7.1) absent; `distribution_v1` excludes canonical material | Build `derived_meta/`: snippet/PoC/explanation/diff/quote bodies replaced by null + pointer; new `PERMISSIONS.json` for all 18 sources; export guard fails if any input path is not in the released set | `derived_meta` builds; guard passes on released set, fails on one seeded unreleased path |
| R5 | `legal_clearance_claimed` | correctly `false` | Keep `false` until human sign-off | Unchanged |

**Effort:** 3ΓÇô4 days + human rights review. **Parallelizable:** detector (agent) vs `derived_meta` (agent) with `RELEASE_MANIFEST.json` single-writer.

### WS7 ΓÇö Pin hygiene & provenance (S2)

| ID | Defect | Evidence | Fix | Acceptance |
|---|---|---|---|---|
| P1 | `*_commit` fields accept non-pins | jsonl_v3 21 short SHAs / 99.4% unknown; jsonl_v4 269 short; derived_v3 47,877 unresolvable; `derived/counterexamples.jsonl` 47 branch literals in `commit_sha`; Vbeta 0 pinned; 1,522 branch/tag vs 884 pinned URLs | New `scripts/check_pin_hygiene.py`: value is `"unknown"` or 40-hex; classify short/branch/malformed; checked-in baseline so only NEW violations fail; `reports/pin_hygiene.json` | Fixture test (`main`, `a72fa0e`, 40-hex, `unknown`); gate wired; deterministic output |
| P2 | No per-record pin status | ΓÇö | Derived overlay (`derived/pin_status.jsonl`) ΓÇö **do not mutate source layers** | Overlay covers declared layers; canonical guard still passes |
| P3 | Link rot | 5 dead repos + 1 archived; 22 two-revision rows unrecoverable | `scripts/check_link_rot.py` + `scripts/deposit_swh.py`; `swh:1:rev:` ids; per-record `source_availability`; weekly scheduled CI | Fixture-tested offline; live run reports 0 unremediated dead-repo rows |
| P4 | Hash mismatches | 3/58 reproduction manifest, 4/67 artefact hashes, all allowlisted | Disclose in `verified_experiments.json`, not only in the script constant; re-derive where possible | Every allowlist entry has a public reason |
| P5 | Verdict contradicts report | `2024-01-renft/H-01`: `verdict=not_executed` vs `verified_experiments.json` executed | Reconcile in a gate; one owner ruling recorded | No record where the two disagree |

**Effort:** 3ΓÇô4 days (P3 network-gated). **Parallelizable:** P1/P2 offline; P3 network.

### WS8 ΓÇö Executable grounding (S2/S3)

| ID | Defect | Fix | Acceptance |
|---|---|---|---|
| X1 | Clean checkout crashes | `run_verified_experiments.py:785` `NotADirectoryError` on missing `work/wt/renft-smart`; no README prerequisite | Actionable error + prerequisite doc + OPEN ledger entry (E-4 covers only `tests/test_prove_split.py`) | New-clone run prints the exact `git clone` command and exits non-zero, not a traceback |
| X2 | 6/11 qualified rows have no committed evidence | 3 OpenZeppelin + 2 re-nft + 1 Tapioca point at git-ignored `work/prove_runs/` | **Downgrade** those rows to `evidence_absent` (honest, cheap, rights-safe) or commit artefacts; add test that `qualified` ΓçÆ tracked artefacts | `qualified` rows with tracked evidence = 11/11, or the stage count changes to match reality |
| X3 | No toolchain pinning | Per experiment: `solc`, `evm_version`, `optimizer*`, `via_ir`, `auto_detect_solc=false`, foundry/hardhat version | `toolchain.json` per experiment + schema + gate | Every experiment dir has one; schema-validated |
| X4 | Byte-identity requirement undocumented | 1inch case needs an adapted harness | `harness_identity: identical|adapted` recorded per experiment | Field present on every two-revision experiment |
| X5 | No containerization | ΓÇö | Dockerfile + `repro` script for reNFT + 1inch harnesses (SEC-bench norm) | `docker build && ./repro` reproduces the committed stdout |
| X6 | Answer-key commitment unverifiable | Published commitment 16,068 B / `c1d94f34ΓÇª`; builder produces 9,048 B / `c0a8f60eΓÇª`; `grader_self_check.json` regenerates identical | Write the failing test first (commitment == rebuild); key holder decides which tree is authoritative | Test exists and passes, or the commitment is withdrawn |

**Effort:** 3ΓÇô5 days + compute/network for X5. **X6 is blocked on a decision, not code.**

### WS9 ΓÇö Benchmark data hygiene (S2)

| ID | Defect | Fix | Acceptance |
|---|---|---|---|
| B1 | Near-duplicate leakage in shipped families | E: 185/376 (49.2%) at 5-gram Jaccard ΓëÑ0.9; T: 2/2 (100%); A clean (max 0.765) | Quarantine or document per family with a measured predicate and a published count | No family shipped as "clean" without a printed max-similarity figure |
| B2 | `record_id_overlap` false positive on U/V | all rows `source: null` ΓåÆ empty-string "overlap" | Treat null as missing, not as equal | Flag gone; true overlap still detected (fixture) |
| B3 | Secondary holdout reuses 56.9% of test inputs | `group_disjoint_verified` true by construction | Reframe the claim: report reuse rate; stop calling it independent | Manifest states the reuse percentage |
| B4 | Family R compositionally broken | `held_out_labels_unseen_in_train`, `split_composition_drift`; 878 tier-0 test rows | Re-split by source ├ù tier, or retire R with a published mechanism | Flags clear, or status = retired with reason |
| B5 | Vbeta 82% test partition | 5,668/6,935 | Justify explicitly or rebalance | Documented rationale with the number |
| B6 | Source/language concentration unreported | v3 100% Solidity, 64.3% one source; Vbeta 87.4% Solidity, 74.6% one source; non-Solidity 19ΓÇô55 records each | Per-source and per-language breakdown as first-class headline stats; admission quotas for new data | README headline carries the concentration figures |
| B7 | OPEN-KEY by construction | every family ships `answer_key` in-row | Cannot be fixed for existing families; publish a de-contamination protocol; grow VLUN-Prove (X-side) | Protocol doc; Prove task count tracked |

**Effort:** 3ΓÇô4 days. **Parallelizable:** yes, but any family rebuild must precede the final regeneration.

### WS10 ΓÇö Reasoning depth (S2, mostly external)

| ID | Defect | Fix | Acceptance |
|---|---|---|---|
| C1 | root_cause/attack_sequence/impact/fix = 0.0% on 12,402 v3+Vbeta records | Span-linked annotation: `{value, evidence_type, source_refs, span}`; `unknown` stays a counted outcome; no inference without a verbatim quote; start from 40 verbatim candidates in `derived/root_cause_candidates.jsonl` | Coverage report shows root_cause known > 0 for V3 with 100% span-linked evidence |
| C2 | Enrichment drops fields | `derived/` drops root_cause (5 in raw); `derived_v2_2/` drops root_cause/summary (40 in raw) | Carry-through fix + regression test | No field present in raw and absent in derived without a recorded reason |
| C3 | Hollow training files | `attacker_reasoning.jsonl` 45/45 null output; `exploit_reasoning.jsonl` and `patch_reasoning.jsonl` 0 rows; `negative_reasoning.jsonl` reason null in 96/96 | Populate or delete; never ship a file that is 100% null | No training file is 100% null |
| C4 | IAA never measured | `annotation/iaa_v1/responses/` empty; `iaa_status.json` measured=false | Execute the frozen blinded protocol (n=300) with two qualified reviewers | kappa + Krippendorff alpha with intervals |

**Effort:** 2ΓÇô4 weeks + annotator hours + reviewers (external).

---

## 4. Execution waves

Constraints that shape the sequencing (from the repository's own operating rules):

- **One writer per shared artifact.** Generated reports are byte-compared by gates; parallel writers create false drift.
- **Never run two suites/gates against this tree at once.** `check_reproducibility.py` replays the derived layer in place behind `work/.repro_replay.lock`; two overlapping replays previously deleted `derived/records.jsonl`.
- **Generate every byte-hashed artifact on an LF worktree.** `git ls-files --eol` must show no `w/crlf` before any regeneration.
- **Validate on a fresh clone before pushing.** Local-green with CRLF has already produced a red CI.
- **Fixed-point regeneration order:** `validate_v31 ΓåÆ build_repro_report ΓåÆ build_remediation_report ΓåÆ generate_readme ΓåÆ build_datasheet ΓåÆ inventory_rights ΓåÆ validate_vbeta --resnapshot ΓåÆ build_quarantine_report ΓåÆ build_json_catalog (last)`; for benchmark changes insert `build_benchmark ΓåÆ independent_benchmark_audit ΓåÆ holdout ΓåÆ baselines ΓåÆ metrics ΓåÆ eval leakage` before `generate_readme`, and regenerate `RELEASE_MANIFEST.json` **after** all content changes (it hashes every path).

| Wave | Contents | Owners (parallel) | Wall-clock | Exit criteria |
|---|---|---|---|---|
| **0 ΓÇö Decisions** | Sign off WS4 approach; confirm push authority; confirm rights/IAA/RPC are out of scope | you | 30 min | Written decision recorded in `docs/EVIDENCE_LEDGER.md` |
| **1 ΓÇö Truth & gates (P0)** | WS1 (G1ΓÇôG7), WS2 (D1ΓÇôD8) | 2 agents; `run_gates.py` single-writer = integrator | 1ΓÇô2 days | Fresh-clone `run_gates` shows SKIPPED not PASS; `generate_reports --check` green in CI; 8 false phrases gone; 0 `w/crlf` |
| **2 ΓÇö Numbers & keystone (P0/P1)** | WS3 (S1ΓÇôS6), WS4 (A1ΓÇôA3), WS6 detector (R1ΓÇôR3) | 3 agents; scoring scripts / benchmark builder / rights scripts are disjoint | 1ΓÇô2 days | Every metric has a CI + effective n; 0 conflicted groups; 0 unattributed released runs |
| **3 ΓÇö Data & provenance (P1)** | WS5 (V1ΓÇôV5), WS6 `derived_meta` (R4), WS7 (P1ΓÇôP2), WS8 (X1ΓÇôX4) | 4 agents; `derived_v4`, `derived_meta`, pin overlay, experiments are disjoint | 2ΓÇô3 days | TOC < 1% admitted; `derived_meta` builds + guard passes; pin gate green vs baseline; clean-checkout error actionable |
| **4 ΓÇö Hygiene & depth (P2)** | WS9 (B1ΓÇôB7), WS5 extractor future-proofing, WS8 X5 containerization, WS10 C2ΓÇôC3 | 3 agents | 2ΓÇô3 days | Published per-family similarity + concentration stats; no 100%-null training file |
| **5 ΓÇö Integration (single writer)** | Full regeneration to fixed point, full gate suite, fresh-clone verification, commit, CI green | integrator only | 1 day | Fresh clone: all gates pass, skips honest, tree clean after gates |
| **6 ΓÇö External blockers** | Rights outreach (E-12), IAA reviewers (E-11), archive RPC (W4), Prove growth | humans | weeks | Tracked, not promised |

**Parallelization rule for agents:** each agent owns a disjoint file set; no agent runs `run_gates.py`, `check_reproducibility.py`, `build_all.py`, or the full test suite; targeted tests only; LF-only writes; report every command with its exit code. The integrator is the only writer of `run_gates.py`, `README.md`, `RELEASE_MANIFEST.json`, and the JSON catalog.

---

## 5. Decisions required from you

| # | Decision | Why it blocks | Options |
|---|---|---|---|
| **Dec-1** | Family A fix approach (WS4) | Changes what the PRIMARY family measures; every evaluation claim depends on it | **(a) claim dimension** ΓÇö labels/floors unchanged, contradictions gone, semantics become claim adjudication; (b) code-level relabel ΓÇö test set collapses to 98.6% positive; (c) drop ambiguous rows ΓÇö 68 test rows; (d) retire A |
| **Dec-2** | Prove answer key authority (X6) | Only the key holder can say which `prove_tasks_private.jsonl` is real | committed 16,068 B key vs builder's 9,048 B output |
| **Dec-3** | 3 stale `validation_failure` entries (G2) | Must be adjudicated, not silently deleted | Evidence in `validation_report.json` says stale ΓåÆ record resolution and remove |
| **Dec-4** | 6 unverifiable "qualified" Prove rows (X2) | Downgrade changes a headline count (11 ΓåÆ 5 + 6 evidence-absent) | downgrade (recommended) vs commit withheld artefacts (rights risk) |
| **Dec-5** | Push authority for the remediation branch | CI validation needs a remote run | push branch (no merge) vs local-only |
| **Dec-6** | Scope of `derived_meta` (R4) | New public export surface | build now vs document-only |

Out of code scope regardless of decision: rights clearance (OQ-001..005), IAA execution, archive RPC funding, model evaluation compute, upstream permissions.

---

## 6. Before ΓåÆ target (measured, not promised)

| Metric | Today | Target |
|---|---|---|
| Family A conflicted identical-input groups | 14 (306 rows) | 0, enforced by test |
| SkipΓåÆPASS paths in the gate runner | 1 | 0 |
| Stale-report contradictions (`still_true` vs live gate) | 3 | 0 |
| Headline metrics with 95% CI | 0 | 100% |
| Metrics reporting effective n | 0 | 100% of family-A rows |
| Tracked files CRLF in worktree | 12 | 0 |
| Released paths with unattributed verbatim runs | 5 | 0 |
| Pin-named fields with short/branch values | ΓëÑ337 (+47 branch literals) | 0 above checked-in baseline; every value classified |
| Cited repos dead without archival | 6 / 697 | 0 unremediated |
| V4 `impact` TOC rate (widest predicate) | 52.0% | < 1% |
| `derived_meta/` | absent | builds, guard-enforced |
| Prove qualified rows with tracked evidence | 5 / 11 | 11 / 11 or stage count honest |
| Records with root_cause Γêº impact Γêº fix | 43 / 20,899 (0.21%) | ΓëÑ 300, 100% span-linked, V3/Vbeta > 0 |
| Executed evidence coverage | ~168 / 18,529 (0.9%) | grows only with RPC access ΓÇö not promised |

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Data-layer edits cascade through ~40 currency gates | Change data first, regenerate in the documented order, run the full suite once, on a clean LF tree |
| Parallel agents create false drift | Disjoint ownership; single-writer integration wave; no concurrent gate runs |
| Replay deletes `derived/` | Never run two suites; keep the replay lock; back up `derived/` before wave 3 |
| Claim dimension is read as "moving the goalposts" | Publish the before/after conflict counts, the label-invariance proof, and the rejected alternatives in the ledger and CHANGELOG |
| Rights gate hardening flags many new paths | Land it with a checked-in baseline; remediate the 5 known files first; never lower the threshold to pass |
| V4 "repair" invents text | Correction overlay sets `null` + reason; no generated replacement prose, ever |
| Plan is read as a promise of scores | Targets are measured counts, not grades |

---

## 8. Explicit non-goals

- No change to published row counts, family task/scorable counts, or the five verified two-revision patches.
- No weakening of any gate. No failure converted to a skip.
- No invented labels, reasoning text, or licences.
- No legal determination: `legal_clearance_claimed` stays `false`.
- No claim that the umbrella `run_gates.py` passes until it has been run end-to-end on a fresh clone and the output is captured.
- No model evaluations: still no compute, so published numbers remain floors.

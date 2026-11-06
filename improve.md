# improve.md — path to a defensible 10/10

Target: move VLUN from its externally-reviewed **4/10 ("not vendor-ready")** to a state where every
headline number survives adversarial audit and every claim is mechanically checkable.

This document is written against commit `e79b31a` (Python 3.12, Windows, `177/177 tests OK`).
Every number below was measured on that commit, not copied from a report.

---

## 0. Read this first: what "10/10" can and cannot mean

The repo has two self-contradicting quality signals, and both are legitimate:

- `reports/reproducibility_report.md` — **374 gate checks, 0 critical failures**
- `_audit/INDEPENDENT_REVIEW.md` — **4/10, "not vendor-ready"**, 8 refuted claims

**The review is partly stale.** It was written at `93af4b9` (2026-10-04). I re-verified its claims
against HEAD and these are **already fixed** — do not spend time re-doing them:

| Review claim | Status at `e79b31a` |
|---|---|
| "mutable citations 453→0 is false — 471 `commit_sha` still equal `main`/`master`" | **FIXED.** 0 occurrences in `derived/records.jsonl`. `validate_checks.py:629-641` now counts from the records and cross-checks the resolver's report, so the circularity is gone. |
| "2 stages fail while the build still exits 0" | **FIXED.** `build_all.json` → `{"ok": 21, "skipped_no_network": 5}`, 0 failed. |
| "the 5 reproduced PoCs have zero committed artefacts" | **FIXED.** 36 committed `result.json` under `experiments/`. |
| "benchmark is unscoreable as shipped, 62% unscorable" | **FIXED.** `test_benchmark_b_g.py::TestNoFamilyIsDecorative` enforces no family has `scorable == 0`. |
| "gate checks pass vacuously on a fresh clone" | **FIXED.** `run_gates.py:154-164` fails when `npass == 0`. |
| "artefact hash drift (27 values)" | **FIXED.** `v32_provenance_closure.md` + `tests/test_artefact_hashes.py` (8 tests). |

**The ceiling is not 10/10 by default.** Two workstreams are blocked on things an agent cannot do —
a funded Ethereum *archive* RPC key, and outbound email to upstream authors for licence clearance
(`Vbeta/reports_vbeta/licence_clearance_popoc_checklist.md` says so explicitly). Phases 7 and 9 are
therefore written as *"remove our own exposure / unblock the path"*, not *"obtain permission"*.
Without those two human actions the honest score is **~8.5/10**, and the plan says so rather than
claiming otherwise.

**Governing principle stays unchanged.** `TRUTH > COMPLETENESS > SCALE > METRICS`. Every task below
must make the dataset *more honest*, never merely larger.

---

## 0b. Status at `aa82ac1` (2026-11-06)

Marked from the repository, not from intent. "Done" means the deliverable exists **and** a gate or
test enforces it; "partial" names exactly what is missing.

| Phase | Status | Evidence in the tree | Missing |
|---|---|---|---|
| 0 baseline | **DONE** | `BASELINE.md`; ordered-list row 1 `FIXED in c6b45df` | — |
| 1 evidence pointers | **PARTIAL** | `every_fact_field_has_a_pointer` gate (critical, closed 29 v2.2 leaks at `aa82ac1`); `claim()` helper in `vlun_io.py`/`vlun_ml.py` | 1.2 not done: **0 of 722** derived records carry a `rule:` source_ref, so `rule-derived` refs are still unpopulated; 3-bucket classification absent |
| 2 immutable permalinks | **DONE** | `derived_commit_pins_are_immutable` gate (`validate_checks.py:235`); row 5 `FIXED in 8abe43f` | — |
| 3 benchmark rebuild | **PARTIAL** | 3.1/3.2 done: 10 families retired (`B,E,K,L,M,N,O,P,v3_S,v3_T`), 19 live; class-disjoint holdout shipped (`benchmark/independent/…`, 2,684 tasks) and documented as OPEN-KEY in `docs/RUBRIC.md`; baselines rebuilt | 3.3 `split_degenerate` is a comment in `build_v3.py:103`, not a gate; 3.4 holdout is a *second, stricter* protocol, not the primary metric; 3.5 shortcut≥0.95 gate not found in `validate_checks.py` (only `benchmark_status.py` saturation reporting) |
| 4 empty fields | **PENDING** | — | `root_cause` / `fix_description` extraction over v3 + Vbeta; no-invention gate |
| 5 code-grounded negatives | **BLOCKED** | `run_negative_experiments.py:163` needs RPC | item 24 (human) |
| 6 fresh-clone rebuild | **PARTIAL** | README (generated) now documents `--derive-l6-only` and the `build_all.py` canonical-rewrite guard; five once-destroyed layers are in `CANONICAL_LAYERS`; generators refuse to shrink without `--allow-shrink`; `inventory_rights.py` reaches a fixed point | **no** `docs/REPRODUCE.md`, **no** `harvest_manifest.json`, no absent-vs-broken exit-2 split, no fresh-clone gate matrix; `build_v3.py` still needs git-ignored `V3/clones/` |
| 7 `derived_meta/` | **PENDING** | licence exposure limited via `WITHHELD.json` + per-record rights fields | metadata-only layer not built; benchmark payloads still read full derived rows |
| 8 hygiene | **PARTIAL** | doc numbers generated (`generate_readme.py`); `v2_1_summary` counts derived from `reports/validation_report.json`; `inventory_rights` fixed point | no mypy/TypedDict pass, no unified `--check` staleness semantics, no version-coherence gate |
| 9 execution depth | **BLOCKED** | 18 proof runs, 5 L5, 0 L6 in V3; 7 L6 in v1 | item 24 (human RPC key), then 4 blocked proofs + 952 Tier-B |

Facts behind the marks that changed during the 2026-11-06 remediation: the v2.2 layer publishes
**5** L5 records (not 35) under an artefact-grounded adjudication; `derived/` publishes **7** L6
records from `reports/verified_experiments.json`; V3 publishes `candidate_artefacts 127`,
`execution_attempts 18`, `evidence_admitted_records 127` (defined as admitted L3+ records, **not**
reproduced exploits). Gates: `validate.py` 84/84, `check_manifests` 181/181, `validate_v3` 46/46,
suite 854 OK / 8 skips.

**Next unblocked work, in plan order:** 1.2 (populate `rule:` refs), then 3.3/3.4/3.5 (degenerate-split
gate, holdout as primary, shortcut gate), then 6 (`docs/REPRODUCE.md` + `harvest_manifest.json` +
exit-2 semantics), then 4 and 7.

---

## 1. Verified scorecard

Measured, not quoted. `✗` = fails an adversarial check today.

| # | Dimension | Now | Target | Blocking phase |
|---|---|---|---|---|
| 1 | **Benchmark validity** | **3/10** | 10/10 | Phase 3 |
| 2 | **Evidence pointers** | 5/10 | 10/10 | Phase 1 |
| 3 | **Citation immutability** | 7/10 | 10/10 | Phase 2 |
| 4 | **Reproducibility** | 6/10 | 10/10 | Phase 6 |
| 5 | **Data completeness (depth)** | 4/10 | 8/10 | Phase 4 |
| 6 | **Licensing exposure** | 5/10 | 9/10 (human-blocked at 10) | Phase 7 |
| 7 | **Hard negatives** | 4/10 | 8/10 | Phase 5 |
| 8 | **Operational hygiene** | 8/10 | 10/10 | Phase 8 |
| — | Gate suite | **374/374, 0 failures** | hold | all |
| — | Test suite | **177/177 OK** | grow | all |

### The three measurements that define the gap

**A. Twelve of the fifteen scored families are solvable by a shortcut; nine are perfectly so.**
From `reports/independent/audit.json` → `families[*].baselines_test_split.best_shortcut_accuracy`,
cross-referenced with `families[*].answer_leakage.severity`. (Seven families — D, F, G, H, I, J, Q —
report no shortcut score at all and are excluded from the count.)

```
best_shortcut  family                                answer_leak
   1.0000      B_root_cause_reasoning               none
   1.0000      E_exploit_verification               medium
   1.0000      K_language_ecosystem_routing         high
   1.0000      M_experiment_level_classification    none
   1.0000      N_attacker_identity_extraction       none
   1.0000      O_record_class_and_scope             medium
   1.0000      v3_R_source_tier_routing             none
   1.0000      v3_S_contest_outcome                 none
   1.0000      v3_T_taxonomy_explicit               medium
   0.9998      vbeta_V_source_tier_routing          none
   0.9834      vbeta_U_language_routing             medium
   0.9032      P_provenance_tier_and_rights         none
   0.5641      C_attacker_reasoning                 medium
   0.5510      A_vulnerability_detection            none
   0.5172      L_severity_reconciliation            high
```

**Nine at exactly `1.0000`.** A twelfth (`P`, `0.9032`) is close enough that the distinction is
cosmetic. So: **three families sit below 0.60 — `A`, `C`, `L` — and not all three survive.**

| Family | Shortcut | Literal leak | Usable as evidence? |
|---|---|---|---|
| `A_vulnerability_detection` | 0.5510 | none | **yes** — the only family clean on both axes |
| `C_attacker_reasoning` | 0.5641 | **medium** | partially |
| `L_severity_reconciliation` | 0.5172 | **high** | **no** — resists the baseline but leaks the answer |

Two families leak their answer literally at `high`: **`K`** and **`L`**.

**B. Four fields are empty on 12,402 records** (`reports/field_coverage.md`):

| Field | v3 (5,467) | Vbeta (6,935) | Known % |
|---|---|---|---|
| `attack_sequence` | 0 | 0 | **0.0** |
| `root_cause` | 0 | 0 | **0.0** |
| `impact` | 0 | 0 | **0.0** |
| `fix_description` | 0 | 0 | **0.0** |

Also `vbeta.records.status_observed` 91/6935 = **1.3%**, `v1.findings.root_cause` = **1.9%**.

**C. 1,905 evidence-typed fields carry no `source_refs`** (measured by walking every
`{value, evidence_type, source_refs}` wrapper in `derived/records.jsonl`):

```
derived_fact   1183 / 1183 have empty or absent source_refs
observed_fact   722 /  722 have empty or absent source_refs
unknown         5794   (correctly carry none — they claim nothing)
reported_claim  1591   (carries refs)
```

This is the single cheapest credibility win in the repo: a `derived_fact` is defined as
*"computed here by a rule that lives in the code"* — so its `source_refs` should name **the rule**
(`scripts/solidity_facts.py:functions`), not a URL. Right now they name nothing.

---

## Phase 0 — Freeze the baseline (half a day)

The review is committed but does not say which of its 8 refutations still stand. Every future reader
has to re-derive that.

1. Create `BASELINE.md` at the repo root: the six verified numbers from §1, the commit, the platform,
   and the `python -m unittest discover -s tests` result.
2. Add a **status table** to `_audit/INDEPENDENT_REVIEW.md` — one row per refuted claim, columns
   `claim | status | evidence | resolved_in`. Use the §0 table verbatim. Never edit the review body;
   annotate it.
3. Add `reports/baseline/measured_2026-10-13.json` as machine-readable input so Phase 1's new gate
   can diff against it.

**Done when:** a fresh reader can tell in 30 seconds which review findings are closed.
**Verify:** `git diff --stat` touches only docs + one JSON.

---

## Phase 1 — Give every evidence field a pointer (1–2 days)

*Fixes the §1-C measurement: 1,905 fields.*

### 1.1 Classify before you fix

The 1,905 are not all the same defect. Split them into three buckets and record the split in
`reports/evidence_pointer_audit.json`:

| Bucket | Meaning | Action |
|---|---|---|
| **meta** | describes the schema or the record's own confidence (`.evidence.schema`, `.evidence.record_confidence`) | legitimately ref-less → register in a published exemption list |
| **rule-derived** | `derived_fact` computed by a named function | `source_refs: ["rule:solidity_facts.py:functions"]` |
| **silent** | a fact-typed claim with no pointer that *should* have one | **must** be fixed — this is the defect |

Do **not** bulk-fill. A wrong pointer is worse than a missing one.

### 1.2 Populate `rule-derived`

- `derived/hard_negatives.jsonl` already does this correctly — its `blocking_condition.source_refs`
  reads `["code-423n4/2024-04-noya/contracts/governance/Keepers.sol@main#L1"]` and its `rule` names
  `scripts/solidity_facts.py:functions`. **Copy that pattern.** `derived/records.jsonl` lost it.
- Extend `scripts/build_derived.py` so every wrapper it emits writes `source_refs` from the rule that
  produced it. Rules already live in `schema_terms.py` / `solidity_facts.py` / `taxonomy.py`.
- New wrapper helper in `vlun_io.py`: `claim(value, evidence_type, rule_ref, note)` so the ref cannot
  be forgotten at a call site.

### 1.3 Make it a gate

Add `scripts/validate_checks.py` check `every_fact_field_has_a_pointer` (critical):
walk all wrappers in `derived/records.jsonl` + `derived_v2_2/records.jsonl`; fail on any
`derived_fact`/`observed_fact` with empty `source_refs` that is not in the published exemption list.
Add the negative-control test to `tests/test_logic.py`.

**Cascade:** `derived/records.jsonl` is consumed by `build_benchmark.py` (A–J), `build_subsets.py`,
`field_coverage.py`, `depth_dashboard.py`, `audit_records.py`, `audit_third_party.py` and every gate.
Treat `build_derived.py` alone as insufficient — re-run the derived consumers, then `generate_readme.py`.

**Done when:** silent bucket = 0, and the gate fails on a planted violation.
**Verify:** `python scripts/build_derived.py` → derived consumers → `python scripts/validate.py --quiet`
&& `python -m unittest discover -s tests`

---

## Phase 2 — Make every permalink immutable (1–2 days)

*Fixes the gap left after Phase 0: `commit_sha` is pinned but 1,255 URLs are not.*

The record fields are pinned (`commit_sha == main|master` → 0), **but the permalinks are not**:

```
derived/records.jsonl   /blob/main/ or /blob/master/  →  1255 occurrences
jsonl/findings.jsonl                                    →    61
jsonl/negative_findings.jsonl                           →   115
```

A `source_url` of `.../blob/main/File.sol#L42-L56` is a *mutable* citation even when the sibling
`commit_sha` field holds a real sha. A third party following the URL tomorrow gets different bytes.

1. Add a rewrite pass in `build_derived.py`: whenever `code_context[].commit_sha` is 40-hex,
   rewrite `source_url` to use that sha. Where the sha is genuinely unknown, **downgrade the URL to
   an explicit `source_url_unpinned: true` field** rather than leaving a branch link that looks pinned.
2. Extend the `derived_mutable` scan in `validate_checks.py:629` to cover **URLs** for
   `/blob/(main|master)/`, not just `commit_sha` values. As written, the check passes on 1,255 mutable
   links.
3. `jsonl/` is read-only — do **not** rewrite it. That leaves **176 mutable permalinks in the read-only
   v1 source layer**. Report that residual explicitly in the v1 gate as an open number rather than
   letting it disappear.

**Cascade — this is wider than it looks.** `check_leakage.py`'s `exact` detector keys on source URLs,
so changing 1,255 URLs changes leakage results; `audit_third_party.py` builds a per-repo URL census;
`build_benchmark.py` embeds `code_blocks`; `datasets/` and `training/` are rebuilt by
`build_subsets.py`; `generate_stats.py` recomputes citation stats. Full sequence:

```
build_derived.py → build_hard_negatives.py → build_counterexamples.py
  → build_reproduction.py → build_subsets.py → build_benchmark.py
  → check_leakage.py --emit splits_v2 → audit_third_party.py → audit_records.py
  → resolve_citations.py → generate_stats.py → generate_reports.py
  → field_coverage.py → depth_dashboard.py → generate_readme.py
  → validate.py → check_manifests.py → check_reproducibility.py
  → python -m unittest discover -s tests
```

Budget two days for this. Do not stop at `build_derived.py && validate.py` — a partial run leaves the
repo in a state where `validate.py` passes and `check_reproducibility.py` does not.

**Done when:** `validate.py` fails if any `/blob/main|master/` survives in `derived/`, and the count in
read-only `jsonl/` is reported rather than hidden.
**Verify:** the full sequence above, ending with all 177 tests green.

---

## Phase 3 — Rebuild the benchmark so shortcuts stop working (7–11 days)

*This is the headline. It moves 3/10 → 10/10 and nothing else moves the score as far.*

> **Cascade warning — read before estimating.** Every task in 3.1–3.4 changes task *inputs* or
> *population*, which invalidates answer keys, baselines, manifests and every generated document that
> quotes a benchmark number. Do not budget these as "edit one builder". The full regeneration set is:
>
> ```
> build_benchmark.py (A–J)  → benchmark/A..J + benchmark/manifest.json
> build_benchmark_v22.py    → benchmark/K..Q + merge into manifest.json
> build_benchmark_v31.py    → benchmark/v3_T + v3_manifest.json
> Vbeta/scripts/build_vbeta.py → benchmark_vbeta/U,V + vbeta_manifest.json
> score_benchmark.py × 6 baselines   → reports/baselines/*.json
> independent_benchmark_audit.py      → reports/independent/audit.json
> build_secondary_holdout.py          → benchmark/independent/*.jsonl + manifest
> generate_reports.py                 → reports/benchmark_metrics.{json,md}, final_quality_report.md
> generate_v22_reports.py             → reports/v2_2/benchmark.json + quality_report.md
> check_manifests.py                  → reports/manifest_checks.json  (recomputes all counts)
> build_json_catalog.py               → reports/json_catalog.{json,md} (file lists change)
> build_datasheet.py                  → docs/DATASHEET.md
> generate_readme.py                  → README.md + NOTICE.md  (every benchmark table)
> python -m unittest discover -s tests
> ```
>
> `test_baselines.py`, `test_benchmark_b_g.py`, `test_independent_benchmark.py`,
> `test_generated_docs.py`, `test_json_catalog.py` and `test_field_coverage.py` will all fail if any
> step in that chain is skipped. Budget **one full regeneration + re-gate per sub-phase**, not once at
> the end.

### 3.1 Retire the saturated families — do not delete them

Nine families are at exactly `1.0000`; with `P` (0.9032) that is ten families carrying no signal.
Deleting them destroys a real (if boring) asset; shipping them as headline evidence is dishonest.

- Move them into `benchmark/retired_families/` with a per-family `retirement.json` naming the
  measured shortcut accuracy **and** the leak severity, so the reason is data not opinion.
- Remove them from the headline micro-average. **Publish both numbers**, always labelled:
  - `micro_accuracy_all_families` — for continuity with prior releases
  - `micro_accuracy_discriminating_families` — **the one to quote**
- Add the measured list to the `schema_terms.py` deprecated-terms discipline: a family may not return
  to the headline without an audit showing `best_shortcut_accuracy < 0.75` on the test split.

*Retiring a family also shrinks `check_manifests.py`'s task census — that count is published in
README, so `generate_readme.py --check` will fail until regenerated.*

### 3.2 Fix the two literal leaks

- **`K`** (`language_ecosystem_routing`, leak `high`, shortcut `1.0000`): the answer is recoverable from
  the record-id language prefix (`cairo:CVE-…`). `build_benchmark_v22.py` already has a rule that only
  `input` is shown; enforce it by stripping the prefix from any id that reaches `input`, then require
  the audit's own detector to report `K` below 0.95. **If it does not drop, retire `K`** — do not ship a
  family whose own gate cannot clear it.
- **`L`** (`severity_reconciliation`, leak `high`): severity appears in `published_severities` (68 rows)
  and in prose (26). `L` is the more interesting failure — it resists the *baseline* (0.5172) while
  leaking the *answer*, which is exactly the kind of defect a shortcut scan alone misses. Either
  **remove `published_severities` from `input`** and re-ask "what severity do independent sources agree
  on, and who says so" (so the answer becomes the disagreement, not the severity), or retire `L`.

### 3.3 Fix R's split defect

Train spans tiers `0:878 / 1:3517 / 2:611`; validation **and** test are **100% tier 2** because
`c4-reserve-findings` appears in neither. Train-majority therefore scores **exactly 0.0000** while
TF-IDF scores 1.0000 — the split cannot distinguish "learned the task" from "learned the prefix".

- Change v3 splits from **by-source** to **by-source × stratified-by-tier** for family R only,
  keeping by-source isolation as a hard constraint.
- Add gate check: every split must contain ≥2 distinct labels, else the family is auto-flagged
  `split_degenerate` and excluded from the headline. (`splits_v3/` regeneration + `check_manifests.py`.)

### 3.4 Promote the class-disjoint holdout to the primary metric

`benchmark/independent/secondary_holdout_tasks.jsonl` (2,716 tasks) already exists and already shows
every shortcut collapsing to **0.0000**. That is the honest measurement. Make it primary:

- `docs/RUBRIC.md` — lead with holdout accuracy; report official-split accuracy second as
  "in-distribution, contaminated by construction".
- Retrain every baseline against the holdout. Expect most to land near random. **That is the finding,
  not a failure to report.**

### 3.5 Gate it

`run_gates.py` must fail when any family has `best_shortcut_accuracy >= 0.95` on its test split **or**
`answer_leakage.severity == "high"`. `tests/test_independent_benchmark.py` already has both detectors —
wire them into the gate list. The audit is deliberately `--check`-only so it cannot rewrite what it
verifies; keep that, but make a *stale-shortcut* or *high-leak* result a **failure** rather than a
rebuildable staleness note.

**Done when:** the quoted headline is holdout accuracy on non-degenerate families, and every retired
family has a published mechanism. **Expect the headline micro-accuracy to fall** — that is the correct
outcome, and the changelog should say so.
**Verify:** the 3.x regeneration chain above, ending `python scripts/independent_benchmark_audit.py`
&& `python scripts/score_benchmark.py --baseline majority` && all 177 tests.

---

## Phase 4 — Fill the four empty fields (5–10 days)

*Fixes the §1-B measurement. Biggest raw-data win: 12,402 records × 4 fields.*

The text exists in the source archives — `normalize_v3_lib.py` already extracts attack sequences for
DeFiHackLabs (878 rows). Extend that extraction to the other corpora.

1. **`root_cause` (v3 + Vbeta).** The normalization report shows `taxonomy_confidence` already yields
   596 explicit + 1497 derived labels. Harvest the sentence that produced each explicit label and
   store it as `root_cause` with `evidence_type: reported_claim` and a char-span. Never summarise.
2. **`fix_description`.** `reports/v3/experimental_proof.md` shows 47 patch candidates all
   `not_testable`, and 2,359 rows have unknown `fix_status_reported`. Extract the remediation
   paragraph verbatim where present; `unknown` where absent.
3. **`impact`.** Only where the source states a consequence in its own words. Most v3 sources are
   severity-only reports — for those the correct answer stays `unknown`. **A 40% honest fill beats a
   100% inferred fill.**
4. **`attack_sequence`.** Reuse `v31_extract.extract_attack_sequence` for the 952 Tier-B
   experiment-ready rows (see `reports/v3/experiment_readiness_queue.md`).

### 4.1 Hard rule for every new field

`reported_claim`, with the quoted sentence **and** its char-span in the source file, and a
`source_file_sha256` proving the text came from that file. `scripts/build_source_sha_index.py` already
builds the index that makes this checkable on a fresh clone with no clones present. Add a gate check
that every new `reported_claim` sentence is byte-present in the indexed text — this is the
"no invention" guarantee, currently only applied to v3.1.

**Cascade:** `normalize_v3.py` writes `normalized_records_preview.jsonl` (12,504 rows) and family T is
built from it — so any extraction change moves `benchmark/v3_T_taxonomy_explicit.jsonl` too, plus
`field_coverage.md`, `depth_dashboard.md` and the v3.1 gate.

**Done when:** v3 `root_cause` ≥60% known, `fix_description` ≥40%, and `field_coverage.md` shows real
movement with every known value traceable to a quoted span.
**Verify:** `python scripts/normalize_v3.py && python scripts/build_benchmark_v31.py
&& python scripts/field_coverage.py --check && python scripts/validate_v31.py` && full tests.

---

## Phase 5 — Turn unknown negatives into code-grounded negatives (3–5 days)

`derived/hard_negatives.jsonl`: 458 negatives, of which **441 are `unknown`** — 96% carry no reason.

1. **Widen the gate detector.** `scripts/solidity_facts.py` recognises exactly three access-control
   forms (`onlyX` modifier, inline caller-identity `require`, internal/private visibility) — that is
   why only 8 of 458 code-grounded. Add: modifiers inherited from a base contract, modifier bodies
   defined in another file, `Pausable`/`whenNotPaused` composition, timelock delay checks, and role
   checks performed inside a called internal function.
2. **Attribute more judgements.** `build_hard_negatives.py` asserts a blocking condition when a
   judge/sponsor states it. 9 rows qualify today. Re-mine the C4 issue-comment archives already
   cloned under `work/repos/` for `disputed` (24 rows) and `duplicate` (319) verdicts with quoted
   reasoning — the comment bodies are already in `provenance.submission_issue_comments`.
3. ~~**Execute the remainder.** Scale `scripts/run_negative_experiments.py` beyond its current 3.~~
   **BLOCKED — do not start until Phase 9 item 1.** `run_negative_experiments.py:163` calls
   `ex.forge_test(...)`, so it needs Foundry, the audited clones, and the same funded archive RPC that
   gates Phase 9. Items 1 and 2 are fully offline and should land first; treat item 3 as a Phase 9
   sub-task, not a Phase 5 deliverable.

**Done when:** `unknown` drops below 300 from items 1–2 alone, and every newly-resolved negative states
a code reference or quotes a named source.
**Verify:** `python scripts/build_hard_negatives.py && python scripts/generate_reports.py` — read
`reports/hard_negative_stats.json`.

---

## Phase 6 — Make a fresh clone able to rebuild everything (2–3 days)

`work/`, `V3/clones/`, `nextdata/` are git-ignored. So:

- v3 **cannot** rebuild without ~3 GB of clones (`build_v3.py:109` returns 2 — correct).
- **Vbeta cannot rebuild at all** without `nextdata/` (734 scraped Solodit pages) *and*
  `work/sources/{Web3Bugs,scabench,lisa-bench}`. A fresh clone cannot run
  `Vbeta/scripts/build_vbeta.py` at all. This is not documented as a limitation.

### 6.1 Exit-2 semantics must distinguish absent from broken

Four scripts already use exit 2: `build_v3.py:109`, `check_ml_layer.py:55`, `normalize_v3.py:102`,
`score_benchmark.py:425`; `run_gates.py:83` maps it to `SKIPPED_CODES`. The harvest scripts currently
hard-crash instead. Converting crash → skip is right **only if** it cannot hide a real failure, so:

- **Exit 2 (SKIP) iff** a declared required input *path does not exist*, and emit a machine-readable
  reason naming the exact missing path (mirror `check_ml_layer.py:53-55`: `SKIPPED: <path> does not
  exist — <what it would have checked>`).
- **Exit 1 (FAIL) if** the input exists but is unparseable, internally inconsistent, fails a schema
  check, or its row count disagrees with its manifest. A present-but-broken corpus is a *failure*; it
  must never become a skip.
- Every skip must be recorded in the gate report with its path, so `run_gates.py`'s
  `checks_skipped` count is attributable. `reports/build_all.json` already does this correctly — each
  stage carries a `reason` field — so follow that shape.

> **Related defect to fix here, not later.** `build_v3.py:109` returns 2 only when *all* 18 clones are
> missing. If *some* are missing, line 114 logs `[warn] missing clone dir …` and **continues with zero
> rows for that source** — a silently smaller layer reported as a pass. Split it: all-absent → 2;
> partially absent → 1, naming the sources.

### 6.2 Documentation and manifest

1. Document the asymmetry honestly in `Vbeta/README.md` next to Rule 1: *"Vbeta is receipt-proven,
   not offline-reproducible. A fresh clone cannot rebuild it without re-running the harvests, which
   need network + Firecrawl credits."*
2. Commit a **content-addressed harvest manifest** under `Vbeta/harvest_manifest.json`: for each of
   the 7,060 candidates, the `source_url`, the harvested-file `sha256`, and the harvest rule version.
   Hashes only — never the prose (METADATA_ONLY). This makes the input set auditable without
   redistributing it.
3. Add `docs/REPRODUCE.md` listing, per gate, the inputs it needs and the exact command to obtain them
   (Foundry ≥0.2.0, `VLUN_RPC_URL`, Firecrawl credits, clone remotes from `V3/clones/MANIFEST.md`).

**Done when:** a fresh clone can run `python scripts/run_gates.py` and every gate either passes or
reports a named, actionable skip — and no present-but-broken input can be skipped.
**Verify:** `git clone <url> /tmp/fresh && cd /tmp/fresh && python scripts/run_gates.py` — record the
real matrix in `BASELINE.md`.

---

## Phase 7 — Cut licence exposure to zero self-inflicted risk (2 days + human wait)

*424 of 722 v1 records self-declare redistributing source from repos with **no declared licence**;
390 carry Solidity text, 346 carry PoC source. This is the biggest non-technical risk in the repo.*

**7.1 The fix we can make alone (2 days):** prove the dataset is fully useful with **zero** third-party
text. Add `scripts/build_derived_metadataless.py` producing `derived_meta/records.jsonl` — identical
records with every `snippet`, `poc.code`, `explanation`, `diff` and `judge_and_sponsor_quotes.body`
replaced by `{value: null, evidence_type: observed_fact, source_refs: [<url>], note: "not
redistributed; fetch it yourself via scripts/fetch_sources.py"}`.

Then:
- publish `derived_meta/` alongside `derived/`, and state in the README that it is the
  **recommended entry point for commercial training**;
- re-point the benchmark at `derived_meta/` for any family a model will see (families D, G, H, J
  currently embed PoC and diff text in `input`);
- state the resulting exposure as *zero redistributed third-party text*, which is a claim the whole
  repo can defend with a single `git grep`.

This converts the risk from *"we redistributed unlicensed text"* to *"we redistribute none"*, without
needing anyone's permission and without deleting the research value.

**Cascade:** re-pointing the benchmark at `derived_meta/` re-runs the whole Phase 3 chain
(`build_benchmark.py` → baselines → audit → holdout → `check_manifests.py` → README). Do not combine
7.1 with 3.x in one pass; land 7.1 as its own commit so a regression is bisectable.

**7.2 The fix we cannot make (blocked):** two draft emails already exist in
`Vbeta/reports_vbeta/licence_clearance_popoc_checklist.md` for PoPoC and the Cyfrin
audit-checklist. Sending them is a human action. Until it happens, both source ids stay unregistered —
which is the correct current behaviour. **Leave it alone; do not work around it.**

**Done when:** `derived_meta/` exists, every benchmark model-facing payload is metadata-only, and
`reports/third_party_audit.json` has a `derived_meta` section reporting 0 redistributed bodies.
**Verify:** `python scripts/audit_third_party.py` — it must still exit non-zero for the `derived/`
layer. That non-zero is the flag, not a bug to silence.

---

## Phase 8 — Operational hygiene (1–2 days)

1. **Unify `--check`.** 21 scripts implement it in **3 different flavours**; the weakest
   (dry-run-compute-and-write-nothing) **exits 0 even when the file on disk is stale**, so it does not
   protect anything. Make every `--check` mean: *rebuild in memory, byte-compare, exit 1 on
   difference*. Files: `build_v3.py`, `normalize_v3.py`, `build_benchmark_v22.py`,
   `build_derived_v22.py`, `build_splits_v22.py`, `run_dhl_experiments.py`, `ingest_audit_sources.py`.
2. **Enable real type checking.** mypy reports **348 errors in 63 files** (dynamically-typed
   `dict`/`list` record shapes). Add `TypedDict` definitions for the ~6 canonical record shapes in
   `schema/`, then enable mypy incrementally via `[[tool.mypy.overrides]]` per-module
   `ignore_errors = true` until the critical modules (`vlun_io`, `schema_terms`, `poc_classification`,
   `vlun_v3`, `vlun_ml`) are clean, then tighten. `ruff format --check` would rewrite 103 files — do
   it as one dedicated commit so the diff is reviewable and separate from any logic change.
3. **Fix the doc number drift.** `CONTRIBUTING.md` says 175 tests (actual 177) and 21 gates
   (actual 22). `Vbeta/REMOVAL_CANDIDATES.md` says 54 RESEARCH_ONLY (actual 62).
   `reports/v3/INTEGRATION_NOTES.md` says `V3/clones` ~3.1 GB (measured 2.98 GB).
   Prefer **generating** these numbers — `tests/test_generated_docs.py` already does this for
   README/ANSWER_KEY/CHANGELOG; extend it to `CONTRIBUTING.md` and `REMOVAL_CANDIDATES.md`.
4. **Version coherence.** `pyproject.toml` says `2.2.0` while the corpus ships layers v3.0/3.1/3.2 +
   Vbeta. Add an explicit `dataset_layers: ["v1","v2.2","v3.0","v3.1","v3.2","vbeta"]` field so the
   packaging version is not mistaken for the layer set.
5. **Orphan run.** `experiments_v3/pilot-bybit-2025-02/` is a complete committed artefact set
   referenced by no report, so it contributes to no record's level. Either fold it into
   `reports/v3/experimental_proof.json` or move it to `experiments_v3/_unreferenced/` with a one-line
   reason. Do not leave it silently inert.
6. **Housekeeping.** `.freebuff/`, `ai/`, `brag-output/`, `.mypy_cache/`, `.ruff_cache/`,
   `.pytest_cache/` are git-ignored local trees (verified: 0 tracked files). Confirm that stays true
   and remove `brag-output/`'s unlicensed third-party SFX from disk.

**Done when:** every `--check` is a real staleness gate, `run_gates.py` is green, and no doc number
is hand-typed.
**Verify:** `python -m pre_commit run --all-files` and `python scripts/run_gates.py`

---

## Phase 9 — Execution depth (blocked on one human action)

Today the whole repository contains **9 L6 verified patches** (v1: 7, v2.2: 1, v3: 0) and **2 L5
exploits** (v3.2). That is the deepest honest weakness and it is *not* a code problem.

1. **The blocker:** `requirements.txt` states 140 of 155 PoCs and all fork proofs are blocked without
   `VLUN_RPC_URL`, an **Ethereum archive** endpoint. Public RPCs are rate-limited and are not a
   substitute. 4 of the 6 v3.2 runs are blocked on exactly this (`archive_state_unavailable`, with
   verbatim `missing trie node` errors preserved in `experiments_v3/`).
   → **Human action: obtain a funded archive RPC key.** Nothing else in this phase can start.
2. Then, in order:
   - re-run `python scripts/run_dhl_experiments.py --reanalyze` first (offline, free) to confirm the
     4 blocked runs are blocked on the endpoint and nothing else;
   - re-run with the funded key; each newly-executed PoC is either L3/L4/L5 or a **verbatim backend
     error** — never a silent pass;
   - drain the **952 Tier-B experiment-ready rows** in
     `reports/v3/experiment_readiness_queue.md`;
   - convert the **47 patch candidates** (all currently `not_testable`) — the shortest path to more
     L6, because L6 only needs the same PoC run on both revisions;
   - **and only now** return to Phase 5 item 3 (scale `run_negative_experiments.py`), which shares this
     same toolchain dependency.
3. Publish `docs/EXECUTION.md`: the exact procedure, the toolchain pins (forge 1.8.3 /
   `cae51ad4…`, solc 0.8.37 per `v32_provenance_closure.md`), the honesty paths
   (`environment_unavailable`, `rpc_unavailable`, `archive_state_unavailable`), and the known
   limitation that the full DeFiHackLabs tree does not compile at the pinned commit
   (missing `src/interface.sol`, missing balancer import, a unicode literal).

**Done when:** L5+L6 counts rise, or the remaining gap is fully attributed to named environmental
blockers with verbatim evidence.

---

## Ordered execution list

| # | Task | Phase | Est. | Blocked |
|---|---|---|---|---|
| 1 | **FIXED in c6b45df** (0 mutable commit_sha across 2756 shas) - `BASELINE.md` + review status table | 0 | 0.5d | — |
| 2 | Evidence-pointer audit + 3-bucket classification | 1.1 | 0.5d | — |
| 3 | `claim()` helper; populate `rule-derived` refs; rebuild derived consumers | 1.2 | 1.5d | — |
| 4 | `every_fact_field_has_a_pointer` gate + negative-control test | 1.3 | 0.5d | — |
| 5 | **FIXED in 8abe43f** (0 mutable commit_sha and 0 mutable source_url across 2756 shas / 2034 urls in derived/records.jsonl; derived_commit_pins_are_immutable gate) - Rewrite permalinks to pinned sha | 2 | 2d | — |
| 6 | Retire 9 saturated families (+P); dual headline numbers; regen chain | 3.1 | 2d | — |
| 7 | Fix K's id-prefix leak — or retire K if the detector will not clear it | 3.2 | 1d | — |
| 8 | Fix or retire L (leaks high while resisting the baseline) | 3.2 | 1d | — |
| 9 | Stratify R's splits by tier; add `split_degenerate` gate | 3.3 | 1d | — |
| 10 | Make class-disjoint holdout primary; retrain 6 baselines | 3.4 | 1d | — |
| 11 | Gate: fail on shortcut ≥0.95 **or** leak == high | 3.5 | 0.5d | — |
| 12 | Extend `root_cause` / `fix_description` extraction to v3 + Vbeta | 4.1–4.2 | 4d | — |
| 13 | No-invention gate over every new `reported_claim` | 4.1 | 1d | — |
| 14 | Widen access-control detector; re-mine C4 comments | 5.1–5.2 | 3d | — |
| 15 | `harvest_manifest.json` (hashes only); exit-2 absent-vs-broken split; fix `build_v3.py:114` partial-clone warn | 6 | 2d | — |
| 16 | `docs/REPRODUCE.md`; fresh-clone gate matrix in `BASELINE.md` | 6.3 | 0.5d | — |
| 17 | `derived_meta/` metadata-only layer (own commit) | 7.1 | 1.5d | — |
| 18 | Point benchmark payloads at `derived_meta/`; re-run 3.x chain | 7.1 | 1d | — |
| 19 | Send the 2 clearance emails | 7.2 | — | **human** |
| 20 | Unify `--check` to staleness-compare | 8.1 | 0.5d | — |
| 21 | mypy TypedDicts + per-module overrides; ruff format commit | 8.2 | 1d | — |
| 22 | Doc-number drift → generated; version coherence | 8.3–8.4 | 0.5d | — |
| 23 | Orphan run; housekeeping | 8.5–8.6 | 0.5d | — |
| 24 | Obtain funded archive RPC key | 9.1 | — | **human + budget** |
| 25 | Re-run 4 blocked proofs; drain 952 Tier-B; convert 47 patch candidates | 9.2 | 5d+ | after 24 |
| 26 | Scale negative execution (Phase 5 item 3) | 5.3 | 2d | after 24 |

Total unblocked work: **~28 days**. With the two human items: the honest ceiling is ~8.5/10.

**Row status at `aa82ac1`** (the rest of this table is unchanged from its original measurement):
1, 5 — **DONE** (see §0b; row 1 `c6b45df`, row 5 `8abe43f`).
4 — **DONE**: `every_fact_field_has_a_pointer` is a critical gate and has a negative-control path in
`tests/`; it closed 29 v2.2 leaks during the 2026-11-06 remediation.
2, 3 — **PARTIAL**: gate + `claim()` helper exist; `rule:` refs are still 0/722 and the 3-bucket
classification has not been written.
6, 7, 8 — **DONE for retirement** (10 frozen families under `benchmark/retired_families/`, live
manifest 19 families; K and L are retired, not fixed). The *measurement* half of 6 (dual headline
numbers) is in `docs/RUBRIC.md`; 9–11 remain open.
15, 16 — **PARTIAL**: the README now documents the offline build path and the canonical-layer guard,
and `CANONICAL_LAYERS` covers the five layers an input-less run once destroyed, but there is no
`harvest_manifest.json`, no `docs/REPRODUCE.md`, and no absent-vs-broken exit-2 split.
20, 22 — **PARTIAL**: `inventory_rights` reaches a fixed point and `v2_1_summary` derives its gate
counts, but `--check` is not unified to staleness-compare across scripts and no version-coherence gate
exists.
12–14, 17–18, 21, 23 — **OPEN**. 19, 24 — **human**. 25–26 — blocked behind 24.

**Phases 0, 1, 2, 8 are ~6 days total and require no external input or permission.** Start there —
highest ratio of defensibility to effort, and Phase 1 alone closes the most embarrassing remaining
finding.

---

## What this plan deliberately does not do

- **Does not delete the saturated families.** They are real data with a measured weakness; the honest
  move is to publish the weakness, not remove the evidence.
- **Does not invent `attack_sequence` / `impact` / `root_cause` to fill 0% cells.** A summary written
  by a model is a `derived_fact` wearing a `reported_claim`'s clothes. Fields stay `unknown` until a
  quoted span exists. Coverage that drops back after a rebuild is a *correct* outcome.
- **Does not work around the licence block.** `licence_clearance_popoc_checklist.md` says an agent
  cannot send email. It is right.
- **Does not let a skip hide a broken input.** Exit 2 means "absent", never "present and wrong"
  (§6.1) — otherwise Phase 6 would trade a visible failure for an invisible one.
- **Does not chase a 10/10 that requires inventing evidence.** If Phases 7.2 and 9.1 stay blocked, the
  honest score is ~8.5/10 with two named, documented blockers. That is a defensible release. A 10/10
  obtained by widening a claim's evidence type is worth less than the 4/10 was for finding the problem.

---

## Definition of done

A third party who has never seen this repository, running only the committed gates, can answer
**yes** to all six:

1. Does every number in the README recompute from the canonical records? *(already yes — 171 checks)*
2. Does every evidence-typed field name what backs it? *(Phase 1)*
3. Is every citation immutable, including the URL and not just the sha? *(Phase 2)*
4. Does the quoted benchmark number survive a class-disjoint holdout and a leak scan? *(Phase 3)*
5. Can a fresh clone reach a green-or-explained gate matrix, naming every skip? *(Phase 6)*
6. Does the dataset redistribute **zero** third-party text on its recommended path? *(Phase 7.1)*

If the answer is yes, an external review would score it 9–10 — and unlike the current 4/10, that score
would survive being re-derived by someone hostile.

---

## Agent execution prompt

Paste the block below into a fresh agent session to execute this plan. It encodes
the governing principle, the verification discipline, and the repo's load-bearing
conventions — so the work stays honest even when the operator changes.

```
You are executing improve.md in the VLUN repository (smart-contract security
reasoning dataset). Read improve.md fully first, then execute ONE task from
"Ordered execution list" per session, in order, starting at the lowest
unfinished number. Do not skip ahead, do not batch phases.

Governing principle (non-negotiable):
TRUTH > COMPLETENESS > SCALE > METRICS. Every change must make the dataset
more honest, never merely larger. `unknown` is a counted outcome — never fill
it by guessing, summarising, or inferring. A wrong pointer is worse than a
missing one. A coverage number that drops back after an honest rebuild is a
correct outcome.

Before writing any code:
1. Re-measure the task's premise from the canonical files (jsonl*/,
   derived*/, benchmark/, reports/). Never quote a number from prose —
   including this plan. If your measurement disagrees with improve.md,
   stop and report the discrepancy; the plan is stale, not the data.
2. State which files you will touch and what the blast radius is
   (gates, manifests, benchmarks, generated docs that read them).

While working:
3. `jsonl/`, `jsonl_ml/`, `jsonl_v3/` are READ-ONLY. No exceptions.
4. Never invent evidence: new `reported_claim` values require a quoted span
   plus char offsets plus a source sha; new `derived_fact` values require a
   rule that lives in the code, named in `source_refs` (rule:file:function).
5. Refactors must be behavior-preserving: prove it with a pre/post byte
   comparison of every affected output (stash, run, compare, restore),
   not by asserting equivalence.
6. Generated files (README.md, NOTICE.md, docs/DATASHEET.md, reports/*.md
   that have a generator) are edited at their generator, never directly;
   every generator change ends with its --check passing.
7. Keep the build green as you go: `python scripts/run_gates.py` (22 gates),
   `python -m unittest discover -s tests` (177 tests), and
   `ruff check scripts/ tests/ Vbeta/scripts/ Vbeta/tests/` must all pass
   before you stop. Line endings are LF; Python is stdlib-only.
8. If you change a PRESENT sentinel (README.md, benchmark/manifest.json,
   derived_v3/manifest.json, pyproject.toml), re-snapshot with a reason:
   `python Vbeta/scripts/validate_vbeta.py --resnapshot "<why>"`.

When the task's "Done when" holds and its "Verify" command passes:
9. Commit that task alone with a message naming the task number, what changed,
   and the verification evidence (gate/test counts). Never mix tasks in one
   commit. Never commit `work/`, `V3/clones/`, scrape caches, or `ai/`.

Stop and ask the operator instead of guessing when: a measurement contradicts
the plan, a fix requires weakening a gate, scope touches licensing or
redistribution, or an item is marked human-blocked (Phase 7.2 emails,
Phase 9.1 RPC key — document, do not work around).
```
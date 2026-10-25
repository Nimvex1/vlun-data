# VLUN task contracts — what each task actually measures

Status: authored 2026-10-25 on `arena/a7c75743-vlun-data` (baseline
`cb6a2a8`). This file is the reviewable contract layer required by the
quality programme (Phase 1). It is a **specification**, not a generator
output: disagreement with a generated artefact is a defect to be resolved in
favour of the evidence, never by editing this file to match.

Governing rules that apply to every task below:

- **TRUTH > COMPLETENESS > SCALE > METRICS.** A rejected submission is not
  proof its code is safe; a duplicate submission can describe a genuine
  vulnerability; a passing test establishes one defined property, not
  universal security. Missing evidence produces an explicit `unknown`,
  abstention or ineligibility decision — never a fabricated negative.
- For identical task objectives and identical complete supplied inputs, gold
  labels are consistent. Where the same code supports several findings, the
  claim is named in the input or the answer is set-valued (family A's answer
  key states this explicitly).
- **No single headline score mixes task types.** The five measurement kinds
  are kept apart: (A) code-based vulnerability detection, (B)
  claim-conditioned security reasoning, (C) report interpretation and
  evidence extraction, (D) exploit reproduction and patch verification,
  (E) metadata classification.

## 1. Family A — code-based vulnerability detection (kind A)

| field | contract |
|---|---|
| Unit | one supplied code bundle (record `input.code`, one or more blocks) evaluated against one explicit claim |
| Model-visible input | `input.prompt` (fixed instruction text) + `input.code` blocks. The answer-bearing fields (`answer_key*`, `source`) are on the row for traceability and are **not** model-visible: any submission that reads them is disqualified (see `docs/ANSWER_KEY.md`) |
| Required context | the code as published by the audited revision; callers/storage/configuration beyond the bundle are *not* supplied and the contract says so — the task measures "is a confirmed vulnerability documented for this code", not "is the bundle provably vulnerable in every deployment" |
| Label meaning | `answer_key` is the finding's verified existence (labelled from the record's own evidence), not a per-line claim. Answer-key basis is recorded per row (`answer_key_basis`) |
| Abstention | none allowed: the row is labelled from evidence or excluded at build time. Rows without code are kept as a documented population (121 of the 147 test rows) and are scored as a separate stratum, never silently mixed |
| Scoring | exact match on the projected scalar (`docs/RUBRIC.md`), reported per split with majority/source-lookup/lexical/code baselines fitted on train only |
| Admission | a row enters only with an immutable source record and a recorded answer-key basis |

Known structure (measured 2026-10-25, `benchmark/A_vulnerability_detection.jsonl`):
720 rows = 384 distinct full `input` objects = 357 distinct code payloads;
14 identical-input groups carry conflicting labels (330 rows at code-payload
granularity, 306 at full-input granularity); test split 121/147 rows without
code. **Conflicting gold on identical complete inputs is a contract
violation that remains OPEN** — the remedy is an explicit claim dimension or
a set-valued answer, not id changes (see `docs/EVIDENCE_LEDGER.md`, E-1).

## 2. Family B — root-cause reasoning (kind B), retired

Unit: record + claim; answer is a root-cause class from the closed taxonomy
(`scripts/schema_terms.py` / `taxonomy/`). Retired families stay shipped and
audited; retirement is a location, not a verdict.

## 3. Family C — attacker reasoning (kind B)

Who can carry the claim out, with what preconditions and in what order.
Labelled from `attacker_model` evidence only; `unknown` is a counted outcome
(never filled by guessing). Shortcut-sensitive (train-only lexical baseline
~0.56 on held-out): reported as exploratory/invalid evidence, not hidden.

## 4. Family D — exploit construction (kind D, generative)

Unit: (record, claim) → a Foundry test that demonstrates the claimed impact.
**Not string-match scorable** — graded by a judge against executed security
properties where a harness exists. `Scorable 0` in the README table means
"no exactly-matchable scalar key", not "ungraded by anyone".

## 5. Family E — exploit verification (kind B/D), retired

Does a supplied test demonstrate the claimed impact? The label requires an
executed artefact; a test that merely exists or merely passes on the
vulnerable revision proves nothing (enforced by `tests/test_prove_split.py`
stage-ladder rules).

## 6. Family F — false-positive rejection (kind B)

Unit: one evidence packet + one claim; label: valid claim / blocked claim +
reason. Exploratory (17 scorable rows).

## 7. F-extension — F-A and F-B (kinds C and E)

The F-extension is **scored by its own scorer** (`scripts/score_f_extension.py`)
under its own contracts. The README table's `Scorable 0` for both families is
a scope statement about the headline exact-match projection only
(reconciled 2026-10-25 in `scripts/generate_readme.py`; traced in
`docs/EVIDENCE_LEDGER.md`, E-6).

### F-A `Fa_rejection_evidence_axis_vector` (kind C)

| field | contract |
|---|---|
| Unit | one rejection-evidence packet |
| Input | the packet as extracted (no judgement phrases in model input — 67 pairs were excluded for carrying them) |
| Answer | a six-axis vector (`supported` / `not_supported` / `unknown` per axis) **plus per-axis assessability** |
| Scoring | per-axis accuracy/F1 over the **assessed axes only**; missing and invalid predictions count as misses for the gold class and stay in the denominator. Micro + macro published per axis group (input-observable / reasoning / meta) |
| Floors | published per-axis trivial-predictor floor (`reports/f_extension_baselines.json`) |
| Row scoreability | a row is scorable only when the packet carries evidence for every axis: **9 of 458** rows scorable, 449 partial (partial rows are scored on their assessed axes and never counted as negatives) |

### F-B `Fb_duplicate_radar_pair` (kind E)

| field | contract |
|---|---|
| Unit | one candidate/comparison submission pair |
| Input | both submissions' claim surfaces with the triage outcome withheld from both sides |
| Answer | `same_vulnerability` / `distinct_vulnerability` / `ambiguous` |
| Scoring | three-class exact match. `ambiguous` is scorable because the insufficiency is itself established by the recorded evidence (no pointer, or a shared code target and nothing more); such pairs are **never** counted as confirmed negatives |
| Floors | published train-fitted trivial-predictor floor |
| Population | 554 pairs (184 same, 121 distinct, 249 ambiguous) over 386 candidate submissions |

Human validation: none collected for the F-extension; the gold is the
documented rule applied to public evidence. No inter-annotator agreement is
claimed (`reports/f_extension.md` states this).

## 8. Families G–J — patch/verification tasks (kind D)

- **G**: does the fix address the vulnerability? (5 scorable)
- **H**: name the vulnerability, attacker model and PoC at the audited
  revision, against executed code — descriptive reference answers, not
  scalar (NOT_SCORABLE by design).
- **I**: is this exploitable at the audited revision given an executed
  attempt? (1 scorable)
- **J**: does the exploit pass on the vulnerable revision and fail on the
  fixed one? (5 scorable). This is the two-revision comparison contract: same
  test bytes both sides, harness identity recorded
  (`tests/test_artefact_hashes.py`, `tests/test_v32_execution.py`).

## 9. Families K–Q — v2.2 metadata/extraction (kind E, retired except Q)

Record-anchored metadata and evidence typing over `jsonl_ml/`:
K language/ecosystem routing, L severity reconciliation, M experiment-level
classification, N attacker-identity extraction (sentence-quoted), O record
class and scope, P provenance tier and rights, Q evidence-type + quality
rubric (judge-graded dict — NOT_SCORABLE by the exact-match projection).
Retired families keep byte-frozen rows under `benchmark/retired_families/`
and a rebuild must reproduce them exactly (enforced 2026-10-25 by
`scripts/build_benchmark_v22.py --check` and
`tests/test_v22_split_pointers.py`).

## 10. Families R–T (v3) and U–V (Vbeta)

Source-tier routing (R), contest outcome (S), taxonomy-explicit (T),
language routing (U), source-tier routing (V). Metadata classification over
the v3 / Vbeta layers. All are INVALID as evaluation evidence under the
auditor's validity flags (leaks/saturation) — shipped for continuity and
diagnostics, never in the headline. U/V come from the harvested Solodit
mirror; their answers are derivable from publisher metadata (high shortcut
risk, documented).

## 11. VLUN-Prove (kind D, the only private evaluation)

| field | contract |
|---|---|
| Unit | one task with pinned vulnerable/fixed revisions |
| Input | public task list carries the input payload and a revealing-nothing id; the hidden fixed revision and the answer key live outside the tracked tree (machine-local key directory, never in the repository), pinned by commitment hash |
| Labels | a five-stage ladder (`tests/test_prove_split.py`): compile → dependency → run → impact (named assertion, right test) → verified_patch (same test bytes block on the fix). A compile failure credits nothing higher; a wrong test failing is not the claimed violation |
| Scoring | stage-reached + verdict; graded against executed security properties, never string matching |
| Abstention | unsupported runners are `not_gradable`, never dropped |
| Isolation | the key must never live inside the repository (enforced) |

Only genuinely private evaluation in the repository. Everything else is
OPEN-KEY: reproducible public keys are not confidential.

## 12. Span tasks and API-sibling tasks (kinds C and B)

- **Span tasks** (`derived_span_tasks/`): evidence-span extraction — the
  model must ground an answer in the source span; scored with span overlap
  (`tests/test_span_scoring.py`). Gold spans come from independently
  annotated source material where available.
- **API siblings** (`derived_siblings/`): materially similar call sites with
  different protective handling — contrastive security reasoning. Admitted
  set reviewed (`scripts/review_sibling_pairs.py`).

## 13. Training exports

Training rows are task-shaped projections of the same contracts. Admission
is task-specific: a metadata-only record may be useful metadata without
being promoted to executable security ground truth. Every export carries
provenance and eligibility fields; quarantined material stays out of
training views with a machine-readable reason
(`scripts/build_quarantine_report.py`).

## 14. Split contract (all families)

Group related material — underlying case identity, revision pairs, copied
code, report lineage, derived variants — into one leakage group; a group
never straddles splits (`scripts/build_splits_v22.py` post-checks,
`scripts/check_leakage.py`, `scripts/check_eval_leakage.py`). The v2.2 split
pointers hash the exact derived record bytes (`record_sha256`); drift there
is a build failure (regression tests added 2026-10-25).

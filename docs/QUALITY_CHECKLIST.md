# VLUN quality checklist — 2026-10-25

Tracked checklist for the quality programme. Every line has a status:
`DONE`, `PARTIAL`, `OPEN`, or `BLOCKED` (with owner and the exact evidence
needed). A green gate is not independent proof that the dataset or the
benchmark is valid — this checklist is.

Measurement environment for this pass: Linux, CPython 3.11.2, checkout of
`arena/a7c75743-vlun-data` at baseline `cb6a2a8` (single-commit history),
local git-ignored `work/` (sparse) and `V3/clones/` present, `ai/` and
`nextdata/` absent. Full before log: `work/baseline_runs/gates_before.txt`
(machine-local). Findings and evidence: `docs/EVIDENCE_LEDGER.md`.
Task definitions: `docs/TASK_CONTRACTS.md`.

## Phase 1 — task contracts

- [x] DONE — every shipped task family has an explicit contract (unit,
  model-visible input, required context, label meaning, abstention,
  scoring, admission): `docs/TASK_CONTRACTS.md`.
- [x] DONE — the five measurement kinds are named and never summed into one
  headline score; the README headline covers only the PRIMARY exact-match
  set (720 rows of family A).
- [x] DONE — missing-evidence behaviour is explicit (`unknown` counted,
  abstention/ineligibility recorded, never a fabricated negative).
- [ ] OPEN — family A: 14 identical-input groups with conflicting gold
  and scorable rows missing required code (E-1). The audit now marks A
  INVALID; the underlying task data still needs claim-level repair. Blocks
  any family-A leaderboard claim. Owner: dataset maintainers.

## Phase 2 — evidence-qualified core

- [x] DONE — layers are separated (raw `jsonl*`, derived `derived*`,
  admitted `datasets/`, evaluation `benchmark/`, training `training/`) and
  the raw layers are read-only (gate-enforced).
- [x] DONE — corrections are versioned/additive; quarantine carries
  machine-readable reasons (`reports/quarantine*`, `derived_rejections/`).
- [x] DONE — provenance, uncertainty handling, enriched v3.1 records,
  sibling/span tasks and vulnerable/fixed execution pairs are preserved
  (no frozen layer was rewritten in this pass; only derived pointers and
  generator outputs changed).
- [x] PARTIAL — admission fields (rights status, task eligibility,
  verification level) exist per record; per-field coverage is honestly
  published (`reports/field_coverage.md`, four depth fields still 0% known
  in v3/Vbeta — historical §1-B, unchanged and still true).
- [ ] OPEN — measured coverage of unique cases/projects/mechanisms is
  published per family but the mechanism taxonomy is only partially
  assigned (418 root-cause assignments). Owner: taxonomy maintainer.

## Phase 3 — extraction and label quality

- [ ] OPEN — V4 impact/ToC extraction defect (E-9): confirmed ≥1,971 rows;
  repair + span-annotated evaluation of extraction correctness not executed
  (needs annotated spans). Owner: extraction pipeline maintainers.
- [ ] BLOCKED — AI export audit (E-10): `ai/` assets absent here. Owner:
  operator (supply the export).
- [x] DONE — uncertain examples stay uncertain (`unknown` is a counted
  outcome; gates fail on guessing).
- [x] DONE — regression tests cover the repaired extraction/label classes
  (pointer-hash drift, split-assignment stability, K-Q byte-rebuild).

## Phase 4 — credible negatives and contrasts

- [x] DONE — negatives carry provenance and confidence; rejection corpus +
  six axes (`scripts/build_rejection_corpus.py`, F-A gold);
  `classify_negatives.py` + `check_rejection_consistency.py` agree with the
  corpus on every axis; API-sibling contrasts reviewed.
- [x] DONE — paired vulnerable/fixed evidence keeps both revisions, tests
  and derived variants in one split group; same test bytes both sides
  (enforced by `tests/test_v32_execution.py`, `tests/test_artefact_hashes.py`).
- [x] DONE — no "safe" label inferred from rejection or silence (F-A/F-B
  ambiguous pairs are never counted as confirmed negatives; E-6).

## Phase 5 — splits and evaluation

- [x] DONE — split rules frozen before any model measurement; leakage
  groups stay within one partition (post-checks in
  `scripts/build_splits_v22.py`, `scripts/check_leakage.py`,
  `scripts/check_eval_leakage.py`); split-pointer drift is now a build
  failure (E-2/E-15).
- [x] DONE — duplicate/leakage detection audited against the corpus
  (`reports/leakage_report*.json`, `reports/independent/audit.json`).
- [x] DONE — shortcut baselines published per family, fitted on train only
  (majority/random/frequency/retrieval/first-published/majority-published).
- [x] DONE — public open-key benchmarks kept distinct from the private
  VLUN-Prove split; OPEN-KEY status and contamination risk are documented,
  never claimed absent (E-14).
- [ ] OPEN — near-duplicate detection validation against a manually
  reviewed sample exists for families but not for the v4 extraction layer
  (blocked with E-9).

## Phase 6 — executable grounding

- [x] DONE — execution claims carry pinned revisions, byte-hash-checked
  artefacts (`tests/test_artefact_hashes.py`: 30 digests verified from
  committed bytes), same-test-both-sides identity, and stage-ladder
  semantics that refuse to credit beyond the evidence
  (`tests/test_prove_split.py`, `tests/test_v32_execution.py`).
- [x] DONE — recorded historical results are labelled as historical;
  fresh replay requires the git-ignored clones (skips stay
  `skipped_no_network`, never a pass).
- [ ] BLOCKED — full fresh replay of v1/v3.2 PoCs on this machine:
  `work/repos` and `V3/clones` content absent (E-13). Owner: maintainer
  with the pinned clone trees
  (`python scripts/fetch_sources.py` then `run_gates.py`).

## Phase 7 — independent validation and rights

- [x] DONE — blinded annotation study is prepared: sample frozen
  (`iaa-draw-1.0`, n=300, seed=20261018), templates match, adjudication
  rules written (`annotation/iaa_v1/`, `docs/HANDOFF.md` §1).
- [ ] BLOCKED — two independent qualified reviewers must complete it;
  `measured=False` until then (E-11). No fabricated responses anywhere.
- [ ] BLOCKED — outbound licence-clearance requests (E-12,
  `docs/HANDOFF.md` §2). Unresolved rights remain unresolved; the
  rights-redacted distribution keeps its disclaimer.

## Phase 8 — reproducibility and release

- [x] DONE — full local suite + gates run in the documented environment
  (results below). Genuine skips labelled; no failure converted to a skip.
- [x] DONE — independent semantic checks that can fail when generator and
  report agree: pointer-hash recomputation, K-Q byte-rebuild comparison,
  cross-version float-aggregation pins, fresh-clone render tests (E-2, E-7,
  E-8, E-15).
- [ ] BLOCKED — representative model evaluations on frozen sets (needs
  model access/compute; not available here). Owner: evaluation team. The
  protocol and baselines are ready (`docs/RUBRIC.md`, `docs/ANSWER_KEY.md`,
  `reports/baselines/`).
- [x] DONE — release manifest, dataset card (DATASHEET), correction
  history (CHANGELOG), excluded/blocked lists exist and regenerate.

## Before / after

| measurement | before (`cb6a2a8`) | after (this pass) |
|---|---|---|
| `python scripts/validate.py` | 76/78, 2 critical (v2.2 pointers, K/Q rebuild) | 78/78, 0 critical, 0 warnings |
| `python scripts/run_gates.py` | 52 gates: 37 pass / 6 fail / 9 skipped | **52 gates: 43 pass / 0 fail / 9 skipped** — same 9 environment skips as baseline (networked builds, absent `V3/clones`/`work/` inputs), none converted |
| `python -m unittest discover -s tests` | 704 tests, 2F + 1E + 19S | **718 tests, 0F + 0E + 19S** — same 19 environment skips; every fix carries regression tests (14 new: 3 fsum, 3 catalog machine-independence, 2 prove_grader resolution, 2 fresh-clone report rendering, 4 v2.2 pointer-drift net) |
| v2.2 pointer hashes vs derived records | 37 mismatched | 0 mismatched |
| K-Q rebuild vs committed task files | refuse (37 problems) | byte-identical (7 families) |
| `benchmark/manifest.json` `families` | missing Fa/Fb | `sorted(tasks)` incl. Fa/Fb |
| baselines reproducible on 3.10–3.13 | no (1-ULP drift) | yes (`math.fsum`) |
| `build_repro_report.py --check` without local snapshot | FAIL | PASS |
| catalog entries | 775 (2 machine-local) | 774 (committed corpus only) |
| README F-extension wording | "0 scorable" only | both measurements named |
| release manifest | stale (469 released) | reproducible (475 released / 1,347 not released) |

After-state commands (run at the end of this pass; logs in
`work/baseline_runs/`):

```bash
python scripts/run_gates.py        # after: gates=52 pass=43 fail=0 skipped=9, exit 0
python -m unittest discover -s tests  # inside the unit-tests gate: OK (skipped=19)
python scripts/validate.py --quiet # after: 78/78 checks passed; BUILD OK
```

## Separate assessments (they do not average into a score)

1. **Training quality — modest, honest.** Training exports are
   provenance-tagged and task-shaped; coverage of deep fields (root cause,
   attack sequence, impact, fix description) is ~0% in v3/Vbeta and ~2% in
   v1 findings — thin supervision for generative security tasks. Usable for
   classification/contrastive training with the documented caveats; not a
   substitute for execution-grounded pairs (which exist only in the
   reNFT/1inch/v3.2 sets).
2. **Benchmark validity — no defensible headline track yet.** Family A
   (720 rows) is INVALID until its identical-input gold conflicts and
   missing-code rows are repaired (E-1); no family currently qualifies as
   PRIMARY. Everything else is exploratory, invalid, retired or judge-graded
   by rule. Shortcut floors are published; F-A/F-B are honestly scoped
   (E-6). Defensible as a *diagnostic corpus*; not as a leaderboard.
3. **Executable grounding — strong where it exists, small.** The
   two-revision contract is well enforced (stage ladder, artefact digests,
   same-test identity). Coverage is the limiting factor (9 reNFT findings +
   1inch + 4 v3.2), and full replay on a fresh machine is blocked on the
   pinned clone trees.
4. **Redistribution readiness — release export is mechanically clean,
   legally un-cleared.** `RELEASE_MANIFEST.json` reproduces; rights gates
   pass; but licence clearance for third-party report prose is BLOCKED
   (E-12) and the rights-redacted distribution keeps its disclaimer. Do
   not describe any export as legally cleared.

Honest ceiling without the blocked workstreams: **~8/10** as a training
corpus and diagnostic benchmark; **not** a vendor-ready evaluation
benchmark and **not** a legally cleared distribution. Do not claim 10/10.

## Remaining blockers, owners, evidence needed

| # | blocker | owner | exact evidence needed to close |
|---|---|---|---|
| 1 | family A contradictory gold (E-1) | dataset maintainers | claim-level re-adjudication of the 14 groups against source records; rebuilt family file + manifest via owner scripts |
| 2 | V4 ToC extraction (E-9) | extraction maintainers | annotated source spans on a risk-based sample; re-extraction report with field-level correctness |
| 3 | AI export audit (E-10) | operator | the `ai/` export files; then repetition/provenance/overlap audit |
| 4 | human IAA (E-11) | 2 qualified reviewers | filled blinded templates for `iaa-draw-1.0`; adjudication log; agreement metrics with intervals |
| 5 | licence clearance (E-12) | maintainers ↔ rights-holders | written permission per source family, or permanent exclusion from redistribution |
| 6 | fresh PoC replay (Phase 6) | maintainer with clones | `work/repos` + `V3/clones` populated; `run_gates.py` with rebuild-parity executed |
| 7 | model evaluations (Phase 8) | evaluation team | per-task results vs the six baselines, with calibration/abstention on frozen sets |
| 8 | Ethereum archive RPC key (historical improve.md blocker) | funding/operator | a funded archive node key for historical-state execution |

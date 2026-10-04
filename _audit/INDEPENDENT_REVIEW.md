# Independent external review — `vlun-data` v2.1

Reviewer: external validation, no prior involvement with the dataset.
Target: commit `93af4b9` ("v2.1: experimentally proven exploits, verified patches, immutable citations")
Date: 2026-10-04. Environment: Windows 11, Python 3.12.10, Node 22.x, Foundry (`forge`) present,
`slither` absent, network partially available.

Every number below was produced by code in `_audit/` that does **not** import the repository's own
scripts, except where explicitly labelled "author's report". Raw outputs are in
`_audit/*.out.txt`.

---

## VERDICT

| Dimension | Score | One-line justification |
|---|---|---|
| Data quality (evidence layer) | **6/10** | `jsonl/` is genuinely provenance-preserving and internally consistent, but 52% of derived records fail a derived-fact-needs-a-source-ref check, and 432/722 records have no attacker model. |
| Reproducibility | **2/10** | A clean offline rebuild changes **376 of 722 records**, 2 stages fail while the build still exits 0, and the benchmark regenerates with different scorable counts. The "deterministic and reproducible" claim is false. |
| Benchmark validity | **3/10** | 4,109 tasks but **no scorer, no rubric, no baseline, no answer-key spec**; 62% of tasks are unscorable; the majority-class baseline scores 86.0% on validation. |
| Trustworthiness of claims | **3/10** | The single headline v2.1 claim ("mutable citations: 0") is false in the data and is certified by a check that reads the resolver's own report. Three further headline numbers are wrong. |
| **Overall** | **4/10** | Real underlying data and real experimental work, wrapped in a metrics layer that is partly unverified, partly wrong, and in one central case certified circularly. **Not vendor-ready.** |

The repository is *not* worthless. The `jsonl/` evidence layer and the M-11 EIP-712 experiment are
genuinely good work. The problem is that the v2.1 metrics layer overstates what was verified, and
the validation gate is structurally incapable of catching it.

---

## CONFIRMED CLAIMS (independently reproduced)

| Claim | README says | I computed | Verdict |
|---|---|---|---|
| Record counts | records 722, negatives 458, findings 264, exploits 155, patches 38, protocol 8, metadata 11, errors 19 | identical | **confirmed** |
| Unknown attacker identity | "432 of 722 records have an `unknown` attacker identity" | `unknown: 432`, unprivileged 143, privileged 133, malicious_dependency 11, honest_but_misconfigured 3 | **confirmed exactly** |
| PoCs never run | "140 of 155 were never run" | `verification_stats.json` totals `not_executed: 140` | **confirmed** |
| PoCs executed | "15 of 155" | `reproduced 5 + not_reproduced 2 + inconclusive 8 = 15` | **confirmed** |
| PoCs demonstrating impact | "**5** of 155" | `reproduced: 5`; `noya 4 + panoptic 1` | **confirmed** |
| Patch effectiveness | "5 of 38 patches experimentally confirmed effective; 33 not_testable" | `l6_verified_patch: 5`; 9 experiments, 5 verdict `l6_verified_patch`, 4 `inconclusive` | **confirmed** |
| API-sibling pairs | 71 | `total api_sibling_pairs = 71` (30 records carry them) | **confirmed** |
| Records with a counterexample | 43 | 43 of 63 rows populated, 99 counterexample entries | **confirmed** (see minor note) |
| Negatives honestly unknown | 227 | `by_class.unknown = 227` | **confirmed** |
| Negatives with a defensible reason | 231 | `attributed 9 + corroborated_duplicate 221 + derived_from_code 1 = 231` | **confirmed arithmetically — see REFUTED-6 for why this headline misleads** |
| Severity fidelity | findings correctly carry report severity | 0/30 sampled records disagreed with `jsonl/findings.jsonl` | **confirmed** |
| M-11 experiment is real and discriminating | "a patch is called *effective* only when the violation is observed on one and blocked on the other" | byte-identical harness (sha256 `CDB04D72…`) run at both revisions; vulnerable 3 fail / 1 pass, fixed 4/4 pass | **confirmed — this is the strongest artefact in the repo** |

---

## REFUTED CLAIMS

### REFUTED-1 — "Mutable branch citations: 453 → **0**" is FALSE, and the check that certifies it is circular
*Severity: critical. This is the headline v2.1 claim.*

- README limitation #6: *"All 473 occurrences are now pinned to an exact commit… the count is 0."*
- **Actual data:** `derived/records.jsonl` still contains **471** `commit_sha` values equal to
  `main`/`master`, across **172 of 722 records**, in three fields:
  `code_context` (248), `code_context_expanded` (114), `code_reference_only` (109).
  The read-only `jsonl/` layer has 452. **923** `/blob/` URLs across the corpus are pinned to a branch.
- **Root cause:** `scripts/resolve_citations.py:665` reads `derived/records.jsonl`, and its only output
  path is `--out reports/citation_resolution.json` (line 662). **It never writes the resolved SHAs back
  into the data.** It produces a side report proposing the fix and leaves the dataset unchanged.
- **Proof on one record.** `citation_resolution.json` for `2024-04-noya/H-03` /
  `NoyaValueOracle.sol` says `original_reference: main → resolved_commit: cc3854f6…`, `status: resolved`.
  The actual record in `derived/records.jsonl` still carries:
  `commit_sha: main`, `source_url: …/blob/main/contracts/helpers/valueOracle/NoyaValueOracle.sol`.
- **The certifying check is circular.** `validate.py:563` reads
  `left = cites.get("remaining_mutable_occurrences")` from `citation_resolution.json` — the report
  written by the very resolver it is supposed to police — and never inspects `derived/records.jsonl`.
  Meanwhile the check that *does* read real data, `provenance/commit_pins_are_immutable`, **fails with
  453 failures** and is marked `critical=False`.
- **The gate still exits 0.** `python scripts/validate.py` → `51/52 checks passed; 0 critical failures,
  1 warnings` / `BUILD OK`, exit code 0, despite that failing provenance check.

### REFUTED-2 — "Every script is idempotent, … `derived/` deterministic and reproducible" is FALSE
*Severity: critical.*

Clean-room rebuild of the committed tree (fresh copy, offline, `python scripts/build_all.py`):

- **376 of 722 records (52%) change content.** Same IDs, different bytes.
  Fields that change: `quality` (376), `code_context_expanded` (302), `attacker_model` (237),
  `dependency_graph` (230), `license_classification` (226), `redistribution` (226),
  `original_evidence` (155), `verification` (155), `evidence` (130).
- **Two stages fail and the build still reports success:**
  `build_all.json → {'failed': 2, 'ok': 14, 'skipped_no_network': 6}` —
  `verify_patches.py: failed`, `build_reproduction.py: failed`. `build_all.py` exits **0**.
- **11 of 16 key artefacts differ** after rebuild, including `derived/records.jsonl`,
  `derived/counterexamples.jsonl`, `benchmark/C_attacker_reasoning.jsonl`,
  `benchmark/E_exploit_verification.jsonl`, `README.md`, `NOTICE.md`,
  `reports/dataset_stats.json`, `reports/v2_1_summary.json`.
- **The benchmark silently shrinks:** `benchmark_scorable_tasks` 1389 → **1294**;
  family C scorable 290 → 202; family E scorable 7 → **0**.
- **`datasets/verified_findings.jsonl` rebuilds to an empty file** (sha256 `e3b0c442…` = empty string).
  The "high-confidence subset" evaporates without the network stages.
- **The gate cannot tell the difference:** `reports/validation_report.json` is **byte-identical**
  before and after. Same verdict on a materially different tree.

Concrete instance of the information loss, `2024-04-noya/H-01`:

| field | committed | clean offline rebuild |
|---|---|---|
| `verification.verdict` | `reproduced` | — |
| `verification.evidence_type` | `experimentally_verified` | `unknown` |
| `verification.reason` | forge `Success`, `test_assetTokenValueIsIncorrectWhenETHUSDChainlinkOracleIsNeeded` | `"no exploit row for this finding, so no PoC was executed"` |
| `quality.dynamic_verification` | `reproduced` | `not_attempted` |

### REFUTED-3 — "pinpoint exploit experiments run **the same test** against the audited revision and the fixing revision" is FALSE for 1 of the 5 verified patches
*Severity: high.*

From `result.json`, the two commands per experiment:

| finding | vulnerable command | fixed command | same test? |
|---|---|---|---|
| `2024-01-renft/H-01` | `--match-path test/vlun_poc/VlunMaliciousSeaportTip.t.sol` | `--match-path test/vlun_poc/integration__prevented-exploits__MaliciousSeaportTip.t.sol` | **NO** |
| `2024-01-renft/H-03` | `…/integration__prevented-exploits__BypassInvariantChecks.t.sol` | same path | yes |
| `2024-01-renft/H-04` | `…/integration__Exploits.t.sol` | same path | yes |
| `2024-01-renft/M-09` | `…/integration__guarded-transactions__Safe.t.sol` | same path | yes |
| `2024-01-renft/M-11` | `--match-test test_VlunEip712` | `--match-test test_VlunEip712` | yes (byte-identical harness) |

H-01 runs an author-written harness on the vulnerable side and the reporter's regression test on the
fixed side. That is not a controlled comparison, and `validate.py`'s
`v2.1/effective_patch_has_vulnerable_fail_and_fixed_pass` only compares **status strings**, so it
cannot detect this.

Second, the four non-M-11 "verified" experiments fail with `next call did not revert as expected`
(except M-09: `[FAIL: GuardPolicy_FunctionSelectorRequired()]`). That demonstrates **guard presence /
absence**, not impact. No funds move and no state is shown corrupted. The README's "Vulnerabilities
with an observed violation at the audited commit: 5" is generous; only **M-11 shows a semantic
security-property violation with concrete digests**.

### REFUTED-4 — "Code that must not be redistributed is **not** in this repository" is FALSE
*Severity: critical (legal).*

- No `LICENSE` file exists (`ls` for `licence/license/copying` at root → **none**). GitHub therefore
  treats the dataset as unlicensed.
- README: *"The dataset redistributes only code whose licence permits it."*
- The dataset's **own** field contradicts this: `redistribution.flag =
  source_redistributed_without_declared_license` on **424 of 722** records.
- Independent check (my regex, not the repo's classifier): **400 of 722** records contain Solidity
  source text in `code_context`/`code_context_expanded`; **696** citation entries exceed 200 chars.
- Deterministic 20-record sample of flagged records: **19 of 20 contain verbatim function bodies**
  from repositories whose `license_classification` is `unknown`. Examples:
  `2024-01-decent/H-03` (1,338-char `bridge()`), `2022-05-alchemix/M-17` (2,176-char `repay()`),
  `2024-04-noya/submission-1296` and `2024-04-noya/submission-751` (identical 2,302-char
  `executeWithdraw()`).
- **346 records carry PoC source text.** SPDX scan of that text: 329 no header, 3 `UNLICENSED`,
  4 `BUSL-1.1`, 4 `Unlicense`, 3 `MIT`, 3 `Apache-2.0`. These are Code4rena **submission authors'**
  code, redistributed without licence metadata.
- The repo's own original harness code is SPDX `BUSL-1.1`
  (`experiments/*/harness/VlunEip712.t.sol`, `VlunMaliciousSeaportTip.t.sol`) — a source-available
  licence, inconsistent with "redistributes only code whose licence permits it", and with no LICENSE
  file there is no grant for a downstream user.

**What is actually true** (and should be said instead): *some* citations were withheld and replaced by
path+commit+line-range+sha256 resolvable via `scripts/fetch_sources.py`. Withholding was partial, not
complete.

### REFUTED-5 — Split counts are wrong
*Severity: medium.*

README: `train 415 / validation 277 / test 253 / quarantined 2`.
Actual `splits_v2/`: **train 413**, validation 277, test 253; quarantine 2. `413+277+253 = 943`,
`+2 = 945 = 415+277+253`. The README counted the 2 quarantined records inside the train figure while
also listing them separately. `train.jsonl` contains 2 repos (`2022-05-alchemix` 72, `2024-04-noya` 341).

### REFUTED-6 — "Negatives with a defensible reason: 231" is technically true but materially misleading
*Severity: medium.*

`by_class = {attributed 9, corroborated_duplicate 221, derived_from_code 1, unknown 227}`.
**221 of the 231** are `corroborated_duplicate` — i.e. "this claim was valid but someone else already
filed it." That is not a reason the claim fails to reproduce; it is a note that the claim was right.
The honest code-grounded-rejection figure is **1**. The README does disclose that a corroborated
duplicate "is explicitly not a false positive", which is commendable, but the headline table still
counts them as "defensible reasons".

Also: the four-class taxonomy (`negative_class`) **does not exist in the shipped data**. All 458 rows
of `derived/hard_negatives.jsonl` have `negative_class: None` and `rejection_basis: None`. The
classification lives only in `reports/negative_verification_stats.json`. A consumer of the dataset
file cannot see it.

### REFUTED-7 — "`invariants: []` for 35 of 264 records is the intended outcome" understates by 4.4×
*Severity: medium.*

Computed: **155 of 264** `findings.jsonl` records have `security_reasoning.invariants == []`.

### REFUTED-8 — Methodology note in `verified_experiments.json` for M-11 is false
*Severity: low, but it is a factual claim about method.*

Note reads: *"The fixed revision's Signer.sol is read at execution time to decide which assertion is
expected to hold."* The two harness copies are **byte-identical**
(sha256 `CDB04D7296E31D241A80A0011F37570109D8EF1A327800226E9EB9749A580F92`) and contain no such read —
the polarity is hard-coded in three static test functions. The experiment is sound; the note describing
it is not.

---

## NEW ISSUES FOUND (the author's own gate missed these)

### NEW-1 — The gate's evidence checks pass **vacuously** on a fresh clone · critical
`validate.py`'s `evidence/experimental_claims_have_a_run_artefact` and
`evidence/every_reproduced_verdict_names_a_forge_status` iterate `WORK / "poc_runs"`, i.e.
`work/poc_runs/*.json`. `work/` is git-ignored (`.gitignore` line for `work/`; `git ls-files work/`
→ **0 tracked files**). On a fresh clone that glob is empty, so both checks pass with nothing to
check. The README states *"The gate fails if any record claims `experimentally_verified` without a run
artefact behind it."* It does not, on a fresh clone.

### NEW-2 — The 5 reproduced PoCs have **zero committed artefacts** · high
`derived/records.jsonl` marks 7 records `experimentally_verified` with named forge tests:
`2024-04-noya/H-01`, `H-19`, `M-07`, `M-33`, `M-34`, `M-37`, and `2025-06-panoptic/H-01`.
The committed `experiments/` directory contains **only** `2024-01-renft__*` (12 dirs). There is **no**
experiment directory for any NOYA or Panoptic finding. Those 7 test names appear **nowhere** in
`jsonl/exploits.jsonl`, `reports/verification_stats.json`, `reports/reproduction_stats.json`, or
`experiments/reconstruction_log.jsonl`. They exist only in the author's git-ignored `work/poc_runs/`.
So the "5 of 155" headline — the most valuable claim in the dataset — is **unverifiable by any third
party**. The evidence is probably genuine (the tallies are internally consistent), but it is not
publishable evidence.

### NEW-3 — `check_leakage.py` audits a projection that has discarded the leakage · high
`check_leakage.py:377` defaults to `--input splits` and audits those rows. `splits_v2/*.jsonl` is a
thin projection that keeps only **15–18 of 26** top-level record keys. Dropped from every split row:
`attacker_model`, `code_context_expanded`, `code_reference_only`, `dependency_graph`, `evidence`,
`invariants`, `license_classification`, `original_evidence`, `quality`, `redistribution`,
`security_state_transition`, `taxonomy`, `verification`.

Consequence, measured: **811 of 811 external (third-party) citations were dropped**, and
`external citations surviving into splits_v2/: 0`. Therefore all ten author detectors —
exact, code, near-duplicate, semantic, patch-diff, fixing-commit, PoC-body, root-cause,
attack-sequence, protocol-isolation — are **structurally incapable** of detecting leakage via shared
third-party dependencies, vulnerability class, attacker model, or any v2.1 enrichment field.

### NEW-4 — Real cross-split third-party dependency leakage · high
My independent detector (`_audit/dependency_leakage.py`) found:

- `aave/aave-v3-core/contracts/protocol/libraries/logic/ValidationLogic.sol` is cited from
  **`2024-04-noya/M-21` and `2024-04-noya/submission-431` (TRAIN)** at commit `724a9ef43adf`, and from
  **`2024-12-bakerfi/M-12` (TEST)** at commit `782f51917056`.
  Same upstream file, **train ↔ test**. Exact `(file, commit)` match across splits: **0**, so the
  verbatim-blob overlap is unproven — but the architectural dependency is shared and, per NEW-3,
  invisible to the author's detectors.
- Other cross-split external repos: `Uniswap/v3-periphery` (renft↔decent, both validation),
  `OpenZeppelin/openzeppelin-contracts` (noya↔alchemix, both train). Not cross-split, but they show
  the pattern is systemic.

### NEW-5 — Concept-level leakage the detectors cannot see · high (validity threat)
`_audit/leakage_pro.py`, five detectors the author does not have:

- **train↔test vulnerability-class Jaccard = 0.625.** 62 distinct taxonomy classes appear in more than
  one split; only **2** classes are train-only; only 7 test classes are absent from train.
  A model trained on `train` has been taught the concept of ~63% of `test`'s class vocabulary.
  Stated fairly: this is *not* instance contamination — it is what a security-reasoning dataset is
  for. But it means **no score from this benchmark can be read as novel-vulnerability discovery**
  unless a class-disjoint protocol is also reported. The repo reports no such protocol.
- **18 submitters span splits**, including `alexczm` and `benrai` in **train and test**, and
  `0xpiken` in validation and test. (`c4-bot-*` are Code4rena bot accounts, not human style leakage.)
- Contract-name collision across train↔test: `ValidationLogic`. Function-name collisions: `burn`,
  `executeDeposit`, `mint`.

### NEW-6 — `derived_fact` values shipped with empty `source_refs` · high
README defines `derived_fact` as *"computed here by a rule that lives in the code"*.
In a deterministic 30-record sample I found **50** such fields with a **non-null value but
`source_refs: []`** — concentrated in `attacker_model.attacker_identity`,
`attacker_model.required_cross_contract_state`, and `evidence.record_confidence`. The
`attacker_identity` `rule` field is the *same* full decision-table string for all records
(`"role modifier present -> privileged; tx.origin authorisation -> honest_but_misconfigured; …"`),
so it does not identify which branch fired. A curator cannot audit which rule produced a label.
`validate.py`'s `evidence/evidence_type_in_closed_vocabulary` only tests vocabulary membership.

### NEW-7 — Benchmark cannot be scored as shipped · critical for a data buyer
- **No scoring script exists.** No `score*`, `evaluate*`, `baseline*`, `rubric*`, or `predict*` file
  anywhere outside `work/`. `reports/benchmark_metrics.json` openly states
  *"metrics that need a predictor are reported as not measurable rather than estimated."*
- **No dependency manifest**: no `requirements.txt`, `pyproject.toml`, `setup.py`, `environment.yml`.
- **No answer-key format specification**, no rubric for the free-text families.
- **62% of tasks are unscorable** (2,720 of 4,109): `unlabeled`/`unscorable`/`partial`.
  Per family: `B_root_cause_reasoning` **0 scorable** of 720 (416 partial + 304 unscorable);
  `G_patch_verification` **0** of 38; `E_exploit_verification` **7** of 720;
  `F_false_positive_rejection` 15 of 458, of which **9 have `blocking_condition: null`**
  (a model scores by answering nothing); `C_attacker_reasoning` 290; `D_exploit_construction` 346;
  `A_vulnerability_detection` 720.
- **Family A barely discriminates.** Positive rate swings across splits:
  train 96/344 = **27.9%**, validation 32/229 = **14.0%**, test 66/147 = **44.9%**.
  Always-answer-`no_confirmed_vulnerability` scores **0.721 / 0.860 / 0.551**.
  Any published score near 86% on validation is uninformative.
- **The three "experimentally grounded" families the README highlights cannot discriminate and have
  no test split.** All of `H_verified_exploit` (5), `I_verified_non_exploit` (3), `J_verified_patch` (5)
  are **`validation` only — zero test tasks**. `I` has 1 scorable task, single class → majority
  baseline = 100%. `J` has 5 scorable tasks, **all one class** (`effective` / `pass` / `fail`… with
  `fixed_revision_result: pass`) → majority baseline = 100%. `H` is free-text with no rubric.
- `benchmark/manifest.json` reports `answer_key_evidence_levels: {not_recorded: N}` for every family —
  the evidence-level metadata the README advertises is unpopulated.
- **Good:** no answer-string leakage detected (0/720, 0/290, 0/346, 0/7, 0/15, 0/5, 0/1, 0/5).

### NEW-8 — Split schema loss breaks downstream tooling · medium
Because `splits_v2/*.jsonl` drops `taxonomy`, `attacker_model`, `evidence`, `quality`, `invariants`,
`security_state_transition`, and `license_classification`, a consumer who takes the *splits* as the
product (the obvious choice) silently loses the entire v2/v2.1 enrichment — including the licence
classification. `derived/records.jsonl` is the only complete artefact.

### NEW-9 — `slither` is an undeclared hard dependency · medium
Stage 12 `run_static_analysis.py` requires `slither`, which is not installed here and is not declared
anywhere. The README claims "5 analysed, 1 reported unanalysable" from that stage.

### NEW-10 — Numbers inconsistent inside the README itself · low
Limitation #6 says "453 code citations used to pin a branch name" then "All **473** occurrences are
now pinned". Both refer to the same set. Separately, the corpus contains **923** branch-pinned
`/blob/` URLs and 452–471 mutable `commit_sha` values depending on layer.

---

## PHASE 3 — PoC VERIFICATION (with `VLUN_RPC_URL` unset; could not supply an archive endpoint)

I could not obtain a public archive RPC endpoint in this environment, so I could **not** re-run the
140 unexecuted PoCs. Stating that plainly rather than inferring a result.

What I could verify independently, from committed artefacts:
- Totals are internally consistent: 5 reproduced + 2 not reproduced + 8 inconclusive + 140
  not executed = 155.
- **Compile rate:** `poc_compilation_rate = {repos_attempted: 8, repos_compiled: 4,
  poc_files_materialised: 20, poc_files_skipped: 133}`. Only 20 of 153 PoC files were even
  materialised. Per-repo `compile_rc`: renft `null` (never attempted), wildcat/bakerfi/gte-perps `1`
  (fail), alchemix/decent/noya/panoptic `0`.
- **Classification of the 4 "inconclusive" experiments — all are harness/toolchain, not stale pins
  and not wrong findings.** In every case the *fixed* revision passed and the *vulnerable* revision
  failed to **compile**, with a specific named cause, not a shrug:
  - `H-06`: `Error (7576): Undeclared identifier` in `integration__prevented-exploits__PreapproveToBypassGuard.t.sol`
  - `M-01`: `erc1155s[0].mint(...)` — argument mismatch in `integration__guarded-transactions__ERC1155.t.sol`
  - `M-02`: `bytes32 msg…` type error at line 178 of `integration__prevented-exploits__PermitTokens.t.sol`
  - `M-08`: `Error (6160): Wrong argument count for function call: 2 arguments given` in `…__ERC721.t.sol`
  These are fixture drift between the audited and fixing revisions — the README's
  "reconstruction ceiling on fixture drift" is an accurate diagnosis.
- **M-11 is the one experiment I could fully corroborate** without the withheld source: byte-identical
  harness, 4 tests, vulnerable 1 pass / 3 fail, fixed 4 pass, with a deliberate
  `test_VlunEip712_EncodingsDiffer` control that prevents a vacuously-true assertion, and it reads real
  protocol state by inheriting `Signer` rather than re-implementing hashing. This is the methodology
  the other eight should aspire to.

---

## CRITICAL BLOCKERS (must be fixed before this dataset is sold or listed)

1. **Add a `LICENSE`.** Absent today. Without it there is no grant, and GitHub reports the repo as
   unlicensed. For a data vendor this alone is disqualifying.
2. **Resolve the licence conflict.** 424 records self-declare
   `source_redistributed_without_declared_license`; 400 contain Solidity source; 346 carry third-party
   PoC code. Either strip the text (keep path + commit + line range + sha256 + a fetch script) or
   obtain redistribution rights. The README's current sentence must be replaced with the true one.
3. **Stop claiming "mutable citations: 0".** It is 471 in the derived layer and 923 branch-pinned URLs
   in the corpus. Either make `resolve_citations.py` actually write the resolved SHAs back into
   `derived/records.jsonl` (the information already exists in its own report), or retract the claim.
4. **Make the gate able to fail.** `commit_pins_are_immutable` fails with 453 problems and is
   `critical=False`; `build_all.py` exits 0 with 2 failed stages; `no_mutable_branch_citations_remain`
   reads the resolver's own report. Rewrite that check to count mutable refs in
   `derived/records.jsonl` directly, make it `critical=True`, and make `build_all.py` exit non-zero on
   any stage failure.
5. **Ship the run artefacts for the 5 reproduced PoCs.** They are the most valuable claims in the
   dataset and currently exist only in git-ignored `work/`. Commit hashed `command/stdout/stderr/result`
   for `2024-04-noya/H-01`, `M-07`, `M-34`, `M-37`, `2025-06-panoptic/H-01` as `experiments/` already
   does for reNFT.
6. **Ship a scorer.** Add `scripts/score_benchmark.py`, an answer-key format spec, a rubric for the
   free-text families, and at least two reference baselines (majority-class and retrieval) with their
   scores printed. Without these a buyer cannot produce a single number.
7. **Fix the two structural reproducibility breaks:** commit the `work/poc_runs` verdicts (or a hashed
   summary under `reports/`), and make the 6 network stages' outputs explicit inputs so an offline
   rebuild reproduces byte-identical artefacts. Today 376/722 records change.

---

## RECOMMENDED ACTIONS (prioritised)

**P0 — credibility, do before listing**
1. Add `LICENSE` (CC BY 4.0 for the data, MIT for `scripts/`, and keep PoC/harness text under its
   original licence with per-file SPDX + a `THIRD_PARTY_LICENSES.md`).
2. Rewrite the licensing section honestly: state that 424 records contain redistributed source from
   unlicensed repositories and are flagged, and either remove that text or license it.
3. Correct the four wrong numbers: train 415→413, invariants 35→155, "negatives with a defensible
   reason 231"→ break out `1 derived_from_code / 9 attributed / 221 corroborated duplicate`,
   "mutable citations 0"→ the real count.
4. Add `requirements.txt` + `pyproject.toml`; declare `slither` as an optional extra and degrade
   stage 12 gracefully.

**P1 — make the claims true**
5. Make `resolve_citations.py` write resolved SHAs back into `derived/records.jsonl`, then re-run
   `validate.py` and let `commit_pins_are_immutable` pass for real.
6. Make `commit_pins_are_immutable` critical and computed over `derived/` as well as `jsonl/`.
7. Delete or rewrite `no_mutable_branch_citations_remain` — a check that reads its subject's own report
   should not exist.
8. Make `build_all.py` exit non-zero if any stage fails; make `validate.py`'s evidence checks report
   `skipped_no_workdir` rather than `ok` when `work/poc_runs` is absent.
9. Commit run artefacts for the 5 reproduced PoCs (NEW-2).
10. Re-run H-01 as a controlled same-test comparison, or downgrade it from L6.

**P2 — benchmark integrity**
11. Write `scripts/score_benchmark.py` + `docs/ANSWER_KEY.md` + `docs/RUBRIC.md`.
12. Publish the two baselines I computed: family A majority-class = 0.721/0.860/0.551 by
    train/validation/test. Any family-A result must be reported against that floor.
13. Re-balance or re-split family A, or document the per-split positive rate next to every score.
14. Add test-split tasks to H/I/J, or state plainly that the experimental families are validation-only
    case studies, not benchmarks.
15. Reduce family B's 304 `unscorable` rows or drop the family; a "root cause reasoning" benchmark
    with zero complete labels should not be advertised as a benchmark family.
16. Populate `answer_key_evidence_levels` instead of `not_recorded`.

**P3 — leakage**
17. Re-point `check_leakage.py` at `derived/records.jsonl`, not `splits/`. Adopt
    `_audit/dependency_leakage.py` and `_audit/leakage_pro.py` as `scripts/check_leakage_conceptual.py`.
    Add detectors for: taxonomy-class overlap, shared external dependency target, submitter overlap,
    contract-name and function-name collision. Publish the train/test class Jaccard (0.625) as a
    stated limitation and ship a **class-disjoint** secondary split so a buyer can measure
    novel-concept generalisation separately.
19. Adjudicate the `aave/aave-v3-core` train↔test overlap (NEW-4).
20. Keep `splits_v2/` schema loss (NEW-8) but document it, or ship a fat split.

**P4 — dataset depth (where real value still is)**
21. The honest gaps are large and worth funding: 140/155 PoCs never executed; 432/722 attacker models
    unknown; 259/264 `root_cause` fields empty; 44/264 `summary` and 44/264 `broken_behavior` empty;
    155/264 with empty `invariants`; 7138 `unknown` evidence values vs 2556 `reported_claim`.
    Publishing *coverage* metrics per field would let buyers price the dataset honestly, which is
    worth more than raising headline numbers.
22. The `M-11` harness methodology (inherit the real contract, hard-coded polarity, include a
    vacuous-truth control) is the right pattern — extend it to more findings rather than adding more
    redaction/withholding machinery.

---

## WHAT I COULD NOT VERIFY

- Whether the 5 reproduced PoCs genuinely reproduced on a real run. The run artefacts are git-ignored
  and I had no archive RPC. The tallies are internally consistent and the 9 reNFT pinpoint experiments
  are corroborated by committed artefacts, so I believe the pipeline is honest — but I cannot
  attest to the NOYA/Panoptic runs.
- `slither` static-analysis results (stage 12), because `slither` is not installed.
- Whether the resolved commit SHAs in `citation_resolution.json` actually contain the cited content.
  All 473 are well-formed 40-hex and use plausible methods
  (`blob_identity_first_commit` 464, `submodule_pointer_at_audit_snapshot` 5,
  `date_anchored_blob_identity` 4; confidence high 429 / medium 44) — but
  `blob_identity_first_commit` resolves to the **first commit that introduced a blob**, which is
  generally *earlier* than the audited revision. Verifying this needs the repositories cloned, which
  the network stages would do.
- Semantics of the 20 sampled hard negatives and 10 counterexample sets against the live Code4rena
  reports. I verified internal consistency and that 18/20 honestly declare a null blocking condition;
  I did not fetch the upstream audits.
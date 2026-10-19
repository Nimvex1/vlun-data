# Derivation log — how `root-cause-1.0` was built from the 40 candidates

This vocabulary is **project-local**. It has not been proposed to, reviewed by, or
adopted by anyone outside this repository. It is therefore **not a community standard**
and must never be described as one. Only the SWC and CWE identifiers it maps to are
external, and each of those maps carries its own justification or an explicit `no_map`.

## 0. The starting point was not a taxonomy

`derived/root_cause_candidates.jsonl` holds **40 rows** (verified: `wc -l` = 40, 40 unique
`record_id`s, all present in `derived/records.jsonl`). Every row carries:

- `"rule": "verbatim first-two-sentences quote of finding.summary; candidate, not verified cause"`
- `"evidence_type": "reported_claim"`, `"source": "jsonl/findings.jsonl (row unmodified)"`.

So the list is, by its own metadata, **unverified quoted prose**. It is not a validated
taxonomy, not a vocabulary, and not evidence that any stated cause is correct. Six of the
40 are not even cause sentences — their text begins with the `< <` quote artefact left over
from the upstream report, and one (`2024-01-renft/H-05`) is an editorial lead-in that says
"this report takes advantage of multiple bugs" and names none of them.

**This log is the validation step.** Each candidate was read against the record's own
`code_context`, `security_reasoning`, `verification` and `patch` blocks; where the prose
asserted a cause that citable material could not support, the candidate was rejected rather
than dressed up as a label. Nothing in the vocabulary is inherited from the candidate file
by default.

Also checked for pre-existing vocabulary: `schema/evidence-vocabulary.json` (evidence types,
levels L0-L6, negative classes — no cause list), `scripts/taxonomy.py` (the C4
`category -> family -> class -> subtype` overlay, which is a *class* hierarchy, not a cause
hierarchy), `docs/RUBRIC.md` (family B is scored only on `invariant_stated`; the rubric
itself says B's root-cause prose is judge-graded), `reports/patch_verification_v2.json`
(`fix_category_vocabulary`, which names what a *fix* changes: authorization,
input_validation, state_update, accounting, …). There was no earlier root-cause taxonomy to
extend, and `reports/` contains no `root_cause*` file other than the candidates themselves.

## 1. Splitting the four axes first

Before grouping anything, each candidate sentence was sorted into cause / impact / primitive
/ component. Most of the 40 do not state a cause at all in their first two sentences:

| candidate | what its sentence actually names | axis |
|---|---|---|
| `2024-01-decent/H-01` | "allows malicious users to get access to the mint and burn functions" | impact, from which the cause (no gate on the setter) is inferred |
| `2024-01-renft/H-06` | "The Escrow contract … can be completely drained" | impact |
| `2024-04-noya/H-04` | "tokens have a contract-level admin controlled blocklist" | external fact; cause inferred (unchecked callee failure) |
| `2025-08-gte-perps/H-01` | "if an attacker … submit a large number of minor withdrawal requests" | primitive + impact; cause = the queue traversal |
| `2024-12-bakerfi/H-05` | "may be vulnerable to frontrunning attacks" | primitive |
| `2024-04-noya/H-21` | "will falsely remove the market … so that stake won't be counted towards TVL" | cause and impact in one sentence |

The vocabulary is therefore defined only over the cause axis, and every leaf carries
`root_cause_statement.not_impact / not_primitive / not_component` to say what must *not* be
written in a cause field. `scripts/validate_taxonomy.py` screens the cause fields
lexically for impact, primitive and component language.

## 2. Candidate → category, in full

39 of the 40 candidates produced a label; the labels below are the `adjudicated_candidate`
rows in `taxonomy/assignments_v1.jsonl` (`confidence: high`).

| candidate | label(s) | primary | note |
|---|---|---|---|
| 2024-01-decent/H-01 | RC-01, RC-02 | RC-01 | open setter **and** unvalidated address |
| 2024-01-decent/H-02 | RC-14, RC-04 | RC-14 | report's own sentence is about gas; message trust secondary |
| 2024-01-decent/H-03 | RC-07, RC-02 | RC-07 | refund recipient read from the wrong field |
| 2024-01-decent/H-04 | RC-03, RC-04 | RC-03 | destination liquidity never bounded before sending |
| 2024-01-renft/H-01 | RC-02 | RC-02 | any ERC20 accepted as consideration |
| 2024-01-renft/H-03 | RC-17 | RC-17 | control yields to Seaport before state is final |
| 2024-01-renft/H-04 | RC-07 | RC-07 | hand-written offset selects the wrong ABI parameter |
| 2024-01-renft/H-05 | **RC-99 unlabelled** | — | editorial lead-in, states no cause; rejected as evidence |
| 2024-01-renft/H-06 | RC-08 | RC-08 | rentals creatable that bypass the release precondition |
| 2024-01-renft/H-07 | RC-08 | RC-08 | partial-offer completion test omits the lender's outstanding claim |
| 2024-04-noya/H-03 | RC-19, RC-09 | RC-19 | routed feed read; decimals mixing secondary |
| 2024-04-noya/H-04 | RC-05, RC-18 | RC-05 | unchecked callee refusal; the blocklist fact is the external rule |
| 2024-04-noya/H-09 | RC-18 | RC-18 | Prisma recovery-mode rule misapplied |
| 2024-04-noya/H-10 | RC-21 | RC-21 | documented reset effect not implemented |
| 2024-04-noya/H-11 | RC-18, RC-10 | RC-18 | SNX collateral accounting model differs from SNX |
| 2024-04-noya/H-12 | RC-07 | RC-07 | swap-remove re-keys the wrong position id |
| 2024-04-noya/H-16 | RC-03 | RC-03 | borrow path asserts no solvency bound |
| 2024-04-noya/H-17 | RC-03 | RC-03 | mint below intended health factor allowed |
| 2024-04-noya/H-19 | RC-09 | RC-09 | decimals ignored in `convertCToL` |
| 2024-04-noya/H-21 | RC-06, RC-10 | RC-06 | position cleared while the stake still exists |
| 2024-08-wildcat/H-01 | RC-13, RC-15 | RC-13 | fill rounding biased; queue provisioning secondary |
| 2024-12-bakerfi/H-01 | RC-09, RC-21 | RC-09 | shares returned where underlying is consumed |
| 2024-12-bakerfi/H-02 | RC-01 | RC-01 | `harvest` callable by anyone |
| 2024-12-bakerfi/H-03 | RC-06 | RC-06 | `_deployedAmount` not updated on `undeploy` |
| 2024-12-bakerfi/H-04 | RC-09 | RC-09 | decimals assumed 18 across vault/strategy |
| 2024-12-bakerfi/H-05 | RC-16 | RC-16 | permit consumed by another caller in the same block |
| 2024-12-bakerfi/H-06 | RC-01 | RC-01 | router spends a third party's ERC20 allowance |
| 2024-12-bakerfi/H-07 | RC-01 | RC-01 | same cause over the ERC4626-share allowance |
| 2025-06-panoptic/H-01 | RC-11 | RC-11 | premium polarity inverted in `poolExposure` |
| 2025-06-panoptic/H-02 | RC-10 | RC-10 | underlying included in the NAV population by configuration |
| 2025-08-gte-perps/H-01 | RC-15 | RC-15 | required traversal over an inflatable queue |
| 2025-08-gte-perps/H-02 | RC-15 | RC-15 | rule composition makes the bid side unfillable |
| 2025-08-gte-perps/H-03 | RC-10 | RC-10 | burn pays out of gross balance including distributor fees |
| 2025-08-gte-perps/H-04 | RC-10 | RC-10 | swap infers input from the same gross difference |
| 2025-08-gte-perps/H-05 | RC-10 | RC-10 | mint pays LP for accrued fees as if they were liquidity |
| 2025-08-gte-perps/H-06 | RC-02 | RC-02 | any `quoteAsset` address accepted by `addRewards` |
| 2025-08-gte-perps/H-07 | RC-06, RC-08 | RC-06 | shares retired while the reward stream keeps running |
| 2025-08-gte-perps/H-08 | RC-20 | RC-20 | CREATE2 derivation disagrees with the deployed pair address |
| 2025-08-gte-perps/H-09 | RC-16, RC-15 | RC-16 | graduation's `addLiquidity` reorders against a 1 wei pre-claim |
| 2025-08-gte-perps/H-10 | RC-12 | RC-12 | swap path never charges the fee |

## 3. Merges (many candidates → one leaf)

- **RC-01** merged 4 candidates (`decent/H-01`, `bakerfi/H-02`, `H-06`, `H-07`). Their v1
  classes were `Access Control/Privilege escalation`, `Access Control/Missing authorisation
  check` and `Token Standards/ERC4626 non-compliance` — three different class strings, one
  cause. `bakerfi/H-06` and `H-07` are the *same* defect over two asset types and were
  merged rather than split by token standard.
- **RC-07** merged 3 (`renft/H-04`, `noya/H-12`, `decent/H-03`), previously filed under
  `Missing kill switch`, `Wrong variable or branch` and `Permanent DoS`. Two of those three
  class strings name a location or an impact, not the wrong-reference cause.
- **RC-08** merged 3 (`renft/H-06`, `renft/H-07`, `gte/H-07`): all transition predicates.
- **RC-09** merged 4 (`bakerfi/H-01`, `bakerfi/H-04`, `noya/H-19`, `noya/H-03` secondary).
- **RC-10** merged 5 (`gte/H-03`, `H-04`, `H-05`, `panoptic/H-02`, `noya/H-11` secondary):
  the `DeFi/AMM invariant logic` and `Accounting/Incorrect reserves` buckets had grouped a
  population error with an arithmetic error; the population leaf absorbed them.
- **RC-03** merged 3 (`noya/H-16`, `noya/H-17`, `decent/H-04`).
- **RC-15** merged 3 (`gte/H-01`, `gte/H-02`, `wildcat/H-01` secondary).
- **RC-04** merged the two Cross-Chain candidates (`decent/H-02` secondary, `decent/H-04`
  secondary); v1 had one as `Message verification` and the other as `Bridge authorisation`,
  which are the sender-side and receiver-side descriptions of one cause.

## 4. Splits (one candidate → several labels, or one bucket → several leaves)

- `decent/H-02` split into **RC-14** (execution budget assumed) + **RC-04** (payload trust):
  the report conflates a gas problem with a bridge-trust problem.
- `noya/H-04` split into **RC-05** (unchecked refusal) + **RC-18** (token behaviour
  misapplied): only the first is a defect in this contract's code.
- `wildcat/H-01` split into **RC-13** (rounding bias) + **RC-15** (queue provisioning).
- `bakerfi/H-01` split into **RC-09** (shares vs underlying) + **RC-21** (the documented
  effect of `getBalance` is not what the body returns).
- `gte/H-09` split into **RC-16** (ordering) + **RC-15** (graduation blocked).
- The v1 `Accounting` bucket was split across **RC-06 / RC-09 / RC-10 / RC-11 / RC-12 /
  RC-13**, because "Accounting" is a component-family label that hid six different causes.

## 5. Rejected candidate labels and rejected candidate evidence

- **`2024-01-renft/H-05` — rejected as evidence.** The candidate names no cause; the record
  carries no `code_context` at the pinned revision for the claim it makes. It is recorded as
  `RC-99` with the reason, not forced into `RC-01` just because its v1 class string says
  "Missing authorisation check". A class string is not evidence.
- **`< <` artefact candidates** (`decent/H-02`, `decent/H-03`, `renft/H-05`, `renft/H-06`,
  `noya/H-10`, `noya/H-21`): the leading `< <` is a quoting artefact from the upstream
  report, not content. Where the surviving sentence stated a cause the candidate was used
  (`decent/H-02`, `decent/H-03`, `renft/H-06`, `noya/H-10`, `noya/H-21`); only `renft/H-05`
  had nothing left after the artefact.
- **Rejected as category-forming:** the impact-words that dominate several candidates
  ("drained", "permanently lost", "locked forever", "lose their cross-chain transaction").
  They produced no leaf; they are recorded in `not_impact` on the leaves they attach to.
- **Rejected as category-forming:** the primitive-words ("frontrunning", "reentrancy",
  "donation", "swap") and the component-words ("Router", "Escrow", "Connector", "Pair").
  Each became a `not_primitive` / `not_component` field rather than a category.
- **v1 class strings deliberately not promoted to leaves:** `Flash-loan interaction`
  (primitive), `Griefing` (motive), `Blocked withdrawals` / `Permanent DoS` /
  `Temporary DoS` / `Liquidation failure` / `Bad debt` / `Insolvency` (impacts),
  `AMM invariant logic` (component), `Missing kill switch` / `Emergency control weakness`
  (absent feature, not a code defect), `Oracle manipulation` (impact+primitive). Each of
  these now produces an *unlabelled* outcome with a reason, so the dataset records that the
  old class cannot be read as a cause instead of quietly mapping it to one.

## 6. Coverage extensions (leaves with no candidate grounding)

Two leaves were added because the dataset's own class vocabulary contains records that the
40 candidates never touch. They are marked `derivation.origin = coverage_extension` and are
**the least validated part of this version**:

- **RC-22 upgradeability or storage-layout contract broken** — v1 carries `Storage collision`
  and `Unauthorised upgrade` records.
- **RC-23 signature or authorisation-data validation gap** — v1 carries `Missing domain
  separation` (21 records), `Signature replay` (12), `Signature malleability` (3),
  `Incorrect nonce handling` (2).

Without them those records would have been forced into RC-01/RC-07, which would have been a
fabricated fit. **RC-17** and **RC-19** are marked `single_candidate_plus_coverage`: one
grounded candidate each, retained because 24 and 18 records carry the matching class.

## 7. Thin leaves (real but rare)

`RC-11` (n=1), `RC-14` (n=1), `RC-20` (n=1), `RC-21` (n=2), `RC-08` (n=4). They are kept
because each is grounded in an adjudicated candidate and each is *distinct in mechanism*;
deleting them would have pushed those candidates into a broader leaf and lost the
distinction. `root-cause-1.1` may merge them if the IAA study shows annotators cannot tell
them apart — that is exactly the decision the study is designed to inform.

## 8. Candidates that could not be grounded

Exactly one: `2024-01-renft/H-05`. Recorded as unlabelled with its reason; listed in
`reports/root_cause_taxonomy_stats.json` under `candidate_adjudication.unlabelled`.

## 9. Everything else in the overlay is a draft, not a validation

`taxonomy/assignments_v1.jsonl` has **418 rows** (the root-cause-bearing pool: 40 candidates
plus every record with a stated broken behaviour or an invariant):

- 40 `adjudicated_candidate` rows, `confidence: high` — the section 2 table above.
- 357 `v1_class_rule` rows, `confidence: medium` — produced by the `CLASS_RULES` table in
  `scripts/assign_root_causes.py`, which maps a v1 class string to a leaf. **These are
  drafts.** They have not been read against their record's code by a human, and they are
  the exact rows the item-14 study is meant to adjudicate. Do not cite them as validated.
- 21 rows whose record has no v1 class at all: unlabelled, `confidence: low`.
- 98 rows unlabelled in total, 76 of them because a class string names an impact,
  primitive, component, or absent feature (reasons recorded per row and aggregated in
  `reports/root_cause_taxonomy_stats.json`).
- 99 rows carry 2-3 labels under the composition rules; 0 rows violate an exclusivity rule
  (the gate rejects such a file).
- 69 rows are `asserted` (at or above the leaf's minimum evidence level) and 251 are
  `provisional`.

Evidence-level distribution across the pool: L0 86, L2 307, L4 13, L5 5, L6 7. Nothing is
graded L1 or L3, and the reason is recorded rather than hidden: a quoted PoC always travels
with line-verified source (so L2), and no record has a compile-only attestation without an
execution record (so L3 is empty by construction).

## 10. Reproduction

```bash
python scripts/assign_root_causes.py            # overlay + stats
python scripts/assign_root_causes.py --check    # exit 1 on drift
python scripts/validate_taxonomy.py --check      # exit 1 on any rule violation
python -m pytest tests/test_taxonomy_gate.py -q
```

Canonical files are never written: the assignment layer is `taxonomy/assignments_v1.jsonl`
plus one JSON report, and `derived/records.jsonl` is read-only input to both.

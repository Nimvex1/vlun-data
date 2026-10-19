# Root-cause taxonomy v1 — `root-cause-1.0`

A **project-local, versioned, closed-vocabulary** classification of root causes for the
VLUN dataset. It is not a community standard and must not be described as one: nothing
outside this repository has adopted it. Its nearest external relatives are the (frozen,
unmaintained since 2020) SWC registry and the maintained
[EEA EthTrust Security Levels specification](https://entethalliance.org/specs/ethtrust-sl);
where those two cover a leaf, the mapping below records exactly how close the fit is.

Machine-readable form: `taxonomy/root_cause_v1.jsonl` (31 entries: 7 facets,
23 assignable leaves, 1 reserved sentinel). Overlay assignments:
`taxonomy/assignments_v1.jsonl`. Gate: `python scripts/validate_taxonomy.py`.

## 1. Scope

In scope: the reason a described security property could be violated **in the code or
configuration of the audited revision**. One entry per cause, judged from citable material
in the record.

Out of scope, and deliberately separated:

- **impact** — what the violation produces (funds moved, availability lost, fees avoided);
- **primitive** — the mechanism the attacker uses to reach it (reentrancy, a flash loan,
  frontrunning, a donation, a replayed signature);
- **component** — where the code sits (oracle, router, vault, connector, factory, bridge).

The v1 class strings the dataset inherited mix all four, which is the reason this
vocabulary exists rather than another spelling of the same list.

## 2. Root cause vs impact vs primitive vs component

The four axes are tested by four questions. A candidate label passes the root-cause test
only if replacing the attacker's opportunity with a different one leaves the label true.

**Worked example 1 — `2024-01-decent/H-01`.**
Title: "Anyone can update the address of the Router…".
*impact*: mint/burn authority over `DcntEth` passes to any caller.
*primitive*: an unauthenticated call to a setter.
*component*: `DcntEth` router wiring.
*root cause*: **RC-01** — authorisation the design requires is not enforced on the
reachable path. Test: if a different actor (a buggy relayer rather than an attacker)
reached the same setter, the cause would still be RC-01. Label retained: RC-01, secondary
RC-02 (the accepted address is also unvalidated).

**Worked example 2 — `2025-08-gte-perps/H-04`.**
*impact*: reserves drained through `swap`.
*primitive*: a `sync`/donation sequence that changes the pair's balance.
*component*: `GTELaunchpadV2Pair`.
*root cause*: **RC-10** — the aggregate is taken over a population (gross balance,
including accrued fees owed to the distributor) that the design assigns to someone else.
The donation is the primitive; "AMM invariant logic" is the component. Labelling the
record by its primitive would make the taxonomy a list of attacks.

**Worked example 3 — `2024-04-noya/H-04`.**
*impact*: withdrawals blocked.
*primitive*: a token that reverts for a blocklisted holder.
*component*: the withdrawal batch.
*root cause*: **RC-05** — the code assumes an external call succeeds and provides no
handling for the failure the callee can return; secondary **RC-18** because the assumption
contradicts the token's documented behaviour. The v1 class for this record is
`Denial of Service / Blocked withdrawals`, which states the impact, not the cause.

**Worked example 4 — `2024-12-bakerfi/H-05`.**
*impact*: a user's tokens are taken.
*primitive*: frontrunning a permit.
*root cause*: **RC-16** — the design commits on an observation it cannot hold stable
across the ordering window. "Frontrunning" never appears in a root-cause field.

## 3. Hierarchy

Seven facets group the leaves; **facets are containers, never labels** (an assignment may
not use `RC-G-*`).

| Facet | Leaves |
|---|---|
| RC-G-COMPUTE | RC-09, RC-10, RC-11, RC-12, RC-13 |
| RC-G-DEPLOY | RC-20 |
| RC-G-LIVENESS | RC-14, RC-15 |
| RC-G-ORDER | RC-16, RC-17 |
| RC-G-STATE | RC-06, RC-07, RC-08, RC-21, RC-22 |
| RC-G-TRUST | RC-01 |
| RC-G-VERIFY | RC-02, RC-03, RC-04, RC-05, RC-18, RC-19, RC-23 |

`RC-G-TRUST`, `RC-G-ORDER` and `RC-G-DEPLOY` hold one or two leaves each: the vocabulary is
honest about being unevenly populated rather than inventing siblings to look symmetric. The sentinel
`RC-99 unlabelled` is not a category; it records that no leaf fit, with a reason.

## 4. The 23 leaves

| id | name | facet | min evidence | n (this dataset) |
|---|---|---|---|---|
| RC-01 | Open gate on a privileged operation | TRUST | L2 | 27 |
| RC-02 | Unvalidated external input treated as trusted | VERIFY | L2 | 9 |
| RC-03 | Missing or too-permissive quantitative bound | VERIFY | L3 | 44 |
| RC-04 | Inbound cross-domain message accepted without origin or state check | VERIFY | L3 | 15 |
| RC-05 | Returned failure of an external call ignored | VERIFY | L2 | 14 |
| RC-06 | Required bookkeeping update omitted | STATE | L2 | 7 |
| RC-07 | Wrong target referenced by an update or lookup | STATE | L2 | 6 |
| RC-08 | Lifecycle transition condition incomplete | STATE | L3 | 4 |
| RC-09 | Unit or scale mismatch between producers and consumers | COMPUTE | L3 | 44 |
| RC-10 | Wrong population or basis used for an aggregate | COMPUTE | L3 | 49 |
| RC-11 | Sign or direction inversion | COMPUTE | L4 | 1 |
| RC-12 | Fee or reward obligation never accrued on the path | COMPUTE | L3 | 12 |
| RC-13 | Truncation or precision loss at a boundary | COMPUTE | L4 | 17 |
| RC-14 | Execution budget assumed adequate | LIVENESS | L4 | 1 |
| RC-15 | Required operation grows with attacker-supplied state | LIVENESS | L4 | 11 |
| RC-16 | Shared state read or written across an interleaving window | ORDER | L4 | 11 |
| RC-17 | State observed before it is final, across a control transfer | ORDER | L4 | 33 |
| RC-18 | External component's documented behaviour misapplied | VERIFY | L3 | 64 |
| RC-19 | External state value consumed without freshness or provenance validation | VERIFY | L3 | 17 |
| RC-20 | Deployment or derivation inconsistent with the code's own expectation | DEPLOY | L4 | 1 |
| RC-21 | Implemented behaviour contradicts its own stated contract | STATE | L2 | 2 |
| RC-22 | Upgradeability or storage-layout contract broken | STATE | L2 | 7 |
| RC-23 | Signature or authorisation-data validation gap | VERIFY | L2 | 25 |

Full definitions, inclusion rules, exclusion rules, impact/primitive/component
disambiguation, citations, positive and negative examples:
`taxonomy/root_cause_v1.jsonl` (one JSON object per entry) and
`annotation/iaa_v1/guide.md` (the annotator-facing short form).

## 5. Evidence requirements

Ladder used repo-wide: **L0** prose claim · **L1** quoted artefact · **L2** source
reconstructed and line-checked at the pinned commit · **L3** a reconstruction compiles ·
**L4** something executed at the audited revision · **L5** the claimed violation was
reproduced · **L6** vulnerable revision reproduced **and** the fixed revision blocked by
the same test.

A leaf's floor is the level at which *this kind of cause* can be asserted rather than
argued from:

- **L2** for causes that are properties of the source itself — an absent gate (RC-01), an
  unchecked return (RC-05), a missing write (RC-06), a wrong identifier (RC-07), an
  unimplemented documented effect (RC-21), a layout contradiction (RC-22), an unbound
  signature (RC-23).
- **L3** where the claim needs two conventions or two codebases compared, or a reachable
  state — bounds (RC-03), cross-domain trust (RC-04), transition predicates (RC-08),
  unit/scale (RC-09), aggregation basis (RC-10), omitted charge (RC-12), external semantics
  (RC-18), feed freshness (RC-19).
- **L4** where the cause is only visible by running something — budget (RC-14), growth and
  provisioning (RC-15), interleaving (RC-17), ordering (RC-16), sign inversion (RC-11),
  rounding bias (RC-13), address derivation (RC-20).

Assignment rows carry the record's `evidence_level`, an `evidence_basis` string explaining
how it was derived, `meets_minimum_evidence` per label, and `assignment_status`:
`asserted` (at or above the floor), `provisional` (below it), or `unlabelled`. Below the
floor the label is a hypothesis, and the row says so. No row in the pool is graded L1 or L3, and the reason is recorded rather than hidden:
quoted PoC code always travels with line-verified source (so L2), and no record carries a
compile-only attestation without an execution record (so L3 is empty by construction).

## 6. Multi-label and hierarchy rules

- 1–3 labels per record; `primary` is the one that would still be assigned if the others
  were struck. No record is forced to exactly one.
- Compose only where the leaf declares composition (`composable_with`, with the rule that
  licenses it). Composition is not a synonym list: RC-01 + RC-02 means both an unenforced
  role and an unvalidated value were needed.
- `exclusive_with` forbids co-labelling; the gate enforces it.
- Facet ids are not assignable; the sentinel `RC-99` never co-occurs with a leaf.
- Overlap is allowed where the two causes are independently fixable (RC-06 + RC-12: the fee
  is not charged *and* its accumulator is stale). Where one cause is a restatement of the
  other in different words, keep the more specific leaf and drop the generic one.

## 7. SWC / CWE mapping

| leaf | SWC | relation | CWE | relation |
|---|---|---|---|---|
| RC-01 | SWC-100, SWC-105 | narrow, narrow | CWE-284, CWE-863 | exact, exact |
| RC-02 | SWC-135, SWC-112 | partial, narrow | CWE-20 | exact |
| RC-03 | SWC-135 | partial | CWE-1284, CWE-754 | exact, narrow |
| RC-04 | SWC-112 | partial | CWE-284 | narrow |
| RC-05 | SWC-104, SWC-113 | exact, narrow | CWE-252, CWE-703 | exact, narrow |
| RC-06 | SWC-135 | partial | CWE-664 | narrow |
| RC-07 | SWC-129 | narrow | CWE-682 | partial |
| RC-08 | SWC-100 | narrow | CWE-841 | exact |
| RC-09 | SWC-101 | narrow | CWE-682 | exact |
| RC-10 | **no_map** | — | CWE-682 | exact |
| RC-11 | **no_map** | — | CWE-480 | exact |
| RC-12 | **no_map** | — | CWE-841 | narrow |
| RC-13 | SWC-101 | narrow | CWE-131 | partial |
| RC-14 | SWC-124, SWC-126 | exact, narrow | CWE-400 | narrow |
| RC-15 | SWC-128 | exact | CWE-400 | exact |
| RC-16 | SWC-114 | exact | CWE-362 | exact |
| RC-17 | SWC-107 | exact | CWE-841 | exact |
| RC-18 | **no_map** | — | CWE-829 | narrow |
| RC-19 | SWC-116 | narrow | CWE-829 | narrow |
| RC-20 | **no_map** | — | CWE-665 | partial |
| RC-21 | SWC-135 | partial | CWE-710 | partial |
| RC-22 | SWC-108, SWC-109 | narrow, narrow | CWE-696 | partial |
| RC-23 | SWC-117, SWC-121, SWC-122 | exact, exact, narrow | CWE-347 | exact |

`no_map` is an explicit answer, not a gap in this document: the SWC registry has no entry
for an aggregation-population error, an inverted polarity, an omitted economic charge, a
third-party integration semantics error, or a deployment mismatch, and inventing an SWC
number would be worse than saying none fits. Every justification lives on the entry
itself, including which maps are narrow or partial rather than sound.

**Verification record.** The registry cited by the project brief,
`https://smartcontract-it.github.io/swc-registry/`, returns **404**; the maintained-up-to-2020
registry lives at `https://github.com/SmartContractSecurity/SWC-registry`, and its pages
resolve through `https://swcregistry.io/docs/SWC-<n>`. On 2026-10-18 this project fetched
`entries/docs/SWC-100…136.md` from that repository and the `cwe.mitre.org/data/definitions/`
pages for every CWE cited, recorded each identifier's title, and frozen the result as the
`VERIFIED_SWC` / `VERIFIED_CWE` snapshot in `scripts/validate_taxonomy.py`. The gate now
rejects any identifier absent from that snapshot, so an unverified SWC/CWE number cannot
enter the taxonomy. Both registries' relationship lists were read; EthTrust is cited where
the SWC registry is silent, and its status as the maintained successor is recorded per entry.

## 8. Versioning

- Identifier: **`root-cause-1.0`**; file schema tag `root-cause-1.0`; every vocabulary
  entry and every assignment row carries `taxonomy_version`.
- The vocabulary is **closed**: an id outside it fails the gate. New ids appear only in a
  new minor or major version, never by editing 1.0 in place.
- A **patch** release may change wording, citations, examples and justifications without
  changing what a label means, and stays `root-cause-1.0`.
- A **minor** release (`1.1`) may add leaves, add composition rules, and tighten an
  inclusion rule that splits one leaf's population; it must not relabel records that 1.0
  would still label identically.
- A **major** release (2.0) is required whenever any 1.0-labelled record would receive a
  different leaf, or when the root-cause/impact/primitive/component axes are redrawn.

## 9. Deprecation and migration

- Leaves are deprecated, never deleted: a deprecated entry keeps its id, gains
  `lifecycle: "deprecated"`, `deprecated_in`, `sunset_in`, and `replacement` pointing at
  its successor(s). The gate keeps validating deprecated entries so historical assignment
  files stay readable.
- **1.0 → 1.1 migration contract.** 1.1 must ship a per-leaf mapping table:
  `keep`, `split(→ RC-a, RC-b)` with the predicate that decides the split, `merge(← …)`,
  or `retire(→ RC-x)`. A `split` migration must state which 1.0 records move: the rule is
  evaluated against each 1.0 row's `evidence_level` and the leaf's citation, not against
  a fresh read of the corpus, so the migration is reproducible. Rows whose split cannot be
  decided from the 1.0 record stay `RC-99` in 1.1 with the reason `indeterminate under split`.
- **What invalidates a migration.** Any of these forces a major version and a full
  re-assignment rather than a mapping table: merging two leaves that 1.0 allowed to
  co-occur (composition sets change); moving a leaf between facets when a rule keys on the
  facet; changing the ladder or a leaf's minimum evidence level; and — the important one —
  a measured IAA result that shows a leaf is not reproducible (κ or α below the guide's
  floor). An IAA study cannot be simulated to justify a migration:
  `annotation/iaa_v1/protocol.md` is currently protocol-only and
  `reports/iaa_status.json` says `measured: false`, so **no leaf of 1.0 has a human
  reproducibility measurement yet**, and no 1.1 may claim one.
- **Reassignment cost.** `taxonomy/assignments_v1.jsonl` is an overlay: canonical records
  are untouched, so a version bump regenerates the overlay and leaves every earlier file
  byte-comparable. 378 of the 418 assigned rows are unadjudicated (357 v1-class rule
  drafts plus 21 rows whose record carries no class at all), so the first thing a 1.1 does
  is replace those drafts with human-adjudicated labels, not invent new ones.

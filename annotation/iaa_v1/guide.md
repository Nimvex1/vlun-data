# Annotator guide — VLUN root-cause annotation (iaa-v1)

Read this before labelling. It is the only document annotators are allowed to consult;
the dataset's own labels (`taxonomy.class`, `taxonomy.category`,
`derived/root_cause_candidates.jsonl`, `taxonomy/assignments_v1.jsonl`) are hidden from
the sample rows on purpose. Do not look them up while annotating — that contaminates
agreement, and the study measures independent judgement, not copying.

## What you are judging

Five constructs per record. All are answered from the row's `visible` block only.

### 1. Root cause — `rc_labels`, `rc_primary`

Pick from the closed vocabulary in `taxonomy/root_cause_v1.md` (the definitions table).
Rules:

- Name **why the code fails**, not what the attacker gets, not how they got there, and
  not which contract is involved. If your sentence starts with "the attacker can …" or
  ends with "… resulting in lost funds", you are writing impact, not cause.
- 1–3 labels. `rc_primary` must be one of them and must be the label you would defend if
  only one could stand.
- If nothing in the vocabulary fits what the evidence shows, leave `rc_labels` empty, set
  `unlabelled_or_wrong_category` to `UNLABELLED`, and write the reason in
  `unlabelled_reason`. An honest UNLABELLED is worth more than a forced label.
- If a vocabulary leaf exists but its definition does not cover the case, also set
  `flag_new_category` to `yes` and describe it in `notes`.

Quick separation table (worked examples are in the taxonomy document):

| Axis | Question it answers | Example sentence |
|---|---|---|
| root cause | why could the invariant be broken at all? | "the setter has no role check on the reachable path" |
| impact | what is lost or gained when it is broken? | "anyone can mint and burn" |
| primitive | what mechanism did the attacker use? | "a flash loan", "reentrancy", "front-running" |
| component | where does it live? | "the Router contract", "the ERC4626 vault" |

### 2. Severity tier — `severity_tier` (ordinal)

| Tier | Meaning in this dataset | Read it as |
|---|---|---|
| 0 | none / no severity asserted by any source | nothing published a tier |
| 1 | `qa` / informational | quality issue, no direct value effect |
| 2 | `medium` | bounded value effect, or clear availability loss |
| 3 | `high` | unauthorised value movement or permanent loss is reachable |

Tier is a judgement about the *described* consequence given the stated preconditions, not
about how famous the protocol is. Use 0 only when the row really gives you nothing.

### 3. Evidence level — `evidence_ceiling` (ordinal, L0–L6)

What has actually been shown, not what you believe:

| Level | Requirement |
|---|---|
| L0 | prose claim only |
| L1 | a quote (report sentence, PoC text) |
| L2 | source reconstructed and line-checked at the pinned commit |
| L3 | a reconstruction compiles |
| L4 | something executed at the audited revision |
| L5 | the claimed violation was reproduced by that execution |
| L6 | vulnerable revision reproduced **and** the fixed revision blocked by the same test |

The row tells you which of these exist: `code_context[*].line_range_verified` (L2),
`poc.has_code` (L1/L3 candidate), `verification.attempted` + `verification.test_evidence`
(L4), `verification.verdict` (L5), `patch.has_diff` plus a recorded fixed-revision result
(L6). Mark the **highest** level the row itself supports. If a PoC is quoted but no run is
recorded, the ceiling is L2 — quoting code is not executing it.

### 4. Violated invariant — `invariant_stated`

`yes` only when the row quotes or reconstructs a stated property (a NatSpec line, a test
assertion, a report sentence that names the property) that the described behaviour breaks.
`no` when the row describes an outcome without ever stating the rule it violates. This is
a reporting question, not a physics question: the invariant may well exist and simply not
be stated in the source material.

### 5. Category fit — `unlabelled_or_wrong_category`, `flag_new_category`

`WRONG_CATEGORY` means: a label from the vocabulary is present in your view but the leaf
chosen by the dataset (which you cannot see) is wrong — use it only when you are also
confident in your own label. `flag_new_category=yes` means the vocabulary has no leaf for
what you saw; these flags are the input to the next version of the taxonomy.

## Procedure

1. Copy `blank/annotator_N.template.csv` to `responses/annotator_N.csv`. Do not edit the
   template in place; do not reuse another annotator's file.
2. `annotator_kind` must be `human` and `annotator_id` must be a stable pseudonym that is
   yours alone. Machine or model passes are rejected by `scripts/iaa_statistics.py` and
   reported as a violation, not as agreement.
3. Work the rows in file order. Annotate independently: no discussion, no shared notes,
   no peeking at another annotator's file until everyone has finished.
4. Fill every column for every row. Blank `rc_primary` is allowed only with
   `unlabelled_or_wrong_category=UNLABELLED` and a non-empty `unlabelled_reason`.
5. Do not correct the record, the code context, or the taxonomy while annotating. If
   something looks broken, write it in `notes` and finish the file.
6. When done, commit `responses/annotator_N.csv` (or hand it to the study owner) and run
   `python scripts/iaa_statistics.py` to regenerate `reports/iaa_status.json`.

## Timing and effort

The pilot is 20 rows, then 280 more. Typical measured rate for this kind of record is
4–8 minutes per row when code context is present, under 2 minutes when it is prose-only.
Budget accordingly; do not rush the last hundred rows, and do not backfill labels from
titles alone.

## What is *not* being measured

Reproduction quality, sponsor correctness, and whether the original audit was right.
Those have their own gates. This study measures only whether independent readers, given
the same evidence and this guide, produce the same labels.

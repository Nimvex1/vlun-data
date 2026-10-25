# VLUN handoff packages — human review & permissions

Prepared 2026-10-25. These are the two workstreams that cannot be completed
without human action. Nothing here is marked complete; `docs/QUALITY_CHECKLIST.md`
lists both as BLOCKED with this file as the handoff.

---

## §1 Blinded annotation study (inter-annotator agreement)

**Status: BLOCKED — needs two independent qualified reviewers.**

### What exists already

- Frozen sample: `annotation/iaa_v1/` — draw id `iaa-draw-1.0`, n=300,
  seed=20261018, template hash matched by `scripts/sample_iaa.py --check`
  and `scripts/iaa_statistics.py --check` (which reports `measured=False`
  and stays byte-stable until real responses arrive).
- Label definitions and adjudication rules are already written into the
  sample materials; they must be **frozen before** any response is
  collected. If a definition needs changing, version the draw and restart.

### Protocol (do not deviate without versioning)

1. Recruit **two** reviewers who did not author the labels and did not work
   on this repository's pipelines. Record qualifications (years of smart-
   contract/security review experience, familiarity with the ecosystems in
   the sample: Solidity, Vyper, Move, Cairo, Rust/Tezos, TEAL).
2. Each reviewer works independently, blinded to the existing gold labels,
   to the other reviewer's responses, and to the model-facing shortcuts
   (source ids, filenames). The sample rows already carry the blinding
   transform (`docs/HANDOFF.md` companion files under `annotation/iaa_v1/`
   describe it; redaction records never contain the answer text).
3. Labels per the frozen templates. When evidence is insufficient, the
   correct response is the explicit `unknown`/abstain option — forced
   guesses corrupt agreement metrics.
4. Adjudication after BOTH responses are locked: disagreements are resolved
   by a third party or by discussion **after** raw responses are preserved.
   The adjudication log is separate from the raw draw.
5. Report: per-axis confusion, raw agreement, Cohen's kappa (two raters) or
   Krippendorff's alpha (if abstentions/missing), with bootstrap
   confidence intervals; break out positives, negatives, synthetic
   examples, extraction-derived rows and the hard cases the sample
   stratified for. Report reviewer qualifications.
6. Feed the result into `scripts/iaa_statistics.py` (it computes from real
   response files) and re-run `python scripts/run_gates.py`. Until then,
   `measured=False` must stay — do not fill templates with fabricated
   human responses, and do not substitute LLM self-consistency for IAA.

### Sample composition reminders

The draw deliberately covers: labelled/unlabelled spans, synthetic-style
records, extraction-derived V4 rows (see `docs/EVIDENCE_LEDGER.md` E-9),
F-extension rule-derived gold (E-6), and family A's disputed input groups
(E-1). Agreement on the disputed strata is exactly the evidence the
open defects need.

---

## §2 Licence clearance (redistribution rights)

**Status: BLOCKED — needs rights-holders' permission.**

### What exists already

- `NOTICE.md`: attribution to all original authors (contests, audit firms,
  incident PoC authors).
- `scripts/inventory_rights.py`, `scripts/check_rights_consistency.py`,
  `scripts/reconcile_v4_licensing.py`, `V4/licensing.json`: machine-checked
  licence state; no contradictory status; no copied expressive content in
  the distribution view; gates green.
- `distribution_v1/`: rights-redacted distribution which **explicitly
  disclaims legal clearance** and excludes canonical training and benchmark
  material. Keep that disclaimer until §2 closes per source family.
- `Vbeta/reports_vbeta/` licence checklist records the per-source status.

### What is NOT established

A hash, a citation, a public URL, or a short quotation length does **not**
grant redistribution. Unresolved rights stay unresolved. Specifically
un-cleared: third-party audit-report prose used as extraction input for the
V4 layer, and any expressive content beyond short attributed quotations in
the derived layers.

### Request package (per source family)

For each publisher/firm family in `V4/licensing.json` / the Vbeta checklist:

1. A short request letter identifying: the exact artefacts (paths +
   `RELEASE_MANIFEST.json` entries + sha256), the intended use (security
   training/evaluation dataset, redistributable under the stated licence),
   what transformation is applied (structured extraction of findings, no
   verbatim report redistribution in the release export), and the contact
   for withdrawal.
2. Track replies in a permissions log (per family: requested / granted /
   denied / no response, with dates and the exact scope granted).
3. On denial or non-response: keep the family out of redistributable
   exports permanently; citations and hashes can stay; re-run
   `python scripts/build_release_manifest.py` and the rights gates.
4. On grant: record the permission document (or a durable link + hash),
   update `V4/licensing.json` via its owner script, re-run the rights
   gates and the release manifest. Only then may a release be described as
   licence-cleared for that family.

### Personal data

Release exports must omit unnecessary personal information. The existing
redaction machinery (`scripts/redact_machine_paths.py`, per-field
transforms recorded without answer text) covers machine paths; review the
`raw_body_excerpt` / author fields of V4 rows before any external release.

---

## §3 What NOT to do while blocked

- Do not mark IAA or licence clearance as complete on the basis of gates —
  the gates only verify internal consistency.
- Do not relax the rights-redacted distribution's disclaimer.
- Do not promote V4 rows to executable ground truth (they are L0 metadata
  with known extraction defects, E-9).
- Do not claim the F-extension gold is human-validated.
- Do not claim absence of pretraining contamination for any OPEN-KEY
  benchmark family.

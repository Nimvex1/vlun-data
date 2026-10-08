# Licence clearance — PoPoC + Cyfrin audit-checklist (BLOCKED, no corpus use)

Status 2026-10-07: neither source may enter any dataset layer until its
licence is cleared in writing. This file records the block, the drafts,
and the rule. An AI agent cannot send email; a human must send and file
the reply here.

## 1. PoPoC (ASSERT-KTH/PoPoC @ 3288405)

- Contents: `verified_audits/0001…` folders (Dockerfile + PoC.sol each).
- Licence: **no LICENSE file in the clone** (verified). Upstream overlaps
  Solodit/C4 sets already mirrored → duplicate risk on top of licence risk.
- Needed: permission to extract structured facts (finding title, severity,
  PoC presence) with attribution, or a licence file upstream.
- Draft request (send to the repo contacts listed on
  https://github.com/ASSERT-KTH/PoPoC):

> Subject: Licence question for research reuse of PoPoC finding metadata
>
> Hello — we maintain VLUN, a provenance-preserving smart-contract
> security dataset (CC BY 4.0 data, MIT pipeline). We would like to
> extract structured, attributed facts (finding titles, severities, PoC
> presence — never full file contents) from PoPoC's verified_audits
> folders. Your repo currently carries no LICENSE file. Would you grant
> permission for this metadata-only reuse with attribution, or consider
> adding an OSI-approved licence? Happy to comply with any conditions.

## 2. Cyfrin audit-checklist (Cyfrin/audit-checklist @ 008855f)

- Contents: `checklist.json` (370 items, 13 categories) + contributor
  checklists in `ref/`. Intended use: taxonomy mapping aid only, never
  findings.
- Licence: **no LICENSE file in the clone** (verified).
- Needed: permission to reference checklist item IDs/text in taxonomy
  mapping notes, or a licence file upstream.
- Draft request (send via the repo's contact channels on
  https://github.com/Cyfrin/audit-checklist):

> Subject: Licence question for taxonomy-mapping reference to the audit checklist
>
> Hello — we maintain VLUN (CC BY 4.0 data, MIT pipeline) and would like
> to reference your audit-checklist item IDs (e.g. SOL-AM-DOSA-1) in our
> taxonomy mapping notes, with attribution and links back. Your repo
> currently carries no LICENSE file. Would you grant permission for this
> reference use, or consider adding an OSI-approved licence?

## Rule (gate-enforced by posture, not yet by code)

No `popoc` / `audit-checklist` source id may be registered in
`Vbeta/sources.json` until a written clearance is filed here with date
and grantor. The `decide()` rule admits only observed or operator-owned
rows; third-party text without a licence stays out entirely.

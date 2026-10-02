# Code4rena smart-contract security dataset

A provenance-preserving, security-reasoning dataset built from eight public
Code4rena audit repositories. Every record is traceable to a specific public
artefact: a report section, a GitHub issue, a comment, or a commit-pinned
permalinked source file.

The goal is causal security reasoning, not vulnerability names. Records carry the
full chain: protocol context → relevant code → intended behavior → the invariant
that should hold → the vulnerability → root cause → attacker prerequisites and
capabilities → attack path → impact → exploitability → PoC → validation verdict →
mitigation → fixed behavior.

## Layout

```
dataset/
├── raw/                     downloaded source material, kept separate from the output
│   ├── repos/               the 8 requested repositories (findings + source)
│   ├── source/              the sibling source-code repositories the audits cover
│   ├── issues/              GitHub issues API dump (all 3,395 submissions)
│   ├── comments/            issue comments, where the verdicts actually live
│   ├── web/                 code4rena.com report pages, rendered to markdown
│   ├── code_refs.json       every GitHub blob permalink the reports cite
│   ├── code_files.json      the file contents behind those permalinks
│   ├── parsed_reports.json  section-aware parse of each final report
│   ├── protocols.json       per-repository protocol metadata
│   └── mitigation_patches.json  the fixing PR diffs
├── normalized/
│   └── findings_extractive.json   verbatim evidence per finding, before normalisation
├── jsonl/
│   ├── findings.jsonl           264 records: 204 judged H/M + 60 QA
│   ├── negative_findings.jsonl   458 records: rejected / disputed / duplicate
│   ├── exploits.jsonl            155 records: PoC material
│   ├── patches.jsonl              38 records: vulnerable → fixed pairs
│   ├── protocol.jsonl              8 records
│   ├── metadata.jsonl             11 records (8 repos + 3 substitutions)
│   └── errors.jsonl                18 records: every known extraction limitation
├── splits/
│   ├── train.jsonl  validation.jsonl  test.jsonl
└── reports/
    ├── dataset_stats.json
    ├── extraction_errors.json
    └── source_manifest.json
```

`scripts/build_all.py` rebuilds every output from `dataset/raw` in order, and
`scripts/validate.py` is the gate: it fails the build on any schema, provenance,
dedup, or split-leak problem.

## Repositories

| Repository | Protocol | Findings | Source |
|---|---|---|---|
| `code-423n4/2024-04-noya` | NOYA multi-collateral vault | 23 H / 63 M | C4 mirror + sibling repo |
| `code-423n4/2024-01-renft` | reNFT ERC721/1155 rental | 7 H / 16 M / 6 QA | C4 mirror + `re-nft/smart-contracts` submodule |
| `code-423n4/2024-01-decent` | Decent cross-chain intent router | 4 H / 5 M / 3 QA | C4 mirror + sibling repo |
| `code-423n4/2024-08-wildcat` | Wildcat loan market | 1 H / 8 M / 23 QA | C4 mirror + sibling repo |
| `code-423n4/2022-05-alchemix` | Alchemix credit system | 17 M / 11 QA | C4 mirror + sibling repo |
| `code-423n4/2024-12-bakerfi` | BakerFi ERC4626 strategy vault | 7 H / 16 M / 9 QA | private audit repo + published report |
| `code-423n4/2025-06-panoptic` | Panoptic HypoVault | 2 H / 2 QA | private audit repo + published report |
| `code-423n4/2025-08-gte-perps` | GTE perps CLOB + launchpad | 10 H / 25 M / 6 QA | private audit repo + published report |

All eight requested repositories exist and were cloned. Three of them
(`2024-12-bakerfi`, `2025-08-gte-perps`, `2025-06-panoptic`) are **private** audit
repositories: they hold the source and the audit rules but publish no findings.
For those, findings come from the published report on code4rena.com and each
substitution is recorded as a `metadata` record and in `reports/extraction_errors.json`.

## How each field is sourced

Nothing in a record is written from memory. The rules are:

| Field | Source |
|---|---|
| `finding.severity` | the report's own section heading; `severity_source` names it |
| `finding.status` / `validation.*` | Code4rena's public GitHub labels plus the decision blocks quoted in the report; `validation.evidence` lists every label and quote used |
| `finding.vulnerability_classes` | a rule-based classifier over the report's prose; `classifier_evidence` records the literal span that triggered each class |
| `code_context[].snippet` | the file contents at the commit pinned in the report's permalink |
| `code_context[].line_start/line_end` | only set from the permalink, and only trusted when the file was actually retrieved (`line_range_verified`) |
| `code_context[].documented_intent` | NatSpec `@notice`/`@dev` read from that same file |
| `security_reasoning.intended_behavior` | the report's design-goal paragraph, or NatSpec when the report has none (`intended_behavior_source` says which) |
| `security_reasoning.invariants` | normative sentences in the finding's own prose, or the behaviour the remediation prescribes; each carries a `source_type` and a `source` note saying it is **not** quoted from a protocol specification |
| `security_reasoning.attacker_capabilities` | sentences naming an actor and a capability verb, plus capabilities read off the resolved function's visibility and modifiers |
| `security_reasoning.attacker_limitations` | the same, plus access-control facts from the code (e.g. a function behind `onlyOwner` cannot be reached by an unprivileged caller) |
| `security_reasoning.impact.*` | one dimension filled per sentence that actually evidences it; empty means the report does not state it |
| `poc.*` | quoted from the report. `reproducible` is `false` everywhere — nothing was compiled or run |
| `patch.*` | the fixing PR diff from the published mitigation review, with its merge commit SHA |
| `provenance.*` | the report file, the submission issue, the comments, and every permalink used |

## Negative examples

`negative_findings.jsonl` holds submissions that did **not** survive judging:
115 rejected, 24 sponsor-disputed, 319 duplicates. Each record separates
`why_it_looked_plausible` from `why_it_is_not_a_vulnerability`, and
`rejection_basis` says how strong the evidence is:

- `public_judge_or_sponsor_comment` — a verdict is publicly quoted and attributed
- `public_discussion_no_verdict_attributed` — discussion exists but Code4rena did
  not attribute it to the judge or the sponsor, so it is left as `participant`
- `label_only` — only a rejection label exists; the reason says so rather than
  inventing one

Rejected records carry **no severity** — a report that was not accepted has no
judged severity. Duplicates point at the canonical record via
`validation.duplicate_of`, so multiple descriptions of one bug do not become
multiple vulnerabilities.

## Splits

Splits are assigned per **repository**, never per finding, so the same protocol's
source code and the same root cause can never appear in two splits.

```
train      2024-04-noya (86), 2022-05-alchemix (28)                 415 records
validation 2024-01-renft (29), 2024-01-decent (12)                  277 records
test       2024-12-bakerfi (32), 2024-08-wildcat (32),
           2025-06-panoptic (4), 2025-08-gte-perps (41)            253 records
```

`validate.py` checks three leakage modes and fails on any: a repository in two
splits, a finding id in two splits, or the same `file::function` in two splits.

## Known limitations

`reports/extraction_errors.json` is the machine-readable list; the substantive
ones are:

1. **PoCs were never executed.** Every `reproducible` flag is `false`. The code
   is quoted from the report; running it needs the audited repo at the recorded
   commit plus each audit's own test harness.
2. **Private audits expose no per-submission verdicts.** For bakerfi, panoptic and
   gte-perps, `validation.status` rests on the finding's presence in the final
   report. code4rena's `/submissions/` pages are client-rendered with no public
   API, so their contents are absent.
3. **427 of 458 negative findings have only a label.** C4's judging rationale is
   mostly not public. Those records say so. A further 22 have public discussion
   that Code4rena did not attribute to the judge or sponsor, so it is left
   attributed to `participant` rather than reassigned.
4. **13 of 740 permalinks could not be used as source.** Ten referenced files
   (renamed or deleted repositories) could not be retrieved at all; four findings
   cite a line range that does not exist in the file at the commit their permalink
   points to. Those `code_context` entries keep the permalink and the claimed line
   numbers, carry no snippet, and set `line_range_verified: false` with a
   `range_source` that says why. `scripts/audit_line_ranges.py` re-checks all
   1,435 verified ranges byte-for-byte against the retrieved file; it currently
   reports zero mismatches.
5. **5 repositories declare no licence.** `provenance.license` is empty and
   `license_verified` is `false` for those rather than assuming a licence.
6. **QA / Low entries are not judged findings.** They are included
   (`record_class: "qa"`, `severity: "qa"`, `status: "acknowledged"`) and are
   marked as such, not presented as accepted vulnerabilities.
7. **Sparse invariants are left sparse.** 109 of 264 records carry an invariant.
   The rest genuinely do not state one normatively, and inventing a plausible
   invariant for a record that lacks one would teach the model to hallucinate the
   very thing these fields exist to capture.

## Rebuilding

```bash
python scripts/build_all.py            # from dataset/raw
python scripts/validate.py             # gate; exits non-zero on any failure
python scripts/audit_line_ranges.py    # re-verify every code_context against its file
```

The fetch stages are cached and only re-run when their cache is missing:

```bash
python scripts/fetch_issues.py             # GitHub issues API
python scripts/fetch_comments.py           # issue comments
python scripts/fetch_web_reports.py        # code4rena.com report pages
python scripts/inventory_code_refs.py      # every permalink the reports cite
python scripts/fetch_code_files.py         # the files behind those permalinks
python scripts/fetch_mitigation_patches.py # the fixing PR diffs
```

All GitHub calls use `GH_TOKEN`. Nothing outside `github.com` and
`code4rena.com` was used, and no source URL in any record is synthesised.

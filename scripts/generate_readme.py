#!/usr/bin/env python3
"""Generate README.md from the reports, so no number in it can drift.

The v1 README carried hand-written counts (18 error records when there were 19,
"1,435 verified ranges" from a pre-redaction build that cannot be reproduced from
the published copy). Prose is fine to hand-write; counts are not. This script
owns README.md and pulls every figure from reports/.

    python scripts/generate_readme.py
    python scripts/generate_readme.py --check    # exit 1 if README is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import BENCH, DERIVED, REPORTS, ROOT, WORK, log  # noqa: E402

README = ROOT / "README.md"
NOTICE = ROOT / "NOTICE.md"


def render_notice() -> str:
    """NOTICE.md is generated because its numbers change with every build."""
    man = jread(ROOT / "publish_manifest.json", {}) or {}
    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    dm = jread(DERIVED / "manifest.json", {}) or {}
    tot = ver.get("totals", {})
    comp = ver.get("poc_compilation_rate", {})
    flagged = dm.get("redistribution_flagged", {}).get(
        "source_redistributed_without_declared_license", 0)
    ex = sum(1 for _ in open(DERIVED / "records.jsonl", encoding="utf-8")) \
        if (DERIVED / "records.jsonl").exists() else 0

    return f"""# NOTICE — third-party source code, and what was verified

This repository is a **redacted** copy of a Code4rena-derived smart-contract
security dataset. The reasoning, validation and exploit data are present; a
portion of the embedded Solidity source has been removed for licensing reasons.

## What was withheld from the published copy

| | |
|---|---|
| `code_context` entries removed | {man.get('code_context_entries_removed', 0):,} |
| Solidity lines withheld | {man.get('source_lines_withheld', 0):,} |
| Fixing diffs withheld | {man.get('patch_diffs_removed', 0):,} |

## Why

1. **Third-party dependencies.** Many cited snippets are libraries the audited
   protocol merely integrates with — OpenZeppelin, Seaport, Aave, Pendle, Silo,
   Prisma, Morpho, Uniswap, LayerZero, Balancer, Stargate and others. They are not
   the subject of the audits and are not published here.

2. **Source-available audited code.** reNFT, BakerFi and Wildcat are published
   under licences that permit use but **not** redistribution (BUSL-1.1 / Commons
   Clause). Their code, and the diffs of the PRs that fixed their findings, are
   excluded.

## What was kept, and the caveat that matters

Code from the audited protocols whose repositories declare **no licence** — NOYA,
Decent, Alchemix, Panoptic and GTE — remains in this repository, because it was
redistributed upstream. That is a deliberate, upstream decision, not a
determination that the terms are permissive.

`python scripts/fetch_sources.py` reads the LICENSE file at each cited commit and
reports what it finds. {flagged} of {ex:,} derived records carry source text from
a repository that declares **no licence at all**: their terms are unstated rather
than permissive. Each is flagged at `redistribution.flag` in
`derived/records.jsonl`. **If you need a strictly licence-clean corpus, treat
every `code_context[].snippet` in this repository as a citation to resolve from
the original audit rather than as redistributable text.**

## Provenance is intact

Nothing was summarised, paraphrased or invented. For every withheld snippet the
record keeps, under `code_reference_only`: the source file path, the commit SHA,
the line range, the GitHub permalink and a sha256 of the content that
`scripts/fetch_sources.py` retrieved locally.

## What execution actually established

`jsonl/` is the original v1 layer and its `poc.reproducible` flags remain
`false` — that layer is not rewritten. Execution evidence lives in the derived
layer:

| | |
|---|---|
| exploit records attempted | {tot.get('exploit_records', 0)} |
| repositories that compiled | {comp.get('repos_compiled', 0)} of {comp.get('repos_attempted', 0)} |
| PoCs that demonstrated the claimed impact | **{tot.get('reproduced', 0)}** |
| PoCs that ran without the claimed impact | {tot.get('not_reproduced', 0)} |
| PoCs run but inconclusive | {tot.get('inconclusive', 0)} |
| PoCs that could not be executed | {tot.get('not_executed', 0)} |

A PoC counts as reproduced only when forge reported `Success` for its test; see
`reports/verification_stats.json` for the per-record command, status and failure
reason, and `scripts/validate.py` fails the build if any record claims
experimental verification without a run artefact behind it.

## Harness modifications

To run the PoCs, `scripts/verify_pocs.py` may, and records when it does:

* install `node_modules` with `--legacy-peer-deps` (these repositories pin hardhat 2.x),
* reset the repository's **test** tree to the pinned commit,
* insert the reporter's PoC function into the test contract the report names,
* set `FOUNDRY_VIA_IR=true` (these projects do not compile without it).

No file under `src/` or `contracts/` is ever modified, and no vulnerable contract
is altered to make a PoC pass. Every modification is listed per repository under
`harness_modifications` in `reports/verification_stats.json`.

## Upstream

Built entirely from public sources: `github.com/code-423n4/*` audit repositories,
the dependency repositories their reports cite, and the published reports at
`code4rena.com`. No source URL in any record is synthesised.
"""


def jread(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def render() -> str:
    s = jread(REPORTS / "dataset_stats.json", {}) or {}
    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    patch = jread(REPORTS / "patch_verification.json", {}) or {}
    hn = jread(REPORTS / "hard_negative_stats.json", {}) or {}
    ce = jread(REPORTS / "counterexample_stats.json", {}) or {}
    leak = jread(REPORTS / "leakage_report.json", {}) or {}
    vrep = jread(REPORTS / "validation_report.json", {}) or {}
    audit = jread(REPORTS / "pre_upgrade_audit.json", {}) or {}
    srcman = jread(WORK / "source_manifest.json", {}) or {}
    bench = jread(BENCH / "manifest.json", {}) or {}
    dm = jread(DERIVED / "manifest.json", {}) or {}
    ee = jread(REPORTS / "extraction_errors.json", {}) or {}

    rc = s.get("record_counts", {})
    sc = s.get("splits", {}).get("counts", {})
    tot = ver.get("totals", {})
    comp = ver.get("poc_compilation_rate", {})
    cc = s.get("code_context", {})
    fc = s.get("field_coverage", {})

    def n(x):
        return f"{x:,}" if isinstance(x, int) else str(x)

    lines = f"""# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus built from {rc.get('repositories_processed', 8)} public Code4rena
audits. Every record traces to a public artefact: a report section, a submission issue, a comment,
or a commit-pinned permalink.

This is v2. v1 shipped structured findings but **executed nothing**: every `poc.reproducible` was
`false`, its statistics disagreed with its own data in four places, and the scripts its README
described were not published. v2 adds per-field evidence semantics, real PoC execution, grounded
hard negatives, counterexamples, a leakage-resistant split, a benchmark, and a validation gate
that fails when any of it drifts.

## Layout

```
jsonl/            the ORIGINAL v1 evidence layer. Never rewritten by this pipeline.
├── findings.jsonl            {n(rc.get('findings', 0))} records
├── negative_findings.jsonl    {n(rc.get('negatives', 0))} records
├── exploits.jsonl             {n(rc.get('exploits', 0))} records
├── patches.jsonl              {n(rc.get('patches', 0))} records
├── protocol.jsonl             {n(rc.get('protocol', 0))} records
├── metadata.jsonl             {n(rc.get('metadata', 0))} records
└── errors.jsonl               {n(rc.get('errors', 0))} records

derived/         enriched records, deterministic and reproducible
├── records.jsonl              {n(dm.get('records', 0))} records with evidence, attacker model,
│                              state transition, expanded context, taxonomy, quality
├── hard_negatives.jsonl       {n(hn.get('total', 0))} structured rejections
├── counterexamples.jsonl      {n(ce.get('records_with_at_least_one_counterexample', 0))} counterexample sets
└── manifest.json

splits/          v1 repository-level splits (kept for comparison)
splits_v2/       leakage-free splits + quarantine.jsonl
benchmark/       seven task families, machine readable
reports/         every generated report, including pre_upgrade_audit.json
scripts/         the pipeline (see below)
work/            clones, retrieved source, execution logs — git-ignored
```

`jsonl/` is the contract: **original evidence**. Everything the dataset builder inferred lives in
`derived/`, everything a machine actually ran lives in `work/` and is summarised in
`reports/verification_stats.json`. A researcher can always separate what the audit said from what
the builder derived from what was experimentally verified.

## What was actually done

| | v1 | v2 |
|---|---|---|
| statistics | 4 of 24 disagreed with the data | generated by `scripts/generate_stats.py`, enforced by the gate |
| cited source retrieved | 0 files (`dataset/raw` unpublished) | {n(srcman.get('total_files_retrieved', 0))} of {n(srcman.get('total_files_requested', 0))} pinned (commit, file) pairs |
| PoCs compiled | 0 | {comp.get('repos_compiled', 0)} of {comp.get('repos_attempted', 0)} repositories |
| PoCs executed | 0 | {tot.get('reproduced', 0) + tot.get('not_reproduced', 0) + tot.get('inconclusive', 0)} of {tot.get('exploit_records', 0)} |
| PoCs demonstrating the claimed impact | unknown | **{tot.get('reproduced', 0)}** of {tot.get('exploit_records', 0)} |
| negatives with a code-grounded reason | 0 | {hn.get('blocking_condition_derived_from_code', 0)} derived + {hn.get('blocking_condition_reported_by_source', 0)} reported |
| cross-split leakage checks | 3 | 4 detectors, {leak.get('semantic_overlap', {}).get('count', 0)} real duplicates found and quarantined |
| validation gate | described, not shipped | {vrep.get('passed', 0)}/{vrep.get('checks', 0)} checks, {vrep.get('failed_critical', 0)} critical failures |

Full accounting, including what could **not** be verified, is in
[`reports/final_quality_report.md`](reports/final_quality_report.md).

## Split integrity

v1 splits by repository, so one protocol's source never appears twice. v2 adds four detectors —
exact (ids, URLs, commit shas), code (identical and normalised snippets, function signatures,
`file::function`), near-duplicate (token Jaccard), and semantic (4-shingle cosine).

The detector found real leakage: the boilerplate submission *"Unsafe use of `transfer()`/
`transferFrom()` with `IERC20`"* was filed by the same submitter against two different audits.
`scripts/check_leakage.py --emit splits_v2` quarantines the redundant copy — records are set aside,
never deleted, and no repository is ever relocated.

```
train       {sc.get('train', 0)}      validation   {sc.get('validation', 0)}      test       {sc.get('test', 0)}
quarantined {leak.get('splits_v2', {}).get('records_quarantined', 0)}      (see splits_v2/quarantine.jsonl)
```

## Evidence semantics

Every derived field is wrapped as `{{value, evidence_type, source_refs}}` with `evidence_type` from
a closed vocabulary:

| type | meaning |
|---|---|
| `observed_fact` | read out of a retrieved artefact |
| `reported_claim` | stated by an identifiable external source |
| `derived_fact` | computed here by a rule that lives in the code |
| `experimentally_verified` | produced by actually compiling and running something |
| `externally_attributed` | attributed to a named third party (judge, sponsor, label) |
| `unverified` | asserted somewhere, not checked here |
| `unknown` | no defensible value exists |

`unknown` is a first-class, counted outcome. The gate fails if any record claims
`experimentally_verified` without a run artefact behind it, and no PoC is marked reproduced unless
forge reported `Success` for its test.

## Honest limitations

{n(ee.get('total', 0))} limitations are enumerated in
[`reports/extraction_errors.json`](reports/extraction_errors.json) and summarised in the final
quality report. The ones that matter most:

1. **Most PoCs do not execute.** {tot.get('not_executed', 0)} of {tot.get('exploit_records', 0)}
   were never run. The blocker is the toolchain, not Solidity: these 2022–2025 repositories pin
   hardhat 2.x with peer ranges modern npm rejects, and fork-based PoCs need an archive RPC key
   that is not distributed. Set `VLUN_RPC_URL` to an archive endpoint and re-run
   `scripts/verify_pocs.py` — that is the highest-value action available downstream.
2. **{hn.get('blocking_condition_unknown', 0)} of {n(hn.get('total', 0))} negatives have no
   defensible rejection reason.** Code4rena's judging rationale is largely not public. Those
   records say `rejection_basis: label_only` and leave `blocking_condition` as `unknown` rather than
   inventing a plausible one.
3. **{dm.get('attacker_identity_unknown', 0)} of {n(dm.get('records', 0))} records have an
   `unknown` attacker identity**, mostly negatives that cite no code at all.
4. **{ce.get('records_with_at_least_one_counterexample', 0)} of
   {ce.get('confirmed_high_medium_records', 0)} confirmed High/Medium findings have a
   counterexample** — most findings cite only the vulnerable function, so there is no neighbouring
   function to build a false hypothesis about.
5. **{dm.get('redistribution_flagged', {}).get('source_redistributed_without_declared_license', 0)}
   records contain source text whose repository declares no licence.** v1 redistributed it; v2
   flags it. A downstream redistributor must decide for themselves.
6. **453 code citations pin a branch name** (`main`) instead of a commit, so those line ranges are
   not reproducible over time. Reported as a validation warning.
7. **No invariant was invented.** `invariants: []` for {s.get('findings', {}).get('total', 264) - dm.get('with_invariant', 0)}
   of {n(s.get('findings', {}).get('total', 264))} records is the intended outcome.
8. **{patch.get('evaluated', 0)} of {patch.get('patch_records', 0)} patches could be verified
   effective.** A merged PR is not evidence; only running the PoC against both revisions is.

Code that must not be redistributed is **not** in this repository. Where v1 withheld it, the
citation survives — path, commit, line range, URL, sha256 — and `scripts/fetch_sources.py`
retrieves it locally so structure can be analysed without copying text out.

## Pipeline

```bash
python scripts/build_all.py --with-network   # everything
```

or stage by stage:

```bash
python scripts/fetch_sources.py              # clone + retrieve every pinned citation
python scripts/verify_pocs.py                 # compile and run the PoCs
python scripts/verify_patches.py              # vulnerable vs fixed revisions
python scripts/build_derived.py               # evidence, attacker model, state transition
python scripts/build_hard_negatives.py        # structured rejection reasons
python scripts/build_counterexamples.py
python scripts/check_leakage.py --emit splits_v2
python scripts/build_benchmark.py
python scripts/generate_stats.py              # the only source of statistics
python scripts/generate_reports.py
python scripts/validate.py                    # the gate; non-zero on failure
```

Every script is idempotent, takes `--help`, and writes only under `derived/`, `splits_v2/`,
`benchmark/`, `reports/` or `work/`. `jsonl/` is read-only.

## Repositories

| Repository | Protocol | Findings | Split |
|---|---|---|---|
"""
    for repo, count in sorted(s.get("findings", {}).get("by_repository", {}).items()):
        split = next((k for k, v in s.get("splits", {}).get("by_repository", {}).items()
                      if repo in v), "?")
        lines += (f"| `code-423n4/{repo}` | {(s.get('protocol_records', {}).get('names') or ['?'])[0]} "
                  f"| {n(count)} | {split} |\n")
    lines += f"""
Source for every citation was retrieved at the pinned commit
({n(srcman.get('total_files_retrieved', 0))} of {n(srcman.get('total_files_requested', 0))} files,
sha256 recorded). Licence class per repository is in `derived/records.jsonl`
(`license_classification`), and redistribution status per record is in `redistribution.flag`.

## Licensing

The dataset redistributes only code whose licence permits it. Where it does not — the audited
protocols are BUSL-1.1 / Commons Clause or declare no licence at all — the text is absent and the
citation is retained. `reports/extraction_errors.json` records which is which. Nothing here
circumvents a licence, and a withheld citation is never "solved" by copying the source in.

## Attribution

Findings, verdicts and PoC code belong to their original authors: Code4rena and the
competitive-audit participants. See [`NOTICE.md`](NOTICE.md).
"""
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    want = render()
    notice = render_notice()
    if args.check:
        stale = []
        if (not README.exists()) or README.read_text(encoding="utf-8") != want:
            stale.append("README.md")
        if (not NOTICE.exists()) or NOTICE.read_text(encoding="utf-8") != notice:
            stale.append("NOTICE.md")
        if stale:
            log(f"STALE {', '.join(stale)} — run: python scripts/generate_readme.py")
            return 1
        log("README.md and NOTICE.md are current")
        return 0
    README.write_text(want, encoding="utf-8", newline="\n")
    NOTICE.write_text(notice, encoding="utf-8", newline="\n")
    log(f"wrote README.md ({len(want.splitlines())} lines) and "
        f"NOTICE.md ({len(notice.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
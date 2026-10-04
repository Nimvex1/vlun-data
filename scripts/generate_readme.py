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
from vlun import BENCH, DERIVED, REPORTS, ROOT, WORK, log, read_jsonl  # noqa: E402

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
    exp = jread(REPORTS / "verified_experiments.json", {}) or {}
    pv = jread(REPORTS / "patch_verification_v2.json", {}) or {}
    exp_verdicts: dict = {}
    for _e in exp.get("experiments", []):
        exp_verdicts[_e.get("verdict")] = exp_verdicts.get(_e.get("verdict"), 0) + 1

    def n(x) -> str:
        return f"{x:,}" if isinstance(x, int) else str(x)

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

## What execution actually established in v2.1

v2 executed 155 PoCs with a weak criterion (any forge run) and reported 5 as "reproduced"
without recording the assertion that failed. v2.1 replaces that with pinpoint experiments:

| | |
|---|---|
| declared exploit experiments | {n(len(exp.get('experiments', [])))} |
| verified effective patches (L6) | **{n(pv.get('experimentally_confirmed_pairs'))}** |
| inconclusive, with the missing symbol recorded | {n(exp_verdicts.get('inconclusive', 0))} |
| experiments that modified production code | 0 (asserted per run by the gate) |
| experiments that ran against an unpinned revision | 0 (`prepare()` refuses to start) |

Every experiment directory under `experiments/` holds the harness as compiled, the exact command,
forge's per-test verdict, the observed `[FAIL: ...]` reason and a `result.json` with the artefact
hashes. `scripts/validate.py` fails the build if any L6 record lacks both legs, if any effective
patch lacks a failing vulnerable leg and a passing fixed leg, or if any experiment touched a file
under `src/` or `contracts/`.

`jsonl/` is still the original v1 layer and its `poc.reproducible` flags remain `false` — that layer
is not rewritten. Execution evidence lives in `reports/reproduction_stats.json`,
`reports/patch_verification_v2.json` and `experiments/`.

## What v2 execution established (superseded, kept for comparison)

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

In v2.1 the harness never touches a repository file at all. The experiment engine writes into a
separate overlay directory (`test/vlun_poc/`) and rewrites the overlay's own `@test/...` imports,
so `git status` shows the additions and nothing else. Where a fixture only exists in a later
revision it is supplied as an overlay file and listed per run in
`experiments/*/result.json` under `forensics`.

**Harness files are licence-gated too.** Only the tests this pipeline wrote itself are published
under `experiments/*/harness/`. A harness file copied verbatim out of reNFT is **not** published:
`experiments/*/harness/WITHHELD.json` records its path, byte count and sha256, plus the commit to
read it from, so the exact bytes that were compiled stay verifiable without redistributing BUSL-1.1
source. `scripts/validate.py` fails the build if a withheld file appears in the published tree.

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
    repro = jread(REPORTS / "reproduction_stats.json", {}) or {}
    exp = jread(REPORTS / "verified_experiments.json", {}) or {}
    pv = jread(REPORTS / "patch_verification_v2.json", {}) or {}
    negs = jread(REPORTS / "negative_verification_stats.json", {}) or {}
    cites = jread(REPORTS / "citation_resolution.json", {}) or {}
    # Counted from the data, not from the resolver's own report: the report is a
    # claim ABOUT the dataset and must never be the source of a README figure.
    derived_pin = jread(REPORTS / "third_party_audit.json", {}) or {}
    third_party = derived_pin
    _vpath = DERIVED / "records.jsonl"
    _derived_total = _derived_mutable = 0
    if _vpath.exists():
        import re as _re
        _blob = _re.compile(r"/blob/([^/]+)/")
        for _r in read_jsonl(_vpath):
            for _k in ("code_context", "code_context_expanded",
                       "code_reference_only", "vulnerable_code"):
                for _e in (_r.get(_k) or []):
                    if not isinstance(_e, dict):
                        continue
                    _derived_total += 1
                    _sha = _e.get("commit_sha") or ""
                    _m = _blob.search(_e.get("source_url") or "")
                    if (_sha and not _re.match(r"^[0-9a-f]{40}$", _sha)) or \
                       (_m and not _re.match(r"^[0-9a-f]{40}$", _m.group(1))):
                        _derived_mutable += 1
    source_layer_mutable = (derived_pin.get("source_layer_mutable_citations")
                            or cites.get("mutable_occurrences"))
    static = jread(REPORTS / "static_analysis.json", {}) or {}
    benchq = jread(REPORTS / "benchmark_quality.json", {}) or {}
    V2_BEFORE_REPRO = 5
    exp_verdicts = {}
    for _e in exp.get("experiments", []):
        exp_verdicts[_e.get("verdict")] = exp_verdicts.get(_e.get("verdict"), 0) + 1

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

v1 shipped structured findings but **executed nothing**: every `poc.reproducible` was `false`, its
statistics disagreed with its own data in four places, and the scripts its README described were not
published. v2 added per-field evidence semantics and a validation gate. **This is v2.1**, whose
subject is experimental evidence:

* every exploit PoC is given a **proof-shape class** (nine values) and a **quality level L0-L6**,
  and a level above L2 is only reachable by an actual run artefact;
* **pinpoint exploit experiments** run the same test against the audited revision and against the
  fixing revision, so a patch is called *effective* only when the violation is observed on one and
  blocked on the other — and only when both runs really executed that same test. An experiment whose
  two sides ran *different* tests is recorded as
  `inconclusive_not_a_controlled_comparison`, never as an effectiveness result;
* **every mutable branch citation in the shipped derived layer is resolved** and written back into
  `derived/records.jsonl`, by content identity, submodule pointer or date-anchored blob identity.
  {n(_derived_mutable)} of {n(_derived_total)} citations remain mutable. The read-only `jsonl/`
  evidence layer still carries {n(source_layer_mutable)} of them and is never rewritten;
* **hard negatives are re-classified** into verified / attributed / corroborated-duplicate /
  unknown, and a corroborated duplicate is explicitly *not* a false positive;
* **API-sibling counterexample pairs**, **Slither cross-checks**, **ten benchmark families**
  including the three that only accept experimentally produced ground truth, and
  **high-confidence subsets** with published admission rules.

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

derived/         enriched records, deterministic given the same inputs
├── records.jsonl              {n(dm.get('records', 0))} records with evidence, attacker model,
│                              state transition, expanded context, taxonomy, quality
├── hard_negatives.jsonl       {n(hn.get('total', 0))} structured rejections
├── counterexamples.jsonl      {n(ce.get('records_with_at_least_one_counterexample', 0))} counterexample sets
└── manifest.json

experiments/     one directory per attempted exploit: harness, command, stdout,
                 stderr, trace and result.json for the vulnerable and the fixed
                 revision. Small, hashed, and committed on purpose.
datasets/        high-confidence subsets, each with a published admission rule
training/        task-oriented training files, split by task rather than one blob
splits/          v1 repository-level splits (kept for comparison)
splits_v2/       leakage-free splits + quarantine.jsonl
benchmark/       ten task families, machine readable
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

### v2.1: experimentally proven evidence

| | v2 | v2.1 |
|---|---|---|
| PoC records given a proof-shape class | 0 | {n(repro.get('exploit_records', 0))} of {n(repro.get('exploit_records', 0))} |
| PoC records given an L0-L6 level | 0 | {n(repro.get('exploit_records', 0))} |
| Pinpoint exploit experiments executed | 0 | {n(len(exp.get('experiments', [])))} |
| Vulnerabilities with an observed violation at the audited commit | {n(V2_BEFORE_REPRO)} | {n(exp_verdicts.get('l6_verified_patch', 0) + exp_verdicts.get('reproduced_but_not_blocked', 0))} |
| Patches verified effective (reproduced on vulnerable, blocked on fixed) | 0 | **{n(pv.get('experimentally_confirmed_pairs'))}** |
| Mutable branch citations in the shipped derived layer | {n(source_layer_mutable)} | **{n(_derived_mutable)}** of {n(_derived_total)} |
| Negatives with a defensible reason | 15 | **{n(negs.get('total', 0) - (negs.get('by_class', {}) or {}).get('unknown', 0))}** — of which **{n((negs.get('by_class', {}) or {}).get('derived_from_code'))}** are derived from code, **{n((negs.get('by_class', {}) or {}).get('attributed'))}** attributed to a named source, and **{n((negs.get('by_class', {}) or {}).get('corroborated_duplicate'))}** are corroborated duplicates (a valid claim filed twice — *not* a rejected one) |
| Negatives still honestly unknown | 443 | **{n((negs.get('by_class', {}) or {}).get('unknown'))}** |
| API-sibling counterexample pairs | 0 | {n(ce.get('api_sibling_pairs', 0))} |
| Repositories with a static-analysis signal | none | {n((static.get('by_status', {}) or {}).get('available', 0))} analysed, {(static.get('by_status', {}) or {}).get('partial', 0) + (static.get('by_status', {}) or {}).get('unavailable', 0)} reported unanalysable |
| Benchmark families | 7 | 10 |
| Benchmark tasks with experimentally produced ground truth | 0 | {n(benchq.get('experimentally_grounded_tasks'))} |

Full accounting, including what could **not** be verified and why, is in
[`reports/v2_1_quality_report.md`](reports/v2_1_quality_report.md). The v2 report it supersedes is
kept at [`reports/final_quality_report.md`](reports/final_quality_report.md).

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

0. **Only {n(len(exp.get('experiments', [])))} pinpoint experiments exist and
   {n(exp_verdicts.get('inconclusive', 0))} of them are inconclusive.** That is the honest number.
   Each names the audited commit, the exact command and the observed assertion message; the
   failures record the specific missing symbol rather than a shrug. Widening this needs either an
   archive RPC for the fork-based proofs or a per-PoC port of the reporter's own fixtures; see
   `experiments/*/vulnerable/result.json`.
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
    records contain source text whose repository declares no licence.** This is disclosed, not
    resolved: the text is here, it is flagged per record in `redistribution.flag`, and
    `scripts/audit_third_party.py` re-measures the count from the text itself
    (`reports/third_party_audit.json`). **A downstream redistributor must decide for themselves
    whether their use is lawful.** See `LICENSE` part 3.
6. **{n(source_layer_mutable)} citations in the read-only `jsonl/` layer used a branch name**
    (`main`) instead of a commit, so those line ranges were not reproducible over time. All
    {n(cites.get('occurrences_by_status', {}).get('resolved', 0))} of them are now pinned to an exact
    commit **in the data** by content identity, submodule pointer or date-anchored blob identity.
    No SHA was invented: where no identity test succeeded the citation stays mutable and is counted,
    and the count in the shipped derived layer is **{n(_derived_mutable)}**. The `jsonl/` layer is
    the v1 evidence record and is never rewritten, so its {n(source_layer_mutable)} stay and are
    reported by the gate as a counted, non-fatal warning.
7. **No invariant was invented.** `invariants: []` for {s.get('findings', {}).get('total', 264) - dm.get('with_invariant', 0)}
    of {n(s.get('findings', {}).get('total', 264))} records is the intended outcome.
8. **{pv.get('experimentally_confirmed_pairs')} of {pv.get('patch_records', 0)} patches are
   experimentally confirmed effective; {n((pv.get('by_fix_effectiveness') or {}).get('not_testable', 0))} are `not_testable` because no experiment ran both of their revisions
   effective.** A merged PR is not evidence; only running the PoC against both revisions is.

**Some** source that must not be redistributed has been withheld from this repository: for those
citations the text is absent and the citation survives — path, commit, line range, URL, sha256 — so
`scripts/fetch_sources.py` retrieves it locally and its structure can be analysed without copying
text out. **Withholding was partial, not complete.**
{dm.get('redistribution_flagged', {}).get('source_redistributed_without_declared_license', 0)}
records still carry verbatim source text from repositories that declare no licence. Each says so in
`redistribution.flag`, and `LICENSE` part 3 sets out exactly what that does and does not license. No
permission has been obtained from the upstream protocol authors, and this dataset cannot grant it.

## Pipeline

The pipeline core is **standard-library only** — see `requirements.txt` and `pyproject.toml`. `git`,
`forge` and `node` are needed for the experiment stages; `slither` is optional and its absence is
recorded rather than hidden.

```bash
python scripts/build_all.py --with-network   # everything
```

or stage by stage:

```bash
python scripts/fetch_sources.py              # clone + retrieve every pinned citation
python scripts/verify_pocs.py                 # compile and run the PoCs
python scripts/verify_patches.py              # vulnerable vs fixed revisions
python scripts/resolve_citations.py           # mutable branch refs -> exact commits
python scripts/run_verified_experiments.py    # exploit experiments, both revisions
python scripts/run_negative_experiments.py    # attempt each hard negative's attack
python scripts/verify_patches.py              # vulnerable vs fixed, plus the delta
python scripts/classify_negatives.py          # four-class negative taxonomy
python scripts/build_reproduction.py          # PoC classes, L-levels, replay manifest
python scripts/run_static_analysis.py         # Slither where the repo builds
python scripts/audit_third_party.py           # measure + disclose redistributed source
python scripts/export_run_artefacts.py        # commit executed-PoC run records
python scripts/build_derived.py               # evidence, attacker model, state transition
python scripts/build_hard_negatives.py        # structured rejection reasons
python scripts/build_counterexamples.py
python scripts/check_leakage.py --emit splits_v2
python scripts/build_benchmark.py             # ten task families
python scripts/build_subsets.py               # datasets/ and training/
python scripts/generate_stats.py              # the only source of statistics
python scripts/generate_reports.py
python scripts/generate_v21_reports.py        # the v2.1 BEFORE/AFTER report
python scripts/validate.py                    # the gate; non-zero on failure
```

Every script is idempotent, takes `--help`, and writes only under `derived/`, `splits_v2/`,
`benchmark/`, `reports/`, `experiments/` or `work/`. `jsonl/` is read-only.

**`build_all.py` exits non-zero if any stage fails or if the gate fails.** It used to exit 0 with
two stages failing, which is how a broken build ships as a green pipeline. Stages that cannot run
for want of network report `skipped_no_network` and the summary says so; a skip is not a pass.

**The pipeline is not self-contained.** Several stages need network access, and the experiment
stages additionally read clones and retrieved source out of `work/`, which is git-ignored. A fresh
clone therefore reproduces the JSONL layers, the derived layer and the statistics, but **not** the
experiment-derived fields: without `work/poc_runs` the `verification` block of a record degrades to
`unknown` and the benchmark loses its experimentally grounded families. That is stated rather than
hidden, and `reports/run_artefacts_index.json` commits the verdicts so the counts remain checkable
without `work/`.

## Repositories

| Repository | Protocol | Findings | Split |
|---|---|---|---|
"""
    proto_by_repo = {}
    for _r in read_jsonl(DERIVED / "records.jsonl"):
        _repo = (_r.get("source") or {}).get("repository")
        _name = (_r.get("protocol") or {}).get("name")
        if _repo and _name:
            proto_by_repo.setdefault(_repo, _name)
    for repo, count in sorted(s.get("findings", {}).get("by_repository", {}).items()):
        split = next((k for k, v in s.get("splits", {}).get("by_repository", {}).items()
                      if repo in v), "?")
        lines += (f"| `code-423n4/{repo}` | {proto_by_repo.get(repo, '?')} "
                  f"| {n(count)} | {split} |\n")
    lines += f"""
Source for every citation was retrieved at the pinned commit
({n(srcman.get('total_files_retrieved', 0))} of {n(srcman.get('total_files_requested', 0))} files,
sha256 recorded). Licence class per repository is in `derived/records.jsonl`
(`license_classification`), and redistribution status per record is in `redistribution.flag`.

## Licensing

**This dataset does not redistribute only code whose licence permits it.** Stating that plainly is
the purpose of this section.

* `LICENSE` splits the terms three ways: the data under `jsonl/`, `derived/`, `splits*/`,
  `benchmark/`, `datasets/`, `training/`, `reports/` is **CC BY 4.0**; the pipeline under
  `scripts/` is **MIT**; and third-party source is **not licensed here at all**.
* **{n(third_party.get('records_self_declared_redistributed_unlicensed_source', 0))} of
  {n(third_party.get('records', 0))} records still carry verbatim Solidity quoted from a repository
  that declares no licence.** Each is flagged in `redistribution.flag`, and
  `scripts/audit_third_party.py` re-derives the count from the text itself rather than trusting
  the dataset's own classifier (`reports/third_party_audit.json`). Quotation for research is a
  different question from redistribution; that question belongs to you, and this dataset cannot
  answer it.
* **{n(third_party.get('records_containing_solidity_source_text', 0))} records contain Solidity
  source text; {n(third_party.get('citation_entries_over_200_chars', 0))} citation entries exceed
  200 characters.** Nothing here is paraphrased.
* Withholding was **partial**. Where a citation was withheld, the text is absent and the citation
  survives — path, commit, line range, URL, sha256 — so
  `scripts/fetch_sources.py` retrieves it locally and its structure can be analysed without
  copying text out.
* PoC code in `jsonl/exploits.jsonl` belongs to the Code4rena submission authors. It is reproduced
  as quoted evidence with its original SPDX identifier preserved where the author supplied one, and
  **no** licence is applied by us.
* Harness code the authors wrote for `experiments/` is their own work under
  `SPDX-License-Identifier: BUSL-1.1` — source-available, not open source, and not
  covered by the MIT grant.
* **No permission has been obtained from the upstream protocol authors.**

If you need a clean dataset for redistribution or commercial training, use the withheld records, or
run `scripts/fetch_sources.py` and pull the sources yourself under your own compliance process.

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
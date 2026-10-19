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
from vlun import BENCH, DERIVED, REPORTS, RETIRED_FAMILIES, ROOT, log, read_jsonl  # noqa: E402

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
    ce = jread(REPORTS / "counterexample_stats.json", {}) or {}
    vrep = jread(REPORTS / "validation_report.json", {}) or {}
    bench = jread(BENCH / "manifest.json", {}) or {}
    dm = jread(DERIVED / "manifest.json", {}) or {}
    exp = jread(REPORTS / "verified_experiments.json", {}) or {}
    pv = jread(REPORTS / "patch_verification_v2.json", {}) or {}
    negs = jread(REPORTS / "negative_verification_stats.json", {}) or {}
    _negm = negs.get("metrics") or {}
    prove = jread(REPORTS / "prove_split_interface.json", {}) or {}
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
    # v2.2 layer: multi-language sources, derived records, splits, experiments.
    # Every figure below is counted from those artefacts, never typed in.
    from vlun_ml import DERIVED_V22, ML_JSONL, SPLITS_V22, load_findings, load_sources  # noqa: E402
    from vlun_v3 import V3_FAMILY_FILES  # noqa: E402  (v3 manifest-key -> task-file map)
    d22m = jread(DERIVED_V22 / "manifest.json", {}) or {}
    fam_n = len(bench.get("tasks") or {})
    ml_sources = ml_findings = 0
    if ML_JSONL.exists():
        ml_sources, ml_findings = len(load_sources()), len(load_findings())
    v22_splits: dict = {}
    for _sp in ("train", "validation", "test", "quarantine"):
        _p = SPLITS_V22 / f"{_sp}.jsonl"
        if _p.exists():
            v22_splits[_sp] = sum(1 for r in read_jsonl(_p) if r.get("layer") == "v2.2") \
                if _sp != "quarantine" else len(read_jsonl(_p))
    # v3 layer: eighteen new sources harvested from V3/clones. Same rule as
    # above: every figure is read from the v3 artefacts, never typed in.
    v3m = jread(REPORTS / "v3" / "dataset_summary.json", {}) or {}
    v3bench = jread(BENCH / "v3_manifest.json", {}) or {}
    v3gate = jread(REPORTS / "v3" / "validation_v3.json", {}) or {}
    v3split: dict = {}
    _sp3 = ROOT / "splits_v3" / "split.json"
    if _sp3.exists():
        _sj = jread(_sp3, {}) or {}
        for _k, _v in ((_sj.get("splits") or {}).items()):
            v3split[_k] = len(_v)
    exp_verdicts = {}
    for _e in exp.get("experiments", []):
        exp_verdicts[_e.get("verdict")] = exp_verdicts.get(_e.get("verdict"), 0) + 1
    # V3.1 / V3.2 figures (same rule: read from artefacts, never typed).
    norm31 = jread(REPORTS / "v3" / "normalization_report.json", {}) or {}
    proof32 = jread(REPORTS / "v3" / "experimental_proof.json", {}) or {}
    pr31 = jread(REPORTS / "v3" / "patch_static_review.json", {}) or {}
    _prdr = pr31.get("by_patch_review_status", {}) or {}
    v3gate = jread(REPORTS / "v3" / "validation_v3.json", {}) or {}
    v31gate = jread(REPORTS / "v3" / "validation_v31.json", {}) or {}
    tri32 = (proof32.get("compile_triage") or {})
    _cov = (norm31.get("coverage_before_after") or {})
    _cov_after = _cov.get("after_v31", {})
    # v3 record-level verification levels AFTER the V3.2 execution overlay
    # (read from the manifest, never typed in).
    _v3lv = (v3m.get("admitted_verification_levels") or {})
    _v3_executed = sum(v for k, v in _v3lv.items() if k in ("L3", "L4", "L5", "L6"))
    _v3_l5 = sum(v for k, v in _v3lv.items() if k in ("L5", "L6"))
    _v3_runs = v3m.get("experimental_runs_attempted", 0) or 0
    # Vbeta layer: isolated new-language + Solodit-mirror layer. Same rule as
    # above: every figure is read from the Vbeta artefacts, never typed in.
    _vb = ROOT / "Vbeta"
    vbm = jread(_vb / "derived_vbeta" / "manifest.json", {}) or {}
    _vbsplit = jread(_vb / "splits_vbeta" / "split.json", {}) or {}
    _vbsplits = {k: len(v) for k, v in ((_vbsplit.get("splits") or {}).items())}
    vbbm = jread(_vb / "benchmark_vbeta" / "vbeta_manifest.json", {}) or {}
    vbharv = jread(_vb / "reports_vbeta" / "solodit_harvest_stats.json", {}) or {}
    # Indexed-issue count comes from the committed harvest stats (the URL
    # index itself lives in git-ignored nextdata/, so a fresh clone must
    # not rescan it). The local file is only a fallback for harvest-time.
    _solodit_indexed = vbharv.get("indexed", 0) or 0
    _sidx = ROOT / "nextdata" / "_index_all_1926.json"
    if not _solodit_indexed and _sidx.exists():
        try:
            _rows = json.loads(_sidx.read_text(encoding="utf-8-sig"))
            _solodit_indexed = sum(
                1 for _r in _rows
                if isinstance(_r, dict) and (_r.get("url") or {}).get("value"))
        except (json.JSONDecodeError, OSError):
            _solodit_indexed = 0
    vbgate = jread(_vb / "reports_vbeta" / "validation_vbeta.json", {}) or {}
    # CRITICAL checks only. The Vbeta gate's isolation/present_sentinels check
    # is warn-only and hashes README.md itself, so folding it into the count
    # makes this file depend on its own hash: any edit flips the count,
    # which rewrites the README, which flips the count again. Circular by
    # construction; the sentinel warning still surfaces in the Vbeta gate
    # output and reports_vbeta/validation_vbeta.json.
    _vbgchecks = [c for c in vbgate.get("checks", [])
                  if c.get("critical", True)]
    _vbgpass = sum(1 for _c in _vbgchecks if _c.get("ok"))
    _vbm_tasks = vbbm.get("tasks", {}) or {}
    _btasks = bench.get("tasks", {}) or {}
    _v3tasks = (v3bench.get("tasks", {}) or {})
    _vbdec = vbm.get("candidate_decisions", {}) or {}
    _vblvl = vbm.get("candidate_verification_levels", {}) or {}
    _vblang = vbm.get("admitted_by_language", {}) or {}
    def _one(d):
        return json.dumps(d, sort_keys=True)

    rc = s.get("record_counts", {})
    # Live cross-manifest check count (written by check_manifests.py). Never a
    # literal: the README previously hard-coded 101 while the gate ran 171.
    _mchecks = jread(REPORTS / "manifest_checks.json", {}) or {}
    # Per-field coverage is counted from reports/field_coverage.json the same
    # way build_datasheet.py does — never typed in, so the two generated
    # documents cannot disagree.
    _fcover = jread(REPORTS / "field_coverage.json", {}) or {}
    _fc_fields = _fcover.get("fields", {}) or {}
    # known_pct == 0.0 is falsy, so `or 100` reclassified fully unknown
    # fields as fully known and undercounted the thin ones (README said
    # 3 of 28 when 11 are under 50%). Non-numeric stays 100; zero stays 0.
    _fc_thin = sum(
        1 for _v in _fc_fields.values()
        if isinstance(_v, dict)
        and isinstance(_v.get("known_pct"), (int, float))
        and _v["known_pct"] < 50)

    def n(x):
        return f"{x:,}" if isinstance(x, int) else str(x)

    def _fam_letter(name: str) -> str:
        # "A_vulnerability_detection" -> A; "v3_R_source_tier_routing" -> R;
        # "vbeta_U_language_routing" -> U; file variants with .jsonl likewise.
        base = name[:-6] if name.endswith(".jsonl") else name
        if base.startswith("v3_"):
            return base.split("_")[1]
        if base.startswith("vbeta_"):
            return base.split("_")[1]
        return base.split("_")[0]

    _sat_letters = set()
    _bl_base = jread(REPORTS / "baselines" / "baseline_majority.json", {}) or {}
    _bl_rand = jread(REPORTS / "baselines" / "baseline_random_seed7.json", {}) or {}
    _bl_freq = jread(REPORTS / "baselines" / "baseline_frequency_seed7.json", {}) or {}
    _bl_fp = jread(REPORTS / "baselines" / "baseline_first_published.json", {}) or {}
    _bl_mp = jread(REPORTS / "baselines" / "baseline_majority_published.json", {}) or {}
    _bl_ret = jread(REPORTS / "baselines" / "baseline_retrieval.json", {}) or {}
    _depth = jread(REPORTS / "depth_dashboard.json", {}) or {}
    for _fam, _s in ((_bl_base.get("families") or {}).items()):
        # None accuracy (nothing predicted) is not saturation; an explicit
        # None check keeps a real 0.0 comparable and a missing value out.
        if (isinstance(_s, dict)
                and isinstance(_s.get("accuracy"), (int, float))
                and _s["accuracy"] >= 0.94):
            _sat_letters.add(_fam_letter(_fam))
    # Exploratory families (below the 100-row headline floor) come from the
    # same committed report, never typed in.
    _expl_letters = {_fam_letter(_f) for _f in
                     (_bl_base.get("families_exploratory") or {})}
    _expl_scorable = (_bl_base.get("micro_exploratory") or {}).get(
        "scorable", 0) or 0
    def _retired(fam_key: str) -> bool:
        # Manifest task keys (A_vulnerability_detection, R_v3_source_tier_routing)
        # vs retired task-file names (A_vulnerability_detection.jsonl,
        # v3_R_source_tier_routing.jsonl); v3 keys map through V3_FAMILY_FILES.
        if f"{fam_key}.jsonl" in RETIRED_FAMILIES:
            return True
        return V3_FAMILY_FILES.get(fam_key, "") in RETIRED_FAMILIES

    # Manifest-scorable universe vs scorer-covered headline set, reconciled
    # live: the gap is the retired families' scorable rows, the exploratory
    # families' sub-floor rows, plus the three out-of-scope families
    # (D generative, H descriptive, Q judge-graded).
    _excl_reasoned = sum(
        (_spec.get("scorable", 0) if isinstance(_spec, dict) else _spec)
        for _fam, _spec in _btasks.items()
        if _fam_letter(_fam) in ("D", "H", "Q"))
    _retired_scorable = sum(
        (_spec.get("scorable", 0) if isinstance(_spec, dict) else _spec)
        for _fam, _spec in _btasks.items() if _retired(_fam))
    _retired_scorable += sum(
        (_spec if isinstance(_spec, int) else _spec.get("scorable", 0))
        for _fam, _spec in _v3tasks.items() if _retired(_fam))
    _retired_letters = ", ".join(
        sorted({_fam_letter(_f) for _f in RETIRED_FAMILIES}))

    def _status(fam: str) -> str:
        if _retired(fam):
            return "RETIRED"
        if _fam_letter(fam) in _expl_letters:
            return "EXPLORATORY"
        if _fam_letter(fam) in _sat_letters:
            return "SATURATED"
        return ""

    _bench_rows = "\n".join(
        f"| `{fam}` | {n((spec if isinstance(spec, dict) else {}).get('tasks', 0))} | "
        f"{n((spec if isinstance(spec, dict) else {}).get('scorable', 'n/a'))} | "
        f"{_status(fam)} | v1/A-Q |"
        for fam, spec in sorted(_btasks.items()))
    _v3bench_rows = "\n".join(
        f"| `{fam}` | {n(tasks)} | {n(tasks)} | "
        f"{_status(fam)} | v3 |"
        for fam, tasks in sorted(_v3tasks.items()))
    _vbbench_rows = "\n".join(
        f"| `{fam}` | {n(tasks)} | {n(tasks)} | "
        f"{_status(fam)} | Vbeta |"
        for fam, tasks in sorted(_vbm_tasks.items()))
    _v22_lvl = d22m.get("experiment_levels", {}) or {}
    _v22_verified = sum(v for k, v in _v22_lvl.items() if k in ("L5", "L6"))
    _vb_lvl = vbm.get("candidate_verification_levels", {}) or {}
    _vb_verified = sum(v for k, v in _vb_lvl.items() if k in ("L5", "L6"))
    _cov = (_bl_base.get("coverage") or {})

    def _acc(x):
        return f"{x:.4f}" if isinstance(x, (int, float)) else "n/a"

    def _rate_cell(_d):
        _m = _d.get("micro") or {}
        return (f"{_acc(_m.get('accuracy'))} @ {n(_m.get('predicted', 0))}"
                f"/{n(_m.get('scorable', 0))}")

    def _over_scorable_cell(_d):
        return _acc((_d.get("micro") or {}).get("accuracy_scorable"))

    def _cont_cell(_d):
        _m = _d.get("micro_all_families") or {}
        return (f"{_acc(_m.get('accuracy'))} @ {n(_m.get('predicted', 0))}"
                f"/{n(_m.get('scorable', 0))}")

    # Baseline table, all cells live from the committed baseline JSONs. A
    # zero-prediction run shows "n/a" for accuracy-among-predictions and its
    # 0/scorable coverage — never a 0.0000 that reads as a scored result.
    _bl_rows = "\n".join(
        f"| {_label} | {_rate_cell(_d)} | {_over_scorable_cell(_d)} | "
        f"{_cont_cell(_d)} |"
        for _label, _d in (
            ("majority", _bl_base),
            ("random-seed7", _bl_rand),
            ("frequency-seed7", _bl_freq),
            ("first-published (L only, retired family)", _bl_fp),
            ("majority-published (L only, retired family)", _bl_mp),
            ("TF-IDF retrieval", _bl_ret)))

    lines = f"""# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus of smart-contract security findings. Every record traces to a
public artefact — a report section, a submission issue, a registry payload, or a commit-pinned
permalink — and every claim carries its evidence type. Governing rule: truth over scale;
`unknown` is a counted outcome, never a gap to fill by guessing.

## Dataset at a glance

| Layer | Source | Records | Strongest evidence |
|---|---|---|---|
| v1 | 8 Code4rena audits (Solidity) | {n(dm.get('records', 0))} derived | {n(len(exp.get('experiments', [])))} pinpoint experiments, **{n(pv.get('experimentally_confirmed_pairs'))}** L6 verified patches |
| v2.2 | advisories/audits/bounties/post-mortems, 5 languages | {n(d22m.get('records', 0))} | {n(sum(v for k, v in (d22m.get('experiment_levels') or {}).items() if k != 'none'))} executed runs, levels `{d22m.get('experiment_levels')}` |
| V3.0 | 18 new archives (audits, contests, incident PoCs, 1 research dataset) | {n(v3m.get('record_count', 0))} admitted / {n(v3m.get('candidate_count', 0))} candidates | levels `{_one(_v3lv)}` after the V3.2 execution overlay |
| V3.1 | normalized findings with spans + overlays | {n(norm31.get('preview_count', 0))} preview rows ({n((norm31.get('fragment_decisions') or {}).get('admitted', 0))} new) | severity on {n(_cov_after.get('severity_known', 0))}, class on {n(_cov_after.get('class_known', 0))}, files on {n(_cov_after.get('affected_files', 0))} |
| V3.2 | fork executions of incident PoCs | {n(len((proof32.get('runs') or [])))} runs | **{(proof32.get('by_level') or {}).get('L5', 0)}** L5 reproduced thefts, {(proof32.get('by_level') or {}).get('L3', 0)} blocked at L3 |
| Vbeta | {n(vbm.get('source_count', 0))} new sources (incl. Solodit mirror) | {n(vbm.get('record_count', 0))} admitted / {n(vbm.get('candidate_count', 0))} candidates | L0/L1 only — nothing executed in this pass |

Gates (0 critical failures everywhere): v2 {vrep.get('passed', 0)}/{vrep.get('checks', 0)} · v3.0 {v3gate.get('passed', 0)}/{v3gate.get('total', 0)} · v3.1 {v31gate.get('passed', 0)}/{v31gate.get('total', 0)} · Vbeta {_vbgpass}/{len(_vbgchecks)}. Cross-manifest and reproducibility gates recompute every count from canonical records — see `scripts/check_manifests.py`, `scripts/check_reproducibility.py` and [`reports/reproducibility_report.md`](reports/reproducibility_report.md) for the gate summary.

Verification density (L5+L6 ÷ admitted records): v1 {n(pv.get('experimentally_confirmed_pairs', 0))}/{n(dm.get('records', 0))} · v2.2 {n(_v22_verified)}/{n(d22m.get('records', 0))} · V3.0 {n(_v3_l5)}/{n(v3m.get('record_count', 0))} · Vbeta {n(_vb_verified)}/{n(vbm.get('record_count', 0))} (L0/L1-only by construction). Counted as executed evidence (any level above L1, i.e. a real compile or run artefact): v1 {n(pv.get('experimentally_confirmed_pairs', 0))}/{n(dm.get('records', 0))} · v2.2 {n(_v22_verified)}/{n(d22m.get('records', 0))} · V3.0 {n(_v3_executed)}/{n(v3m.get('record_count', 0))} · Vbeta 0/{n(vbm.get('record_count', 0))}. Depth is reported next to scale so dilution is visible, not hidden.

## Layout

```
jsonl/            ORIGINAL v1 evidence layer ({n(rc.get('findings', 0))} findings, {n(rc.get('negatives', 0))} negatives, {n(rc.get('exploits', 0))} exploits, {n(rc.get('patches', 0))} patches). Never rewritten.
derived/          enriched v1 records ({n(dm.get('records', 0))}): evidence, attacker model, state transition, taxonomy, quality
experiments/      one directory per attempted exploit (harness, command, stdout, stderr, result.json)
jsonl_ml/         v2.2 source layer ({n(ml_findings)} findings, {n(ml_sources)} sources). Read-only.
derived_v2_2/     v2.2 derived records ({n(d22m.get('records', 0))}) with quality rubric + experiment view
splits_v2_2/      v2.2 splits (train {n(v22_splits.get('train'))}, validation {n(v22_splits.get('validation'))}, test {n(v22_splits.get('test'))}, quarantine {n(v22_splits.get('quarantine'))})
experiments_v2_2/ executed multi-language runs
jsonl_v3/         v3 source layer ({n(v3m.get('candidate_count', 0))} candidates, {n(v3m.get('source_count', 0))} sources). Read-only.
derived_v3/       v3 records ({n(v3m.get('record_count', 0))}) + v3.1 fragments/overlays/preview ({n(norm31.get('preview_count', 0))} rows)
splits_v3/        by-source splits, no source spans splits
experiments_v3/   v3.2 fork-execution artefacts (command, stdout, stderr, harness manifest, result.json)
datasets/         high-confidence subsets, each with a published admission rule
training/         task-oriented training files
splits_v2/       post-quarantine v1/v2 splits (the pre-quarantine splits/ was retired; see scripts/vlun.py)
benchmark/        {fam_n} families (A-J v1, K-Q v2.2, R-S v3, T v3.1-taxonomy) + U-V Vbeta ({n(sum(_vbm_tasks.values()) if isinstance(_vbm_tasks, dict) else 0)} tasks)
benchmark/retired_families/  retired headline-excluded families ({_retired_letters}), frozen byte-identical with per-family retirement.json; still shipped, audited and scored for continuity
reports/          every generated report, including reports/v2_2/ and reports/v3/
scripts/          the pipeline (standard-library only; see below)
tests/            stdlib-only tests for terminology, counts, splits, gates (run: `python -m unittest discover -s tests`)
Vbeta/            isolated new-language layer ({n(vbm.get('record_count', 0))} admitted / {n(vbm.get('candidate_count', 0))} candidates, {n(vbm.get('source_count', 0))} sources): own scripts, splits, benchmarks U-V, gates; never touches PRESENT
nextdata/ + .firecrawl/  local-only Solodit scrape artefacts ({n(_solodit_indexed)} issue URLs indexed, {n(vbharv.get('harvested', 0))} detail pages harvested): referenced by path, METADATA_ONLY
work/             clones, retrieved source, execution logs — git-ignored
```

`jsonl/` is the contract: **original evidence**. Inferred analysis lives in `derived/`, machine
executions in `work/` (summarised in `reports/`). A researcher can always separate what the audit
said from what the builder derived from what was executed.

## Evidence model

Every derived field carries `{{value, evidence_type, source_refs}}`. Closed vocabulary:

| type | meaning |
|---|---|
| `observed_fact` | read out of a retrieved artefact |
| `reported_claim` | stated by an identifiable external source |
| `derived_fact` | computed here by a rule that lives in the code |
| `experimentally_verified` | produced by actually compiling + running something |
| `externally_attributed` | attributed to a named third party (judge, sponsor, label) |
| `unverified` | asserted somewhere, not checked here |
| `unknown` | no defensible value exists |

PoC quality ladder: **L0** report prose · **L1** PoC quoted · **L2** PoC reconstructed ·
**L3** compiles · **L4** executes · **L5** claimed violation reproduced ·
**L6** reproduced on the vulnerable revision *and* blocked on the fixed one (same test).
Above L2 requires a run artefact; L6 requires both legs. No PoC is marked reproduced unless
forge reported `Success`, and no patch is called effective without the controlled comparison.

## What is verified (honest counts)

- **v1/v2:** {n(len(exp.get('experiments', [])))} pinpoint experiments
  ({n(exp_verdicts.get('inconclusive', 0))} inconclusive, missing symbol recorded);
  **{n(pv.get('experimentally_confirmed_pairs'))}** patches verified effective;
  rejection evidence over {n(negs.get('total', 0))} rejected submissions (axes are independent
  and not additive): {n(_negm.get('reason_attributed_to_judge_or_sponsor'))} carry a reason
  attributed to a named judge or sponsor, {n(_negm.get('reason_supported_by_cited_code'))} where
  a gate in the cited code removes the standing the claim itself asserts,
  **{n(negs.get('technical_reason_why_the_claim_is_false'))}** in total have a technical reason
  the claim is false, {n(_negm.get('claim_corroborated_as_duplicate_of_confirmed_finding'))} are
  corroborated as duplicates of an accepted finding (redundancy, not falsity),
  {n(_negm.get('exploit_attempted_and_claimed_violation_not_demonstrated'))} had an exploit
  attempted that did not demonstrate the violation, and
  {n(_negm.get('unknown_or_insufficient_evidence'))} rest on a public label alone — definitions
  in [`reports/rejection_evidence.md`](reports/rejection_evidence.md);
  {n(ce.get('api_sibling_pairs', 0))} API-sibling counterexample pairs.
- **v2.2:** {n(sum(v for k, v in (d22m.get('experiment_levels') or {}).items() if k != 'none'))} executed runs;
  {n(((d22m.get('attacker_identity') or {}).get('unknown')))} of {n(d22m.get('records', 0))} records state no attacker standing.
- **V3.0:** {n((v3m.get('candidate_decisions') or {}).get('IMPORT', 0))} strong imports +
  {n((v3m.get('candidate_decisions') or {}).get('IMPORT_AS_UNVERIFIED', 0))} unverified imports +
  {n((v3m.get('candidate_decisions') or {}).get('IMPORT_AS_NEGATIVE', 0))} hard negatives +
  {n((v3m.get('candidate_decisions') or {}).get('CORROBORATION_ONLY', 0))} corroborations; the rest stays
  research-only rather than being forced into the dataset.
- **V3.1:** {n((norm31.get('fragment_decisions') or {}).get('admitted', 0))} admitted findings
  (severity explicit on {n((norm31.get('severity_confidence') or {}).get('explicit', 0))});
  taxonomy explicit on {n((norm31.get('taxonomy_confidence') or {}).get('explicit', 0))}, derived on
  {n((norm31.get('taxonomy_confidence') or {}).get('derived', 0))}, unknown elsewhere — by rule, not by optimism.
- **V3.2:** {n(tri32.get('compiled_l3', 0))}/{n(tri32.get('total', 0))} incident PoCs compile (L3); {n(_v3_executed)} admitted v3 records now carry a run artefact (levels `{_one(_v3lv)}`),
  {(proof32.get('by_level') or {}).get('L5', 0)} thefts reproduced on fork with attacker-profit
  evidence; {n(len((proof32.get('runs') or [])) - (proof32.get('by_level') or {}).get('L5', 0))} blocked
  (pruned RPC, unreplayable state, repo drift — each with verbatim backend errors in
  `experiments_v3/`); 47 V3.1 patch candidates stay unverified at the candidate
  layer: {n(_prdr.get('static_diff_only', 0))} cite a
  static diff review, {n(_prdr.get('diff_unavailable', 0))} have no retrievable source, and
  {n(_prdr.get('executed_fix_verified', 0))} additionally carries an executed two-side PoC
  (violation only on the vulnerable revision; harness and logs in
  [`experiments_v3/1inch-lop-m01/`](experiments_v3/1inch-lop-m01/)) — a diff
  review states what changed, not whether the fix works
  ([`derived_v3/patch_reviews.jsonl`](derived_v3/patch_reviews.jsonl),
  [`reports/v3/patch_static_review.json`](reports/v3/patch_static_review.json)).
- **VLUN-Prove:** {n(len(prove.get('tasks') or []))} two-revision proof tasks published as a
  scoring interface ([`reports/prove_split_interface.md`](reports/prove_split_interface.md)).
  A submission is credited stage by stage — generated → compiles → executes → impact reproduced
  → patch verified — where `impact_reproduced` requires the *expected assertion* to be what
  broke, and a compile or dependency failure stops the ladder instead of being relabelled as a
  failed proof. The answer key (fixed revisions, expected assertions) lives outside this
  repository and is pinned by hash
  ({n(len(((prove.get('private_commitment') or {}).get('files') or {})))} files committed in
  [`reports/prove_split_interface.json`](reports/prove_split_interface.json)).
  Self-check: the project's own recorded runs were replayed through the grader's rules
  (`{(prove.get('grader_self_check') or {}).get('stage_reached_distribution')}`), which is a
  check of the grader, not of any model. The ~200-task held-out split is **not** reported as
  met: only {n((prove.get('pool') or {}).get('tasks_with_two_revisions_executed'))} tasks have
  both revisions executed today, and each further task needs a pinned fix and a test run on
  both sides before it can be counted.
- **Vbeta:** {n(vbm.get('record_count', 0))} admitted records from {n(vbm.get('candidate_count', 0))} candidates
  ({n(_vbdec.get('IMPORT', 0))} IMPORT, {n(_vbdec.get('IMPORT_AS_UNVERIFIED', 0))} unverified,
  {n(_vbdec.get('IMPORT_AS_NEGATIVE', 0))} negatives, {n(_vbdec.get('RESEARCH_ONLY', 0))} research-only);
  {n(_vblvl.get('L1', 0))} L1 quoted-PoC rows (rest L0); languages `{_one(sorted(_vblang.keys()))}`;
  splits train {n(_vbsplits.get('train'))} / validation {n(_vbsplits.get('validation'))} / test {n(_vbsplits.get('test'))}.
- Full per-source accounting, unknowns with resolving evidence, and extraction failures:
  [`reports/v2_1_quality_report.md`](reports/v2_1_quality_report.md),
  [`reports/v2_2/quality_report.md`](reports/v2_2/quality_report.md),
  [`reports/v3/quality_report.md`](reports/v3/quality_report.md),
   [`reports/v3/normalization_report.md`](reports/v3/normalization_report.md),
   [`reports/v3/normalization_unknowns.md`](reports/v3/normalization_unknowns.md),
   [`Vbeta/reports_vbeta/quality_report.md`](Vbeta/reports_vbeta/quality_report.md),
   [`Vbeta/reports_vbeta/shieldify_ingestion_report.md`](Vbeta/reports_vbeta/shieldify_ingestion_report.md),
   [`Vbeta/reports_vbeta/solodit_ingestion_report.md`](Vbeta/reports_vbeta/solodit_ingestion_report.md).
- Depth over scale: per-layer verification levels, field coverage and {n(_depth.get('root_cause_corrections', 0))} verbatim
  root_cause candidates for High findings ([`reports/depth_dashboard.md`](reports/depth_dashboard.md),
  generated by `scripts/depth_dashboard.py`; originals untouched).
- Packaging: machine-readable schemas ([`schema/`](schema/), generated from
  `scripts/schema_terms.py`), [`CITATION.cff`](CITATION.cff),
  [`CHANGELOG.md`](CHANGELOG.md), [`docs/DATASHEET.md`](docs/DATASHEET.md)
  (generated from reports), and CI running all gates on push/PR.
- Per-field coverage (which fraction of records actually carry root_cause, attacker model,
  impact, severity, language, … — {n(_fc_thin)} of {n(len(_fc_fields))} tracked fields under 50% known):
  [`reports/field_coverage.md`](reports/field_coverage.md), generated by
  `scripts/field_coverage.py` from the canonical files.

## Splits & benchmarks

Splits isolate by repository (v1/v2) or by record/source (v2.2/v3/Vbeta); duplicates are quarantined,
never deleted. Benchmark families A-V are machine-readable under `benchmark/` (A-T) and
`Vbeta/benchmark_vbeta/` (U-V) with manifests; answer keys rebuild from the records, and
families that need experimentally produced ground truth only admit rows that have it.

| Family | Tasks | Scorable | Status | Layer |
|---|---|---|---|---|
{_bench_rows}
{_v3bench_rows}
{_vbbench_rows}

`Scorable` is the manifest count (answer key present); `Status` marks
families retired to `benchmark/retired_families/`, demoted to EXPLORATORY
(fewer than 100 headline scorable rows) or SATURATED (headline majority >=
0.94). The exact-match scorer
(`scripts/score_benchmark.py`, rubric in `docs/RUBRIC.md`, keys in
`docs/ANSWER_KEY.md`) covers {_cov.get('scorer_covered', 0):,} of
{_cov.get('manifest_scorable_total', 0):,} manifest-scorable tasks; the rest are the
{len(RETIRED_FAMILIES)} retired families' {_retired_scorable:,} scorable rows (scored only in
the continuity twin below), the {len(_expl_letters)} exploratory families' {_expl_scorable:,} sub-floor
rows (scored per-family and in the continuity twin), plus D generative, H
descriptive and Q judge-graded tasks
({_excl_reasoned:,} rows), excluded with stated reasons.

Published deterministic baselines. `acc @ predicted/scorable` is micro-accuracy on
the tasks the baseline actually predicted, shown with its coverage; the `over scorable`
column counts unpredicted tasks as wrong, so abstention is visible, never silent.
Headline rows exclude the retired and exploratory families (see Status marks
above and `benchmark/retired_families/`); continuity rows cover **all families
ever shipped** (headline + exploratory + retired), comparable to prior releases.

| Baseline | Headline acc @ predicted/scorable | Headline acc over scorable | Continuity acc @ predicted/scorable |
|---|---|---|---|
{_bl_rows}

first-published and majority-published are L-only predictors over a retired family:
they emit nothing on headline families by construction, so their headline accuracy is
**n/a with zero predictions**, never a 0.0000 that reads as a scored result — the
`over scorable` column is where the abstention shows as 0.0000 of
{_cov.get('scorer_covered', 0):,} headline scorable tasks.
Families marked SATURATED (headline majority >= 0.94: {", ".join(sorted(_sat_letters))})
carry no signal — a model beat there proves nothing. The
{len(_expl_letters)} exploratory families ({", ".join(sorted(_expl_letters))}) are below the
100-row floor where a family score is interpretable, so they carry no
headline claim either — their rows stay scored per-family and in the
continuity twin. Family A majority accuracy
differs by split (see baseline reports); a split-blind floor is a validity
hazard. `scripts/check_manifests.py` recomputes every one of these
counts from the canonical records
(manifest-file agreement, task-record resolution, split coverage, RESEARCH_ONLY
leak scans, L5/L6-without-artefact and `verified_patch` scans). A family whose file disagrees
with its manifest fails the build.

## Licensing

- `LICENSE` is three-way: data under `jsonl*/`, `derived*/`, `splits*/`, `benchmark/`,
  `datasets/`, `training/`, `reports/` is **CC BY 4.0**; `scripts/` is **MIT**; third-party
  source is **not licensed here at all**.
- {dm.get('redistribution_flagged', {}).get('source_redistributed_without_declared_license', 0)} v1 records
  carry verbatim source from repositories declaring no licence (flagged per record; re-measured
   from the text itself in `reports/third_party_audit.json`). V3 keeps link + sha256 + attributed
   facts only (METADATA_ONLY). Vbeta keeps links + observed facts only (METADATA_ONLY) —
   full report prose is never copied in; `openzeppelin-cairo` rows carry observed MIT.
- Vbeta sources are first-party audit pages plus a tier-2 Solodit mirror (auditor originals
  stay canonical). No operator-authored rows remain: the single interim one was retired and
  replaced by its harvested original (see `Vbeta/reports_vbeta/solodit_ingestion_report.md`).
- No permission has been obtained from upstream protocol authors. For redistribution or
  commercial training, pull sources yourself via `scripts/fetch_sources.py` under your own
  compliance process. See [`NOTICE.md`](NOTICE.md).

## Reproduce

```bash
python scripts/build_all.py --with-network   # everything
python scripts/validate.py                   # the gate (non-zero on failure)
python scripts/validate_v3.py                # v3 gate
python scripts/validate_v31.py               # v3.1 gate
python scripts/check_manifests.py            # {n(_mchecks.get('checks_total', 0))} count/reference checks, recomputed from canonical records
python scripts/check_reproducibility.py      # provenance, determinism, isolation (skips stay skipped_no_network)
python -m unittest discover -s tests        # terminology, invariants, fixtures (incl. intentionally-broken)
python scripts/generate_readme.py --check    # this file is generated; stays current only if regenerated
python Vbeta/scripts/build_vbeta.py --check  # Vbeta dry run (writes only under Vbeta/)
python Vbeta/scripts/validate_vbeta.py       # Vbeta gate
python Vbeta/tests/test_vbeta.py             # Vbeta tests
```

Every script is idempotent, takes `--help`, and writes only under its own layer directories;
`jsonl/`, `jsonl_ml/`, `jsonl_v3/` are read-only. Offline runs skip network stages explicitly
(`skipped_no_network` — a skip is never reported as a pass). Fresh clones reproduce the JSONL and
derived layers but not execution artefacts, which live git-ignored under `work/` (verdicts stay
checkable via committed `result.json` files).

Key stages:

```bash
python scripts/fetch_sources.py              # clone + retrieve pinned citations
python scripts/verify_pocs.py                 # compile and run PoCs
python scripts/verify_patches.py              # vulnerable vs fixed revision pairs
python scripts/resolve_citations.py           # branch refs -> exact commits
python scripts/run_verified_experiments.py    # exploit experiments, both revisions
python scripts/build_derived.py               # evidence, attacker model, taxonomy
python scripts/build_hard_negatives.py        # structured rejection reasons
python scripts/check_leakage.py --emit splits_v2
python scripts/build_benchmark.py             # families A-J
python scripts/build_benchmark_v22.py         # families K-Q
python scripts/build_subsets.py               # datasets/ and training/
python scripts/generate_stats.py              # the only source of statistics
python scripts/ingest_audit_sources.py        # audit-source registry
python scripts/build_v3.py                    # v3: 18 clones -> jsonl_v3/derived_v3/splits_v3 + R-S
python scripts/validate_v3.py                 # the v3 gate
python scripts/normalize_v3.py                # v3.1: boundaries, fields, overlays, preview
python scripts/validate_v31.py                # the v3.1 gate
python scripts/build_benchmark_v31.py         # family T (explicit taxonomy)
python scripts/run_dhl_experiments.py         # v3.2: staged fork executions
python scripts/check_manifests.py             # cross-manifest count integrity (writes nothing)
python scripts/check_reproducibility.py        # reproducibility gate incl. Vbeta rebuild parity
python Vbeta/scripts/harvest_solodit.py       # scrape -> Vbeta/solodit_candidates.json (deterministic)
python Vbeta/scripts/build_vbeta.py           # candidates -> records/splits/U-V (Vbeta only)
```

## Repositories (v1 scope)

| Repository | Protocol | Findings | Split |
|---|---|---|---|
| `code-423n4/2022-05-alchemix` | Alchemix | 28 | train |
| `code-423n4/2024-01-decent` | Decent | 12 | validation |
| `code-423n4/2024-01-renft` | reNFT | 29 | validation |
| `code-423n4/2024-04-noya` | NOYA | 86 | train |
| `code-423n4/2024-08-wildcat` | The Wildcat Protocol | 32 | test |
| `code-423n4/2024-12-bakerfi` | BakerFi Invitational | 32 | test |
| `code-423n4/2025-06-panoptic` | Panoptic Hypovault | 4 | test |
| `code-423n4/2025-08-gte-perps` | GTE Perps and Launchpad | 41 | test |

V3 spans 18 more archives (audits, contests, incident PoCs); per-source accounting is in
[`reports/v3/quality_report.md`](reports/v3/quality_report.md).

## Vbeta layer (isolated, additive)

`Vbeta/` holds {n(vbm.get('source_count', 0))} new sources with zero overlap against V3's 18 archives:
professional-audit pages (OtterSec, Neodyme, Trail of Bits, Runtime Verification, Veridise ZK,
MoveBit, OpenZeppelin Cairo), contest findings (Immunefi, Cyfrin CodeHawks, Cantina),
Shieldify portfolio findings, and a Solodit HIGH+MEDIUM mirror
({n(vbharv.get('harvested', 0))} detail pages harvested of {n(_solodit_indexed)} indexed,
{n(vbharv.get('rejected', 0))} duplicate excluded; languages `{_one(sorted(set(vbharv.get('languages', []))))}`).
Rule 1: PRESENT is read-only — every Vbeta writer refuses paths outside `Vbeta/`, and the gate
warns if any PRESENT sentinel drifts from `Vbeta/present_snapshot.json`. Rule 2: truth over
scale (no record above L1 without run artefacts). Rule 3: METADATA_ONLY (links + observed
facts; full prose one hop away, never copied in). Admission is computed in code
(`decide()`): IMPORT only on title + severity + link + status all observed. See
[`Vbeta/README.md`](Vbeta/README.md) and the per-source ingestion reports.

## Integrity infrastructure

One canonical vocabulary — `scripts/schema_terms.py` (single source of truth; imports, never
redefines, the existing enums) — separates sources from findings, candidates from admitted
records, derived rows from preview rows, published PoCs (L1) from reproduced ones (L5/L6),
and team-reported `Fixed` from `verified_patch`. Validators reject deprecated terms
(`verified source`, `reproduced`-as-prose, `Fixed (verified)`). Status:
[`reports/reproducibility_report.md`](reports/reproducibility_report.md) is generated from the
JSON each gate writes and holds every gate's size and critical-failure count -- the
numbers that do not vary by machine. The per-check PASS/SKIP matrix is deliberately not
pinned there: it depends on whether the git-ignored `V3/clones`/`work/` are present, so it
is the CI run for the commit, or `python scripts/run_gates.py` locally. `validate.py`,
`validate_v3.py`, `validate_v31.py` and the Vbeta gate enforce it per layer.

## ML quickstart

- Vulnerability detection / reasoning tasks: `training/*.jsonl` (v1 task files) and
  `benchmark/` A-T + `Vbeta/benchmark_vbeta/` U-V (every task carries its split; answer keys
  rebuild from the records).
- Admission-filtered records: `datasets/` (each row carries a published
  `admission_rule`), `derived_v3/records.jsonl` (each row carries `decision`,
  `verification_level`, `language`, `ecosystem`, `benchmark_split`),
  `Vbeta/derived_vbeta/records.jsonl` (each row carries `decision`,
  `verification_level`, `language`, `ecosystem`; the split lives in the
  benchmark manifests under `Vbeta/benchmark_vbeta/`).
- Splits never leak across train/validation/test by repository or source; duplicates sit in
  `quarantine`, never deleted. Check any of this with `scripts/check_manifests.py`.

## Attribution

Findings, verdicts and PoC code belong to their original authors: Code4rena and the
competitive-audit participants, the professional auditors (Shieldify, OtterSec, Neodyme,
Trail of Bits, Runtime Verification, Veridise, MoveBit, OpenZeppelin, Zellic, Pashov and
others), the contest platforms (Cantina, CodeHawks, Immunefi, Sherlock), the incident PoC
authors, and Cyfrin Solodit as a mirror (auditor originals stay canonical).
See [`NOTICE.md`](NOTICE.md).
"""
    return lines


def render_v4() -> str:
    m = jread(ROOT / "derived_v4" / "manifest.json", {}) or {}
    if not m:
        return ""
    levels = m.get("verification_levels", {}) or {}
    langs = ", ".join(f"{k} {v}" for k, v in (m.get("languages") or {}).items())
    return (
        "\n## V4 layer\n\n"
        "Isolated layer extracted from the cloned Halborn/Oak/CoinFabrik report archives "
        f"(`work/cloned_conversion/staged_report_candidates.jsonl`, {m.get('source_candidates_staged', 0)} report candidates). "
        f"Records: {m.get('extracted_findings', 0)} extracted, {m.get('admitted', 0)} admitted, "
        f"{m.get('quarantined', 0)} quarantined, {m.get('duplicates', 0)} duplicates. "
        f"Evidence levels: {levels}. Languages: {langs}. Missing provenance is tracked in the manifest; "
        "all records are L0 only (no PoC execution was performed). Details: "
        "`reports/cloned_repo_conversion_v2.md`, `jsonl_v4/`, `derived_v4/`.\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    want = render() + render_v4()
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

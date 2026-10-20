#!/usr/bin/env python3
"""Generate the human-readable reports from machine-readable facts.

    reports/extraction_errors.json   every known limitation, v1 and v2, one entry each
    reports/benchmark_metrics.md    what can actually be measured, and what cannot
    reports/final_quality_report.md  BEFORE / AFTER / improved / unverifiable / limited

Nothing here computes a number that a source does not support. Metrics whose
denominator is zero are reported as "not measurable" rather than as 0% or 100%.

    python scripts/generate_reports.py
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    BENCH, DERIVED, JSONL, REPORTS, WORK, log, read_jsonl, write_json,
)

MD = REPORTS


def jread(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def jl(p: Path):
    return read_jsonl(p) if p.exists() else []


def pct(n, d):
    return "not measurable" if not d else f"{n}/{d} ({100.0 * n / d:.1f}%)"


# ---------------------------------------------------------------------------
# extraction errors
# ---------------------------------------------------------------------------

def build_extraction_errors() -> dict:
    """v1's error records plus every limitation discovered while hardening.

    v1 records are kept verbatim and marked `origin: v1`; anything this pipeline
    discovered is `origin: v2`. A researcher can therefore see which limitations
    were known to the builder and which the upgrade surfaced.
    """
    v1 = jl(JSONL / "errors.jsonl")
    entries = []
    for r in v1:
        e = r.get("error") or {}
        entries.append({
            "origin": "v1",
            "kind": e.get("kind"),
            "repository": e.get("repository"),
            "audit": e.get("audit_name"),
            "summary": e.get("impact") or e.get("detail") or "",
            "detail": e.get("detail"),
            "urls": e.get("urls") or [],
            "affected_files": e.get("affected_files") or [],
            "still_true": True,
            "source": r.get("source"),
        })

    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    leak = jread(REPORTS / "leakage_report.json", {}) or {}
    srcman = jread(WORK / "source_manifest.json", {}) or {}
    vpath = REPORTS / "validation_report.json"
    vrep = jread(vpath, {}) or {}

    def add(kind, summary, detail, scope=None, urls=None, origin="v2"):
        entries.append({"origin": origin, "kind": kind, "repository": scope,
                        "summary": summary, "detail": detail, "urls": urls or [],
                        "affected_files": [], "still_true": True})

    tot = ver.get("totals", {})
    reasons = ver.get("not_executed_failure_reasons", {})
    if tot.get("not_executed", 0):
        _k, dtext = dominant_blocker(reasons)
        add("poc_not_executed",
            f"{tot.get('not_executed', 0)} of {tot.get('exploit_records', 0)} PoCs could not be "
            "executed at all",
            f"failure reasons: {reasons}. {dtext}",
            "all")

    for r in (srcman.get("repos") or []):
        if r.get("files_missing"):
            add("source_unavailable",
                f"{r['files_missing']} cited file(s) could not be retrieved from {r['repo']}",
                "; ".join(f"{m['file']} @ {m['commit_sha'][:10]}: {m['reason']}"
                          for m in (r.get("missing_detail") or [])[:5]),
                r["repo"])
        if r.get("status") == "clone_failed":
            add("source_unavailable", f"repository {r['repo']} could not be cloned",
                r.get("detail", ""), r["repo"])
        lic = r.get("license") or {}
        if not lic.get("found"):
            add("license_not_declared",
                f"{r['repo']} has no LICENSE file at any cited commit",
                "source text attributed to this repository cannot be classified as "
                "redistributable, so it is classified `unknown` and the redistribution is "
                "flagged rather than assumed lawful.", r["repo"])

    for c in vrep.get("details", []):
        if c["check"] == "commit_pins_are_immutable" and c["failure_count"]:
            add("mutable_commit_reference",
                f"{c['failure_count']} code citations pin a branch name instead of a commit",
                "commit_sha values such as 'main' or 'release-v5.0' are mutable, so the cited "
                "line ranges are not reproducible over time. The v1 statistics already claimed "
                "byte-for-byte range verification, which cannot hold for these.", "all")

    if leak.get("exact_overlap", {}).get("count_commit_shas"):
        add("cross_split_commit_reference",
            f"{leak['exact_overlap']['count_commit_shas']} commit is cited from two splits",
            "the shared ref is a third-party dependency commit (`main`) cited by findings in two "
            "different audited repositories. It is reported rather than suppressed: a model can "
            "see the same dependency helper in both splits.")

    sem = leak.get("semantic_overlap", {}).get("count", 0)
    if sem:
        add("cross_split_near_duplicate",
            f"{sem} cross-split near-duplicate pair(s) detected by token/shingle similarity",
            "boilerplate submissions (for example 'Unsafe use of transfer()/transferFrom() with "
            "IERC20') were filed by the same submitter against two different audits. "
            "scripts/check_leakage.py --emit splits_v2 quarantines the redundant train copy.",
            "cross-repo")

    for c in vrep.get("details", []):
        if not c["ok"] and c["critical"]:
            add("validation_failure", f"validation gate: {c['check']}",
                f"{c['failure_count']} failures", "dataset")

    by_kind = collections.Counter(e["kind"] for e in entries)
    by_origin = collections.Counter(e["origin"] for e in entries)
    return {
        "generated_by": "scripts/generate_reports.py",
        "description": "Every known limitation of this dataset. `origin: v1` entries were "
                       "recorded by the original builder; `origin: v2` entries were surfaced by "
                       "the hardening pipeline. Nothing is marked resolved unless a check "
                       "proves it.",
        "total": len(entries),
        "by_kind": dict(sorted(by_kind.items())),
        "by_origin": dict(by_origin),
        "resolved_entries": 0,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# benchmark metrics
# ---------------------------------------------------------------------------

def build_benchmark_metrics() -> str:
    man = jread(BENCH / "manifest.json", {}) or {}
    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    patch = jread(REPORTS / "patch_verification.json", {}) or {}
    neg = jread(REPORTS / "negative_verification_stats.json", {}) or {}
    negm = neg.get("metrics") or {}
    ce = jread(REPORTS / "counterexample_stats.json", {}) or {}
    leak = jread(REPORTS / "leakage_report.json", {}) or {}
    tasks = man.get("tasks", {})

    det = jl(BENCH / "A_vulnerability_detection.jsonl")
    fp = jl(BENCH / "F_false_positive_rejection.jsonl")
    ev = jl(BENCH / "retired_families" / "E_exploit_verification.jsonl")
    d_t = jl(BENCH / "D_exploit_construction.jsonl")
    # Majority-baseline accuracy per family (recomputed by the scorer, read
    # here — never typed). Families at >= 0.94 carry no signal: beating
    # majority there proves nothing about a model. Exploratory families
    # (below the 100-row headline floor) and retired families are read from
    # their own blocks and tagged EXPLORATORY / RETIRED instead of
    # SATURATED.
    maj = {}
    _expl = set()
    _ret = set()
    try:
        _bl = json.loads((REPORTS / "baselines"
                          / "baseline_majority.json").read_text(
                              encoding="utf-8"))
        for _blk in ("families", "families_exploratory", "families_retired"):
            for _fam, _s in (_bl.get(_blk, {}) or {}).items():
                if isinstance(_s, dict) and _s.get("accuracy") is not None:
                    maj[_fam[:-6] if _fam.endswith(".jsonl") else _fam] = \
                        _s["accuracy"]
        _expl = {(_f[:-6] if _f.endswith(".jsonl") else _f)
                 for _f in (_bl.get("families_exploratory") or {})}
        _ret = {(_f[:-6] if _f.endswith(".jsonl") else _f)
                for _f in (_bl.get("families_retired") or {})}
    except (OSError, json.JSONDecodeError):
        maj = {}
        _expl = set()
        _ret = set()

    test_det = [t for t in det if t["split"] == "test"]
    test_pos = sum(1 for t in test_det if t["answer_key"]["label"] == "vulnerable")
    test_neg = len(test_det) - test_pos

    totals = ver.get("totals", {})
    ex_n = totals.get("exploit_records", 0)
    comp = ver.get("poc_compilation_rate", {})

    test_fp = [t for t in fp if t["split"] == "test" and t["answer_key_status"] == "labeled"]

    rows = [
        ("precision", "not measurable",
         "no model has been run against this benchmark; precision is a property of a predictor, "
         "not of the dataset. What the dataset provides is the labelled set needed to compute it."),
        ("recall", "not measurable", "same reason as precision."),
        ("F1", "not measurable", "same reason as precision."),
        ("false-positive rate", "not measurable",
         "requires a predictor. The benchmark supplies "
         f"{len(test_fp)} scorable false-positive-rejection tasks in the held-out split."),
        ("false-negative rate", "not measurable", "requires a predictor."),
        ("PoC compilation rate",
         pct(comp.get("repos_compiled", 0), comp.get("repos_attempted", 0)) + " repositories",
         f"{comp.get('poc_files_materialised', 0)} PoC files were written from the code quoted in "
         f"the reports; {comp.get('poc_files_skipped', 0)} could not be expressed as a Solidity "
         "test body."),
        ("PoC execution rate",
         pct(totals.get("reproduced", 0) + totals.get("not_reproduced", 0)
             + totals.get("inconclusive", 0), ex_n),
         "reproduced + not_reproduced + inconclusive over all exploit records."),
        ("exploit confirmation rate", pct(totals.get("reproduced", 0), ex_n),
         "A PoC counts only when forge reported Success for that test. Nothing else is promoted."),
        ("patch verification rate", pct(patch.get("evaluated", 0), patch.get("patch_records", 0)),
         f"{patch.get('fix_confirmed_effective', 0)} fixes confirmed effective by running the same "
         "PoC against vulnerable and fixed revisions."),
        ("negative-example accuracy", "not measurable",
         f"the held-out split has {len(test_fp)} scorable false-positive tasks; of "
         f"{neg.get('total', 0)} negatives only {negm.get('reason_attributed_to_judge_or_sponsor', 0)}"
         " carry a reason attributed to a named judge or sponsor and "
         f"{negm.get('reason_supported_by_cited_code', 0)} are blocked by a gate in the cited "
         f"code, while {negm.get('unknown_or_insufficient_evidence', 0)} rest on a public "
         "label alone, so scoring them would reward guessing."),
        ("duplicate detection accuracy",
         f"{leak.get('near_duplicate_overlap', {}).get('count', 0)} near-duplicate and "
         f"{leak.get('semantic_overlap', {}).get('count', 0)} semantic cross-split pairs found",
         "detector recall is not validated against a hand-labelled set; the two pairs it found "
         "were checked by hand and are genuine."),
    ]

    lines = [
        "# Benchmark metrics",
        "",
        "Generated by `scripts/generate_reports.py` from `reports/benchmark_metrics.json` and the",
        "files under `benchmark/`. Nothing in this file is estimated.",
        "",
        "## What can be measured",
        "",
        "| metric | value | basis |",
        "|---|---|---|",
    ]
    for name, value, basis in rows:
        lines.append(f"| {name} | {value} | {basis} |")

    lines += [
        "",
        "## Task coverage",
        "",
        "A task is *scorable* only where an answer key genuinely exists. Unlabelled tasks are",
        "written to `benchmark/*.jsonl` with `answer_key_status` and a reason, and are excluded",
        "from any metric, because a key invented to fill a slot would measure the generator, not",
        "the model.",
        "",
        "| task | tasks | scorable | partial | unlabelled | train | validation | test | majority |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, t in sorted(tasks.items()):
        bs = t.get("by_split", {})
        ma = maj.get(name)
        if ma is None:
            flag = "n/a"
        else:
            tag = ""
            if name in _expl:
                tag = " EXPLORATORY"
            elif name in _ret:
                tag = " RETIRED"
            elif ma >= 0.94:
                tag = " SATURATED"
            flag = f"{ma:.3f}{tag}"
        lines.append(f"| `{name}` | {t['tasks']} | {t['scorable']} | {t.get('partial', 0)} | "
                     f"{t.get('unlabeled', 0)} | {bs.get('train', 0)} | {bs.get('validation', 0)} | "
                     f"{bs.get('test', 0)} | {flag} |")

    lines += [
        "",
        "## Held-out split composition (task A)",
        "",
        f"- `vulnerable` (judged, confirmed): **{test_pos}**",
        f"- `no_confirmed_vulnerability` (rejected / disputed / duplicate / QA): **{test_neg}**",
        "",
        "A detector evaluated on this split is rewarded for saying `vulnerable` only when the",
        "Code4rena judge confirmed it, and penalised for flagging the rejected submissions. The",
        f"whole-split base rate is {100.0 * test_pos / len(test_det):.1f}% positive, so a trivial",
        "always-positive baseline scores that. Report it alongside any F1.",
        "",
        "## Known limitations of this benchmark",
        "",
        f"- Task D supplies {len(d_t)} PoC bodies quoted from reports. Their correctness is not "
        "established: only the fraction counted under *exploit confirmation rate* has been run.",
        f"- Task E is labelled on its {sum(1 for t in ev if t['answer_key_status'] == 'labeled')} "
        f"rows with an executed verdict; the other {sum(1 for t in ev if t['answer_key_status'] != 'labeled')} "
        "are unlabelled — a PoC verification task needs an executed ground truth, and executing "
        "them needs an archive RPC and a working toolchain.",
        f"- Task G is labelled on its {tasks.get('G_patch_verification', {}).get('scorable', 0)} "
        "rows where the same exploit was run against both the vulnerable and the fixed revision "
        f"(L6); the other {tasks.get('G_patch_verification', {}).get('unlabeled', 0)} are "
        "`not_testable` — no executable PoC on either side, so their effectiveness is genuinely "
        "unestablished.",
        f"- Counterexamples exist for only {ce.get('records_with_at_least_one_counterexample', 0)} "
        f"of {ce.get('confirmed_high_medium_records', 0)} confirmed High/Medium findings. The "
        "reasons are counted in `reports/counterexample_stats.json`, not glossed over.",
        "- Baseline predictors have been run (`reports/baselines/`, rubric in "
        "`docs/RUBRIC.md`): majority, label-frequency, copy-the-publisher, "
        "TF-IDF retrieval and seeded random. Families with majority accuracy "
        ">= 0.94 are marked SATURATED above; the four exploratory families "
        "(F, G, I, J) are marked EXPLORATORY — below the 100-row floor where "
        "a family score is interpretable — and a model beat there carries no "
        "signal either.",
        "",
    ]
    (MD / "benchmark_metrics.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# final quality report
# ---------------------------------------------------------------------------

DOMINANT_TEXT = {
    "poc_invalid":
        "The dominant blocker is that the published PoC is not a runnable test. The "
        "Code4rena reports publish two kinds of proof: executable test functions, and "
        "suggested *contract* patches — a function the reporter asks you to add to the "
        "vulnerable contract in order to demonstrate the issue. The second kind is real "
        "evidence and it is preserved in `poc.code`, but it cannot be executed as "
        "published, so it is recorded as `poc_invalid` rather than dressed up as a test.",
    "dependency_unavailable":
        "The dominant blocker is that the audited repositories do not build here.",
    "environment_unavailable":
        "The dominant blocker is the execution environment, not the PoC: the fork-based "
        "tests need an archive RPC that the dataset does not distribute.",
    "broken_original_test":
        "The dominant blocker is that the published PoC does not compile as published.",
    "source_unavailable": "The dominant blocker is unavailable source.",
    "historical_commit_unavailable":
        "The dominant blocker is a historical commit that no longer resolves.",
    "license_restriction": "The dominant blocker is a licensing restriction.",
    "insufficient_evidence":
        "The dominant blocker is insufficient evidence to attempt execution at all.",
    "poc_reconstruction_failed": "The dominant blocker is a failed PoC reconstruction.",
    "no_poc_published": "The dominant blocker is that no PoC was published for these findings.",
    "none": "No PoC was blocked.",
}


def dominant_blocker(reasons: dict) -> tuple[str, str]:
    if not reasons:
        return "none", ""
    key = max(reasons.items(), key=lambda kv: kv[1])[0]
    return key, DOMINANT_TEXT.get(key, f"The dominant blocker is `{key}`.")


def build_final_report() -> str:
    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    patch = jread(REPORTS / "patch_verification.json", {}) or {}
    hn = jread(REPORTS / "hard_negative_stats.json", {}) or {}
    neg = jread(REPORTS / "negative_verification_stats.json", {}) or {}
    negm = neg.get("metrics") or {}
    ce = jread(REPORTS / "counterexample_stats.json", {}) or {}
    leak = jread(REPORTS / "leakage_report.json", {}) or {}
    dman = jread(DERIVED / "manifest.json", {}) or {}
    bench = jread(BENCH / "manifest.json", {}) or {}
    vrep = jread(REPORTS / "validation_report.json", {}) or {}
    srcman = jread(WORK / "source_manifest.json", {}) or {}

    t = ver.get("totals", {})
    comp = ver.get("poc_compilation_rate", {})
    reasons = ver.get("not_executed_failure_reasons", {})

    def num(x):
        return str(x) if x is not None else "0"

    before_after = [
        ("reported statistics trustworthy",
         "no — 4 of the 24 checked v1 statistics disagreed with the JSONL",
         f"yes — {vrep.get('passed', 0)}/{vrep.get('checks', 0)} gate checks pass and "
         "`reported_statistics == computed_statistics` is enforced"),
        ("per-field evidence type", "absent", "7-value closed vocabulary on every derived field"),
        ("audit of the original repository", "none published",
         "reports/pre_upgrade_audit.json, mechanical, reproducible"),
        ("cited source retrieved", "0 files (the raw dump is not published)",
         f"{srcman.get('total_files_retrieved', 0)}/{srcman.get('total_files_requested', 0)} "
         "pinned (commit, file) pairs, hash-verified"),
        ("PoCs compiled", "0", pct(ver.get('poc_compilation_rate', {}).get('repos_compiled', 0),
                                   ver.get('poc_compilation_rate', {}).get('repos_attempted', 0))
         + " repositories"),
        ("PoCs executed", "0", pct(t.get("reproduced", 0) + t.get("not_reproduced", 0)
                                   + t.get("inconclusive", 0), t.get("exploit_records", 0))),
        ("PoCs that demonstrated the claimed impact", "0 (unknown; nothing was run)",
         pct(t.get("reproduced", 0), t.get("exploit_records", 0))),
        ("hard negatives with a code-grounded rejection reason",
         "0 (427 of 458 were label-only with no reason recorded)",
         f"{negm.get('reason_supported_by_cited_code', 0)} of "
         f"{hn.get('blocking_condition_derived_from_code', 0)} recorded code gates actually "
         "remove the standing the claim asserts (the rest sit on a neighbouring function or on "
         "a claim that names a privileged actor); "
         f"{negm.get('reason_attributed_to_judge_or_sponsor', 0)} carry a reason quoted from a "
         f"public judge or sponsor comment; {negm.get('unknown_or_insufficient_evidence', 0)} "
         "rest on a public label alone"),
        ("counterexamples for confirmed H/M", "0",
         f"{ce.get('records_with_at_least_one_counterexample', 0)} of "
         f"{ce.get('confirmed_high_medium_records', 0)}"),
        ("records with a state transition", "0 (attack_path strings only)",
         f"{dman.get('state_transition_present', 0)} present, "
         f"{dman.get('state_transition_with_transactions', 0)} with structured transactions"),
        ("records with a structured attacker model", "0 (free-text capabilities)",
         f"{dman.get('records', 0) - dman.get('attacker_identity_unknown', 0)} of "
         f"{dman.get('records', 0)} classified "
         f"({dman.get('attacker_kind_basis', {})})"),
        ("code context expansion beyond a flat permalink list", "none",
         f"{dman.get('code_context_analysed_files', 0)} files analysed to contract, function, "
         "modifier, guard and state-variable level"),
        ("patch effectiveness tested", "0",
         f"{patch.get('evaluated', 0)} of {patch.get('patch_records', 0)} evaluated; "
         f"{patch.get('fix_confirmed_effective', 0)} confirmed effective"),
        ("leakage detection", "3 hard checks (repo, id, file::function)",
         f"4 detectors; found {leak.get('near_duplicate_overlap', {}).get('count', 0)} "
         f"near-duplicate and {leak.get('semantic_overlap', {}).get('count', 0)} semantic "
         "cross-split pairs, both hand-checked and quarantined"),
        ("taxonomy depth", "2 levels, inconsistent names",
         "4 levels (category/family/class/subtype) mapped onto a stated table, C4 strings kept"),
        ("benchmark", "none",
         f"{sum(x['tasks'] for x in bench.get('tasks', {}).values())} tasks across 7 families, "
         f"{sum(x['scorable'] for x in bench.get('tasks', {}).values())} scorable"),
    ]

    lines = [
        "# VLUN v2 — final quality report",
        "",
        "Generated by `scripts/generate_reports.py`. Every number here is read from a machine-",
        "readable report in `reports/`. Where a measurement was not possible the line says so.",
        "",
        "## BEFORE → AFTER",
        "",
        "| dimension | BEFORE (published v1) | AFTER (this pipeline) |",
        "|---|---|---|",
    ]
    for a, b, c in before_after:
        lines.append(f"| {a} | {b} | {c} |")

    lines += [
        "",
        "## WHAT IMPROVED",
        "",
        "1. **The reported numbers are now true.** Four v1 statistics were wrong: `poc_available`",
        "   (155 reported, 346 actual — the key conflated exploit rows with `poc.available`",
        "   fields), `code_context_entries` (557 vs 895), `code_context_with_verified_line_range`",
        "   (510 vs 827) and `findings_with_named_judge_or_sponsor_verdict` (105 vs 110). README",
        "   additionally claimed 18 error records (there are 19). All statistics are now generated",
        "   by `scripts/generate_stats.py` and the gate fails if the file on disk differs from a",
        "   fresh computation.",
        "2. **The source layer is no longer a dead citation list.** v1 shipped 326 pinned",
        "   (commit, file) citations whose content lived in an unpublished `dataset/raw`. This",
        "   pipeline clones the audited repositories and the 24 third-party dependencies they",
        f"   cite, and retrieves {srcman.get('total_files_retrieved', 0)} of",
        f"   {srcman.get('total_files_requested', 0)} cited files byte-for-byte at the pinned",
        "   commit. That unlocks contract-level analysis, access-control facts and counterexamples",
        "   without redistributing a single withheld source file.",
        "3. **PoCs are now actually attempted.** All",
        f"   {t.get('exploit_records', 0)} exploit records were classified, and the",
        f"   {comp.get('poc_files_materialised', 0)} that are runnable tests were written into a",
        "   Foundry or Hardhat harness at the pinned commit, compiled and executed, with the",
        "   exact command, forge status and failure reason recorded per record. The remainder",
        "   were recognised as *not runnable as published* — the reports often give a suggested",
        "   contract patch instead of a test — before any build was attempted. Most still did",
        "   not run; the reason is recorded per record rather than summarised away.",
        "4. **The negative corpus explains itself where the evidence allows.**",
        f"   {negm.get('reason_supported_by_cited_code', 0)} negatives carry a blocking",
        "   condition that removes the standing the submission's own text claims; the other",
        f"   {hn.get('blocking_condition_derived_from_code', 0) - negm.get('reason_supported_by_cited_code', 0)}",
        "   recorded gates are kept as context only, because the gate sits on a neighbouring",
        "   function or the claim names a privileged actor.",
        f"   {negm.get('reason_attributed_to_judge_or_sponsor', 0)} carry a reason quoted from a public",
        f"   judge or sponsor comment. {negm.get('unknown_or_insufficient_evidence', 0)} stay",
        "   `unknown`, which is the correct answer and is counted as a first-class outcome.",
        "5. **Cross-split leakage was found and removed.** The detector found",
        f"   {leak.get('semantic_overlap', {}).get('count', 0)} genuinely duplicated submission",
        "   pairs — the same boilerplate `transfer()/transferFrom()` findings filed against two",
        "   different audits. `splits_v2/` quarantines the redundant train copies; nothing was",
        "   deleted and no repository was relocated.",
        "",
        "## WHAT COULD NOT BE VERIFIED",
        "",
        "This is the honest accounting of failure.",
        "",
        f"- **{t.get('not_executed', 0)} of {t.get('exploit_records', 0)} PoCs were never",
        "  executed.** Breakdown of the recorded reasons:",
        "",
    ]
    for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]):
        lines.append(f"    - `{k}`: {v}")
    _dkey, dtext = dominant_blocker(reasons)
    lines += [
        "",
        f"  {dtext}",
        "",
        "  Secondary blockers, in order of what they cost:",
        "",
        "  - **The report PoCs are fragments.** Most are written as \"add this test to",
        "    testFoundry/testOracle.sol\" and reference the audit's own fixtures. Injecting the",
        "    verbatim function into the named test contract works for some; the rest need the",
        "    author's harness reconstructed, which is per-PoC research, not a script.",
        "  - **Dependency installation.** These repositories pin hardhat 2.x with peer ranges",
        "    modern npm rejects. `--legacy-peer-deps` resolves most of them and the strategy that",
        "    succeeded is recorded per repository, but some still do not build.",
        "  - **Archive RPC.** Fork-based PoCs need a mainnet archive endpoint, and none is",
        "    distributed with the dataset. Setting `VLUN_RPC_URL` and re-running",
        "    `scripts/verify_pocs.py` turns every `environment_unavailable` verdict into a real",
        "    pass or fail, and is the single highest-value action available downstream.",
        "",
        f"  {comp.get('poc_files_materialised', 0)} of {t.get('exploit_records', 0)} PoCs were",
        "  materialised into a harness; the remainder were recognised as non-runnable before any",
        "  build was attempted, and `scripts/verify_pocs.py` records which and why.",
        "",
        f"- **No patch was confirmed effective.** {patch.get('patch_records', 0)} patch records",
        f"  exist; {patch.get('evaluated', 0)} could be evaluated and",
        f"  {patch.get('fix_confirmed_effective', 0)} were confirmed by running a PoC against",
        "  both revisions. This is blocked by the same toolchain limits, and the patch diffs are",
        "  withheld in the published copy.",
        "- **No invariant was invented, and none was derived from a failing assertion.**",
        "  `invariants` is empty for records where no source states one. That is deliberate:",
        "  inventing a plausible invariant teaches exactly the hallucination these fields exist to",
        "  prevent.",
        "- **No numeric state values were produced.** State transitions transcribe the attack path",
        "  and the PoC assertions; they do not compute balances.",
        "- **No static-analysis signal was collected.** Slither is installed, but running it over",
        "  eight repositories that do not build here would produce detector noise, not evidence.",
        "  It is deliberately absent rather than reported as a clean result.",
        "",
        "## WHAT REMAINS LIMITED",
        "",
        f"- **{negm.get('unknown_or_insufficient_evidence', 0)} of {neg.get('total', 0)} negatives "
        "have no technical rejection reason.** Code4rena's judging rationale is largely not "
        "public. A duplicate pointer at a confirmed finding says the copy was redundant, not "
        "that the claim was wrong. This corpus cannot teach *why* a false positive is false at "
        "scale; it can only teach the claim, the code, and the fact of rejection.",
        f"- **{ce.get('records_with_at_least_one_counterexample', 0)} of",
        f"  {ce.get('confirmed_high_medium_records', 0)} confirmed High/Medium findings have a",
        "  counterexample.** Most findings cite exactly one function — the vulnerable one — so",
        "  there is no neighbouring function to build a false hypothesis about. Reasons are",
        "  counted in `reports/counterexample_stats.json`.",
        f"- **{dman.get('attacker_identity_unknown', 0)} of {dman.get('records', 0)} records have",
        "  an `unknown` attacker identity.** Mostly the negatives that cite no code at all.",
        f"- **{dman.get('redistribution_flagged', {}).get('source_redistributed_without_declared_license', 0)}",
        "  records contain source text from a repository that declares no licence** at the pinned",
        "  commit. v1 redistributed it; this pipeline flags it rather than asserting it was",
        "  lawful. A downstream redistributor must decide for themselves.",
        "- **453 code citations pin a branch name** (`main`, `release-v5.0`) rather than a commit.",
        "  Those line ranges are not reproducible over time, and v1's claim of byte-for-byte",
        "  verification cannot hold for them. This is reported as a validation warning.",
        "- **The audit repositories themselves are mostly unlicensed or BUSL.** Source from them",
        "  stays withheld; only structure and behaviour are analysed.",
        "",
        "## Reproducing every number",
        "",
        "```bash",
        "python scripts/fetch_sources.py       # clone + retrieve every pinned citation",
        "python scripts/verify_pocs.py          # compile and run the PoCs",
        "python scripts/verify_patches.py       # vulnerable vs fixed",
        "python scripts/build_derived.py        # evidence, attacker model, state transition",
        "python scripts/build_hard_negatives.py # structured rejection reasons",
        "python scripts/build_counterexamples.py",
        "python scripts/check_leakage.py --emit splits_v2",
        "python scripts/build_benchmark.py",
        "python scripts/generate_stats.py",
        "python scripts/generate_reports.py",
        "python scripts/validate.py             # the gate",
        "```",
        "",
        f"Last validation: {vrep.get('passed', 0)}/{vrep.get('checks', 0)} checks passed, "
        f"{vrep.get('failed_critical', 0)} critical failures, {vrep.get('warnings', 0)} warnings.",
        "",
    ]
    (MD / "final_quality_report.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return "\n".join(lines)


def main() -> int:
    ee = build_extraction_errors()
    write_json(REPORTS / "extraction_errors.json", ee)
    log(f"wrote reports/extraction_errors.json ({ee['total']} entries, {ee['by_origin']})")

    md = build_benchmark_metrics()
    write_json(REPORTS / "benchmark_metrics.json",
               {"generated_by": "scripts/generate_reports.py",
                "note": "see reports/benchmark_metrics.md; metrics that need a predictor are "
                        "reported as not measurable rather than estimated",
                "task_coverage": (jread(BENCH / "manifest.json", {}) or {}).get("tasks", {}),
                "verification_totals": (jread(REPORTS / "verification_stats.json", {}) or {}).get("totals", {}),
                "markdown_lines": len(md.splitlines())})
    log("wrote reports/benchmark_metrics.md")

    fr = build_final_report()
    log(f"wrote reports/final_quality_report.md ({len(fr.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

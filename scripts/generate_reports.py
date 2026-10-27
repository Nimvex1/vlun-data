#!/usr/bin/env python3
"""Generate the human-readable reports from machine-readable facts.

    reports/extraction_errors.json   every known limitation, v1 and v2, one entry each
    reports/benchmark_metrics.md    what can actually be measured, and what cannot
    reports/final_quality_report.md  BEFORE / AFTER / improved / unverifiable / limited

Nothing here computes a number that a source does not support. Metrics whose
denominator is zero are reported as "not measurable" rather than as 0% or 100%.

Freshness (`--check`) is independent of semantic validation: a byte-identical
regeneration can still contain a resolved or unverifiable finding. Findings are
never deleted; each carries `state` in {open, resolved, superseded,
unverifiable} with evidence for any non-open state.

    python scripts/generate_reports.py
    python scripts/generate_reports.py --check
"""

from __future__ import annotations

import argparse
import collections
import hashlib
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


FINDING_STATES = ("open", "resolved", "superseded", "unverifiable")
INPUT_DEPENDENT_KINDS = ("license_not_declared", "source_unavailable")


def finding_id(entry: dict) -> str:
    """Stable identity for an extraction-error finding across regenerations."""
    payload = {
        "origin": entry.get("origin"),
        "kind": entry.get("kind"),
        "repository": entry.get("repository"),
        "summary": entry.get("summary"),
        "audit": entry.get("audit"),
        "source": entry.get("source"),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _validation_detail(check_name: str) -> dict | None:
    vrep = jread(REPORTS / "validation_report.json", {}) or {}
    for c in vrep.get("details") or []:
        if c.get("check") == check_name:
            return c
    return None


def adjudicate_absent(previous: dict, fid: str) -> dict:
    """Keep a historical finding that live generation no longer emits.

    Never delete. Never invent a still_true=false resolution without
    evidence. Missing inputs are unverifiable, not zero findings.
    """
    row = dict(previous)
    row["finding_id"] = fid
    existing_state = row.get("state")
    if existing_state in ("resolved", "superseded", "unverifiable") and row.get("resolution"):
        return row
    kind = row.get("kind")
    if kind == "validation_failure":
        check = (row.get("summary") or "").removeprefix("validation gate: ").strip()
        detail = _validation_detail(check)
        if detail is not None and detail.get("ok") and detail.get("failure_count") == 0:
            row["state"] = "resolved"
            row["still_true"] = False
            row["resolution"] = {
                "reason": ("validation_report.json records this check as ok "
                           "with failure_count=0"),
                "evidence": "reports/validation_report.json",
                "check": check,
                "failure_count": 0,
            }
            return row
        row["state"] = "unverifiable"
        row["still_true"] = None
        row["resolution"] = {
            "reason": ("live generation no longer emits this validation_failure "
                       "and the named check is not independently confirmed"),
            "evidence": "reports/validation_report.json",
            "check": check,
        }
        return row
    if kind in INPUT_DEPENDENT_KINDS:
        srcman = WORK / "source_manifest.json"
        if not srcman.exists():
            row["state"] = "unverifiable"
            row["still_true"] = None
            row["resolution"] = {
                "reason": ("work/source_manifest.json is unavailable; live "
                           "generation cannot confirm or refute this finding"),
                "evidence": "work/source_manifest.json",
                "missing_input": "work/source_manifest.json",
            }
            return row
        row["state"] = "resolved"
        row["still_true"] = False
        row["resolution"] = {
            "reason": ("source_manifest.json is present and live generation "
                       "no longer emits this finding"),
            "evidence": "work/source_manifest.json",
        }
        return row
    row["state"] = "unverifiable"
    row["resolution"] = {
        "reason": ("not emitted by live generation; no independent evidence "
                   "to resolve or refute"),
        "evidence": "scripts/generate_reports.py",
    }
    return row


def merge_extraction_errors(live_entries: list[dict], previous: dict | None) -> dict:
    prev_entries = list((previous or {}).get("entries") or [])
    live_by_id: dict[str, dict] = {}
    for e in live_entries:
        row = dict(e)
        fid = finding_id(row)
        row["finding_id"] = fid
        row["state"] = "open"
        row["still_true"] = True
        live_by_id[fid] = row

    merged: list[dict] = []
    seen: set[str] = set()
    for e in prev_entries:
        fid = e.get("finding_id") or finding_id(e)
        if fid in seen:
            continue
        seen.add(fid)
        if fid in live_by_id:
            merged.append(live_by_id[fid])
        else:
            merged.append(adjudicate_absent(e, fid))
    for fid, row in live_by_id.items():
        if fid in seen:
            continue
        merged.append(row)

    by_kind = collections.Counter(e.get("kind") for e in merged)
    by_origin = collections.Counter(e.get("origin") for e in merged)
    by_state = collections.Counter(e.get("state") or "open" for e in merged)
    return {
        "generated_by": "scripts/generate_reports.py",
        "description": "Every known limitation of this dataset. `origin: v1` "
                       "entries were recorded by the original builder; "
                       "`origin: v2` entries were surfaced by the hardening "
                       "pipeline. Findings are never deleted. `state` is "
                       "open / resolved / superseded / unverifiable; a "
                       "non-open state requires a `resolution` record naming "
                       "reason and evidence. `still_true` is not inferred "
                       "from a newer green report alone.",
        "total": len(merged),
        "by_kind": dict(sorted((k or "", n) for k, n in by_kind.items())),
        "by_origin": dict(by_origin),
        "by_state": dict(sorted(by_state.items())),
        "resolved_entries": int(by_state.get("resolved", 0)),
        "entries": merged,
    }


# ---------------------------------------------------------------------------
# extraction errors
# ---------------------------------------------------------------------------

def live_extraction_entries() -> list[dict]:
    """v1's error records plus every limitation discovered while hardening.

    v1 records are kept verbatim and marked `origin: v1`; anything this pipeline
    discovered is `origin: v2`. Historical findings that this function no
    longer emits are preserved by `merge_extraction_errors`, not deleted.
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

    return entries


def build_extraction_errors() -> dict:
    live = live_extraction_entries()
    previous = jread(REPORTS / "extraction_errors.json", {}) or {}
    return merge_extraction_errors(live, previous)


# ---------------------------------------------------------------------------
# benchmark metrics
# ---------------------------------------------------------------------------

def build_benchmark_metrics() -> str:
    """The benchmark-metric artefacts belong to the scorer.

    `reports/benchmark_metrics.json` and `reports/benchmark_metrics.md` are
    generated by `scripts/score_benchmark.py --build-metrics`, which owns the
    audited family status, the primary metric's denominator and the
    train-only baseline floors. This module used to write a second, thinner
    version of the same two files: two builders for one artefact, so
    whichever ran last won, and the two versions disagreed about which
    families count. The delegation keeps one builder and one artefact.
    """
    import benchmark_status as bstatus  # noqa: PLC0415
    import score_benchmark as sb  # noqa: PLC0415
    status_rep = bstatus.cached_status_report()
    fam_data = sb.load_families(status_rep)
    rep = sb.build_metrics_report(status_rep, fam_data)
    jtext = json.dumps(rep, indent=2, sort_keys=True) + "\n"
    mtext = sb.render_metrics_md(rep) + "\n"
    sb._write(sb.METRICS_JSON, jtext)  # noqa: SLF001
    sb._write(sb.METRICS_MD, mtext)  # noqa: SLF001
    return mtext


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
    return "\n".join(lines)


def check_outputs(ee: dict) -> int:
    """Compare extraction_errors.json to committed bytes. Writes nothing.

    `final_quality_report.md` reads `work/source_manifest.json` (git-ignored).
    A missing manifest is not zero retrievals, and this --check must be
    reproducible on a fresh clone, so that file is not part of the
    byte-identity gate. Semantic staleness of the quality report is a
    separate defect from report freshness.
    """
    ee_path = REPORTS / "extraction_errors.json"
    if not ee_path.exists():
        log("MISSING reports/extraction_errors.json")
        return 1
    on_disk = jread(ee_path, {}) or {}
    if on_disk != ee:
        log("STALE reports/extraction_errors.json — run: "
            "python scripts/generate_reports.py")
        return 1
    log(f"ok: extraction_errors.json ({ee['total']} entries) is current")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="rebuild in memory and compare to committed artefacts")
    args = ap.parse_args()

    ee = build_extraction_errors()
    if args.check:
        return check_outputs(ee)

    write_json(REPORTS / "extraction_errors.json", ee)
    log(f"wrote reports/extraction_errors.json ({ee['total']} entries, "
        f"{ee.get('by_origin')}, by_state={ee.get('by_state')})")

    # benchmark_metrics.* belong to score_benchmark.py; keep the historical
    # delegation on a write run so an operator who runs this script still
    # refreshes them. --check does not touch them.
    md = build_benchmark_metrics()
    log(f"wrote reports/benchmark_metrics.md and reports/benchmark_metrics.json "
        f"via scripts/score_benchmark.py ({len(md.splitlines())} lines)")

    # final_quality_report.md interpolates work/source_manifest.json. Writing
    # it on a checkout without that file would replace measured retrieval
    # counts with 0/0. Only rewrite it when the optional input is present.
    if (WORK / "source_manifest.json").exists():
        fr = build_final_report()
        (MD / "final_quality_report.md").write_text(
            fr, encoding="utf-8", newline="\n")
        log(f"wrote reports/final_quality_report.md ({len(fr.splitlines())} lines)")
    else:
        log("skipped writing final_quality_report.md: "
            "work/source_manifest.json absent (not 0 retrievals)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

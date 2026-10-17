#!/usr/bin/env python3
"""Static diff review of the V3.1 patch candidates.

The 47 V3.1 patch candidates all carry ``patch_status: not_testable`` because
no executable PoC has ever run on either side of their recorded fix. This
script adds a *separate* fact per candidate without touching that verdict:

    a cited static diff between the recorded audited revision and the
    recorded fix commit -- what changed -- never whether the fix works.

Separation rules (enforced here, re-checked by ``validate_v31.py``):

- ``fix_effectiveness`` stays ``not_testable`` unless the finding has an
  *executed* two-side PoC recorded in ``work/patch_poc/index.json`` with
  committed evidence under ``experiments_v3/``: the same valid scenario
  compiled and executed against BOTH revisions with the correct violation
  demonstrated only on the vulnerable side (L6-equivalent evidence), on an
  ``in_diff`` finding. A diff, a project build, or a single-side run never
  flips it.
- ``patch_review_status == "static_diff_only"`` states exactly what was
  reviewed: the diff. It is not a PoC level and earns no L2+ claim.
- ``patch_review_status == "executed_fix_verified"`` means the row carries
  the executed two-side evidence above in addition to its cited diff.
- ``patch_review_status == "diff_unavailable"`` states the truth when the
  source no longer exists anywhere retrievable. The per-repository evidence
  of that search lives in ``source_recovery`` in the report.

Reads:  derived_v3/patch_candidates.json   (never modified)
        work/patch_poc/index.json          (optional PoC attempt index)
Writes: derived_v3/patch_reviews.jsonl
        reports/v3/patch_static_review.json

Clones (git-ignored, ``work/patch_repos/``); a fresh checkout that lacks a
clone produces ``diff_unavailable`` for that repository's rows, never a
fabricated diff:

    git clone https://github.com/1inch/limit-order-protocol work/patch_repos/limit-order-protocol
    git clone --filter=blob:none https://github.com/tredesboi/tapioca-periph work/patch_repos/tapioca-periph

The gTrade/SXT upstreams were deleted and no mirror carries the pinned
revisions (GitHub forks, successor repos and Software Heritage were all
checked; see ``source_recovery``); their rows are ``diff_unavailable``.

licence: no diff text is redistributed. Rows carry counts, file paths, the
control-category label and a sha256 of the diff read locally -- not the diff.

    python scripts/review_patch_candidates.py
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_v3 as V  # noqa: E402
from vlun_io import read_jsonl, sha256_text, write_json, write_jsonl  # noqa: E402
from verify_patches import classify_fix  # noqa: E402

DERIVED = V.DERIVED_V3
CANDIDATES = DERIVED / "patch_candidates.json"
OUT_ROWS = DERIVED / "patch_reviews.jsonl"
OUT_REPORT = V.REPORTS_V3 / "patch_static_review.json"
CLONES = V.ROOT / "work" / "patch_repos"
POC_INDEX = V.ROOT / "work" / "patch_poc" / "index.json"

REVIEW_VERSION = "static-review-1"

STATIC = "static_diff_only"
UNAVAILABLE = "diff_unavailable"
EXECUTED = "executed_fix_verified"

TEST_RE = re.compile(r"(^|/)(tests?|test)(/|_)|Test\.sol$|\.t\.sol$", re.I)
CONFIG_NAMES = ("foundry.toml", "hardhat.config", "package.json")

# Per-repository retrieval state. `unavailable_detail` is the audited record
# of the search when the pinned revisions cannot be obtained anywhere.
REPO_SOURCES: dict[str, dict] = {
    "https://github.com/1inch/limit-order-protocol": {
        "slug": "limit-order-protocol",
        "mirror_used": None,
        "outcome": "recoverable",
        "evidence": "public upstream; full clone; both recorded revisions present",
        "unavailable_detail": None,
    },
    "https://github.com/Tapioca-DAO/tapioca-periph": {
        "slug": "tapioca-periph",
        "mirror_used": "https://github.com/tredesboi/tapioca-periph",
        "outcome": "recoverable_via_mirror",
        "evidence": "upstream deleted (404); mirror fork carries both recorded "
                    "revisions (verified with git cat-file -e)",
        "unavailable_detail": None,
    },
    "https://github.com/GainsNetwork-org/gTrade-contracts": {
        "slug": "gTrade-contracts",
        "mirror_used": None,
        "outcome": "unrecoverable",
        "evidence": "upstream deleted (404 for GainsNetwork-org/gTrade-contracts "
                    "and GainsNetwork/gTrade-contracts); pinned revisions absent "
                    "from gTrade-v5, gTrade-v6 and gTrade-v6.1; fork search (37 "
                    "hits) checked, incl. adsorptionenthalpy/gTrade-v6.1 (17 MB, "
                    "pushed 2024-07-01) -- neither revision present; Software "
                    "Heritage origin lookup 404; no fork of the deleted repo exists",
        "unavailable_detail": "repository deleted upstream; no fork carries the "
                               "recorded revisions; Software Heritage has no archive",
    },
    "https://github.com/spaceandtimelabs/sxt-token": {
        "slug": "sxt-token",
        "mirror_used": None,
        "outcome": "unrecoverable",
        "evidence": "upstream deleted (404); successor spaceandtimefdn/sxt-token "
                    "(created 2025-04-29, 3 commits) does not contain either "
                    "recorded revision; only fork ilyadruzh/sxt-token forks the "
                    "successor; Software Heritage origin lookup 404; fork search "
                    "(4 hits) found no repository with the audited history",
        "unavailable_detail": "repository deleted upstream; the successor "
                               "repository lacks the recorded revisions; Software "
                               "Heritage has no archive",
    },
}

# Fix locality per finding, assessed by reading the cited pair's diff locally
# and the review's own scope (the 1inch review spans two repositories, but
# every V3.1 candidate for it records only the limit-order-protocol pair).
# Vocabulary:
#   in_diff      the cited diff changes the contract/mechanism the finding
#                targets
#   not_in_diff  it does not; the fix may live in the review's second
#                repository (limit-order-settlement, whose fix revision the
#                candidate record never captured) or beyond this pair
#   ambiguous    cannot be decided from the diff alone
# Scoped strictly to the cited cumulative pair; not a fix verdict.
FIX_LOCALITY: dict[str, tuple[str, str, str]] = {
    "pashov-audits:team/1inch-security-review:[L-01]": (
        "limit-order-settlement:IntegratorFeeExtension", "not_in_diff",
        "targets the review's second repository; its fix revision was not "
        "captured in the V3.1 candidate record"),
    "pashov-audits:team/1inch-security-review:[L-02]": (
        "limit-order-protocol:auction timeDelta encoding", "not_in_diff",
        "the cited diff contains no auction/timeDelta change"),
    "pashov-audits:team/1inch-security-review:[L-03]": (
        "limit-order-protocol:auction rate-bump division", "not_in_diff",
        "the cited diff contains no auction/timeDelta change"),
    "pashov-audits:team/1inch-security-review:[L-04]": (
        "limit-order-settlement:WhitelistExtension", "not_in_diff",
        "targets the review's second repository; its fix revision was not "
        "captured in the V3.1 candidate record"),
    "pashov-audits:team/1inch-security-review:[M-01]": (
        "limit-order-protocol:FeeTaker.postInteraction", "in_diff",
        "the diff adds receive() and an ETH branch in postInteraction"),
    "pashov-audits:team/1inch-security-review:[M-02]": (
        "limit-order-protocol:FeeTaker.postInteraction", "ambiguous",
        "the diff reworks FeeTaker but carries no visible balance clamp"),
}
LOCALITY_SCOPE_NOTE = (
    "Assessed for the six 1inch findings only. The tapioca-periph pair is a "
    "123-file repo-wide cumulative diff (108 commits), where a file merely "
    "appearing in the diff has no bearing on any single finding's fix; its "
    "rows leave fix_locality null rather than guess.")

_DIFF_CACHE: dict[tuple, dict | None] = {}
_TREE_CACHE: dict[tuple, list[str]] = {}


def _run(clone: Path, *args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.quotepath=false", *args],
                          cwd=str(clone), capture_output=True, timeout=timeout)


def _has_commit(clone: Path, sha: str) -> bool:
    r = _run(clone, "cat-file", "-e", f"{sha}^{{commit}}", timeout=60)
    return r.returncode == 0


def _remote(clone: Path) -> str:
    r = _run(clone, "remote", "get-url", "origin", timeout=60)
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def _read_diff(clone: Path, v: str, f: str) -> dict | None:
    """The diff facts, cached per (clone, revision pair)."""
    key = (str(clone), v, f)
    if key in _DIFF_CACHE:
        return _DIFF_CACHE[key]
    r = _run(clone, "diff", "--no-color", "--unified=0", v, f)
    if r.returncode != 0:
        _DIFF_CACHE[key] = None
        return None
    diff = r.stdout.decode("utf-8", "replace")
    added = [ln for ln in diff.splitlines()
             if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln for ln in diff.splitlines()
               if ln.startswith("-") and not ln.startswith("---")]
    delta = {"diff_bytes": len(diff), "added_lines": len(added),
             "removed_lines": len(removed),
             # internal only (classifier input); never committed
             "added_sample": [ln[1:].strip() for ln in added[:120]],
             "removed_sample": [ln[1:].strip() for ln in removed[:120]]}

    paths: list[str] = []
    r2 = _run(clone, "diff", "--name-status", "-z", v, f)
    if r2.returncode == 0:
        toks = r2.stdout.decode("utf-8", "replace").split("\0")
        i = 0
        while i < len(toks):
            st = toks[i]
            if not st:
                i += 1
                continue
            if st[0] in ("R", "C"):
                old = toks[i + 1] if i + 1 < len(toks) else ""
                new = toks[i + 2] if i + 2 < len(toks) else ""
                paths.append(new or old)
                i += 3
            else:
                paths.append(toks[i + 1] if i + 1 < len(toks) else "")
                i += 2
    r3 = _run(clone, "rev-list", "--count", f"{v}..{f}", timeout=300)
    n = r3.stdout.decode("utf-8", "replace").strip()
    commits = int(n) if r3.returncode == 0 and n.isdigit() else None
    out = {"delta": delta, "paths": paths, "commits_between": commits,
           "diff_text": diff}
    _DIFF_CACHE[key] = out
    return out


def _tree(clone: Path, sha: str) -> list[str]:
    key = (str(clone), sha)
    if key in _TREE_CACHE:
        return _TREE_CACHE[key]
    r = _run(clone, "ls-tree", "-r", "--name-only", sha, timeout=300)
    names = r.stdout.decode("utf-8", "replace").splitlines() if r.returncode == 0 else []
    _TREE_CACHE[key] = names
    return names


def _build_context(clone: Path, fixed: str) -> dict:
    names = _tree(clone, fixed)
    root = {p.split("/", 1)[0] for p in names}
    return {"foundry_toml": "foundry.toml" in root,
            "hardhat_config": any(r.startswith("hardhat.config") for r in root),
            "package_json": "package.json" in root,
            "test_files_present": sum(1 for p in names if TEST_RE.search(p))}


def _poc_overrides() -> tuple[dict, str]:
    if not POC_INDEX.exists():
        return {}, "no local PoC attempt index (work/patch_poc/index.json)"
    try:
        doc = json.loads(POC_INDEX.read_text(encoding="utf-8"))
        attempts = doc.get("attempts", [])
        return ({a["finding_id"]: a for a in attempts
                 if isinstance(a, dict) and a.get("finding_id")},
                f"local PoC attempt index read ({len(attempts)} entries)")
    except (OSError, ValueError, KeyError) as exc:
        return {}, f"local PoC attempt index unreadable: {exc}"


def _review_one(c: dict, poc: dict) -> dict:
    repo = c.get("repository", "")
    v, f = c.get("vulnerable_commit", ""), c.get("fixed_commit", "")
    src = REPO_SOURCES.get(repo)
    fid = c.get("finding_id", "?")
    row = {
        "finding_id": fid,
        "repository": repo,
        "vulnerable_commit": v,
        "fixed_commit": f,
        "patch_review_status": UNAVAILABLE,
        "review_method": None,
        "diff_unavailable_reason": None,
        "diff_unavailable_detail": None,
        "cited_diff": None,
        "diff_stats": None,
        "fix_category": classify_fix(None),
        "fix_locality": None,
        "patch_review_rationale": "",
        "fix_effectiveness": "not_testable",
        "fix_effectiveness_reason":
            "static review only: the same valid PoC has not been compiled and "
            "executed against both revisions with the correct violation shown "
            "only on the vulnerable side",
        "poc_reconstruction": {
            "attempted": False,
            "outcome": "not_attempted",
            "note": "static review pass; no execution attempted for this finding",
        },
        "normalization_version": "3.1",
        "review_version": REVIEW_VERSION,
        "generated_by": "scripts/review_patch_candidates.py",
    }
    if fid in poc:
        o = poc[fid]
        pr = {
            "attempted": bool(o.get("attempted", True)),
            "outcome": o.get("outcome", "unknown"),
            "note": o.get("note", ""),
        }
        if o.get("evidence"):
            pr["evidence"] = o["evidence"]
        row["poc_reconstruction"] = pr
        if o.get("patch_review_status"):
            row["patch_review_status"] = o["patch_review_status"]
        if o.get("fix_effectiveness"):
            row["fix_effectiveness"] = o["fix_effectiveness"]
            row["fix_effectiveness_reason"] = (
                o.get("effectiveness_reason") or o.get("note", "")
                or row["fix_effectiveness_reason"])
    if fid in FIX_LOCALITY:
        target, assessment, evidence = FIX_LOCALITY[fid]
        row["fix_locality"] = {"target": target, "assessment": assessment,
                               "evidence": evidence}

    if src is None:
        row["diff_unavailable_reason"] = "clone_not_mapped"
        row["diff_unavailable_detail"] = "repository not in the retrieval map"
        row["patch_review_rationale"] = (
            "No static diff: no retrieval route is recorded for this repository.")
        return row

    clone = CLONES / src["slug"]
    if not (clone / ".git").exists():
        row["diff_unavailable_reason"] = "clone_not_present"
        row["diff_unavailable_detail"] = (
            "local clone absent; see module docstring for the clone commands")
        row["patch_review_rationale"] = (
            "No static diff computed here: the git-ignored local clone is absent. "
            "Re-run with the clone present; the committed rows for this "
            "repository were produced where the clone existed.")
        return row
    if not (_has_commit(clone, v) and _has_commit(clone, f)):
        row["diff_unavailable_reason"] = "commits_unavailable"
        row["diff_unavailable_detail"] = src["unavailable_detail"] or (
            "local clone does not contain both recorded revisions")
        row["patch_review_rationale"] = (
            "No static diff: " + (src["unavailable_detail"] or
                                  "the recorded revisions are absent locally") + ".")
        return row

    info = _read_diff(clone, v, f)
    if info is None:
        row["diff_unavailable_reason"] = "diff_command_failed"
        row["diff_unavailable_detail"] = "git diff between the recorded revisions failed"
        row["patch_review_rationale"] = (
            "No static diff: git could not read the diff between the recorded "
            "revisions in the local clone.")
        return row

    delta, paths = info["delta"], info["paths"]
    commits = info["commits_between"]
    cat = classify_fix(delta)
    ctx = _build_context(clone, f)
    tests = sorted(p for p in paths if TEST_RE.search(p))
    base = (src["mirror_used"] or repo).rstrip("/")
    status = (EXECUTED if row["patch_review_status"] == EXECUTED else STATIC)
    row.update({
        "patch_review_status": status,
        "review_method": "git_diff_between_recorded_revisions",
        "diff_unavailable_reason": None,
        "diff_unavailable_detail": None,
        "cited_diff": {
            "compare_url": f"{base}/compare/{v}...{f}",
            "mirror_used": src["mirror_used"],
            "diff_command": f"git diff --no-color --unified=0 {v} {f}",
            "diff_sha256": sha256_text(info["diff_text"]),
            "commit_urls": [f"{repo}/commit/{v}", f"{repo}/commit/{f}"],
            "caveat": ("cumulative diff between the recorded audited revision and "
                       "the recorded fix commit; it includes every commit landed "
                       "in between, not necessarily only the fix"),
        },
        "diff_stats": {
            "commits_between": commits,
            "files_changed": len(paths),
            "added_lines": delta["added_lines"],
            "removed_lines": delta["removed_lines"],
            "paths": paths[:60],
            "paths_truncated": len(paths) > 60,
            "tests_touched": tests[:15],
            "tests_touched_count": len(tests),
            "build_context_at_fixed": ctx,
        },
        "fix_category": cat,
    })
    row["patch_review_rationale"] = (
        f"Static diff between the audited revision and the recorded fix: "
        f"{commits if commits is not None else '?'} commit(s), "
        f"{len(paths)} file(s), +{delta['added_lines']} / -{delta['removed_lines']} "
        f"line(s). Control signals match `{cat['category']}` at "
        f"`{cat['confidence']}` confidence. This states what the diff changes, "
        f"not whether the code is fixed.")
    return row


def _aggregate(rows: list[dict], candidates: list[dict], poc_note: str) -> dict:
    by_status: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    by_conf: dict[str, int] = {}
    by_repo: dict[str, dict] = {}
    pairs: dict[tuple, dict] = {}
    loc: dict[str, int] = {}
    eff: dict[str, int] = {}
    outs: dict[str, int] = {}
    attempted = 0
    cited = 0
    for r in rows:
        by_status[r["patch_review_status"]] = by_status.get(r["patch_review_status"], 0) + 1
        cat = r["fix_category"]["category"]
        by_cat[cat] = by_cat.get(cat, 0) + 1
        conf = r["fix_category"]["confidence"]
        by_conf[conf] = by_conf.get(conf, 0) + 1
        eff[r["fix_effectiveness"]] = eff.get(r["fix_effectiveness"], 0) + 1
        outs[r["poc_reconstruction"]["outcome"]] = \
            outs.get(r["poc_reconstruction"]["outcome"], 0) + 1
        fl = r.get("fix_locality")
        if fl:
            loc[fl["assessment"]] = loc.get(fl["assessment"], 0) + 1
        e = by_repo.setdefault(r["repository"], {"candidates": 0})
        e["candidates"] += 1
        e[r["patch_review_status"]] = e.get(r["patch_review_status"], 0) + 1
        if r["poc_reconstruction"].get("attempted"):
            attempted += 1
        cd = r.get("cited_diff")
        if cd:
            cited += 1
            k = (r["repository"], r["vulnerable_commit"], r["fixed_commit"])
            pe = pairs.setdefault(k, {
                "repository": r["repository"],
                "vulnerable_commit": r["vulnerable_commit"],
                "fixed_commit": r["fixed_commit"],
                "diff_sha256": cd["diff_sha256"],
                "candidates_citing": 0,
            })
            pe["candidates_citing"] += 1
    recovery = []
    for repo, src in sorted(REPO_SOURCES.items()):
        clone = CLONES / src["slug"]
        recovery.append({
            "repository": repo,
            "upstream_state": ("public" if src["outcome"] == "recoverable"
                               else "deleted_or_inaccessible"),
            "local_clone": str(clone.relative_to(V.ROOT)).replace("\\", "/")
            if (clone / ".git").exists() else None,
            "clone_remote": _remote(clone) if (clone / ".git").exists() else None,
            "mirror_used": src["mirror_used"],
            "outcome": src["outcome"],
            "evidence": src["evidence"],
        })
    return {
        "generated_by": "scripts/review_patch_candidates.py",
        "review_version": REVIEW_VERSION,
        "normalization_version": "3.1",
        "patch_candidates": len(candidates),
        "rows": len(rows),
        "by_patch_review_status": by_status,
        "by_repository": by_repo,
        "unique_diff_pairs": len(pairs),
        "by_diff_pair": [pairs[k] for k in sorted(pairs)],
        "by_fix_category": dict(sorted(by_cat.items())),
        "by_fix_confidence": dict(sorted(by_conf.items())),
        "fix_locality_assessed": sum(loc.values()),
        "fix_locality_by_assessment": dict(sorted(loc.items())),
        "fix_locality_scope_note": LOCALITY_SCOPE_NOTE,
        "rows_with_cited_diff": cited,
        "fix_effectiveness": dict(sorted(eff.items())),
        "execution": {"poc_runs_performed": attempted,
                      "outcomes": dict(sorted(outs.items())),
                      "levels_claimed": []},
        "poc_attempt_source": poc_note,
        "review_vocabulary": [STATIC, UNAVAILABLE, EXECUTED],
        "separation_guarantee": (
            "A static diff review states what changed, never whether the fix "
            "works. fix_effectiveness stays `not_testable` unless the finding "
            "has an executed two-side PoC (work/patch_poc/index.json) with "
            "committed evidence in experiments_v3/: the same valid scenario "
            "run on both revisions with the correct violation only on the "
            "vulnerable side, on an in_diff finding. A diff review, a project "
            "build, or a single-side run never flips it, and no review row "
            "earns an L-level claim."),
        "licence_note": (
            "No diff text is redistributed: rows carry counts, file paths, a "
            "control-category label and a sha256 of the diff read locally."),
        "source_recovery": recovery,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    candidates = read_jsonl(CANDIDATES)
    poc, poc_note = _poc_overrides()
    rows = sorted((_review_one(c, poc) for c in candidates),
                  key=lambda r: r["finding_id"])

    cand_ids = [c.get("finding_id") for c in candidates]
    row_ids = [r["finding_id"] for r in rows]
    if len(rows) != len(candidates) or set(row_ids) != set(cand_ids):
        print("FATAL: review rows do not match patch candidates 1:1")
        return 1
    bad_eff: list[str] = []
    for r in rows:
        if r["fix_effectiveness"] == "not_testable":
            continue
        pr = r["poc_reconstruction"]
        ev = pr.get("evidence") or {}
        if not (pr.get("attempted") is True
                and pr.get("outcome") == "fix_verified_two_side"
                and isinstance(ev.get("vulnerable"), dict)
                and isinstance(ev.get("fixed"), dict)
                and ev["vulnerable"].get("result")
                and ev["fixed"].get("result")
                and (r.get("fix_locality") or {}).get("assessment") == "in_diff"):
            bad_eff.append(r["finding_id"])
    if bad_eff:
        print("FATAL: an effectiveness claim needs an executed two-side PoC "
              "on an in_diff finding (work/patch_poc/index.json + committed "
              "evidence): " + ", ".join(bad_eff))
        return 1

    # Audits record one cumulative diff per repository, so several findings
    # cite the same revision pair. State that count on the row instead of
    # letting 25 rows read as 25 independent diffs.
    pair_counts: dict[tuple, int] = {}
    for r in rows:
        cd = r.get("cited_diff")
        if cd:
            k = (r["repository"], r["vulnerable_commit"], r["fixed_commit"])
            pair_counts[k] = pair_counts.get(k, 0) + 1
    for r in rows:
        cd = r.get("cited_diff")
        if cd:
            cd["shared_with_candidates"] = pair_counts[
                (r["repository"], r["vulnerable_commit"], r["fixed_commit"])]

    write_jsonl(OUT_ROWS, rows)
    report = _aggregate(rows, candidates, poc_note)
    write_json(OUT_REPORT, report)
    if not args.quiet:
        V.log(f"review_patch_candidates.py: {len(rows)} rows "
              f"({report['by_patch_review_status']}) -> "
              f"{OUT_ROWS.relative_to(V.ROOT)}")
        V.log(f"review_patch_candidates.py: report -> "
              f"{OUT_REPORT.relative_to(V.ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

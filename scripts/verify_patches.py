#!/usr/bin/env python3
"""P5: does the fix actually fix it?

A merged PR is not evidence that a vulnerability is closed. The only thing that
demonstrates it is running the same PoC against the fixed revision and watching
it stop working.

For each patch record:

    if the PoC never executed on the vulnerable revision
        -> status insufficient_evidence, and that is the honest answer
    else
        checkout the fixed commit, run the same PoC
        vulnerable_revision_exploited / fixed_revision_exploited / regression_test_passed

A patch is never called effective because a PR exists. Diffs stay out of the
dataset: they were withheld for licence reasons in the published copy, so this
script reads them from the local clone and records only the outcome.

    python scripts/verify_patches.py
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_pocs as vp  # noqa: E402
from vlun import (  # noqa: E402
    REPORTS, WORK, load_core, log, owner_repo, run, write_json,
)

RUNS = WORK / "poc_runs"
OUT = WORK / "patch_verification"


def execution_index() -> dict:
    idx = {}
    if not RUNS.exists():
        return idx
    for f in sorted(RUNS.glob("*.json")):
        if f.name == "_all.json":
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        for v in d.get("verdicts", []):
            idx[v["finding_id"]] = {**v, "repo": d["repo"]}
    return idx


def check_one(patch: dict, exe: dict, timeout: int) -> dict:
    fid = (patch.get("finding") or {}).get("id")
    owner = owner_repo(patch["source"])
    p = patch.get("patch") or {}
    base = {
        "finding_id": fid,
        "repository": owner,
        "vulnerable_commit": p.get("vulnerable_commit") or None,
        "fixed_commit": p.get("fixed_commit") or None,
        "prs": p.get("prs") or [],
        "remediation_status": p.get("remediation_status"),
        "diff_available_locally": bool((p.get("diff") or "").strip()),
        "diff_withheld": bool(p.get("diff_withheld")),
    }

    vuln = exe.get(fid)
    if not vuln:
        base.update(fix_verification={"status": "not_attempted",
                                      "reason": "no PoC execution record for this finding"})
        return base
    if vuln["verdict"] != "reproduced":
        base["fix_verification"] = {
            "status": "insufficient_evidence",
            "reason": f"the PoC did not exploit the vulnerable revision "
                      f"(verdict={vuln['verdict']}), so a fix cannot be evaluated",
        }
        return base

    fixed = p.get("fixed_commit")
    if not fixed:
        base["fix_verification"] = {
            "status": "insufficient_evidence",
            "reason": "no fixing commit is recorded, only PR references",
            "vulnerable_revision_exploited": True,
            "fixed_revision_exploited": None,
            "regression_test_passed": None,
        }
        return base

    root = WORK / "repos" / owner.replace("/", "__")
    OUT.mkdir(parents=True, exist_ok=True)
    work = OUT / owner.replace("/", "__")
    if not (root / ".git").exists():
        base["fix_verification"] = {"status": "insufficient_evidence", "reason": "clone unavailable"}
        return base

    rc, _, err, _ = run(["git", "-C", str(root), "checkout", "--quiet", "--force", fixed], timeout=1800)
    if rc != 0:
        base["fix_verification"] = {"status": "insufficient_evidence",
                                    "reason": f"fixed commit {fixed[:10]} could not be checked out: "
                                              f"{(err or '')[:120]}"}
        return base

    ex_rows = [json.loads(l) for l in
               (WORK.parent / "jsonl" / "exploits.jsonl").read_text(encoding="utf-8").splitlines()
               if l.strip() and (json.loads(l)["finding"].get("id") == fid)]
    mat = vp.materialise(root, ex_rows)
    comp = vp.compile_project(root, vp.detect_toolchain(root), timeout)
    if not comp.get("compiled"):
        base["fix_verification"] = {
            "status": "insufficient_evidence",
            "vulnerable_revision_exploited": True, "fixed_revision_exploited": None,
            "regression_test_passed": None,
            "reason": f"the fixed revision does not compile here: "
                      f"{(comp.get('error') or '')[-300:]}",
        }
        return base

    tr = vp.run_tests(root, vp.detect_toolchain(root), None, timeout)
    results = vp.parse_forge_results(tr.get("parsed"))
    name = (ex_rows[0]["exploit"].get("test_name") or "").strip() if ex_rows else ""
    hit = results.get(name)
    if not hit:
        base["fix_verification"] = {
            "status": "insufficient_evidence", "vulnerable_revision_exploited": True,
            "fixed_revision_exploited": None, "regression_test_passed": None,
            "reason": "the PoC test does not exist in the fixed revision's test set",
        }
        return base
    verdict, _ = vp.classify(hit["status"], hit["reason"])
    still = verdict == "reproduced"
    base["fix_verification"] = {
        "status": "evaluated",
        "vulnerable_revision_exploited": True,
        "fixed_revision_exploited": still,
        "regression_test_passed": not still,
        "forge_status_on_fixed_revision": hit["status"],
        "reason_on_fixed_revision": (hit["reason"] or "")[:400],
        "command": tr["command"],
        "interpretation": ("the PoC still succeeds after the fix, so the fix is incomplete"
                           if still else
                           "the PoC no longer succeeds after the fix, consistent with the "
                           "vulnerability being closed"),
    }
    run(["git", "-C", str(root), "checkout", "--quiet", "--force",
         vuln.get("head_commit") or patch["source"]["commit_sha"]], timeout=1800)
    return base


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=5400)
    args = ap.parse_args()

    exe = execution_index()
    patches = [r for r in load_core()["patches"]]
    out = []
    for p in patches:
        res = check_one(p, exe, args.timeout)
        out.append(res)
        log(f"  {res['finding_id']:32s} {res['fix_verification']['status']}")

    tally = collections.Counter(r["fix_verification"]["status"] for r in out)
    summary = {
        "generated_by": "scripts/verify_patches.py",
        "patch_records": len(out),
        "by_status": dict(tally),
        "evaluated": sum(1 for r in out if r["fix_verification"].get("status") == "evaluated"),
        "vulnerable_revision_exploited": sum(
            1 for r in out if r["fix_verification"].get("vulnerable_revision_exploited")),
        "fixed_revision_exploited": sum(
            1 for r in out if r["fix_verification"].get("fixed_revision_exploited")),
        "fix_confirmed_effective": sum(
            1 for r in out if r["fix_verification"].get("status") == "evaluated"
            and r["fix_verification"].get("regression_test_passed")),
        "guarantee": "a patch is called effective only when the same PoC exploited the vulnerable "
                     "revision and then failed on the fixed revision. A merged PR is never "
                     "sufficient.",
        "records": out,
    }
    write_json(REPORTS / "patch_verification.json", summary)
    log(f"\npatch_verification.json: {summary['by_status']}")
    log(f"  evaluated={summary['evaluated']} "
        f"fix_confirmed_effective={summary['fix_confirmed_effective']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
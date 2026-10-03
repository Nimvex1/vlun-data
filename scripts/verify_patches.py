#!/usr/bin/env python3
"""Does the fix actually fix it?

A merged PR is not evidence that a vulnerability is closed. The only thing that
demonstrates it is running the same PoC against the fixed revision and watching it
stop working, for the right reason.

Two evidence sources feed this report:

  1. `reports/verified_experiments.json` — findings where both revisions were
     actually executed. Those are the only records that can reach
     `fix_effectiveness = effective`.
  2. `jsonl/patches.jsonl` — the recorded vulnerable/fixed commits and the PR
     references. A patch whose revisions were never both executed is reported as
     `not_testable` with the reason, never as effective.

Patch delta analysis: when both revisions are available locally the diff is read
from git and classified by what kind of control changed. The classification is a
statement about the diff, not a claim that the fix works; only the experiment can
make that claim.

    python scripts/verify_patches.py
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiments as ex  # noqa: E402
from vlun import JSONL, REPORTS, log, read_jsonl, write_json  # noqa: E402

# What kind of control the diff changed. Assigned from the diff's own text.
FIX_CATEGORIES = (
    "authorization", "input_validation", "state_update", "accounting",
    "reentrancy_protection", "oracle_validation", "slippage_protection",
    "nonce/replay_protection", "parameter_correction", "recipient_correction",
    "token_handling", "DoS_prevention", "upgradeability", "cross_chain_validation",
    "other",
)

CATEGORY_SIGNALS = {
    "authorization": ("onlyOwner", "onlyRole", "require(msg.sender", "Unauthorized",
                      "_checkRole", "msg.sender !=", "auth", "guardian", "whitelist"),
    "input_validation": ("require(", "invalid", "validate", "sanity", "zero address",
                         "address(0)", "calldatalength", "bounds"),
    "state_update": ("= ", "delete ", "storage", "_set", "update", "s_"),
    "accounting": ("totalAssets", "totalSupply", "shares", "balanceOf", "reserve",
                   "reserveRatio", "collateral", "debt"),
    "reentrancy_protection": ("nonReentrant", "ReentrancyGuard", "lock", "unlocked"),
    "oracle_validation": ("latestRoundData", "chainlink", "oracle", "priceFeed",
                          "stale", "heartbeat", "decimals"),
    "slippage_protection": ("slippage", "minAmountOut", "amountOutMin", "priceLimit"),
    "nonce/replay_protection": ("nonce", "deadline", "expiration", "usedHashes",
                                "signed", "eip712", "domainSeparator"),
    "parameter_correction": ("= 0", "constant", "OFFSET", "offset", "MAX_", "MIN_"),
    "recipient_correction": ("recipient", "receiver", "to =", "beneficiary", "escrow"),
    "token_handling": ("transferFrom", "safeTransfer", "feeOnTransfer", "IERC20",
                       "token.", "allowance"),
    "DoS_prevention": ("gas", "unchecked", "block.", "while (", "try ", "catch"),
    "upgradeability": ("upgrade", "proxy", "implementation", "delegatecall", "initializer"),
    "cross_chain_validation": ("lzReceive", "messageId", "sourceChain", "endpoint",
                              "bridge", "adapter"),
}

# Repositories whose fixed revisions live somewhere other than the audit snapshot.
FIX_REPO = {
    "2024-01-renft": ("renft-smart", "https://github.com/re-nft/smart-contracts.git"),
    "2024-12-bakerfi": ("bakerfi-contracts", "https://github.com/baker-fi/bakerfi-contracts.git"),
}


def load_experiments() -> dict[str, dict]:
    f = REPORTS / "verified_experiments.json"
    if not f.exists():
        return {}
    return {e["finding_id"]: e for e in
            json.loads(f.read_text(encoding="utf-8")).get("experiments", [])}


def read_diff(slug: str, vulnerable: str, fixed: str) -> dict | None:
    clone = ex.WT / slug
    if not (clone / ".git").exists():
        return None
    r = subprocess.run(["git", "diff", "--unified=0", vulnerable, fixed, "--", "src", "contracts"],
                       cwd=str(clone), capture_output=True, text=True, timeout=900,
                       errors="replace")
    if r.returncode != 0:
        return None
    diff = r.stdout
    added = [l for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    files = [l for l in diff.splitlines() if l.startswith("diff --git")]
    return {"diff_bytes": len(diff), "files_changed": len(files),
            "added_lines": len(added), "removed_lines": len(removed),
            "added_sample": [l[1:].strip() for l in added[:120]],
            "removed_sample": [l[1:].strip() for l in removed[:120]],
            "paths": [l.split(" b/", 1)[-1] for l in files][:60]}


def classify_fix(delta: dict | None) -> dict:
    if not delta:
        return {"category": "other", "evidence_type": "unknown",
                "confidence": "unknown",
                "note": "the diff was not legally or technically retrievable here"}
    text = ("\n".join(delta["added_sample"]) + "\n"
            + "\n".join(delta["removed_sample"])).lower()
    scores = {}
    for cat, needles in CATEGORY_SIGNALS.items():
        scores[cat] = sum(text.count(n.lower()) for n in needles)
    best = sorted(scores.items(), key=lambda kv: -kv[1])
    top, second = best[0], best[1] if len(best) > 1 else (None, 0)
    if top[1] == 0:
        return {"category": "other", "evidence_type": "derived_fact",
                "confidence": "low", "signal_counts": {k: v for k, v in best[:5]},
                "note": "no control signal in the diff; classified as other"}
    ambiguous = second[1] > 0 and second[1] / max(top[1], 1) > 0.8
    return {
        "category": top[0],
        "evidence_type": "derived_fact",
        "confidence": "low" if ambiguous else "medium",
        "signal_counts": {k: v for k, v in best[:5]},
        "note": ("the diff matches more than one control category equally; the label is "
                 "the weakest defensible reading" if ambiguous else
                 "assigned from keyword signals in the diff; it states what changed, "
                 "not whether the fix works"),
    }


def effectiveness(exp: dict | None) -> dict:
    if not exp:
        return {"fix_effectiveness": "not_testable",
                "reason": "no experiment ran both revisions for this finding"}
    v = exp.get("revisions", {})
    vs = (v.get("vulnerable") or {}).get("status")
    fs = (v.get("fixed") or {}).get("status")
    verdict = exp.get("verdict")
    if verdict == "l6_verified_patch":
        return {
            "fix_effectiveness": "effective",
            "vulnerable_revision_result": vs,
            "fixed_revision_result": fs,
            "failure_reason_on_fixed": ((v.get("fixed") or {}).get("declared_expectation")),
            "regression_test": (exp.get("match_test")),
            "reason": ("the same test observed the violation on the audited revision and "
                       "the property held on the fixed revision"),
        }
    if verdict == "reproduced_but_not_blocked":
        return {"fix_effectiveness": "ineffective", "vulnerable_revision_result": vs,
                "fixed_revision_result": fs,
                "reason": "the violation was still observed on the fixed revision"}
    if verdict == "exploit_not_reproduced_on_vulnerable_revision":
        return {"fix_effectiveness": "inconclusive",
                "vulnerable_revision_result": vs, "fixed_revision_result": fs,
                "reason": ("the property already held on the audited revision, so this "
                           "experiment cannot measure the fix")}
    return {"fix_effectiveness": "not_testable",
            "vulnerable_revision_result": vs, "fixed_revision_result": fs,
            "reason": (exp.get("inconclusive_reason")
                       or "the experiment did not produce both a violation and a block")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(REPORTS / "patch_verification_v2.json"))
    ap.add_argument("--emit-legacy", default=str(REPORTS / "patch_verification.json"))
    args = ap.parse_args()

    patches = read_jsonl(JSONL / "patches.jsonl")
    experiments = load_experiments()

    rows = []
    for p in patches:
        fid = p["finding"]["id"]
        pt = p.get("patch") or {}
        repo = p["source"]["repository"]
        exp = experiments.get(fid)
        eff = effectiveness(exp)

        slug, url = FIX_REPO.get(repo, (repo.replace("/", "__"), None))
        delta = None
        if exp:
            # The patch record's `vulnerable_commit` is the *audit repository* HEAD.
            # The diff has to be taken inside the patched repository, against the
            # revision the experiment actually ran on.
            vuln_for_diff = ((exp.get("revisions", {}).get("vulnerable") or {})
                             .get("commit") or pt.get("vulnerable_commit") or "")
            fixed_for_diff = ((exp.get("revisions", {}).get("fixed") or {})
                              .get("commit") or pt.get("fixed_commit") or "")
            delta = read_diff(slug, vuln_for_diff, fixed_for_diff)
            delta = dict(delta or {"unavailable": True})
            delta["diffed_vulnerable_commit"] = vuln_for_diff
            delta["diffed_fixed_commit"] = fixed_for_diff
            delta["patch_record_vulnerable_commit"] = pt.get("vulnerable_commit")
        commit_discrepancy = None
        if exp:
            rec_fx = pt.get("fixed_commit") or ""
            exp_fx = ((exp.get("revisions", {}).get("fixed") or {}).get("commit") or "")
            if rec_fx and exp_fx and rec_fx != exp_fx:
                commit_discrepancy = {
                    "patch_record_fixed_commit": rec_fx,
                    "experiment_fixed_commit": exp_fx,
                    "note": ("the v1 patch record names a different fixing commit than the one "
                             "the experiment used. The experiment uses the commit that carries "
                             "this finding's mitigation, identified from the mitigation commit "
                             "that introduced its regression test. Both SHAs are retained; "
                             "neither is silently preferred."),
                }
        rows.append({
            "finding_id": fid,
            "repository": repo,
            "severity": p["finding"].get("severity"),
            "vulnerable_commit": pt.get("vulnerable_commit"),
            "fixed_commit": pt.get("fixed_commit"),
            "fixed_repository": slug if exp else None,
            "fixing_commit_discrepancy": commit_discrepancy,
            "remediation_status": pt.get("remediation_status"),
            "prs": pt.get("prs_withheld") or pt.get("prs") or [],
            "diff_withheld_for_licence": bool(pt.get("diff_withheld")),
            "patch_delta": delta,
            "patch_delta_scope": (
                "cumulative diff from the audited revision to the recorded fix commit; "
                "it necessarily includes every mitigation landed in between, so the "
                "category describes the whole delta rather than this finding's hunk "
                "alone" if delta and delta.get("files_changed") else None),
            "fix_category": classify_fix(delta),
            **eff,
        })

    tally = collections.Counter(r["fix_effectiveness"] for r in rows)
    doc = {
        "generated_by": "scripts/verify_patches.py",
        "patch_records": len(rows),
        "by_fix_effectiveness": dict(tally),
        "experimentally_confirmed_pairs": tally.get("effective", 0),
        "fix_category_vocabulary": list(FIX_CATEGORIES),
        "guarantee": ("a patch is called effective only when the same test observed the "
                      "violation on the audited revision and the property held on the fixed "
                      "revision. A merged PR, a remediation label or a diff is never "
                      "sufficient."),
        "licence_note": ("diffs are read from local clones for analysis only; no diff text "
                         "is redistributed for the BUSL-1.1 repositories"),
        "records": rows,
    }
    write_json(Path(args.out), doc)

    # keep the v2 report path alive so older tooling still resolves
    legacy = {
        "generated_by": "scripts/verify_patches.py (v2 compatibility view)",
        "patch_records": len(rows),
        "by_status": dict(tally),
        "evaluated": tally.get("effective", 0) + tally.get("ineffective", 0),
        "fix_confirmed_effective": tally.get("effective", 0),
        "records": [{
            "finding_id": r["finding_id"], "repository": r["repository"],
            "vulnerable_commit": r["vulnerable_commit"],
            "fixed_commit": r["fixed_commit"],
            "fix_verification": {"status": r["fix_effectiveness"],
                                 "vulnerable_revision_result": r.get("vulnerable_revision_result"),
                                 "fixed_revision_result": r.get("fixed_revision_result"),
                                 "regression_test_passed": r["fix_effectiveness"] == "effective",
                                 "reason": r.get("reason")},
        } for r in rows],
    }
    write_json(Path(args.emit_legacy), legacy)

    log(f"patch_verification_v2.json: {dict(tally)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
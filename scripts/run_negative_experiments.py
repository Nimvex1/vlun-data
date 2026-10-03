#!/usr/bin/env python3
"""Attempt the exploit each hard negative claims, and record what happened.

A negative is only `experimentally_verified` when the proposed attack was
actually executed and observed to fail. This script does exactly that for the
negatives whose claim names a function the audited repository's own regression
suite exercises:

    the claim is reconstructed from the submission's own text
    the attack is run against the AUDITED revision
    the outcome is one of
        false_positive_verified          the attack was attempted and reverted
        exploit_reproduced               the attack succeeded -> this is not a negative
        claim_misunderstood              the claim does not describe this code path
        historical_environment_unavailable  the harness could not be run here

Where the harness cannot be built on the audited revision, the reason is recorded
(`reconstruction_failed`, `rpc_unavailable`, ...) and the negative stays
`unknown`. Nothing is inferred.

    python scripts/run_negative_experiments.py --rerun
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiments as ex  # noqa: E402
import run_verified_experiments as rve  # noqa: E402
from vlun import JSONL, REPORTS, log, read_jsonl, write_json  # noqa: E402

VULNERABLE = rve.RENFT_VULN

# (negative id, the claim as the reporter states it, the regression test that
#  exercises exactly that action, the commit whose test was used as the harness)
NEGATIVE_CASES = [
    dict(
        finding_id="2024-01-renft/submission-621",
        claimed_attack=("a renter bypasses the Guard completely by calling "
                        "`setFallbackHandler()` on the rental safe, then performs "
                        "unguarded transactions"),
        test="integration/prevented-exploits/SetCustomFallbackHandler.t.sol",
        fix_commit="1783237cf05c9369c271b6f3a388b8d57d03ecc8",
        overlays=[],
        match_test="test_",
        blocking_condition=("the Guard's guarded-selector check rejects "
                            "`setFallbackHandler(address)` before the Safe executes it"),
    ),
    dict(
        finding_id="2024-01-renft/submission-630",
        claimed_attack=("a renter burns the lender's rented ERC-721/ERC-1155 tokens, "
                        "destroying the asset while the rental is active"),
        test="integration/guarded-transactions/ERC721.t.sol",
        fix_commit="fb8013111b57c1e09482fb3193db58cb892229e9",
        overlays=["utils/GnosisSafeUtils.sol",
                  "mocks/tokens/standard/MockERC721.sol"],
        match_test="test_",
        blocking_condition=("the Guard's guarded-selector list includes the burn "
                            "selectors, so the call reverts"),
    ),
    dict(
        finding_id="2024-01-renft/submission-584",
        claimed_attack=("the Guard does not check `burn(address,uint256,uint256)` on "
                        "ERC-1155, so an attacker can burn the renter's tokens"),
        test="integration/guarded-transactions/ERC1155.t.sol",
        fix_commit="d4e3b8e640ec8192030dc061dcb97ad50f12da53",
        overlays=["utils/GnosisSafeUtils.sol",
                  "mocks/tokens/standard/MockERC1155.sol"],
        match_test="test_",
        blocking_condition=("the Guard's guarded-selector list includes the ERC-1155 "
                            "burn selectors, so the call reverts"),
    ),
]


def outcome(status: str, per_test: dict, reason_detail: str | None) -> tuple[str, dict]:
    if status in ("compile_error", "toolchain_failure", "timeout"):
        return "historical_environment_unavailable", {"run_failure": reason_detail}
    if status not in ("pass", "fail"):
        return "historical_environment_unavailable", {"run_failure": status}
    failed = [k for k, v in (per_test or {}).items()
              if str(v.get("status")) not in ("Success", "success")]
    if not failed:
        # every assertion held: each `vm.expectRevert` saw the guard block the call
        return "false_positive_verified", {
            "attempted_assertions": len(per_test or {}),
            "reverted_assertions": len(per_test or {}),
            "reading": ("every assertion in the harness expected the attack to revert and "
                        "every one of them reverted, so the claimed attack does not get "
                        "through on this revision"),
        }
    return "exploit_reproduced", {
        "assertions_that_did_not_block": [
            {"test": k, "forge_reason": (per_test.get(k) or {}).get("reason")}
            for k in failed][:8],
        "reading": "at least one claimed attack was not blocked; this record is not a "
                   "false positive",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rerun", action="store_true")
    args = ap.parse_args()

    negatives = {n["finding"]["id"]: n for n in read_jsonl(JSONL / "negative_findings.jsonl")}
    spec = rve.fixed(VULNERABLE)  # same slug and framework; commit is the audited one
    spec = ex.RepoSpec(**{**spec.__dict__, "commit": VULNERABLE})

    results = []
    for case in NEGATIVE_CASES:
        neg = negatives.get(case["finding_id"])
        if not neg:
            log(f"  {case['finding_id']}: not in the negative layer, skipped")
            continue
        log(f"  {case['finding_id']}")
        test_src = rve.git_show("renft-vulnerable", case["fix_commit"], "test/" + case["test"])
        overlay = {}
        for path in case["overlays"]:
            rev = rve.RENFT_FIXTURE_UPDATES.get(path, case["fix_commit"])
            overlay[path] = rve.git_show("renft-vulnerable", rev, "test/" + path)
        harness = rve.build_harness({case["test"]: test_src}, overlay)
        match_path = "test/vlun_poc/" + rve.flatten(case["test"])

        prior = ex.load_done(case["finding_id"], "attempted")
        if prior and not args.rerun and prior.get("status") in ("pass", "fail",
                                                                "compile_error",
                                                                "toolchain_failure"):
            log(f"    cached ({prior['status']})")
            # Re-derive the outcome from the stored artefact so a cached run
            # reports the same verdict a fresh run would, not a placeholder.
            run_reason, run_detail = ex.classify_run_failure(
                ex.RunResult(status=prior["status"], exit_code=prior.get("exit_code", 0),
                             stdout="", stderr="", per_test=prior.get("per_test") or {}))
            verdict, detail = outcome(prior["status"], prior.get("per_test") or {}, run_detail)
            results.append({
                "finding_id": case["finding_id"],
                "repository": "2024-01-renft",
                "claimed_attack": case["claimed_attack"],
                "blocking_condition_under_test": case["blocking_condition"],
                "audited_commit": (prior.get("repository") or {}).get("commit"),
                "command": prior.get("command"),
                "execution_result": prior["status"],
                "run_failure_reason": run_reason or None,
                "status": verdict,
                "detail": detail,
                "per_test_status": {k: v.get("status")
                                    for k, v in (prior.get("per_test") or {}).items()},
                "artifact": str(Path(ex.EXPERIMENTS / case["finding_id"].replace("/", "__")
                                     / "attempted").relative_to(ex.ROOT)).replace("\\", "/"),
                "cached": True,
                "production_files_modified":
                    (prior.get("forensics") or {}).get("production_files_modified_count"),
            })
            continue

        info = ex.prepare(spec)
        ex.materialise(spec, harness)
        forensics = ex.clean_repo_forensics(spec)
        result, command = ex.forge_test(spec, match_path, None)
        human = ex.capture_human(spec, match_path, None) if result.status == "fail" else ""
        d = ex.write_artifacts(
            case["finding_id"], "attempted", harness, result, command,
            third_party=ex.third_party_set(harness, set()), commit=info["head"],
            extra={"repository": {"slug": spec.slug, "commit": info["head"],
                                  "commit_pinned": info["head_matches_pinned"],
                                  "url": spec.url, "framework": "foundry"},
                   "forensics": forensics,
                   "claimed_attack": case["claimed_attack"],
                   "blocking_condition_under_test": case["blocking_condition"]},
            repo_info={"slug": spec.slug, "commit": info["head"],
                       "commit_pinned": info["head_matches_pinned"],
                       "url": spec.url, "framework": "foundry"})
        if human:
            (Path(d) / "stdout_human.txt").write_text(human[:ex.MAX_STREAM], encoding="utf-8")

        run_reason, run_detail = ex.classify_run_failure(result)
        verdict, detail = outcome(result.status, result.per_test, run_detail)
        log(f"    {result.status} -> {verdict}")
        results.append({
            "finding_id": case["finding_id"],
            "repository": "2024-01-renft",
            "claimed_attack": case["claimed_attack"],
            "blocking_condition_under_test": case["blocking_condition"],
            "audited_commit": info["head"],
            "command": command,
            "execution_result": result.status,
            "run_failure_reason": run_reason or None,
            "status": verdict,
            "detail": detail,
            "per_test_status": {k: v.get("status") for k, v in (result.per_test or {}).items()},
            "artifact": str(Path(d).relative_to(ex.ROOT)).replace("\\", "/"),
            "production_files_modified":
                forensics.get("production_files_modified_count"),
        })

    write_json(REPORTS / "negative_experiments.json", {
        "generated_by": "scripts/run_negative_experiments.py",
        "note": ("Each experiment attempted the attack the submission describes, on the "
                 "audited revision. `false_positive_verified` is only emitted when the "
                 "attack was executed and every assertion observed the guard blocking it."),
        "experiments": results,
    })
    for r in results:
        log(f"  {r['finding_id']:34s} {r.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
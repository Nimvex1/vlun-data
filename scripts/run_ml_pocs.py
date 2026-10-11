#!/usr/bin/env python3
"""Execute the audit reports' own PoCs and keep the run artefacts.

The five v2.2 source reports each ship runnable tests. A report claiming "PoC
passes" is a `reported_claim`; only a run we actually performed, with its
stdout, stderr, exit code and toolchain versions on disk, is
`experimentally_verified`. This script is what turns the first into the second.

    python scripts/run_ml_pocs.py            # run every declared PoC
    python scripts/run_ml_pocs.py --only kerf
    python scripts/run_ml_pocs.py --list

Artefacts go to experiments_v2_2/<id>/ :
    result.json   command, rc, seconds, toolchain, parsed test counts, hashes
    stdout.txt    captured stdout
    stderr.txt    captured stderr

The target repositories live outside this checkout (they are the audited code,
not part of the dataset), so they are never written to beyond what `forge` needs
to build: their out/ and cache/ directories. Nothing in this repository's
jsonl/, derived/ or datasets/ is touched by a run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import ROOT, log  # noqa: E402
from vlun_io import sha256_file  # noqa: E402  (shared hash primitive; was a local copy)

OUT = ROOT / "experiments_v2_2"


def vyper_python(tag: str) -> Path | None:
    """Interpreter of the vyper version pinned for `tag`, if it is installed."""
    try:
        from run_vyper_poc import venv_python
        return venv_python(tag)
    except Exception:
        return None

# The audited repositories, outside this checkout. Absolute on purpose: these
# are the machine's copies of third-party code, not dataset content. Each is
# overridable via VLUN_<NAME> so another machine can point at its own copies;
# a missing path degrades to an explicit not_run/source_unavailable, never a
# silent skip.
def _ext(env: str, default: str) -> Path:
    return Path(os.environ.get(env, default))


ZENTORY_A = _ext("VLUN_ZENTORY_MODE_A_REPO",
                 r"C:\Users\jeet\Documents\zentory-protocol-main\zentory-protocol-main\contracts")
ZENTORY_B = _ext("VLUN_ZENTORY_SELF_REPO",
                 r"C:\Users\jeet\Downloads\zentory-protocol-main\zentory-protocol-main\contracts")
KERF = _ext("VLUN_KERF_REPO",
            r"C:\Users\jeet\Downloads\kerf-contracts-main\kerf-contracts-main")
QUANTILLON = _ext("VLUN_QUANTILLON_REPO",
                  r"C:\Users\jeet\Downloads\smart-contracts-main\smart-contracts-main\quantillon-protocol")

# (id, repo, cwd-relative, argv, source report, what it proves, expectation)
# `expect` is what the report itself predicts, so a run is judged against the
# claim rather than against "exit code 0". Two of these tests are *written to
# fail* on the vulnerable tree: they assert the correct invariant, so a green run
# would mean the bug was fixed and the report's claim is no longer reproducible.
SPECS = [
    ("zentory-modea-accountingl2", ZENTORY_A, ".",
     ["forge", "test", "--match-path", "test/audit/AccountingL2PoC.t.sol", "-vv"],
     "zentory-mode-a",
     "the five accounting/governance PoCs of report A",
     {"all_pass": True, "min_tests": 5}),
    ("zentory-modea-auditpoc", ZENTORY_A, ".",
     ["forge", "test", "--match-path", "test/audit/AuditPoc.t.sol", "-vv"],
     "zentory-mode-a",
     "report A: 1 pass, 1 FAIL on the current tree (the live H-3 bug)",
     {"fail": ["test_totalVeSupply_notDecrementedOnFullDecay_withdraw"],
      "pass": ["test_cancelSubscription_revertsBecauseVaultHoldsNoFunds"]}),
    ("zentory-contractaudit-supply", ZENTORY_A, ".",
     ["forge", "test", "--match-test",
      "test_totalVeSupply_notDecrementedOnFullDecay_withdraw", "-vv"],
     "zentory-contracts-audit",
     "H2 totalVeSupply not decremented on full decay (expected to fail today)",
     {"fail": ["test_totalVeSupply_notDecrementedOnFullDecay_withdraw"],
      "min_tests": 1}),
    ("zentory-contractaudit-cancel", ZENTORY_A, ".",
     ["forge", "test", "--match-test",
      "test_cancelSubscription_revertsBecauseVaultHoldsNoFunds", "-vv"],
     "zentory-contracts-audit",
     "H3 cancelSubscription always reverts (the test asserts the revert)",
     {"all_pass": True, "min_tests": 1}),
    ("zentory-selfaudit-auditpocs", ZENTORY_B, ".",
     ["forge", "test", "--match-path", "test/Audit*", "-vv"],
     "zentory-self-audit",
     "the self-audit's 24 Solidity PoCs",
     {"all_pass": True, "min_tests": 24}),
    ("zentory-selfaudit-findingspoc", ZENTORY_B, ".",
     ["forge", "test", "--match-path", "test/FindingsPoc.t.sol", "-vv"],
     "zentory-self-audit",
     "the self-audit's original 7 finding PoCs",
     {"all_pass": True, "min_tests": 7}),
    ("zentory-selfaudit-airdrop-node", ZENTORY_B, ".",
     ["node", "test/AuditAirdropSnapshotPoc.mjs"],
     "zentory-self-audit",
     "M-09 off-chain airdrop snapshot model",
     {"all_pass": True, "min_tests": 0}),
    ("kerf-auditpoc", KERF, ".",
     ["forge", "test", "--match-path", "test/AuditPoc.t.sol", "-vv"],
     "kerf-report",
     "Kerf's four findings, seven PoC tests",
     {"all_pass": True, "min_tests": 7}),
    ("quantillon-emergencyunstake", QUANTILLON, ".",
     ["forge", "test", "--match-contract", "EmergencyUnstakeRecipientPoC",
      "--match-test", "PoC", "-vv"],
     "quantillon-report",
     "H-1 emergencyUnstake pays an arbitrary recipient, plus its control",
     {"all_pass": True, "min_tests": 2}),
    # Vyper: compile-time and executable differential experiments. The PoC
    # sources live in this checkout (experiments_v2_2/pocs/vyper), each written
    # from a published advisory's claim, so cwd here is the dataset root rather
    # than one of the audited trees.
    ("vyper-optimizer-ternary", ROOT, ".",
     [sys.executable, "scripts/run_vyper_poc.py", "--id", "optimizer_ternary"],
     "vyper-GHSA-6j9c-gvcw-74fj",
     "the optimizer folds `msg.value | 2` to 1: IR differential plus a deployed "
     "call returning 1 at -O gas and 7 at -O none",
     {"min_tests": 0,
      "stdout_contains": [
          "CHECK pass ir_v0.3.10_optimize_gas_folds_msg_value_or_2_to_1",
          "CHECK pass ir_v0.3.10_optimize_none_keeps_the_callvalue_expression",
          "CHECK pass runtime_optimize_gas_calc_true_with_value_5_returns_1",
          "CHECK pass runtime_optimize_none_calc_true_with_value_5_returns_7"],
      "stdout_not_contains": ["CHECK fail"]}),
    ("vyper-rawcall-value", ROOT, ".",
     [sys.executable, "scripts/run_vyper_poc.py", "--id", "rawcall_value"],
     "vyper-GHSA-x2c2-q32w-4w6m",
     "value= on a delegate call: accepted by 0.3.10, rejected by 0.4.0, with a "
     "control that compiles on both",
     {"min_tests": 0,
      "stdout_contains": [
          "CHECK pass vulnerable_compiler_accepts_value_kwarg_on_a_delegate_call",
          "CHECK pass vulnerable_compiler_also_accepts_the_control_without_value",
          "CHECK pass patched_compiler_rejects_value_kwarg_on_a_delegate_call",
          "CHECK pass patched_compiler_still_accepts_the_control_without_value"],
      "stdout_not_contains": ["CHECK fail"]}),
    # Move: the Cetus CLMM incident's root cause, IntegerMate's
    # math_u256::checked_shlw, as a three-revision differential -
    # the audited mask era, the insufficient PR #6 fix, and the
    # merged PR #7 fix. The PoC module is tracked in this checkout
    # (experiments_v2_2/pocs/move) and installed into each
    # revision's worktree by the runner, so cwd is the dataset root
    # rather than one of the audited trees.
    ("move-cetus-checked-shlw", ROOT, ".",
     [sys.executable, "scripts/run_move_poc.py", "--id",
      "cetus_checked_shlw"],
     "move:cetus-checked-shlw",
     "checked_shlw silently truncates a product of exactly 2^192 on "
     "the audited revision and on the insufficient PR #6 revision, "
     "and reports overflow on the PR #7 fix, with a below-boundary "
     "control passing on all three",
     {"min_tests": 0,
      "stdout_contains": [
          "CHECK pass mask_era_4d09c8b_checked_out_revision",
          "CHECK pass mask_era_4d09c8b_control_shifts_below_2pow192",
          "CHECK pass mask_era_4d09c8b_boundary_2pow192_shifts_silently",
          "CHECK pass pr6_era_fc84a51_checked_out_revision",
          "CHECK pass pr6_era_fc84a51_control_shifts_below_2pow192",
          "CHECK pass pr6_era_fc84a51_boundary_2pow192_shifts_silently",
          "CHECK pass pr7_fix_06660f7_checked_out_revision",
          "CHECK pass pr7_fix_06660f7_control_shifts_below_2pow192",
          "CHECK pass pr7_fix_06660f7_boundary_2pow192_reports_overflow"],
      "stdout_not_contains": ["CHECK fail"]}),
]

# forge 1.8.3's final line is either
#   "Ran 4 test suites in 132ms (400ms CPU time): 7 tests passed, 0 failed, 0 skipped (7 total tests)"
# or, with no suites matched, "No tests found". The word "tests" sits between
# the count and "passed", which an earlier regex missed.
RE_TEST_SUMMARY = re.compile(
    r"(\d+) tests? passed, (\d+) failed, (\d+) skipped")
RE_TEST_SUMMARY_2 = re.compile(
    r"Tests:\s+(\d+) passed, (\d+) failed, (\d+) skipped")
RE_PASS = re.compile(r"^\[PASS\]\s+(\S+)", re.M)
RE_FAIL = re.compile(r"^\[FAIL(?:ure)?[^\]]*\]\s*(\S+)", re.M)


def _first_lines(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                           errors="replace")
        t = (p.stdout or "") + (p.stderr or "")
        return " ".join(t.strip().splitlines()[:2])[:300]
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def tool_versions(argv: list[str]) -> dict:
    out = {}
    # The Vyper differentials compile the same file with two interpreters and
    # deploy it on a local anvil node, so what matters is those versions rather
    # than the interpreter that happens to drive the run.
    if any(str(a).endswith("run_vyper_poc.py") for a in argv):
        for tag in ("0.3.10", "0.4.0"):
            py = vyper_python(tag)
            if py is None:
                out[f"vyper {tag}"] = "unavailable"
                continue
            out[f"vyper {tag}"] = _first_lines([str(py), "-m", "vyper",
                                                "--version"])
        out["anvil"] = _first_lines(["anvil", "--version"])
        out["cast"] = _first_lines(["cast", "--version"])
        return out
    # The Move differential is compiled and run by two sui releases:
    # the era-matching 1.6.3 for the audited revision (its Move.toml
    # pins framework mainnet-v1.6.3, which the 1.48.2 compiler
    # rejects) and 1.48.2 for the two revisions that pin 1.48.2.
    if any(str(a).endswith("run_move_poc.py") for a in argv):
        sui_148 = ROOT / "work" / "toolchains" / "sui.exe"
        sui_163 = (ROOT / "work" / "toolchains-1.6.3" / "target"
                   / "release" / "sui-windows-x86_64.exe")
        out["sui 1.48.2"] = (_first_lines([str(sui_148), "--version"])
                               if sui_148.exists() else "unavailable")
        out["sui 1.6.3"] = (_first_lines([str(sui_163), "--version"])
                              if sui_163.exists() else "unavailable")
        return out
    exe = argv[0]
    for name, cmd in (("forge", ["forge", "--version"]),
                      ("solc", ["solc", "--version"]),
                      ("node", ["node", "--version"]),
                      ("vyper", ["vyper", "--version"])):
        if exe != name and name not in ("solc",):
            continue
        out[name] = _first_lines(cmd)
    return out


def parse_result(stdout: str, stderr: str, rc: int) -> dict:
    """Summary counts plus the individual test names forge printed.

    `failing_tests` is load-bearing: a report that predicts "1 pass, 1 fail on
    the unpatched tree" is only confirmed if the *named* test is the one that
    failed, not merely that some test failed.
    """
    text = stdout + "\n" + stderr
    m = RE_TEST_SUMMARY.search(text) or RE_TEST_SUMMARY_2.search(text)
    counts = None
    if m:
        counts = {"passed": int(m.group(1)), "failed": int(m.group(2)),
                  "skipped": int(m.group(3))}
    passes = sorted(set(RE_PASS.findall(stdout)))
    fails = sorted(set(RE_FAIL.findall(stdout)))
    # forge prints [FAIL(...)] with the reason in the bracket; normalise to the
    # test name so a reader can compare it against the report's prediction.
    fails = [f.split("(")[0].strip() for f in fails]
    return {
        "exit_code": rc,
        "test_counts": counts,
        "passing_tests": passes,
        "failing_tests": fails,
        "failing_test_count": len(fails),
        "assertion_stdout_captured": bool(stdout.strip()),
    }


def judge(parsed: dict, expect: dict, text: str = "") -> dict:
    """Compare a run against the claim the report makes about it.

    A raw exit code is not the verdict. Two of these tests assert the *correct*
    invariant on a tree where it does not hold, so they are supposed to fail:
    if they passed, the bug would be fixed and the report would no longer be
    reproducible. The claim is what gets tested.

    For runs that are not forge test suites (the Vyper compiler differentials)
    the claim is expressed as substrings the output must or must not contain.
    """
    counts = parsed.get("test_counts") or {"passed": 0, "failed": 0, "skipped": 0}
    passing = [p.rstrip("()") for p in parsed.get("passing_tests") or []]
    failures = []
    min_tests = expect.get("min_tests")
    if min_tests:
        ran = counts["passed"] + counts["failed"]
        if ran < min_tests:
            failures.append(f"ran {ran} test(s); the report declares {min_tests}")
    if expect.get("all_pass") and counts["failed"]:
        failures.append(f"{counts['failed']} test(s) failed but every one was "
                        f"expected to pass")
    if not parsed.get("assertion_stdout_captured") and min_tests != 0:
        failures.append("no stdout captured, so no assertion could be observed")
    for name in expect.get("fail") or []:
        if name not in (parsed.get("failing_tests") or []):
            failures.append(f"expected {name} to fail; it did not fail")
    for name in expect.get("pass") or []:
        if name not in passing:
            failures.append(f"expected {name} to pass; it did not pass")
    for needle in expect.get("stdout_contains") or []:
        if needle not in text:
            failures.append(f"expected the output to contain: {needle!r}")
    for needle in expect.get("stdout_not_contains") or []:
        if needle in text:
            failures.append(f"expected the output not to contain: {needle!r}")
    if "exit_code" in expect and parsed.get("exit_code") != expect["exit_code"]:
        failures.append(f"expected exit code {expect['exit_code']}, got "
                        f"{parsed.get('exit_code')}")
    return {"declared": expect, "met": not failures, "violations": failures}


def run_one(spec, timeout: int) -> dict:
    sid, repo, cwd, argv, report, desc, expect = spec
    work = repo / cwd
    d = OUT / sid
    d.mkdir(parents=True, exist_ok=True)
    log(f"\n=== {sid}")
    log(f"    {argv[0]} {' '.join(argv[1:])}")
    log(f"    cwd: {work}")
    if not work.exists():
        result = {"experiment_id": sid, "status": "not_run",
                  "failure_reason": "source_unavailable",
                  "detail": f"repository path missing: {work}"}
        (d / "result.json").write_text(json.dumps(result, indent=2) + "\n",
                                       encoding="utf-8")
        log("    -> not_run (repository missing)")
        return result
    t0 = time.time()
    try:
        p = subprocess.run(argv, cwd=str(work), capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        rc, out, err, timed_out = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as exc:
        rc, out, err, timed_out = 124, (exc.stdout or ""), \
            (exc.stderr or "") + f"\ntimeout after {timeout}s", True
    except FileNotFoundError as exc:
        rc, out, err, timed_out = 127, "", str(exc), False
    secs = round(time.time() - t0, 1)

    (d / "stdout.txt").write_text(out, encoding="utf-8")
    (d / "stderr.txt").write_text(err, encoding="utf-8")
    parsed = parse_result(out, err, rc)
    verdict = judge(parsed, expect, out + "\n" + err)
    if timed_out:
        status = "timeout"
    elif rc == 127:
        status = "tool_missing"
    elif not verdict["met"]:
        status = "claim_mismatch"
    else:
        status = "ok"

    result = {
        "experiment_id": sid,
        "source_report": report,
        "description": desc,
        "status": status,
        "expectation": verdict,
        "command": " ".join(argv),
        "argv": argv,
        "cwd": "<repo>",
        "timeout_seconds": timeout,
        "seconds": secs,
        "toolchain": tool_versions(argv),
        **parsed,
        "artefacts": {},
    }
    for name in ("stdout.txt", "stderr.txt"):
        f = d / name
        if f.exists():
            result["artefacts"][name] = {
                "sha256": sha256_file(f),
                "bytes": f.stat().st_size,
            }
    (d / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    counts = result["test_counts"]
    summary = (f"{counts['passed']} passed, {counts['failed']} failed, "
               f"{counts['skipped']} skipped") if counts else f"rc={rc}"
    log(f"    -> {status} ({secs}s) {summary}")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="substring filter on the experiment id")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    if args.list:
        for s in SPECS:
            log(f"{s[0]:36} {s[3][0]:6} {s[4]}")
        return 0

    specs = [s for s in SPECS if not args.only or args.only in s[0]]
    if not specs:
        log("no experiment matched")
        return 1

    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for spec in specs:
        results.append(run_one(spec, args.timeout))

    # A filtered run must not shrink the index: the runs that were not repeated
    # are still on disk, and their artefacts are what the dataset points at.
    if len(specs) < len(SPECS):
        order = {s[0]: i for i, s in enumerate(SPECS)}
        recorded = {}
        for r in results:
            recorded[r["experiment_id"]] = r
        for spec in SPECS:
            if spec[0] in recorded:
                continue
            f = OUT / spec[0] / "result.json"
            if f.exists():
                recorded[spec[0]] = json.loads(f.read_text(encoding="utf-8"))
        results = sorted(recorded.values(), key=lambda r: order[r["experiment_id"]])

    index = {
        "generated_by": "scripts/run_ml_pocs.py",
        "experiments": results,
        "totals": {
            "declared": len(results),
            "ok": sum(1 for r in results if r["status"] == "ok"),
            "failed": sum(1 for r in results if r["status"] == "failed"),
            "other": sum(1 for r in results
                         if r["status"] not in ("ok", "failed")),
            "tests_passed": sum((r.get("test_counts") or {}).get("passed", 0)
                                for r in results),
            "tests_failed": sum((r.get("test_counts") or {}).get("failed", 0)
                                for r in results),
        },
    }
    (OUT / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    log("\ntotals: " + json.dumps(index["totals"]))
    log(f"wrote {OUT / 'index.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

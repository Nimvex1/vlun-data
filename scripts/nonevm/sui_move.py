"""Sui Move adapter: `sui move test` against pinned upstream revisions.

Platform: Sui Move.  Native runner: the pinned Sui CLI in `work/tools`.
Every revision is a read-only shared clone under `work/repos/`; this adapter
copies the package into an isolated scratch tree, writes its own `#[test]`
module there, and runs the platform's native test command against a single
named test.  Nothing is published or executed on a chain: `sui move test`
compiles to Move bytecode and runs in the local Move VM only - no gateway,
no faucet, no objects, no funds.

The candidate is `move:cetus-checked-shlw` (integer-mate `math_u256::checked_shlw`,
the root cause of the 2025-05-22 Cetus CLMM incident).  Three pinned
revisions are available locally:

    mask_era_4d09c8b  IntegerMate v1.1.0  audited/exploited  (sui 1.6.3 era)
    pr6_era_fc84a51   IntegerMate v1.1.1  incomplete PR #6 fix
    pr7_fix_06660f7   IntegerMate v1.1.2  merged PR #7 fix

The overflow check reads `if (n > mask)`.  On v1.1.0 `mask` was
`0xffffffffffffffff << 192`, so any product below 2^256 - 2^192 - including
2^192 itself and 3*2^192 - passed the check and was shifted left by 64,
discarding the result.  PR #6 corrected the mask to `1 << 192` but kept the
strict `>`, which still lets exactly 2^192 through; PR #7 changed it to `>=`.
Each revision is therefore run against three named assertions whose
expectations differ, which is what makes the differential non-vacuous.
"""
from __future__ import annotations

import re
from pathlib import Path

import common as C

PLATFORM = "sui_move"

ROOT = C.ROOT
SUI_148 = ROOT / "work" / "tools" / "sui-1.48.2" / "sui.exe"
SUI_163 = ROOT / "work" / "toolchains-1.6.3" / "target" / "release" / \
    "sui-windows-x86_64.exe"

POC_MODULE = '''#[test_only]
module integer_mate::nonevm_shlw_poc {
    use integer_mate::math_u256;

    /// Non-vacuity control: strictly below 2^192 shifts correctly on every
    /// revision.  If this fails, the two cells below prove nothing.
    #[test]
    fun nonevm_control_below_boundary_shifts_correctly() {
        let (r, oob) = math_u256::checked_shlw(0xffffffffffffffffffffffffffffffffffffffffffffffff);
        assert!(r == 0xffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000, 101);
        assert!(!oob, 102);
    }

    /// The published violation: a product of exactly 2^192 passes the
    /// `n > mask` check, is shifted, and its top bits are discarded (r == 0,
    /// oob == false).  Expected to PASS on v1.1.0 and v1.1.1, FAIL on v1.1.2.
    #[test]
    fun nonevm_boundary_exactly_2pow192_truncates_to_zero() {
        let (r, oob) = math_u256::checked_shlw(0x1000000000000000000000000000000000000000000000000);
        assert!(r == 0, 103);
        assert!(!oob, 104);
    }

    /// The same truncation one step above the boundary (3 * 2^192).  It
    /// separates v1.1.0 from v1.1.1: the corrected mask catches this value,
    /// so this cell is expected to PASS only on the audited v1.1.0.
    #[test]
    fun nonevm_above_boundary_3x2pow192_truncates_to_zero() {
        let (r, oob) = math_u256::checked_shlw(0x3000000000000000000000000000000000000000000000000);
        assert!(r == 0, 105);
        assert!(!oob, 106);
    }
}
'''

RE_PASS = re.compile(r"^\[\s*PASS\s*\]\s+(\S+)$", re.M)
RE_FAIL = re.compile(r"^\[\s*FAIL\s*\]\s+(\S+)$", re.M)
RE_SUMMARY = re.compile(r"Test result:\s*(\S+)\.\s*Total tests:\s*(\d+);"
                        r"\s*passed:\s*(\d+);\s*failed:\s*(\d+)", re.M)

REVISIONS = [
    {"label": "mask_era_4d09c8b", "worktree": ROOT / "work" / "repos" / "im-mask",
     "commit": "4d09c8ba0527274983c6664a5d5def2e784d4692", "sui": SUI_163,
     "era": "IntegerMate v1.1.0, the audited and exploited revision",
     "expected": {
         "nonevm_control_below_boundary_shifts_correctly": "PASS",
         "nonevm_boundary_exactly_2pow192_truncates_to_zero": "PASS",
         "nonevm_above_boundary_3x2pow192_truncates_to_zero": "PASS"},
     "claim_cell": {"nonevm_boundary_exactly_2pow192_truncates_to_zero",
                    "nonevm_above_boundary_3x2pow192_truncates_to_zero"}},
    {"label": "pr6_era_fc84a51", "worktree": ROOT / "work" / "repos" / "im-boundary",
     "commit": "fc84a51c29fabfbfbdb8ed76506b61a07493d492", "sui": SUI_148,
     "era": "IntegerMate v1.1.1, the incomplete PR #6 fix",
     "expected": {
         "nonevm_control_below_boundary_shifts_correctly": "PASS",
         "nonevm_boundary_exactly_2pow192_truncates_to_zero": "PASS",
         "nonevm_above_boundary_3x2pow192_truncates_to_zero": "FAIL"},
     "claim_cell": {"nonevm_boundary_exactly_2pow192_truncates_to_zero"}},
    {"label": "pr7_fix_06660f7", "worktree": ROOT / "work" / "repos" / "im-fixed",
     "commit": "06660f704c4ac1d443ab62346a46b5b60d49df33", "sui": SUI_148,
     "era": "IntegerMate v1.1.2, the merged PR #7 fix",
     "expected": {
         "nonevm_control_below_boundary_shifts_correctly": "PASS",
         "nonevm_boundary_exactly_2pow192_truncates_to_zero": "FAIL",
         "nonevm_above_boundary_3x2pow192_truncates_to_zero": "FAIL"},
     "claim_cell": set()},
]

BLOCKERS = {
    "move:zellic-3.1-usable-value-drop":
        "native_runner_not_applicable_and_build_time_exceeds_budget: the fix "
        "is in MystenLabs/sui crates/sui-adapter (Rust full node); a scoped "
        "`cargo test` needs the whole Sui workspace build",
    "move:zellic-3.2-control-flow-graph":
        "build_time_exceeds_budget: the vulnerable CFG construction lives in "
        "move-language/move's bytecode verifier (Rust); the era-matching "
        "commits are pinned but the workspace build exceeds the per-run budget",
    "move:CVE-2023-42374":
        "native_runner_not_applicable: a crafted compressed script must be "
        "sent to a running Sui node; that needs a built sui-node binary plus a "
        "localnet, which exceeds this pilot's per-run budget",
    "move:CVE-2023-36184":
        "native_runner_not_applicable: the crash is reached through the JSON-"
        "RPC deserializer of a running node, not through `sui move test`",
    "move:navi-pool-01-withdraw-permission":
        "dependency_resolution_uncached_sui_framework_rev: the audited Navi "
        "package pins a Sui framework revision that is not in the local git "
        "dependency cache, so resolving it means a full MystenLabs/sui clone",
    "move:navi-lend-06-coin-type":
        "dependency_resolution_uncached_sui_framework_rev: same audited "
        "repository and same uncached framework pin as POOL-01",
    "move:sui-amm-6.7-zero-liquidity":
        "revision_unresolved: the report's Received Commit line is a 39-hex "
        "value with no leading 0x and is not resolvable, and the framework pin "
        "is not cached",
    "move:volo-os-vol-adv-00-roundupshares":
        "dependency_resolution_uncached_sui_framework_rev: the Volo package "
        "pins an OtterSec-era Sui framework rev absent from the local cache",
}

CLAIM = ("integer-mate math_u256::checked_shlw truncated a 320-bit product "
         "silently, letting unbacked liquidity be minted (Cetus CLMM "
         "post-incident analyses; integer-mate PR #7)")


def prerequisites() -> list[dict]:
    rows = []
    for path, label in ((SUI_148, "sui 1.48.2 (era-matching for v1.1.1/v1.1.2)"),
                        (SUI_163, "sui 1.6.3 (era-matching for v1.1.0)")):
        ok = path.exists()
        rows.append({
            "tool": f"sui cli: {label}", "path": str(path),
            "install_status": "installed" if ok else "missing",
            "version": C.tool_version([str(path), "--version"]) if ok else None,
            "install_command": None if ok else
            "cargo install --git https://github.com/MystenLabs/sui --rev <rev> sui "
            "(or the release archive for the matching tag)"})
    rows.append({
        "tool": "move git dependency cache (~/.move)",
        "install_status": "installed" if Path.home().joinpath(".move").exists()
        else "missing", "version": None,
        "install_command": "created on first `sui move` run that resolves a git "
                           "dependency"})
    return rows


def toolchain() -> dict:
    return {"tool": "sui", "native_command": "sui move test <test name>",
            "version_1_48_2": C.tool_version([str(SUI_148), "--version"]),
            "version_1_6_3": C.tool_version([str(SUI_163), "--version"])
            if SUI_163.exists() else "missing"}


def licence() -> dict:
    return {"upstream": "MIT (CetusProtocol/integer-mate)",
            "harness_origin": "the #[test] module is written by this adapter "
                              "and is not copied from upstream",
            "redistribution": "the audited package sources stay in the local "
                              "scratch copy; no upstream file is copied into a "
                              "distribution artefact",
            "withheld": None}


def plan(records: list[dict]) -> tuple[list[dict], list[dict]]:
    pool = {c["record_id"]: c for c in C.candidates_for(PLATFORM, records)}
    specs, blocked = [], []
    cand = pool.get("move:cetus-checked-shlw")
    if cand:
        for rev in REVISIONS:
            for test, expect in rev["expected"].items():
                specs.append({
                    "platform": PLATFORM, "candidate": cand, "rev": rev,
                    "test": test, "expect": expect,
                    "is_claim_cell": test in rev["claim_cell"],
                    "run_slug": f"{rev['label']}-{test[len('nonevm_'):][:40]}"})
    for rid, reason in BLOCKERS.items():
        if rid in pool:
            blocked.append({"platform": PLATFORM, "candidate": pool[rid],
                            "blocker": reason, "run_slug": "blocked"})
    return specs, blocked


def _prepare(rev: dict, run_slug: str) -> tuple[Path | None, str | None, dict]:
    """Copy the pinned package into scratch; return (pkg, blocker, pin)."""
    head = C.git_rev_parse(rev["worktree"])
    pin = {"repo": "https://github.com/CetusProtocol/integer-mate",
           "requested_ref": rev["label"], "commit": head,
           "expected_commit": rev["commit"],
           "resolved_by": "git rev-parse on the local pinned worktree",
           "revision_unresolved": None}
    pkg_src = rev["worktree"] / "sui"
    if not pkg_src.is_dir():
        return None, f"package_dir_missing {pkg_src}", pin
    if head != rev["commit"]:
        return None, (f"pinned_revision_mismatch: worktree HEAD is {head}, "
                      f"the candidate names {rev['commit']}"), pin
    if not rev["sui"].exists():
        return None, (f"toolchain_missing: sui binary {rev['sui']} is not "
                      f"present (era-matching compiler for this revision)"), pin
    dest = C.ensure_scratch() / run_slug / "pkg"
    C.copy_tree(pkg_src, dest)
    stale = dest / "tests" / "checked_shlw_poc.move"
    if stale.exists():
        stale.unlink()          # only this adapter's own PoC module is run
    (dest / "tests").mkdir(parents=True, exist_ok=True)
    poc = dest / "tests" / "nonevm_shlw_poc.move"
    C.write_text(poc, POC_MODULE)
    pin["poc_sha256"] = C.sha256_file(poc)
    pin["package_manifest_sha256"] = C.sha256_file(dest / "Move.toml")
    return dest, None, pin


def execute(spec: dict) -> dict:
    cand, rev, test = spec["candidate"], spec["rev"], spec["test"]
    prereq = prerequisites()
    pkg, blocker, pin = _prepare(rev, spec["run_slug"])
    if blocker:
        return C.make_run(
            platform=PLATFORM, record_id=cand["record_id"],
            run_slug=spec["run_slug"], claim=CLAIM, status="blocked",
            outcome="blocked", ladder="L1", toolchain=toolchain(), pin=pin,
            assertion=None,
            run={"argv": [str(rev["sui"]), "move", "test", test],
                 "run_kind": "none", "isolation": "local scratch copy of the "
                 "pinned package; Move VM only, no chain"},
            prerequisites=prereq, licence=licence(), blocker=blocker,
            evidence_note="prerequisite failed before the native runner started")

    argv = [str(rev["sui"]), "move", "test", test]
    r = C.run_argv(argv, cwd=pkg, timeout=280)
    out = r["stdout"] + "\n" + r["stderr"]
    passed = {m.group(1).split("::")[-1] for m in RE_PASS.finditer(out)}
    failed = {m.group(1).split("::")[-1] for m in RE_FAIL.finditer(out)}
    summary = RE_SUMMARY.search(out)
    if test in passed:
        observed = "PASS"
    elif test in failed:
        observed = "FAIL"
    elif "error[E" in out or "Error: Package compilation" in out:
        observed = None
    else:
        observed = None

    if observed is None:
        compile_err = "error[E" in out
        return C.make_run(
            platform=PLATFORM, record_id=cand["record_id"],
            run_slug=spec["run_slug"], claim=CLAIM,
            status="compile_failed" if compile_err else "timeout",
            outcome="compile_failed" if compile_err else "inconclusive",
            ladder="L2", toolchain=toolchain(), pin=pin,
            assertion={"name": f"integer_mate::nonevm_shlw_poc::{test}",
                       "kind": "named_test", "expected": spec["expect"],
                       "observed": None, "met": None},
            run={"argv": argv, "cwd": str(pkg), "exit_code": r["exit_code"],
                 "seconds": r["seconds"], "timeout_seconds": 280,
                 "run_kind": "native_test",
                 "isolation": "local Move VM in an isolated scratch copy; no "
                              "chain, no funds"},
            prerequisites=prereq, licence=licence(),
            blocker=f"{'compile_failed' if compile_err else 'no_named_test_result'}"
                    f" exit={r['exit_code']}",
            stdout=r["stdout"], stderr=r["stderr"])

    met = observed == spec["expect"]
    if met and spec["is_claim_cell"]:
        outcome, ladder = "claim_reproduced", "L5"
    else:
        outcome, ladder = "executed_without_impact", "L4"
    assertion = {
        "name": f"integer_mate::nonevm_shlw_poc::{test}",
        "kind": "named_test",
        "statement": f"{rev['era']}: expected {spec['expect']} for the named "
                     f"test",
        "expected": {"test_status": spec["expect"],
                     "why": "v1.1.0/v1.1.1 keep the strict `n > mask` check; "
                            "v1.1.2 uses `n >= mask`"},
        "observed": {"test_status": observed,
                     "suite_summary": summary.group(0) if summary else None},
        "met": met, "not_just_exit_code": True,
    }
    note = (f"{rev['label']}: {test} observed {observed} (expected "
            f"{spec['expect']}). ")
    if met and spec["is_claim_cell"]:
        note += "The published truncation reproduces on this pinned revision."
    elif met and rev["label"] == "pr7_fix_06660f7":
        note += ("The fixed revision refuses the same call, so the violating "
                 "test is blocked there - the L6 shape when paired with the "
                 "vulnerable revision.")
    elif not met:
        note += "Expectation and observation differ; recorded as not reproduced."
    run = {"argv": argv, "cwd": str(pkg), "exit_code": r["exit_code"],
           "seconds": r["seconds"], "timeout_seconds": 280,
           "run_kind": "native_test",
           "isolation": "isolated scratch copy of the pinned package; local "
                        "Move VM only - no gateway, no faucet, no chain"}
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=spec["run_slug"], claim=CLAIM, status="executed",
        outcome=outcome, ladder=ladder, toolchain=toolchain(), pin=pin,
        assertion=assertion, run=run, prerequisites=prereq, licence=licence(),
        stdout=r["stdout"], stderr=r["stderr"], evidence_note=note)


def execute_blocked(row: dict) -> dict:
    cand = row["candidate"]
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=f"blocked-{cand['record_id'].split(':')[-1][:40]}",
        claim=cand["title"] or CLAIM, status="blocked", outcome="blocked",
        ladder="L1", toolchain=toolchain(),
        pin={"requested_ref": cand.get("affected_versions"), "commit": None,
             "revision_unresolved": row["blocker"]},
        assertion=None,
        run={"argv": [str(SUI_148), "move", "test"], "run_kind": "none",
             "isolation": "would be a local scratch copy plus the local Move VM"},
        prerequisites=prerequisites(), licence=licence(),
        blocker=row["blocker"],
        evidence_note="candidate in the v2.2 pool that this pilot could not "
                      "execute; the blocker text is the finding")

#!/usr/bin/env python3
"""Run the Move PoC differential of VLUN v2.2 and print observations.

One experiment: the Cetus CLMM incident of 2025-05-22, whose root cause
is IntegerMate's `math_u256::checked_shlw`. The audited library checked
`n > mask` with `mask = 0xffffffffffffffff << 192`, so a product of
exactly 2^192 passed the check and was shifted, silently discarding the
result's top bits. The same test module is run against three revisions
of the audited repository:

  mask_era_4d09c8b   IntegerMate v1.1.0 - the audited, exploited code
                     (`0xffffffffffffffff << 192`, `n > mask`)
  pr6_era_fc84a51    v1.1.1, PR #6 - mask corrected to `1 << 192` but
                     the comparison is still `n > mask`, so the
                     boundary value still slips through
  pr7_fix_06660f7    v1.1.2, PR #7 - the comparison becomes `n >= mask`,
                     which stops the violation

The PoC asserts the *vulnerable* behaviour (n == 2^192 shifts silently),
so it passes on the two vulnerable revisions and aborts on the fix,
while a below-boundary control passes on all three - proving the
differential is not vacuous. That is the L6 shape: the violation
reproduces on the audited revision and stops on the fixed one.

Every observation is printed as `OBS name=value`; every assertion as
`CHECK pass name` / `CHECK fail name`. The caller (scripts/run_ml_pocs.py)
asserts on those lines rather than on an exit code, because these runs
are judged against the published claim.

The audited repository is third-party code and lives outside the
dataset's tracked files, under work/repos/im-*. The PoC module itself is
tracked (experiments_v2_2/pocs/move/checked_shlw_poc.move) and is copied
into each revision's tests/ directory before the run, so the tested code
is always the versioned one.

The mask-era package pins Sui framework mainnet-v1.6.3 in its Move.toml.
The 1.48.2 compiler cannot build that framework (it expects
std::unit_test::poison, which does not exist in the 1.6.3-era std), so
that revision is tested with the era-matching sui 1.6.3 compiler; the
other two pin mainnet-v1.48.2 and are tested with sui 1.48.2.

Exit codes: 0 assertions ran (check the CHECK lines), 127 an environment
requirement (a toolchain binary or a revision worktree) is unavailable.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun_io import sha256_file  # noqa: E402  (shared hash primitive; was a local copy)

ROOT = Path(__file__).resolve().parent.parent
POC = ROOT / "experiments_v2_2" / "pocs" / "move" / "checked_shlw_poc.move"

# (label, worktree, expected HEAD, era-matching compiler, what the
# revision is, and whether the boundary violation is expected to still
# reproduce there)
REVISIONS = [
    {
        "label": "mask_era_4d09c8b",
        "worktree": ROOT / "work" / "repos" / "im-mask",
        "sha": "4d09c8ba0527274983c6664a5d5def2e784d4692",
        "sui": ROOT / "work" / "toolchains-1.6.3" / "target" / "release"
               / "sui-windows-x86_64.exe",
        "era": "IntegerMate v1.1.0, the audited and exploited revision",
        "boundary_expected": "pass",
    },
    {
        "label": "pr6_era_fc84a51",
        "worktree": ROOT / "work" / "repos" / "im-boundary",
        "sha": "fc84a51c29fabfbfbdb8ed76506b61a07493d492",
        "sui": ROOT / "work" / "toolchains" / "sui.exe",
        "era": "IntegerMate v1.1.1, the incomplete PR #6 fix",
        "boundary_expected": "pass",
    },
    {
        "label": "pr7_fix_06660f7",
        "worktree": ROOT / "work" / "repos" / "im-fixed",
        "sha": "06660f704c4ac1d443ab62346a46b5b60d49df33",
        "sui": ROOT / "work" / "toolchains" / "sui.exe",
        "era": "IntegerMate v1.1.2, the merged PR #7 fix",
        "boundary_expected": "fail",
    },
]

CONTROL_TEST = "control_below_the_boundary_still_shifts"
BOUNDARY_TEST = "boundary_exactly_2_pow_192_shifts_silently"
POC_TESTS = (CONTROL_TEST, BOUNDARY_TEST)

RE_TESTLINE = re.compile(r"^\[\s*(PASS|FAIL)\s*\]\s+(.+?)\s*$", re.M)
RE_SUMMARY = re.compile(
    r"Test result:\s*(\S+)\.\s*Total tests:\s*(\d+);\s*passed:\s*(\d+);"
    r"\s*failed:\s*(\d+)")
RE_ABORT = re.compile(r"aborted with code (\d+)")
RE_MASK = re.compile(r"^\s*let mask = (.+?);\s*$", re.M)
RE_CMP = re.compile(r"^\s*if \(n\s*(>=|>)\s*mask\)\s*\{\s*$", re.M)

CHECKS: list[dict] = []


def obs(name: str, value) -> None:
    print(f"OBS {name}={value}", flush=True)


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail})
    tail = f" :: {detail}" if detail else ""
    print(f"CHECK {'pass' if ok else 'fail'} {name}{tail}", flush=True)


def unavailable(reason: str) -> "None":
    print(f"ERROR {reason}", flush=True)
    raise SystemExit(127)


def git_head(worktree: Path) -> str | None:
    try:
        p = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            capture_output=True, text=True, errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def first_line(argv: list[str]) -> str:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           errors="replace", timeout=60)
        return (p.stdout or p.stderr).strip().splitlines()[:1][0] \
            if (p.stdout or p.stderr).strip() else "no version output"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def run_revision(rev: dict) -> None:
    label = rev["label"]
    worktree = rev["worktree"]
    pkg = worktree / "sui"
    if not pkg.is_dir():
        unavailable(f"revision_worktree_missing {label} ({pkg})")
    if not rev["sui"].exists():
        unavailable(f"toolchain_missing {label} ({rev['sui']})")
    if not POC.exists():
        unavailable(f"poc_source_missing ({POC})")

    # Provenance: what is actually checked out, and which compiler builds it.
    head = git_head(worktree)
    obs(f"{label}_head", head or "unknown")
    check(f"{label}_checked_out_revision", head == rev["sha"],
          f"expected {rev['sha']}, worktree reports {head}")
    obs(f"{label}_toolchain", first_line([str(rev["sui"]), "--version"]))
    obs(f"{label}_era", rev["era"])

    # Code-grounded evidence: the comparison as it actually stands at
    # this revision, read from the worktree's own source.
    src = (pkg / "sources" / "math_u256.move").read_text(
        encoding="utf-8", errors="replace")
    m = RE_MASK.search(src)
    obs(f"{label}_src_mask", m.group(1).strip() if m else "not found")
    m = RE_CMP.search(src)
    obs(f"{label}_src_comparison", f"n {m.group(1)} mask" if m
        else "not found")

    # Install the tracked PoC so the tested code is the versioned code.
    dest = pkg / "tests" / "checked_shlw_poc.move"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(POC, dest)
    obs(f"{label}_poc_sha256", sha256_file(dest))

    try:
        p = subprocess.run(
            [str(rev["sui"]), "move", "test"], cwd=str(pkg),
            capture_output=True, text=True, errors="replace", timeout=900)
    except subprocess.TimeoutExpired:
        check(f"{label}_control_shifts_below_2pow192", False,
              "sui move test timed out after 900s")
        check(f"{label}_boundary_2pow192_shifts_silently", False,
              "sui move test timed out after 900s")
        return
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    obs(f"{label}_exit_code", p.returncode)

    passed: set[str] = set()
    failed: set[str] = set()
    for m in RE_TESTLINE.finditer(out):
        status, target = m.group(1), m.group(2)
        test = target.split("::")[-1]
        if test in POC_TESTS:
            (passed if status == "PASS" else failed).add(test)
            print(m.group(0), flush=True)
    s = RE_SUMMARY.search(out)
    obs(f"{label}_suite", s.group(0) if s else "no summary line printed")

    check(f"{label}_control_shifts_below_2pow192",
          CONTROL_TEST in passed,
          "control test did not pass; the differential would be vacuous")

    if rev["boundary_expected"] == "pass":
        check(f"{label}_boundary_2pow192_shifts_silently",
              BOUNDARY_TEST in passed,
              "the violation test did not pass on this vulnerable revision")
    else:
        check(f"{label}_boundary_2pow192_reports_overflow",
              BOUNDARY_TEST in failed,
              "the violation test did not fail on the fixed revision")
        aborts = RE_ABORT.findall(out)
        if aborts:
            obs(f"{label}_abort_code", aborts[0])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", default="cetus_checked_shlw",
                    help="experiment id, kept for SPECS uniformity")
    args = ap.parse_args()
    if args.id != "cetus_checked_shlw":
        print(f"ERROR unknown_experiment_id {args.id}", flush=True)
        return 127

    for rev in REVISIONS:
        print(f"\n=== {rev['label']}: {rev['era']}", flush=True)
        run_revision(rev)

    print(f"\n{len(CHECKS)} checks ran, "
          f"{sum(1 for c in CHECKS if c['ok'])} passed, "
          f"{sum(1 for c in CHECKS if not c['ok'])} failed", flush=True)
    # The verdict is in the CHECK lines, not the exit code: a run whose
    # checks failed is still a run, and run_ml_pocs.py judges it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

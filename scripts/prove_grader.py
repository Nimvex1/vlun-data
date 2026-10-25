#!/usr/bin/env python3
"""The VLUN-Prove grader: run one submitted test on both revisions, honestly.

Isolation contract, enforced in code:

  * the answer key (fixed revision + expected assertion) is read from a directory
    OUTSIDE the repository, passed in via `--home` or `VLUN_PRIVATE_HOME`;
  * every run writes its own artefact directory with the submission bytes, the
    exact command, the toolchain, stdout/stderr and their SHA-256, so a verdict
    can be re-checked after the fact;
  * a stage is credited only on the evidence named in
    `reports/prove_split_interface.json`.

The interesting function is `stage_ladder()`: it is pure, so the rules can be
tested without a toolchain. In particular a submission that fails to compile, or
whose test errors during setup, or whose failure assertion is not the expected
one, never reaches `impact_reproduced` — and never reaches `patch_verified`
unless the same bytes passed on the second revision.

`patch_verified` alone is not a fully effective patch: a fix that deletes or
disables the affected feature also blocks the exploit. `behaviour_preserved` is
therefore the top stage and needs a recorded fixed-revision regression run with a
vulnerable-revision baseline, no new failures, passing positive-path assertions,
and evidence that the feature still exists. The grader never runs (and never
invents) that suite itself: pass it with `--regression-evidence <json>`.

    python scripts/prove_grader.py --task-id prove-2024-01-renft__H-04 \
        --submission dir/with/test/files --out work/prove_runs/<id> [--home ...] \
        [--regression-evidence recorded_regression.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import ROOT, log  # noqa: E402

STAGES = ("generated", "compiles", "executes", "impact_reproduced", "patch_verified",
          "behaviour_preserved")
UNRELATED_REASONS = re.compile(
    r"compiler error|source not found|not found: |no tests ran|could not find|"
    r"old artifact|bad artifact|weird: cannot assign|tracing error|"
    r"insufficient funds|gas", re.I)

# A behaviour-preservation record must describe the project's own suite. A command
# that selects only the submitted PoC overlay proves the exploit is blocked; it
# says nothing about the rest of the project, so it may not be presented as a
# regression run.
SUBMISSION_ONLY_COMMAND = re.compile(r"test[/\\]vlun_poc", re.I)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
PASS_STATUSES = ("success", "pass", "passed")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_key(home: Path, task_id: str) -> dict:
    resolved = Path(home).resolve()
    root = ROOT.resolve()
    if resolved == root or root in resolved.parents:
        raise SystemExit(f"answer key must live outside the repository, got {resolved}")
    key = resolved / "vlun_prove" / "prove_tasks_private.jsonl"
    if not key.exists():
        raise SystemExit(f"no answer key at {key}; run scripts/build_prove_split.py first")
    for line in key.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("task_id") == task_id:
            return row
    raise SystemExit(f"task {task_id!r} is not in the private split")


def behaviour_verdict(regression: dict | None, expected: dict | None = None) -> tuple[bool, str]:
    """Decide whether the fix preserves the project's intended behaviour.

    `regression` is a recorded run, never a claim:

        {"baseline": {"revision": <vulnerable sha>, "test_command": str,
                      "test_artifact_sha256": <64-hex>, "failures": [test, ...]},
         "fixed":    {"revision": <fixed sha>, "test_command": str,
                      "test_artifact_sha256": <64-hex>, "failures": [test, ...],
                      "feature_present": bool, "disabled": bool,
                      "removed_symbols": [str, ...]},
         "positive_path": [{"name": str, "status": "Success"|"Failure"}, ...]}

    Refused when the baseline is absent, when the failures list is missing (a
    missing list is not a green suite), when the fixed revision adds a failure,
    when the two revisions did not run the same hash-pinned artifact, when the
    fixed revision is not the pinned fix, when the feature was removed/disabled,
    or when a targeted positive-path assertion did not pass. Returns
    (ok, reason).
    """
    if not isinstance(regression, dict) or not regression:
        return (False, "no behaviour-preservation run recorded: the project's existing "
                       "test suite was not executed on the fixed revision, so a blocked "
                       "exploit is the only evidence and the feature may be gone")
    if regression.get("available") is False:
        return (False, str(regression.get("reason")
                           or "behaviour-preservation evidence is not available"))
    baseline = regression.get("baseline")
    fixed = regression.get("fixed")
    if not isinstance(baseline, dict):
        return (False, "the vulnerable-revision baseline is missing: pre-existing "
                       "failures cannot be separated from regressions introduced by "
                       "the fix")
    if not isinstance(fixed, dict):
        return (False, "the fixed-revision regression run is missing")

    for label, run in (("baseline", baseline), ("fixed", fixed)):
        if not str(run.get("test_command") or "").strip():
            return (False, f"{label}: no test command was recorded")
        if SUBMISSION_ONLY_COMMAND.search(str(run.get("test_command") or "")):
            return (False, f"{label}: the command selects only the submitted PoC overlay "
                           "(test/vlun_poc); that is not the project's existing suite")
        if not _HEX64.match(str(run.get("test_artifact_sha256") or "")):
            return (False, f"{label}: the test artifact is not hash-pinned "
                           "(need a 64-hex sha256)")
        if "failures" not in run or not isinstance(run.get("failures"), list):
            return (False, f"{label}: the failures list was not recorded; an absent "
                           "baseline is not a green baseline")
        if not run.get("revision"):
            return (False, f"{label}: no pinned revision was recorded")

    if baseline.get("test_artifact_sha256") != fixed.get("test_artifact_sha256"):
        return (False, "the two revisions did not run the same hash-pinned test artifact")
    pinned = (expected or {}).get("fixed_revision")
    if pinned and fixed.get("revision") != pinned:
        return (False, f"fixed: the regression ran at {str(fixed.get('revision'))[:10]}, "
                       f"not the pinned fix {str(pinned)[:10]}")

    base_failures = {str(t) for t in baseline["failures"]}
    fixed_failures = {str(t) for t in fixed["failures"]}
    new_failures = sorted(fixed_failures - base_failures)
    if new_failures:
        return (False, "the fix introduced regression failures: "
                       + ", ".join(new_failures))

    if fixed.get("feature_present") is False or regression.get("feature_removed") is True:
        return (False, "the affected feature is absent from the fixed revision: blocking "
                       "the exploit by deleting the feature is not a fix")
    if fixed.get("disabled") is True:
        return (False, "the affected feature is recorded as disabled on the fixed revision")
    removed = [str(s) for s in (fixed.get("removed_symbols") or []) if s]
    if removed:
        return (False, "the fix removed the feature's symbols: " + ", ".join(removed))

    positive = regression.get("positive_path") or []
    if not positive:
        return (False, "no targeted positive-path assertion was recorded on the fixed "
                       "revision")
    failed_positive = [str((item or {}).get("name") or "<unnamed>") for item in positive
                       if str((item or {}).get("status") or "").lower() not in PASS_STATUSES]
    if failed_positive:
        return (False, "positive-path assertions did not pass on the fixed revision: "
                       + ", ".join(failed_positive))
    return (True, f"{len(fixed_failures)} failure(s) on the fixed revision, none new "
                  f"against a baseline of {len(base_failures)}; "
                  f"{len(positive)} positive-path assertion(s) passed")


def stage_ladder(submission: dict, vulnerable: dict, fixed: dict, expected: dict,
                 regression: dict | None = None) -> dict:
    """Decide the stages from recorded run evidence. Pure, so it is testable.

    `submission`: {"files": {path: bytes-hex-free text}, }
    `vulnerable`/`fixed`: {"build_rc": int, "dependency_ok": bool, "ran_tests": bool,
                           "per_test_status": {test: "Success"|"Failure"},
                           "signals": [{"test","forge_reason","assertion_messages"}]}
    `expected`: {"failing_tests": [...], "signals": [...], "security_property": str,
                 "fixed_revision": <optional pinned sha>}
    `regression`: the optional `behaviour_verdict()` record. Absent means the run
    stops at `patch_verified` and is not fully verified — never a guessed pass.
    """
    out = {s: False for s in STAGES}
    why: dict[str, str] = {}

    def verdict(stage: str) -> dict:
        return {"stages": out, "reasons": why, "stage_reached": stage,
                "fully_verified": out["behaviour_preserved"]}

    files = {k: v for k, v in (submission.get("files") or {}).items() if v.strip()}
    out["generated"] = bool(files)
    if not files:
        why["generated"] = "the submission contained no non-empty test file"
        return verdict("none")

    for label, run in (("vulnerable", vulnerable), ("fixed", fixed)):
        if run.get("build_rc") not in (0, None) or not run.get("dependency_ok", True):
            why["compiles"] = f"{label}: build rc={run.get('build_rc')}, " \
                              f"dependencies {run.get('dependency_ok')}"
            return verdict("generated")
    out["compiles"] = True

    if not (vulnerable.get("ran_tests") and vulnerable.get("per_test_status")):
        why["executes"] = "no test from the submission executed on the vulnerable revision"
        return verdict("compiles")
    out["executes"] = True

    want = set(expected.get("failing_tests") or [])
    got_fail = {t for t, s in (vulnerable.get("per_test_status") or {}).items()
                if s == "Failure"}
    matched = want & got_fail
    if not matched:
        why["impact_reproduced"] = (
            f"expected one of {sorted(want)} to fail on the vulnerable revision; "
            f"observed failures {sorted(got_fail) or 'none'}")
        return verdict("executes")

    sig = {s.get("test"): s for s in (vulnerable.get("signals") or [])}
    assertion_ok = False
    detail = ""
    for t in sorted(matched):
        observed = sig.get(t) or {}
        reason = (observed.get("forge_reason") or "")
        messages = " | ".join(observed.get("assertion_messages") or [])
        blob = f"{reason} {messages}"
        if UNRELATED_REASONS.search(blob or "") and not reason.startswith("assert"):
            detail = f"{t}: failure reason looks unrelated ({blob[:80]!r})"
            continue
        if not (reason or messages):
            detail = f"{t}: failed but recorded no assertion or revert reason"
            continue
        assertion_ok = True
        detail = f"{t}: {reason or messages[:120]}"
        break
    if not assertion_ok:
        why["impact_reproduced"] = detail
        return verdict("executes")
    out["impact_reproduced"] = True
    why["impact_reproduced"] = detail

    if not fixed.get("ran_tests"):
        why["patch_verified"] = "the second-revision run did not execute the test"
        return verdict("impact_reproduced")
    same = {t: s for t, s in (fixed.get("per_test_status") or {}).items() if t in matched}
    if not same or any(s != "Success" for s in same.values()):
        why["patch_verified"] = f"second revision did not block the same test: {same}"
        return verdict("impact_reproduced")
    out["patch_verified"] = True
    why["patch_verified"] = f"{sorted(same)} passed unmodified on the second revision"

    preserved, preservation_detail = behaviour_verdict(regression, expected)
    why["behaviour_preserved"] = preservation_detail
    if not preserved:
        return verdict("patch_verified")
    out["behaviour_preserved"] = True
    return verdict("behaviour_preserved")


def run_forge(worktree: Path, test_file: Path, match: str, timeout: int) -> dict:
    """Execute one submission file in an already-prepared worktree."""
    def _run(cmd):
        t0 = time.time()
        try:
            p = subprocess.run(cmd, cwd=str(worktree), capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            return p.returncode, p.stdout, p.stderr, time.time() - t0
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout}s", time.time() - t0
        except FileNotFoundError as exc:
            return 127, "", str(exc), time.time() - t0
    rc, out, err, build_s = _run(["forge", "build"])
    if rc != 0:
        return {"build_rc": rc, "dependency_ok": True, "ran_tests": False,
                "per_test_status": {}, "signals": [], "stdout": out, "stderr": err,
                "duration_s": round(build_s, 2)}
    rc, out, err, test_s = _run(
        ["forge", "test", "--match", match, str(test_file), "--json"])
    status, signals = _parse_forge(out)
    return {"build_rc": 0, "dependency_ok": True, "ran_tests": bool(status),
            "per_test_status": status, "signals": signals,
            "stdout": out, "stderr": err, "exit_code": rc,
            "duration_s": round(test_s, 2)}


def _test_name(name: str) -> str:
    """forge --json reports bare identifiers, the human log reports `name()`."""
    return name if name.endswith(")") else f"{name}()"


def parse_forge_output(stdout: str) -> tuple[dict, list]:
    """Per-test verdicts + failure signals from `forge test --json` output.

    Returns ({test: "Success"|"Failure"}, [{"test", "forge_reason",
    "assertion_messages"}]). An unparseable log returns an empty result rather
    than a guess: the ladder then stops at the stage the evidence supports.
    """
    status: dict[str, str] = {}
    signals: list[dict] = []
    blob = None
    for start in (i for i, ch in enumerate(stdout or "") if ch == "{"):
        try:
            candidate, _ = json.JSONDecoder().raw_decode(stdout[start:])
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(candidate, dict) and candidate:
            blob = candidate
            break
    if blob is None:
        # human-readable output. forge prints `[FAIL: reason] test()` / `[PASS] test()`
        # per suite, and the tick/cross list underneath; both shapes are read, and a
        # reason found here is recorded as a signal rather than discarded.
        for m in re.finditer(r"\[FAIL:\s*([^\]]*)\]\s*(\S+)", stdout or ""):
            label = _test_name(m.group(2))
            status[label] = "Failure"
            signals.append({"test": label, "forge_reason": m.group(1).strip() or None,
                            "assertion_messages": []})
        for m in re.finditer(r"\[PASS\]\s*(\S+)", stdout or ""):
            status.setdefault(_test_name(m.group(1)), "Success")
        for m in re.finditer(r"^\s*([+x])\s+(\S+)", stdout or "", re.M):
            status.setdefault(_test_name(m.group(2)),
                              "Success" if m.group(1) == "+" else "Failure")
        return status, signals
    for suite, res in blob.items():
        if not isinstance(res, dict):
            continue
        for name, info in (res.get("test_results") or {}).items():
            if not isinstance(info, dict):
                continue
            ok = info.get("status") == "Success"
            label = _test_name(name)
            status[label] = "Success" if ok else "Failure"
            if ok:
                continue
            items = info.get("items") or {}
            messages = [a.get("reason", "") for a in (items.get("assertions") or [])
                        if isinstance(a, dict) and a.get("reason")]
            signals.append({"test": label,
                            "forge_reason": info.get("reason") or items.get("reason"),
                            "assertion_messages": messages})
    return status, signals


_parse_forge = parse_forge_output


def preserve(outdir: Path, task_id: str, submission_dir: Path, runs: dict,
             verdict: dict, key_hash: str,
             regression: dict | None = None) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    payload = {"task_id": task_id, "verdict": verdict, "answer_key_sha256": key_hash,
               "regression_evidence": regression,
               "revisions": {k: v for k, v in runs.items()
                             if k != "submission"}, "generated_by": "scripts/prove_grader.py"}
    files = {}
    for name, text in [( "result.json", json.dumps(payload, indent=2, sort_keys=True) + "\n")]:
        (outdir / name).write_text(text, encoding="utf-8", newline="\n")
        files[name] = sha256_bytes((outdir / name).read_bytes())
    for label, run in runs.items():
        if label == "submission" or not isinstance(run, dict):
            continue
        for stream in ("stdout", "stderr"):
            if run.get(stream) is not None:
                p = outdir / f"{label}_{stream}.txt"
                p.write_text(run[stream], encoding="utf-8", newline="\n")
                files[p.name] = sha256_bytes(p.read_bytes())
    sub = outdir / "submission"
    sub.mkdir(exist_ok=True)
    for f in sorted(submission_dir.glob("*")) if submission_dir.exists() else []:
        if f.is_file():
            dst = sub / f.name
            dst.write_bytes(f.read_bytes())
            files[f"submission/{f.name}"] = sha256_bytes(dst.read_bytes())
    payload["artefact_hashes"] = files
    (outdir / "result.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8", newline="\n")
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--submission", required=True, help="directory holding the test file(s)")
    ap.add_argument("--home", default=os.environ.get("VLUN_PRIVATE_HOME"),
                    help="private answer-key root (outside the repo)")
    ap.add_argument("--out", default=str(ROOT / "work" / "prove_runs"),
                    help="artefact directory (git-ignored; preserved per run)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--regression-evidence", default=None,
                    help="JSON file with a recorded behaviour-preservation run "
                         "(baseline + fixed-revision suite); without it the verdict "
                         "stops at patch_verified and is not fully verified")
    args = ap.parse_args()

    if not args.home:
        raise SystemExit("--home or VLUN_PRIVATE_HOME must point at the private split; "
                         "the grader will not read an answer key from inside the repository")
    regression = None
    if args.regression_evidence:
        path = Path(args.regression_evidence)
        if not path.is_file():
            raise SystemExit(f"no regression evidence at {path}")
        regression = json.loads(path.read_text(encoding="utf-8"))
    key = read_key(Path(args.home), args.task_id)
    key_hash = sha256_bytes(Path(args.home).resolve().joinpath(
        "vlun_prove", "prove_tasks_private.jsonl").read_bytes())

    import experiments as ex  # noqa: E402
    sub_dir = Path(args.submission)
    files = {p.name: p.read_text(encoding="utf-8", errors="replace")
             for p in sorted(sub_dir.glob("*")) if p.is_file()}
    match = key.get("match_test") or "vlun"
    runs = {"submission": {"files": files}}
    for label in ("vulnerable", "fixed"):
        spec = ex.RepoSpec(slug=f"prove-{key['finding_id'].split('/')[0]}",
                           url=_repo_url(key), commit=key[f"{label}_commit"],
                           submodules=True, framework=key.get("framework") or "foundry")
        prepared = ex.prepare(spec, timeout=args.timeout)
        wt = ex.worktree(spec)
        ex.clean_overlay(spec)
        test_rel = "test/vlun_poc/" + next(iter(files), "submission.t.sol")
        ex.materialise(spec, {test_rel: files})
        run = run_forge(wt, wt / test_rel, match, args.timeout)
        run["prepared"] = prepared
        runs[label] = run

    verdict = stage_ladder({"files": files},
                           {k: v for k, v in runs["vulnerable"].items()},
                           {k: v for k, v in runs["fixed"].items()},
                           key.get("expected_assertion") or {}, regression)
    preserve(Path(args.out) / args.task_id, args.task_id, sub_dir, runs,
             verdict, key_hash, regression)
    log(json.dumps({"task_id": args.task_id, "stage_reached": verdict["stage_reached"],
                    "fully_verified": verdict["fully_verified"],
                    "stages": verdict["stages"], "reasons": verdict["reasons"],
                    "preserved_to": str(Path(args.out) / args.task_id)}, indent=2))
    return 0 if verdict["stages"]["behaviour_preserved"] else 1


def _repo_url(key: dict) -> str:
    """Resolve the clone URL for a task's pinned revisions.

    The private key carries the repository for every task, so a task from any codebase
    can be graded, not only the nine findings the experiment registry happens to know.
    A repository string that is not a clone URL (a local artefact directory, for
    example) still has to resolve through the registry: an unresolvable URL is a hard
    failure, never a guessed checkout.

    Resolution reads the statically declared registry only. It must not call
    `build_registry()`: materialising the registry reads test bytes out of the
    pinned local clone (`work/wt/...`), and a missing clone then surfaces as a
    `FileNotFoundError` from the working-tree lookup instead of the documented
    hard failure for an unregistered finding — and the materialised entries key
    the revision by `repo_key`, not `repo`, so the URL is in `REPOS` either way.
    """
    candidate = str(key.get("repository_url") or key.get("repository") or "")
    if candidate.startswith(("https://", "http://", "git@", "ssh://", "file://")):
        return candidate
    import run_verified_experiments as rve  # noqa: E402
    url = rve.declared_repo_url(key["finding_id"])
    if url:
        return url
    raise SystemExit(f"no registry entry for {key['finding_id']}: cannot resolve a clone URL")


if __name__ == "__main__":
    raise SystemExit(main())

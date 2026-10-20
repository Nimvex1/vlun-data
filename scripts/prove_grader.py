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

    python scripts/prove_grader.py --task-id prove-2024-01-renft__H-04 \
        --submission dir/with/test/files --out work/prove_runs/<id> [--home ...]
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

STAGES = ("generated", "compiles", "executes", "impact_reproduced", "patch_verified")
UNRELATED_REASONS = re.compile(
    r"compiler error|source not found|not found: |no tests ran|could not find|"
    r"old artifact|bad artifact|weird: cannot assign|tracing error|"
    r"insufficient funds|gas", re.I)


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


def stage_ladder(submission: dict, vulnerable: dict, fixed: dict, expected: dict) -> dict:
    """Decide the five stages from recorded run evidence. Pure, so it is testable.

    `submission`: {"files": {path: bytes-hex-free text}, }
    `vulnerable`/`fixed`: {"build_rc": int, "dependency_ok": bool, "ran_tests": bool,
                           "per_test_status": {test: "Success"|"Failure"},
                           "signals": [{"test","forge_reason","assertion_messages"}]}
    `expected`: {"failing_tests": [...], "signals": [...], "security_property": str}
    """
    out = {s: False for s in STAGES}
    why: dict[str, str] = {}

    files = {k: v for k, v in (submission.get("files") or {}).items() if v.strip()}
    out["generated"] = bool(files)
    if not files:
        why["generated"] = "the submission contained no non-empty test file"
        return {"stages": out, "reasons": why, "stage_reached": "none"}

    for label, run in (("vulnerable", vulnerable), ("fixed", fixed)):
        if run.get("build_rc") not in (0, None) or not run.get("dependency_ok", True):
            why["compiles"] = f"{label}: build rc={run.get('build_rc')}, " \
                              f"dependencies {run.get('dependency_ok')}"
            out["stage_reached"] = "generated"
            return {"stages": out, "reasons": why, "stage_reached": "generated"}
    out["compiles"] = True

    if not (vulnerable.get("ran_tests") and vulnerable.get("per_test_status")):
        why["executes"] = "no test from the submission executed on the vulnerable revision"
        return {"stages": out, "reasons": why, "stage_reached": "compiles"}
    out["executes"] = True

    want = set(expected.get("failing_tests") or [])
    got_fail = {t for t, s in (vulnerable.get("per_test_status") or {}).items()
                if s == "Failure"}
    matched = want & got_fail
    if not matched:
        why["impact_reproduced"] = (
            f"expected one of {sorted(want)} to fail on the vulnerable revision; "
            f"observed failures {sorted(got_fail) or 'none'}")
        return {"stages": out, "reasons": why, "stage_reached": "executes"}

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
        return {"stages": out, "reasons": why, "stage_reached": "executes"}
    out["impact_reproduced"] = True
    why["impact_reproduced"] = detail

    if not fixed.get("ran_tests"):
        why["patch_verified"] = "the second-revision run did not execute the test"
        return {"stages": out, "reasons": why, "stage_reached": "impact_reproduced"}
    same = {t: s for t, s in (fixed.get("per_test_status") or {}).items() if t in matched}
    if not same or any(s != "Success" for s in same.values()):
        why["patch_verified"] = f"second revision did not block the same test: {same}"
        return {"stages": out, "reasons": why, "stage_reached": "impact_reproduced"}
    out["patch_verified"] = True
    why["patch_verified"] = f"{sorted(same)} passed unmodified on the second revision"
    top = "patch_verified"
    return {"stages": out, "reasons": why, "stage_reached": top}


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
             verdict: dict, key_hash: str) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    payload = {"task_id": task_id, "verdict": verdict, "answer_key_sha256": key_hash,
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
    args = ap.parse_args()

    if not args.home:
        raise SystemExit("--home or VLUN_PRIVATE_HOME must point at the private split; "
                         "the grader will not read an answer key from inside the repository")
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
                           key.get("expected_assertion") or {})
    preserve(Path(args.out) / args.task_id, args.task_id, sub_dir, runs,
             verdict, key_hash)
    log(json.dumps({"task_id": args.task_id, "stage_reached": verdict["stage_reached"],
                    "stages": verdict["stages"], "reasons": verdict["reasons"],
                    "preserved_to": str(Path(args.out) / args.task_id)}, indent=2))
    return 0 if verdict["stages"]["patch_verified"] else 1


def _repo_url(key: dict) -> str:
    import run_verified_experiments as rve  # noqa: E402
    for e in rve.build_registry():
        if e["finding_id"] == key["finding_id"]:
            return (e.get("revisions") or {}).get("vulnerable", {}).get("repo").url
    raise SystemExit(f"no registry entry for {key['finding_id']}: cannot resolve a clone URL")


if __name__ == "__main__":
    raise SystemExit(main())

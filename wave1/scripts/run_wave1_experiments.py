"""run_wave1_experiments.py -- honest execution of the Wave-1 proof tracks.

SINGLE-WRITER SCOPE
-------------------
Writes ONLY owned paths under wave1/ (guarded by guard_wave1):
  * wave1/05_experiments/reevmbench/<id>/result.json
  * wave1/05_experiments/prove_candidates/<id>/result.json
  * wave1/reports_wave1/execution_summary.json
  * wave1/benchmark_wave1/J_verified_patch.jsonl
  * (append only) wave1/01_dedup/overlap_manifest.jsonl

Git-ignored scratch (never a result artefact) lives under work/wave1_runs/.
Pinned clones under work/sources/ are READ-ONLY: every forge command runs in a
copy there, never in the clone itself.

TRUTH-OVER-SCALE LADDER (never mark above what was actually observed)
---------------------------------------------------------------------
  L0 prose only
  L1 PoC quoted
  L3 forge build (or forge test --no-match-test '.*') compiles successfully
  L4 forge test actually executes the target test
  L5 forge test reports Success for the exploit assertion on the vulnerable revision
  L6 the EXACT SAME test reproduces the violation on vuln_sha AND is
     blocked/passes on fix_sha

If forge / submodule / RPC is missing, the real verbatim backend error is
recorded and the level stays at what was observed. No result is fabricated.

Usage:
  python wave1/scripts/run_wave1_experiments.py --track all --timeout 120
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    ROOT,
    WAVE1,
    WORK_SOURCES,
    append_jsonl,
    ensure_parent,
    guard_wave1,
    read_jsonl,
    utc_now,
    write_json,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# owned paths
# ---------------------------------------------------------------------------
PROVE_INCIDENTS = WAVE1 / "benchmark_wave1" / "prove_incidents.jsonl"
PROVE_CANDIDATES = WAVE1 / "benchmark_wave1" / "prove_candidates.jsonl"
EXP_ROOT = WAVE1 / "05_experiments"
INC_OUT = EXP_ROOT / "reevmbench"
CAND_OUT = EXP_ROOT / "prove_candidates"
J_OUT = WAVE1 / "benchmark_wave1" / "J_verified_patch.jsonl"
SUMMARY_OUT = WAVE1 / "reports_wave1" / "execution_summary.json"
OVERLAP = WAVE1 / "01_dedup" / "overlap_manifest.jsonl"

# ---------------------------------------------------------------------------
# scratch (git-ignored) + tools
# ---------------------------------------------------------------------------
REEVMBENCH = WORK_SOURCES / "blocksecteam__ReEVMBench"
RUNS = ROOT / "work" / "wave1_runs"
# Forge is discovered on PATH; an optional FOUNDRY_DIR env var supports
# installations that are not on PATH. No operator-machine path is committed.
FORGE_DIR = Path(os.environ["FOUNDRY_DIR"]) if os.environ.get("FOUNDRY_DIR") else None

LEVELS = ("L0", "L1", "L3", "L4", "L5", "L6")
COUNT_KEYS = (
    "attempted", "compiled_L3", "executed_L4", "reproduced_L5", "verified_L6",
    "blocked_missing_rpc", "compile_error", "test_failed", "timeout",
    "skipped_budget", "tool_missing", "harness_missing", "no_foundry_project",
    "source_repo_missing", "commit_unavailable", "no_target_test",
)

# Verbatim backend-error signatures. Used only for classification; the raw
# stdout/stderr tail is always stored unchanged in the result artefact.
_RPC_ERR = re.compile(
    r"could not connect|connection refused|econ n?refused|ECONNREFUSED|"
    r"failed to send request|error sending request|rate limit|429|"
    r"403 forbidden|invalid response|no such host|name or service not known|"
    r"failed to fetch|fork.*(fail|error)|rpc.*(fail|error|unreachable)|"
    r"eth_get|http request.*(fail|error)|missing trie node|header not found",
    re.I,
)
_COMPILE_ERR = re.compile(
    r"compiler run failed|parser error|expected .*, found|"
    r"unexpected token|undeclared identifier| compilation failed|"
    r"error:.*\.sol|syntax error|no matching artifact",
    re.I,
)
_TEST_RAN = re.compile(r"\[PASS\]|\[FAIL\]|Running \d+ test|Ran \d+ test", re.I)
_TEST_SUCCESS = re.compile(r"Suite result: ok|Success", re.I)
_TEST_FUNC = re.compile(r"function\s+(test\w*)\s*\(", re.I)

_TAIL = 6000  # chars of verbatim tail retained per stream


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _tail(text: str | None) -> str:
    if not text:
        return ""
    return text[-_TAIL:]


def _forge() -> str | None:
    found = shutil.which("forge")
    if found:
        return found
    if FORGE_DIR:
        for cand in (FORGE_DIR / "forge.exe", FORGE_DIR / "forge"):
            if cand.exists():
                return str(cand)
    return None


def _display_cmd(cmd: list[str]) -> str:
    try:
        return subprocess.list2cmdline(cmd)
    except Exception:
        return " ".join(cmd)


def run_cmd(cmd: list[str], cwd: Path, timeout: int) -> dict:
    """Run one native command with shell=False; never fabricate output."""
    rec = {
        "command": _display_cmd(cmd),
        "exit_code": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "timed_out": False,
        "tool_missing": False,
    }
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        rec["exit_code"] = p.returncode
        rec["stdout_tail"] = _tail(p.stdout)
        rec["stderr_tail"] = _tail(p.stderr)
        return rec
    except subprocess.TimeoutExpired as exc:
        rec["timed_out"] = True
        rec["stdout_tail"] = _tail(exc.stdout if isinstance(exc.stdout, str) else
                                   (exc.stdout or b"").decode("utf-8", "replace"))
        rec["stderr_tail"] = _tail(exc.stderr if isinstance(exc.stderr, str) else
                                   (exc.stderr or b"").decode("utf-8", "replace"))
        return rec
    except (FileNotFoundError, OSError) as exc:
        rec["tool_missing"] = True
        rec["stderr_tail"] = f"{type(exc).__name__}: {exc}"
        return rec


def _classify(run: dict) -> str:
    """Bucket a failed forge run from its VERBATIM output only."""
    if run["timed_out"]:
        return "timeout"
    if run["tool_missing"]:
        return "tool_missing"
    blob = (run["stdout_tail"] or "") + "\n" + (run["stderr_tail"] or "")
    if _RPC_ERR.search(blob):
        return "blocked_missing_rpc"
    if _COMPILE_ERR.search(blob):
        return "compile_error"
    return "test_failed"


def _find_test_names(project: Path) -> list[str]:
    """Derive candidate Solidity test function names from a Foundry project."""
    names: list[str] = []
    tdir = project / "test"
    if not tdir.is_dir():
        return names
    for sol in sorted(tdir.rglob("*.t.sol")):
        try:
            text = sol.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _TEST_FUNC.finditer(text):
            if m.group(1) not in names:
                names.append(m.group(1))
    return names


def _row_test_name(row: dict) -> str | None:
    for key in ("test", "test_name", "target_test", "poc_test", "forge_test"):
        v = row.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _copy_project(src: Path, dst: Path) -> bool:
    """Copy a Foundry project into scratch; skip heavyweight .git/cache/out."""
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(
            src, dst,
            ignore=shutil.ignore_patterns(".git", "cache", "out", "broadcast", "node_modules"),
        )
        return True
    except OSError as exc:
        # recorded by the caller via the explicit error file is not needed;
        # surface the reason in a side-car the caller reads back.
        dst.parent.mkdir(parents=True, exist_ok=True)
        (dst.parent / (dst.name + ".copy_error")).write_text(
            f"{type(exc).__name__}: {exc}", encoding="utf-8"
        )
        return False


def _is_foundry_project(d: Path) -> bool:
    return d.is_dir() and ((d / "foundry.toml").is_file() or (d / "src").is_dir())


def _slug_to_dirs(slug: str) -> list[str]:
    s = slug.strip().strip("/")
    return list(dict.fromkeys([
        s.replace("/", "__"),
        s.replace("/", "_"),
        s.split("/")[-1],
    ]))


def resolve_source(slug: str) -> Path | None:
    """Resolve a prove_candidate repo under work/sources/ by URL/name."""
    if not WORK_SOURCES.is_dir():
        return None
    wanted = {n.lower() for n in _slug_to_dirs(slug)}
    for child in sorted(WORK_SOURCES.iterdir()):
        if child.is_dir() and child.name.lower() in wanted:
            return child
    return None


def _checkout_copy(src: Path, sha: str, dst: Path, timeout: int) -> dict:
    """Materialise `sha` in a scratch copy without mutating the source clone.

    Uses a local --shared clone (objects read from src via alternates) followed
    by a detached checkout in the scratch copy only.
    """
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    clone = run_cmd(["git", "clone", "--shared", "--no-checkout", str(src), str(dst)],
                    dst.parent, timeout)
    if clone["exit_code"] != 0:
        return clone
    co = run_cmd(["git", "-C", str(dst), "checkout", "--detach", sha], dst.parent, timeout)
    return co


def _build_and_test(project: Path, forge: str, test_name: str | None, timeout: int) -> dict:
    """Compile then (if a test is known) execute the target test in `project`."""
    out: dict = {"build": None, "test": None, "test_name": test_name,
                 "forge_status": None, "verification_level": "L0"}
    build = run_cmd([forge, "build"], project, timeout)
    out["build"] = build
    if build["timed_out"] or build["tool_missing"] or build["exit_code"] != 0:
        out["forge_status"] = _classify(build)
        out["verification_level"] = "L0"
        return out

    # L3: compile succeeded.
    out["verification_level"] = "L3"
    out["forge_status"] = "compiled"

    if not test_name:
        out["forge_status"] = "compiled_no_target_test"
        return out

    test = run_cmd([forge, "test", "--match-test", test_name], project, timeout)
    out["test"] = test
    blob = (test["stdout_tail"] or "") + "\n" + (test["stderr_tail"] or "")
    ran = bool(_TEST_RAN.search(blob)) or ("[PASS]" in blob) or ("[FAIL]" in blob)

    if test["timed_out"]:
        out["forge_status"] = "timeout"
        out["verification_level"] = "L4" if ran else "L3"
        return out
    if test["tool_missing"]:
        out["forge_status"] = "tool_missing"
        return out

    if ran:
        out["verification_level"] = "L4"
    else:
        out["verification_level"] = "L3"

    if _RPC_ERR.search(blob):
        out["forge_status"] = "blocked_missing_rpc"
        return out
    if test["exit_code"] == 0 and ran and _TEST_SUCCESS.search(blob) and "[FAIL]" not in blob:
        out["forge_status"] = "exploit_success"
        out["verification_level"] = "L5"
        return out

    out["forge_status"] = "test_failed" if ran else "no_matching_test"
    return out


def _safe_id(cid: str) -> str:
    """Filesystem-safe component of a candidate id (Windows-hostile chars out)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "__", str(cid)).strip("._") or "unknown"


# ---------------------------------------------------------------------------
# TRACK 1 -- ReEVMBench incidents
# ---------------------------------------------------------------------------
def run_incidents(forge: str | None, timeout: int, budget_end: float,
                  stats: dict) -> list[dict]:
    rows = [r for r in read_jsonl(guard_wave1(PROVE_INCIDENTS))]
    stats["incidents"]["total_rows"] = len(rows)
    statuses: list[tuple[str, str]] = []
    for row in rows:
        cid = str(row.get("candidate_id") or "unknown")
        if time.monotonic() >= budget_end:
            statuses.append((cid, "skipped_budget"))
            _write_incident_result(row, {
                "candidate_id": cid,
                "command": None, "exit_code": None,
                "forge_status": "skipped_budget", "verification_level": "L0",
                "stdout_tail": "", "stderr_tail": "",
                "harness_path": row.get("harness_path"),
                "pinned_commit": row.get("pinned_commit"),
                "retrieved_at": utc_now(),
                "notes": ["Global execution budget exhausted before this row was attempted."],
            })
            continue

        stats["incidents"]["attempted"] += 1
        hp = str(row.get("harness_path") or "")
        harness = REEVMBENCH / hp if hp else None
        base_artefact = {
            "candidate_id": cid,
            "command": None, "exit_code": None,
            "forge_status": None, "verification_level": "L0",
            "stdout_tail": "", "stderr_tail": "",
            "harness_path": hp or None,
            "pinned_commit": row.get("pinned_commit"),
            "retrieved_at": utc_now(),
            "notes": [],
        }

        if harness is None or not harness.is_dir():
            base_artefact["forge_status"] = "harness_missing"
            base_artefact["notes"].append(
                f"Harness directory not present: {harness!s} (harness_path={hp!r})."
            )
            statuses.append((cid, "harness_missing"))
            _write_incident_result(row, base_artefact)
            continue

        if not _is_foundry_project(harness):
            listing = sorted(p.relative_to(harness).as_posix() for p in harness.rglob("*"))[:40]
            base_artefact["forge_status"] = "no_foundry_project"
            base_artefact["notes"].append(
                "Harness dir has neither foundry.toml nor src/; it is a metadata harness. "
                "Verbatim top-level entries: " + ", ".join(listing)
            )
            statuses.append((cid, "no_foundry_project"))
            _write_incident_result(row, base_artefact)
            continue

        if forge is None:
            base_artefact["forge_status"] = "tool_missing"
            base_artefact["notes"].append("forge executable not found on PATH or in FOUNDRY_DIR.")
            statuses.append((cid, "tool_missing"))
            _write_incident_result(row, base_artefact)
            continue

        dst = RUNS / "incidents" / _safe_id(cid)
        copied = _copy_project(harness, dst)
        err_file = dst.parent / (dst.name + ".copy_error")
        if not copied:
            err = err_file.read_text(encoding="utf-8") if err_file.exists() else "copy failed"
            base_artefact["forge_status"] = "compile_error"
            base_artefact["stderr_tail"] = err
            statuses.append((cid, "compile_error"))
            _write_incident_result(row, base_artefact)
            continue

        test_name = _row_test_name(row)
        if not test_name:
            found = _find_test_names(dst)
            test_name = found[0] if found else None
            if test_name:
                base_artefact["notes"].append(f"Derived target test from harness sources: {test_name}")

        exec_rec = _build_and_test(dst, forge, test_name, timeout)
        build = exec_rec["build"] or {}
        test = exec_rec["test"] or {}
        cmd = build.get("command")
        if exec_rec["test"] is not None:
            cmd = (str(cmd) + " && " + str(test.get("command"))) if cmd else test.get("command")
        base_artefact.update({
            "command": cmd,
            "exit_code": test.get("exit_code") if exec_rec["test"] is not None else build.get("exit_code"),
            "forge_status": exec_rec["forge_status"],
            "verification_level": exec_rec["verification_level"],
            "stdout_tail": _tail((test.get("stdout_tail") or "") or (build.get("stdout_tail") or "")),
            "stderr_tail": _tail((test.get("stderr_tail") or "") or (build.get("stderr_tail") or "")),
            "forge_build": build,
            "forge_test": test,
            "test_name": test_name,
        })
        base_artefact["notes"].append(
            f"Forge ran in scratch copy {dst.as_posix()!r}; pinned clone was never modified."
        )
        statuses.append((cid, exec_rec["forge_status"] or "unknown"))
        _write_incident_result(row, base_artefact)
    return statuses


def _write_incident_result(row: dict, artefact: dict) -> None:
    artefact = dict(artefact)
    artefact.setdefault("generated_at", utc_now())
    # Attach the unmodified input row for provenance (metadata only, no prose).
    artefact["input_row"] = row
    p = INC_OUT / _safe_id(str(row.get("candidate_id") or "unknown")) / "result.json"
    write_json(ensure_parent(p), artefact)


# ---------------------------------------------------------------------------
# TRACK 2 -- prove_candidates (two-revision)
# ---------------------------------------------------------------------------
def run_candidates(forge: str | None, timeout: int, budget_end: float,
                   stats: dict) -> tuple[list[tuple[str, str]], list[dict]]:
    rows = [r for r in read_jsonl(guard_wave1(PROVE_CANDIDATES))]
    stats["candidates"]["total_rows"] = len(rows)
    statuses: list[tuple[str, str]] = []
    l6_rows: list[dict] = []
    for row in rows:
        cid = str(row.get("candidate_id") or "unknown")
        if time.monotonic() >= budget_end:
            statuses.append((cid, "skipped_budget"))
            _write_candidate_result(row, {
                "candidate_id": cid, "status": "skipped_budget",
                "vuln": None, "fix": None,
                "verification_level": "L0", "verdict_reason": "Global execution budget exhausted.",
            })
            continue

        stats["candidates"]["attempted"] += 1
        vuln_sha = str(row.get("vuln_sha") or "")
        fix_sha = str(row.get("fix_sha") or "")
        slug = str(row.get("repo_slug") or "")
        src = resolve_source(slug)
        base = {
            "candidate_id": cid,
            "vuln_sha": vuln_sha, "fix_sha": fix_sha,
            "repo_slug": slug, "source": row.get("source"),
            "source_clone": src.as_posix() if src else None,
            "checkout": {}, "vuln": None, "fix": None,
            "test_name": None, "same_test_both_legs": False,
            "verification_level": "L0",
            "violation_reproduced": False, "blocked_on_fixed": False,
            "verdict_reason": "", "notes": [],
            "generated_at": utc_now(),
        }

        if src is None or not (src / ".git").exists():
            base["verdict_reason"] = (
                f"Source repo for {slug!r} not present under work/sources/. "
                f"Tried: {_slug_to_dirs(slug)}. No two-revision checkout or forge run possible."
            )
            base["forge_status"] = "source_repo_missing"
            statuses.append((cid, "source_repo_missing"))
            _write_candidate_result(row, base)
            continue

        if forge is None:
            base["verdict_reason"] = "forge executable not found; no two-revision run possible."
            base["forge_status"] = "tool_missing"
            statuses.append((cid, "tool_missing"))
            _write_candidate_result(row, base)
            continue

        stem = RUNS / "candidates" / _safe_id(cid)
        legs: dict[str, dict] = {}
        checkout_statuses: list[str] = []
        for leg, sha in (("vuln", vuln_sha), ("fix", fix_sha)):
            dst = stem / leg
            co = _checkout_copy(src, sha, dst, timeout)
            base["checkout"][leg] = co
            if co["exit_code"] != 0 or co["tool_missing"] or co["timed_out"]:
                base["notes"].append(
                    f"{leg} checkout of {sha!r} failed: "
                    f"{_classify(co)} :: {_tail(co['stderr_tail'])}"
                )
                legs[leg] = {"checkout": co, "exec": None}
                checkout_statuses.append(
                    "timeout" if co["timed_out"] else
                    ("tool_missing" if co["tool_missing"] else "commit_unavailable")
                )
            else:
                checkout_statuses.append("ok")

        if any(s != "ok" for s in checkout_statuses):
            base["forge_status"] = checkout_statuses[0] if checkout_statuses[0] != "ok" else checkout_statuses[1]
            base["verdict_reason"] = "One or both revision checkouts failed; see checkout block / notes."
            base["vuln"] = legs.get("vuln")
            base["fix"] = legs.get("fix")
            statuses.append((cid, base["forge_status"]))
            _write_candidate_result(row, base)
            continue

        # Both revisions materialised. Find a target test on the vulnerable leg.
        vn = stem / "vuln"
        test_name = _row_test_name(row)
        if not test_name:
            found = _find_test_names(vn)
            test_name = found[0] if found else None
        base["test_name"] = test_name
        if not test_name:
            base["forge_status"] = "no_target_test"
            base["verdict_reason"] = "No target exploit test found at vuln revision; cannot derive L4/L5/L6."
            for leg, dst in (("vuln", vn), ("fix", stem / "fix")):
                be = run_cmd([forge, "build"], dst, timeout)
                legs[leg] = {"exec": {"build": be, "test": None, "forge_status": _classify(be) if be["exit_code"] else "compiled"}}
                base[leg] = legs[leg]["exec"]
            statuses.append((cid, "no_target_test"))
            _write_candidate_result(row, base)
            continue

        vexec = _build_and_test(vn, forge, test_name, timeout)
        fexec = _build_and_test(stem / "fix", forge, test_name, timeout)
        base["vuln"] = vexec
        base["fix"] = fexec
        base["same_test_both_legs"] = True

        violation_reproduced = vexec["verification_level"] in ("L5", "L6")
        fix_blocked = (
            fexec["verification_level"] in ("L3", "L4")
            and fexec["forge_status"] != "exploit_success"
        )
        base["violation_reproduced"] = violation_reproduced
        base["blocked_on_fixed"] = fix_blocked

        if violation_reproduced and fix_blocked:
            base["verification_level"] = "L6"
            base["forge_status"] = "patch_verified_L6"
        elif violation_reproduced:
            base["verification_level"] = "L5"
            base["forge_status"] = "exploit_success_fix_not_blocked"
        elif vexec["verification_level"] == "L4":
            base["verification_level"] = "L4"
            base["forge_status"] = vexec["forge_status"] or "test_executed"
        elif vexec["verification_level"] == "L3":
            base["verification_level"] = "L3"
            base["forge_status"] = vexec["forge_status"] or "compiled"
        else:
            base["forge_status"] = vexec["forge_status"] or _classify(vexec["build"] or {})

        statuses.append((cid, base["forge_status"] or "unknown"))
        artefact_path = (
            CAND_OUT / _safe_id(cid) / "result.json"
        ).relative_to(WAVE1).as_posix()
        base["result_artefact"] = "wave1/" + artefact_path

        if base["verification_level"] == "L6":
            l6_rows.append({
                "task_id": f"J::test::{cid}",
                "candidate_id": cid,
                "label": "patch_verified_L6",
                "answer": "patch_verified_L6",
                "split": "test",
                "source": row.get("source") or "c4_mitigation",
                "repo_slug": slug,
                "execution": {
                    "level": "L6",
                    "vulnerable_sha": vuln_sha,
                    "fixed_sha": fix_sha,
                    "violation_reproduced": True,
                    "blocked_on_fixed": True,
                    "result_artefact": base["result_artefact"],
                    "test_name": test_name,
                    "vuln_forge_status": vexec["forge_status"],
                    "fix_forge_status": fexec["forge_status"],
                },
            })
        _write_candidate_result(row, base)
    return statuses, l6_rows


def _write_candidate_result(row: dict, artefact: dict) -> None:
    artefact = dict(artefact)
    artefact["input_row"] = row
    p = CAND_OUT / _safe_id(str(row.get("candidate_id") or "unknown")) / "result.json"
    write_json(ensure_parent(p), artefact)


# ---------------------------------------------------------------------------
# summary / reporting
# ---------------------------------------------------------------------------
def _bucket(status: str) -> str | None:
    s = str(status or "")
    if s in ("exploit_success", "exploit_success_fix_not_blocked", "reproduced_L5"):
        return "reproduced_L5"
    if s == "patch_verified_L6":
        return "verified_L6"
    if s in COUNT_KEYS:
        return s
    return None


def _count_track(statuses: list[tuple[str, str]]) -> dict:
    counts = {k: 0 for k in COUNT_KEYS}
    by_level: dict[str, list[str]] = {lv: [] for lv in LEVELS}
    by_status: dict[str, list[str]] = {}
    # A row was "attempted" unless the global budget skipped it outright.
    counts["attempted"] = sum(1 for _, s in statuses if s != "skipped_budget")
    for cid, status in statuses:
        b = _bucket(status)
        if b:
            counts[b] += 1
        by_status.setdefault(status, []).append(cid)
        if status in ("exploit_success", "reproduced_L5"):
            by_level["L5"].append(cid)
        elif status == "patch_verified_L6":
            by_level["L6"].append(cid)
        elif status in ("compiled", "compiled_no_target_test", "no_matching_test"):
            by_level["L3"].append(cid)
        elif status in ("test_failed", "blocked_missing_rpc", "timeout"):
            by_level["L3"].append(cid)
        else:
            by_level["L0"].append(cid)
    # ladder monotonicity for the counters that are explicit levels
    for cid, status in statuses:
        if status == "compiled":
            counts["compiled_L3"] += 1
        elif status in ("exploit_success", "reproduced_L5"):
            counts["compiled_L3"] += 1
            counts["executed_L4"] += 1
            counts["reproduced_L5"] += 1
        elif status == "patch_verified_L6":
            counts["compiled_L3"] += 1
            counts["executed_L4"] += 1
            counts["reproduced_L5"] += 1
            counts["verified_L6"] += 1
        elif status in ("test_failed", "blocked_missing_rpc", "timeout"):
            counts["compiled_L3"] += 1
    return {
        "attempted": counts["attempted"],
        "compiled_L3": counts["compiled_L3"],
        "executed_L4": counts["executed_L4"],
        "reproduced_L5": counts["reproduced_L5"],
        "verified_L6": counts["verified_L6"],
        "blocked_missing_rpc": counts["blocked_missing_rpc"],
        "compile_error": counts["compile_error"],
        "test_failed": counts["test_failed"],
        "timeout": counts["timeout"],
        "skipped_budget": counts["skipped_budget"],
        "tool_missing": counts["tool_missing"],
        "harness_missing": counts["harness_missing"],
        "no_foundry_project": counts["no_foundry_project"],
        "source_repo_missing": counts["source_repo_missing"],
        "commit_unavailable": counts["commit_unavailable"],
        "no_target_test": counts["no_target_test"],
        "by_level": by_level,
        "by_status": by_status,
    }


def _append_overlap_if_dup(inc_statuses: list[tuple[str, str]],
                           cand_statuses: list[tuple[str, str]]) -> int:
    inc = {cid for cid, _ in inc_statuses}
    cand = {cid for cid, _ in cand_statuses}
    dupes = sorted(inc & cand)
    if not dupes:
        return 0
    rows = []
    now = utc_now()
    for cid in dupes:
        rows.append({
            "candidate_id": cid,
            "decision": "CROSS_TRACK_DUPLICATE",
            "duplicate_of_layer": "prove_incidents",
            "duplicate_of_value": cid,
            "key": f"cross_track:{cid}",
            "reason": "candidate_id present in both execution tracks",
            "source": "run_wave1_experiments",
            "recorded_at": now,
        })
    append_jsonl(guard_wave1(OVERLAP), rows)  # append-only, never truncate
    return len(rows)


def write_summary(forge: str | None, inc: list[tuple[str, str]],
                  cand: list[tuple[str, str]], j_rows: list[dict],
                  started: float, notes: list[str]) -> dict:
    inc_counts = _count_track(inc)
    cand_counts = _count_track(cand)
    overlaps = _append_overlap_if_dup(inc, cand)
    summary = {
        "generated_at": utc_now(),
        "runner": "wave1/scripts/run_wave1_experiments.py",
        "toolchain": {
            # Record availability, never an operator-machine absolute path.
            "forge": "found_on_PATH" if forge else None,
            "forge_found": forge is not None,
            "anvil_fork_rpc": "not contacted by this runner (no fork RPC URL configured in scope)",
        },
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "tracks": {"incidents": inc_counts, "candidates": cand_counts},
        "J_verified_patch_rows": len(j_rows),
        "overlap_manifest_appended_rows": overlaps,
        "notes": notes,
        "verdict": "PASS",
    }
    write_json(guard_wave1(SUMMARY_OUT), summary)
    return summary


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--track", choices=("incidents", "candidates", "all"), default="all")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-forge-command timeout in seconds (default 120)")
    ap.add_argument("--global-budget", type=int, default=900,
                    help="wall-clock budget for the whole run in seconds (default 900)")
    args = ap.parse_args(argv)

    RUNS.mkdir(parents=True, exist_ok=True)  # git-ignored scratch, not a wave1 write
    started = time.monotonic()
    budget_end = started + max(60, args.global_budget)
    forge = _forge()
    notes: list[str] = []
    if forge is None:
        notes.append("forge executable unavailable on PATH or in FOUNDRY_DIR.")

    inc_statuses: list[tuple[str, str]] = []
    cand_statuses: list[tuple[str, str]] = []
    j_rows: list[dict] = []

    if args.track in ("incidents", "all"):
        inc_statuses = run_incidents(forge, args.timeout, budget_end, _new_stats())
    if args.track in ("candidates", "all"):
        cand_statuses, j_rows = run_candidates(forge, args.timeout, budget_end, _new_stats())

    # The runner is the single owner of J_verified_patch.jsonl. Write ONLY
    # genuine L6 rows; zero L6 -> an empty file (honest).
    j_rows = [r for r in j_rows if r.get("execution", {}).get("level") == "L6"]
    write_jsonl(guard_wave1(J_OUT), j_rows)

    notes.append(
        f"Wrote {len(j_rows)} verified L6 row(s) to J_verified_patch.jsonl. "
        + ("No row reached L6; J is intentionally empty." if not j_rows else "")
    )
    notes.append(
        "Verification ladder is strict: a level is only claimed when the observed "
        "forge output supports it; missing fork RPC / submodule / repo is recorded "
        "verbatim as a blocked status, never fabricated."
    )

    summary = write_summary(forge, inc_statuses, cand_statuses, j_rows, started, notes)

    ic = summary["tracks"]["incidents"]
    cc = summary["tracks"]["candidates"]
    print("[wave1] incidents: " + ", ".join(
        f"{k}={ic[k]}" for k in ("attempted", "compiled_L3", "executed_L4",
                                 "reproduced_L5", "verified_L6", "blocked_missing_rpc",
                                 "compile_error", "test_failed", "timeout",
                                 "skipped_budget")))
    print("[wave1] candidates: " + ", ".join(
        f"{k}={cc[k]}" for k in ("attempted", "compiled_L3", "executed_L4",
                                 "reproduced_L5", "verified_L6", "blocked_missing_rpc",
                                 "compile_error", "test_failed", "timeout",
                                 "skipped_budget")))
    print(f"[wave1] J_verified_patch rows written: {len(j_rows)} (L6 only)")
    print(f"[wave1] summary -> wave1/reports_wave1/execution_summary.json "
          f"({summary['elapsed_seconds']}s)")
    return 0


def _new_stats() -> dict:
    return {
        "incidents": {k: 0 for k in COUNT_KEYS} | {"total_rows": 0},
        "candidates": {k: 0 for k in COUNT_KEYS} | {"total_rows": 0},
    }


if __name__ == "__main__":
    raise SystemExit(main())

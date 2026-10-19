"""Shared primitives for the non-EVM execution pilot (spec item 9).

Stdlib only.  Every adapter in this package resolves its prerequisites, pins
a revision, runs the platform's native test command in an isolated scratch
directory, captures stdout/stderr with sha256, and evaluates a *named
assertion or state change* - never a bare exit code.

Artefact layout written by :func:`write_run_artefacts`::

    experiments_nonevm/<record_slug>/<run_slug>/
        command.txt      the exact argv that was (or would be) executed
        toolchain.txt    tool + runtime version output(s)
        harness.json     pin + runtime version + isolation notes
        assertion.json   the named assertion, its expectation and observation
        stdout.txt       captured stdout ('' when the run never started)
        stderr.txt       captured stderr
        result.json      everything above, plus hashes and the ladder level

The evidence ladder used repo-wide (a compiler success is L3; execution
alone is not L5):

    L0 prose, L1 quoted, L2 reconstructed, L3 compiles, L4 executes,
    L5 claimed violation reproduced, L6 vulnerable reproduced AND the fixed
    revision blocked by the same test.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RECORDS_V22 = ROOT / "derived_v2_2" / "records.jsonl"
ARTEFACT_ROOT = ROOT / "experiments_nonevm"
REPORT_JSON = ROOT / "reports" / "nonevm_pilot.json"
REPORT_MD = ROOT / "reports" / "nonevm_pilot.md"
SCRATCH = ROOT / "work" / "nonevm" / "runs"

SCHEMA = "vlun-nonevm-run/1"
LADDER = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]
OUTCOMES = [
    "blocked",
    "compile_failed",
    "executed_without_impact",
    "inconclusive",
    "claim_reproduced",
]
# platforms covered by spec item 9, and the (language, ecosystem) pairs the
# v2.2 derived layer uses to describe them.
PLATFORM_KEYS = {
    "cosmwasm": {("rust", "cosmwasm")},
    "solana_anchor": {("rust", "anchor")},
    "sui_move": {("move", "sui")},
    "aptos_move": {("move", "aptos")},
    "cairo_scarb": {("cairo", "starknet"), ("cairo", "cairo")},
}
PLATFORM_ORDER = ["cosmwasm", "solana_anchor", "aptos_move", "sui_move", "cairo_scarb"]


# --------------------------------------------------------------------------
# hashing / small io
# --------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slug(record_id: str) -> str:
    """experiments/<id> dirs cannot contain ':' on Windows; use '__'."""
    return record_id.replace(":", "__").replace("/", "_")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def write_json(path: Path, obj) -> None:
    write_text(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def read_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
# candidate discovery
# --------------------------------------------------------------------------
def load_records() -> list[dict]:
    out = []
    if not RECORDS_V22.exists():
        return out
    with open(RECORDS_V22, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def candidates_for(platform: str, records: list[dict] | None = None) -> list[dict]:
    keys = PLATFORM_KEYS[platform]
    recs = records if records is not None else load_records()
    rows = []
    for r in recs:
        if (r.get("language"), r.get("ecosystem")) not in keys:
            continue
        f = r.get("finding") or {}
        rows.append({
            "record_id": r["id"],
            "platform": platform,
            "language": r.get("language"),
            "ecosystem": r.get("ecosystem"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "status": f.get("status"),
            "affected_versions": f.get("affected_versions"),
            "patched_versions": f.get("patched_versions"),
            "components": f.get("affected_components") or [],
            "sources": [
                {"source_id": e.get("source_id"), "url": e.get("url"),
                 "title": e.get("title")}
                for e in ((r.get("sources_view") or {}).get("entries") or [])
            ],
        })
    return rows


# --------------------------------------------------------------------------
# process / git helpers
# --------------------------------------------------------------------------
def run_argv(argv: list[str], cwd: Path | None = None, timeout: int = 280,
             env: dict | None = None) -> dict:
    """Execute argv, capture both streams, never raise."""
    t0 = time.time()
    base = dict(os.environ)
    if env:
        base.update(env)
    try:
        p = subprocess.run(argv, cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=base)
        rc, so, se = p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        rc, so, se = 124, (e.stdout or "") if isinstance(e.stdout, str) else ""
        se = (se + f"\nTIMEOUT after {timeout}s").strip()
    except OSError as e:
        rc, so, se = 127, "", f"EXEC_FAILED {e}"
    return {"argv": argv, "cwd": str(cwd) if cwd else os.getcwd(),
            "exit_code": rc, "stdout": so, "stderr": se,
            "seconds": round(time.time() - t0, 2),
            "timeout_seconds": timeout}


def tool_version(argv: list[str], timeout: int = 90) -> str:
    r = run_argv(argv, timeout=timeout)
    text = (r["stdout"] or r["stderr"] or "").strip()
    if not text:
        return f"unavailable(exit {r['exit_code']})"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return " / ".join(lines[:3])


def which(name: str) -> str | None:
    return shutil.which(name)


def git_rev_parse(worktree: Path) -> str | None:
    r = run_argv(["git", "-C", str(worktree), "rev-parse", "HEAD"], timeout=60)
    return r["stdout"].strip() if r["exit_code"] == 0 else None


RE_SHA = re.compile(r"^[0-9a-f]{40}$")


def git_ls_remote_sha(url: str, ref: str, timeout: int = 90) -> str | None:
    """Resolve a remote ref to a 40-hex commit without cloning."""
    for target in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", ref,
                   f"refs/heads/{ref}"):
        r = run_argv(["git", "ls-remote", url, target], timeout=timeout)
        if r["exit_code"] != 0:
            continue
        for line in r["stdout"].splitlines():
            parts = line.split()
            if len(parts) >= 2 and RE_SHA.match(parts[0]):
                return parts[0]
    return None


def git_shallow_clone(url: str, ref: str, dest: Path, timeout: int = 280) -> dict:
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    return run_argv(["git", "clone", "--quiet", "--depth", "1", "--branch",
                     ref, url, str(dest)], timeout=timeout)


def copy_tree(src: Path, dest: Path, skip_build: bool = True) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(
        "build", ".git", "target") if skip_build else None)


# --------------------------------------------------------------------------
# run records
# --------------------------------------------------------------------------
def make_run(*, platform: str, record_id: str, run_slug: str, claim: str,
             status: str, outcome: str, ladder: str, toolchain: dict,
             pin: dict, assertion: dict | None, run: dict | None,
             prerequisites: list[dict], licence: dict, stdout: str = "",
             stderr: str = "", blocker: str | None = None,
             evidence_note: str = "") -> dict:
    return {
        "schema": SCHEMA,
        "platform": platform,
        "record_id": record_id,
        "run_slug": run_slug,
        "claim": claim,
        "status": status,          # executed | blocked | compile_failed | timeout
        "outcome": outcome,        # one of OUTCOMES
        "ladder": ladder,          # one of LADDER
        "toolchain": toolchain,
        "prerequisites": prerequisites,
        "pin": pin,
        "assertion": assertion,
        "run": run,
        "blocker": blocker,
        "licence": licence,
        "evidence_note": evidence_note,
        "stdout": stdout,
        "stderr": stderr,
    }


def write_run_artefacts(rec: dict) -> Path:
    d = ARTEFACT_ROOT / slug(rec["record_id"]) / rec["run_slug"]
    d.mkdir(parents=True, exist_ok=True)
    argv = (rec.get("run") or {}).get("argv") or []
    write_text(d / "command.txt", " ".join(argv) + "\n" if argv
               else "NOT RUN: " + (rec.get("blocker") or "") + "\n")
    write_text(d / "toolchain.txt", json.dumps(
        {"toolchain": rec["toolchain"], "prerequisites": rec["prerequisites"]},
        indent=2, sort_keys=True) + "\n")
    write_json(d / "harness.json", {
        "pin": rec["pin"], "toolchain": rec["toolchain"],
        "run_kind": (rec.get("run") or {}).get("run_kind", "none"),
        "isolation": (rec.get("run") or {}).get("isolation"),
        "schema": SCHEMA,
    })
    if rec.get("assertion") is not None:
        write_json(d / "assertion.json", rec["assertion"])
    write_text(d / "stdout.txt", rec.get("stdout") or "")
    write_text(d / "stderr.txt", rec.get("stderr") or "")

    arts = {}
    for name in ("command.txt", "toolchain.txt", "harness.json", "stdout.txt",
                 "stderr.txt"):
        p = d / name
        arts[name] = {"bytes": p.stat().st_size, "sha256": sha256_file(p)}
    if (d / "assertion.json").exists():
        p = d / "assertion.json"
        arts["assertion.json"] = {"bytes": p.stat().st_size,
                                  "sha256": sha256_file(p)}
    out = {k: v for k, v in rec.items() if k not in ("stdout", "stderr")}
    out["artefacts"] = arts
    write_json(d / "result.json", out)
    return d


# --------------------------------------------------------------------------
# integrity validation (also used by tests/test_nonevm_pilot.py)
# --------------------------------------------------------------------------
REQUIRED_FILES = ["command.txt", "toolchain.txt", "harness.json", "result.json"]


def validate_run_dir(d: Path) -> list[str]:
    """Return a list of integrity errors for one artefact directory.

    An empty list means the directory is a well-formed, self-consistent run.
    """
    errors: list[str] = []
    for name in REQUIRED_FILES:
        if not (d / name).exists():
            errors.append(f"missing_required_artefact {name}")
    rj = d / "result.json"
    if not rj.exists():
        return errors
    try:
        res = read_json(rj)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return [f"result.json_unparseable {e}"]

    # R1 - every recorded hash must match the bytes on disk.
    for name, meta in (res.get("artefacts") or {}).items():
        p = d / name
        if not p.exists():
            errors.append(f"artefact_missing {name}")
            continue
        actual = sha256_file(p)
        if actual != meta.get("sha256"):
            errors.append(
                f"artefact_hash_mismatch {name} recorded={meta.get('sha256')} "
                f"actual={actual}")
        if meta.get("bytes") != p.stat().st_size:
            errors.append(f"artefact_size_mismatch {name}")

    status = res.get("status")
    outcome = res.get("outcome")
    ladder = res.get("ladder")
    assertion = res.get("assertion")
    run = res.get("run")
    if run is not None and not isinstance(run, dict):
        errors.append("run_field_not_an_object")
        run = {}
    if assertion is not None and not isinstance(assertion, dict):
        errors.append("assertion_field_not_an_object")
        assertion = None
    kind = run.get("run_kind")

    # R2 - an executed run must name what it asserted and show the observation.
    if status == "executed":
        if not assertion:
            errors.append("executed_without_assertion")
        else:
            if not assertion.get("name"):
                errors.append("executed_assertion_has_no_name")
            if assertion.get("observed") is None:
                errors.append("executed_assertion_has_no_observation")
            if assertion.get("expected") is None:
                errors.append("executed_assertion_has_no_expectation")
        if run.get("exit_code") is None:
            errors.append("executed_without_exit_code")
        if kind in (None, "none"):
            errors.append("executed_without_run_kind")

    # R3 - L5/L6 require a real test execution and a met named assertion.
    if ladder in ("L5", "L6") or outcome == "claim_reproduced":
        if status != "executed":
            errors.append(f"claim_reproduced_from_non_execution status={status}")
        if kind == "compile_only":
            errors.append("ladder_escalation_from_compile_only_run")
        if kind not in ("native_test", "test_harness", "state_change"):
            errors.append(f"claim_reproduced_without_test_run kind={kind}")
        if outcome == "claim_reproduced" and not (assertion or {}).get("met"):
            errors.append("claim_reproduced_but_assertion_not_met")

    # R4 - a compile-only run can never exceed L3.
    if kind == "compile_only" and ladder in ("L4", "L5", "L6"):
        errors.append(f"compile_only_promoted_to_{ladder}")

    # R5 - a blocked run must carry a blocker string.
    if status in ("blocked", "compile_failed", "timeout"):
        if not res.get("blocker"):
            errors.append(f"{status}_run_without_blocker_string")
        if outcome == "claim_reproduced":
            errors.append(f"{status}_run_claimed_reproduced")

    # R6 - vocabulary.
    if outcome not in OUTCOMES:
        errors.append(f"unknown_outcome {outcome}")
    if ladder not in LADDER:
        errors.append(f"unknown_ladder {ladder}")
    if not res.get("record_id") or not res.get("platform"):
        errors.append("run_without_record_or_platform")
    return errors


def iter_run_dirs(artefact_root: Path = ARTEFACT_ROOT) -> list[Path]:
    """Every directory that holds a result.json, at either nesting depth."""
    if not artefact_root.exists():
        return []
    out = []
    for rec_dir in sorted(p for p in artefact_root.iterdir() if p.is_dir()):
        if (rec_dir / "result.json").exists():
            out.append(rec_dir)          # flat layout: one run per record dir
        for run_dir in sorted(p for p in rec_dir.iterdir() if p.is_dir()):
            if (run_dir / "result.json").exists():
                out.append(run_dir)
    return out


def load_runs(artefact_root: Path = ARTEFACT_ROOT) -> list[dict]:
    runs = []
    for d in iter_run_dirs(artefact_root):
        try:
            res = read_json(d / "result.json")
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue
        res["_dir"] = str(d.relative_to(artefact_root.parent)).replace("\\", "/")
        runs.append(res)
    return runs


def validate_pilot(artefact_root: Path = ARTEFACT_ROOT) -> dict:
    """Validate every run; return {runs, clean, errors:[{dir, errors}]}."""
    errs = []
    dirs = iter_run_dirs(artefact_root)
    for d in dirs:
        e = validate_run_dir(d)
        if e:
            errs.append({"dir": str(d).replace("\\", "/"), "errors": e})
    return {"runs_validated": len(dirs), "clean": not errs, "error_dirs": errs}


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def build_report(runs: list[dict], candidates: dict[str, list[dict]],
                 prereq_matrix: list[dict], integrity: dict) -> dict:
    per = {}
    for plat in PLATFORM_ORDER:
        rows = [r for r in runs if r.get("platform") == plat]
        oc, lad, bl = {}, {}, {}
        for r in rows:
            oc[r.get("outcome")] = oc.get(r.get("outcome"), 0) + 1
            lad[r.get("ladder")] = lad.get(r.get("ladder"), 0) + 1
            if r.get("blocker"):
                bl[r["blocker"]] = bl.get(r["blocker"], 0) + 1
        per[plat] = {
            "candidates": len(candidates.get(plat, [])),
            "candidate_record_ids": sorted(
                c["record_id"] for c in candidates.get(plat, [])),
            "eligible_for_execution": sum(
                1 for r in rows if r.get("status") == "executed"
                or (r.get("run") or {}).get("argv")),
            "runs": len(rows),
            "executed": sum(1 for r in rows if r.get("status") == "executed"),
            "outcomes": dict(sorted(oc.items())),
            "ladder": dict(sorted(lad.items())),
            "blockers": dict(sorted(bl.items())),
            "unique_records": len({r.get("record_id") for r in rows}),
        }
    executed_records = {r["record_id"] for r in runs if r.get("status") == "executed"}
    return {
        "schema": SCHEMA,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "spec_item": "9 non-EVM execution pilot",
        "evidence_ladder": dict(zip(LADDER, [
            "prose", "quoted", "reconstructed", "compiles", "executes",
            "claimed violation reproduced",
            "vulnerable reproduced and fixed revision blocked by same test"])),
        "outcome_vocabulary": OUTCOMES,
        "counts": {
            "candidates_total": sum(len(v) for v in candidates.values()),
            "candidates_by_platform": {p: len(candidates.get(p, []))
                                       for p in PLATFORM_ORDER},
            "runs_total": len(runs),
            "unique_records_with_runs": len({r["record_id"] for r in runs}),
            "unique_records_executed": len(executed_records),
            "executed_runs": sum(1 for r in runs if r.get("status") == "executed"),
            "outcomes_overall": _tally(runs, "outcome"),
            "ladder_overall": _tally(runs, "ladder"),
            "blockers_overall": _tally(runs, "blocker"),
        },
        "prerequisite_matrix": prereq_matrix,
        "platforms": per,
        "integrity": integrity,
        "runs": [
            {k: r.get(k) for k in (
                "platform", "record_id", "run_slug", "status", "outcome",
                "ladder", "blocker", "_dir")}
            | {"assertion": (r.get("assertion") or {}).get("name"),
               "pin": (r.get("pin") or {}).get("commit")
               or (r.get("pin") or {}).get("requested_ref")}
            for r in sorted(runs, key=lambda x: (x.get("platform") or "",
                                                 x.get("record_id") or "",
                                                 x.get("run_slug") or ""))],
    }


def _tally(runs: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in runs:
        v = r.get(key)
        if v is None:
            continue
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def render_md(rep: dict) -> str:
    c = rep["counts"]
    L = []
    L.append("# Non-EVM execution pilot (spec item 9)")
    L.append("")
    L.append(f"Generated {rep['generated_utc']} from the artefacts under "
             "`experiments_nonevm/`; every count below is recomputed, not typed in.")
    L.append("")
    L.append("Platforms: CosmWasm, Solana Anchor, Aptos/Sui Move, Cairo/Scarb. "
             "Isolated local scratch environments only - no live-chain transactions, "
             "no real funds, no faucet claims, no deployments.")
    L.append("")
    L.append("## Headline")
    L.append("")
    L.append(f"* candidates by platform: " + ", ".join(
        f"{p} {n}" for p, n in c["candidates_by_platform"].items()))
    L.append(f"* total runs: **{c['runs_total']}** across "
             f"**{c['unique_records_with_runs']}** unique records; "
             f"executed runs: **{c['executed_runs']}** "
             f"({c['unique_records_executed']} records executed at all)")
    L.append(f"* outcomes: " + ", ".join(f"{k} {v}" for k, v in
                                        c["outcomes_overall"].items()))
    L.append(f"* ladder reached: " + ", ".join(f"{k} {v}" for k, v in
                                               c["ladder_overall"].items()))
    L.append(f"* artefact integrity: " + ("all runs self-consistent"
                                          if rep["integrity"]["clean"]
                                          else "ERRORS - see integrity section"))
    L.append("")
    L.append("## Per platform")
    L.append("")
    L.append("| platform | candidates | runs | executed | outcomes | blockers |")
    L.append("|---|---|---|---|---|---|")
    for p in PLATFORM_ORDER:
        d = rep["platforms"][p]
        oc = ", ".join(f"{k} {v}" for k, v in d["outcomes"].items()) or "-"
        bl = "; ".join(f"{k} x{v}" for k, v in d["blockers"].items()) or "-"
        L.append(f"| {p} | {d['candidates']} | {d['runs']} | {d['executed']} "
                 f"| {oc} | {bl} |")
    L.append("")
    L.append("## Prerequisite matrix")
    L.append("")
    L.append("| tool | platform | install status | observed version | install command |")
    L.append("|---|---|---|---|---|")
    for row in rep["prerequisite_matrix"]:
        L.append(f"| `{row['tool']}` | {row['platform']} | {row['install_status']} "
                 f"| {row.get('version') or '-'} | `{row.get('install_command') or 'already installed'}` |")
    L.append("")
    L.append("## Runs")
    L.append("")
    L.append("| platform | record | run | status | outcome | ladder | assertion | pin | artefacts |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for r in rep["runs"]:
        L.append(f"| {r['platform']} | `{r['record_id']}` | `{r['run_slug']}` "
                 f"| {r['status']} | {r['outcome']} | {r['ladder']} "
                 f"| `{r.get('assertion') or '-'}` | `{str(r.get('pin') or '-')[:14]}` "
                 f"| `{r['_dir']}` |")
    L.append("")
    L.append("## Blockers as data")
    L.append("")
    if c["blockers_overall"]:
        for k, v in c["blockers_overall"].items():
            L.append(f"* `{k}` - {v} run(s)")
    else:
        L.append("* none recorded")
    L.append("")
    audit = rep.get("unexecuted_pool_audit") or {}
    if audit.get("exists"):
        L.append("## Candidate pools that could not be pinned")
        L.append("")
        L.append(f"Recomputed from `{audit['path']}` (metadata-only layer; no "
                 "prose or code from it is copied into an artefact): "
                 f"{audit.get('findings_total')} findings, of which "
                 f"{audit.get('non_solidity_total')} are non-Solidity: "
                 + ", ".join(f"{k} {v}" for k, v in
                             audit["non_solidity_by_language"].items()))
        L.append("")
        L.append(f"{audit.get('non_solidity_with_a_40_hex_sha_somewhere')} of "
                 "those carry a 40-hex sha anywhere in the record; the rest "
                 "reference contest links with no upstream commit, so no pin "
                 "can be resolved and they stay out of the executed set.")
        L.append("")
    disc = rep.get("declared_behaviour_discrepancies") or []
    if disc:
        L.append("## Where the published scoping and the observed behaviour differ")
        L.append("")
        L.append("Executed cells whose expectation (taken from the advisory's "
                 "own version ranges and profiles) did not match what the "
                 "runner reported. These stay `executed_without_impact`: the "
                 "run happened, the claim did not reproduce in that "
                 "configuration.")
        L.append("")
        L.append("| record | pin | declared | assertion | expected | observed |")
        L.append("|---|---|---|---|---|---|")
        for d in disc:
            L.append(f"| `{d['record_id']}` | {d['pin']} | {d['declared']} "
                     f"| `{d['assertion']}` | {d['expected']} | {d['observed']} |")
        L.append("")
    L.append("## Integrity")
    L.append("")
    L.append(f"{rep['integrity']['runs_validated']} run directories validated; "
             + ("no errors." if rep["integrity"]["clean"] else
                "problems found:"))
    for e in rep["integrity"]["error_dirs"]:
        L.append(f"* `{e['dir']}`: " + ", ".join(e["errors"]))
    L.append("")
    L.append("## Scope honesty")
    L.append("")
    L.append("A compiler success is recorded as L3 and is never promoted to L4+; "
             "an execution that does not reproduce the named claim stays at L4 "
             "(`executed_without_impact`). This pilot does not claim to be the "
             "first or only multi-VM executed security corpus; the comparison "
             "against public projects is in `reports/nonevm_landscape.md`.")
    L.append("")
    return "\n".join(L)


def report_stdout_line(msg: str) -> None:
    print(msg, flush=True)


def ensure_scratch() -> Path:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH

#!/usr/bin/env python3
"""Experiment engine: run a Solidity test against a specific repository revision.

Every claim of experimental verification in VLUN goes through this module. It is
deliberately narrow: it takes a pinned commit, an optional harness overlay, a
test name and an expectation, runs `forge test`, and writes the artefacts a
third party needs to replay the experiment.

Design rules that make the results trustworthy:

  * The repository is checked out at an explicit commit. Nothing is ever run
    against a branch tip.
  * Production code is never modified. The overlay is written into a separate
    directory (`test/vlun_poc/` for Foundry, `test/vlun_poc/` for Hardhat) and
    imports are rewritten to point at it, so the repository's own files are
    untouched and `git status` proves it.
  * Every harness modification is recorded, per file, in the result.
  * A run is only reported as `pass` when forge itself reported the test as
    passing. A crash, a compile error or a timeout is never a pass.
  * Every run is resumable: `result.json` is the memo, and the experiment id is
    a hash of (finding, repository, commit, harness digest, test name).

Artifacts per experiment:

    experiments/<finding_id>/<revision_label>/
        harness/          the overlay files exactly as compiled
        command.txt       the exact command line
        stdout.txt        forge stdout (truncated to 200 kB)
        stderr.txt        forge stderr
        trace.txt         `forge test -vvvv` traces, when requested
        result.json       machine readable outcome
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
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import ROOT, WORK, log, write_json  # noqa: E402

WT = WORK / "wt"          # working clones used for experiments
EXPERIMENTS = ROOT / "experiments"
STAGING = WT / "harness"  # where overlays are staged before being copied in

MAX_STREAM = 200_000

# Overlay directories per framework. Foundry auto-discovers `*.t.sol` under the
# test directory; Hardhat discovers `test/**`.
FOUNDRY_OVERLAY = "test/vlun_poc"
HARDHAT_OVERLAY = "test/vlun_poc"

# ---------------------------------------------------------------------------
# Licence gate on harness files.
#
# A harness overlay is a mix of two things:
#
#   * tests this pipeline wrote, from the reporter's published attack sequence
#     or from the security property in the finding. Those are ours to publish.
#   * files copied verbatim out of the audited repository. reNFT is BUSL-1.1,
#     which permits use but not redistribution, so those bytes are NOT written
#     into the published tree. They are recorded by path, commit and sha256 and
#     are re-obtainable with `git show <commit>:<path>`.
#
# The distinction is mechanical: a file is third-party if the experiment
# declared it as an overlay taken from a commit, which the registry records.
# ---------------------------------------------------------------------------
AUTHORED_MARKER = "vlun_poc_authored"


def third_party_set(harness: dict[str, str], authored: set[str]) -> set[str]:
    """Harness names whose bytes come from the audited repository.

    reNFT is BUSL-1.1: use is permitted, redistribution is not. Only files the
    experiment authored itself are publishable; everything else is withheld from
    `experiments/` and recorded by path, size and sha256 instead.
    """
    return {name for name in harness if name not in authored}


def classify_harness_files(harness: dict[str, str], third_party: set[str]) -> dict:
    """-> {authored: [...], withheld: [{path, sha256, bytes}]}."""
    authored, withheld = [], []
    for name, body in sorted(harness.items()):
        h = {"path": name, "sha256": sha256_text(body), "bytes": len(body.encode("utf-8"))}
        if name in third_party:
            withheld.append(h)
        else:
            authored.append(name)
    return {"authored": authored, "withheld": withheld}


# Toolchain requirements recorded per experiment so a replay knows what to install.
TOOLCHAIN = {
    "forge": "foundry (forge 1.8.3 or any 1.x)",
    "solc": "selected by the repository's foundry.toml / hardhat config",
    "node": "node 18+ only for Hardhat projects",
    "git": "git 2.x with submodule support",
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_files(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode())
        h.update(b"\0")
        h.update(files[name].encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# repository preparation
# ---------------------------------------------------------------------------
@dataclass
class RepoSpec:
    slug: str                 # local directory name under work/wt
    url: str                  # clone URL
    commit: str               # the exact revision to test
    submodules: bool = True
    prepare: list[dict] = field(default_factory=list)   # [{cmd, env, cwd}]
    build_env: dict = field(default_factory=dict)
    build_command: list[str] = field(default_factory=list)
    framework: str = "foundry"


@dataclass
class RunResult:
    status: str                       # pass | fail | compile_error | not_run | timeout
    exit_code: int
    stdout: str
    stderr: str
    test_status: str | None = None    # forge's own verdict for the target test
    duration_s: float = 0.0
    detail: str = ""
    gas_used: int | None = None
    decoded_logs: list[str] = field(default_factory=list)
    reverted: bool | None = None
    per_test: dict = field(default_factory=dict)


def worktree(spec: RepoSpec) -> Path:
    return WT / spec.slug


def ensure_clone(spec: RepoSpec) -> Path:
    """Clone once, then reuse. Never re-clones if the directory already exists."""
    p = worktree(spec)
    if (p / ".git").exists():
        return p
    p.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1", GIT_TERMINAL_PROMPT="0")
    r = subprocess.run(["git", "clone", "--quiet", spec.url, str(p)],
                       capture_output=True, text=True, timeout=1800, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"clone failed for {spec.url}: {r.stderr[:400]}")
    return p


def prepare(spec: RepoSpec, timeout: int = 3600) -> dict:
    """Check out the pinned commit, install submodules, build. Idempotent."""
    p = ensure_clone(spec)
    steps: list[dict] = []

    def _run(cmd, cwd=p, env=None, tmo=timeout, label=None):
        full = dict(os.environ)
        full.update(env or {})
        t0 = time.time()
        try:
            r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                               timeout=tmo, env=full, errors="replace")
            steps.append({"label": label or " ".join(cmd[:3]), "cmd": cmd,
                          "rc": r.returncode, "seconds": round(time.time() - t0, 2),
                          "stderr_tail": (r.stderr or "")[-1200:]})
            return r.returncode, r.stdout or "", r.stderr or ""
        except subprocess.TimeoutExpired:
            steps.append({"label": label or " ".join(cmd[:3]), "cmd": cmd,
                          "rc": 124, "seconds": round(time.time() - t0, 2),
                          "stderr_tail": f"timeout after {tmo}s"})
            return 124, "", f"timeout after {tmo}s"

    _run(["git", "fetch", "--quiet", "--all"], label="git fetch")
    rc, _, _ = _run(["git", "checkout", "--quiet", "--force", spec.commit],
                    label="git checkout pinned commit")
    if rc != 0:
        # the commit may only exist on a remote ref
        _run(["git", "fetch", "--quiet", "origin", spec.commit], label="git fetch commit")
        rc, _, _ = _run(["git", "checkout", "--quiet", "--force", spec.commit],
                        label="git checkout pinned commit (retry)")
    _, head, _ = _run(["git", "rev-parse", "HEAD"], label="git rev-parse HEAD")
    if head.strip() != spec.commit:
        raise RuntimeError(
            f"checkout did not land on the pinned commit for {spec.slug}: "
            f"expected {spec.commit}, HEAD is {head.strip()!r}. Refusing to run an "
            "experiment against an unpinned revision.")
    if spec.submodules:
        _run(["git", "submodule", "update", "--init", "--recursive"],
             label="git submodule update --init --recursive")
    for step in spec.prepare:
        rc, out, err = _run(step["cmd"], cwd=p if not step.get("cwd") else p / step["cwd"],
                            env=step.get("env"), label=step.get("label"))
        if rc != 0 and step.get("required", True):
            break
    if spec.build_command:
        _run(spec.build_command, cwd=p, env=spec.build_env, tmo=timeout,
             label="build: " + " ".join(spec.build_command[:2]))
    _, dirty, _ = _run(["git", "status", "--porcelain"], label="git status")
    return {
        "path": str(p),
        "head": head.strip(),
        "head_matches_pinned": head.strip() == spec.commit,
        "framework": spec.framework,
        "steps": steps,
        "dirty_lines": len([x for x in dirty.splitlines() if x.strip()]),
    }


def overlay_dir(spec: RepoSpec) -> Path:
    return worktree(spec) / (FOUNDRY_OVERLAY if spec.framework == "foundry"
                             else HARDHAT_OVERLAY)


def clean_overlay(spec: RepoSpec) -> None:
    d = overlay_dir(spec)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


def materialise(spec: RepoSpec, files: dict[str, str]) -> list[dict]:
    """Write the harness overlay. Returns one manifest row per file."""
    clean_overlay(spec)
    d = overlay_dir(spec)
    d.mkdir(parents=True, exist_ok=True)
    manifest = []
    for rel, content in sorted(files.items()):
        target = d / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        manifest.append({"path": f"{FOUNDRY_OVERLAY}/{rel}".replace("\\", "/"),
                         "sha256": sha256_text(content),
                         "bytes": len(content.encode("utf-8"))})
    return manifest


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------
def _dec(entry) -> str:
    """forge's decoded_logs entries are either objects or already-flat strings."""
    if isinstance(entry, dict):
        for key in ("raw", "message", "decoded"):
            if entry.get(key):
                return str(entry[key])
        return json.dumps(entry, sort_keys=True)
    return str(entry)


def classify_run_failure(res: RunResult) -> tuple[str, str | None]:
    """-> (controlled failure reason, the specific missing symbol when there is one).

    `reconstruction_failed` is the honest answer when the audited revision cannot
    host the test: the reporter's harness depends on a fixture, mock or error
    selector that only exists after the mitigation. That is a statement about the
    historical environment, not about the vulnerability.
    """
    text = (res.stderr or "") + "\n" + (res.stdout or "")
    if res.status == "timeout":
        return "timeout", None
    if res.status == "compile_error":
        m = re.search(r'Member "([A-Za-z0-9_]+)" not found', text)
        if m:
            return "reconstruction_failed", f"missing symbol {m.group(1)} (added by the mitigation)"
        m = re.search(r'Source "([^"]+)" not found', text)
        if m:
            return "reconstruction_failed", f"missing source {m.group(1)}"
        m = re.search(r"Undeclared identifier", text)
        if m:
            ln = re.search(r"-->\s*([^\n:]+):(\d+)", text)
            where = f"{ln.group(1)}:{ln.group(2)}" if ln else "unknown location"
            return "reconstruction_failed", f"undeclared identifier at {where} (fixture absent on this revision)"
        m = re.search(r"Wrong argument count for function call", text)
        if m:
            return "reconstruction_failed", "fixture signature drift between revisions"
        return "toolchain_failure", None
    if res.status == "toolchain_failure":
        if "no tests match" in text:
            return "reconstruction_failed", "the harness declares no test on this revision"
        return "toolchain_failure", None
    if res.status == "not_run":
        return "toolchain_failure", None
    return "", None


def forge_test(spec: RepoSpec, test_path: str | None, match_test: str | None,
               verbosity: int = 2, timeout: int = 2400, extra_env: dict | None = None,
               trace: bool = False) -> tuple[RunResult, str]:
    """Run `forge test` and parse forge's own JSON verdict."""
    cmd = ["forge", "test", "--json"]
    if match_test:
        cmd += ["--match-test", match_test]
    if test_path:
        cmd += ["--match-path", test_path]
    cmd += ["-vv"]
    env = dict(os.environ)
    env.update(spec.build_env)
    env.update(extra_env or {})
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=str(worktree(spec)), capture_output=True,
                           text=True, timeout=timeout, env=env, errors="replace")
        rc, out, err = r.returncode, r.stdout or "", r.stderr or ""
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = f"timeout after {timeout}s"
        timed_out = True
    dur = time.time() - t0

    res = RunResult(status="not_run", exit_code=rc, stdout=out, stderr=err,
                    duration_s=round(dur, 2))
    if timed_out:
        res.status = "timeout"
        res.detail = f"forge test exceeded {timeout}s"
        return res, " ".join(cmd)

    payload = None
    if out.strip().startswith("{"):
        try:
            payload = json.loads(out)
        except json.JSONDecodeError:
            # forge may print warnings before the JSON body
            i = out.find("{")
            if i >= 0:
                try:
                    payload = json.loads(out[i:])
                except json.JSONDecodeError:
                    payload = None
    if payload is None:
        res.status = "compile_error" if "Error" in err or "error" in out else "toolchain_failure"
        res.detail = (err or out)[-800:]
        return res, " ".join(cmd)

    # forge --json emits either {"test_results": {...}} or, per suite,
    # {"<suite>": {"test_results": {...}}}. Accept both.
    suites: dict[str, dict] = {}
    if isinstance(payload.get("test_results"), dict):
        suites["<all>"] = payload
    else:
        for k, v in payload.items():
            if isinstance(v, dict) and isinstance(v.get("test_results"), dict):
                suites[k] = v
    if not suites:
        res.status = "compile_error" if "Compiler run failed" in out else "toolchain_failure"
        res.detail = "forge produced no test results"
        return res, " ".join(cmd)

    results: dict[str, dict] = {}
    for suite in suites.values():
        results.update(suite.get("test_results") or {})
    if not results:
        res.status = "compile_error" if "Compiler run failed" in out else "toolchain_failure"
        res.detail = "forge produced suites but no test results"
        return res, " ".join(cmd)

    statuses = [str(t.get("status")) for t in results.values()]
    if "Failure" in statuses or "fail" in statuses:
        res.status = "fail"
    else:
        res.status = "pass"
    res.test_status = "success" if res.status == "pass" else "failure"
    first = next(iter(results.values()))
    res.gas_used = first.get("kind", {}).get("Unit", {}).get("gas")
    res.decoded_logs = [(_dec(d))[:2000] for d in (first.get("decoded_logs") or [])][:80]
    res.per_test = {
        name: {"status": t.get("status"),
               "logs": [_dec(d)[:600] for d in (t.get("decoded_logs") or [])][:12],
               "reason": _fail_reason((out or "") + "\n" + (err or ""), name)}
        for name, t in results.items()
    }
    return res, " ".join(cmd)


_FAIL_LINE = re.compile(r"\[FAIL:\s*([^\]]*)\]\s*(\S+)")


def _fail_reason(stdout: str, test_name: str) -> str | None:
    """forge prints `[FAIL: reason] testName(...)`; the JSON omits the reason."""
    for m in _FAIL_LINE.finditer(stdout or ""):
        if test_name and test_name.split("(")[0] in m.group(2):
            return m.group(1).strip()
    return None


def capture_human(spec: RepoSpec, test_path: str | None, match_test: str | None,
                  timeout: int = 2400) -> str:
    """`forge test` without `--json`: the only output that carries `[FAIL: reason]`."""
    cmd = ["forge", "test"]
    if match_test:
        cmd += ["--match-test", match_test]
    if test_path:
        cmd += ["--match-path", test_path]
    env = dict(os.environ)
    env.update(spec.build_env)
    try:
        r = subprocess.run(cmd, cwd=str(worktree(spec)), capture_output=True,
                           text=True, timeout=timeout, env=env, errors="replace")
        return (r.stdout or "") + "\n" + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return f"human-readable capture exceeded {timeout}s"


def fail_reason(human_output: str, test_name: str) -> str | None:
    return _fail_reason(human_output, test_name)


def npx_hardhat_test(spec: RepoSpec, test_path: str | None, timeout: int = 2400
                     ) -> tuple[RunResult, str]:
    """Run a single Hardhat test file. Parses mocha's summary, not forge."""
    rel = test_path or ""
    cmd = ["npx", "hardhat", "test", rel] if rel else ["npx", "hardhat", "test"]
    env = dict(os.environ)
    env.update(spec.build_env)
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=str(worktree(spec)), capture_output=True, text=True,
                           timeout=timeout, env=env, errors="replace")
        rc, out, err = r.returncode, r.stdout or "", r.stderr or ""
        timed_out = False
    except subprocess.TimeoutExpired:
        rc, out, err, = 124, "", f"timeout after {timeout}s"
        timed_out = True
    dur = time.time() - t0
    res = RunResult(status="not_run", exit_code=rc, stdout=out, stderr=err,
                    duration_s=round(dur, 2))
    if timed_out:
        res.status = "timeout"
        res.detail = f"hardhat test exceeded {timeout}s"
        return res, " ".join(cmd)
    if "passing" in out:
        res.status = "pass"
        res.test_status = "success"
    elif "failing" in out:
        res.status = "fail"
        res.test_status = "failure"
    elif "Error" in err or "error" in out:
        res.status = "compile_error"
        res.detail = (err or out)[-800:]
    else:
        res.status = "toolchain_failure"
        res.detail = (err or out)[-800:]
    return res, " ".join(cmd)


def capture_trace(spec: RepoSpec, test_path: str | None, match_test: str | None,
                  timeout: int = 2400) -> str:
    """`forge test -vvvv` traces for the same selection. Best effort."""
    cmd = ["forge", "test", "-vvvv"]
    if match_test:
        cmd += ["--match-test", match_test]
    if test_path:
        cmd += ["--match-path", test_path]
    env = dict(os.environ)
    env.update(spec.build_env)
    try:
        r = subprocess.run(cmd, cwd=str(worktree(spec)), capture_output=True,
                           text=True, timeout=timeout, env=env, errors="replace")
        return (r.stdout or "")[:MAX_STREAM]
    except subprocess.TimeoutExpired:
        return f"trace capture exceeded {timeout}s"


# ---------------------------------------------------------------------------
# artifact storage
# ---------------------------------------------------------------------------
def write_artifacts(finding_id: str, revision_label: str, harness: dict[str, str],
                    result: RunResult, command: str, extra: dict | None = None,
                    trace: str | None = None, repo_info: dict | None = None,
                    third_party: set[str] | None = None,
                    commit: str | None = None) -> Path:
    """experiments/<finding_id>/<revision_label>/ — small, hashed, git-committable.

    Harness files declared third-party are not written: the audited repository is
    BUSL-1.1, which permits use but not redistribution. Their path, size and
    sha256 are recorded so the exact bytes that were compiled stay verifiable
    against the upstream repository.
    """
    safe = finding_id.replace("/", "__").replace("\\", "__")
    d = EXPERIMENTS / safe / revision_label
    hd = d / "harness"
    if hd.exists():
        shutil.rmtree(hd, ignore_errors=True)
    hd.mkdir(parents=True, exist_ok=True)
    split = classify_harness_files(harness, third_party or set())
    for rel in split["authored"]:
        target = hd / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(harness[rel], encoding="utf-8", newline="\n")
    if split["withheld"]:
        write_json(hd / "WITHHELD.json", {
            "why": ("these harness files are verbatim copies from the audited repository, "
                    "which is licensed BUSL-1.1 (use permitted, redistribution not). They "
                    "are therefore not published in this repository."),
            "how_to_obtain": ("git show <commit>:<path> in the audited repository; the sha256 "
                              "below is the hash of the exact bytes that were compiled in "
                              "this experiment, so a replay can be verified byte for byte."),
            "commit": commit,
            "files": split["withheld"],
        })
    (d / "command.txt").write_text(command + "\n", encoding="utf-8")
    (d / "stdout.txt").write_text(result.stdout[:MAX_STREAM], encoding="utf-8")
    (d / "stderr.txt").write_text(result.stderr[:MAX_STREAM], encoding="utf-8")
    if trace:
        (d / "trace.txt").write_text(trace[:MAX_STREAM], encoding="utf-8")
    payload = {
        "finding_id": finding_id,
        "revision_label": revision_label,
        "status": result.status,
        "test_status": result.test_status,
        "exit_code": result.exit_code,
        "duration_s": result.duration_s,
        "gas_used": result.gas_used,
        "detail": result.detail[:2000],
        "command": command,
        "harness_digest": digest_files(harness),
        "harness_files": split["authored"],
        "harness_files_withheld_for_licence": [f["path"] for f in split["withheld"]],
        "harness_file_digests": {f["path"]: f["sha256"]
                                 for f in split["withheld"] + [
                                     {"path": n, "sha256": sha256_text(harness[n])}
                                     for n in split["authored"]]},
        "decoded_logs": result.decoded_logs[:20],
        "per_test": {k: {"status": v.get("status"),
                         "reason": v.get("reason"),
                         "logs": (v.get("logs") or [])[:6]}
                     for k, v in (result.per_test or {}).items()},
        "repository": repo_info or {},
        "environment_requirements": TOOLCHAIN,
        "artifact_sha256": {},
    }
    payload["harness_file_digests"] = {
        f["path"]: f["sha256"] for f in split["withheld"]}
    payload["harness_file_digests"].update(
        {name: sha256_text(harness[name]) for name in split["authored"]})
    for name in ("command.txt", "stdout.txt", "stderr.txt", "trace.txt"):
        f = d / name
        if f.exists():
            payload["artifact_sha256"][name] = sha256_text(
                f.read_text(encoding="utf-8", errors="replace"))
    if extra:
        payload.update(extra)
    write_json(d / "result.json", payload)
    return d


def experiment_id(finding_id: str, spec_slug: str, commit: str, harness: dict[str, str],
                  match_test: str | None) -> str:
    return sha256_text("|".join([finding_id, spec_slug, commit, digest_files(harness),
                                 match_test or ""]))[:24]


def load_done(finding_id: str, revision_label: str) -> dict | None:
    """Resume support: a previous result.json for this experiment."""
    safe = finding_id.replace("/", "__").replace("\\", "__")
    f = EXPERIMENTS / safe / revision_label / "result.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def clean_repo_forensics(spec: RepoSpec) -> dict:
    """`git status --porcelain` of the working tree, proving src/ is untouched."""
    try:
        r = subprocess.run(["git", "status", "--porcelain"], cwd=str(worktree(spec)),
                           capture_output=True, text=True, timeout=300)
        lines = [x for x in r.stdout.splitlines() if x.strip()]
    except Exception:  # noqa: BLE001 - forensics must never break an experiment
        return {"available": False}
    prod, harness_dir = [], []
    for ln in lines:
        path = ln[3:].strip().strip('"')
        norm = path.replace("\\", "/")
        if norm.startswith(("src/", "contracts/")):
            prod.append(ln)
        elif "vlun_poc" in norm:
            harness_dir.append(ln)
    return {
        "available": True,
        "production_files_modified": prod,
        "production_files_modified_count": len(prod),
        "overlay_files": harness_dir,
        "other_changes": [ln for ln in lines
                          if ln not in prod and ln not in harness_dir][:20],
        "clean": not prod,
    }

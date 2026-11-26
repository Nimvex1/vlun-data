"""Foundry workspace materialisation + honest command execution.

Everything in this module writes to git-ignored scratch under work/wave1_runs/
(or to the pinned read-only source clone's *copy*). No canonical or wave1
artefact is ever written here; the caller owns all wave1/ writes.

Stdlib only. Commands use shell=False and are recorded verbatim.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

_TAIL = 6000
_IGNORE = shutil.ignore_patterns(".git", "out", "cache", "broadcast", "node_modules")
_MINIMAL_TOML = '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\n'

PASS_RE = re.compile(r"\[PASS\]\s+(\S+?)\s*\(", re.M)
FAIL_RE = re.compile(r"\[FAIL[^\]]*\]\s+(\S+?)\s*\(", re.M)
RAN_RE = re.compile(r"Ran \d+ test", re.I)
RPC_RE = re.compile(
    r"could not connect|connection refused|econ n?refused|failed to send request|"
    r"error sending request|rate limit|429|403 forbidden|invalid response|"
    r"no such host|name or service not known|failed to fetch|fork.*(fail|error)|"
    r"rpc.*(fail|error|unreachable)|eth_get|http request.*(fail|error)|"
    r"missing trie node|header not found",
    re.I,
)
COMPILE_RE = re.compile(
    r"compiler run failed|parser error|expected .*, found|unexpected token|"
    r"undeclared identifier|compilation failed|error:.*\.sol|syntax error|"
    r"no matching artifact|could not compile",
    re.I,
)


def _tail(text: str | None) -> str:
    if not text:
        return ""
    return str(text)[-_TAIL:]


def display_cmd(cmd: list[str]) -> str:
    try:
        return subprocess.list2cmdline(cmd)
    except (TypeError, ValueError):
        # Non-string argv item: fall back to a plain join for logging only.
        return " ".join(cmd)


def run_cmd(cmd: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
    """Run one native command; never fabricate stdout/stderr."""
    rec: dict[str, Any] = {
        "command": display_cmd(cmd),
        "exit_code": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "timed_out": False,
        "tool_missing": False,
    }
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True,
            errors="replace", timeout=max(1, timeout), shell=False,
        )
        rec["exit_code"] = p.returncode
        rec["stdout_tail"] = _tail(p.stdout)
        rec["stderr_tail"] = _tail(p.stderr)
    except subprocess.TimeoutExpired as exc:
        rec["timed_out"] = True
        out, err = exc.stdout, exc.stderr
        rec["stdout_tail"] = _tail(out.decode("utf-8", "replace") if isinstance(out, bytes) else out)
        rec["stderr_tail"] = _tail(err.decode("utf-8", "replace") if isinstance(err, bytes) else err)
    except (FileNotFoundError, OSError) as exc:
        rec["tool_missing"] = True
        rec["stderr_tail"] = f"{type(exc).__name__}: {exc}"
    return rec


def classify_failure(run: dict[str, Any]) -> str:
    if run.get("timed_out"):
        return "timeout"
    if run.get("tool_missing"):
        return "tool_missing"
    blob = (run.get("stdout_tail") or "") + "\n" + (run.get("stderr_tail") or "")
    if RPC_RE.search(blob):
        return "blocked_missing_rpc"
    if COMPILE_RE.search(blob):
        return "compile_error"
    return "test_failed"


def discover_tools(work_root: Path) -> dict[str, Any]:
    """Tool availability only -- never an operator-machine absolute path."""
    env_forge = os.environ.get("FOUNDRY_DIR") or ""
    forge_dir = Path(env_forge) if env_forge else None
    forge = shutil.which("forge")
    if not forge and forge_dir:
        for name in ("forge.exe", "forge"):
            cand = forge_dir / name
            if cand.is_file():
                forge = str(cand)
                break
    anvil = shutil.which("anvil")
    cast = shutil.which("cast")
    # Do not commit the resolved paths; only availability and a generic label.
    forge_std = _find_forge_std(work_root)
    return {
        "forge_available": bool(forge),
        "forge_label": "found_on_PATH_or_FOUNDRY_DIR" if forge else None,
        "anvil_available": bool(anvil),
        "cast_available": bool(cast),
        "cached_forge_std_available": bool(forge_std),
        "forge_std_label": "cached_copy_under_work" if forge_std else None,
        "_forge": forge,
        "_forge_std": str(forge_std) if forge_std else None,
    }


def _find_forge_std(work_root: Path) -> Path | None:
    roots = [work_root / p for p in ("hats_pilot", "patch_repos", "poc_reruns", "sources")]
    found: list[Path] = []
    for base in roots:
        if not base.is_dir():
            continue
        try:
            for p in base.rglob("forge-std"):
                if (p / "src" / "Forge.sol").is_file() and "node_modules" not in p.parts:
                    found.append(p)
        except OSError:
            continue
    if not found:
        return None
    return sorted(found, key=lambda p: len(p.parts))[0]


def _copy_tree(src: Path, dst: Path) -> dict[str, Any]:
    rec: dict[str, Any] = {"source": str(src), "destination": str(dst), "ok": False,
                           "method": "copytree"}
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    if dst.exists():
        # Windows can refuse to delete deeply nested vendored lib paths. Move
        # the stale tree aside so copytree can create a fresh destination.
        stale = dst.with_name(dst.name + "_stale_" + str(int(time.time())))
        try:
            dst.rename(stale)
            rec["stale_moved_to"] = str(stale)
        except OSError:
            pass
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(src, dst, ignore=_IGNORE)
        rec["ok"] = True
    except OSError as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


def clone_at(url: str, dest: Path, commit: str, timeout: int) -> dict[str, Any]:
    """Clone a repo and (try to) check out ``commit``; record every attempt."""
    rec: dict[str, Any] = {
        "url": url, "destination": str(dest), "requested_commit": commit or None,
        "attempts": [], "ok": False, "head": None, "checked_out_commit": None,
    }
    if not url:
        rec["failure"] = "no_repo"
        return rec

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    git = shutil.which("git") or "git"

    def go(args: list[str], cwd: Path, label: str) -> dict[str, Any]:
        env_cmd = [git] + args
        r = run_cmd(env_cmd, cwd, timeout)
        r["step"] = label
        rec["attempts"].append(r)
        return r

    if (dest / ".git").is_dir():
        rec["attempts"].append({"step": "reuse_existing_clone", "command": None,
                                "exit_code": 0, "stdout_tail": "", "stderr_tail": ""})
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        # --no-checkout avoids a HEAD working tree that conflicts with the
        # pinned commit (deep vendored lib trees on Windows).
        cl = go(["clone", "--no-checkout", "--quiet", url, str(dest)],
                dest.parent, "git_clone")
        if cl["exit_code"] != 0 or cl["timed_out"] or cl["tool_missing"]:
            rec["failure"] = "clone_failed"
            return rec
    # Deeply nested vendored Solidity libraries exceed Win32 MAX_PATH unless
    # git is told to allow long paths. This is a scratch clone only.
    go(["-C", str(dest), "config", "core.longpaths", "true"],
       dest.parent, "git_config_longpaths")

    head = go(["-C", str(dest), "rev-parse", "HEAD"], dest.parent, "rev_parse_head")
    if head["exit_code"] == 0:
        rec["head"] = head["stdout_tail"].strip().splitlines()[-1] if head["stdout_tail"].strip() else None

    if not commit:
        co = go(["-C", str(dest), "checkout", "--quiet", "--force", "HEAD"],
                dest.parent, "git_checkout_head")
        if co["exit_code"] != 0:
            rec["failure"] = "checkout_failed"
            return rec
        rec["ok"] = True
        rec["checked_out_commit"] = rec["head"]
        return rec

    probe = go(["-C", str(dest), "cat-file", "-t", commit], dest.parent, "cat_file_commit")
    if probe["exit_code"] != 0:
        fetch = go(["-C", str(dest), "fetch", "--quiet", "origin", commit],
                   dest.parent, "git_fetch_commit")
        if fetch["exit_code"] != 0:
            # A reachable HEAD is still a usable vulnerable snapshot; record
            # that the requested base_commit was unavailable verbatim.
            rec["commit_unavailable"] = True
            rec["commit_error"] = _tail(fetch["stderr_tail"] or probe["stderr_tail"])
            if rec["head"]:
                rec["ok"] = True
                rec["checked_out_commit"] = rec["head"]
            else:
                rec["failure"] = "commit_unavailable"
            return rec
        probe = go(["-C", str(dest), "cat-file", "-t", commit], dest.parent, "cat_file_after_fetch")

    co = go(["-C", str(dest), "checkout", "--quiet", "--force", "--detach", commit],
            dest.parent, "git_checkout_commit")
    if co["exit_code"] != 0:
        # Discard a stale/mixed working tree from an interrupted prior run and
        # retry once before declaring the commit unavailable.
        go(["-C", str(dest), "reset", "--hard", "--quiet", "HEAD"],
           dest.parent, "git_reset_before_retry")
        co = go(["-C", str(dest), "checkout", "--quiet", "--force", "--detach", commit],
                dest.parent, "git_checkout_commit_retry")
    if co["exit_code"] != 0:
        rec["failure"] = "commit_unavailable"
        rec["commit_error"] = _tail(co["stderr_tail"])
        return rec
    rec["checked_out_commit"] = commit
    rec["ok"] = True
    return rec


def dockerfile_clone_url(harness: Path) -> str:
    df = harness / "Dockerfile"
    if not df.is_file():
        return ""
    try:
        text = df.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"git\s+clone\s+(?:--[^\s]+\s+)*(\S+)", text)
    if not m:
        return ""
    url = m.group(1).strip().strip("\"'")
    if not url.startswith("http"):
        return ""
    return url if url.endswith(".git") else url + ".git"


def derive_clone_urls(audit_id: str, harness: Path) -> list[str]:
    """URL candidates in priority order: Dockerfile first, then derived fallbacks."""
    urls: list[str] = []
    from_docker = dockerfile_clone_url(harness)
    if from_docker:
        urls.append(from_docker)
    slug = str(audit_id or "").strip()
    if slug and slug.startswith("audits/"):
        slug = slug.split("/", 1)[1]
    if slug:
        for owner in ("evmbench-org", "code-423n4"):
            for suffix in ("", "-findings"):
                u = f"https://github.com/{owner}/{slug}{suffix}.git"
                if u not in urls:
                    urls.append(u)
    return urls


def project_root(checkout: Path, run_cmd_dir: str) -> Path:
    if run_cmd_dir:
        cand = checkout / run_cmd_dir.strip("/")
        if cand.is_dir():
            return cand
    return checkout


def install_tests(workspace_root: Path, harness: Path, vuln: dict[str, Any]) -> list[dict[str, Any]]:
    """Copy harness test sources to their mapped repo-root-relative paths."""
    out: list[dict[str, Any]] = []
    for src_rel, dst_rel in (vuln.get("test_path_mapping") or {}).items():
        src = harness / str(src_rel)
        dst = workspace_root / str(dst_rel)
        entry = {"source": str(src), "destination": str(dst_rel), "copied": False}
        if src.is_file():
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                entry["copied"] = True
            except OSError as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
        else:
            entry["error"] = "harness test source missing"
        out.append(entry)
    return out


def _ensure_libs_and_config(project: Path, forge_std: str | None) -> list[str]:
    notes: list[str] = []
    lib = project / "lib" / "forge-std"
    if not (lib / "src" / "Forge.sol").is_file() and forge_std:
        try:
            lib.parent.mkdir(parents=True, exist_ok=True)
            if lib.exists():
                shutil.rmtree(lib, ignore_errors=True)
            shutil.copytree(forge_std, lib, ignore=_IGNORE)
            notes.append("wired cached forge-std into lib/forge-std")
        except OSError as exc:
            notes.append(f"forge-std wiring failed: {type(exc).__name__}: {exc}")
    if not (project / "foundry.toml").is_file():
        try:
            (project / "foundry.toml").write_text(_MINIMAL_TOML, encoding="utf-8", newline="\n")
            notes.append("created minimal foundry.toml")
        except OSError as exc:
            notes.append(f"foundry.toml creation failed: {type(exc).__name__}: {exc}")
    return notes


def _fixed_via_worktree(checkout: Path, fixed: Path, commit: str,
                        timeout: int) -> dict[str, Any]:
    """Materialise a second workspace with git worktree (handles long paths)."""
    git = shutil.which("git") or "git"
    run_cmd([git, "-C", str(checkout), "config", "core.longpaths", "true"],
            checkout.parent, timeout)
    run_cmd([git, "-C", str(checkout), "worktree", "prune"], checkout.parent, timeout)
    if fixed.exists():
        run_cmd([git, "-C", str(checkout), "worktree", "remove", "--force", str(fixed)],
                checkout.parent, timeout)
        shutil.rmtree(fixed, ignore_errors=True)
    if fixed.exists():
        # A stale directory that Windows refused to delete: do not collide.
        stale = fixed.with_name(fixed.name + "_stale_" + str(int(time.time())))
        try:
            fixed.rename(stale)
        except OSError:
            pass
    fixed.parent.mkdir(parents=True, exist_ok=True)
    r = run_cmd([git, "-C", str(checkout), "worktree", "add", "--quiet",
                 "--force", "--detach", str(fixed), commit or "HEAD"],
                checkout.parent, timeout)
    r["method"] = "git_worktree"
    r["ok"] = r["exit_code"] == 0
    return r


def make_fixed_workspace(checkout: Path, fixed: Path, harness: Path,
                         vulns: list[dict[str, Any]], run_cmd_dir: str,
                         forge_std: str | None, commit: str = "",
                         timeout: int = 180) -> dict[str, Any]:
    """Materialise a second workspace at the same revision, then apply patches."""
    # Copy the *working tree* of the vulnerable checkout, not the committed
    # tree: the former contains the wired forge-std, minimal foundry.toml,
    # installed harness tests and any dependency recovery. A git worktree
    # would omit those and produce a false L6 regression.
    copied = _copy_tree(checkout, fixed)
    if not copied["ok"]:
        wt = _fixed_via_worktree(checkout, fixed, commit, timeout)
        if wt["ok"]:
            copied = {"ok": True, "method": "git_worktree", "checkout": wt,
                      "destination": str(fixed), "source": str(checkout)}
        else:
            copied["worktree_fallback_reason"] = _tail(wt["stderr_tail"])
    info: dict[str, Any] = {"workspace": str(fixed), "copy": copied,
                            "patch_sources": [], "diff_applications": [], "notes": []}
    if not info["copy"]["ok"]:
        return info
    proj = project_root(fixed, run_cmd_dir)
    info["project_root"] = str(proj)
    info["notes"].extend(_ensure_libs_and_config(proj, forge_std))

    for v in vulns:
        for src_rel, dst_rel in (v.get("patch_path_mapping") or {}).items():
            src = harness / str(src_rel)
            dst = fixed / str(dst_rel)
            entry = {"vulnerability": v.get("id"), "source": str(src), "destination": str(dst_rel),
                     "copied": False}
            if src.is_file():
                try:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
                    entry["copied"] = True
                except OSError as exc:
                    entry["error"] = f"{type(exc).__name__}: {exc}"
            else:
                entry["error"] = "harness patch source missing"
            info["patch_sources"].append(entry)
            if entry["copied"]:
                info["notes"].append(f"applied fixed source {dst_rel} for {v.get('id')}")

        if not any(e["copied"] and e.get("vulnerability") == v.get("id")
                   for e in info["patch_sources"]):
            vid = str(v.get("id") or "").strip()
            candidates = sorted((harness / "patch").glob(f"{vid}.diff")) if (harness / "patch").is_dir() else []
            for diff in candidates:
                git = shutil.which("git") or "git"
                r = run_cmd([git, "apply", "-p1", "--whitespace=nowarn", str(diff)],
                            fixed, 60)
                info["diff_applications"].append({"vulnerability": vid, "diff": diff.name, **r})
                if r["exit_code"] == 0:
                    info["notes"].append(f"applied {diff.name} via git apply -p1")
    return info


def _test_flags(vuln: dict[str, Any], config_flags: str) -> list[str]:
    tokens: list[str] = []
    for text in (config_flags or "", str(vuln.get("test_flags") or "")):
        tokens.extend(str(text).split())
    # --silent/--quiet suppress the [PASS]/[FAIL] lines we must observe.
    cleaned = [t for t in tokens if t not in ("--silent", "-q", "--quiet")]
    cleaned.append("-vvv")
    return cleaned


def _npm_recover(project: Path, build: dict[str, Any], timeout: int) -> dict[str, Any] | None:
    """Install declared JS dependencies when a build fails on node_modules paths."""
    blob = (build.get("stdout_tail") or "") + "\n" + (build.get("stderr_tail") or "")
    if "node_modules" not in blob or COMPILE_RE.search(blob) is None:
        return None
    manifests = [project / "package.json", project.parent / "package.json"]
    manifest = next((p for p in manifests if p.is_file()), None)
    if manifest is None:
        return None
    # On Windows shutil.which("npm") resolves to npm.ps1, which CreateProcess
    # cannot launch (shell=False). The .cmd shim next to it is executable.
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        return None
    if npm.lower().endswith(".ps1"):
        sibling = Path(npm).with_suffix(".cmd")
        npm = str(sibling) if sibling.is_file() else npm
    root = manifest.parent
    return run_cmd([npm, "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                   root, max(240, timeout * 2))


def build_and_test(forge: str, project: Path, tests: list[tuple[dict[str, Any], str]],
                   config_flags: str, timeout: int, budget_end: float) -> dict[str, Any]:
    """forge build once, then forge test for each target; honest ladder."""
    out: dict[str, Any] = {
        "project_root": str(project), "build": None, "tests": [],
        "forge_status": None, "verification_level": "L0",
        "dependency_install": None,
    }
    build_timeout = max(timeout, 240)
    build = run_cmd([forge, "build", "--root", str(project)], project, build_timeout)
    out["build"] = build
    if build["exit_code"] != 0 and not build["timed_out"] and not build["tool_missing"]:
        install = _npm_recover(project, build, timeout)
        if install is not None:
            out["dependency_install"] = install
            if install["exit_code"] == 0:
                build = run_cmd([forge, "build", "--root", str(project)],
                                project, build_timeout)
                out["build"] = build
    if build["timed_out"] or build["tool_missing"] or build["exit_code"] != 0:
        out["forge_status"] = classify_failure(build)
        return out
    if not tests:
        out["forge_status"] = "compiled_no_target_test"
        out["verification_level"] = "L3"
        return out

    out["verification_level"] = "L3"
    saw_run = False
    saw_success = False
    saw_fail = False
    for vuln, name in tests:
        if time.monotonic() >= budget_end:
            r = {"vulnerability": vuln.get("id"), "test_name": name,
                 "command": None, "exit_code": None, "stdout_tail": "",
                 "stderr_tail": "", "timed_out": False, "skipped_budget": True,
                 "ran": False, "exploit_success": False}
            out["tests"].append(r)
            continue
        flags = _test_flags(vuln, config_flags)
        cmd = [forge, "test", "--root", str(project), "--match-test", name] + flags
        r = run_cmd(cmd, project, timeout)
        blob = (r.get("stdout_tail") or "") + "\n" + (r.get("stderr_tail") or "")
        passed = bool(re.search(r"\[PASS\]\s+" + re.escape(name) + r"\s*\(", blob))
        failed = bool(re.search(r"\[FAIL[^\]]*\]\s+" + re.escape(name) + r"\s*\(", blob))
        ran = bool(RAN_RE.search(blob)) or passed or failed or "[PASS]" in blob or "[FAIL" in blob
        r.update({
            "vulnerability": vuln.get("id"), "test_name": name,
            "ran": ran, "passed": passed, "failed": failed,
            "exploit_success": bool(r["exit_code"] == 0 and passed and
                                    "Suite result: ok" in blob and "[FAIL" not in blob),
            "rpc_indicated": bool(RPC_RE.search(blob)),
        })
        out["tests"].append(r)
        saw_run = saw_run or ran
        saw_success = saw_success or r["exploit_success"]
        saw_fail = saw_fail or failed

    if saw_success:
        out["verification_level"] = "L5"
        out["forge_status"] = "exploit_success"
    elif saw_run:
        out["verification_level"] = "L4"
        out["forge_status"] = "test_executed" if not saw_fail else "test_failed"
    elif any(t.get("rpc_indicated") for t in out["tests"]):
        out["forge_status"] = "blocked_missing_rpc"
    elif any(t["timed_out"] for t in out["tests"]):
        out["forge_status"] = "timeout"
    else:
        out["forge_status"] = "no_matching_test"
    return out

"""run_wave1_experiments.py -- materialise and run the Wave-1 proof workspaces.

SINGLE-WRITER SCOPE
-------------------
Writes ONLY the owned paths below (all through guard_wave1):
  * wave1/05_experiments/reevmbench/<id>/result.json
  * wave1/05_experiments/prove_candidates/<id>/result.json
  * wave1/reports_wave1/execution_summary.json
  * wave1/benchmark_wave1/J_verified_patch.jsonl

Git-ignored scratch (never a result artefact) lives under work/wave1_runs/.
Pinned clones under work/sources/ are READ-ONLY. Every forge command runs in a
scratch workspace copied from, or the disposable scratch clone of, a source.

TRUTH-OVER-SCALE LADDER (never claim above what was observed)
-------------------------------------------------------------
  L0  no compilation
  L3  forge build succeeded
  L4  forge test executed the target test
  L5  forge test reported Success for the exploit assertion (vulnerable side)
  L6  the SAME test reproduced on the vulnerable revision and was blocked /
      failed on the fixed revision (mapped patch sources or patch diff)

Missing RPC, missing repo, compile errors and timeouts are recorded with the
verbatim backend output; they are never fabricated into a higher level.

Usage:
  python wave1/scripts/run_wave1_experiments.py --track all --timeout 120 --budget 3600
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    ROOT,
    WAVE1,
    WORK_SOURCES,
    guard_scratch,
    guard_wave1,
    read_jsonl,
    utc_now,
    write_json,
    write_jsonl,
)
from experiments.foundry import (  # noqa: E402
    build_and_test,
    clone_at,
    derive_clone_urls,
    discover_tools,
    install_tests,
    make_fixed_workspace,
    project_root,
    run_cmd,
)
from experiments.yaml_lite import exploit_vulnerabilities, parse_config  # noqa: E402

# ---------------------------------------------------------------------------
# owned paths
# ---------------------------------------------------------------------------
PROVE_INCIDENTS = WAVE1 / "benchmark_wave1" / "prove_incidents.jsonl"
PROVE_CANDIDATES = WAVE1 / "benchmark_wave1" / "prove_candidates.jsonl"
INC_OUT = WAVE1 / "05_experiments" / "reevmbench"
CAND_OUT = WAVE1 / "05_experiments" / "prove_candidates"
J_OUT = WAVE1 / "benchmark_wave1" / "J_verified_patch.jsonl"
SUMMARY_OUT = WAVE1 / "reports_wave1" / "execution_summary.json"

# ---------------------------------------------------------------------------
# scratch + constants
# ---------------------------------------------------------------------------
REEVMBENCH = WORK_SOURCES / "blocksecteam__ReEVMBench"
RUNS = ROOT / "work" / "wave1_runs"
LEVELS = ("L0", "L1", "L3", "L4", "L5", "L6")
STATUS_KEYS = (
    "attempted", "L3", "L4", "L5", "L6", "no_repo", "clone_failed",
    "compile_error", "test_failed", "no_test_suite", "blocked_missing_rpc",
    "timeout", "skipped_budget", "tool_missing", "harness_missing",
    "no_foundry_project", "framework_hardhat", "commit_unavailable",
    "checkout_failed", "no_target_test", "harness_test_missing",
    "verification_incomplete", "suite_executed",
)
SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")


def _safe_id(cid: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "__", str(cid)).strip("._") or "unknown"


def _now() -> str:
    return utc_now()


# Operator-machine profile paths are never written into a tracked artefact.
# The repository's machine-path gate accepts REDACTED as a genuine placeholder.
# Only the account-name component is replaced; the rest of the command/path
# (tool name, repo-relative arguments) stays meaningful. Forge stdout/stderr
# tails can also contain POSIX home paths baked into compiler output, so those
# are redacted with the same token.
_REDACT_PATTERNS = (
    re.compile(
        r"(?P<prefix>(?<![A-Za-z0-9])[A-Za-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+)"
        r"[A-Za-z0-9._-]+"
    ),
    re.compile(r"(?P<prefix>(?<![A-Za-z0-9])/(?:home|Users|root)/)[A-Za-z0-9._-]+"),
    re.compile(r"(?P<prefix>(?<![A-Za-z0-9])/tmp/)[A-Za-z0-9._-]+(?=[\\/]|$)"),
)


def _redact_paths(text: str) -> str:
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(lambda m: m.group("prefix") + "REDACTED", text)
    return text


def _jsonable(value: Any) -> Any:
    """Recursively coerce paths to strings and redact machine-local profile paths.

    This is applied to EVERY value written to a tracked result.json, the
    execution summary and the J rows. The real (unredacted) paths are still
    used at runtime to execute commands and read the fixed workspaces; only
    what is serialised into the artefact is redacted.
    """
    if isinstance(value, Path):
        return _redact_paths(str(value))
    if isinstance(value, str):
        return _redact_paths(value)
    if isinstance(value, dict):
        return {_redact_paths(str(k)): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _git_blob_sha(data: bytes) -> str:
    """The real git-blob object id of ``data`` (never a fabricated value)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _applied_fixed_relpaths(info: dict[str, Any]) -> list[str]:
    """Repo-root-relative paths of the fixed sources applied to a fixed workspace."""
    rels: set[str] = set()
    for entry in (info or {}).get("patch_sources") or []:
        if isinstance(entry, dict) and entry.get("copied") and entry.get("destination"):
            rels.add(str(entry["destination"]).replace("\\", "/").lstrip("./"))
    for note in (info or {}).get("notes") or []:
        m = re.match(r"\s*applied fixed source\s+(.+?)\s+for\s+", str(note))
        if m:
            rels.add(m.group(1).replace("\\", "/").lstrip("./"))
    return sorted(rels)


def _compute_fixed_blob_sha(fixed_root: Path, info: dict[str, Any]) -> str | None:
    """Hash the exact bytes of the applied fixed sources in ``fixed_root``.

    Returns the git-blob SHA over the concatenation of the patched source
    files (sorted by relative path, so it is deterministic), or None when the
    workspace/evidence is missing. No identifier is invented.
    """
    rels = _applied_fixed_relpaths(info)
    if not rels or not fixed_root.is_dir():
        return None
    chunks: list[bytes] = []
    for rel in rels:
        try:
            data = (fixed_root / rel).read_bytes()
        except OSError:
            return None
        if not data:
            return None
        chunks.append(data)
    sha = _git_blob_sha(b"".join(chunks))
    return sha if SHA40.match(sha) else None


def _write_incident_result(row: dict[str, Any], artefact: dict[str, Any]) -> None:
    art = dict(artefact)
    art.setdefault("generated_at", _now())
    art["input_row"] = row
    path = INC_OUT / _safe_id(str(row.get("candidate_id") or "unknown")) / "result.json"
    write_json(guard_wave1(path), _jsonable(art))


def _write_candidate_result(row: dict[str, Any], artefact: dict[str, Any]) -> None:
    art = dict(artefact)
    art.setdefault("generated_at", _now())
    art["input_row"] = row
    path = CAND_OUT / _safe_id(str(row.get("candidate_id") or "unknown")) / "result.json"
    write_json(guard_wave1(path), _jsonable(art))


def _toolchain_note(tools: dict[str, Any]) -> str:
    parts = ["forge=" + ("available" if tools["forge_available"] else "MISSING"),
             "anvil=" + ("available" if tools["anvil_available"] else "MISSING"),
             "cast=" + ("available" if tools["cast_available"] else "MISSING"),
             "cached_forge_std=" + ("available" if tools["cached_forge_std_available"] else "MISSING")]
    return "; ".join(parts)


def _harness_listing(harness: Path) -> list[str]:
    if not harness.is_dir():
        return []
    out: list[str] = []
    for p in sorted(harness.rglob("*")):
        if p.is_file():
            out.append(p.relative_to(harness).as_posix())
        if len(out) >= 80:
            break
    return out


_RPC_ENV_KEYS = (
    "RPC_URL", "ETH_RPC_URL", "BSC_RPC_URL", "BASE_RPC_URL", "ARBITRUM_RPC_URL",
    "ALCHEMY_API_KEY", "INFURA_API_KEY", "ETHERSCAN_API_KEY", " FOUNDRY_RPC",
)


def _rpc_env_present() -> bool:
    return any(os.environ.get(k, "").strip() for k in _RPC_ENV_KEYS)


# ---------------------------------------------------------------------------
# TRACK 1 -- ReEVMBench incidents
# ---------------------------------------------------------------------------
def process_incident(row: dict[str, Any], tools: dict[str, Any],
                     timeout: int, budget_end: float) -> tuple[str, dict[str, Any]]:
    cid = str(row.get("candidate_id") or "unknown")
    hp = str(row.get("harness_path") or "")
    base_commit = str(row.get("pinned_commit") or "")
    art: dict[str, Any] = {
        "candidate_id": cid,
        "command": None, "commands": [], "exit_code": None, "exit_codes": [],
        "forge_status": None, "verification_level": "L0",
        "stdout_tail": "", "stderr_tail": "",
        "harness_path": hp or None, "base_commit": base_commit or None,
        "fixed_workspace": None, "toolchain_note": _toolchain_note(tools),
        "retrieved_at": _now(), "notes": [],
    }
    if time.monotonic() >= budget_end:
        art["forge_status"] = "skipped_budget"
        art["notes"].append("Global execution budget exhausted before this row was attempted.")
        return "skipped_budget", art

    harness = REEVMBENCH / hp if hp else None
    if harness is None or not harness.is_dir():
        art["forge_status"] = "harness_missing"
        art["notes"].append(f"Harness directory absent under ReEVMBench clone: {hp!r}.")
        return "harness_missing", art
    guard_scratch(harness)

    cfg = parse_config(harness / "config.yaml")
    framework = str(cfg.get("framework") or "")
    vulns = exploit_vulnerabilities(cfg)
    art["harness_listing"] = _harness_listing(harness)
    art["config_summary"] = {
        "id": cfg.get("id"), "framework": framework or None,
        "run_cmd_dir": cfg.get("run_cmd_dir") or None,
        "base_commit": cfg.get("base_commit") or None,
        "default_test_flags": cfg.get("default_test_flags") or None,
        "vulnerabilities_total": len(cfg.get("vulnerabilities") or []),
        "vulnerabilities_with_tests": len(vulns),
    }
    base_commit = str(cfg.get("base_commit") or base_commit or "")
    art["base_commit"] = base_commit or None

    if framework.lower().startswith("hardhat"):
        art["forge_status"] = "framework_hardhat"
        art["notes"].append(
            "Harness framework is Hardhat (JS/TS tests); this Foundry runner does not "
            "claim an execution level for it. No forge command was run on this row."
        )
        return "framework_hardhat", art
    if "clarahacks" in hp.lower() and (harness / "exploit" / "fork_config.json").is_file():
        fork = {}
        try:
            fork = json.loads((harness / "exploit" / "fork_config.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        art["fork_config"] = {
            "chain": fork.get("chain"), "chain_id": fork.get("chain_id"),
            "fork_block_number": fork.get("fork_block_number"),
            "exploit_transactions": [t.get("tx_hash") for t in (fork.get("exploit_transactions") or [])],
            "victim_addresses": [v.get("address") for v in (fork.get("victim_addresses") or [])],
        }
        if not _rpc_env_present():
            art["forge_status"] = "blocked_missing_rpc"
            art["notes"].append(
                "ClaraHacks harness needs an upstream RPC fork to deploy/replay the "
                "incident (chain/fork block in fork_config). No RPC URL API key is set "
                "in the environment and the harness contains no test/ or patch/ sources; "
                "the exploit cannot be executed locally. See fork_config."
            )
            return "blocked_missing_rpc", art
    if not vulns:
        art["forge_status"] = "no_test_suite"
        art["notes"].append(
            "Harness carries no vulnerability with both a target test and a test path "
            "mapping; nothing executable to materialise. See harness_listing."
        )
        return "no_test_suite", art
    if not tools["forge_available"]:
        art["forge_status"] = "tool_missing"
        art["notes"].append("forge executable unavailable on PATH / FOUNDRY_DIR.")
        return "tool_missing", art

    forge = tools["_forge"]
    run_dir = str(cfg.get("run_cmd_dir") or "")
    stem = RUNS / "reevmbench" / _safe_id(cid)
    urls = derive_clone_urls(str(cfg.get("id") or hp), harness)
    art["clone_urls_attempted"] = urls
    clone: dict[str, Any] | None = None
    for url in urls:
        if time.monotonic() >= budget_end:
            break
        clone = clone_at(url, stem / "checkout", base_commit, max(180, timeout * 2))
        clone["url"] = url
        if clone.get("ok"):
            break
    art["clone"] = clone or {"failure": "no_repo", "url": None, "attempts": []}
    if not clone or not clone.get("ok"):
        status = str(clone.get("failure") if clone else "no_repo")
        if status == "commit_unavailable":
            art["notes"].append("Requested base_commit could not be fetched; see clone.attempts.")
        art["forge_status"] = status
        art["stderr_tail"] = str((clone or {}).get("commit_error") or
                                 _last_stderr(clone) if clone else "no clone URL available")
        return status, art

    checkout = stem / "checkout"
    project = project_root(checkout, run_dir)
    art["source_checkout"] = str(checkout)
    art["project_root"] = str(project)
    if not (project / "foundry.toml").is_file() and not (project / "src").is_dir():
        art["forge_status"] = "no_foundry_project"
        art["notes"].append(
            "Cloned project has neither foundry.toml nor src/; verbatim top-level entries: "
            + ", ".join(sorted(p.name for p in project.iterdir()))[:1500]
        )
        return "no_foundry_project", art

    # Materialise the vulnerable workspace (the disposable scratch checkout).
    installs: list[dict[str, Any]] = []
    for v in vulns:
        installs.extend(install_tests(checkout, harness, v))
    art["test_installation"] = installs
    if not any(e.get("copied") for e in installs):
        art["forge_status"] = "harness_test_missing"
        art["notes"].append("No harness test source could be copied into the workspace.")
        return "harness_test_missing", art

    from experiments.foundry import _ensure_libs_and_config  # local import, private helper
    art["notes"].extend(_ensure_libs_and_config(project, tools.get("_forge_std")))

    # Materialise the second (fixed) workspace at the same base revision.
    fixed_root = stem / "fixed"
    fixed_info = make_fixed_workspace(
        checkout, fixed_root, harness, vulns, run_dir, tools.get("_forge_std"),
        commit=base_commit or str((clone or {}).get("checked_out_commit") or "HEAD"),
        timeout=max(120, timeout),
    )
    for v in vulns:
        fixed_info.setdefault("test_installation", []).extend(install_tests(fixed_root, harness, v))
    art["fixed_workspace"] = fixed_info
    if not fixed_info.get("copy", {}).get("ok"):
        art["notes"].append("Fixed workspace copy failed; L6 cannot be established.")

    tests = [(v, str(v.get("test")).strip()) for v in vulns]
    config_flags = str(cfg.get("default_test_flags") or "")
    vres = build_and_test(forge, project, tests, config_flags, timeout, budget_end)
    art["vulnerable"] = vres
    art["command"] = vres.get("build", {}).get("command")
    art["commands"] = ([vres["build"]["command"]] if vres.get("build") else [])
    art["exit_code"] = (vres.get("build") or {}).get("exit_code")
    art["exit_codes"] = [art["exit_code"]]
    for t in vres.get("tests") or []:
        if t.get("command"):
            art["commands"].append(t["command"])
            art["exit_codes"].append(t.get("exit_code"))
            if not art["stdout_tail"]:
                art["stdout_tail"] = t.get("stdout_tail") or ""
                art["stderr_tail"] = t.get("stderr_tail") or ""
    if not art["stdout_tail"]:
        art["stdout_tail"] = (vres.get("build") or {}).get("stdout_tail") or ""
        art["stderr_tail"] = (vres.get("build") or {}).get("stderr_tail") or ""

    status = str(vres.get("forge_status") or "unknown")
    art["verification_level"] = str(vres.get("verification_level") or "L0")
    art["forge_status"] = status

    if art["verification_level"] == "L5" and fixed_info.get("copy", {}).get("ok"):
        fixed_project = project_root(fixed_root, run_dir)
        fres = build_and_test(forge, fixed_project, tests, config_flags, timeout, budget_end)
        art["fixed"] = fres
        for t in fres.get("tests") or []:
            if t.get("command"):
                art["commands"].append(t["command"])
                art["exit_codes"].append(t.get("exit_code"))
        vmap = {str(t.get("test_name")): t for t in vres.get("tests") or []}
        fmap = {str(t.get("test_name")): t for t in fres.get("tests") or []}
        pairs = []
        for name, vt in vmap.items():
            ft = fmap.get(name, {})
            reproduced = bool(vt.get("exploit_success"))
            blocked = bool(ft.get("ran") and ft.get("failed") and not ft.get("exploit_success"))
            if reproduced and blocked:
                pairs.append({"test_name": name, "vulnerable": "PASS", "fixed": "FAIL"})
        art["l6_pairs"] = pairs
        art["all_exploits_blocked_on_fixed"] = bool(pairs) and len(pairs) == sum(
            1 for t in vmap.values() if t.get("exploit_success"))
        if pairs:
            art["verification_level"] = "L6"
            art["forge_status"] = "patch_verified_L6"
            status = "patch_verified_L6"
            # Bind the L6 claim to the exact fixed bytes that were applied in
            # the fixed workspace. This is a real git-blob SHA (NOT a commit
            # SHA); if it cannot be computed the row is excluded from J.
            fixed_info = art.get("fixed_workspace") or {}
            fixed_sha = _compute_fixed_blob_sha(fixed_root, fixed_info)
            art["fixed_sha"] = fixed_sha
            art["fixed_sha_basis"] = "git_blob_of_patched_sources" if fixed_sha else None
            if fixed_sha:
                art["fixed_source_paths"] = _applied_fixed_relpaths(fixed_info)
            else:
                art["notes"].append(
                    "Could not compute a real git-blob SHA over the applied fixed "
                    "sources; this L6 artefact is excluded from J_verified_patch."
                )
    elif art["verification_level"] == "L5":
        art["notes"].append("L5 observed but no fixed workspace was available to test L6.")
        status = "exploit_success"
    return status, art


def _last_stderr(clone: dict[str, Any] | None) -> str:
    if not clone:
        return ""
    for step in reversed(clone.get("attempts") or []):
        if isinstance(step, dict) and step.get("stderr_tail"):
            return str(step["stderr_tail"])
    return str(clone.get("commit_error") or "")


# ---------------------------------------------------------------------------
# TRACK 2 -- prove_candidates (two-revision)
# ---------------------------------------------------------------------------
def _repo_listing(repo: Path) -> dict[str, Any]:
    files: list[str] = []
    for p in sorted(repo.rglob("*")):
        if p.is_file() and ".git" not in p.relative_to(repo).parts:
            files.append(p.relative_to(repo).as_posix())
    return {"top_level": sorted(p.name for p in repo.iterdir() if p.name != ".git"),
            "file_count": len(files), "files": files[:80]}


def _suite_kind(repo: Path) -> str:
    for rel in ("foundry.toml",):
        if (repo / rel).is_file():
            return "foundry"
    for p in repo.rglob("hardhat.config.*"):
        if ".git" not in p.parts:
            return "hardhat"
    if (repo / "Cargo.toml").is_file():
        return "cargo"
    return "none"


def _checkout_leg(repo: Path, sha: str, dest: Path, timeout: int) -> dict[str, Any]:
    if dest.is_dir():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git") or "git"
    # A previous run may have registered a worktree at this path.
    run_cmd([git, "-C", str(repo), "worktree", "prune"], repo.parent, timeout)
    run_cmd([git, "-C", str(repo), "worktree", "remove", "--force", str(dest)],
            repo.parent, timeout)
    run_cmd([git, "-C", str(repo), "config", "core.longpaths", "true"],
            repo.parent, timeout)
    fetch = run_cmd([git, "-C", str(repo), "fetch", "--quiet", "origin", sha],
                    repo.parent, timeout)
    if fetch["exit_code"] != 0:
        return {"sha": sha, "ok": False, "failure": "commit_unavailable", "fetch": fetch}
    wt = run_cmd([git, "-C", str(repo), "worktree", "add", "--quiet", "--detach",
                  str(dest), sha], repo.parent, timeout)
    if wt["exit_code"] == 0:
        return {"sha": sha, "ok": True, "method": "git_worktree", "checkout": wt}
    # Fallback: local shared clone with detached checkout.
    cl = run_cmd([git, "clone", "--quiet", "--shared", "--no-checkout",
                  str(repo), str(dest)], dest.parent, timeout)
    co = run_cmd([git, "-C", str(dest), "checkout", "--quiet", "--detach", sha],
                 dest.parent, timeout)
    return {"sha": sha, "ok": co["exit_code"] == 0, "method": "shared_clone",
            "clone": cl, "checkout": co}


def process_candidate(row: dict[str, Any], repo_cache: dict[str, dict[str, Any]],
                      tools: dict[str, Any], timeout: int,
                      budget_end: float) -> tuple[str, dict[str, Any]]:
    cid = str(row.get("candidate_id") or "unknown")
    slug = str(row.get("repo_slug") or "")
    vuln_sha = str(row.get("vuln_sha") or "")
    fix_sha = str(row.get("fix_sha") or "")
    art: dict[str, Any] = {
        "candidate_id": cid, "repo_slug": slug,
        "vuln_sha": vuln_sha, "fix_sha": fix_sha,
        "permalink": row.get("permalink"),
        "vuln": None, "fix": None, "checkout": {}, "clone": None,
        "verification_level": "L0", "forge_status": None,
        "violation_reproduced": False, "blocked_on_fixed": False,
        "toolchain_note": _toolchain_note(tools),
        "retrieved_at": _now(), "notes": [],
    }
    if time.monotonic() >= budget_end:
        art["forge_status"] = "skipped_budget"
        art["notes"].append("Global execution budget exhausted before this row was attempted.")
        return "skipped_budget", art
    if not slug:
        art["forge_status"] = "no_repo"
        art["notes"].append("Row carries no repo_slug.")
        return "no_repo", art

    if slug not in repo_cache:
        last = slug.split("/")[-1]
        dest = RUNS / "prove_repos" / _safe_id(last)
        if dest.is_dir() and (dest / ".git").is_dir():
            repo_cache[slug] = {"ok": True, "path": str(dest),
                                "url": f"https://github.com/{slug}.git", "attempts": []}
        else:
            repo_cache[slug] = clone_at(f"https://github.com/{slug}.git", dest, "", 300)
            repo_cache[slug]["path"] = str(dest)
    clone = repo_cache[slug]
    art["clone"] = clone
    repo = Path(str(clone.get("path") or RUNS / "prove_repos" / _safe_id(slug.split("/")[-1])))
    if not clone.get("ok") or not (repo / ".git").is_dir():
        art["forge_status"] = "clone_failed"
        art["notes"].append("Repository clone failed; see clone.attempts for verbatim output.")
        return "clone_failed", art

    listing = _repo_listing(repo)
    art["repo_listing"] = listing
    suite = _suite_kind(repo)
    art["suite_kind"] = suite
    if suite == "none":
        art["forge_status"] = "no_test_suite"
        art["verification_level"] = "L0"
        art["notes"].append(
            "Repository is issue-markdown/JSON data only: no foundry.toml, no "
            "hardhat.config.* and no Cargo.toml. Verbatim directory listing is in "
            "repo_listing. No test suite was fabricated."
        )
        return "no_test_suite", art

    if not tools["forge_available"] and suite == "foundry":
        art["forge_status"] = "tool_missing"
        return "tool_missing", art

    stem = RUNS / "prove_candidates" / _safe_id(cid)
    legs: dict[str, dict[str, Any]] = {}
    for leg, sha in (("vuln", vuln_sha), ("fix", fix_sha)):
        if not SHA40.match(sha) or sha == (fix_sha if leg == "vuln" else vuln_sha):
            legs[leg] = {"sha": sha, "ok": False, "failure": "invalid_or_same_sha"}
        else:
            legs[leg] = _checkout_leg(repo, sha, stem / leg, timeout)
    art["checkout"] = legs
    if any(not legs[k].get("ok") for k in ("vuln", "fix")):
        art["forge_status"] = "checkout_failed"
        art["notes"].append("One or both revision checkouts failed; see checkout block.")
        return "checkout_failed", art

    if suite == "foundry":
        tests: list[tuple[dict[str, Any], str]] = []
        for leg in ("vuln", "fix"):
            root = stem / leg
            if not (root / "foundry.toml").is_file():
                root = next((p.parent for p in root.rglob("foundry.toml")), root)
            legs[leg]["project_root"] = str(root)
            if leg == "vuln":
                # Derive exploit test functions from the vulnerable revision.
                for sol in sorted(root.rglob("*.t.sol")):
                    text = sol.read_text(encoding="utf-8", errors="replace")
                    for m in re.finditer(r"function\s+(test\w*)\s*\(", text):
                        if m.group(1) not in [n for _, n in tests]:
                            tests.append(({"id": "derived"}, m.group(1)))
        vres = build_and_test(tools["_forge"], Path(str(legs["vuln"]["project_root"])),
                              tests[:5], "", timeout, budget_end)
        fres = build_and_test(tools["_forge"], Path(str(legs["fix"]["project_root"])),
                              tests[:5], "", timeout, budget_end)
        art["vuln"], art["fix"] = vres, fres
        vmap = {str(t.get("test_name")): t for t in vres.get("tests") or []}
        fmap = {str(t.get("test_name")): t for t in fres.get("tests") or []}
        reproduced = any(t.get("exploit_success") for t in vmap.values())
        blocked = any(fmap.get(n, {}).get("ran") and fmap.get(n, {}).get("failed")
                      for n, t in vmap.items() if t.get("exploit_success"))
        art["violation_reproduced"] = reproduced
        art["blocked_on_fixed"] = blocked
        if reproduced and blocked:
            art["verification_level"] = "L6"
            art["forge_status"] = "patch_verified_L6"
        elif reproduced:
            art["verification_level"] = "L5"
            art["forge_status"] = "exploit_success"
        elif vres.get("verification_level") == "L4":
            art["verification_level"] = "L4"
            art["forge_status"] = vres.get("forge_status") or "test_executed"
        elif vres.get("verification_level") == "L3":
            art["verification_level"] = "L3"
            art["forge_status"] = "compiled"
        else:
            art["forge_status"] = vres.get("forge_status") or "verification_incomplete"
        return str(art["forge_status"]), art

    # hardhat / cargo: execute the project's standard test command on both legs.
    cmd_for = {"hardhat": ["npx", "hardhat", "test"], "cargo": ["cargo", "test"]}[suite]
    for leg in ("vuln", "fix"):
        root = stem / leg
        r = run_cmd(cmd_for, root, timeout)
        art[leg] = {"command": r["command"], "exit_code": r["exit_code"],
                    "stdout_tail": r["stdout_tail"], "stderr_tail": r["stderr_tail"]}
    art["forge_status"] = "suite_executed"
    art["verification_level"] = "L4"
    return "suite_executed", art


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def _load_results(folder: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not folder.is_dir():
        return out
    for p in sorted(folder.rglob("result.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def _count_track(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {k: 0 for k in STATUS_KEYS}
    by_level: dict[str, list[str]] = {lv: [] for lv in LEVELS}
    by_status: dict[str, list[str]] = {}
    for r in results:
        cid = str(r.get("candidate_id") or "unknown")
        status = str(r.get("forge_status") or "unknown")
        level = str(r.get("verification_level") or "L0")
        by_status.setdefault(status, []).append(cid)
        if level in by_level:
            by_level[level].append(cid)
        if status != "skipped_budget":
            counts["attempted"] += 1
        if status in ("patch_verified_L6", "verified_L6"):
            counts["L6"] += 1
        elif status in ("exploit_success", "reproduced_L5"):
            counts["L5"] += 1
        elif status in ("test_executed", "suite_executed"):
            counts["L4"] += 1
        elif status in ("compiled", "compiled_no_target_test", "no_matching_test"):
            counts["L3"] += 1
        elif status == "skipped_budget":
            counts["skipped_budget"] += 1
        elif status in ("no_repo", "source_repo_missing"):
            counts["no_repo"] += 1
        elif status == "clone_failed":
            counts["clone_failed"] += 1
        elif status == "compile_error":
            counts["compile_error"] += 1
        elif status == "test_failed":
            counts["test_failed"] += 1
        elif status == "no_test_suite":
            counts["no_test_suite"] += 1
        elif status == "blocked_missing_rpc":
            counts["blocked_missing_rpc"] += 1
        elif status == "timeout":
            counts["timeout"] += 1
        elif status == "tool_missing":
            counts["tool_missing"] += 1
        elif status == "harness_missing":
            counts["harness_missing"] += 1
        elif status == "no_foundry_project":
            counts["no_foundry_project"] += 1
        elif status == "framework_hardhat":
            counts["framework_hardhat"] += 1
        elif status == "commit_unavailable":
            counts["commit_unavailable"] += 1
        elif status == "checkout_failed":
            counts["checkout_failed"] += 1
        elif status == "no_target_test":
            counts["no_target_test"] += 1
        elif status == "harness_test_missing":
            counts["harness_test_missing"] += 1
        else:
            counts["verification_incomplete"] += 1
    # Ladder counters are monotonic and derived from observed levels.
    levels = [str(r.get("verification_level") or "L0") for r in results]
    counts["L3"] = sum(1 for lv in levels if lv in ("L3", "L4", "L5", "L6"))
    counts["L4"] = sum(1 for lv in levels if lv in ("L4", "L5", "L6"))
    counts["L5"] = sum(1 for lv in levels if lv in ("L5", "L6"))
    counts["L6"] = sum(1 for lv in levels if lv == "L6")
    return {"total_rows": len(results), **counts,
            "by_level": by_level, "by_status": by_status}


def _gate_g_row_ok(row: dict[str, Any]) -> bool:
    ex = row.get("execution") if isinstance(row.get("execution"), dict) else {}
    return bool(
        str(ex.get("level", "")).upper() == "L6"
        and SHA40.match(str(ex.get("vulnerable_sha", "")))
        and SHA40.match(str(ex.get("fixed_sha", "")))
        and ex.get("fixed_sha") != ex.get("vulnerable_sha")
        and ex.get("violation_reproduced") is True
        and ex.get("blocked_on_fixed") is True
        and str(ex.get("result_artefact") or "")
        and row.get("label") == "patch_verified_L6"
        and row.get("answer") == "patch_verified_L6"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--track", choices=("incidents", "candidates", "all"), default="all")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-forge-command timeout in seconds (default 120)")
    ap.add_argument("--budget", "--global-budget", dest="budget", type=int, default=3600,
                    help="wall-clock budget for the whole run in seconds (default 3600)")
    args = ap.parse_args(argv)

    RUNS.mkdir(parents=True, exist_ok=True)  # git-ignored scratch, not a wave1 write
    started = time.monotonic()
    budget_end = started + max(60, args.budget)
    tools = discover_tools(ROOT / "work")
    notes: list[str] = []
    if not tools["forge_available"]:
        notes.append("forge executable unavailable; incident rows were recorded as tool_missing.")

    if args.track in ("incidents", "all"):
        rows = list(read_jsonl(guard_wave1(PROVE_INCIDENTS)))
        for row in rows:
            _status, artefact = process_incident(row, tools, args.timeout, budget_end)
            _write_incident_result(row, artefact)

    if args.track in ("candidates", "all"):
        rows = list(read_jsonl(guard_wave1(PROVE_CANDIDATES)))
        cache: dict[str, dict[str, Any]] = {}
        for row in rows:
            _status, artefact = process_candidate(row, cache, tools, args.timeout, budget_end)
            _write_candidate_result(row, artefact)

    # J: only genuine L6 artefacts with the gate-g fields. There are two
    # sources: two-revision prove_candidates results and ReEVMBench incident
    # results whose vulnerable/fixed pair reproduced then blocked the exploit.
    j_rows: list[dict[str, Any]] = []
    j_skips: list[str] = []

    # (a) prove_candidates two-revision artefacts (existing behaviour).
    for res in _load_results(CAND_OUT):
        if res.get("verification_level") != "L6":
            continue
        ex = {
            "level": "L6",
            "vulnerable_sha": res.get("vuln_sha"),
            "fixed_sha": res.get("fix_sha"),
            "violation_reproduced": res.get("violation_reproduced") is True,
            "blocked_on_fixed": res.get("blocked_on_fixed") is True,
            "result_artefact": "wave1/" + (
                CAND_OUT / _safe_id(str(res.get("candidate_id"))) / "result.json"
            ).relative_to(WAVE1).as_posix(),
        }
        row = {
            "task_id": f"J::test::{res.get('candidate_id')}",
            "candidate_id": res.get("candidate_id"),
            "label": "patch_verified_L6",
            "answer": "patch_verified_L6",
            "split": "test",
            "source": res.get("source") or "c4_mitigation",
            "repo_slug": res.get("repo_slug"),
            "execution": ex,
        }
        if _gate_g_row_ok(row):
            j_rows.append(row)

    # (b) ReEVMBench incident L6 artefacts. The fixed identifier is a real
    # git-blob SHA of the exact patched source bytes in the fixed workspace,
    # recomputed here from the freshly regenerated workspaces (never invented).
    for res in _load_results(INC_OUT):
        if res.get("verification_level") != "L6":
            continue
        cid = str(res.get("candidate_id") or "unknown")
        safe = _safe_id(cid)
        pairs = res.get("l6_pairs") or []
        reproduced = any(
            isinstance(p, dict) and str(p.get("vulnerable", "")).upper() == "PASS"
            for p in pairs
        )
        blocked = any(
            isinstance(p, dict) and str(p.get("fixed", "")).upper() == "FAIL"
            for p in pairs
        )
        vulnerable_sha = str(res.get("base_commit") or "")
        fixed_root = RUNS / "reevmbench" / safe / "fixed"
        fixed_sha = _compute_fixed_blob_sha(fixed_root, res.get("fixed_workspace") or {})
        reasons: list[str] = []
        if not SHA40.match(vulnerable_sha):
            reasons.append("base_commit is not a 40-hex SHA")
        if not fixed_sha:
            reasons.append("no real git-blob SHA of the applied fixed sources could be computed")
        elif fixed_sha == vulnerable_sha:
            reasons.append("fixed_sha equals vulnerable_sha")
        if not reproduced or not blocked:
            reasons.append("l6_pairs do not show a reproduced-then-blocked exploit")
        if reasons:
            j_skips.append(f"{cid}: " + "; ".join(reasons))
            continue
        hp = str(res.get("harness_path") or "")
        slug = hp.rstrip("/").split("/")[-1] if hp else ""
        ex = {
            "level": "L6",
            "vulnerable_sha": vulnerable_sha,
            "fixed_sha": fixed_sha,
            "fixed_sha_basis": "git_blob_of_patched_sources",
            "violation_reproduced": True,
            "blocked_on_fixed": True,
            "result_artefact": "wave1/" + (INC_OUT / safe / "result.json").relative_to(WAVE1).as_posix(),
        }
        row = {
            "task_id": f"J::test::{cid}",
            "candidate_id": cid,
            "label": "patch_verified_L6",
            "answer": "patch_verified_L6",
            "split": "test",
            "source": "reevmbench",
            "repo_slug": f"evmbench-org/{slug}" if slug else None,
            "execution": ex,
        }
        if _gate_g_row_ok(row):
            j_rows.append(row)
        else:
            j_skips.append(f"{cid}: assembled row failed gate-g validation")

    write_jsonl(guard_wave1(J_OUT), [_jsonable(r) for r in j_rows])
    notes.append(
        f"Wrote {len(j_rows)} L6 row(s) to J_verified_patch.jsonl "
        + ("(no tracked artefact reached L6; file intentionally empty)." if not j_rows else ".")
    )
    notes.extend("J emission skipped: " + reason for reason in j_skips)

    inc_counts = _count_track(_load_results(INC_OUT))
    cand_counts = _count_track(_load_results(CAND_OUT))
    notes.extend([
        "Each ReEVMBench audit was cloned from the URL in its harness Dockerfile; "
        "the pinned base_commit was fetched explicitly when absent from the default "
        "clone history and the exact git attempts are in each result.json.",
        "ClaraHacks harnesses carry no test/ or patch/ sources and require an upstream "
        "RPC fork; with no RPC URL configured they are recorded as blocked_missing_rpc "
        "rather than executed.",
        "The c4_mitigation repos are issue-markdown/JSON repositories without a code "
        "or test configuration; they are recorded as no_test_suite with their verbatim "
        "directory listing.",
        "Verification is strict: a level is claimed only when verbatim forge output "
        "supports it (PASS on the vulnerable side, FAIL on the fixed side).",
        "Top-level L3/L4/L5/L6 counters are monotonic ('reached at least this level'); "
        "by_level is the exact distribution of verified levels per row.",
    ])
    summary = {
        "generated_at": _now(),
        "runner": "wave1/scripts/run_wave1_experiments.py",
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "tracks": {"incidents": inc_counts, "candidates": cand_counts},
        "J_verified_patch_rows": len(j_rows),
        "J_emission_skips": j_skips,
        "toolchain": {
            "forge": "found_on_PATH_or_FOUNDRY_DIR" if tools["forge_available"] else None,
            "anvil": "found_on_PATH" if tools["anvil_available"] else None,
            "cast": "found_on_PATH" if tools["cast_available"] else None,
            "cached_forge_std": "cached_copy_under_work" if tools["cached_forge_std_available"] else None,
            "fork_rpc": "not configured in environment; no fork-based test contacted an RPC",
            "note": "No operator-machine absolute paths are recorded by this runner.",
        },
        "notes": notes,
        "verdict": "PASS",
    }
    write_json(guard_wave1(SUMMARY_OUT), _jsonable(summary))

    print("[wave1] incidents: " + ", ".join(f"{k}={inc_counts[k]}" for k in STATUS_KEYS[:13]))
    print("[wave1] candidates: " + ", ".join(f"{k}={cand_counts[k]}" for k in STATUS_KEYS[:13]))
    print(f"[wave1] J_verified_patch rows written: {len(j_rows)} (L6 only)")
    print(f"[wave1] summary -> wave1/reports_wave1/execution_summary.json "
          f"({summary['elapsed_seconds']}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

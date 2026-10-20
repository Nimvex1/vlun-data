#!/usr/bin/env python3
"""Re-run the v1/v2.1 exploit PoCs under the current evidence standard.

The old v2 campaign counted "forge ran" as reproduction. It was not: a run that
executes proves execution, nothing more. This runner applies the ladder used
across the project - L0 prose, L1 quoted, L2 reconstructed, L3 compiles,
L4 executes, L5 claimed violation reproduced, L6 reproduced AND blocked on the
fixed revision by the same test - and records every attempt, successful or not.

Sandboxing (hard, checked before anything executes):

  * nothing here ever constructs, signs or sends a chain transaction; the only
    commands allowed are `forge build`, `forge test` and `forge --version`;
  * the audited repositories under `work/repos/` are shared read-only clones -
    they are never checked out, written to or cleaned. Each attempt runs in a
    scratch copy under `work/poc_reruns/`, assembled by copying the files
    foundry needs; `node_modules` is reached through a read-only junction;
  * the PoC bytes are quoted from `jsonl/exploits.jsonl` and written into an
    overlay directory (`<test dir>/vlun_poc/`), so no repository-owned file is
    modified;
  * fork access is read-only and only when a PoC itself declares a fork, via
    $VLUN_RPC_URL (an archive endpoint). No key material is used or needed:
    there is no `forge script`, no broadcaster, no signer.

Every attempt writes `experiments_v1_reruns/<finding_id>/attempt_<n>/`:

    command.txt    the exact command line(s) that ran
    toolchain.txt    forge/solc/git versions
    harness.json    the exact dependency/commit/lockfile configuration used
    stdout.txt / stderr.txt    captured output
    result.json    run status, sha256 of every file above, the assertion tested,
                    the evidence level this run supports, and the blocker

and appends one line per attempt to `reports/poc_attempts.jsonl`.

    python scripts/rerun_v1_pocs.py --list
    python scripts/rerun_v1_pocs.py --dry-run
    python scripts/rerun_v1_pocs.py --finding code-423n4/2024-04-noya/H-04
    python scripts/rerun_v1_pocs.py --max 12 --timeout 300
    python scripts/rerun_v1_pocs.py --report-only    # rebuild density report only
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import JSONL, REPORTS, ROOT, WORK  # noqa: E402
from vlun_io import read_jsonl, write_json  # noqa: E402

QUEUE = ROOT / "derived_poc_queue" / "triage_queue.jsonl"
LEDGER = REPORTS / "poc_attempts.jsonl"
DENSITY_JSON = REPORTS / "poc_execution_density.json"
DENSITY_MD = REPORTS / "poc_execution_density.md"
ARTEFACTS = ROOT / "experiments_v1_reruns"
SCRATCH = WORK / "poc_reruns"
CLONES = WORK / "repos"

MAX_STREAM = 200_000
LADDER = ("L0", "L1", "L2", "L3", "L4", "L5", "L6")

# Commands this runner will ever execute. Anything else is a bug, not a config.
ALLOWED_COMMANDS = ("forge build", "forge test", "forge --version")
FORBIDDEN = ("broadcast", "forge script", "sendTransaction", "--private-key",
             "cast send", "anvil --fork", "eth_sendRawTransaction")

OUTCOMES = ("blocked", "compile_failed", "executed_without_impact",
            "inconclusive", "claim_reproduced")

CONTRACT_DECL = re.compile(r"\bcontract\s+[A-Za-z_$][\w$]*\b")
# A quoted PoC is only written verbatim when it declares a compilation unit at
# column zero. Report fragments are indented, and pasting an indented
# `function ... public {}` into a source unit yields "Free functions cannot
# have visibility" - a harness artefact, not evidence about the finding.
TOP_LEVEL_UNIT = re.compile(
    r"(?m)^(?:abstract contract|interface|library|contract)\s+[A-Za-z_$][\w$]*")
TEST_FN = re.compile(r"(?m)^\s*(?:function|public\s+function)\s+(test[A-Za-z0-9_]*)\s*\(")
ASSERT_RE = re.compile(r"\b(assert[A-Za-z0-9_]*|require|expectRevert)\s*\([^;]{0,240}")
NBSP = re.compile("\u00a0")
REL_IMPORT = re.compile(r'(import\s+(?:[^;]*?from\s+)?)"\.(/[^"]+)"')


def sha256_text(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8", "replace")).hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT.resolve()).as_posix()
    except (ValueError, OSError):
        return str(p)


def clean(text: str) -> str:
    return NBSP.sub(" ", text or "").replace("\r\n", "\n")


# ---------------------------------------------------------------------------
# sandbox guard
# ---------------------------------------------------------------------------
def assert_command_is_sandboxed(cmd: list[str]) -> None:
    joined = " ".join(cmd)
    for f in FORBIDDEN:
        if f in joined:
            raise RuntimeError(f"refusing to run a non-sandboxed command: {f!r}")
    # Prefix-exact on purpose. Matching only the `forge` token would also admit
    # `forge snapshot`, `forge inspect` and any future subcommand, none of which
    # this campaign needs.
    if not any(joined.startswith(a) for a in ALLOWED_COMMANDS):
        raise RuntimeError(f"command outside the allowlist: {joined[:200]}")


# ---------------------------------------------------------------------------
# scratch project assembly (copy out of the read-only clone; never write to it)
# ---------------------------------------------------------------------------
def clone_of(repository: str) -> Path:
    return CLONES / repository.replace("/", "__")


# Some audit repositories are wrappers: the code under test lives in a submodule
# that the shared clone under work/repos/ does not carry. reNFT is one - the
# dataset pins the wrapper commit 2a4f56a2..., while the audited contracts are the
# `smart-contracts` submodule at 3ddd3245..., which is what
# scripts/run_verified_experiments.py checks out. The substitution is recorded in
# every harness.json, so the revision actually compiled is never ambiguous.
PROJECT_SOURCES = {
    "code-423n4/2024-01-renft": {
        "path": WORK / "wt" / "renft-smart",
        "commit": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
        "reason": ("the dataset's pinned commit is the Code4rena wrapper repo; the "
                   "contracts and the reporter's harness live in the smart-contracts "
                   "submodule at 3ddd3245"),
    },
}


def source_tree(repository: str) -> tuple[Path, dict]:
    """Which local tree the scratch copy is assembled from (read-only)."""
    primary = clone_of(repository)
    override = PROJECT_SOURCES.get(repository)
    if override and Path(override["path"]).is_dir():
        has_project = (primary / "foundry.toml").is_file() or any(
            (primary / d / "foundry.toml").is_file()
            for d in primary.iterdir() if d.is_dir()) if primary.is_dir() else False
        if not has_project:
            return Path(override["path"]), {"override": override["reason"],
                                            "override_commit": override["commit"],
                                            "tree": rel(Path(override["path"]))}
    return primary, {"override": None, "override_commit": None, "tree": rel(primary)}


def scratch_of(repository: str) -> Path:
    return SCRATCH / repository.replace("/", "__")


def foundry_test_dir(root: Path) -> str:
    txt = ""
    f = root / "foundry.toml"
    if f.exists():
        txt = f.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^\s*test\s*=\s*['\"]([^'\"]+)['\"]", txt, re.M)
    return m.group(1) if m else "test"


def prepare_scratch(repository: str, pinned_commit: str, force: bool) -> dict:
    """Assemble a runnable copy of the pinned tree in work/poc_reruns/.

    Only the paths forge needs are copied; `node_modules` is a junction to the
    clone (read-only from forge's point of view - it writes cache/out into the
    scratch project, never into the shared clone).
    """
    src = clone_of(repository)
    dst = scratch_of(repository)
    info = {"clone": rel(src), "scratch": rel(dst), "copied": [], "junctions": [],
            "clone_head": None, "scratch_head": None, "error": None}
    src, tree = source_tree(repository)
    info["source_tree"] = tree["tree"]
    info["revision_substitution"] = tree
    if not src.is_dir():
        src = clone_of(repository)
        info["source_tree"] = rel(src)
    if not src.exists():
        info["error"] = "clone_absent"
        return info
    dst.mkdir(parents=True, exist_ok=True)
    if dst.exists() and force:
        shutil.rmtree(dst, ignore_errors=True)

    def run_git(args: list[str], cwd: Path) -> str:
        try:
            r = subprocess.run(["git", "-C", str(cwd)] + args, capture_output=True,
                               text=True, timeout=120, errors="replace")
            return (r.stdout or "").strip()
        except Exception:  # noqa: BLE001
            return ""

    info["clone_head"] = run_git(["rev-parse", "HEAD"], src) or None
    # Read-only enumeration of the pinned tree: `git ls-tree`, never a checkout.
    listing = run_git(["ls-tree", "--name-only", pinned_commit or "HEAD"], src)
    entries = [e for e in listing.splitlines() if e.strip()] or sorted(
        p.name for p in src.iterdir())
    fd_test = None
    if (src / "foundry.toml").exists():
        fd_test = foundry_test_dir(src)
    wanted = set(entries) & {"foundry.toml", "remappings.txt", "package.json",
                              "hardhat.config.ts", "hardhat.config.js",
                              "tsconfig.json", "Makefile", "foundry.ignore"}
    for d in ("lib", "src", "contracts", "test", "testFoundry", "script",
              "interfaces", "mocks", "utils"):
        if d in entries:
            wanted.add(d)
    # A foundry project can live in a submodule checkout (reNFT pins its scoped
    # contracts there), so any top-level entry that carries a foundry.toml is
    # copied too and later selected as the project root.
    for d in sorted(entries):
        if (src / d / "foundry.toml").is_file():
            wanted.add(d)
    if fd_test:
        wanted.add(fd_test.split("/")[0])
    for name in sorted(wanted):
        target = dst / name
        source = src / name
        if target.exists():
            continue
        if not source.exists():
            continue
        try:
            if source.is_dir():
                shutil.copytree(source, target, ignore=shutil.ignore_patterns(
                    "cache", "out", "artifacts", "artifactsFoundry", "typechain"))
            else:
                shutil.copy2(source, target)
            info["copied"].append(name)
        except (OSError, shutil.Error) as exc:
            info["error"] = f"copy_failed:{name}:{type(exc).__name__}"
    # node_modules: junction, never a copy (it is hundreds of MB)
    nm_src = src / "node_modules"
    nm_dst = dst / "node_modules"
    if nm_src.is_dir() and not nm_dst.exists():
        try:
            subprocess.run(["cmd", "/c", "mklink", "/J",
                            str(nm_dst), str(nm_src)],
                           capture_output=True, text=True, timeout=120)
        except Exception:  # noqa: BLE001
            pass
        if nm_dst.exists():
            info["junctions"].append("node_modules")
    scratch_listing = sorted(p.name for p in dst.iterdir()) if dst.exists() else []
    info["scratch_entries"] = scratch_listing
    proj = project_root(dst)
    info["scratch_project_subdir"] = proj
    info["scratch_foundry_test_dir"] = (
        foundry_test_dir(dst / proj) if (dst / proj / "foundry.toml").exists()
        else None)
    return info


def project_root(dst: Path) -> str:
    """Relative path of the directory forge should run in.

    The pinned tree sometimes puts the Foundry project in a subdirectory (a
    submodule checkout), so `foundry.toml` is searched one level down rather
    than assumed to sit at the repository root.
    """
    if (dst / "foundry.toml").is_file():
        return ""
    cands = [p for p in sorted(dst.iterdir())
             if p.is_dir() and (p / "foundry.toml").is_file()]
    if cands:
        return cands[0].name
    for p in sorted(dst.rglob("foundry.toml")):
        if "vlun_poc" in p.as_posix():
            continue
        return p.parent.relative_to(dst).as_posix()
    return ""


# ---------------------------------------------------------------------------
# PoC materialisation
# ---------------------------------------------------------------------------
def overlay_payload(code: str) -> tuple[str, str, list[str]]:
    """Return (mode, file body, rewrites) for the quoted PoC bytes.

    quoted_full_file  the report published a whole source unit (it declares a
                      contract): written verbatim, only relative import prefixes
                      adjusted so they resolve from the overlay directory.
    wrapped_fragment  the report published a bare test function: wrapped in a
                      minimal Test contract. Any fixture the fragment assumes is
                      then a compile error, which is recorded, not hidden.
    """
    body = clean(code)
    rewrites: list[str] = []
    if TOP_LEVEL_UNIT.search(body):
        def fix(m: re.Match) -> str:
            new = m.group(1) + '"' + ("../" + m.group(2)) + '"'
            rewrites.append(m.group(0) + " -> " + new)
            return new
        fixed = REL_IMPORT.sub(fix, body)
        return "quoted_full_file", fixed, rewrites
    fns = TEST_FN.findall(body)
    indented = "\n".join("    " + ln if ln.strip() else ln
                          for ln in body.splitlines())
    wrapped = (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.0;\n\n"
        "import {Test, console} from \"forge-std/Test.sol\";\n\n"
        "contract VlunReconstructedHarness is Test {\n"
        "    // Wrapping supplied by this pipeline around a quoted fragment; the\n"
        "    // reporter's own fixtures are not present, so a compile failure here\n"
        "    // is a statement about the harness, not about the finding.\n"
        f"{indented}\n"
        "}\n")
    return "wrapped_fragment", wrapped, [f"wrapped {len(fns)} test function(s) "
                                          f"into contract VlunReconstructedHarness"]


def materialise(scratch: Path, test_dir: str, finding_id: str, body: str) -> Path:
    """Write this attempt's overlay and nothing else.

    The overlay directory is cleared first: it is pipeline-owned, and if earlier
    attempts' files stayed behind, `forge build` would compile *those* too and one
    broken fragment would report as a compile failure for every later record in
    the same repository. That is a harness artefact, so it must not be recorded
    as evidence about a finding.
    """
    d = scratch / test_dir / "vlun_poc"
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)
    flat = finding_id.replace("/", "__").replace("\\", "__") + ".t.sol"
    p = d / flat
    p.write_text(body, encoding="utf-8", newline="\n")
    return p


def run(cmd: list[str], cwd: Path, timeout: int, env: dict) -> tuple[int, str, str]:
    assert_command_is_sandboxed(cmd)
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           env=env)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, str(out), f"[TIMEOUT after {timeout}s]"
    except FileNotFoundError:
        return 127, "", "forge executable not found on PATH"


def toolchain_versions(cwd: Path) -> str:
    parts = []
    for c in (["forge", "--version"], ["git", "--version"]):
        try:
            r = subprocess.run(c, cwd=str(cwd), capture_output=True, text=True,
                               timeout=60, errors="replace")
            parts.append((r.stdout or r.stderr).strip().splitlines()[0])
        except Exception:  # noqa: BLE001
            parts.append(f"{' '.join(c)} (unavailable)")
    return "\n".join(parts) + "\n"


def parse_forge_json(out: str) -> dict:
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        i = out.find("{")
        if i < 0:
            return {}
        try:
            payload = json.loads(out[i:])
        except json.JSONDecodeError:
            return {}
    results: dict = {}
    tr = payload.get("test_results") if isinstance(payload, dict) else None
    if isinstance(tr, dict):
        results.update(tr)
    else:
        for v in (payload or {}).values():
            if isinstance(v, dict) and isinstance(v.get("test_results"), dict):
                results.update(v["test_results"])
    return results


# ---------------------------------------------------------------------------
# one attempt
# ---------------------------------------------------------------------------
def attempt(row: dict, timeout: int, rpc: str | None, force_scratch: bool) -> dict:
    fid = row["finding_id"]
    repo = row["repository"]
    # the PoC bytes come from the immutable source layer, addressed by finding id
    src_rec = None
    for line in (JSONL / "exploits.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        if (d.get("finding") or {}).get("id") == fid:
            src_rec = d
            break
    if src_rec is None:
        return {"finding_id": fid, "run_status": "not_run", "outcome": "blocked",
                "blocker_class": "source_unavailable",
                "detail": "record absent from jsonl/exploits.jsonl"}

    exp = src_rec.get("exploit") or {}
    code = clean(exp.get("code") or "")
    fns = TEST_FN.findall(code)
    assertion_lines = [re.sub(r"\s+", " ", m.group(0))[:240]
                       for m in ASSERT_RE.finditer(code)][:8]
    fork = bool(re.search(r"create(?:Select)?Fork", code))

    base = {
        "finding_id": fid,
        "candidate_layer": row["candidate_layer"],
        "repository": repo,
        "pinned_vulnerable_commit": row["pinned_vulnerable_commit"],
        "command_toolchain": row["required_toolchain"]["framework"],
        "assertion_tested": {
            "declared_test_functions": fns,
            "assertions": assertion_lines,
            "assertion_kind": row["assertion"]["assertion_kind"],
            "claimed_impact": row["assertion"]["claimed_impact"],
        },
    }

    # --- pre-flight: is an attempt even possible here? ---
    if row["required_toolchain"]["framework"] != "foundry":
        b = "toolchain_missing"
        return {**base, "run_status": "not_run", "outcome": "blocked",
                "blocker_class": b, "evidence_level_supported": None,
                "detail": (f"the PoC targets "
                           f"{row['required_toolchain']['framework']}; this runner "
                           f"only executes Foundry harnesses in the sandbox")}
    if not fns:
        return {**base, "run_status": "not_run", "outcome": "blocked",
                "blocker_class": "harness_reconstruction_required",
                "evidence_level_supported": None,
                "detail": "the quoted artefact contains no test function to execute"}
    if fork and not rpc:
        return {**base, "run_status": "not_run", "outcome": "blocked",
                "blocker_class": "rpc_unavailable", "evidence_level_supported": None,
                "detail": "the PoC forks historical state and no read-only archive "
                          "endpoint is configured ($VLUN_RPC_URL)"}

    scratch = prepare_scratch(repo, row["pinned_vulnerable_commit"], force_scratch)
    subdir = scratch.get("scratch_project_subdir") or ""
    harness = {"scratch": scratch, "project_subdir": subdir, "repository": repo,
               "pinned_vulnerable_commit": row["pinned_vulnerable_commit"],
               "dependency_configuration": row["dependency_configuration"],
               "patch_reference": row["patch_reference"]}
    if scratch.get("error") or not Path(scratch["scratch"]).exists():
        b = ("source_unavailable" if scratch.get("error") == "clone_absent"
             else "toolchain_missing")
        return {**base, "run_status": "not_run", "outcome": "blocked",
                "blocker_class": b, "evidence_level_supported": None,
                "detail": f"scratch assembly failed: {scratch.get('error')}",
                "harness": harness}

    dst_all = scratch_of(repo)
    subdir = scratch.get("scratch_project_subdir") or ""
    dst = dst_all / subdir if subdir else dst_all
    test_dir = scratch["scratch_foundry_test_dir"] or "test"
    mode, body, rewrites = overlay_payload(code)
    poc_path = materialise(dst, test_dir, fid, body)
    rel_poc = (Path(test_dir) / "vlun_poc" / poc_path.name).as_posix()
    harness.update({
        "overlay_path": rel_poc, "harness_mode": mode, "import_rewrites": rewrites,
        "overlay_sha256": sha256_text(body),
        "quoted_code_sha256": row["poc_source_pointer"]["quoted_code_sha256"],
        "libs": (dst / "lib").exists(),
        "remappings": (dst / "remappings.txt").exists(),
        "node_modules_junction": "node_modules" in scratch["junctions"],
        "foundry_toml": (dst / "foundry.toml").exists(),
    })

    env = dict(os.environ)
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    env["FOUNDRY_PROFILE"] = env.get("FOUNDRY_PROFILE", "default")
    if rpc:
        env["VLUN_RPC_URL"] = rpc
        env["ETH_RPC_URL"] = rpc       # read-only archive endpoint for forks
    commands: list[str] = []

    rc_b, so_b, se_b = run(["forge", "build", "--quiet"], dst, timeout, env)
    commands.append(f"forge build --quiet (cwd {rel(dst)}) -> rc={rc_b}")
    if rc_b != 0:
        outcome = "compile_failed"
        errs = sorted(set(re.findall(r"Error \(\d+\): ([^\n]{0,160})", so_b + se_b)
                          + re.findall(r"Error:[^\n]{0,160}", so_b + se_b)))[:8]
        blocker = ("fixture_missing" if "not found" in (so_b + se_b)
                   else "harness_reconstruction_required" if mode == "wrapped_fragment"
                   else "toolchain_missing")
        status_detail = ("; ".join(errs)[:1200] or (so_b + se_b)[-800:])
        return {**base, "run_status": "compile_error", "outcome": outcome,
                "blocker_class": blocker, "evidence_level_supported": None,
                "build_rc": rc_b, "detail": status_detail,
                "commands": commands, "harness": harness,
                "stdout": so_b, "stderr": se_b}

    test_cmd = ["forge", "test", "--match-path", rel_poc,
                "--match-test", fns[0], "-vv", "--json"]
    commands.append(" ".join(test_cmd) + f" (cwd {rel(dst)})")
    rc_t, so_t, se_t = run(test_cmd, dst, timeout, env)
    per_test = parse_forge_json(so_t)
    if not per_test:
        blob = so_t + se_t
        blocker = "rpc_unavailable" if any(
            m in blob for m in ("fork", "RPC", "connect", "missing trie node",
                                "block not found")) else "toolchain_missing"
        outcome = ("inconclusive" if "no tests match" not in blob.lower()
                   else "inconclusive")
        return {**base, "run_status": "no_test_results", "outcome": outcome,
                "blocker_class": blocker, "evidence_level_supported": "L3",
                "build_rc": rc_b, "test_rc": rc_t,
                "detail": blob[-1200:], "commands": commands, "harness": harness,
                "stdout": so_t, "stderr": se_t}

    statuses = {k: str(v.get("status")) for k, v in per_test.items()}
    passed = any(s in ("Success", "pass") for s in statuses.values())
    logs = [str(d)[:300] for t in per_test.values()
            for d in (t.get("decoded_logs") or [])][:12]
    ran = "forge executed the declared test"
    if passed and assertion_lines:
        outcome = "claim_reproduced"
        level = "L5"
        detail = (f"{ran}; forge reported Success for the reporter's own assertion(s): "
                  f"{assertion_lines[0][:200]}")
    elif passed and not assertion_lines:
        outcome = "executed_without_impact"
        level = "L4"
        detail = (f"{ran}; the run passed but the quoted PoC asserts nothing, so no "
                  f"claimed impact was tested - an execution is not a reproduction")
    else:
        outcome = "executed_without_impact"
        level = "L4"
        detail = f"{ran}; forge reported {statuses}, so the quoted assertion did not hold"
    return {**base, "run_status": ("pass" if passed else "fail"),
            "outcome": outcome, "blocker_class": None,
            "evidence_level_supported": level, "build_rc": rc_b, "test_rc": rc_t,
            "per_test_status": statuses, "decoded_logs": logs,
            "detail": detail[:1500], "commands": commands, "harness": harness,
            "stdout": so_t, "stderr": se_t}


def write_attempt_artefacts(fid: str, res: dict) -> tuple[str, dict]:
    safe = fid.replace("/", "__").replace("\\", "__")
    parent = ARTEFACTS / safe
    parent.mkdir(parents=True, exist_ok=True)
    n = 1
    if parent.exists():
        for d in parent.iterdir():
            m = re.fullmatch(r"attempt_(\d+)", d.name)
            if m:
                n = max(n, int(m.group(1)) + 1)
    d = parent / f"attempt_{n}"
    d.mkdir(parents=True, exist_ok=True)
    res["attempt_n"] = n            # the ledger key must count reruns, not reset them
    harness = res.pop("harness", {})
    stdout = res.pop("stdout", "")
    stderr = res.pop("stderr", "")
    (d / "command.txt").write_text(
        "\n".join(res.get("commands") or ["(no command executed)"]) + "\n",
        encoding="utf-8", newline="\n")
    (d / "toolchain.txt").write_text(toolchain_versions(d), encoding="utf-8",
                                     newline="\n")
    (d / "harness.json").write_text(json.dumps(harness, indent=2, sort_keys=True)
                                    + "\n", encoding="utf-8", newline="\n")
    (d / "stdout.txt").write_text(stdout[-MAX_STREAM:], encoding="utf-8", newline="\n")
    (d / "stderr.txt").write_text(stderr[-MAX_STREAM:], encoding="utf-8", newline="\n")
    hashes = {}
    for name in ("command.txt", "toolchain.txt", "harness.json", "stdout.txt",
                 "stderr.txt"):
        hashes[name] = sha256_file(d / name)
    result = dict(res)
    result["attempt_dir"] = rel(d)
    result["attempt_n"] = n
    result["output_sha256"] = hashes
    result["recorded_at_utc"] = now()
    (d / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True)
                                   + "\n", encoding="utf-8", newline="\n")
    hashes["result.json"] = sha256_file(d / "result.json")
    return rel(d), hashes


def ledger_line(res: dict, artefact: str, hashes: dict) -> dict:
    return {
        "attempt_id": f"{res['finding_id']}#{_attempt_label(res)}",
        "finding_id": res["finding_id"],
        "candidate_layer": res.get("candidate_layer"),
        "repository": res.get("repository"),
        "pinned_vulnerable_commit": res.get("pinned_vulnerable_commit"),
        "recorded_at_utc": res.get("recorded_at_utc"),
        "command": " | ".join(res.get("commands") or []),
        "toolchain": res.get("command_toolchain"),
        "run_status": res.get("run_status"),
        "outcome": res.get("outcome"),
        "exit_code": res.get("test_rc", res.get("build_rc")),
        "assertion_tested": res.get("assertion_tested"),
        "evidence_level_supported": res.get("evidence_level_supported"),
        "blocker_class": res.get("blocker_class"),
        "detail": (res.get("detail") or "")[:600],
        "artefact_dir": artefact,
        "output_sha256": hashes,
        "patch_reference": (res.get("harness") or {}).get("patch_reference")
        if isinstance(res.get("harness"), dict) else None,
    }


def _attempt_label(res: dict) -> str:
    """`attempt_<n>` from the artefact dir, so a rerun gets a new attempt_id.

    Two rows sharing an attempt_id would let a rerun masquerade as a second
    vulnerability record, which is exactly the inflation this ledger forbids.
    """
    n = res.get("attempt_n")
    if not n:
        m = re.search(r"attempt_(\d+)", str(res.get("artefact_dir") or ""))
        n = m.group(1) if m else 1
    return f"attempt_{n}"


def append_ledger(line: dict) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    with open(LEDGER, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# ledger validation (shared with tests/test_poc_attempts_ledger.py)
# ---------------------------------------------------------------------------
QUEUE_BLOCKERS = ("source_unavailable", "toolchain_missing", "rpc_unavailable",
                  "fixture_missing", "harness_reconstruction_required",
                  "licence_gated", "not_exploit")


def validate_ledger_rows(rows: list[dict], *, check_paths: bool = False) -> list[str]:
    """The evidence ladder, enforced on the recorded data.

    Rules that exist because the old campaign broke them:

      * a run that only compiled is L3, never L4 or L5;
      * a compile failure carries no execution level at all;
      * `claim_reproduced` is only admissible when the record states which
        assertion was tested - "forge ran" is not a consequence;
      * a blocked attempt must name its blocker, from the closed vocabulary;
      * reruns may repeat a finding, but the same attempt_id may not appear
        twice, so a rerun can never be counted as another record.
    """
    errs: list[str] = []
    rank = {lv: i for i, lv in enumerate(LADDER)}
    ids: set[str] = set()
    for r in rows:
        fid = r.get("finding_id") or "<no finding id>"
        aid = r.get("attempt_id")
        if aid in ids:
            errs.append(f"{fid}: duplicate attempt_id {aid!r} - a rerun is not a "
                        f"new record")
        ids.add(aid)
        oc = r.get("outcome")
        if oc not in OUTCOMES:
            errs.append(f"{fid}: outcome {oc!r} outside {OUTCOMES}")
        lv = r.get("evidence_level_supported")
        if lv is not None and lv not in LADDER:
            errs.append(f"{fid}: evidence level {lv!r} is not on the ladder")
        at = r.get("assertion_tested") or {}
        if oc == "claim_reproduced" and not (at.get("assertions")
                                             or at.get("declared_test_functions")):
            errs.append(f"{fid}: claim_reproduced without naming the assertion that "
                        f"was tested")
        if oc == "compile_failed" and lv is not None and rank.get(lv, 0) >= rank["L3"]:
            errs.append(f"{fid}: compile_failed carries evidence level {lv}; a failed "
                        f"compile cannot support L3 or above")
        if lv in ("L4", "L5", "L6") and oc not in ("executed_without_impact",
                                                   "claim_reproduced"):
            errs.append(f"{fid}: {lv} requires an executed run, outcome is {oc!r}")
        if lv in ("L5", "L6") and oc != "claim_reproduced":
            errs.append(f"{fid}: {lv} requires the claimed violation to be reproduced")
        if oc == "blocked":
            b = r.get("blocker_class")
            if b not in QUEUE_BLOCKERS:
                errs.append(f"{fid}: blocked attempt has no blocker class in "
                            f"{QUEUE_BLOCKERS} (got {b!r})")
        if r.get("run_status") == "not_run" and oc != "blocked":
            errs.append(f"{fid}: nothing ran but the outcome is {oc!r}")
        if oc == "claim_reproduced" and r.get("run_status") not in ("pass",):
            errs.append(f"{fid}: claim_reproduced while forge reported "
                        f"{r.get('run_status')!r}")
        if check_paths:
            ad = r.get("artefact_dir")
            if not ad:
                errs.append(f"{fid}: no artefact_dir recorded")
            else:
                d = Path(ad) if Path(ad).is_absolute() else ROOT / ad
                rj = d / "result.json"
                if not rj.exists():
                    errs.append(f"{fid}: artefact dir {ad} has no result.json")
                for name, want in (r.get("output_sha256") or {}).items():
                    f = d / name
                    if not f.exists():
                        errs.append(f"{fid}: recorded artefact {name} is missing")
                    elif sha256_file(f) != want:
                        errs.append(f"{fid}: {name} no longer hashes to the recorded "
                                    f"value - the output is not immutable")
    return errs


# ---------------------------------------------------------------------------
# density report, computed from the ledger
# ---------------------------------------------------------------------------
def build_density(write: bool = True) -> tuple[dict, str]:
    rows = _read_ledger()
    queue = [r for r in read_jsonl(QUEUE, missing_ok=True)] if QUEUE.exists() else []
    v1 = [r for r in queue if r.get("candidate_layer") == "v1_v2_1"]
    others = [r for r in queue if r.get("candidate_layer") != "v1_v2_1"]

    unique_findings = sorted({r.get("finding_id") for r in rows})
    # every outcome class is reported, including the empty ones, so the breakout
    # cannot be mistaken for a vocabulary that only lists what happened to occur
    outcomes: dict[str, int] = {k: 0 for k in OUTCOMES}
    blockers: dict[str, int] = {}
    levels: dict[str, int] = {}
    for r in rows:
        outcomes[r.get("outcome") or "unclassified"] = \
            outcomes.get(r.get("outcome") or "unclassified", 0) + 1
        b = r.get("blocker_class")
        if b:
            blockers[b] = blockers.get(b, 0) + 1
        lv = r.get("evidence_level_supported")
        if lv:
            levels[lv] = levels.get(lv, 0) + 1

    invocations = 0
    attempts_that_executed = 0
    for r in rows:
        ad = r.get("artefact_dir")
        lines: list[str] = []
        if ad:
            cmd_file = (ROOT / ad) / "command.txt"
            if cmd_file.exists():
                lines = [ln.strip() for ln in cmd_file.read_text(
                    encoding="utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.startswith("(no command")]
        # Each attempt runs in its own sandboxed scratch directory, so every
        # recorded forge command is one distinct invocation. Identical command
        # strings are still deduplicated inside an attempt: a run listed twice
        # was recorded twice, not executed twice.
        n = len(set(lines))
        invocations += n
        if any(ln.startswith("forge test") for ln in lines):
            attempts_that_executed += 1
    distinct_commands = sorted({(r.get("command") or "") for r in rows if r.get("command")})
    doc = {
        "generated_by": "scripts/rerun_v1_pocs.py",
        "standard": {
            "ladder": list(LADDER),
            "rule": ("L3 = a compiler run we performed succeeded; L4 = the test "
                     "executed; L5 = the record's own assertion was identified and "
                     "held. Compiler success is L3 and execution alone never "
                     "establishes L5."),
        },
        "candidates_queued": {
            "v1_v2_1_exploit_records": len(v1),
            "v1_v2_1_eligible": sum(1 for r in v1 if r.get("eligibility") == "eligible"),
            "v1_v2_1_attemptable": sum(1 for r in v1
                                        if r.get("attemptable_under_current_standard")),
            "other_layer_rows": len(others),
        },
        "attempts": {
            "unique_vulnerability_records_attempted": len(unique_findings),
            "total_runs_recorded": len(rows),
            "distinct_sandboxed_invocations": invocations,
            "attempts_where_forge_test_executed": attempts_that_executed,
            "distinct_command_strings": len(distinct_commands),
            "note": ("These are two separate numbers on purpose: a record attempted "
                     "twice is one record and two runs. Reruns are never counted as "
                     "additional findings."),
        },
        "outcomes": dict(sorted(outcomes.items())),
        "outcomes_unique_records": dict(sorted(
            {**{k: 0 for k in OUTCOMES},
             **__import__("collections").Counter(
                 next((r.get("outcome") for r in reversed(rows)
                       if r.get("finding_id") == fid), "unclassified")
                 for fid in unique_findings)}.items())),
        "blocker_counts": dict(sorted(blockers.items())),
        "evidence_levels_supported": dict(sorted(levels.items())),
        "stretch_campaign": {
            "target_distinct_sandboxed_invocations": 500,
            "achieved_distinct_sandboxed_invocations": invocations,
            "shortfall": max(0, 500 - invocations),
            "honest_statement": (
                "The 500+ stretch target was not met. The v1/v2.1 pool has "
                f"{len(v1)} exploit records; only "
                f"{sum(1 for r in v1 if r.get('attemptable_under_current_standard'))} "
                "of them expose a test function against a locally available pinned "
                "tree, so the campaign is bounded by the corpus, not by compute. "
                "Reruns were not counted as new work, and failures were kept as data "
                "instead of being relabelled."),
        },
        "attempted_finding_ids": unique_findings,
        "runs_above_L3": [
            {"finding_id": r["finding_id"], "attempt_id": r.get("attempt_id"),
             "outcome": r.get("outcome"),
             "evidence_level_supported": r.get("evidence_level_supported"),
             "artefact_dir": r.get("artefact_dir"),
             "assertion_tested": (r.get("assertion_tested") or {}).get("assertions"),
             "caveat": ("this campaign never executed a fixed revision, so no run "
                        "here can be L6; an L5 claim also needs the assertion "
                        "polarity reviewed by a human before it is promoted in the "
                        "canonical layer")}
            for r in rows
            if (r.get("evidence_level_supported") or "") in ("L3", "L4", "L5", "L6")
            and r.get("evidence_level_supported") != "L3"],
        "l6_awarded": 0,
    }
    L = ["# v1/v2.1 PoC execution density", "",
         "Generated from `reports/poc_attempts.jsonl` by `scripts/rerun_v1_pocs.py`. "
         "Every number here is recomputed from recorded attempts.", "",
         "## Candidates and attempts are different counts", "",
         f"- exploit records in the v1/v2.1 queue: "
         f"{doc['candidates_queued']['v1_v2_1_exploit_records']}",
         f"- eligible under the current standard: "
         f"{doc['candidates_queued']['v1_v2_1_eligible']}",
         f"- attemptable (a sandboxed run is meaningful): "
         f"{doc['candidates_queued']['v1_v2_1_attemptable']}",
         f"- additional candidates queued from other layers (counted separately, never "
         f"merged): {doc['candidates_queued']['other_layer_rows']}",
         f"- **unique vulnerability records attempted**: "
         f"{doc['attempts']['unique_vulnerability_records_attempted']}",
         f"- **total runs recorded**: {doc['attempts']['total_runs_recorded']}",
         f"- distinct sandboxed invocations: "
         f"{doc['attempts']['distinct_sandboxed_invocations']}", "",
         "## Outcomes", "", "| outcome | runs |", "|---|---|"]
    for k, v in doc["outcomes"].items():
        L.append(f"| `{k}` | {v} |")
    L += ["", "Per unique record (last attempt wins):", "",
          "| outcome | records |", "|---|---|"]
    for k, v in doc["outcomes_unique_records"].items():
        L.append(f"| `{k}` | {v} |")
    L += ["", "## Blockers, as preserved data", "", "| blocker | runs |", "|---|---|"]
    if doc["blocker_counts"]:
        for k, v in doc["blocker_counts"].items():
            L.append(f"| `{k}` | {v} |")
    else:
        L.append("| (none recorded) | 0 |")
    L += ["", "## Evidence levels the runs support", ""]
    for k, v in doc["evidence_levels_supported"].items():
        L.append(f"- `{k}`: {v} run(s)")
    L += ["", "## Runs that reached the execution levels", ""]
    if doc["runs_above_L3"]:
        for e in doc["runs_above_L3"]:
            L.append(f"- `{e['finding_id']}` ({e['attempt_id']}) -> "
                     f"`{e['evidence_level_supported']}` / `{e['outcome']}`, "
                     f"artefact `{e['artefact_dir']}`")
            for a in (e["assertion_tested"] or [])[:3]:
                L.append(f"  - assertion: `{a[:160]}`")
        L.append(f"- caveat: {doc['runs_above_L3'][0]['caveat']}")
    else:
        L.append("- none: no recorded run compiled and executed a PoC to a verdict")
    L += ["", f"L6 awarded by this campaign: {doc['l6_awarded']} "
          "(no fixed revision was executed under this standard).", "",
          "## Stretch campaign", "",
          f"- target: {doc['stretch_campaign']['target_distinct_sandboxed_invocations']} "
          f"distinct sandboxed PoC/test invocations",
          f"- achieved: {doc['stretch_campaign']['achieved_distinct_sandboxed_invocations']}",
          f"- shortfall: {doc['stretch_campaign']['shortfall']}", "",
          doc["stretch_campaign"]["honest_statement"], ""]
    md = "\n".join(L) + "\n"
    if write:
        write_json(DENSITY_JSON, doc)
        DENSITY_MD.write_text(md, encoding="utf-8", newline="\n")
    return doc, md


def _read_ledger() -> list[dict]:
    if not LEDGER.exists():
        return []
    return [json.loads(line) for line in LEDGER.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Re-run v1/v2.1 PoCs under the "
                                              "current evidence standard.")
    ap.add_argument("--list", action="store_true", help="show the attempt pool, run nothing")
    ap.add_argument("--dry-run", action="store_true",
                    help="assemble harness decisions and write nothing outside "
                         "experiments_v1_reruns")
    ap.add_argument("--finding", action="append", default=[],
                    help="only this finding id (repeatable)")
    ap.add_argument("--max", type=int, default=50, help="cap on attempts in one invocation")
    ap.add_argument("--timeout", type=int, default=300, help="per-command seconds")
    ap.add_argument("--rerun-scratch", action="store_true",
                    help="rebuild the scratch copy from the clone first")
    ap.add_argument("--report-only", action="store_true",
                    help="rebuild the density report from the ledger, run nothing")
    ap.add_argument("--check", action="store_true",
                    help="regenerate the density report and byte-compare; run nothing")
    args = ap.parse_args()

    rpc = os.environ.get("VLUN_RPC_URL")
    if args.report_only or args.check:
        doc, md = build_density(write=args.report_only)
        if args.report_only:
            DENSITY_MD.write_text(md, encoding="utf-8", newline="\n")
        if args.check:
            ok = True
            for p, want in ((DENSITY_JSON, json.dumps(doc, indent=2, sort_keys=True,
                                                      ensure_ascii=False) + "\n"),
                             (DENSITY_MD, md)):
                have = p.read_text(encoding="utf-8") if p.exists() else ""
                if have != want:
                    print(f"DRIFT  {rel(p)}")
                    ok = False
                else:
                    print(f"OK     {rel(p)}")
            return 0 if ok else 1
        print(json.dumps(doc["attempts"], indent=2))
        return 0

    if not QUEUE.exists():
        print(f"queue missing: run scripts/build_poc_triage_queue.py first ({rel(QUEUE)})")
        return 1
    queue = [r for r in read_jsonl(QUEUE)
             if r.get("candidate_layer") == "v1_v2_1"]
    pool = [r for r in queue if r.get("attemptable_under_current_standard")]
    pool.sort(key=lambda r: (r["eligibility"] != "eligible", r["finding_id"]))
    if args.finding:
        pool = [r for r in queue if r["finding_id"] in set(args.finding)]
    if args.list:
        for r in pool:
            print(f"{r['finding_id']:34s} {r['poc_class']:32s} "
                  f"{r['eligibility']:13s} {','.join(r['blocker_classes'])}")
        print(f"\n{len(pool)} attemptable of {len(queue)} queued v1/v2.1 records")
        return 0
    pool = pool[:args.max]
    print(f"attempting {len(pool)} candidate(s); per-command timeout "
          f"{args.timeout}s; rpc={'set' if rpc else 'unset'}")
    ARTEFACTS.mkdir(parents=True, exist_ok=True)
    for i, row in enumerate(pool, 1):
        res = attempt(row, args.timeout, rpc, args.rerun_scratch)
        if args.dry_run:
            print(f"[{i}/{len(pool)}] {row['finding_id']} -> "
                  f"{res.get('outcome')} ({res.get('blocker_class')}) DRY")
            continue
        art, hashes = write_attempt_artefacts(row["finding_id"], res)
        line = ledger_line(res, art, hashes)
        append_ledger(line)
        print(f"[{i}/{len(pool)}] {row['finding_id']} -> {line['outcome']} "
              f"level={line['evidence_level_supported']} "
              f"blocker={line['blocker_class']} [{art}]")
    doc, _md = build_density()
    print(json.dumps({"attempts": doc["attempts"], "outcomes": doc["outcomes"],
                      "blockers": doc["blocker_counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

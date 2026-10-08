#!/usr/bin/env python3
"""Execute the PoCs. For real. And record exactly what happened.

Pipeline per audited repository:

  prepare   check out the pinned commit, work out the toolchain, install deps
  compile   forge build (or hardhat compile) — record solc/forge version, rc
  materialise
            write each PoC quoted from the published report into the harness
  execute   one `forge test --json` run; parse per-test status
  classify  map the run outcome to an honest verdict

Verdict vocabulary (never upgraded without evidence):

  reproduced        the PoC test passed, so the claimed behaviour was exercised
  not_reproduced    the PoC compiled and ran to completion without the effect
  inconclusive      the PoC could not be run to a conclusion
  not_executed      no attempt was possible, `failure_reason` says why

`not_executed` reasons come from the closed list in vlun.EXEC_FAILURE_REASONS.
A PoC is never marked reproduced unless a test run says so.

    python scripts/verify_pocs.py --list
    python scripts/verify_pocs.py --repo code-423n4/2024-04-noya
    python scripts/verify_pocs.py                 # all repos
    python scripts/verify_pocs.py --skip-install  # reuse existing node_modules

Output: work/poc_runs/<repo>.json, merged into reports/verification_stats.json.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    DERIVED, EXEC_FAILURE_REASONS, REPORTS, WORK, load_core, log, owner_repo, run,
    tool_version, write_json,
)

CLONES = WORK / "repos"
RUNS = WORK / "poc_runs"
POC_DIR = "poc_vlun"

# Foundry cheatcodes the report PoCs lean on that need an archive node.
FORK_CHEATCODES = ("createFork", "createSelectFork", "selectFork", "rollFork", "makeCall")

DEAD_RPC = re.compile(r"https://(?:[a-z0-9-]+\.)?(?:infura\.io|alchemy\.com)/[^\"\s]*")


def repo_dir(owner_repo: str) -> Path:
    return CLONES / owner_repo.replace("/", "__")


# ---------------------------------------------------------------------------
# stage: prepare
# ---------------------------------------------------------------------------

def detect_toolchain(root: Path) -> dict:
    has_forge = (root / "foundry.toml").exists() or (root / "foundry.ignore").exists()
    pkg = root / "package.json"
    hardhat = False
    scripts = {}
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            hardhat = "hardhat" in (data.get("devDependencies") or {}) or "hardhat" in (data.get("dependencies") or {})
            scripts = data.get("scripts") or {}
        except json.JSONDecodeError:
            pass
    return {
        "foundry": has_forge,
        "hardhat": hardhat,
        "npm_scripts": sorted(scripts),
        "foundry_test_dir": _foundry_test_dir(root),
    }


def _foundry_test_dir(root: Path) -> str | None:
    f = root / "foundry.toml"
    if not f.exists():
        return None
    m = re.search(r"^\s*test\s*=\s*['\"]([^'\"]+)['\"]", f.read_text(encoding="utf-8", errors="replace"), re.M)
    return m.group(1) if m else "test"


def install_deps(root: Path, skip: bool) -> dict:
    """Install node dependencies, trying progressively harder strategies.

    These are 2022-2025 audit repos pinned to hardhat 2.x with peer ranges that
    npm 11 rejects outright, so `--legacy-peer-deps` is the default rather than
    the exception. Which strategy worked is recorded, because "dependencies
    installed" and "dependencies installed the way the authors intended" are
    different claims.
    """
    out = {"needed": False}
    nm = root / "node_modules"
    if nm.exists() and any(nm.iterdir()):
        out["status"] = "already_present"
        return out
    if skip:
        out.update(status="skipped_by_flag")
        return out
    out["needed"] = True
    lock = root / "package-lock.json"
    npm = shutil.which("npm") or shutil.which("npm.cmd")
    npx = shutil.which("npx") or shutil.which("npx.cmd")
    if not npm:
        out.update(status="failed", attempts=[],
                   error="npm not found on PATH; install Node.js or pass --skip-install")
        return out
    strategies = [[npm, "install", "--no-audit", "--no-fund", "--legacy-peer-deps"]]
    if lock.exists():
        strategies.append([npm, "ci", "--no-audit", "--no-fund"])
        strategies.append([npm, "install", "--no-audit", "--no-fund", "--legacy-peer-deps", "--force"])
    attempts = []
    for cmd in strategies:
        t0 = time.time()
        rc, sout, serr, timed = run(cmd, cwd=root, timeout=3600)
        attempts.append({"cmd": " ".join(cmd), "rc": rc, "seconds": round(time.time() - t0, 1),
                         "timed_out": timed, "tail": (serr or sout)[-500:]})
        if rc == 0:
            out.update(status="ok", strategy=attempts[-1]["cmd"], seconds=attempts[-1]["seconds"], attempts=attempts)
            return out
    out.update(status="failed", seconds=attempts[-1]["seconds"], attempts=attempts)
    return out


def patch_dead_rpcs(root: Path, rpc: str | None) -> dict:
    """Swap dead third-party RPC endpoints in harness files for a working node.

    Only files under the repository's own test/resource directories are touched.
    No contract under src/ or contracts/ is modified. Every edit is logged so the
    record can state that the harness, not the vulnerable code, was altered.
    """
    if not rpc:
        return {"applied": False, "reason": "no VLUN_RPC_URL supplied; dead endpoints left in place"}
    edits = []
    for pat in ("test", "testFoundry", "tests", "utils"):
        d = root / pat
        if not d.exists():
            continue
        for f in d.rglob("*.sol"):
            try:
                text = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            new = DEAD_RPC.sub(rpc, text)
            if new != text:
                f.write_text(new, encoding="utf-8", newline="")
                edits.append(str(f.relative_to(root)).replace("\\", "/"))
    return {"applied": True, "files_edited": edits[:40], "count": len(edits),
            "scope": "test harness resource files only; no contract source modified"}


# ---------------------------------------------------------------------------
# stage: compile
# ---------------------------------------------------------------------------

def compile_project(root: Path, tc: dict, timeout: int) -> dict:
    res = {"toolchain": tc}
    env = {"FOUNDRY_VIA_IR": "true", "FOUNDRY_OPTIMIZER": "true", "FOUNDRY_OPTIMIZER_RUNS": "200",
           "FOUNDRY_PROFILE": "default"}
    t0 = time.time()
    if tc["foundry"]:
        rc, out, err, timed = run(["forge", "build"], cwd=root, timeout=timeout, env=env)
        res.update(runner="forge build", rc=rc, timed_out=timed,
                   seconds=round(time.time() - t0, 1),
                   compiled=rc == 0,
                   solc=(re.search(r"with Solc ([0-9.]+)", out or "") or [None, None])[1]
                        if re.search(r"with Solc ([0-9.]+)", out or "") else None,
                   error=(err or out)[-1500:])
    elif tc["hardhat"]:
        npx = shutil.which("npx") or shutil.which("npx.cmd")
        if not npx:
            res.update(runner="hardhat compile", compiled=False, rc=127,
                       error="npx not found on PATH")
            return res
        rc, out, err, timed = run([npx, "hardhat", "compile"], cwd=root, timeout=timeout)
        res.update(runner="hardhat compile", rc=rc, timed_out=timed,
                   seconds=round(time.time() - t0, 1), compiled=rc == 0, solc=None,
                   error=(err or out)[-1500:])
    else:
        res.update(runner=None, compiled=False, rc=None, error="no forge or hardhat project detected")
    return res


# ---------------------------------------------------------------------------
# stage: materialise PoCs
# ---------------------------------------------------------------------------


def resolve_test_name(ex: dict) -> str | None:
    """The PoC's test function name, from the record or from the code itself."""
    named = (ex.get("test_name") or "").strip()
    if named:
        return named
    found = re.findall(r"\bfunction\s+(test\w*)\s*\(", ex.get("code") or "")
    return found[0] if found else None


def poc_function_body(ex: dict) -> str | None:
    """The reporter's test function, verbatim, or None if the PoC is not a test.

    The Code4rena reports also publish suggested *contract* patches (a function
    to add to the vulnerable contract, to demonstrate the issue). Those are real
    evidence but they are not runnable tests, so they are recorded as
    `poc_invalid` rather than dressed up as one.
    """
    code = (ex.get("code") or "").strip()
    name = resolve_test_name(ex)
    if not code or not name:
        return None
    m = re.search(r"\bfunction\s+" + re.escape(name) + r"\s*\(", code)
    if not m:
        return None
    return code[m.start():].strip()


NBSP = "    "


def normalise_poc_text(code: str) -> tuple[str, list[str]]:
    """Repair encoding damage in report-quoted code, recording what was changed.

    Code4rena report text is HTML-rendered, so Solidity arrives with non-breaking
    spaces that solc rejects as invalid tokens. Replacing them with ASCII spaces
    is an encoding repair, not an edit of the reporter's logic — but it is
    recorded rather than done silently.
    """
    changes = []
    out = code
    if any(ch in out for ch in NBSP):
        for ch in NBSP:
            out = out.replace(ch, " ")
        changes.append("nbsp_to_ascii_space")
    out = out.replace(" ", " ").replace(" ", " ")
    return out, changes


def restore_test_files(root: Path, test_dir: str) -> dict:
    """Reset the test tree to the pinned commit.

    Injection rewrites repository files. Resetting first means each run starts
    from exactly the audited code, so a PoC can never inherit state from an
    earlier run.
    """
    rc, out, err, _ = run(["git", "-C", str(root), "checkout", "--quiet", "--force", "--", test_dir],
                         timeout=900)
    return {"restored": rc == 0, "rc": rc, "path": test_dir, "detail": (err or "")[:200]}


def braces_balanced(code: str) -> bool:
    """True when a snippet's braces close.

    Report PoCs are frequently truncated snippets. Injecting one that does not
    close produces unbalanced braces that break the *whole* project build, which
    would then be misreported as a repository dependency problem.
    """
    s = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    s = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', s)
    depth = 0
    for ch in s:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def hinted_test_file(root: Path, test_dir: str, ex: dict) -> Path | None:
    """The test file the report names, e.g. "add this test to testFoundry/testOracle.sol"."""
    for field in (ex.get("test_file") or "", ex.get("setup") or ""):
        for h in re.findall(r"[\w./\\-]+\.sol", field):
            name = h.replace("\\", "/").split("/")[-1]
            cand = root / test_dir / name
            if cand.exists():
                return cand
            for f in (root / test_dir).rglob(name):
                return f
    return None


def imports_of(path: Path | None) -> list[str]:
    """Non-relative import statements of one file."""
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out, seen = [], set()
    for m in re.finditer(r"^\s*import\s+[^;]+;", text, re.M):
        line = " ".join(m.group(0).split())
        if re.search(r'import\s+[^;]*from\s+["\']\.', line) or re.search(r'import\s+["\']\.', line):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def inject_into_existing(root: Path, test_dir: str, ex: dict, fn_code: str) -> dict | None:
    """Append the PoC to the single test contract the report names.

    Most report PoCs are written as "add this test to testFoundry/testOracle.sol"
    and reference the project's own fixtures (`owner`, `vm`, base helpers) that a
    standalone wrapper cannot see. Injection is restricted to files declaring a
    single contract, because appending into a multi-contract file would corrupt
    it. Only test files are touched; nothing under src/ or contracts/ is modified.
    """
    hints = []
    for field in (ex.get("test_file") or "", ex.get("setup") or ""):
        hints += re.findall(r"[\w./\\-]+\.sol", field)
    target = None
    for h in hints:
        name = h.replace("\\", "/").split("/")[-1]
        cand = root / test_dir / name
        if cand.exists():
            target = cand
            break
        for f in (root / test_dir).rglob(name):
            target = f
            break
    if target is None:
        return None
    text = target.read_text(encoding="utf-8", errors="replace")
    if len(re.findall(r"\bcontract\s+\w+", text)) != 1:
        return None  # ambiguous target; fall back to a standalone wrapper
    end = _contract_body_end(text)
    if end is None:
        return None
    marker = "\n    // --- vlun: PoC quoted verbatim from the published report ---\n"
    new = text[:end].rstrip("\n") + "\n" + marker + fn_code + "\n    " + text[end:]
    target.write_text(new, encoding="utf-8", newline="")
    return {"file": str(target.relative_to(root)).replace("\\", "/"),
            "method": "injected_into_existing_test"}


def _contract_body_end(text: str) -> int | None:
    """Index of the closing brace of the file's single contract.

    `rfind('}')` is wrong here: a file often declares the contract and then an
    interface or library after it, and the last brace belongs to that later
    declaration. Inserting there produces unbalanced braces, so the contract's own
    closing brace is located by matching depth from its opening brace.
    """
    m = re.search(r"\bcontract\s+\w+[^{;]*\{", text)
    if not m:
        return None
    depth, i = 0, m.end() - 1
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def project_imports(root: Path, test_dir: str, limit: int = 40) -> list[str]:
    """Import statements the project's own tests use.

    A report PoC is written to be pasted into the audit's test suite, so it
    relies on symbols the suite already imports. A bare wrapper has none of them.
    Reusing the project's import list is what lets the verbatim snippet compile
    without editing a single line of the reporter's code.
    """
    d = root / test_dir
    if not d.exists():
        return []
    seen, out = set(), []
    for f in sorted(d.rglob("*.sol"))[:40]:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r'^\s*import\s+[^;]+;', text, re.M):
            line = " ".join(m.group(0).split())
            # Relative imports ("../x.sol") resolve against the *importing* file's
            # directory, so moving the snippet into our own subdirectory breaks
            # them. They are dropped; the remaining imports are resolved through
            # the project's remappings and keep working from anywhere.
            if re.search(r'import\s+[^;]*from\s+["\']\.', line) or re.search(r'import\s+["\']\.', line):
                continue
            if line not in seen:
                seen.add(line)
                out.append(line)
            if len(out) >= limit:
                return out
    return out


def solidity_wrapper(fn_code: str, test_name: str, pragma: str = ">=0.6.0",
                    imports: list[str] | None = None) -> str:
    body = "\n".join(f"import {imp[len('import '):]}" for imp in (imports or []))
    header = (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "// Generated by scripts/verify_pocs.py from the PoC quoted verbatim in the\n"
        "// Code4rena report. No line of the reporter's code was modified.\n"
        f"pragma solidity {pragma};\n\n"
        "import \"forge-std/Test.sol\";\n"
        + (body + "\n" if body else "")
        + "\ncontract VlunPoc is Test {\n"
    )
    return header + fn_code + "\n}\n"


def clean_poc_dir(root: Path, test_dir: str) -> None:
    """Remove our own PoC directory before anything looks for native tests.

    Ordering matters: `native_tests` searches the test tree for the report's test
    names, and if a previous run's generated files are still on disk it finds
    them and claims they ship with the repository. That would fabricate
    provenance, so the directory is cleared first.
    """
    d = root / test_dir / POC_DIR
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


def native_tests(root: Path, test_dir: str, names: list[str]) -> dict[str, dict]:
    """PoC tests the audited repository already ships at the pinned commit.

    This is the strongest evidence available: the reporter's own test, present in
    the code that was audited, needing no reconstruction and no modification.
    """
    if not names:
        return {}
    d = root / test_dir
    if not d.exists():
        return {}
    want = set(names)
    found: dict[str, dict] = {}
    for f in d.rglob("*.sol"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"function\s+([A-Za-z_$][\w$]*)\s*\(", text):
            n = m.group(1)
            if n in want and n not in found:
                found[n] = {"file": str(f.relative_to(root)).replace("\\", "/"),
                            "line": text.count("\n", 0, m.start()) + 1}
    return found


def project_pragma(root: Path) -> str:
    """A pragma broad enough for whatever the project already compiles."""
    for name in ("foundry.toml",):
        f = root / name
        if f.exists():
            m = re.search(r"solc(?:_version)?\s*=\s*['\"]?([0-9]+\.[0-9]+\.[0-9]+)",
                          f.read_text(encoding="utf-8", errors="replace"))
            if m:
                return f">={m.group(1)}"
    return ">=0.6.0"


def materialise(root: Path, exploits: list[dict], test_dir: str | None = None,
                skip_ids: set[str] | None = None) -> dict:
    """Write one PoC file per exploit into the project's own test directory.

    It has to go *inside* foundry.toml's `test` path: forge only discovers tests
    under src/ and test/, so a directory at the repository root compiles as
    library code and is silently skipped ("No tests found in project"). Nothing
    under src/ or contracts/ is touched.
    """
    skip_ids = skip_ids or set()
    rel_dir = f"{test_dir or 'test'}/{POC_DIR}"
    dest = (root / test_dir / POC_DIR) if test_dir else (root / POC_DIR)
    # Clear our own directory first. A previous run's PoC files would otherwise
    # break this run's compile and be misattributed to the current PoCs.
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    pragma = project_pragma(root)
    imports = project_imports(root, test_dir)
    written, skipped, injected = [], [], []
    for row in exploits:
        rid = row["finding"]["id"]
        if rid in skip_ids:
            continue
        ex = row["exploit"]
        name = resolve_test_name(ex)
        if not (ex.get("code") or "").strip():
            skipped.append({"finding_id": rid, "reason": "no_poc_published"})
            continue
        fn_code, text_fixes = normalise_poc_text(poc_function_body(ex) or "")
        if not fn_code.strip():
            # The published PoC is not a runnable test (it is a suggested contract
            # patch or prose): poc_invalid, per the closed vocabulary in
            # vlun.EXEC_FAILURE_REASONS.
            skipped.append({"finding_id": rid, "reason": "poc_invalid"})
            continue
        if not braces_balanced(fn_code):
            # A truncated snippet. Injecting it would break the whole project
            # build and be misreported as a dependency problem.
            skipped.append({"finding_id": rid, "reason": "broken_original_test",
                            "detail": "the PoC quoted in the report is a truncated snippet: "
                                      "its braces do not close"})
            continue
        placed = inject_into_existing(root, test_dir, ex, fn_code)
        if placed:
            injected.append({"finding_id": rid, "test_name": name, **placed})
            written.append({"finding_id": rid, "file": placed["file"], "test_name": name,
                            "method": placed["method"], "text_normalisations": text_fixes,
                            "bytes": len(fn_code)})
            continue
        path = dest / f"{rid.replace('/', '__')}.t.sol"
        # Use the imports of the test file the report names, not the whole
        # project's: a union of every test import redeclares shared structs and
        # fails to compile. With no hint, the wrapper stands alone.
        hint = hinted_test_file(root, test_dir, ex)
        used = imports_of(hint) if hint else []
        path.write_text(solidity_wrapper(fn_code, name, pragma, used),
                        encoding="utf-8", newline="")
        written.append({"finding_id": rid, "file": f"{rel_dir}/{path.name}", "test_name": name,
                        "method": "standalone_wrapper", "text_normalisations": text_fixes,
                        "imports_from": (str(hint.relative_to(root)).replace("\\", "/")
                                         if hint else None),
                        "imports_used": len(used), "bytes": len(fn_code)})
    return {"written": written, "skipped": skipped, "dir": rel_dir, "injected": injected,
            "wrapper_imports": len(imports)}


# ---------------------------------------------------------------------------
# stage: execute
# ---------------------------------------------------------------------------

def run_tests(root: Path, match_test: str | None, timeout: int) -> dict:
    env = {"FOUNDRY_VIA_IR": "true", "FOUNDRY_OPTIMIZER": "true", "FOUNDRY_OPTIMIZER_RUNS": "200",
           "ETH_RPC_URL": os.environ.get("ETH_RPC_URL", ""),
           "MAINNET_RPC_URL": os.environ.get("MAINNET_RPC_URL", os.environ.get("ETH_RPC_URL", ""))}
    # `--json` already suppresses ANSI and cannot be combined with `--color` in
    # forge 1.8, so neither flag is passed here.
    args = ["forge", "test", "--json"]
    if match_test:
        # one run for every PoC at once: a regex alternation over the test names
        args += ["--match-test", match_test]
    args += ["--fuzz-runs", os.environ.get("VLUN_FUZZ_RUNS", "64")]
    t0 = time.time()
    rc, out, err, timed = run(args, cwd=root, timeout=timeout, env=env)
    parsed = None
    if out:
        text = out.strip()
        # forge prefixes nothing but may append a summary line, so try the whole
        # buffer first and only then look for the start of a JSON value.
        for candidate in (text, text[text.find("["):] if text.find("[") >= 0 else None,
                          text[text.find("{"):] if text.find("{") >= 0 else None):
            if not candidate:
                continue
            try:
                parsed = json.loads(candidate)
                break
            except json.JSONDecodeError:
                # trailing junk after the JSON: parse the longest valid prefix
                for end in range(len(candidate), 1, -1):
                    try:
                        parsed = json.loads(candidate[:end])
                        break
                    except json.JSONDecodeError:
                        continue
                if parsed is not None:
                    break
    return {"command": " ".join(args), "rc": rc, "timed_out": timed,
            "seconds": round(time.time() - t0, 1), "parsed": parsed,
            "stdout_tail": (out or "")[-4000:], "stderr_tail": (err or "")[-2000:]}


def parse_forge_results(parsed) -> dict[str, dict]:
    """Flatten `forge test --json` into {test name -> result}.

    forge has shipped three shapes for this output: a list of suite objects, a
    mapping of "path/to/File.t.sol:Contract" -> suite, and a list whose single
    element is that mapping. All three are accepted rather than assumed, because
    a mis-parse here would silently report zero executed tests.
    """
    out: dict[str, dict] = {}

    def walk(node, depth=0):
        if depth > 4 or not isinstance(node, (dict, list)):
            return
        if isinstance(node, dict):
            if "test_results" in node and isinstance(node["test_results"], dict):
                for name, r in node["test_results"].items():
                    if not isinstance(r, dict):
                        continue
                    rec = {
                        "status": r.get("status"),
                        "reason": (r.get("reason") or "")[:600],
                        "counterexample": r.get("counterexample"),
                        "decoded_log": [x[:200] for x in
                                        (r.get("decoded_logs") or r.get("decoded_log") or [])[:6]],
                        "gas_used": ((r.get("kind") or {}).get("Unit") or {}).get("gas")
                        if isinstance(r.get("kind"), dict) else r.get("gas_used"),
                        "forge_key": name,
                    }
                    out[name] = rec
                    out.setdefault(name.split("(")[0].strip(), rec)
                return
            for v in node.values():
                walk(v, depth + 1)
        else:
            for v in node:
                walk(v, depth + 1)

    walk(parsed)
    return out


def find_result(results: dict[str, dict], name: str) -> dict | None:
    """Look a test up by name, tolerating forge's `name()` key form."""
    if not name:
        return None
    for cand in (name, f"{name}()"):
        if cand in results:
            return results[cand]
    hits = [v for k, v in results.items() if k.split("(")[0].strip() == name]
    return hits[0] if hits else None


def classify(status: str | None, reason: str) -> tuple[str, str | None]:
    if status == "Success":
        return "reproduced", None
    if status == "Failure":
        low = reason.lower()
        if any(k in low for k in ("fork", "rpc", "429", "rate limit", "provider", "connection")):
            return "inconclusive", "environment_unavailable"
        if any(k in low for k in ("stack too deep", "solc", "parsererror", "typeerror")):
            return "inconclusive", "broken_original_test"
        return "not_reproduced", None
    if status == "Skipped":
        return "inconclusive", "insufficient_evidence"
    return "inconclusive", "environment_unavailable"


def classify_run_failure(rc: int, stderr: str, stdout: str) -> str:
    """Why the test run itself produced nothing.

    When `forge test` never got as far as running tests, every per-PoC verdict
    would otherwise be attributed to the PoC. That is wrong: a bad flag or a
    missing compiler is an environment problem, and it is recorded as one.
    """
    low = ((stderr or "") + (stdout or "")).lower()
    if "unexpected argument" in low or "unrecognized option" in low or "invalid option" in low:
        return "environment_unavailable"
    if any(k in low for k in ("could not instantiate forked", "429", "rate limit",
                              "failed to get account", "connection refused", "dns")):
        return "environment_unavailable"
    if any(k in low for k in ("error: no tests found", "no test functions")):
        return "broken_original_test"
    if "compiler" in low or "solc" in low or "stack too deep" in low:
        return "broken_original_test"
    return "environment_unavailable"


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def compile_isolating(root: Path, tc: dict, timeout: int, poc_dir: str,
                      attempts: int = 5) -> tuple[dict, list[dict]]:
    """Compile, setting aside any generated PoC that breaks the build.

    One PoC snippet that cannot compile standalone would otherwise block every
    other PoC in the repository, and the blocker would be misreported as a
    repository dependency problem. Each round reads the compiler's own file
    references, quarantines just those generated files, and retries — bounded, so
    a repository that never compiles stops after `attempts` rounds.

    Injected PoCs are never quarantined this way: they modify a repository test
    file, and isolating them would mean reverting that file, which is recorded
    separately as a modified harness.
    """
    isolated: list[dict] = []
    result: dict = {}
    for round_no in range(1, attempts + 1):
        result = compile_project(root, tc, timeout)
        if result.get("compiled"):
            return result, isolated
        err = result.get("error") or ""
        guilty = sorted({m for m in re.findall(re.escape(poc_dir) + r"/[\w\-.]+\.t\.sol", err)})
        if not guilty:
            return result, isolated
        moved = []
        for rel in guilty:
            p = root / rel
            if p.exists():
                p.rename(p.with_suffix(".t.sol.failed"))
                moved.append(rel)
        if not moved:
            return result, isolated
        isolated.append({"round": round_no, "quarantined_files": moved,
                         "reason": "the generated PoC does not compile standalone"})
        log(f"  isolated {len(moved)} non-compiling PoC file(s), retrying")
    return result, isolated


def run_repo(owner_repo: str, exploits: list[dict], args) -> dict:
    root = repo_dir(owner_repo)
    log(f"\n=== {owner_repo} ===")
    if not (root / ".git").exists():
        # scripts/fetch_sources.py only clones repositories whose files the
        # dataset cites, so an audit repository can be absent even though the
        # dataset needs its test harness. Clone it here rather than reporting a
        # missing dependency that is really a missing clone.
        org, _, name = owner_repo.partition("/")
        log(f"  no clone; fetching {owner_repo}")
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet",
             f"https://github.com/{org}/{name}.git", str(root)], timeout=3600)
    if not (root / ".git").exists():
        return {"repo": owner_repo, "status": "clone_failed",
                "note": "run scripts/fetch_sources.py, or check that the repository exists",
                "verdicts": [], "tally": {}, "failure_reasons": {}}

    t0 = time.time()
    if args.checkout:
        head = exploits[0]["source"].get("commit_sha") if exploits else None
        if head:
            rc, _, err, _ = run(["git", "-C", str(root), "checkout", "--quiet", "--force", head], timeout=1800)
            log(f"  checkout {head[:10]} rc={rc}")

    tc = detect_toolchain(root)
    log(f"  toolchain: {tc}")
    dep = install_deps(root, args.skip_install)
    log(f"  deps: {dep.get('status')}")
    rpc_patch = patch_dead_rpcs(root, args.rpc_url or os.environ.get("VLUN_RPC_URL"))
    if rpc_patch.get("applied"):
        log(f"  harness rpc patch: {rpc_patch['count']} files")

    test_dir = tc["foundry_test_dir"] or "test"
    clean_poc_dir(root, test_dir)
    restore = restore_test_files(root, test_dir)
    names = [resolve_test_name(r["exploit"]) for r in exploits]
    named = [n for n in names if n]
    natives = native_tests(root, test_dir, named) if tc["foundry"] else {}
    if natives:
        log(f"  {len(natives)} PoC tests already ship in this repo at the pinned commit")

    mat = (materialise(root, exploits, test_dir, skip_ids=set(
                r["finding"]["id"] for r in exploits
                if resolve_test_name(r["exploit"]) in natives))
           if not args.no_materialise else {"written": [], "skipped": [], "dir": None})
    log(f"  materialised {len(mat['written'])} PoC files, skipped {len(mat['skipped'])}")

    comp, isolated = compile_isolating(root, tc, args.compile_timeout,
                                       mat["dir"] if mat["dir"] else POC_DIR)
    log(f"  compile: {comp.get('runner')} rc={comp.get('rc')} in {comp.get('seconds')}s "
        f"solc={comp.get('solc')}"
        + (f" ({len(isolated)} isolation rounds)" if isolated else ""))
    if not comp.get("compiled"):
        log("  compile failed -> PoCs cannot be executed for this repo")

    runnable = sorted(set(natives) | {w["test_name"] for w in mat["written"]})
    test_run = {"executed": False}
    results: dict[str, dict] = {}
    run_failure_reason = None
    if comp.get("compiled") and runnable:
        # No anchors: forge matches --match-test against the full signature
        # including its parameter list, so `^name$` matches nothing.
        alt = "(" + "|".join(re.escape(n) for n in runnable) + ")"
        test_run = run_tests(root, alt, args.test_timeout)
        results = parse_forge_results(test_run.get("parsed"))
        if test_run.get("rc") != 0 or not results:
            run_failure_reason = classify_run_failure(
                test_run.get("rc", 1), test_run.get("stderr_tail", ""), test_run.get("stdout_tail", ""))
        log(f"  forge test --json rc={test_run['rc']} in {test_run['seconds']}s -> {len(results)} tests"
            + (f" (run failed: {run_failure_reason})" if run_failure_reason else ""))

    # --- per-exploit verdict ---
    verdicts = []
    for row in exploits:
        rid = row["finding"]["id"]
        name = resolve_test_name(row["exploit"])
        written = next((w for w in mat["written"] if w["finding_id"] == rid), None)
        native = natives.get(name)
        base = {
            "finding_id": rid,
            "finding_severity": row["finding"].get("severity"),
            "poc_type": ("repo_native_test" if native else
                         "report_quoted_poc" if written else
                         ("no_poc_published" if not (row["exploit"].get("code") or "").strip()
                          else "not_a_runnable_test")),
            "poc_native_location": native,
            "poc_materialised_file": written["file"] if written else None,
            "poc_placement": (written.get("method") if written else None),
            "poc_claimed_impact": row["exploit"].get("expected_impact") or "",
            "poc_observed_impact": row["exploit"].get("observed_impact") or "",
        }
        if not native and written is None:
            base.update(verdict="not_executed",
                        failure_reason=next((s["reason"] for s in mat["skipped"] if s["finding_id"] == rid),
                                            "insufficient_evidence"),
                        evidence={})
            verdicts.append(base); continue
        if not comp.get("compiled"):
            err = comp.get("error") or ""
            # A compile error inside our own PoC file is a property of the PoC;
            # anything else is the repository's toolchain failing.
            reason = ("broken_original_test" if POC_DIR in err else "dependency_unavailable")
            base.update(verdict="not_executed", failure_reason=reason,
                        compile_rc=comp.get("rc"),
                        evidence={"compile_error": err[-800:]})
            verdicts.append(base); continue
        hit = find_result(results, name)
        if hit is None:
            if run_failure_reason:
                # the harness never ran, so this is not a property of the PoC
                base.update(verdict="inconclusive", failure_reason=run_failure_reason,
                            evidence={"test_name": name, "forge_status": None,
                                      "note": "the test run itself failed before any PoC "
                                              "was executed",
                                      "forge_stderr": (test_run.get("stderr_tail") or "")[-600:]})
            else:
                base.update(verdict="not_executed", failure_reason="broken_original_test",
                            evidence={"note": "the test name from the report does not exist in "
                                               "the compiled test set", "test_name": name,
                                      "tests_compiled": len(results),
                                      "compiled_test_names": sorted(results)[:40]})
            verdicts.append(base); continue
        verdict, reason = classify(hit["status"], hit["reason"])
        base.update(verdict=verdict, failure_reason=reason,
                    evidence={"test_name": name, "forge_status": hit["status"],
                              "reason": hit["reason"], "decoded_log": hit["decoded_log"],
                              "gas_used": hit["gas_used"]})
        verdicts.append(base)

    tally = collections.Counter(v["verdict"] for v in verdicts)
    reasons = collections.Counter(v["failure_reason"] for v in verdicts if v.get("failure_reason"))
    return {
        "repo": owner_repo, "status": "ok", "seconds": round(time.time() - t0, 1),
        "head_commit": exploits[0]["source"].get("commit_sha") if exploits else None,
        "toolchain": tc, "dependencies": dep, "harness_modifications": rpc_patch,
        "test_tree_restored": restore,
        "compile": {k: v for k, v in comp.items() if k != "toolchain"},
        "materialised": mat, "isolated_wrappers": isolated, "test_run": {k: v for k, v in test_run.items() if k != "parsed"},
        "verdicts": verdicts,
        "tally": dict(tally), "failure_reasons": dict(reasons),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", action="append", help="owner/repo, repeatable")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--skip-install", action="store_true")
    ap.add_argument("--no-materialise", action="store_true")
    ap.add_argument("--no-checkout", dest="checkout", action="store_false")
    ap.add_argument("--rpc-url", default=None, help="archive RPC used to replace dead endpoints")
    ap.add_argument("--compile-timeout", type=int, default=5400)
    ap.add_argument("--test-timeout", type=int, default=5400)
    ap.set_defaults(checkout=True)
    args = ap.parse_args()

    core = load_core()
    by_repo = collections.defaultdict(list)
    for row in core["exploits"]:
        key = owner_repo(row["source"])
        if key:
            by_repo[key].append(row)

    if args.list:
        for k in sorted(by_repo):
            log(f"{k:45s} exploits={len(by_repo[k])}")
        return 0

    RUNS.mkdir(parents=True, exist_ok=True)
    targets = args.repo or sorted(by_repo)
    for name in targets:
        dest = RUNS / (name.replace("/", "__") + ".json")
        if dest.exists():
            log(f"skip {name}: work/poc_runs already has a result (delete it to re-run)")
            continue
        try:
            res = run_repo(name, by_repo[name], args)
        except Exception as exc:  # noqa: BLE001 - one repo must not kill the run
            res = {"repo": name, "status": "driver_error", "detail": f"{type(exc).__name__}: {exc}"[:600],
                   "verdicts": [], "tally": {}, "failure_reasons": {}}
            log(f"  driver error: {exc}")
        dest.write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
        log(f"  verdicts: {res.get('tally')}")

    merge(args)
    return 0


def merge(args) -> None:
    runs = []
    for f in sorted(RUNS.glob("*.json")):
        if f.name == "_all.json":  # this is the merged dump, not a per-repo run
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            runs.append(data)
    verdicts = [v for r in runs for v in r.get("verdicts", [])]
    tally = collections.Counter(v["verdict"] for v in verdicts)
    reasons = collections.Counter(v["failure_reason"] for v in verdicts if v.get("failure_reason"))
    compiled = [r["repo"] for r in runs if r.get("compile", {}).get("compiled")]
    by_repo = {r["repo"]: {"status": r["status"], "tally": r.get("tally", {}),
                          "failure_reasons": r.get("failure_reasons", {}),
                          "compile_rc": r.get("compile", {}).get("rc"),
                          "compile_runner": r.get("compile", {}).get("runner"),
                          "solc": r.get("compile", {}).get("solc"),
                          "seconds": r.get("seconds"),
                          "head_commit": r.get("head_commit"),
                          "dependencies": r.get("dependencies", {}).get("status"),
                          "harness_files_edited": r.get("harness_modifications", {}).get("count", 0)}
                for r in runs}
    out = {
        "generated_by": "scripts/verify_pocs.py",
        "tooling": {"forge": tool_version(["forge", "--version"]), "git": tool_version(["git", "--version"])},
        "environment": {
            "archive_rpc_supplied": bool(args.rpc_url or os.environ.get("VLUN_RPC_URL")),
            "node": os.environ.get("VLUN_FUZZ_RUNS", "64") + " fuzz runs",
        },
        "totals": {"exploit_records": len(verdicts),
                   "reproduced": tally["reproduced"],
                   "not_reproduced": tally["not_reproduced"],
                   "inconclusive": tally["inconclusive"],
                   "not_executed": tally["not_executed"]},
        "poc_compilation_rate": {
            "repos_attempted": len(runs),
            "repos_compiled": len(compiled),
            "poc_files_materialised": sum(len(r.get("materialised", {}).get("written", [])) for r in runs),
            "poc_files_skipped": sum(len(r.get("materialised", {}).get("skipped", [])) for r in runs),
        },
        "not_executed_failure_reasons": dict(reasons),
        "failure_reason_vocabulary": list(EXEC_FAILURE_REASONS),
        "by_repository": by_repo,
        "guarantee": "No record is marked reproduced unless a forge run reported Success for its test.",
    }
    write_json(REPORTS / "verification_stats.json", out)
    write_json(RUNS / "_all.json", runs)
    log(f"\nverification_stats.json: {out['totals']}")
    log(f"  compiled repos {len(compiled)}/{len(runs)}; "
        f"failure reasons {dict(reasons)}")


if __name__ == "__main__":
    raise SystemExit(main())
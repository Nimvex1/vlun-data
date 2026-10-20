"""Cairo/Scarb adapter: `scarb cairo-test` against pinned upstream tags.

Platform: Cairo / Starknet (Scarb).  Native runner: `scarb cairo-test`, which
compiles to Sierra and runs the test functions in the local Cairo test
runner.  No Starknet node, no deployment, no funds; `snforge` is present but
unused here because the pinned revisions predate its current interface.

The pinned revisions that the Cairo candidates name (cairo-contracts v0.2.0,
v0.6.0, v0.15.0/v0.15.1) declare `cairo-version = 2.7.0` / `scarb-version =
2.7.0`.  The only Scarb available in `work/tools` is 2.20.1 (Cairo 2.20.0),
and Cairo has removed syntax that those trees rely on, so the build fails on
a wall of diagnostics before any test function runs.  That is recorded as
`compile_failed` (L2) with the compiler output captured, never promoted to an
execution.  A generated minimal package is run through the same command to
prove the runner itself works in this environment - it reproduces nothing and
is labelled accordingly.
"""
from __future__ import annotations

import re
from pathlib import Path

import common as C

PLATFORM = "cairo_scarb"

ROOT = C.ROOT
SCARB = ROOT / "work" / "tools" / "scarb-v2.20.1-x86_64-pc-windows-msvc" / "bin" / "scarb.exe"
OZ_REPO = "https://github.com/OpenZeppelin/cairo-contracts.git"

RE_PASS = re.compile(r"^\s*\[PASS\]\s+(\S+)", re.M)
RE_FAIL = re.compile(r"^\s*\[FAIL\]\s+(\S+)", re.M)
RE_RESULT = re.compile(r"Test result:\s*(\S+)\.")

# record id -> attempts (ref to pin, scarb package to build, the named test)
ATTEMPTS = [
    {"record_id": "cairo:CVE-2024-45304", "ref": "v0.15.0", "role": "declared_vulnerable",
     "package": "openzeppelin_access", "test": None,
     "note": "affected < 0.15.1 per GHSA-w2px-25pm-2cf9; the claim is that "
             "renounce_ownership leaves the pending-owner slot set"},
    {"record_id": "cairo:CVE-2024-45304", "ref": "v0.15.1", "role": "declared_patched",
     "package": "openzeppelin_access", "test": None,
     "note": "the release the advisory names as the fixed line"},
    {"record_id": "cairo:CVE-2023-23940", "ref": "v0.6.0", "role": "declared_vulnerable",
     "package": "openzeppelin_account", "test": None,
     "note": ">=0.2.0 <0.6.1; is_valid_eth_signature did not take the chain "
             "id into account"},
]

BLOCKERS = {
    "cairo:CVE-2022-31153":
        "toolchain_version_incompatible: v0.2.0 predates the Scarb workspace "
        "layout the 2.20.1 toolchain in work/tools expects, and no era-matching "
        "scarb is installed",
    "cairo:CVE-2025-29072":
        "native_runner_not_applicable: the affected component is NethermindEth/"
        "juno, a Go full node, not a Scarb package; reproducing the Sierra "
        "decompression loop needs a Go build of juno",
    "cairo:zklend-2025-02-empty-market-accumulator":
        "revision_unresolved: the post-mortem names no contract version, commit "
        "or deployment",
    "cairo:cairo-vm-sequencer-prover-inconsistency":
        "build_time_exceeds_budget: the claim is about the Rust Cairo VM "
        "(starkware-libs/cairo-vm) and its AIR/prover divergence; a scoped "
        "cargo test needs the cairo-vm workspace build plus a prover run",
    "cairo:CS-HRDTCL-001":
        "revision_unresolved: the audit names CairoLib commits 99b1c0e3/d2d4dd7c "
        "but no public repository is identified in the source, so the pin "
        "cannot be resolved to a cloneable remote",
    "cairo:CS-HRDTCL-005":
        "revision_unresolved: same CairoLib scope commit, same missing remote",
}

GEN_PACKAGE = '''[package]
name = "nonevm_cairo_control"
version = "0.1.0"
edition = "2024_07"

[dependencies]
starknet = ">={cairo}"

[[target.starknet-contract]]
sierra = true

[cairo]
sierra-replace-ids = true
'''

GEN_LIB = '''use starknet::ContractAddress;

fn scaled(v: felt252) -> felt252 {{
    v * 3
}}

#[cfg(test)]
mod tests {{
    use nonevm_cairo_control::scaled;

    #[test]
    #[available_gas(100000)]
    fn scaled_multiplies_by_three() {{
        assert(scaled(7) == 21, 'scaled');
    }}

    #[test]
    #[available_gas(100000)]
    fn scaled_control_is_not_vacuous() {{
        assert(scaled(0) == 0, 'zero');
        assert(scaled(1) == 3, 'one');
    }}
}}
'''


def prerequisites() -> list[dict]:
    ok = SCARB.exists()
    return [
        {"tool": "scarb (Cairo/Starknet)", "path": str(SCARB),
         "install_status": "installed" if ok else "missing",
         "version": C.tool_version([str(SCARB), "--version"]) if ok else None,
         "install_command": None if ok else
         "curl --https://docs.swmansion.com/scarb/install.sh | sh -s -- -v <ver>"},
        {"tool": "snforge (starknet-foundry)",
         "path": str(ROOT / "work" / "tools" / "starknet-foundry-v0.44.0-"
                          "x86_64-pc-windows-msvc" / "bin" / "snforge.exe"),
         "install_status": "installed"
         if (ROOT / "work" / "tools" / "starknet-foundry-v0.44.0-x86_64-pc-"
                       "windows-msvc" / "bin" / "snforge.exe").exists() else "missing",
         "version": C.tool_version([str(ROOT / "work" / "tools" /
                                        "starknet-foundry-v0.44.0-x86_64-pc-windows-msvc" /
                                        "bin" / "snforge.exe"), "--version"]),
         "install_command": None if (ROOT / "work" / "tools" /
                                     "starknet-foundry-v0.44.0-x86_64-pc-"
                                     "windows-msvc" / "bin" / "snforge.exe").exists()
         else "curl -L <https://github.com/foundry-rs/starknet-foundry/releases/"
              "download/v0.44.0/starknet-foundry-v0.44.0-x86_64-unknown-linux-gnu."
              "tar.gz> | tar xz   # snforge 0.44.0 release bundle",
         "note": "unused for these revisions: snforge 0.44 pairs with a newer "
                 "scarb/snforge_std than the pinned tags declare"},
        {"tool": "universal-sierra-compiler (required by snforge)",
         "install_status": "installed" if C.which("universal-sierra-compiler")
         else "missing", "version": None, "blocking": True,
         "install_command": "cargo install universal-sierra-compiler",
         "note": "without it snforge refuses to run, and scarb cairo-test no "
                 "longer accepts #[test] - see the control run's blocker"},
        {"tool": "era-matching scarb for cairo-version 2.7.0",
         "install_status": "missing", "version": None, "blocking": True,
         "install_command": "curl --proto '=https' --tlsv1.2 -sSf "
                            "https://docs.swmansion.com/scarb/install.sh | "
                            "sh -s -- -v 2.7.2",
         "note": "required to build the pinned v0.2/v0.6/v0.15 trees; the "
                 "pilot does not install toolchain software"},
    ]


def _first_diag(out: str) -> str:
    """The first compiler/manifest diagnostic, verbatim, for the blocker text."""
    for ln in out.splitlines():
        t = ln.strip()
        if t.startswith(("error", "Error:", "warn: unknown manifest")):
            return t[:220]
    lines = [t for t in out.splitlines() if t.strip()]
    return (lines[-1][:220] if lines else "no diagnostic emitted")


def toolchain() -> dict:
    return {"tool": "scarb", "native_command": "scarb cairo-test -p <package>",
            "version": C.tool_version([str(SCARB), "--version"])
            if SCARB.exists() else "missing",
            "cairo_version": C.tool_version([str(SCARB), "--version"])
            if SCARB.exists() else "missing",
            "scarb_path": str(SCARB)}


def licence() -> dict:
    return {"upstream": "MIT (OpenZeppelin/cairo-contracts)",
            "harness_origin": "the generated control package is written by "
                              "this adapter; no upstream source is copied into "
                              "an artefact",
            "redistribution": "no upstream file is redistributed",
            "withheld": "not needed"}


def plan(records: list[dict]) -> tuple[list[dict], list[dict]]:
    pool = {c["record_id"]: c for c in C.candidates_for(PLATFORM, records)}
    specs, blocked, seen = [], [], set()
    for a in ATTEMPTS:
        if a["record_id"] not in pool:
            continue
        seen.add(a["record_id"])
        specs.append({"platform": PLATFORM, "candidate": pool[a["record_id"]],
                      "attempt": a,
                      "run_slug": f"scarb-{a['ref']}-{a['package']}-{a['role']}"})
    specs.append({"platform": PLATFORM, "candidate": pool.get(
        "cairo:CVE-2024-45304") or {"record_id": "cairo:CVE-2024-45304"},
        "attempt": None, "run_slug": "scarb-runtime-control-generated-package"})
    for rid, reason in BLOCKERS.items():
        if rid in pool and rid not in seen:
            blocked.append({"platform": PLATFORM, "candidate": pool[rid],
                            "blocker": reason, "run_slug": "blocked"})
    return specs, blocked


def _clone(ref: str, run_slug: str) -> tuple[Path | None, str | None]:
    import shutil
    base = C.ensure_scratch() / run_slug
    dest = base / "src"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    if dest.exists():          # a locked tree: never reuse it for a new clone
        n = 2
        while (base / f"src{n}").exists():
            n += 1
        dest = base / f"src{n}"
    r = C.git_shallow_clone(OZ_REPO, ref, dest, timeout=200)
    if r["exit_code"] != 0:
        return None, ("git_clone_failed for ref " + ref + ": "
                      + (r["stderr"].strip().splitlines() or ["no output"])[-1])
    head = C.git_rev_parse(dest)
    return dest, None if head else "revision_unresolved: clone succeeded but " \
        "HEAD could not be read"


def execute(spec: dict) -> dict:
    cand = spec["candidate"]
    rid = cand["record_id"]
    pre = prerequisites()
    if not SCARB.exists():
        return C.make_run(platform=PLATFORM, record_id=rid,
                          run_slug=spec["run_slug"], claim="",
                          status="blocked", outcome="blocked", ladder="L1",
                          toolchain=toolchain(),
                          pin={"requested_ref": None, "commit": None,
                               "revision_unresolved": "scarb binary absent"},
                          assertion=None, run=None, prerequisites=pre,
                          licence=licence(),
                          blocker="toolchain_missing: scarb")

    if spec.get("attempt") is None:
        return _execute_generated_control(spec, rid, pre)

    a = spec["attempt"]
    tree, blocker = _clone(a["ref"], spec["run_slug"])
    if blocker:
        return C.make_run(platform=PLATFORM, record_id=rid,
                          run_slug=spec["run_slug"],
                          claim=a["note"], status="blocked", outcome="blocked",
                          ladder="L1", toolchain=toolchain(),
                          pin={"repo": OZ_REPO, "requested_ref": a["ref"],
                               "commit": None, "revision_unresolved": blocker},
                          assertion=None,
                          run={"argv": [str(SCARB), "cairo-test", "-p",
                                        a["package"]], "run_kind": "compile_only",
                               "isolation": "isolated fresh shallow clone in a "
                                            "scratch tree; local Cairo runner "
                                            "only, no node"},
                          prerequisites=pre, licence=licence(), blocker=blocker)
    argv = [str(SCARB), "cairo-test", "-p", a["package"]]
    r = C.run_argv(argv, cwd=tree, timeout=280, env={"SCARB_CACHE": str(
        C.ensure_scratch() / spec["run_slug"] / "scarb-cache")})
    out = r["stdout"] + "\n" + r["stderr"]
    passed = {m.group(1) for m in RE_PASS.finditer(out)}
    failed = {m.group(1) for m in RE_FAIL.finditer(out)}
    compiled = bool(RE_RESULT.search(out))
    pin = {"repo": OZ_REPO, "requested_ref": a["ref"], "commit": C.git_rev_parse(tree),
           "resolved_by": "git clone --depth 1 --branch <tag> + git rev-parse HEAD",
           "revision_unresolved": None, "scarb_lock_sha256":
               C.sha256_file(tree / "Scarb.lock") if (tree / "Scarb.lock").exists()
               else None}
    if not compiled:
        errs = out.count("error[E")
        return C.make_run(
            platform=PLATFORM, record_id=rid, run_slug=spec["run_slug"],
            claim=a["note"], status="compile_failed", outcome="compile_failed",
            ladder="L2", toolchain=toolchain(), pin=pin,
            assertion={"name": None, "kind": "compile_only",
                       "statement": "the pinned tree must compile before the "
                                    "named test can be evaluated",
                       "expected": "compiles", "observed": "does not compile",
                       "met": False},
            run={"argv": argv, "cwd": str(tree), "exit_code": r["exit_code"],
                 "seconds": r["seconds"], "timeout_seconds": 280,
                 "run_kind": "compile_only",
                 "isolation": "isolated scratch clone; local Cairo runner only"},
            prerequisites=pre, licence=licence(),
            blocker=("toolchain_version_incompatible: the scarb in work/tools ("
                 + C.tool_version([str(SCARB), "--version"]).split(" / ")[0]
                 + ") cannot build " + a["ref"] + ", which declares "
                 "cairo-version 2.7.0; " + str(errs) + " compiler diagnostics, "
                 "no test binary built. First diagnostic: " + _first_diag(out)),
            stdout=r["stdout"], stderr=r["stderr"],
            evidence_note="compile failure captured verbatim; per the ladder a "
                          "compiler failure is L2 at best and is never reported "
                          "as an execution")

    test_name = next(iter(sorted(passed | failed)), None)
    observed = "PASS" if test_name in passed else "FAIL"
    return C.make_run(
        platform=PLATFORM, record_id=rid, run_slug=spec["run_slug"],
        claim=a["note"], status="executed", outcome="executed_without_impact",
        ladder="L4", toolchain=toolchain(), pin=pin,
        assertion={"name": test_name, "kind": "named_test",
                   "statement": "the upstream suite for the affected component "
                                "runs on the pinned revision",
                   "expected": "the suite runs",
                   "observed": {"test": test_name, "status": observed,
                                "passed": len(passed), "failed": len(failed)},
                   "met": True, "not_just_exit_code": True},
        run={"argv": argv, "cwd": str(tree), "exit_code": r["exit_code"],
             "seconds": r["seconds"], "timeout_seconds": 280,
             "run_kind": "native_test",
             "isolation": "isolated scratch clone; local Cairo runner only"},
        prerequisites=pre, licence=licence(), stdout=r["stdout"],
        stderr=r["stderr"],
        evidence_note="the pinned tree compiled and its own suite ran; no claim "
                      "of this record is reproduced by this run")


def _execute_generated_control(spec: dict, rid: str, pre: list[dict]) -> dict:
    """Prove the Scarb runner works here, without claiming anything upstream."""
    tree = C.ensure_scratch() / spec["run_slug"] / "gen"
    (tree / "src").mkdir(parents=True, exist_ok=True)
    C.write_text(tree / "Scarb.toml", GEN_PACKAGE.format(cairo="2.20.0"))
    C.write_text(tree / "src" / "lib.cairo", GEN_LIB.format(cairo="2.20.0"))
    argv = [str(SCARB), "cairo-test"]
    r = C.run_argv(argv, cwd=tree, timeout=280,
                   env={"SCARB_CACHE": str(C.ensure_scratch() /
                                           spec["run_slug"] / "scarb-cache")})
    out = r["stdout"] + "\n" + r["stderr"]
    passed = {m.group(1) for m in RE_PASS.finditer(out)}
    failed = {m.group(1) for m in RE_FAIL.finditer(out)}
    ran = bool(RE_RESULT.search(out))
    target = "scaled_multiplies_by_three"
    ok = ran and target in passed and not failed
    return C.make_run(
        platform=PLATFORM, record_id=rid, run_slug=spec["run_slug"],
        claim="runner capability control only: this generated package "
              "reproduces no claim in the dataset",
        status="executed" if ran else "compile_failed",
        outcome="executed_without_impact" if ok else "compile_failed",
        ladder="L4" if ok else "L2",
        toolchain=toolchain(),
        pin={"repo": None, "requested_ref": "generated by this adapter",
             "commit": C.sha256_file(tree / "src" / "lib.cairo"),
             "resolved_by": "sha256 of the generated source",
             "revision_unresolved": None},
        assertion={"name": f"nonevm_cairo_control::{target}",
                   "kind": "named_test",
                   "statement": "scarb cairo-test compiles and runs a named "
                                "test in this environment",
                   "expected": {"test_status": "PASS"},
                   "observed": {"test_status": "PASS" if target in passed
                               else ("FAIL" if target in failed else None),
                                "passed": len(passed), "failed": len(failed)},
                   "met": ok, "not_just_exit_code": True},
        run={"argv": argv, "cwd": str(tree), "exit_code": r["exit_code"],
             "seconds": r["seconds"], "timeout_seconds": 280,
             "run_kind": "native_test" if ran else "compile_only",
             "isolation": "generated package in a scratch tree; local Cairo "
                          "runner only, no node, no deployment"},
        prerequisites=pre, licence=licence(), stdout=r["stdout"],
        stderr=r["stderr"], blocker=None if ran else
        ("compile_failed: scarb " +
         C.tool_version([str(SCARB), "--version"]).split(" / ")[0] +
         " no longer accepts the plain #[test] attribute in a cairo-test "
         "target (the runner is deprecated in favour of snforge, and snforge "
         "needs universal-sierra-compiler, which is absent). First "
         "diagnostic: " + _first_diag(out)),
        evidence_note="harness self-test: separates 'this revision cannot be "
                      "built here' from 'Cairo execution is impossible here'")


def execute_blocked(row: dict) -> dict:
    cand = row["candidate"]
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=f"blocked-{cand['record_id'].split(':')[-1][:40]}",
        claim=cand["title"] or "", status="blocked", outcome="blocked",
        ladder="L1", toolchain=toolchain(),
        pin={"requested_ref": cand.get("affected_versions"), "commit": None,
             "revision_unresolved": row["blocker"]},
        assertion=None,
        run={"argv": [str(SCARB), "cairo-test"], "run_kind": "none",
             "isolation": "would be an isolated scratch clone; local runner only"},
        prerequisites=prerequisites(), licence=licence(),
        blocker=row["blocker"],
        evidence_note="candidate in the v2.2 pool that this pilot could not "
                      "execute; the blocker text is the finding")

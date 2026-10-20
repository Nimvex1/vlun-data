"""CosmWasm adapter: cargo-pinned dependency-version differentials.

Platform: CosmWasm (cosmwasm-std / cosmwasm-vm / wasmvm).
Native runner available here: `cargo test` (Rust).  The chain runtime
(wasmd / wasmvm / a node) is NOT used: no live-chain transaction, no funds,
no deployment.  Every run builds a generated harness crate in an isolated
scratch directory whose `Cargo.toml` pins cosmwasm-std to one exact version,
so the tested code is the published artefact at that pin.

The claims this adapter can execute are the cosmwasm-std arithmetic advisories
(CWA-2024-002 / RUSTSEC-2024-0338), whose text names the affected functions
(`Uint{256,512}::pow`, `Int{256,512}::neg`) and the version ranges, and which
explicitly scopes the 64/128-bit cases to a build without `overflow-checks`.
Because that scoping is a *testable* statement, each version is run in both
Rust profiles:

    release : overflow-checks off (Cargo's release default)
    test/dev: overflow-checks on  (Cargo's dev default)

Each run evaluates one named assertion (one #[test] by exact name), not an
exit code.  The assertion says "the operation silently wraps"; it is expected
to PASS on a declared-vulnerable pin and to FAIL (panic) on a patched pin, so
the same test both reproduces the violation and blocks the fix.
"""
from __future__ import annotations

import re
from pathlib import Path

import common as C

PLATFORM = "cosmwasm"

CARGO = ["cargo"]

# declared in the advisory: affected -> expected "ok", patched -> "failed"
PINS = [
    ("1.5.3", "declared_vulnerable"),
    ("1.5.4", "declared_patched"),
    ("2.0.1", "declared_vulnerable"),
    ("2.0.2", "declared_patched"),
]
PROFILES = [("release", "overflow-checks off"), ("dev", "overflow-checks on")]

# cosmwasm-std 2.0.x does not compile against a floating cosmwasm-crypto: the
# newer crypto adds an RNG argument to ed25519_batch_verify and new
# CryptoError variants.  Pinning the transitive crate is part of pinning the
# revision, so the affected/patched 2.0 pins are locked pair-wise.
EXTRA_PINS = {
    "2.0.1": [("cosmwasm-crypto", "=2.0.1")],
    "2.0.2": [("cosmwasm-crypto", "=2.0.2")],
}

TESTS = {
    "uint256_pow_overflow_wraps_silently":
        "Uint256::pow with an exponent that overflows the 256-bit range "
        "returns a wrapped value instead of panicking",
    "uint512_pow_overflow_wraps_silently":
        "Uint512::pow with an exponent that overflows returns a wrapped "
        "value instead of panicking",
    "int256_neg_min_wraps_silently":
        "negating Int256::MIN returns a wrapped value instead of panicking",
    "uint128_pow_overflow_wraps_silently":
        "Uint128::pow with an overflowing exponent returns a wrapped value "
        "(the advisory scopes this to builds without overflow-checks)",
    "pow_in_range_control":
        "a non-overflowing pow still returns the exact product, so the "
        "differential above is not vacuous",
}

HARNESS = '''use cosmwasm_std::{Uint128, Uint256, Uint512, Int256};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint256_pow_overflow_wraps_silently() {
        let r = std::panic::catch_unwind(|| Uint256::from(2u128).pow(257));
        assert!(r.is_ok(), "Uint256::pow panicked: no silent wrap");
        println!("WRAPPED_UINT256 {}", r.unwrap());
    }

    #[test]
    fn uint512_pow_overflow_wraps_silently() {
        let r = std::panic::catch_unwind(|| Uint512::from(2u128).pow(513));
        assert!(r.is_ok(), "Uint512::pow panicked: no silent wrap");
    }

    #[test]
    fn int256_neg_min_wraps_silently() {
        let r = std::panic::catch_unwind(|| -Int256::MIN);
        assert!(r.is_ok(), "-Int256::MIN panicked: no silent wrap");
    }

    #[test]
    fn uint128_pow_overflow_wraps_silently() {
        let r = std::panic::catch_unwind(|| Uint128::new(2).pow(128));
        assert!(r.is_ok(), "Uint128::pow panicked: no silent wrap");
    }

    #[test]
    fn pow_in_range_control() {
        assert_eq!(Uint256::from(2u128).pow(10), Uint256::from(1024u128));
        assert_eq!(Uint128::new(2).pow(10), Uint128::new(1024));
    }
}
'''

RE_TESTLINE = re.compile(r"^test (\S+) \.\.\. (\w+)", re.M)
RE_SUMMARY = re.compile(r"^test result: (\w+)\. (\d+) passed; (\d+) failed",
                        re.M)

CLAIM_TEXT = ("cosmwasm-std integer types can silently wrap instead of "
              "panicking on overflow (CWA-2024-002 / RUSTSEC-2024-0338)")


def prerequisites() -> list[dict]:
    cargo = C.which("cargo")
    ver = C.tool_version(["cargo", "--version"]) if cargo else None
    rustc = C.tool_version(["rustc", "--version"]) if cargo else None
    return [
        {"tool": "cargo", "install_status": "installed" if cargo else "missing",
         "version": ver, "install_command": None if cargo
         else "rustup component list / https://rustup.rs"},
        {"tool": "rustc", "install_status": "installed" if cargo else "missing",
         "version": rustc, "install_command": None if cargo
         else "https://rustup.rs"},
        {"tool": "crates.io registry access",
         "install_status": "assumed_available" if cargo else "missing",
         "version": None,
         "install_command": None if cargo
         else "cargo search serde --limit 1   # proves the registry is reachable",
         "note": "only the package registry is contacted; no chain RPC, "
                 "no faucet, no deployment"},
    ]


def toolchain() -> dict:
    return {"tool": "cargo", "version": C.tool_version(["cargo", "--version"]),
            "runtime": C.tool_version(["rustc", "--version"]),
            "native_command": "cargo test"}


def _scratch(cell: str) -> Path:
    """One generated crate per (version, profile) cell, reused by its tests.

    The cell directory is keyed by version+profile rather than by the single
    test, so the dependency graph is built once and every named assertion
    afterwards is a libtest invocation against the same compiled binary.  A
    shared CARGO_TARGET_DIR keeps the artefacts of other cells warm too.
    """
    p = C.ensure_scratch() / "cw" / cell
    p.mkdir(parents=True, exist_ok=True)
    (p / "src").mkdir(parents=True, exist_ok=True)
    return p


def prepare(cell_dir: Path, argv_build: list[str]) -> dict:
    """Build the test binary before timing an assertion.

    Cargo resumes an interrupted build, so up to three bounded attempts are
    made; the build is preparation, not the measured run.
    """
    marker = cell_dir / ".prepared"
    if marker.exists():
        return {"attempts": 0, "ok": True}
    last = None
    for _ in range(3):
        last = C.run_argv(argv_build, cwd=cell_dir, timeout=280,
                          env={"CARGO_TERM_COLOR": "never",
                               "CARGO_TARGET_DIR": str(C.ensure_scratch() /
                                                       "cw-target")})
        if last["exit_code"] == 0 or "error[E" in (last["stdout"]
                                                   + last["stderr"]):
            break
    ok = last is not None and (last["exit_code"] == 0
                              or "Executable" in (last["stdout"] + last["stderr"]))
    if ok:
        C.write_text(marker, "prepared\n")
    return {"attempts": 1, "ok": ok, "exit_code": (last or {}).get("exit_code"),
            "output": ((last or {}).get("stdout", "")
                       + (last or {}).get("stderr", ""))[-4000:]}


def _harness_files(dir_: Path, version: str) -> dict:
    pins = f'cosmwasm-std = "={version}"\n'
    for name, req in EXTRA_PINS.get(version, []):
        pins += f'{name} = "{req}"\n'
    toml = ('[package]\nname = "nonevm_cw"\nversion = "0.1.0"\n'
            'edition = "2021"\n\n[dependencies]\n' + pins +
            '\n[profile.release]\noverflow-checks = false\n\n'
            '[profile.test]\noverflow-checks = true\n')
    C.write_text(dir_ / "Cargo.toml", toml)
    C.write_text(dir_ / "src" / "lib.rs", HARNESS)
    return {
        "Cargo.toml.sha256": C.sha256_file(dir_ / "Cargo.toml"),
        "src/lib.rs.sha256": C.sha256_file(dir_ / "src" / "lib.rs"),
    }


def plan(records: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (executable run specs, blocked rows) for the cosmwasm pool."""
    specs, blocked = [], []
    pool = C.candidates_for(PLATFORM, records)
    by_id = {c["record_id"]: c for c in pool}
    cand = by_id.get("rust:CWA-2024-002")
    if cand:
        for version, role in PINS:
            for profile, profile_note in PROFILES:
                for tname, tdesc in TESTS.items():
                    specs.append({
                        "platform": PLATFORM, "candidate": cand,
                        "version": version, "role": role, "profile": profile,
                        "profile_note": profile_note, "test": tname,
                        "test_desc": tdesc,
                        "cell": f"cosmwasm-std-{version}-{profile}",
                        "run_slug": f"cosmwasm-std-{version}-{profile}-{tname}",
                    })
    for cand in pool:
        rid = cand["record_id"]
        if rid == "rust:CWA-2024-002":
            continue
        if rid == "rust:CWA-2026-006":
            reason = ("build_time_exceeds_pilot_budget: the claim is about the "
                      "Wasmer Singlepass compiler embedded in wasmvm; it needs "
                      "a cgo wasmvm build (Wasmer plus a Go host) before any "
                      "assertion can run")
        elif rid == "rust:CWA-2024-004":
            reason = ("build_time_exceeds_pilot_budget: gas mispricing is "
                      "observed through cosmwasm-vm's metered instantiate, "
                      "which needs the full cosmwasm-vm/Wasmer build graph")
        else:
            reason = ("revision_unresolved: the Levana post-mortem names no "
                      "commit, contract version or deployment, so no pin can "
                      "be resolved")
        blocked.append({"platform": PLATFORM, "candidate": cand,
                        "blocker": reason,
                        "run_slug": "blocked"})
    return specs, blocked


def execute(spec: dict) -> dict:
    cand, version, profile, tname = (spec["candidate"], spec["version"],
                                     spec["profile"], spec["test"])
    role = spec["role"]
    prereq = prerequisites()
    cargo = next(p for p in prereq if p["tool"] == "cargo")
    if cargo["install_status"] != "installed":
        return C.make_run(
            platform=PLATFORM, record_id=cand["record_id"],
            run_slug=spec["run_slug"], claim=CLAIM_TEXT, status="blocked",
            outcome="blocked", ladder="L1", toolchain=toolchain(),
            pin={"requested_ref": f"cosmwasm-std={version}", "commit": None,
                 "resolved_by": "crates.io version pin", "revision_unresolved":
                 None},
            assertion=None, run=None, prerequisites=prereq,
            licence=licence(), blocker="toolchain_missing: cargo")

    dir_ = _scratch(spec["cell"])
    harness_files = _harness_files(dir_, version)
    shared_target = str(C.ensure_scratch() / "cw-target")
    env = {"CARGO_TERM_COLOR": "never", "CARGO_TARGET_DIR": shared_target}
    build = ["cargo", "test", "--tests", "--no-run"]
    if profile == "release":
        build.append("--release")
    prep = prepare(dir_, build)
    if not prep["ok"]:
        return C.make_run(
            platform=PLATFORM, record_id=cand["record_id"],
            run_slug=spec["run_slug"], claim=CLAIM_TEXT,
            status="compile_failed", outcome="compile_failed", ladder="L2",
            toolchain=toolchain(), pin={"requested_ref": f"={version}",
                                        "commit": None, "resolved_by":
                                        "crates.io version pin",
                                        "harness_files": harness_files},
            assertion={"name": f"tests::{tname}", "kind": "compile_only",
                       "expected": "compiles", "observed": "does not compile",
                       "met": False},
            run={"argv": build, "cwd": str(dir_), "exit_code":
                 prep.get("exit_code"), "run_kind": "compile_only",
                 "isolation": "generated crate in an isolated scratch dir"},
            prerequisites=prereq, licence=licence(),
            blocker="compile_failed: the pinned crate plus generated harness "
                    "did not build",
            stdout="", stderr=prep.get("output", ""))

    argv = ["cargo", "test", "--tests"]
    if profile == "release":
        argv.append("--release")
    argv += ["--", "--exact", f"tests::{tname}"]
    r = C.run_argv(argv, cwd=dir_, timeout=280, env=env)
    out = r["stdout"] + "\n" + r["stderr"]

    lock = dir_ / "Cargo.lock"
    pin = {
        "repo": "https://github.com/CosmWasm/cosmwasm",
        "requested_ref": f"crates.io cosmwasm-std ={version}",
        "commit": None,
        "resolved_by": "cargo.lock",
        "lock_sha256": C.sha256_file(lock) if lock.exists() else None,
        "lock_resolved_version": _lock_version(lock, "cosmwasm-std"),
        "revision_unresolved": None,
        "harness_files": harness_files,
    }
    observed = None
    for m in RE_TESTLINE.finditer(out):
        if m.group(1).endswith(f"::{tname}"):
            # libtest prints ok / FAILED / ignored; normalise so the
            # expectation ("ok" or "failed") compares case-insensitively
            observed = m.group(2).lower()
    summary = RE_SUMMARY.search(out)
    # the control never depends on the advisory's role: it must pass on every
    # pin, otherwise the differential cells prove nothing
    expected = "ok" if (tname == "pow_in_range_control"
                        or role == "declared_vulnerable") else "failed"
    # a passing non-vacuity control reproduces nothing
    is_claim_cell = tname != "pow_in_range_control"
    if r["exit_code"] == 101 and observed is None and "error[E" in out:
        status, outcome, ladder = "compile_failed", "compile_failed", "L2"
        blocker = "compile_failed: the generated harness did not build"
    elif observed is None:
        status, outcome, ladder = "timeout", "inconclusive", "L2"
        blocker = f"run_produced_no_named_test_result exit={r['exit_code']}"
    else:
        status, blocker = "executed", None
        met = (observed == expected)
        if role == "declared_vulnerable" and met and is_claim_cell:
            outcome, ladder = "claim_reproduced", "L5"
        elif role == "declared_patched" and met:
            outcome, ladder = "executed_without_impact", "L4"
        else:
            outcome, ladder = "executed_without_impact", "L4"
    met_final = (observed == expected) if observed else None
    note = _note(role, profile, tname, observed, expected)
    assertion = {
        "name": f"tests::{tname}",
        "kind": "named_test",
        "statement": spec["test_desc"],
        "expected": {"test_status": expected,
                     "why": f"{version} is {role}; {spec['profile_note']}"},
        "observed": {"test_status": observed,
                     "suite_summary": summary.group(0) if summary else None},
        "met": met_final,
        "not_just_exit_code": True,
    }
    run = {"argv": argv, "cwd": str(dir_), "exit_code": r["exit_code"],
           "seconds": r["seconds"], "timeout_seconds": 280,
           "run_kind": "test_harness",
           "isolation": "generated crate in an isolated scratch dir; local "
                        "test harness only - no chain, no funds, no node"}
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=spec["run_slug"], claim=CLAIM_TEXT, status=status,
        outcome=outcome, ladder=ladder, toolchain=toolchain(), pin=pin,
        assertion=assertion, run=run, prerequisites=prereq, licence=licence(),
        stdout=r["stdout"], stderr=r["stderr"], blocker=blocker,
        evidence_note=note)


def execute_blocked(row: dict) -> dict:
    cand = row["candidate"]
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=f"blocked-{cand['record_id'].split(':')[-1][:32]}",
        claim=CLAIM_TEXT, status="blocked", outcome="blocked", ladder="L1",
        toolchain=toolchain(),
        pin={"requested_ref": cand.get("affected_versions"), "commit": None,
             "revision_unresolved": row["blocker"]},
        assertion=None,
        run={"argv": [], "run_kind": "none",
             "isolation": "would be an isolated local cargo/chain-sandbox run"},
        prerequisites=prerequisites(), licence=licence(),
        blocker=row["blocker"],
        evidence_note="candidate recorded in derived_v2_2 but not executed in "
                      "this pilot; the blocker is the finding.")


def _lock_version(lock: Path, crate: str) -> str | None:
    if not lock.exists():
        return None
    txt = lock.read_text(encoding="utf-8", errors="replace")
    m = re.search(rf'name = "{crate}"\nversion = "([^"]+)"', txt)
    return m.group(1) if m else None


def _note(role: str, profile: str, tname: str, observed, expected) -> str:
    if observed is None:
        return "no named-test result line was produced; recorded as inconclusive"
    base = (f"pin {role}, profile {profile}: expected {expected}, "
            f"observed {observed}.")
    if tname == "pow_in_range_control":
        base += " Non-vacuity control: a passing control is not a reproduction."
    if tname == "uint128_pow_overflow_wraps_silently":
        base += (" This cell is the advisory's own scoping statement: the "
                 "64/128-bit cases wrap only when overflow-checks is off.")
    if observed != expected and tname != "pow_in_range_control":
        base += (" Declared behaviour and observed behaviour differ: recorded "
                 "as executed_without_impact, not as a reproduction.")
    return base


def licence() -> dict:
    return {"upstream": "Apache-2.0 (cosmwasm-std)",
            "harness_origin": "generated by this adapter; no upstream source "
                              "file is copied into the artefacts",
            "redistribution": "allowed", "withheld": None}

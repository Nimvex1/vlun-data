"""Solana Anchor adapter.

Platform: Solana / Anchor.  Native runner: `anchor test`, which builds BPF
and drives a local `solana-test-validator` - still an isolated local test
environment, never a live cluster.

Neither the Anchor CLI nor the Solana CLI is installed on this host, and this
pilot does not install system software or build toolchains from source, so
the Anchor candidates are recorded as blocked with the exact install commands
a user would run.  The pinning half of the work is done: the crate and the
version range each claim needs are named, so clearing the prerequisite leaves
only `cargo build-bpf`/`anchor test`.

Route recorded but not executed inside this pilot's per-run budget: the two
anchor-lang advisories concern `anchor-lang` itself, which is a plain Rust
crate, so a `cargo test` harness around `Program::<Accounts, System>::try_from`
(an AccountInfo with a foreign program id as owner) is the cheapest way to
reach L4/L5 for those records without any chain tooling.  A build of
anchor-lang plus solana-program did not finish inside the 300 s per-run
budget available to this pilot, so no such run is claimed here.
"""
from __future__ import annotations

import common as C

PLATFORM = "solana_anchor"

ANCHOR_INSTALL = ("cargo install --git https://github.com/coral-xyz/anchor "
                  "avm --force --locked && avm install latest && avm use latest")
SOLANA_INSTALL = ('sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"'
                  " then add ~/.local/share/solana/install/active_release/bin "
                  "to PATH")

PINS = {
    "rust:CVE-2026-45137": {
        "crate": "anchor-lang", "repo":
            "https://github.com/coral-xyz/anchor",
        "requested_ref": "v1.0.1 (declared affected) vs v1.0.2 (declared patched)",
        "component": "lang/src/accounts/program.rs - TryFrom<&AccountInfo> for "
                     "Program<'info, T>",
    },
    "rust:GHSA-429q-fhh4-r6hj": {
        "crate": "anchor-lang", "repo": "https://github.com/coral-xyz/anchor",
        "requested_ref": "1.0.0-rc.1 (affected) vs 1.0.0-rc.2 (patched)",
        "component": "InterfaceAccount account substitution",
    },
    "rust:GHSA-6px8-6mw3-4hx4": {
        "crate": "anchor-lang", "repo": "https://github.com/coral-xyz/anchor",
        "requested_ref": "v1.1.2 with feature lazy-account (confirmed by the "
                         "report); no patched release published",
        "component": "lang/src/accounts/lazy_account.rs - LazyAccount::unload()",
    },
}


def prerequisites() -> list[dict]:
    anchor, solana = C.which("anchor"), C.which("solana")
    return [
        {"tool": "anchor-cli", "install_status": "installed" if anchor else "missing",
         "version": C.tool_version(["anchor", "--version"]) if anchor else None,
         "install_command": None if anchor else ANCHOR_INSTALL, "blocking": True},
        {"tool": "solana-cli (incl. solana-test-validator)",
         "install_status": "installed" if solana else "missing",
         "version": C.tool_version(["solana", "--version"]) if solana else None,
         "install_command": None if solana else SOLANA_INSTALL, "blocking": True},
        {"tool": "cargo", "install_status": "installed" if C.which("cargo")
         else "missing", "version": C.tool_version(["cargo", "--version"]),
         "install_command": None, "blocking": False,
         "note": "present, and enough for a crate-level harness, but not for "
                 "`anchor test`, which needs a BPF build and a local validator"},
        {"tool": "cryptography tooling note", "install_status": "not_used",
         "blocking": False,
         "note": "no key material, faucet claim or cluster RPC is used by this "
                 "adapter; the pilot never touches a live network"},
    ]


def toolchain() -> dict:
    return {"tool": "anchor-cli", "native_command": "anchor test",
            "version": C.tool_version(["anchor", "--version"]),
            "solana_version": C.tool_version(["solana", "--version"]),
            "install_status": "installed" if C.which("anchor") else "missing",
            "install_command": None if C.which("anchor")
            else f"{ANCHOR_INSTALL} ; {SOLANA_INSTALL}"}


def licence() -> dict:
    return {"upstream": "Apache-2.0 or MIT (anchor-lang, dual licensed)",
            "harness_origin": "none built; no upstream file is copied",
            "redistribution": "not applicable", "withheld": "not needed - "
                              "no third-party source entered an artefact"}


def plan(records: list[dict]) -> tuple[list[dict], list[dict]]:
    pool = C.candidates_for(PLATFORM, records)
    blocked = [{"platform": PLATFORM, "candidate": c,
                "blocker": ("toolchain_missing: solana-anchor (anchor-cli and "
                            "solana-cli are both absent; `anchor test` needs "
                            "the BPF build and a local solana-test-validator)"),
                "run_slug": "blocked"} for c in pool]
    return [], blocked


def execute_blocked(row: dict) -> dict:
    """Invoke the native commands for real so the blocker is observed."""
    cand = row["candidate"]
    a = C.run_argv(["anchor", "test"], timeout=60)
    s = C.run_argv(["solana", "--version"], timeout=60)
    pin = PINS.get(cand["record_id"], {})
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=f"blocked-{cand['record_id'].split(':')[-1][:40]}",
        claim=cand["title"] or "", status="blocked", outcome="blocked",
        ladder="L1", toolchain=toolchain(),
        pin={"repo": pin.get("repo"), "crate": pin.get("crate"),
             "requested_ref": pin.get("requested_ref"),
             "component": pin.get("component"), "commit": None,
             "revision_unresolved": None if pin else
             "no repository or commit is named by the source"},
        assertion={"name": None, "kind": "not_run",
                   "statement": "anchor test cannot be started until the "
                                "Anchor and Solana CLIs are installed",
                   "expected": None, "observed": None, "met": None},
        run={"argv": a["argv"], "exit_code": a["exit_code"],
             "seconds": a["seconds"], "timeout_seconds": 60,
             "run_kind": "none",
             "isolation": "no isolation needed: the runner never started; a "
                          "real run would use a local validator, never a "
                          "live cluster"},
        prerequisites=prerequisites(), licence=licence(),
        blocker=row["blocker"],
        stdout=a["stdout"] + s["stdout"],
        stderr=(a["stderr"] + "\n" + s["stderr"]).strip(),
        evidence_note=("native runner probed on PATH: `anchor test` exited "
                       f"{a['exit_code']} and `solana --version` exited "
                       f"{s['exit_code']}, which is the prerequisite recorded "
                       "as data. Install: " + ANCHOR_INSTALL + " ; "
                       + SOLANA_INSTALL))

"""Aptos Move adapter.

Platform: Aptos Move.  Native runner: `aptos move test` (Aptos CLI).
The Aptos CLI is not installed on this host and this pilot does not install
system software, so every Aptos candidate is recorded as blocked - with the
exact command a user would run to clear the prerequisite, and with the
pinning work (which package, which commit) resolved so that the run is one
command away from executing.

One thing is checked rather than assumed: the native command is actually
invoked, and the resulting spawn failure is captured as the evidence.
"""
from __future__ import annotations

import common as C

PLATFORM = "aptos_move"

APTOS_INSTALL = ('curl -fsSL "https://get.aptos.dev/cli" | bash   '
                 '(Linux/macOS; on Windows the documented path is WSL)')

# record id -> (repo, pinned ref, package dir inside the repo, component)
TARGETS = {
    "move:CVE-2023-36184-aptos-side": (
        "https://github.com/aptos-labs/aptos-core", "47a0391c", "third_party/move"),
}

PINNED = {
    "move:move-vm-value-depth": {
        "repo": "https://github.com/aptos-labs/aptos-core",
        "requested_ref": "47a0391c612407fe0b1051ef658a29e35d986963",
        "package": "third_party/move (Move VM Rust crate, not a Move package)",
    },
    "move:zellic-3.2-control-flow-graph-aptos": {
        "repo": "https://github.com/move-language/move",
        "requested_ref": "1fa4ed20daaef28b47fe2c5a8d8f63b64523e16d",
        "package": "language/tools/move-bytecode-verifier (Rust)",
    },
    "move:amnis-peg-1-fee-evasion": {
        "repo": "https://github.com/tony001242/amnis-contract",
        "requested_ref": "08239f04ca136224a2f563b4ff63d0469d00c106 / "
                         "7eb9708b22d67dd9e6e57f3ea4891d1f35cc17f1 (audit scope)",
        "package": "sources/pegging.move",
    },
}


def prerequisites() -> list[dict]:
    aptos = C.which("aptos")
    return [
        {"tool": "aptos-cli", "install_status": "installed" if aptos else "missing",
         "version": C.tool_version(["aptos", "--version"]) if aptos else None,
         "install_command": None if aptos else APTOS_INSTALL,
         "blocking": True},
        {"tool": "aptos move test (local Move VM)",
         "install_status": "installed" if aptos else "missing",
         "version": None, "install_command": None if aptos else APTOS_INSTALL,
         "blocking": True,
         "note": "the Sui Move compiler already in work/tools cannot be "
                 "substituted: the packages import aptos_framework / "
                 "std::vector with the Aptos VM's signature and dependency "
                 "layout"},
    ]


def toolchain() -> dict:
    return {"tool": "aptos-cli", "native_command": "aptos move test",
            "version": C.tool_version(["aptos", "--version"]),
            "install_status": "installed" if C.which("aptos") else "missing",
            "install_command": None if C.which("aptos") else APTOS_INSTALL}


def licence() -> dict:
    return {"upstream": "Apache-2.0 (aptos-core) / unpublished for the Amnis "
                        "audit scope repository",
            "harness_origin": "none built; no upstream file is copied",
            "redistribution": "not applicable - nothing was compiled",
            "withheld": "no third-party code is redistributed; the WITHHELD.json "
                        "pattern is not needed because no harness was written"}


def plan(records: list[dict]) -> tuple[list[dict], list[dict]]:
    pool = C.candidates_for(PLATFORM, records)
    blocked = [{"platform": PLATFORM, "candidate": c,
                "blocker": _blocker_for(c["record_id"]),
                "run_slug": "blocked"} for c in pool]
    return [], blocked


def _blocker_for(rid: str) -> str:
    pre = "toolchain_missing: aptos-cli"
    if rid == "move:move-vm-value-depth":
        return (pre + "; and the component named by the record is the Aptos "
                "Move VM written in Rust, whose proof is a cargo test inside "
                "aptos-core (a workspace whose build exceeds this pilot's "
                "per-run budget)")
    if rid == "move:zellic-3.2-control-flow-graph-aptos":
        return (pre + "; the fix commit is in move-language/move's Rust "
                "bytecode verifier, so the assertion is a cargo test, not "
                "`aptos move test`")
    return pre


def execute_blocked(row: dict) -> dict:
    """Invoke the native command for real, so the blocker is observed."""
    cand = row["candidate"]
    attempt = C.run_argv(["aptos", "move", "test", "--help"], timeout=60)
    pin = PINNED.get(cand["record_id"], {})
    return C.make_run(
        platform=PLATFORM, record_id=cand["record_id"],
        run_slug=f"blocked-{cand['record_id'].split(':')[-1][:40]}",
        claim=cand["title"] or "", status="blocked", outcome="blocked",
        ladder="L1", toolchain=toolchain(),
        pin={"repo": pin.get("repo"), "requested_ref": pin.get("requested_ref"),
             "package": pin.get("package"), "commit": None,
             "revision_unresolved": None if pin else
             "the audit report fixes no commit for this finding"},
        assertion={"name": None, "kind": "not_run",
                   "statement": "aptos move test cannot be started until the "
                                "Aptos CLI is installed",
                   "expected": None, "observed": None, "met": None},
        run={"argv": attempt["argv"], "exit_code": attempt["exit_code"],
             "seconds": attempt["seconds"], "timeout_seconds": 60,
             "run_kind": "none",
             "isolation": "no isolation needed: the runner never started"},
        prerequisites=prerequisites(), licence=licence(),
        blocker=row["blocker"], stdout=attempt["stdout"],
        stderr=attempt["stderr"],
        evidence_note=("the native command was invoked and the spawn failed "
                       f"(exit {attempt['exit_code']}), which is the "
                       "prerequisite recorded as data; install command: "
                       + APTOS_INSTALL))

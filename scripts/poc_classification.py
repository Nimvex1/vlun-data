#!/usr/bin/env python3
"""PoC classification and quality levels.

The v2 dataset reported a PoC as "available" or "not available". That is not
enough to reason about, because a report's proof takes several different shapes:
an executable test, a fragment to paste into an existing test, a patch to the
*contract* that demonstrates the issue, a step-by-step recipe, or nothing at all.

This module assigns every exploit record exactly one class from a closed
vocabulary, and one quality level from L0 to L6. Both are statements about
*what the evidence is*, never about whether the finding is true.

Classes
-------
already_runnable                  a complete test function, self-contained enough to compile
runnable_after_import_fix         a complete test function whose imports need correcting
runnable_after_harness_reconstruction  a test body that needs the author's fixtures rebuilt
requires_fork                     needs historical chain state (an archive RPC)
requires_external_state           needs live third-party state or a private key
contract_patch_demonstration      the proof is a patch to the vulnerable contract
incomplete                        prose or a partial fragment with no executable core
invalid                           the artefact contradicts itself or is not a PoC at all
insufficient_evidence             the record makes a security claim with no proof attached

Levels
------
L0  report prose only
L1  PoC code quoted
L2  PoC reconstructed by this pipeline
L3  PoC compiles
L4  PoC executes
L5  PoC experimentally reproduces the claimed security violation
L6  L5 on the vulnerable revision AND fails for the correct reason on the fixed one

Only an actual run can produce L3 or above. Levels are assigned from experiment
artefacts, never from the shape of the text.
"""

from __future__ import annotations

import re

POC_CLASSES = (
    "already_runnable",
    "runnable_after_import_fix",
    "runnable_after_harness_reconstruction",
    "requires_fork",
    "requires_external_state",
    "contract_patch_demonstration",
    "incomplete",
    "invalid",
    "insufficient_evidence",
)

POC_LEVELS = {
    "L0": "report prose only",
    "L1": "PoC code quoted",
    "L2": "PoC reconstructed",
    "L3": "PoC compiles",
    "L4": "PoC executes",
    "L5": "claimed security violation reproduced",
    "L6": "reproduced on the vulnerable revision and blocked on the fixed one",
}

# Controlled vocabulary for why an experiment did not produce a level.
FAILURE_REASONS = (
    "source_unavailable",
    "historical_commit_unavailable",
    "dependency_unavailable",
    "compiler_unavailable",
    "toolchain_failure",
    "broken_original_test",
    "reconstruction_failed",
    "poc_invalid",
    "environment_unavailable",
    "rpc_unavailable",
    "archive_state_unavailable",
    "insufficient_evidence",
    "license_restriction",
    "timeout",
    "resource_limit",
    "fixed_before_execution",
    "other",
)

TEST_FN = re.compile(r"\bfunction\s+(test[A-Za-z0-9_]*)\s*\(")
ANY_FN = re.compile(r"\bfunction\s+([A-Za-z0-9_]+)\s*\(")
CHEATCODE = re.compile(r"\b(vm|stdstore|vm\.)\b|\bdeal\s*\(|\bhoax\s*\(")
ASSERT = re.compile(r"\b(assert[A-Za-z]*|require)\s*\(|vm\.expectRevert")
FORK_MARKERS = (
    "vm.createSelectFork", "vm.createFork", "--fork-url", "fork_block",
    "vm.roll", "block.number", "block.timestamp",
)
EXTERNAL_MARKERS = (
    "PRIVATE_KEY", "privateKey", "ALCHEMIST_KEY", "RPC_URL", "vm.envString",
    "https://", "apiKey",
)
CONTRACT_PATCH_MARKERS = (
    "// add the following", "add the following check", "should be replaced by",
    "suggested patch", "we suggest adding", "replace this with",
    "add this to the contract", "in the contract, add", "the fix is to add",
)


def _text(exploit: dict) -> str:
    parts = [
        exploit.get("code") or "",
        exploit.get("setup") or "",
        exploit.get("narrative") or "",
        exploit.get("reproducibility_note") or "",
    ]
    return "\n".join(p for p in parts if p)


def classify(exploit: dict) -> dict:
    """-> {class, evidence, signals}. Exactly one class, with the signals shown."""
    code = exploit.get("code") or ""
    setup = exploit.get("setup") or ""
    whole = _text(exploit)
    test_fns = TEST_FN.findall(code)

    signals = {
        "has_test_function": bool(test_fns),
        "test_function_count": len(test_fns),
        "has_cheatcodes": bool(CHEATCODE.search(code)),
        "has_assertions": bool(ASSERT.search(code)),
        "has_code": bool(code.strip()),
        "code_bytes": len(code),
        "mentions_fork": any(m in whole for m in FORK_MARKERS),
        "mentions_external_state": any(m in whole for m in EXTERNAL_MARKERS),
        "looks_like_contract_patch": any(m in whole.lower() for m in CONTRACT_PATCH_MARKERS),
        "framework_declared": (exploit.get("framework") or "").strip() or None,
        "test_file_declared": (exploit.get("test_file") or "").strip() or None,
        "setup_is_prose": bool(setup) and not code.strip(),
    }

    ev = {"evidence_type": "derived_fact", "signals": signals}

    # 1. nothing attached at all
    if not code.strip() and not setup.strip():
        return {"poc_class": "insufficient_evidence",
                "rationale": "the record carries no proof artefact: no code and no setup",
                **ev}

    # 2. a self-consistent executable test is present
    if test_fns:
        if signals["has_cheatcodes"] or signals["has_assertions"]:
            cls = "already_runnable"
            why = (f"a complete test function `{test_fns[0]}` with "
                   f"{'cheatcodes' if signals['has_cheatcodes'] else 'assertions'}")
        else:
            cls = "runnable_after_import_fix"
            why = (f"a test function `{test_fns[0]}` is present but the snippet carries no "
                   "imports, so it cannot be compiled as written")
        return {"poc_class": cls, "rationale": why, **ev}

    # 3. code that is not a test at all
    if code.strip():
        # a contract-patch demonstration is a function body aimed at the vulnerable
        # contract rather than at a test
        non_test_fns = [f for f in ANY_FN.findall(code) if not f.startswith("test")]
        if non_test_fns and signals["looks_like_contract_patch"]:
            return {"poc_class": "contract_patch_demonstration",
                    "rationale": (f"the artefact is a proposed function `{non_test_fns[0]}` "
                                  "intended to be added to the vulnerable contract, not a "
                                  "test that can be executed against the audited code"),
                    **ev}
        if re.search(r"\b(interface|library)\s+\w+", code) and "pragma solidity" in code:
            return {"poc_class": "contract_patch_demonstration",
                    "rationale": ("the artefact is a replacement interface or library, i.e. a "
                                  "suggested contract change rather than an executable test"),
                    **ev}
        return {"poc_class": "incomplete",
                "rationale": ("code is quoted but contains no test function and no contract "
                              "boundary, so it cannot be compiled or executed as published"),
                **ev}

    # 4. prose only
    low = whole.lower()
    if signals["mentions_fork"] and re.search(r"fork|mainnet|goerli|sepolia|arbitrum|base\b", low):
        return {"poc_class": "requires_fork",
                "rationale": ("the proof is a narrative that depends on historical chain state; "
                              "it can only be executed against a pinned archive fork"),
                **ev}
    if signals["mentions_external_state"]:
        return {"poc_class": "requires_external_state",
                "rationale": ("the proof depends on live third-party state or a private key, "
                              "which this dataset never handles"),
                **ev}
    return {"poc_class": "incomplete",
            "rationale": ("only prose is published: a step-by-step narrative with no "
                          "executable core"),
            **ev}


def level_for(classification: dict) -> dict:
    """The maximum level justified by the *shape* alone. L1 and below.

    A quoted test is L1 (published PoC), never L2: L2 means the pipeline
    reconstructed something, and classification happens before any
    reconstruction. Only an actual run can produce L3 or above.
    """
    cls = classification["poc_class"]
    if cls == "insufficient_evidence":
        return {"level": "L0", "basis": "no proof artefact is attached"}
    if cls == "already_runnable":
        return {"level": "L1", "basis": "a complete test function is quoted; nothing has been executed or reconstructed"}
    if cls == "runnable_after_import_fix":
        return {"level": "L1", "basis": "a test function is quoted but its imports are missing; nothing reconstructed yet"}
    if cls == "runnable_after_harness_reconstruction":
        return {"level": "L1", "basis": "a test body is quoted; the author's harness is not"}
    if cls == "requires_fork":
        return {"level": "L1", "basis": "a narrative proof requiring an archive fork"}
    if cls == "requires_external_state":
        return {"level": "L1", "basis": "a narrative proof requiring external state"}
    if cls == "contract_patch_demonstration":
        return {"level": "L1", "basis": "a suggested contract patch, not an executable test"}
    if cls == "invalid":
        return {"level": "L0", "basis": "the artefact is not a proof of the claim"}
    return {"level": "L0", "basis": "prose only"}


def upgrade_from_experiment(level: str, experiment: dict) -> tuple[str, str]:
    """Fold an experiment outcome into the level.

    The mapping is deliberately conservative: a test that merely runs is L4, and
    only a declared security property failing on the vulnerable revision (or a
    declared exploit succeeding) reaches L5.
    """
    v = experiment.get("revisions", {}).get("vulnerable") or {}
    f = experiment.get("revisions", {}).get("fixed") or {}
    vs, _fs = v.get("status"), f.get("status")
    verdict = experiment.get("verdict")

    if verdict == "l6_verified_patch":
        return "L6", ("the declared exploit outcome was observed on the audited revision and "
                      "the security property held on the fixed revision")
    if vs in ("pass", "fail") and experiment.get("classification") in (
            "already_runnable", "runnable_after_harness_reconstruction",
            "runnable_after_import_fix"):
        # did the experiment demonstrate the violation, or merely execute?
        exp_v = experiment.get("revisions", {}).get("vulnerable", {}).get(
            "declared_expected_status")
        if exp_v and vs == ("fail" if exp_v == "fail" else "pass"):
            if vs == "pass" and exp_v == "pass" and (experiment.get("match_test") or "").startswith("test_Vlun"):
                return "L5", ("the harness asserts the exploit succeeds and it did on the "
                              "audited revision")
            if vs == "fail" and exp_v == "fail":
                return "L5", ("the declared security-property assertion failed on the audited "
                              "revision, which is the observed violation")
            return "L5", ("the declared exploit outcome was observed on the audited "
                          "revision (expected status matched; no failure occurred, "
                          "so no failure is claimed)")
        return "L4", "the reconstructed test executed; it did not demonstrate the claimed violation"
    if vs in ("compile_error", "toolchain_failure", "timeout"):
        return level, "the reconstructed harness could not be executed on this revision"
    if vs == "pass":
        return "L4", "the reconstructed test executed"
    return level, "no execution evidence"
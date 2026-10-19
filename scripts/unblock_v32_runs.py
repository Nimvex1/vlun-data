#!/usr/bin/env python3
"""V3.2 recovery orchestrator for the four blocked fork runs.

The V3.2 pass (``scripts/run_dhl_experiments.py``) left four runs ``blocked``
at L3 with ``failure_reason: archive_state_unavailable``: burgerswap, gamma,
prisma, shibatoken. This module inspects each blocked run's OWN log and pinned
source (not just its summary category) and re-executes it under a documented
attempt strategy:

  1. archive provider      alternative public archive RPC for the SAME pinned
                           fork target (no scope change to the claim);
  2. rule-compat hardfork  pinned fork target kept, EVM rule set pinned to the
                           rules in force at that height (pre-Prague), because
                           foundry/revm validates replayed historical
                           transactions with TODAY's rules (EIP-7623 gas floor
                           made the prisma replay impossible);
  3. harness reconstruction minimal overlay so the fork point is expressible
                           without transaction replay (fork by block instead of
                           by transaction hash);
  4. provider access       recorded as ``provider_access_unavailable`` when the
                           only remaining providers need an API key / paid plan
                           (no signups, no secrets, no keys are ever stored).

Every attempt lives in ``experiments_v3/<run>/attempt_N/`` and only ADDS that
subdirectory. The bytes at the run root (``command.txt``, ``stdout.txt``,
``stderr.txt``, ``toolchain.txt``, ``harness.json``, ``result.json``) are
hash-pinned by the proof-hashes gate and are never opened for writing -- the
original staged PoC bytes stay untouched; any change goes to ``overlay/``.

Evidence discipline (levels per ``scripts/poc_classification.py``):

  * a level is read back from the attempt's own log, never asserted: L4 needs
    a ``[PASS]`` line for the selected test, L5 additionally needs attacker-side
    profit > 0 in the balance logs;
  * a run that is not recovered keeps its explicit blocker and its L3;
  * any attempt that deviates from the pinned fork target or from today's rule
    set MUST carry a ``scope_change`` note -- the validator rejects it
    otherwise, because "reproduced under the rules at that height" is a
    different claim from "reproduced under today's rules".

Nothing here promotes a canonical layer: ``derived_v3/`` and
``reports/v3/experimental_proof.json`` are read-only inputs. Recovery results
are reported for the main agent to integrate. Safety: local forks + read-only
RPC only; no live transactions, no funds, no deployments, no Docker.

    python scripts/unblock_v32_runs.py --help
    python scripts/unblock_v32_runs.py --check           # plan only
    python scripts/unblock_v32_runs.py --only prisma --timeout 300
    python scripts/unblock_v32_runs.py --report-only     # rebuild reports
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_v3 as V  # noqa: E402
from run_dhl_experiments import (ARCHIVE_MARKERS, RPC_MARKERS, profit_deltas,
                                 test_fns)  # noqa: E402

ROOT = V.ROOT
CLONE = V.CLONES / "defihacklabs"
TEST = CLONE / "src" / "test"
LIB = CLONE / "lib"
EXP = ROOT / "experiments_v3"
REPORTS = V.REPORTS_V3 / "v32_unblock_attempts.json"
REPORTS_MD = V.REPORTS_V3 / "v32_unblock_attempts.md"
SCRATCH = ROOT / "work" / "v32"

LADDER = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]
# root artefacts are immutable: this module never writes these at the run root
PROTECTED = ("command.txt", "stdout.txt", "stderr.txt", "toolchain.txt",
             "harness.json", "result.json")
# a level is only real if the log itself shows it
RECOVERED = ("executed_no_profit_evidence", "violation_observed")

# Providers that need a key / paid plan: recorded as access blockers, never
# configured with a secret.
KEY_GATED = {
    "https://rpc.ankr.com/bsc": "API key required (401 Unauthorized)",
    "https://rpc.ankr.com/arbitrum": "API key required (401 Unauthorized)",
    "https://bsc-rpc.publicnode.com": "personal token required (403)",
    "https://arbitrum-one.publicnode.com": "personal token required (403)",
    "https://ethereum-rpc.publicnode.com": "personal token required (403)",
    "https://bsc-pokt.nodies.app": "paid subscription plan required (403)",
}
# Tenderly-style saved-simulation access: only if credentials already exist
# locally. Never provisioned by this script, never written into an artefact.
LOCAL_TENDERLY_ENV = ("TENDERLY_ACCESS_KEY", "TENDERLY_PROJECT_SLUG",
                      "TENDERLY_USERNAME")

# Read-only fallbacks for resolving "which block held the pinned attack tx".
TX_BLOCK_RESOLVERS = ["https://eth.drpc.org",
                      "https://eth-mainnet.public.blastapi.io"]

# Words that only say WHERE in the attack the number was taken, never WHAT it
# is. A before/after pair counts as profit evidence only when the remaining
# subject words (the asset / the account) match, so that e.g. "Attacker start
# with ~1800 mkUSD" and "wstETH balance ... after attack" cannot be paired into
# a positive "profit" across two different tokens.
POSITION_WORDS = {"before", "after", "current", "start", "started", "balance",
                  "balanceof", "of", "the", "with", "total", "value", "amount",
                  "exploit", "exploiting", "attack", "attacking", "contract",
                  "address", "approximately", "about"}


def label_subjects(label: str) -> set:
    return {w for w in re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", (label or ""))
            if w.lower() not in POSITION_WORDS}


def attacker_profit_evidence(stdout: str) -> list[dict]:
    """Shared-parser deltas, each marked with whether it is admissible L5
    evidence (same subject on both sides, attacker-labelled, positive delta)."""
    out = []
    for d in profit_deltas(stdout):
        subj = sorted(label_subjects(d["label_before"])
                      & label_subjects(d["label_after"]))
        rec = dict(d)
        rec["matched_subjects"] = subj
        rec["valid_attacker_profit"] = bool(d.get("attacker_side")
                                            and d.get("profit", 0) > 0
                                            and subj)
        out.append(rec)
    return out


def tenderly_access() -> dict:
    """Is Tenderly usable from already-present local access? (probe, no secrets)"""
    import os
    present = [k for k in LOCAL_TENDERLY_ENV if os.environ.get(k)]
    return {"available": len(present) == len(LOCAL_TENDERLY_ENV),
            "keys_present": sorted(present),
            "note": "no signups and no secrets are handled by this script; "
                    "access is probed from the environment only"}


# ---------------------------------------------------------------- pinned info

def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def submodule_shas() -> dict:
    """Submodule SHAs of the pinned clone (read-only git query)."""
    try:
        p = subprocess.run(["git", "-C", str(CLONE), "submodule", "status"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        out = {}
        for ln in (p.stdout or "").splitlines():
            m = re.match(r"^\s*\+?-?\s*([0-9a-f]{40})\s+(\S+)", ln)
            if m:
                out[m.group(2)] = m.group(1)
        return out
    except Exception:
        return {}


def remappings() -> dict:
    """Remappings the pinned clone uses (forge-std/=lib/forge-std/src/)."""
    txt = (CLONE / "remappings.txt")
    out = {}
    if txt.is_file():
        for ln in txt.read_text(errors="ignore").splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def parse_fork_target(poc_text: str) -> dict:
    """The fork target the PoC pins for itself: alias + block or tx hash."""
    m = re.search(r'createSelectFork\(\s*"([^"]+)"\s*,\s*'
                  r'([0-9_]+|bytes32\(0x[0-9a-fA-F]+\)|hex"[0-9a-fA-F]+"|'
                  r'[A-Za-z_]\w*)\s*\)', poc_text)
    if not m:
        return {"alias": None, "kind": None, "value": None}
    alias, raw = m.group(1), m.group(2)
    if re.match(r"^[0-9_]+$", raw):
        return {"alias": alias, "kind": "block", "value": int(raw.replace("_", ""))}
    if re.match(r"^[A-Za-z_]\w*$", raw):
        # named constant, e.g. `bytes32 private constant attackTx = hex"00c5..";`
        d = re.search(r'\b%s\s*=\s*(hex"[0-9a-fA-F]+"|0x[0-9a-fA-F]+|\d+)\s*;'
                      % re.escape(raw), poc_text)
        if d:
            raw = d.group(1)
    hx = re.search(r"0?x?([0-9a-fA-F]{64})", raw)
    return {"alias": alias, "kind": "tx", "value": "0x" + hx.group(1)
            if hx else raw}


def uncomment_commented(text: str, needle: str) -> tuple[str, bool]:
    """Enable the PoC's OWN commented-out line(s) that contain `needle`.

    Minimal harness reconstruction: only a line the original authors already
    wrote is switched on, and only inside an experiment overlay.
    """
    out, changed = [], False
    for ln in text.splitlines(keepends=True):
        s = ln.lstrip()
        if s.startswith("//") and needle in ln:
            indent = ln[:len(ln) - len(s)]
            ln = indent + s[2:].lstrip()
            changed = True
        out.append(ln)
    return "".join(out), changed


def logs_excerpt(stdout: str, limit: int = 12) -> list[str]:
    """The `Logs:` block of a forge run -- the raw balance evidence."""
    out, seen = [], False
    for ln in stdout.splitlines():
        if re.match(r"^\s*Logs:\s*$", ln):
            seen = True
            continue
        if seen:
            if not ln.strip() or ln.startswith("Suite result"):
                break
            out.append(ln.strip()[:160])
            if len(out) >= limit:
                break
    return out


def balance_deltas_by_subject(stdout: str) -> list[dict]:
    """Auxiliary pairing: each `after` line with the nearest preceding `before`
    line about the SAME subject. Positional zip (the shared parser) can pair
    unrelated tokens, so this is recorded as corroboration only -- it never
    awards a level by itself, and an unlabelled subject is not claimed as
    attacker-side profit."""
    befores, afters, out = [], [], []
    for line in stdout.splitlines():
        m = re.match(r"\s*(.+?)\s*:\s*([\d,]+(?:\.\d+)?)\s*(?:\[.*\])?\s*$",
                     line)
        if not m:
            continue
        label, num = m.group(1).strip(), m.group(2).replace(",", "")
        try:
            v = float(num)
        except ValueError:
            continue
        low = label.lower()
        if "before" in low or "current balance" in low or "start" in low:
            befores.append((label, v))
        elif "after" in low:
            afters.append((label, v))
    for al, av in afters:
        asub = label_subjects(al)
        for bl, bv in reversed(befores):
            shared = asub & label_subjects(bl)
            if shared:
                out.append({"label_before": bl, "label_after": al,
                            "matched_subjects": sorted(shared),
                            "before": bv, "after": av, "profit": av - bv,
                            "attacker_labelled": "attacker" in
                            (bl + " " + al).lower()})
                break
    return out


def claim_context(poc_text: str) -> dict:
    """What the PoC claims (total lost / objective / attack tx) and how the
    test itself demonstrates it (balance-log labels, assertions)."""
    labels = re.findall(r'log_named_decimal_uint\(\s*"([^"]+)"', poc_text)
    logs = re.findall(r'(?:console2?\.(?:log|log_named_\w+)\()([^)\n]{0,120})',
                      poc_text)
    asserts = re.findall(r"(?m)^\s*(assert\w*\([^;]{0,150};)", poc_text)
    notes = [ln.strip("/ ").strip() for ln in poc_text.splitlines()
             if re.match(r"^\s*//.*(Total Lost|Objective|Attack Tx|Attacker)", ln)]
    return {
        "claim_notes": notes[:6],
        "balance_log_labels": sorted(set(labels)),
        "console_log_lines": [x.strip()[:120] for x in logs][:12],
        "assertions": asserts[:8],
    }


# ------------------------------------------------------------------ strategies

def run_spec(slug: str) -> dict:
    """Per-run pinned inputs + ordered attempt strategies."""
    return {
        "burgerswap": {
            "poc": "2021-05/BurgerSwap_exp.sol", "test": "testExploit",
            "strategies": [
                {"kind": "archive_provider",
                 "provider": {"bsc": "https://api.zan.top/bsc-mainnet"},
                 "why": "public BSC archive serving block 7781159 "
                        "(verified by eth_getBalance probe); exact pinned "
                        "block, today's rules"},
                {"kind": "archive_provider",
                 "provider": {"bsc": "https://bsc.drpc.org"},
                 "why": "second archive provider for the pinned block; "
                        "public endpoint is rate-limited (HTTP 429), so "
                        "calls are paced"},
            ]},
        "gamma": {
            "poc": "2024-01/Gamma_exp.sol", "test": "testExploit",
            "strategies": [
                {"kind": "archive_provider",
                 "provider": {"arbitrum": "https://arb-pokt.nodies.app"},
                 "why": "public Arbitrum archive serving block 166873291 "
                        "(verified probe); arb1.arbitrum.io/rpc answers "
                        "'historical state ... is not available'"},
                {"kind": "archive_provider",
                 "provider": {"arbitrum": "https://arbitrum.drpc.org"},
                 "why": "second provider; probe reported 'Unknown state. "
                        "First available state is 1' for the pinned height"},
            ]},
        "prisma": {
            "poc": "2024-03/Prisma_exp.sol", "test": "test_exploit",
            "strategies": [
                {"kind": "rule_compat_hardfork", "hardfork": "cancun",
                 "provider": {"mainnet": "https://eth.drpc.org"},
                 "scope_change": (
                     "fork target unchanged (exact pinned transaction), but "
                     "the EVM rule set is pinned to cancun, the rules in force "
                     "at that height, because foundry 1.8.3 validates the "
                     "replayed historical transaction with today's Prague "
                     "rules (EIP-7623: gas floor 21680 > gas limit 21438). "
                     "A PASS here shows the violation under the historical "
                     "rule set, NOT under today's rules."),
                 "why": "the run's own log shows a transaction-validation "
                        "error during replay, not missing state: state IS "
                        "available, the rule check is the blocker. Note the "
                        "root attempt changed evm_version (compile target) "
                        "only; this attempt changes the protocol rule set."},
                {"kind": "block_fork_reconstruction",
                 "provider": {"mainnet":
                              "https://eth-mainnet.public.blastapi.io"},
                 "overlay_fork": "block_before_tx",
                 "scope_change": (
                     "fork expressed as the block immediately before the "
                     "attack transaction instead of by transaction hash, so "
                     "no historical transaction is replayed and today's "
                     "rules can be used. Evidence scope narrowed: state at "
                     "the pre-transaction block of that height rather than "
                     "the exact pre-transaction state inside the block; the "
                     "PoC's own calls are unchanged."),
                 "why": "removes the replay leg entirely; needs a harness "
                        "change, isolated to overlay/"},
            ]},
        "shibatoken": {
            "poc": "2023-11/ShibaToken_exp.sol", "test": "test",
            "strategies": [
                {"kind": "archive_provider",
                 "provider": {"bsc": "https://bsc.meowrpc.com"},
                 "why": "public BSC archive serving block 33528882 "
                        "(verified probe, non-empty balance); exact pinned "
                        "block, today's rules. The commented ankr-by-tx "
                        "alternative in the PoC needs an API key."},
                {"kind": "archive_provider",
                 "provider": {"bsc": "https://api.zan.top/bsc-mainnet"},
                 "why": "second archive provider for the pinned block"},
                {"kind": "harness_reconstruction",
                 "provider": {"bsc": "https://api.zan.top/bsc-mainnet"},
                 "overlay_uncomment": ["vm.prank("],
                 "scope_change": (
                     "the PoC's own commented-out vm.prank(attacker, attacker) "
                     "line was enabled, inside overlay/ only. The evidence "
                     "then covers a flash loan initiated BY the original "
                     "attacker address (spoofed caller identity), which is a "
                     "narrower claim than the unmodified PoC reproducing the "
                     "theft as an independent caller."),
                 "why": "the provider for the pinned block was found (the "
                        "test executed and reverted at the first external "
                        "call); the published file ships a commented prank of "
                        "the original attacker -- minimal reconstruction of "
                        "the harness, PoC logic untouched"},
            ]},
        }[slug] if slug in ("burgerswap", "gamma", "prisma",
                             "shibatoken") else None


RUNS = ("burgerswap", "gamma", "prisma", "shibatoken")


# ---------------------------------------------------------------------- stage

def stage(run: str, strat: dict, work: Path) -> tuple[Path, dict]:
    """Build an isolated forge project; PoC bytes verbatim unless overlaid."""
    spec = run_spec(run)
    rel = spec["poc"]
    src = TEST / rel
    proj = work / "proj"
    sdir = proj / "src" / "test"
    (sdir / src.parent.relative_to(TEST)).mkdir(parents=True, exist_ok=True)
    text = src.read_text(errors="ignore")
    dest = sdir / rel
    shutil.copy(src, dest)
    for helper in ("basetest.sol", "tokenhelper.sol"):
        h = TEST / helper
        if h.is_file():
            shutil.copy(h, sdir / helper)

    overlay = {}
    key = "src/test/" + rel

    def _note(change: str) -> None:
        ent = overlay.setdefault(key, {"original_poc_sha256": sha_file(src),
                                       "changes": []})
        ent["changes"].append(change)
        ent["overlay_poc_sha256"] = sha_file(dest)

    if strat.get("overlay_fork") == "block_before_tx":
        blk = strat["fork_block"]
        new = re.sub(r'createSelectFork\(\s*"mainnet"\s*,\s*'
                     r'(bytes32\([^)]*\)|[A-Za-z_]\w*)\s*\)',
                     f'createSelectFork("mainnet", {blk})', text, count=1)
        assert new != text, "overlay fork rewrite did not apply"
        dest.write_text(new, encoding="utf-8", newline="\n")
        _note('vm.createSelectFork("mainnet", <attackTx>) -> '
              f'vm.createSelectFork("mainnet", {blk}); all exploit calls, '
              "amounts and assertions unchanged")
    for needle in strat.get("overlay_uncomment") or []:
        cur = dest.read_text(encoding="utf-8")
        new, changed = uncomment_commented(cur, needle)
        assert changed, f"overlay uncomment found no commented line {needle!r}"
        dest.write_text(new, encoding="utf-8", newline="\n")
        _note(f"enabled the PoC's own commented line containing {needle!r}")

    providers = dict(strat.get("provider") or {})
    toml = ("[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = ['%s']\n"
            "evm_version = 'shanghai'\n" % LIB.as_posix().replace("\\", "/"))
    if strat.get("hardfork"):
        toml += "hardfork = '%s'\n" % strat["hardfork"]
    toml += "\n[rpc_endpoints]\n" + "".join(
        f'{k} = "{v}"\n' for k, v in sorted(providers.items()))
    (proj / "foundry.toml").write_text(toml, encoding="utf-8", newline="\n")
    return proj, overlay


def resolve_fork_block(urls, tx_hash: str) -> tuple[int | None, str | None]:
    """Block containing the pinned attack tx, read from an archive provider
    (read-only eth_getTransactionByHash). Returns (block BEFORE it, source).
    Public endpoints rate-limit, so every candidate is tried in order."""
    import urllib.request
    if isinstance(urls, str):
        urls = [urls]
    for url in list(urls) + TX_BLOCK_RESOLVERS:
        if not url:
            continue
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": "eth_getTransactionByHash",
                           "params": [tx_hash]}).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json",
                                     "User-Agent": "Mozilla/5.0 (vlun-v32)"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read().decode())
            blk = (d.get("result") or {}).get("blockNumber")
            if blk:
                return int(blk, 16) - 1, url
        except Exception:
            continue
    return None, None


# --------------------------------------------------------------------- runner

def run_cmd(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as exc:
        so = (exc.stdout or b"").decode("utf-8", "replace") \
            if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        se = (exc.stderr or b"").decode("utf-8", "replace") \
            if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, so, se + f"\n[TIMEOUT after {timeout}s]"


def classify(rc: int, so: str, se: str, target: str) -> tuple[str, str, str]:
    """(status, failure_reason, detail) from the attempt's own log."""
    tail = "\n".join((so + "\n" + se).splitlines()[-60:])
    passed = re.search(r"\[PASS\]\s+" + re.escape(target), so) is not None
    if rc == 124:
        return "blocked", "run_timeout", "no result within timeout"
    if passed:
        deltas = attacker_profit_evidence(so)
        if any(d["valid_attacker_profit"] for d in deltas):
            return "violation_observed", "", ""
        return "executed_no_profit_evidence", "", ""
    if "no tests match" in se or "No tests found" in so + se:
        return "blocked", "harness_invocation_invalid", \
            "runner selected no tests (not PoC evidence)"
    # Which EVM frame failed is the decisive evidence: a failure reported in
    # setUp() with gas 0 means the fork itself was never served, while a
    # failure in the test function's own frame means the pinned block WAS
    # served and the PoC actually executed (and then reverted). Providers
    # also emit stray archive errors for fetches they retry successfully, so
    # the frame is checked before the log-wide markers.
    m = re.search(r"\[FAIL:\s*([^\]]*)\]\s*" + re.escape(target) + r"\s*\(", so)
    if m and not any(k in m.group(1).lower() for k in
                     ("database error", "trie", "not available",
                      "blocknotfound", "pruned")):
        line = next((ln.strip() for ln in so.splitlines()
                     if m.group(0) in ln), m.group(0))
        return "test_failed", "poc_reverted_on_pinned_fork", line[:300]
    text = so + "\n" + se
    if any(m in text for m in ARCHIVE_MARKERS) or \
            any(m in text for m in ARCHIVE_MARKERS_EXTRA):
        return "blocked", "archive_state_unavailable", first_marker_line(text)
    if any(m in text for m in RPC_MARKERS):
        return "blocked", "rpc_unavailable", first_marker_line(text)
    fail = first_fail_line(so)
    if fail:
        # the fork itself was served and the test ran to a revert: that is a
        # result, not a missing-state blocker. Never relabelled as a success.
        return "test_failed", "poc_reverted_on_pinned_fork", fail
    return "blocked", "execution_failed", tail[:400]


# Log fragments that additionally mean "this provider cannot serve the pinned
# historical state" (the shared ARCHIVE_MARKERS tuple predates the wording
# public endpoints use for a missing trie state at a specific height).
ARCHIVE_MARKERS_EXTRA = ("is not available", "state 0x", "unknown state",
                         "header not found", "historical state")


def first_marker_line(text: str) -> str:
    marks = tuple(ARCHIVE_MARKERS) + ARCHIVE_MARKERS_EXTRA + tuple(RPC_MARKERS)
    for ln in text.splitlines():
        if any(m in ln for m in marks):
            return ln.strip()[:300]
    return ""


def first_fail_line(so: str) -> str:
    for ln in so.splitlines():
        if "[FAIL" in ln:
            return ln.strip()[:300]
    return ""


def level_for(status: str, so: str, target: str, build_rc: int,
              prior_level: str) -> tuple[str, str]:
    """Read the level back off the log; never upgrade without log evidence."""
    if status == "violation_observed":
        return "L5", ("attacker-side profit > 0 observed in the balance logs "
                      "of this attempt on the pinned fork")
    if status == "executed_no_profit_evidence":
        return "L4", (f"forge reported [PASS] {target} on this attempt's "
                      "fork; no attacker-side profit observed, so the claimed "
                      "violation is NOT reproduced")
    if build_rc == 0:
        return prior_level, ("staged PoC still compiles (forge build rc=0); "
                             "nothing new executed")
    return "L2", ("attempt failed before a clean build; the PoC source is "
                  "quoted only")


# ------------------------------------------------------------------- attempt

def attempt_dir(exp_dir: Path, idx: int) -> Path:
    """Attempts only ever ADD ``experiments_v3/<run>/attempt_N/``.

    The run-root bytes are hash-pinned by the proof-hashes gate, so writing at
    the root (or anywhere outside experiments_v3/<run>/attempt_N) is a hard
    error rather than a silent corruption.
    """
    d = exp_dir / f"attempt_{idx + 2}"        # the root run is attempt 1
    assert d.parent == exp_dir and re.fullmatch(r"attempt_[0-9]+", d.name), d
    assert exp_dir.parent == EXP, exp_dir
    assert d.name not in PROTECTED, d
    return d


def execute_attempt(run: str, idx: int, strat: dict, timeout: int,
                    keep_work: bool = False, reuse_log: bool = False,
                    redo: bool = False) -> dict:
    spec = run_spec(run)
    exp_dir = EXP / run
    root_result = json.loads((exp_dir / "result.json").read_text("utf-8"))
    rel, target = spec["poc"], spec["test"]
    src = TEST / rel
    pinned = parse_fork_target(src.read_text(errors="ignore"))
    alias = pinned["alias"] or (root_result.get("fork_aliases") or ["mainnet"])[0]

    strat = dict(strat)
    strat.setdefault("provider", {alias: strat.get("provider_url") or ""})
    adir = attempt_dir(exp_dir, idx)
    if reuse_log and (adir / "result.json").is_file() and not redo:
        return json.loads((adir / "result.json").read_text(encoding="utf-8"))
    if reuse_log and not redo and (adir / "stdout.txt").is_file() and \
            not (adir / "result.json").is_file():
        return finalize_from_log(run, idx, adir, root_result, spec)
    if pinned["kind"] == "tx" and strat.get("overlay_fork"):
        blk, resolver = resolve_fork_block(
            list(strat["provider"].values()), pinned["value"])
        if blk is None:
            return {"run": run, "attempt": idx + 2, "kind": strat["kind"],
                    "status": "blocked", "level_awarded": "L3",
                    "level_basis": "no attempt executed: the pinned attack tx "
                                   "block could not be resolved read-only, so "
                                   "the reconstructed fork point is unknown",
                    "evidence_level_supported": "L3",
                    "recovered": False, "poc_bytes_modified": False,
                    "overlay_files": [], "profit_deltas": [],
                    "failure_reason": "provider_access_unavailable",
                    "detail": "could not resolve the pinned attack tx block "
                              "from any provider; overlay fork point unknown",
                    "scope_change": strat.get("scope_change"),
                    "fork_target_pinned_by_poc": pinned,
                    "fork_target_used": pinned, "hardfork": "not run",
                    "provider": strat["provider"],
                    "original_run": {"level_awarded":
                                     root_result.get("level_awarded")}}
        strat["fork_block"] = blk
        strat["fork_block_source"] = resolver

    work = Path(tempfile.mkdtemp(prefix=f"v32-{run}-")) if not keep_work \
        else (SCRATCH / f"{run}_attempt_{idx + 2}")
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        proj, overlay = stage(run, strat, work)
        cmd = ["forge", "build"]
        brc, bso, bse = run_cmd(cmd, proj, timeout)
        solc = re.search(r"Compiling \d+ files with Solc ([\d.]+)", bso + bse)
        test_cmd = ["forge", "test", "--match-test", target, "-vv"]
        if strat.get("hardfork"):
            test_cmd += ["--hardfork", strat["hardfork"]]
        tcode = " ".join(test_cmd)
        rc, so, se = run_cmd(test_cmd, proj, timeout)

        status, reason, detail = classify(rc, so, se, target)
        level, basis = level_for(status, so, target, brc,
                                 root_result.get("level_awarded") or "L3")
        deltas = attacker_profit_evidence(so) if status in RECOVERED else []
        probe_key = strat["provider"][alias]
        blocked_extra = ""
        if status == "blocked" and probe_key in KEY_GATED:
            reason, blocked_extra = "provider_access_unavailable", \
                KEY_GATED[probe_key]

        adir.mkdir(parents=True, exist_ok=True)
        (adir / "command.txt").write_text(
            f"{tcode}   # cwd: isolated forge project (foundry.toml in "
            f"harness.json)\n", encoding="utf-8", newline="\n")
        (adir / "build_command.txt").write_text(" ".join(cmd) + "\n",
                                                encoding="utf-8", newline="\n")
        (adir / "stdout.txt").write_text((bso + bse + "\n=== forge test ===\n"
                                          + so)[-200000:],
                                         encoding="utf-8", newline="\n")
        (adir / "stderr.txt").write_text((bse + "\n" + se)[-200000:],
                                         encoding="utf-8", newline="\n")
        (adir / "toolchain.txt").write_text(
            (subprocess.run(["forge", "--version"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace",
                             timeout=60).stdout or "").strip() + "\n",
            encoding="utf-8", newline="\n")
        harness = {
            "attempt": idx + 2,
            "kind": strat["kind"],
            "run": run,
            "poc": rel,
            # pinned source: original staged bytes are never modified
            "poc_sha256_original": sha_file(src),
            "clone_head": V.clone_head(CLONE),
            "repository": "https://github.com/SunWeb3Sec/DeFiHackLabs",
            "dependency_lockfile": {
                "lib/forge-std": submodule_shas().get("lib/forge-std"),
                "lockfile_source": "git submodule status (pinned clone)",
            },
            "submodule_shas": submodule_shas(),
            "remappings": remappings(),
            "compiler_version": {"solc_selected_by_forge":
                                 solc.group(1) if solc else None,
                                 "evm_version": "shanghai",
                                 "hardfork": strat.get("hardfork") or
                                 "backend default (today's rules)"},
            "rpc_provider": strat["provider"],
            "fork_target_pinned_by_poc": pinned,
            "fork_target_used": ({"kind": "block", "value": strat["fork_block"]}
                                 if strat.get("fork_block") else pinned),
            "fork_block_source": strat.get("fork_block_source"),
            "fork_block_derivation": ("eth_getTransactionByHash (read-only) -> "
                                      "blockNumber - 1"
                                      if strat.get("fork_block") else None),
            "test_function": target,
            "strategy_reason": strat.get("why"),
            "scope_change": strat.get("scope_change"),
            "overlay": overlay or None,
        }
        (adir / "harness.json").write_text(
            json.dumps(harness, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
        if overlay:
            od = adir / "overlay" / "src" / "test" / Path(rel).parent
            od.mkdir(parents=True, exist_ok=True)
            shutil.copy(proj / "src" / "test" / rel, od / Path(rel).name)
            (adir / "overlay" / "overlay.json").write_text(
                json.dumps({"files": overlay,
                            "note": "all harness changes isolated here; the "
                                    "original staged PoC bytes are untouched"},
                           indent=2, sort_keys=True) + "\n",
                encoding="utf-8", newline="\n")

        rec = {
            "run": run, "attempt": idx + 2, "finding_id": root_result["finding_id"],
            "kind": strat["kind"], "status": status,
            "failure_reason": reason or None,
            "detail": (detail + ("; " + blocked_extra if blocked_extra else ""))
            or None,
            "level_awarded": level,
            "level_basis": basis,
            "evidence_level_supported": level,
            "scope_change": strat.get("scope_change"),
            "recovered": status in RECOVERED,
            "provider": strat["provider"].get(alias),
            "fork_target_pinned_by_poc": pinned,
            "fork_target_used": harness["fork_target_used"],
            "hardfork": harness["compiler_version"]["hardfork"],
            "build_rc": brc, "test_rc": rc,
            "test": {"command": tcode, "rc": rc, "test_function": target},
            "impact_check": claim_context(src.read_text(errors="ignore")),
            "profit_deltas": deltas,
            "balance_deltas_by_subject": balance_deltas_by_subject(so),
            "logs_excerpt": logs_excerpt(so),
            "poc_bytes_modified": bool(overlay),
            "overlay_files": sorted(overlay) if overlay else [],
            "original_run": {"status": root_result.get("status"),
                             "level_awarded": root_result.get("level_awarded"),
                             "failure_reason":
                                 root_result.get("failure_reason")},
            "tenderly_access": tenderly_access(),
            "seconds": round(time.time() - t0, 1),
        }
        if redo:
            rec["redo_note"] = REDO_NOTE
        write_result(adir, rec)
        return rec
    finally:
        if not keep_work:
            shutil.rmtree(work, ignore_errors=True)


HASH_NOTE = ("sha256 over the artefact bytes in this attempt directory; "
             "result.json is written after hashing so it carries no self-hash")

REDO_NOTE = ("this attempt was re-executed in place; the first execution of "
             "the same strategy hit a defect in this script's own overlay "
             "guard (the fork-rewrite never applied, so the forge log still "
             "showed the transaction-replay gas floor). That log proved "
             "nothing about the chain and is superseded by this run.")


def hash_attempt_files(adir: Path) -> dict:
    out = {}
    for p in sorted(adir.rglob("*")):
        if not p.is_file() or p.name == "result.json":
            continue
        ov = adir / "overlay"
        key = (("overlay/" + p.relative_to(ov).as_posix())
               if ov in p.parents else p.name)
        out[key] = sha_file(p)
    return out


def write_result(adir: Path, rec: dict) -> dict:
    rec["artifact_hashes"] = hash_attempt_files(adir)
    rec["artifact_hash_note"] = HASH_NOTE
    (adir / "result.json").write_text(json.dumps(rec, indent=2, sort_keys=True)
                                      + "\n", encoding="utf-8", newline="\n")
    rec["self_validation"] = validate_attempt_dir(adir)
    (adir / "result.json").write_text(json.dumps(rec, indent=2, sort_keys=True)
                                      + "\n", encoding="utf-8", newline="\n")
    return rec


def finalize_from_log(run: str, idx: int, adir: Path, root_result: dict,
                      spec: dict) -> dict:
    """Resume a half-written attempt: the forge commands already ran and their
    logs are on disk, only the record was missing. The verdict is re-derived
    from the committed log text; exit codes are inferred (0 iff the selected
    test shows [PASS]) and that inference is stated in the record."""
    rel, target = spec["poc"], spec["test"]
    src = TEST / rel
    so_full = (adir / "stdout.txt").read_text(encoding="utf-8", errors="replace")
    marker = "=== forge test ==="
    build_log, test_log = (so_full.split(marker, 1) if marker in so_full
                           else ("", so_full))
    se = ((adir / "stderr.txt").read_text(encoding="utf-8", errors="replace")
          if (adir / "stderr.txt").is_file() else "")
    harness = json.loads((adir / "harness.json").read_text(encoding="utf-8"))
    rc = 0 if re.search(r"\[PASS\]\s+" + re.escape(target), test_log) else 1
    brc = 0 if ("Compiler run successful" in build_log
               or "No files changed" in build_log
               or "Compiling " in build_log) else 1
    status, reason, detail = classify(rc, test_log, se, target)
    level, basis = level_for(status, test_log, target, brc,
                             root_result.get("level_awarded") or "L3")
    rec = {
        "run": run, "attempt": idx + 2,
        "finding_id": root_result["finding_id"],
        "kind": harness.get("kind"), "status": status,
        "failure_reason": reason or None, "detail": detail or None,
        "level_awarded": level, "level_basis": basis,
        "evidence_level_supported": level,
        "scope_change": harness.get("scope_change"),
        "recovered": status in RECOVERED,
        "provider": (harness.get("rpc_provider") or {}).get(
            (harness.get("fork_target_pinned_by_poc") or {}).get("alias")),
        "fork_target_pinned_by_poc": harness.get("fork_target_pinned_by_poc"),
        "fork_target_used": harness.get("fork_target_used"),
        "hardfork": (harness.get("compiler_version") or {}).get("hardfork"),
        "build_rc": brc, "test_rc": rc,
        "test": {"command": (adir / "command.txt").read_text(
            encoding="utf-8", errors="replace").split("#")[0].strip(),
            "rc": rc, "test_function": target},
        "impact_check": claim_context(src.read_text(errors="ignore")),
        "profit_deltas": (attacker_profit_evidence(test_log)
                          if status in RECOVERED else []),
        "balance_deltas_by_subject": balance_deltas_by_subject(test_log),
        "logs_excerpt": logs_excerpt(test_log),
        "poc_bytes_modified": bool(harness.get("overlay")),
        "overlay_files": sorted(harness.get("overlay") or {}),
        "original_run": {"status": root_result.get("status"),
                         "level_awarded": root_result.get("level_awarded"),
                         "failure_reason": root_result.get("failure_reason")},
        "tenderly_access": tenderly_access(),
        "seconds": None,
        "reused_log": True,
        "record_note": ("this record was re-derived from the committed log "
                        "text in this directory; no forge command was "
                        "executed by this call. Exit codes are inferred: "
                        "test_rc=0 only when [PASS] <test> appears in the log"),
    }
    return write_result(adir, rec)


def plan(run: str) -> list[dict]:
    """Strategies with resolved pins, for --check (executes nothing)."""
    spec = run_spec(run)
    src = TEST / spec["poc"]
    pinned = parse_fork_target(src.read_text(errors="ignore"))
    out = []
    for i, s in enumerate(spec["strategies"]):
        out.append({"run": run, "attempt": i + 2, "kind": s["kind"],
                    "provider": (s.get("provider") or {}),
                    "fork_target_pinned": pinned,
                    "hardfork": s.get("hardfork"),
                    "scope_change": bool(s.get("scope_change")),
                    "why": s.get("why")})
    return out


# ------------------------------------------------------------------ validation

def validate_attempt_dir(path: Path) -> list[str]:
    """Structural + honesty checks for one attempt directory. Returns errors."""
    errs: list[str] = []
    p = Path(path)
    rec_p = p / "result.json"
    if not rec_p.is_file():
        return [f"{p.name}: result.json missing"]
    try:
        rec = json.loads(rec_p.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [f"{p.name}: result.json unparsable: {exc}"]
    errs += validate_attempt(rec)
    # hashes over the artefacts actually on disk (result.json excluded: it is
    # written after the hashes are computed)
    for name, want in (rec.get("artifact_hashes") or {}).items():
        f = p / name
        if not f.is_file():
            errs.append(f"artifact {name} listed in hashes but absent")
        elif sha_file(f) != want:
            errs.append(f"artifact {name} hash does not match result.json")
    # log evidence must back the claimed level
    so = ""
    if (p / "stdout.txt").is_file():
        so = (p / "stdout.txt").read_text(encoding="utf-8", errors="replace")
    lvl = rec.get("level_awarded")
    tgt = (rec.get("test") or {}).get("test_function") or ""
    if lvl in ("L4", "L5", "L6") and \
            re.search(r"\[PASS\]\s+" + re.escape(tgt), so) is None:
        errs.append(f"{lvl} claimed but stdout shows no [PASS] {tgt}")
    if lvl == "L5" and not any(d.get("attacker_side") and d.get("profit", 0) > 0
                               for d in rec.get("profit_deltas") or []):
        errs.append("L5 claimed without attacker-side profit > 0")
    if lvl == "L6":
        errs.append("L6 requires the fixed revision blocked by the same test; "
                    "no attempt here executes a fixed side")
    # a PoC whose bytes changed must be documented in overlay/
    if rec.get("poc_bytes_modified"):
        if not (p / "overlay").is_dir():
            errs.append("poc_bytes_modified without an overlay/ directory")
        orig = (p / "harness.json")
        if orig.is_file():
            h = json.loads(orig.read_text(encoding="utf-8"))
            for rel, meta in (h.get("overlay") or {}).items():
                ov = p / "overlay" / Path(rel).parent / Path(rel).name
                if ov.is_file() and sha_file(ov) != meta.get(
                        "overlay_poc_sha256"):
                    errs.append(f"overlay {rel} hash differs from harness "
                                "record")
    return errs


def validate_attempt(rec: dict) -> list[str]:
    """Truthfulness rules for one attempt record (no filesystem needed)."""
    errs: list[str] = []
    lvl = rec.get("level_awarded")
    if lvl not in LADDER:
        errs.append(f"level_awarded {lvl!r} outside the L0-L6 ladder")
    if rec.get("evidence_level_supported") not in (None, lvl):
        errs.append("evidence_level_supported disagrees with level_awarded")
    # 1. recovery claim vs blocker
    recovered_status = rec.get("status") in RECOVERED
    recovered_level = lvl in ("L4", "L5", "L6")
    if recovered_level != recovered_status:
        errs.append("recovered status without a recovered level"
                    if recovered_status else
                    "claims a recovered level without a recovered status")
    if recovered_level or recovered_status:
        if rec.get("failure_reason"):
            errs.append("claims recovery "
                        f"({lvl}/{rec.get('status')}) while failure_reason="
                        f"{rec.get('failure_reason')!r} is still set")
    else:
        if not rec.get("failure_reason"):
            errs.append("blocked attempt without an explicit failure_reason")
    # 2. any deviation from the pinned fork target / rule set / PoC bytes
    #    needs a note
    pinned = rec.get("fork_target_pinned_by_poc") or {}
    used = rec.get("fork_target_used") or {}
    deviates = (str(pinned.get("kind")) != str(used.get("kind"))
                or str(pinned.get("value")) != str(used.get("value")))
    rules = str(rec.get("hardfork") or "")
    non_default = rules not in ("", "backend default (today's rules)", "None")
    modified = bool(rec.get("poc_bytes_modified"))
    if (deviates or non_default or modified) and not rec.get("scope_change"):
        errs.append("attempt deviates from the pinned fork target "
                    f"({pinned} -> {used}), the rule set ({rules}) or the "
                    f"PoC bytes ({modified}) with no scope_change note")
    if not deviates and not non_default and not modified \
            and rec.get("scope_change"):
        errs.append("scope_change note present although nothing deviated")
    # 3. never relabel: the original blocker must still be visible
    orig = rec.get("original_run") or {}
    if orig.get("level_awarded") and lvl and lvl < orig["level_awarded"]:
        errs.append(f"level {lvl} is below the level the root run already "
                    f"earned ({orig['level_awarded']})")
    if rec.get("kind") == "archive_provider" and rec.get("scope_change"):
        errs.append("archive_provider attempt keeps the pinned block; it "
                    "must not carry a scope_change note")
    if lvl == "L6":
        errs.append("L6 requires the fixed revision blocked by the same test; "
                    "no attempt here executes a fixed side, so L6 cannot be "
                    "claimed by an attempt record")
    if lvl == "L5" and not any(d.get("attacker_side") and d.get("profit", 0) > 0
                               and d.get("valid_attacker_profit")
                               for d in rec.get("profit_deltas") or []):
        errs.append("L5 claimed without admissible attacker-side profit > 0 "
                    "(same-subject, attacker-labelled balance delta)")
    if lvl in ("L4", "L5") and rec.get("impact_check") is None:
        errs.append("recovered attempt must record the assertion/state-change "
                    "that tests the claimed impact")
    return errs


# --------------------------------------------------------------------- report

def collect_attempts() -> list[dict]:
    rows = []
    for run in sorted(p.name for p in EXP.glob("*") if p.is_dir()):
        for adir in sorted(EXP.glob(f"{run}/attempt_*")):
            rp = adir / "result.json"
            if not rp.is_file():
                continue
            try:
                rec = json.loads(rp.read_text(encoding="utf-8"))
            except ValueError:
                rec = {"run": run, "error": "unparsable result.json"}
            rec.setdefault("run", run)
            rec["_path"] = adir.relative_to(ROOT).as_posix()
            rec["_validation_errors"] = validate_attempt_dir(adir)
            rows.append(rec)
    return rows


def build_report(rows: list[dict]) -> dict:
    def n(pred):
        return sum(1 for r in rows if pred(r))
    rep = {
        "stage": "V3.2 blocked-run recovery attempts (spec item 7)",
        "attempts_total": len(rows),
        "runs_attempted": sorted({r["run"] for r in rows}),
        "runs_recovered": sorted({r["run"] for r in rows
                                 if r.get("recovered")}),
        "runs_still_blocked": sorted({r["run"] for r in rows
                                      if not r.get("recovered")} -
                                     {r["run"] for r in rows
                                      if r.get("recovered")}),
        "attempts_recovered": n(lambda r: bool(r.get("recovered"))),
        "attempts_blocked": n(lambda r: not r.get("recovered")),
        "attempts_with_scope_change": n(lambda r: bool(r.get("scope_change"))),
        "by_status": {}, "by_failure_reason": {}, "by_kind": {},
        "best_level_per_run": {}, "validation_error_count":
            sum(len(r.get("_validation_errors") or []) for r in rows),
        "provider_access_unavailable": n(
            lambda r: r.get("failure_reason") == "provider_access_unavailable"),
        "provider_access": {
            "tenderly": tenderly_access(),
            "key_gated_endpoints": KEY_GATED,
            "policy": "no signups, no API keys and no secrets are handled by "
                      "this pipeline; a provider that needs a token is "
                      "recorded as provider_access_unavailable and its runs "
                      "keep their explicit blocker",
        },
        "note": "counts recomputed from the attempt artefacts on disk; levels "
                "awarded here are reported for integration and never written "
                "into a canonical layer by this script",
        "attempts": [],
    }
    for r in rows:
        for key, field in (("by_status", "status"),
                           ("by_failure_reason", "failure_reason"),
                           ("by_kind", "kind")):
            v = r.get(field) or ("none" if key == "by_failure_reason" else "?")
            rep[key][v] = rep[key].get(v, 0) + 1
        best = rep["best_level_per_run"].get(r["run"])
        cur = r.get("level_awarded")
        if best is None or (cur in LADDER and LADDER.index(cur) >
                            LADDER.index(best)):
            rep["best_level_per_run"][r["run"]] = cur
        rep["attempts"].append({
            "run": r["run"], "attempt": r.get("attempt"), "kind": r.get("kind"),
            "status": r.get("status"), "level": r.get("level_awarded"),
            "failure_reason": r.get("failure_reason"),
            "provider": r.get("provider"),
            "fork_target_used": r.get("fork_target_used"),
            "hardfork": r.get("hardfork"),
            "scope_change": r.get("scope_change"),
            "detail": (r.get("detail") or "")[:300],
            "profit_deltas": r.get("profit_deltas"),
            "balance_deltas_by_subject": r.get("balance_deltas_by_subject"),
            "logs_excerpt": r.get("logs_excerpt"),
            "artifact_hashes": r.get("artifact_hashes"),
            "validation_errors": r.get("_validation_errors"),
            "path": r.get("_path"),
        })
    rep["attempts"].sort(key=lambda a: (a["run"], a.get("attempt") or 0))
    return rep


def write_report(rep: dict) -> None:
    V.write_json(REPORTS, rep)
    L = ["# V3.2 blocked-run recovery attempts (spec item 7)", "",
         "Generated by `scripts/unblock_v32_runs.py` from the attempt "
         "artefacts on disk; counts are recomputed, never hand-typed.", "",
         f"attempts: {rep['attempts_total']}   "
         f"runs attempted: {len(rep['runs_attempted'])}   "
         f"runs recovered: {rep['runs_recovered']}   "
         f"still blocked: {rep['runs_still_blocked']}",
         f"by_status: {rep['by_status']}",
         f"by_failure_reason: {rep['by_failure_reason']}",
         f"by_kind: {rep['by_kind']}",
         f"best level per run: {rep['best_level_per_run']}",
         f"scope-changed attempts: {rep['attempts_with_scope_change']}",
         f"validation errors: {rep['validation_error_count']}", "",
         "| run | attempt | kind | provider | fork target | hardfork | "
         "status | level | blocker | scope change |", "|---|---|---|---|---|"
         "---|---|---|---|---|"]
    for a in rep["attempts"]:
        ft = a.get("fork_target_used") or {}
        L.append(f"| {a['run']} | {a['attempt']} | {a['kind']} | "
                 f"{a['provider']} | {ft.get('kind')}:{ft.get('value')} | "
                 f"{a['hardfork']} | {a['status']} | {a['level']} | "
                 f"{a['failure_reason'] or '-'} | "
                 f"{'yes' if a['scope_change'] else 'no'} |")
    L += ["", "## Provider access",
          f"- Tenderly-style saved simulation usable from existing local "
          f"access: {rep['provider_access']['tenderly']['available']} "
          f"({rep['provider_access']['tenderly']['note']})",
          f"- key-gated public endpoints recorded as "
          f"provider_access_unavailable (never configured with a secret): "
          f"{rep['provider_access']['key_gated_endpoints']}",
          f"- policy: {rep['provider_access']['policy']}", "",
          "## Per-attempt log evidence", ""]
    for a in rep["attempts"]:
        L.append(f"### {a['run']} attempt_{a['attempt']} -> {a['status']} "
                 f"({a['level']})")
        L.append(f"- artefacts: `{a['path']}`")
        if a.get("detail"):
            L.append(f"- log line: {a['detail']}")
        if a.get("scope_change"):
            L.append(f"- scope_change: {a['scope_change']}")
        if a.get("profit_deltas"):
            L.append(f"- profit: {a['profit_deltas']}")
        if a.get("logs_excerpt"):
            L.append(f"- log lines: {a['logs_excerpt']}")
        for d in a.get("balance_deltas_by_subject") or []:
            L.append(f"- same-subject delta ({','.join(d['matched_subjects'])}"
                     f", attacker_labelled={d['attacker_labelled']}): "
                     f"{d['before']} -> {d['after']} (profit {d['profit']}); "
                     "recorded as corroboration only -- it does not award a "
                     "level by itself")
        if a.get("validation_errors"):
            L.append(f"- VALIDATION ERRORS: {a['validation_errors']}")
        L.append("")
    REPORTS_MD.write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")


# ----------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recover the four blocked V3.2 fork runs by re-executing "
                    "each one against archive providers / historical rule "
                    "sets / reconstructed harness, isolating every change to "
                    "an experiment overlay.")
    ap.add_argument("--check", action="store_true",
                    help="print the pinned inputs and attempt plan; run "
                         "nothing and write nothing")
    ap.add_argument("--only", default=None,
                    help="comma-separated run slugs (default: all four)")
    ap.add_argument("--timeout", type=int, default=300,
                    help="per-command seconds (default 300)")
    ap.add_argument("--max-attempts", type=int, default=2,
                    help="strategies to try per run (stop early on recovery)")
    ap.add_argument("--report-only", action="store_true",
                    help="rebuild reports/v3/v32_unblock_attempts.json(+.md) "
                         "from committed attempt artefacts; executes nothing")
    ap.add_argument("--keep-work", action="store_true",
                    help="stage projects under work/v32 instead of temp")
    ap.add_argument("--reuse-logs", action="store_true",
                    help="do not re-execute an attempt that already has "
                         "result.json; if only its logs were written, derive "
                         "the record from those committed logs")
    ap.add_argument("--reclassify", action="store_true",
                    help="re-derive every attempt record from the logs "
                         "already committed in its directory; executes nothing")
    ap.add_argument("--redo", default=None,
                    help="comma-separated attempt numbers to re-execute in "
                         "place (only ever the script's own attempt_N dirs; "
                         "run-root artefacts are never writable)")
    args = ap.parse_args()

    runs = [r.strip() for r in args.only.split(",") if r.strip()] \
        if args.only else list(RUNS)
    bad = [r for r in runs if r not in RUNS]
    if bad:
        V.log(f"unknown run(s): {bad}; known: {list(RUNS)}")
        return 2

    if args.check:
        V.log("unblock_v32_runs --check (nothing executed)")
        for r in runs:
            spec = run_spec(r)
            src = TEST / spec["poc"]
            V.log(f"  {r}: poc={spec['poc']} sha256={sha_file(src)[:16]}... "
                  f"clone_head={V.clone_head(CLONE)[:12]} "
                  f"test={spec['test']}")
            for row in plan(r):
                V.log(f"    attempt_{row['attempt']}: {row['kind']} "
                      f"provider={row['provider']} "
                      f"fork={row['fork_target_pinned']} "
                      f"hardfork={row['hardfork']} "
                      f"scope_change={row['scope_change']}")
            V.log(f"    tenderly access available: "
                  f"{tenderly_access()['available']}")
        return 0

    if not args.report_only and args.reclassify:
        for adir in sorted(EXP.glob("*/attempt_*")):
            run = adir.parent.name
            if run not in runs:
                continue
            spec = run_spec(run)
            root_result = json.loads((EXP / run / "result.json")
                                     .read_text(encoding="utf-8"))
            n = int(re.search(r"(\d+)", adir.name).group(1))
            rec = finalize_from_log(run, n - 2, adir, root_result, spec)
            V.log(f"reclassified {run}/attempt_{n} -> {rec.get('status')} "
                  f"({rec.get('level_awarded')}) "
                  f"errs={rec.get('self_validation')}")
    if not args.report_only and not args.reclassify:
        redo = {int(x) for x in re.findall(r"\d+", args.redo or "")}
        for r in runs:
            spec = run_spec(r)
            strategies = spec["strategies"][:args.max_attempts]
            for i, strat in enumerate(strategies):
                V.log(f"== {r} attempt_{i + 2} ({strat['kind']})")
                rec = execute_attempt(r, i, strat, args.timeout,
                                      keep_work=args.keep_work,
                                      reuse_log=args.reuse_logs,
                                      redo=(i + 2) in redo)
                V.log(f"   -> {rec.get('status')} level={rec.get('level_awarded')}"
                      f" reason={rec.get('failure_reason')} "
                      f"errs={rec.get('self_validation')}")
                if rec.get("recovered"):
                    break
    rows = collect_attempts()
    rep = build_report(rows)
    write_report(rep)
    V.log(f"report: {rep['attempts_total']} attempts, "
          f"recovered={rep['runs_recovered']}, "
          f"blocked={rep['runs_still_blocked']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

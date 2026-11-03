#!/usr/bin/env python3
"""V3.2 execution evidence -> verification level promotion (single source).

The v3.0 integration pass executed nothing, so every derived_v3 record sat at
L0/L1 and the layer showed zero experimental evidence (the largest scientific
gap in the dataset). The V3.2 pass produced real artefacts, committed under
``experiments_v3/`` and summarised in ``reports/v3/experimental_proof.json`` +
``reports/v3/compile_sweep.json``. This module is the ONE place that turns
those artefacts into a per-record verification level, so the builder and the
gates cannot disagree about who earned what.

Two inputs, both committed (git-ignored ``V3/clones`` is never required):

  compile sweep   ``reports/v3/compile_sweep.json``  [{file, rc, errors,
                  supplied, via_ir}] -- one row per PoC staged in isolation;
                  ``rc == 0`` on unmodified PoC bytes earns **L3**.
  proof runs      ``reports/v3/experimental_proof.json`` runs[] -- executed
                  fork runs; each carries status, level_awarded, artefact
                  directory, artefact hashes and, for a reproduced theft,
                  attacker-side profit deltas.

Promotion rules (conservative; a level is never inferred, only read back):

  L3   forge build rc=0 on unmodified PoC bytes. Blocked runs (pruned RPC,
       unreplayable state, timeout) still earned L3: they compiled.
  L4   the fork test executed and forge reported PASS, but no attacker-side
       profit was observed (execution without a reproduced violation).
  L5   attacker profit > 0 observed in balance logs on the pinned fork.
       Requires profit evidence in the run record, not just a status string.

L6 is never awarded here: it needs the same test blocked on the fixed
revision, and no candidate has an executable fixed-side leg.

Everything not covered by an artefact keeps the level the harvester assigned
(L0/L1) and is untouched -- an unexecuted record is never promoted by
proximity to one that was executed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from schema_terms import VIOLATION_IMPACTS

U = "unknown"

# Levels this module can promote to. L6 is a controlled two-revision
# comparison and is never inferred from a one-sided run; a future L6 pass
# has to go through validate_l6_claim instead of promote().
PROMOTABLE_LEVELS = ("L3", "L4", "L5")

L3_PLUS = ("L3", "L4", "L5", "L6")

# Full commit ids only: an abbreviation cannot be checked out on both sides.
_HEX40 = re.compile(r"^[0-9a-f]{40}$")

# Statuses that mean "the run never reached a comparable test outcome".
_SHORT_CIRCUIT_STATUSES = ("blocked", "timeout", "compile_failed")

# Level -> verification_status, using the existing closed vocabulary from
# scripts/audit_sources.py (VERIFICATION_STATES). No new status terms.
LEVEL_TO_STATUS = {
    "L0": "UNVERIFIED",
    "L1": "UNVERIFIED",
    "L2": "RECONSTRUCTED",
    "L3": "COMPILES",
    "L4": "EXECUTES",
    "L5": "VIOLATION_REPRODUCED",
    "L6": "PATCH_VERIFIED",
}

# reproducibility credit for quality_score (slot is 12 points wide)
REPRODUCIBILITY_POINTS = {"L0": 0, "L1": 0, "L2": 0, "L3": 4, "L4": 7,
                          "L5": 10, "L6": 12}

# ---------------------------------------------------------------------------
# claim-specific violation evidence
# ---------------------------------------------------------------------------
# L5 is not "the test passed" and it is not "the attacker balance went up".
# It is a statement about one specific security property, so the evidence has
# to name that property and the observation that violates it. Theft is the one
# impact where a measured attacker gain is the natural proof; every other
# impact has its own observation. An impact that is not in this vocabulary is
# NOT promoted, because the dataset cannot state what was violated.
IMPACT_TYPES = VIOLATION_IMPACTS

# Fields every violation_evidence record must carry. They are the "who, what,
# expected, observed, and which assertion" that make the claim auditable.
_COMMON_EVIDENCE_FIELDS = ("impact_type", "actor", "property", "expected",
                           "observed", "source")

# Impact-specific required fields, plus the boolean that states the violation
# actually happened. A false/absent flag is not evidence.
_IMPACT_FIELDS = {
    "access_control": (("target", "operation", "effect_observed"),),
    "signature_replay": (("signature", "operation"),),
    "dos": (("legitimate_operation", "observed_block"),),
    "accounting_invariant": (("invariant", "expected_relation",
                              "observed_relation"),),
    "oracle_manipulation": (("invariant", "expected_value", "observed_value"),),
    "state_corruption": (("object", "from_state", "to_state"),),
}

# Balance labels that name the asset. Used only to derive evidence for theft
# runs whose committed logs name both the attacker side and the asset.
_ASSET_SYMBOLS = ("cUSDC", "wstETH", "stETH", "WBNB", "WETH", "WBTC", "USDC",
                  "USDT", "DAI", "ETH", "BNB", "MATIC", "ARB", "BTC")


def _present(value) -> bool:
    return isinstance(value, str) and value.strip() not in ("", "unknown", "U")


def _positive_number(value) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and value > 0)


def _asset_from_labels(*labels: str) -> str | None:
    text = " ".join(x for x in labels if isinstance(x, str)).lower()
    for symbol in _ASSET_SYMBOLS:
        if symbol.lower() in text:
            return symbol
    return None


def _execution_from_run(run: dict) -> dict:
    test = run.get("test") or {}
    rc = test.get("rc")
    if rc == 0:
        status = "pass"
    elif rc == 1 and run.get("status") in ("violation_observed", "test_failed"):
        status = "fail"
    else:
        status = "unknown"
    return {"status": status,
            "assertion": test.get("test_function") or "unknown",
            "command": test.get("command")}


def validate_violation_evidence(evidence: dict) -> tuple[bool, list[str]]:
    """Validate a structured claim that a specific violation was observed.

    Returns (ok, errors). The checks are intentionally narrow: an ambiguous
    impact, a missing actor, an unattributed balance change or a failing test
    that is not the claimed assertion all make the evidence unusable for L5.
    """
    errors: list[str] = []
    if not isinstance(evidence, dict):
        return False, ["violation_evidence is not an object"]
    impact = evidence.get("impact_type")
    if impact not in IMPACT_TYPES:
        errors.append(f"impact_type {impact!r} is missing or outside the "
                      f"supported vocabulary")
    for field in _COMMON_EVIDENCE_FIELDS:
        if not _present(evidence.get(field)):
            errors.append(f"{field} is missing or ambiguous")
    execution = evidence.get("execution")
    if not isinstance(execution, dict) or execution.get("status") not in (
            "pass", "fail"):
        errors.append("execution status is missing: no completed run")
    else:
        if not _present(execution.get("assertion")):
            errors.append("the assertion that demonstrates the violation is "
                          "not named")
        if execution.get("status") == "fail":
            if evidence.get("failure_is_intended") is not True:
                errors.append("a failing test is not tied to the intended "
                              "security assertion")
            elif not _present(evidence.get("expected_error")):
                errors.append("a failing test does not name the expected "
                              "error it was asserting")
            elif not _present(evidence.get("failure_evidence")):
                errors.append("a failing test does not record the observed "
                              "failure text")
            elif evidence["expected_error"].strip().lower() not in \
                    evidence["failure_evidence"].lower():
                errors.append("the recorded failure does not contain the "
                              "expected security assertion's error")
    if impact == "fund_theft":
        deltas = [d for d in (evidence.get("profit_deltas") or [])
                  if isinstance(d, dict)]
        attributed = [d for d in deltas
                      if d.get("attacker_side") is True
                      and _positive_number(d.get("profit"))
                      and _present(d.get("label_before"))
                      and _present(d.get("label_after"))]
        if not attributed:
            errors.append("fund_theft needs a positive attacker-side delta "
                          "with both balance labels")
        if not _present(evidence.get("asset")):
            errors.append("fund_theft does not name the asset gained")
    if impact in _IMPACT_FIELDS:
        for fields in _IMPACT_FIELDS[impact]:
            for field in fields:
                if not _present(evidence.get(field)):
                    errors.append(f"{impact} evidence lacks {field}")
    flags = {
        "access_control": "unauthorized",
        "signature_replay": "replay_accepted",
        "dos": "blocked",
        "accounting_invariant": "violated",
        "oracle_manipulation": "violated",
        "state_corruption": "violated",
    }
    flag = flags.get(impact)
    if flag and evidence.get(flag) is not True:
        errors.append(f"{impact} evidence does not assert {flag}=true")
    return (not errors, errors)


def theft_evidence_from_deltas(deltas: list, source: str) -> dict:
    """Structured fund_theft evidence from measured attacker-side deltas.

    Returns {} when no delta is attributed to the attacker, so a positive
    balance change on an unnamed account can never become theft evidence.
    """
    attributed = [d for d in (deltas or [])
                  if isinstance(d, dict) and d.get("attacker_side") is True
                  and _positive_number(d.get("profit"))
                  and _present(d.get("label_before"))
                  and _present(d.get("label_after"))]
    if not attributed:
        return {}
    labels = [str(d.get(k) or "") for d in attributed
              for k in ("label_before", "label_after")]
    named = any("attacker" in label.lower() for label in labels)
    asset = _asset_from_labels(*labels)
    best = max(attributed, key=lambda d: d.get("profit", 0))
    return {
        "impact_type": "fund_theft",
        "actor": "attacker" if named else "unknown",
        "asset": asset or "",
        "property": (f"attacker-controlled {asset} balance" if asset
                     else "attacker-controlled balance"),
        "expected": "the exploit leaves the attacker's balance unchanged",
        "observed": (f"attacker-side delta {best.get('profit')} observed "
                     f"between '{best.get('label_before')}' and "
                     f"'{best.get('label_after')}'"),
        "source": source,
        "profit_deltas": attributed,
    }


def violation_evidence_for_run(run: dict, claim: dict | None = None) -> dict:
    """Build the evidence object for one proof run.

    `claim` is an explicit, committed evidence record (analyst review backed by
    a source pointer). Without it, only theft runs can be reconstructed, and
    only when the committed logs name both the attacker side and the asset.
    """
    explicit = claim or run.get("violation_evidence")
    if explicit:
        ev = dict(explicit)
    else:
        # Only theft can be reconstructed without an explicit claim, and only
        # when the committed logs attribute a positive delta to the attacker.
        ev = theft_evidence_from_deltas(
            run.get("profit_deltas") or [],
            "profit_deltas labels in the committed run record")
        if not ev:
            return {}
    ev.setdefault("execution", _execution_from_run(run))
    if ev.get("impact_type") == "fund_theft" and not ev.get("profit_deltas"):
        ev["profit_deltas"] = run.get("profit_deltas") or []
    if not ev.get("asset") and ev.get("impact_type") == "fund_theft":
        deltas = [d for d in (ev.get("profit_deltas") or [])
                  if isinstance(d, dict) and d.get("attacker_side") is True]
        labels = [str(d.get(k) or "") for d in deltas
                  for k in ("label_before", "label_after")]
        asset = _asset_from_labels(*labels)
        if asset:
            ev["asset"] = asset
    return ev


def _load_claims(root: Path) -> dict:
    """Explicit evidence claims, keyed by finding id, from committed reports."""
    doc = _read(root / "reports" / "v3" / "violation_evidence.json") or {}
    claims = doc.get("runs") if isinstance(doc, dict) else None
    return claims if isinstance(claims, dict) else {}

# repository prefixes stripped before matching an artefact reference to a
# harvested candidate id
_PATH_PREFIXES = ("src/test/", "src/", "past/")


def evidence_key(ref: str) -> str:
    """Canonical <date-dir>/<stem> key for a candidate id or PoC file path.

    Collapses the three spellings the pipeline produces:
      defihacklabs:src/test/2024-04/PikeFinance_exp  (candidate_id)
      defihacklabs:2024-04/PikeFinance_exp.sol       (proof run finding_id)
      2024-04/PikeFinance_exp.sol                    (compile sweep file)
    """
    s = (ref or "").strip().replace("\\", "/")
    if ":" in s:
        s = s.split(":", 1)[1]
    if s.endswith(".sol"):
        s = s[:-4]
    for p in _PATH_PREFIXES:
        if s.startswith(p):
            s = s[len(p):]
            break
    return s


def _read(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _run_executed(run: dict) -> bool:
    """Did this run complete a forge test at all?

    RPC failure, archive-state failure, compile error and timeout are not
    execution evidence, whatever status string the run carries.
    """
    if run.get("failure_reason"):
        return False
    test = run.get("test") or {}
    rc = test.get("rc")
    if rc not in (0, 1):
        return False
    if rc == 0:
        return run.get("status") in ("violation_observed",
                                     "executed_no_profit_evidence", "passed")
    return run.get("status") in ("violation_observed", "test_failed")


def load_evidence(root: Path) -> dict:
    """{evidence_key: {level, status, basis, ...}} from committed artefacts.

    Returns {} when the artefacts are absent -- a layer with no execution
    history promotes nothing, which is the honest default.
    """
    ev: dict = {}

    sweep = _read(root / "reports" / "v3" / "compile_sweep.json")
    rows = (sweep or {}).get("rows") if isinstance(sweep, dict) else sweep
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        key = evidence_key(row.get("file", ""))
        if not key:
            continue
        if row.get("rc") == 0:
            ev[key] = {
                "level": "L3",
                "status": "compiled",
                "basis": ("forge build rc=0 on unmodified PoC bytes, "
                          "isolated per-PoC staging"),
                "compile": {"rc": 0,
                            "via_ir": bool(row.get("via_ir")),
                            "supplied": row.get("supplied") or []},
            }
        else:
            errs = (row.get("errors") or [])[:1]
            ev[key] = {
                "level": "L1",
                "status": "compile_failed",
                "basis": ("forge build failed on unmodified PoC bytes: "
                          + (errs[0][:150] if errs else "no error text")),
            }

    proof = _read(root / "reports" / "v3" / "experimental_proof.json") or {}
    claims = _load_claims(root)
    for run in proof.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        key = evidence_key(run.get("finding_id", ""))
        if not key:
            continue
        executed = _run_executed(run)
        evidence = violation_evidence_for_run(
            run, claims.get(run.get("finding_id", "")))
        ok, errors = validate_violation_evidence(evidence) if executed else (
            False, ["the run did not execute: no completed forge test"])
        base = dict(ev.get(key) or {})
        entry = {
            "status": run.get("status"),
            "basis": run.get("level_basis") or U,
            "failure_reason": run.get("failure_reason"),
            "test": run.get("test") or {},
            "artifact_dir": _rel_artifact(root, run.get("artifact_dir")),
            "artifact_hashes": run.get("artifact_hashes") or {},
            "clone_head": run.get("clone_head"),
            "violation_evidence": evidence if executed else None,
            "violation_evidence_errors": errors,
        }
        if not executed:
            # Keep whatever the compile sweep earned; an unexecuted run is not
            # evidence of anything above L3.
            entry["level"] = base.get("level") or "L1"
        elif ok:
            entry["level"] = "L5"
            entry["status"] = "violation_observed"
            entry["basis"] = (
                "claim-specific violation evidence validated for impact "
                f"'{evidence.get('impact_type')}' on a completed run")
            if evidence.get("impact_type") == "fund_theft":
                deltas = [d for d in (evidence.get("profit_deltas") or [])
                          if isinstance(d, dict)
                          and d.get("attacker_side") is True
                          and _positive_number(d.get("profit"))]
                best = max(deltas, key=lambda d: d.get("profit", 0))
                entry["profit_evidence"] = {
                    "max_profit": best.get("profit"),
                    "label_before": best.get("label_before"),
                    "label_after": best.get("label_after"),
                    "asset": evidence.get("asset"),
                }
        else:
            entry["level"] = "L4"
            entry["status"] = "executed_no_violation_evidence"
            entry["basis"] = ("the run executed but the claimed violation was "
                              "not demonstrated: " + "; ".join(errors[:4]))
        # Merge onto the sweep verdict rather than replacing it: a fork run adds
        # execution evidence, it does not erase the compile evidence the
        # record already earned (a blocked-at-fork PoC still compiles).
        for _f, _v in entry.items():
            if _v is not None:
                base[_f] = _v
        base["compile"] = base.get("compile") or entry.get("compile")
        ev[key] = base
    return ev


def _rel_artifact(root: Path, artifact_dir) -> str | None:
    """Repo-relative artefact path. Absolute local paths are never stored.

    Returns None unless the path provably lies inside this repository: an
    absolute path from some other machine is dropped rather than rewritten
    into a path that does not exist here.
    """
    if not artifact_dir:
        return None
    try:
        return Path(artifact_dir).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def promote(candidates: list[dict], evidence: dict) -> int:
    """Promote harvested candidates in place. Returns the promoted count.

    Idempotent: re-running with the same committed artefacts yields the same
    rows, which is what the rebuild-parity gate checks.
    """
    promoted = 0
    for c in candidates:
        entry = evidence.get(evidence_key(c.get("candidate_id", "")))
        if not entry or entry.get("level") in (None, "L0", "L1"):
            continue
        level = entry["level"]
        if level not in PROMOTABLE_LEVELS:
            # L6 is a two-revision controlled comparison; no single-artefact
            # evidence may silently lift a record (L5 included) to L6.
            continue
        c["verification_level"] = level
        c["verification_status"] = LEVEL_TO_STATUS.get(level, "UNVERIFIED")
        c["verification_evidence"] = entry.get("basis") or U
        exp = {
            "stage": "V3.2 fork execution",
            "level_awarded": level,
            "status": entry.get("status"),
            "basis": entry.get("basis"),
            "artifact_dir": entry.get("artifact_dir"),
            "artifact_hashes": entry.get("artifact_hashes") or {},
            "failure_reason": entry.get("failure_reason"),
        }
        if entry.get("compile"):
            exp["compile"] = entry["compile"]
        if entry.get("test"):
            exp["test"] = entry["test"]
        if entry.get("profit_evidence"):
            exp["profit_evidence"] = entry["profit_evidence"]
        if entry.get("violation_evidence"):
            exp["violation_evidence"] = entry["violation_evidence"]
        if entry.get("violation_evidence_errors"):
            exp["violation_evidence_errors"] = entry[
                "violation_evidence_errors"]
        if entry.get("clone_head"):
            exp["clone_head"] = entry["clone_head"]
        c["experiment"] = exp
        # Keep the decision reason truthful: the row is still an
        # unverified-import (a third-party incident reproduction), but the
        # PoC is no longer merely published.
        c["decision_reason"] = (
            "third-party incident reproduction with executable Foundry "
            f"PoC ({level} earned by this pipeline's own run artefact; "
            "not first-party audited)")
        c["_signals"] = dict(c.get("_signals") or {})
        c["_signals"]["reproducibility"] = REPRODUCIBILITY_POINTS.get(level, 0)
        promoted += 1
    return promoted


def verified_fact(entry: dict) -> str:
    """The one sentence a promoted record may claim as experimentally seen."""
    if not entry:
        return U
    lvl = entry.get("level")
    head = (entry.get("clone_head") or U)[:12]
    if lvl == "L5":
        ve = entry.get("violation_evidence") or {}
        if ve.get("impact_type") == "fund_theft":
            pe = entry.get("profit_evidence") or {}
            return (f"published exploit PoC compiled and executed on a pinned "
                    f"fork (clone HEAD {head}); attacker gained "
                    f"{pe.get('max_profit')} {ve.get('asset') or ''} between "
                    f"'{pe.get('label_before')}' and "
                    f"'{pe.get('label_after')}'")
        return (f"published exploit PoC compiled and executed on a pinned "
                f"fork (clone HEAD {head}); {ve.get('impact_type')} violation "
                f"observed: {ve.get('observed')}")
    if lvl == "L4":
        return (f"published exploit PoC compiled and the fork test executed "
                f"to completion (clone HEAD {head}); no claim-specific "
                "violation evidence was recorded, so the claimed violation "
                "is NOT reproduced")
    if lvl == "L3":
        return (f"published exploit PoC compiles unmodified (forge build "
                f"rc=0) at clone HEAD {head}; nothing was executed against "
                "any chain")
    return U


def artefact_exists(root: Path, entry: dict) -> bool:
    """The committed artefacts a level claims must actually be on disk."""
    if not entry:
        return False
    rel = entry.get("artifact_dir")
    if not rel:
        # L3 straight from the compile sweep keeps no per-run directory;
        # the sweep row itself is the artefact.
        return bool(entry.get("compile", {}).get("rc") == 0)
    d = root / rel
    return (d / "result.json").is_file() and (d / "stdout.txt").is_file()


def _l6_side_status(revision: dict):
    """The completed test outcome of one revision, or None.

    Accepts the explicit `status` field; a revision that only records
    per-test outcomes gets a status when every test agrees, so "one passing
    test" on one side cannot stand in for a completed comparison.
    """
    status = revision.get("status")
    if status in ("pass", "fail"):
        return status
    per_test = revision.get("per_test_status")
    if isinstance(per_test, dict) and per_test:
        outcomes = {str(v).strip().lower() for v in per_test.values()}
        if outcomes <= {"success", "pass"}:
            return "pass"
        if outcomes <= {"failure", "fail"}:
            return "fail"
    return None


def validate_l6_claim(claim: dict) -> tuple[bool, list[str]]:
    """Validate an L6 patch-verified claim against two-revision evidence.

    L6 is a controlled comparison, not a stronger L5: the same test file
    bytes must run against two distinct full 40-hex commits and show the
    declared property polarity (vulnerable fail / fixed pass by default), no
    revision may be short-circuited by a compile/timeout/blocked failure, and
    an explicit claim-specific violation_evidence record must exist. Pure:
    reads only the passed record/experiment, never the filesystem.

    Returns (ok, errors). An empty layer trivially has nothing to validate;
    callers apply this only to records that actually claim L6.
    """
    if not isinstance(claim, dict):
        return False, ["L6 claim is not an object"]
    exp = claim.get("experiment")
    if not isinstance(exp, dict):
        exp = claim
    errors: list[str] = []
    record_level = claim.get("verification_level")
    if record_level is not None and record_level != "L6":
        errors.append(f"claim is recorded as {record_level}, not L6")
    awarded = exp.get("level_awarded")
    if awarded is not None and awarded != "L6":
        errors.append(f"experiment awards {awarded}, not L6")
    revisions = exp.get("revisions")
    if not isinstance(revisions, dict):
        return False, errors + ["no two-revision evidence (revisions map) recorded"]
    vulnerable = revisions.get("vulnerable")
    fixed = revisions.get("fixed")
    vulnerable = vulnerable if isinstance(vulnerable, dict) else {}
    fixed = fixed if isinstance(fixed, dict) else {}
    if not vulnerable:
        errors.append("vulnerable revision evidence is missing")
    if not fixed:
        errors.append("fixed revision evidence is missing")

    commits = []
    for label, revision in (("vulnerable", vulnerable), ("fixed", fixed)):
        commit = revision.get("commit")
        if not isinstance(commit, str) or not _HEX40.match(commit):
            errors.append(f"{label} revision does not name a full 40-hex commit")
            commit = None
        commits.append(commit)
    if all(commits) and commits[0] == commits[1]:
        errors.append("both revisions name the same commit: no controlled comparison")

    harness_v = vulnerable.get("harness_digest")
    harness_f = fixed.get("harness_digest")
    if not _present(harness_v) or not _present(harness_f):
        errors.append("harness digest is missing on one or both revisions")
    elif harness_v != harness_f:
        errors.append("the two revisions ran different harness bytes")
    files_v = vulnerable.get("harness_file_digests")
    files_f = fixed.get("harness_file_digests")
    files_v = files_v if isinstance(files_v, dict) else {}
    files_f = files_f if isinstance(files_f, dict) else {}
    tests_v = {n: d for n, d in files_v.items() if str(n).endswith(".t.sol")}
    tests_f = {n: d for n, d in files_f.items() if str(n).endswith(".t.sol")}
    if not tests_v or not tests_f:
        errors.append("test file digests are missing on one or both revisions")
    elif tests_v != tests_f:
        errors.append("the two revisions did not run the same test file bytes")

    status_v = _l6_side_status(vulnerable)
    status_f = _l6_side_status(fixed)
    if status_v is None:
        errors.append("vulnerable revision records no completed test status")
    if status_f is None:
        errors.append("fixed revision records no completed test status")
    declared_v = vulnerable.get("declared_expected_status")
    declared_f = fixed.get("declared_expected_status")
    if declared_v in ("pass", "fail") and declared_f in ("pass", "fail"):
        if declared_v == declared_f:
            errors.append("declared assertion polarity is not two-sided")
        if status_v is not None and status_v != declared_v:
            errors.append(f"vulnerable status {status_v!r} does not match the "
                          f"declared {declared_v!r}")
        if status_f is not None and status_f != declared_f:
            errors.append(f"fixed status {status_f!r} does not match the "
                          f"declared {declared_f!r}")
    else:
        if status_v is not None and status_v != "fail":
            errors.append("without a declared polarity the vulnerable "
                          "revision must fail the property assertion")
        if status_f is not None and status_f != "pass":
            errors.append("without a declared polarity the fixed revision "
                          "must pass the property assertion")
    per_v = vulnerable.get("per_test_status")
    per_f = fixed.get("per_test_status")
    if isinstance(per_v, dict) or isinstance(per_f, dict):
        per_v = per_v if isinstance(per_v, dict) else {}
        per_f = per_f if isinstance(per_f, dict) else {}
        if not per_v or not per_f:
            errors.append("only one revision records per-test statuses")
        elif sorted(per_v) != sorted(per_f):
            errors.append("the two revisions did not run the same tests")

    for label, revision in (("vulnerable", vulnerable), ("fixed", fixed)):
        reason = revision.get("failure_reason")
        if reason:
            errors.append(f"{label} revision has a failure reason {reason!r}")
        if revision.get("status") in _SHORT_CIRCUIT_STATUSES:
            errors.append(f"{label} revision is {revision.get('status')}: "
                          "the comparison never ran")
        compile_info = revision.get("compile")
        if isinstance(compile_info, dict) and compile_info.get("rc") not in (None, 0):
            errors.append(f"{label} revision did not compile")
    if exp.get("failure_reason"):
        errors.append(f"experiment has a failure reason "
                      f"{exp.get('failure_reason')!r}")
    if exp.get("status") in _SHORT_CIRCUIT_STATUSES:
        errors.append(f"experiment is {exp.get('status')}: the comparison "
                      "never ran")

    evidence = exp.get("violation_evidence")
    if not isinstance(evidence, dict) or not evidence:
        errors.append("no explicit violation_evidence record")
    else:
        evidence_ok, evidence_errors = validate_violation_evidence(evidence)
        if not evidence_ok:
            errors.extend(f"violation_evidence: {e}" for e in evidence_errors)
    return (not errors, errors)


def run_accounting(root: Path, ledger: list[dict],
                   records: list[dict]) -> dict:
    """Run-accounting counts for the V3 manifest, derived from artefacts.

    `candidate_artefacts` and `evidence_admitted_records` come from the
    in-memory ledger/records; the execution counts come from the committed
    `reports/v3/experimental_proof.json`. Every distinct proof run falls in
    exactly one category (success = completed test rc 0, failed =
    `test_failed`, blocked = `blocked`); a duplicate run, a run that fits no
    category, or a run that would fit two is returned as an error, so the
    counts can never double-count.
    """
    proof = _read(root / "reports" / "v3" / "experimental_proof.json") or {}
    runs = [r for r in (proof.get("runs") or []) if isinstance(r, dict)]
    errors: list[str] = []
    seen: dict[str, int] = {}
    successful = failed = blocked = 0
    for index, run in enumerate(runs):
        run_id = str(run.get("finding_id") or f"run#{index}")
        if run_id in seen:
            errors.append(f"proof run {run_id!r} is listed more than once")
            continue
        seen[run_id] = index
        status = str(run.get("status") or "").strip()
        rc = (run.get("test") or {}).get("rc")
        if status == "blocked":
            if rc == 0:
                errors.append(f"proof run {run_id!r} is blocked but its test rc=0")
            blocked += 1
        elif status == "test_failed":
            if rc == 0:
                errors.append(f"proof run {run_id!r} is test_failed but its test rc=0")
            failed += 1
        elif rc == 0:
            successful += 1
        else:
            errors.append(f"proof run {run_id!r} fits no accounting category "
                          f"(status={status!r}, test rc={rc!r})")
    attempts = len(seen)
    if attempts != successful + failed + blocked:
        errors.append(f"attempts {attempts} != successful {successful} + "
                      f"failed {failed} + blocked {blocked}")
    counts = {
        "candidate_artefacts": sum(1 for c in ledger if c.get("experiment")),
        "execution_attempts": attempts,
        "successful_executions": successful,
        "failed_executions": failed,
        "blocked_executions": blocked,
        "evidence_admitted_records": sum(
            1 for r in records if r.get("verification_level") in L3_PLUS),
    }
    return {"counts": counts, "errors": errors, "run_ids": sorted(seen)}
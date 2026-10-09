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
from pathlib import Path

U = "unknown"

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
    for run in proof.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        key = evidence_key(run.get("finding_id", ""))
        if not key:
            continue
        level = run.get("level_awarded")
        status = run.get("status")
        profit = [d for d in (run.get("profit_deltas") or [])
                  if isinstance(d, dict) and d.get("profit", 0) > 0
                  and d.get("attacker_side")]
        entry = {
            "level": level if level in ("L3", "L4", "L5") else "L1",
            "status": status,
            "basis": run.get("level_basis") or U,
            "failure_reason": run.get("failure_reason"),
            "test": run.get("test") or {},
            "artifact_dir": _rel_artifact(root, run.get("artifact_dir")),
            "artifact_hashes": run.get("artifact_hashes") or {},
            "clone_head": run.get("clone_head"),
        }
        if profit:
            best = max(profit, key=lambda d: d.get("profit", 0))
            entry["profit_evidence"] = {
                "max_profit": best.get("profit"),
                "label_before": best.get("label_before"),
                "label_after": best.get("label_after"),
            }
        # Merge onto the sweep verdict rather than replacing it: a fork run adds
        # execution evidence, it does not erase the compile evidence the
        # record already earned (a blocked-at-fork PoC still compiles).
        base = dict(ev.get(key) or {})
        for _f, _v in entry.items():
            if _v is not None:
                base[_f] = _v
        base["compile"] = base.get("compile") or entry.get("compile")
        ev[key] = base

    # L5 must carry profit evidence: refuse the level without it rather
    # than trusting a status string.
    for key, entry in ev.items():
        if entry.get("level") == "L5" and not entry.get("profit_evidence"):
            entry["level"] = "L4"
            entry["status"] = "executed_no_profit_evidence"
            entry["basis"] = ("fork test executed but no attacker-side "
                              "profit evidence in the run record")
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
        pe = entry.get("profit_evidence") or {}
        return (f"published exploit PoC compiled and executed on a pinned "
                f"fork (clone HEAD {head}); attacker profit "
                f"{pe.get('max_profit')} observed between "
                f"'{pe.get('label_before')}' and '{pe.get('label_after')}'")
    if lvl == "L4":
        return (f"published exploit PoC compiled and the fork test executed "
                f"to completion (clone HEAD {head}); no attacker-side profit "
                "was observed, so the claimed violation is NOT reproduced")
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
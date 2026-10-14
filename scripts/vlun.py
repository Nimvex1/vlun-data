"""Shared loaders and constants for the VLUN v2 pipeline.

The `jsonl/` directory is the immutable original-evidence layer produced by the
v1 builder. Nothing in this pipeline writes to it. Derived records go to
`derived/`, so a researcher can always separate:
  original audit evidence  -> jsonl/   (never rewritten)
  dataset-builder analysis -> derived/ (deterministic, reproducible)
  experimental results     -> reports/verification*.json (execution artefacts)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_io as _io  # noqa: E402  (shared JSON/JSONL + hash primitives)

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "jsonl"
DERIVED = ROOT / "derived"
REPORTS = ROOT / "reports"
WORK = ROOT / "work"
BENCH = ROOT / "benchmark"
EXPERIMENTS = ROOT / "experiments"
SPLITS_DIR = ROOT / "splits_v2"
SPLITS_V2 = ROOT / "splits_v2"

# Three versions, three jobs. v2.2 used to be described as "2.0" in this file
# while README.md called the release v2.1 and no `schema_version` existed
# anywhere, so nothing could tell a reader which of the three numbers they were
# looking at. They are now named separately and validate.py fails if they drift
# (check `v2.2/versions_agree`).
DATASET_VERSION = "2.2"   # the release: every artefact this pipeline writes
SCHEMA_VERSION = "2.2"    # the record schema those artefacts are written in
SOURCE_VERSION = "1.0"    # jsonl/ only: the immutable v1 source layer

CORE_FILES = {
    "findings": "findings.jsonl",
    "negatives": "negative_findings.jsonl",
    "exploits": "exploits.jsonl",
    "patches": "patches.jsonl",
    "protocol": "protocol.jsonl",
    "metadata": "metadata.jsonl",
    "errors": "errors.jsonl",
}

SPLITS = ("train", "validation", "test")

# ---------------------------------------------------------------------------
# Evidence semantics (section 4 / 23 of the hardening brief).
# `evidence` marks HOW a value came to exist. A dataset consumer must never be
# able to read a derived statement as an experimentally verified one, so the
# vocabulary is closed and ordered by strength.
# ---------------------------------------------------------------------------
EVIDENCE_TYPES = (
    "observed_fact",  # read directly out of a retrieved artefact
    "reported_claim", # stated by an identifiable external source (report, judge, sponsor)
    "derived_fact",   # computed by this pipeline, rule stated in code
    "experimentally_verified",  # produced by actually compiling + running something
    "externally_attributed",    # attributed to a named third party (judge, sponsor, label)
    "unverified",     # asserted somewhere but not checked here
    "unknown",        # no defensible value available
)

# Ordered weakest -> strongest; used to compute an honest confidence.
_EVIDENCE_RANK = {
    "unknown": 0,
    "unverified": 1,
    "externally_attributed": 2,
    "derived_fact": 3,
    "observed_fact": 4,
    "reported_claim": 4,
    "experimentally_verified": 5,
}

# Why an exploit could not be executed. Never widen this list silently.
EXEC_FAILURE_REASONS = (
    "source_unavailable",
    "dependency_unavailable",
    "historical_commit_unavailable",
    "broken_original_test",
    "environment_unavailable",
    "license_restriction",
    "insufficient_evidence",
    "poc_invalid",
    "poc_reconstruction_failed",
    "no_poc_published",
)

LICENSE_CLASSES = (
    "redistributable",
    "source_available_but_not_redistributable",
    "reference_only",
    "unavailable",
    "unknown",
)

INVARIANT_SOURCES = (
    "explicit_report",
    "nat_spec",
    "test_assertion",
    "protocol_documentation",
    "experimentally_derived",
    "mechanically_derived",
    "none",
)

ATTACKER_KINDS = (
    "unprivileged",
    "privileged",
    "malicious_dependency",
    "honest_but_misconfigured",
    "unknown",
)

TRUSTED_ROLES = (
    "owner",
    "admin",
    "governance",
    "keeper",
    "manager",
    "maintainer",
    "operator",
    "guardian",
    "role_member",
    "none",
)

# ---------------------------------------------------------------------------
# The benchmark families. key -> (file name, layer, the question the family asks).
#
# This is the single source of truth for what a family is: scripts/validate.py
# fails the build if benchmark/manifest.json does not carry every one of these
# keys with a file behind it, so a stage that rebuilds only part of the
# benchmark (build_benchmark.py writes A-J, build_benchmark_v22.py writes K-Q)
# cannot silently drop a family and still ship.
#
# A-J are built by scripts/build_benchmark.py from the v1 layer; K-Q by
# scripts/build_benchmark_v22.py from the v2.2 layer. Both write only under
# benchmark/, and the model-facing payload of every task is its `input` object -
# task ids and `source` blocks carry the record id for traceability and are not
# meant to be shown to a model.
# ---------------------------------------------------------------------------
BENCHMARK_FAMILIES = {
    "A": ("A_vulnerability_detection", "v1",
          "does this protocol contain a confirmed, exploitable vulnerability?"),
    "B": ("B_root_cause_reasoning", "v1",
          "what is the root cause and which invariant does it violate?"),
    "C": ("C_attacker_reasoning", "v1",
          "who can carry this out, what must they be able to do, in what order?"),
    "D": ("D_exploit_construction", "v1",
          "write a Foundry test that demonstrates the claimed impact"),
    "E": ("E_exploit_verification", "v1",
          "does this test demonstrate the claimed impact?"),
    "F": ("F_false_positive_rejection", "v1",
          "is this claim a valid vulnerability, and what blocks it if not?"),
    "G": ("G_patch_verification", "v1",
          "does the fix address the vulnerability?"),
    "H": ("H_verified_exploit", "v1",
          "name the vulnerability, attacker model and PoC at the audited revision, "
          "against code whose experiment was actually executed"),
    "I": ("I_verified_non_exploit", "v1",
          "is this exploitable at the audited revision, given an executed attempt?"),
    "J": ("J_verified_patch", "v1",
          "does the exploit pass on the vulnerable revision and fail on the fixed one?"),
    "K": ("K_language_ecosystem_routing", "v2.2",
          "which language and which ecosystem does this finding concern?"),
    "L": ("L_severity_reconciliation", "v2.2",
          "what severity do the publishers agree on, and who says so?"),
    "M": ("M_experiment_level_classification", "v2.2",
          "which L0-L6 level and which outcome does this executed run earn?"),
    "N": ("N_attacker_identity_extraction", "v2.2",
          "who does a source sentence say can act, and what is the sentence?"),
    "O": ("O_record_class_and_scope", "v2.2",
          "what kind of record is this: advisory, incident, judged finding, "
          "audit finding, or out of scope?"),
    "P": ("P_provenance_tier_and_rights", "v2.2",
          "what tier and origin does each source admit under, and may it be redistributed?"),
    "Q": ("Q_evidence_type_and_quality_rubric", "v2.2",
          "type every claim's evidence and apply the published quality rubric"),
}

# Retired benchmark families: task files live under benchmark/retired_families/
# (v3 families likewise), kept byte-identical and still audited, but excluded
# from the headline micro-average. Task-file names (with .jsonl), matching
# score_benchmark load_tasks keys and the moved files. A family returns to the
# headline only with an audit showing best_shortcut_accuracy < 0.75 on the
# test split. K/L/R are NOT listed: their prescribed fixes (Phase 3.2/3.3)
# run first; failures join this set via the shortcut gate.
RETIRED_FAMILIES = frozenset({
    "B_root_cause_reasoning.jsonl",
    "E_exploit_verification.jsonl",
    "K_language_ecosystem_routing.jsonl",
    "L_severity_reconciliation.jsonl",
    "M_experiment_level_classification.jsonl",
    "N_attacker_identity_extraction.jsonl",
    "O_record_class_and_scope.jsonl",
    "P_provenance_tier_and_rights.jsonl",
    "v3_S_contest_outcome.jsonl",
    "v3_T_taxonomy_explicit.jsonl",
})


def retired_manifest_entry(manifest: dict, task_key: str):
    """Carry a retired family's manifest entry forward unchanged.

    Builders that skip retired families must still emit their manifest
    entries (gates iterate every known family), so the entry is copied
    verbatim from the previous manifest — which on a fresh clone is the
    committed one. Returns None when there is nothing to carry.
    """
    entry = ((manifest or {}).get("tasks") or {}).get(task_key)
    if entry is None:
        return None
    return dict(entry) if isinstance(entry, dict) else entry


def read_jsonl(path: Path) -> list[dict]:
    return _io.read_jsonl(path)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    _io.write_jsonl(path, rows)


def write_json(path: Path, obj) -> None:
    _io.write_json(path, obj)


def load_core() -> dict[str, list[dict]]:
    return {k: read_jsonl(JSONL / v) for k, v in CORE_FILES.items()}


def load_splits() -> dict[str, list[dict]]:
    # The shipped splits are splits_v2/ (post-quarantine). The pre-quarantine
    # splits/ directory was retired: one counter, one truth.
    return {s: read_jsonl(SPLITS_DIR / f"{s}.jsonl") for s in SPLITS}


def rec_id(row: dict) -> str:
    """Stable identifier for a record, independent of array position."""
    rid = row.get("finding", {}).get("id")
    if rid:
        return rid
    rid = row.get("error", {}).get("id") or row.get("error", {}).get("code")
    if rid:
        return str(rid)
    if row.get("protocol"):
        name = row["protocol"]
        return "protocol:" + str(name.get("name") or name)
    blob = json.dumps(row, sort_keys=True, ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()[:24]


def code_entries(row: dict) -> list[dict]:
    """All code-context-like entries a record carries."""
    out = list(row.get("code_context") or [])
    out += list(row.get("vulnerable_code") or [])
    out += list(row.get("code_reference_only") or [])
    return out


def snippet_entries(row: dict) -> list[dict]:
    return [e for e in (row.get("code_context") or []) + (row.get("vulnerable_code") or []) if e.get("snippet")]


def sha256_text(text: str) -> str:
    return _io.sha256_text(text)


def evidence_strength(ev: str) -> int:
    return _EVIDENCE_RANK.get(ev, 0)


GH_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$")


def owner_repo(src: dict) -> str | None:
    """`owner/repo` for a record's `source` block.

    `source.organization` is the audit organisation's display name ("Code4rena"),
    not the GitHub owner, so the owner is taken from repository_url and only
    falls back to organization when the URL is absent.
    """
    if not src:
        return None
    m = GH_REPO_RE.match((src.get("repository_url") or "").strip())
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    if src.get("repository"):
        return f"{src.get('organization') or 'code-423n4'}/{src['repository']}"
    return None


def confidence_from_evidence(levels) -> str:
    """Map a bag of evidence labels to high/medium/low using the weakest link."""
    if not levels:
        return "low"
    worst = min(evidence_strength(x) for x in levels)
    if worst >= 4:
        return "high"
    if worst >= 2:
        return "medium"
    return "low"


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 900, env: dict | None = None):
    """Run a command, never raising. Returns (rc, stdout, stderr, timed_out)."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
            timeout=timeout, env=full_env, errors="replace",
        )
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s", True
    except FileNotFoundError as exc:
        return 127, "", str(exc), False


def tool_version(cmd: list[str], pattern: str = r"(\d+\.\d+\.\d+[\w\-+]*)") -> str:
    rc, out, err, _ = run(cmd, timeout=60)
    text = (out or "") + (err or "")
    m = re.search(pattern, text)
    return m.group(1) if m else "unknown"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def log(*args) -> None:
    print(*args, flush=True)
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

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "jsonl"
DERIVED = ROOT / "derived"
REPORTS = ROOT / "reports"
WORK = ROOT / "work"
BENCH = ROOT / "benchmark"
SPLITS_DIR = ROOT / "splits"
SPLITS_V2 = ROOT / "splits_v2"

DATASET_VERSION = "2.0"
SOURCE_VERSION = "1.0"

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


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{lineno} invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    tmp.replace(path)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    tmp.replace(path)


def load_core() -> dict[str, list[dict]]:
    return {k: read_jsonl(JSONL / v) for k, v in CORE_FILES.items()}


def load_splits() -> dict[str, list[dict]]:
    return {s: read_jsonl(ROOT / "splits" / f"{s}.jsonl") for s in SPLITS}


def core_rows() -> list[tuple[str, dict]]:
    """Every record in `jsonl/` tagged with its file family."""
    out = []
    for family, fname in CORE_FILES.items():
        for row in read_jsonl(JSONL / fname):
            out.append((family, row))
    return out


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
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def die(msg: str, code: int = 1):
    log(f"ERROR: {msg}")
    sys.exit(code)
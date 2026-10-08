"""Shared constants and helpers for the Vbeta layer.

Vbeta is ADDITIVE and ISOLATED: every path below lives under ``Vbeta/``.
No helper here references any PRESENT path for writing. The gate
(validate_vbeta.py) additionally warns if PRESENT sentinels drift.

Governing rule: TRUTH > PROVENANCE > REPRODUCIBILITY > COVERAGE > SCALE.
Fields not established from observed material are ``"unknown"`` / ``None``.
No exploit is executed in this layer, so no record may exceed L1.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
VBETA_DIR = ROOT / "Vbeta"
SCRIPTS = VBETA_DIR / "scripts"
FETCHED = VBETA_DIR / "fetched"
JSONL_VB = VBETA_DIR / "jsonl_vbeta"
DERIVED_VB = VBETA_DIR / "derived_vbeta"
SPLITS_VB = VBETA_DIR / "splits_vbeta"
REPORTS_VB = VBETA_DIR / "reports_vbeta"
BENCH_VB = VBETA_DIR / "benchmark_vbeta"
EXPERIMENTS_VB = VBETA_DIR / "experiments_vbeta"
TESTS = VBETA_DIR / "tests"

DATASET_VERSION_VB = "vbeta-1.0"
SCHEMA_VERSION_VB = "vbeta-1.0"

UNKNOWN = "unknown"

# Closed vocabulary for the DERIVED severity field. The observed string is
# always kept alongside (severity_observed); this mapping never overwrites
# it. Unambiguous tokens map; anything else (Minor, Insight, empty) is
# unknown with a reason — never forced into the nearest bucket.
SEVERITY_NORMALIZED_VOCAB = (
    "critical", "high", "medium", "low", "informational", "unknown",
)

_SEV_WORD = re.compile(
    r"\b(critical|high|medium|low|informational|info)\b")


def normalize_severity(raw) -> tuple[str, str]:
    """Map an observed severity string to the closed vocabulary.

    Returns (value, reason). First vocabulary word wins
    ("**Impact:** High, ..." -> high); "info" alone counts as
    informational; no match -> unknown.
    """
    if raw is None or not str(raw).strip():
        return ("unknown", "no severity observed")
    text = re.sub(r"\*+", "", str(raw)).strip()
    m = _SEV_WORD.search(text.lower())
    if not m:
        return ("unknown",
                f"no closed-vocab token in observed {raw!r:.60}")
    word = m.group(1)
    if word == "info":
        return ("informational", f"'info' in observed {raw!r:.60}")
    return (word, f"first closed-vocab token in observed {raw!r:.60}")

VERIFICATION_LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5", "L6")

DECISIONS = (
    "IMPORT",
    "IMPORT_AS_UNVERIFIED",
    "IMPORT_AS_NEGATIVE",
    "CORROBORATION_ONLY",
    "REJECT",
    "RESEARCH_ONLY",
)

ADMITTED_DECISIONS = ("IMPORT", "IMPORT_AS_UNVERIFIED", "IMPORT_AS_NEGATIVE")

NEGATIVE_CLASSES = (
    "verified_non_exploit",
    "externally_rejected",
    "duplicate",
    "out_of_scope",
    "unknown",
)

URL_RE = re.compile(r"^https://\S+$")
SHA64_RE = re.compile(r"^[0-9a-f]{64}$")


def log(msg: str = "") -> None:
    print(msg, flush=True)


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n": without it Windows text mode emits CRLF, making build
    # output platform-dependent.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n": see write_json — platform-stable LF output.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def assert_inside_vbeta(path: Path) -> Path:
    """Refuse to write anywhere outside Vbeta/. Called by every writer."""
    resolved = path.resolve()
    vbeta = VBETA_DIR.resolve()
    if resolved != vbeta and vbeta not in resolved.parents:
        raise RuntimeError(f"REFUSED: write outside Vbeta/: {path}")
    return path


def load_sources() -> list[dict]:
    return read_json(VBETA_DIR / "sources.json")["sources"]


def decide(candidate: dict) -> tuple[str, str]:
    """Admission rule (code, not hand-stamped). Returns (decision, reason)."""
    kind = candidate.get("kind")
    sev = candidate.get("severity_observed")
    status = candidate.get("status_observed")
    link = candidate.get("link_observed")
    if kind == "finding" and candidate.get("duplicate_of"):
        # Near-duplicate of an admitted row: link kept, never admitted twice.
        return ("CORROBORATION_ONLY",
                "near-duplicate title; first occurrence kept")
    if kind == "finding" and candidate.get("origin") == "user_contributed" and sev:
        # Operator-authored training finding: admitted ONLY as unverified.
        # Evidence stays L0, verified_patch stays false; the receipt records
        # who authored it and when. Never IMPORT (no external source).
        return ("IMPORT_AS_UNVERIFIED",
                "operator-authored training finding; unverified by design")
    if kind == "finding" and sev and link and status:
        if str(status).strip().lower() == "rejected":
            return ("IMPORT_AS_NEGATIVE",
                    "judged-rejected finding with observed severity -> externally_rejected")
        return ("IMPORT", "title+severity+link+status all observed")
    if kind == "finding" and sev and link:
        return ("IMPORT_AS_UNVERIFIED",
                "title+severity+link observed, status partial or unobserved")
    if kind == "finding" and link:
        return ("IMPORT_AS_UNVERIFIED", "title+link observed, severity unobserved")
    if kind == "report_pointer" and candidate.get("zero_findings_declared"):
        return ("IMPORT_AS_NEGATIVE",
                "clean audit declaring no significant flaws -> verified_non_exploit")
    if kind == "report_pointer" and link:
        return ("RESEARCH_ONLY", "report-level pointer only; no per-finding data")
    return ("REJECT", "insufficient observed evidence for any admission class")

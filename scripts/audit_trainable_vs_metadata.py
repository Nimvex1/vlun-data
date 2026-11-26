#!/usr/bin/env python3
"""Audit VLUN JSONL rows: trainable inline content vs metadata-only stubs.

Read-only diagnostic. Discovers every *.jsonl under the repo root (excluding
work/, .git/, node_modules/, .venv/, __pycache__/), classifies every row into
exactly one bucket, evaluates hydration feasibility for stub/partial rows, and
writes:

  reports/metadata_vs_trainable_audit.json
  reports/metadata_stub_hydration_plan.md
  reports/metadata_vs_trainable_audit.md

No dataset file (.jsonl or dataset .json) is ever modified.

Python standard library only.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXCLUDE_DIRS = ("work", ".git", "node_modules", ".venv", "__pycache__")

# Table roles (Option A). Every .jsonl file is exactly one of these:
#   trainable_or_benchmark      - a dataset, derived task table, split or benchmark task
#   governance_or_quarantine_ledger - provenance/rights/quarantine/dedup/audit bookkeeping
#   test_fixture                - files under tests/fixtures/** (deliberately synthetic)
# Only the first role is subject to the hard zero-METADATA_ONLY_STUB assertion in
# scripts/verify_audit.py. The role is recorded per file in the audit JSON so the
# exclusion cannot drift silently when a new ledger or task table is added.
TABLE_ROLES = ("trainable_or_benchmark", "governance_or_quarantine_ledger", "test_fixture")

# Path fragments that identify governance/bookkeeping ledgers. These are exact
# path segments or suffixes, never substring matches on bare words like "source"
# (jsonl_ml/sources_*.jsonl are source declarations -- governance by design).
GOVERNANCE_BASENAMES = frozenset({
    "rights.jsonl", "source_registry.jsonl", "sources.jsonl", "receipts.jsonl",
    "metadata.jsonl", "errors.jsonl", "protocol.jsonl", "duplicates.jsonl",
    "corroborations.jsonl", "corroborations_v31.jsonl", "candidate_ledger.jsonl",
    "admitted_ledger.jsonl", "duplicate_ledger.jsonl", "duplicated_ledger.jsonl",
    "quarantine.jsonl", "registry.jsonl", "manifest.jsonl",
    "rights_ledger.jsonl", "source_ledger.jsonl", "source_sha_index.jsonl",
    "source_candidates.jsonl", "corroborations_v31.jsonl",
})
GOVERNANCE_PATH_FRAGMENTS = (
    "quarantin", "/rights", "rights_", "/governance/", "/01_dedup/",
    "candidate_ledger", "admitted_ledger", "duplicate_ledger", "corroborations",
    "/receipts.", "/registry.", "rights_ledger", "withheld_pointers",
    "rejection_corpus", "audit_ingestion_records", "audit_sources",
    "normalization_fragments", "overlap_manifest", "reconstruction_log",
    "poc_attempts", "root_cause_candidates", "hydration_quarantine",
    "v1_hydration_quarantine", "negative_quarantine", "withheld_harness",
    # Held-out answer keys are governance/evaluation ledgers: they must never
    # be model input, so their metadata-only rows are legitimate bookkeeping.
    "_keys.jsonl", "_exploratory_keys.jsonl",
    # The frozen IAA annotation study sample is a research instrument (no gold
    # answers); it is not model training data and its frozen bytes are pinned.
    "annotation/iaa_v1/sample.jsonl",
    # Raw harvest/staging layers: pointer records for reproducibility, never
    # model input. The trainable projections are derived/records.jsonl etc.
    "vbeta/jsonl_vbeta/findings.jsonl", "jsonl_v3/findings.jsonl",
    "jsonl_v4/findings.jsonl",
    # Rights-governed METADATA_ONLY distribution projections: withheld-content
    # mirrors with pointers, governed by the rights ledger — never model input.
    "distribution_v1/records_v1.jsonl", "distribution_v1/records_v4.jsonl",
)

CODE_MARKERS = (
    "pragma solidity",
    "contract ",
    "function ",
    "def ",
    "fn ",
    "import ",
    "use ",
    "{",
    "}",
    ";",
    "=>",
    "require(",
    "assert",
    "emit ",
    "mapping(",
)

DIFF_MARKERS = ("diff --git ", "--- a/", "+++ b/", "@@ ")
POC_MARKERS = (
    "function test",
    "def test",
    "#[test]",
    "describe(",
    "it(",
    "assert",
    "forge-std",
    "vm.",
    "hardhat",
)
SPEC_DECL_RE = re.compile(
    r"\b(rule|invariant|definition|ghost|method)\s+[A-Za-z_]\w*\s*(\(|\{|ensures|=>|$)",
    re.MULTILINE,
)

METADATA_TOKENS = ("metadata_only", "pointer_only")
# Policy tags that replaced METADATA_ONLY on hydrated rows. They are NOT stub
# markers: a hydrated row carrying one of these values is fully trainable.
HYDRATED_HANDLING_VALUES = (
    "FULL_INLINE_EXTRACTION",
    "VERBATIM_HYDRATED",
    "QUARANTINED_POINTER",
    "INLINE_EVIDENCE_EXTRACTED",
)
FLAG_FIELD_NAMES = ("extraction_mode", "data_handling", "redistribution", "extraction_flag")

KNOWN_CODE_LEAVES = {
    "code", "snippet", "source_code", "code_body", "poc_code",
    "vulnerable_code", "code_context", "code_context_expanded",
}
KNOWN_CODE_SEGMENTS = {"code_context", "code_context_expanded", "vulnerable_code", "code_blocks"}
KNOWN_SPEC_LEAVES = {"rule_body", "invariant_expression", "spec", "cvl", "formal_spec"}

POINTER_LEAVES = {
    "source_location", "clone_head", "source_url", "source_urls", "receipt_url",
    "canonical_url", "vulnerable_commit", "fixed_commit", "commit_sha", "commit",
    "url", "urls", "file", "report_file", "source_files", "fix_pr_urls",
    "repository_url", "pointer", "published_pointer", "target_url", "duplicate_of",
    "issue_url", "original_issue_url", "source_report_id", "affected_file",
}

PLACEHOLDERS = {"", "unknown", "null", "none", "n/a", "na", "redacted", "withheld"}
ADVISORY_DOMAINS = ("code4rena.com", "cantina.xyz", "osec.io", "suisentinel.xyz")

URL_RE = re.compile(r"https?://\S+")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
SHA40_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
GHSA_RE = re.compile(r"GHSA-[a-z0-9-]+", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
ISSUE_RE = re.compile(r"issues/\d+|issues[ #]+\d+", re.IGNORECASE)
PULL_RE = re.compile(r"pull/\d+|pulls?[ #]+\d+", re.IGNORECASE)
ALPHA_RE = re.compile(r"[A-Za-z]+")
ASSERT_RE = re.compile(r"\bassert\w*\s*\(|\bassert\b")

BUCKET_NAMES = ("FULLY_TRAINABLE", "PARTIAL_TEXT_NO_CODE", "METADATA_ONLY_STUB")
HYDRATION_NAMES = (
    "HYDRATABLE_FROM_LOCAL_WORK",
    "HYDRATABLE_FROM_GIT_OR_GITHUB",
    "UNHYDRATABLE_DEAD_POINTER",
)
HYDRATION_SHORT = {
    "HYDRATABLE_FROM_LOCAL_WORK": "LOCAL",
    "HYDRATABLE_FROM_GIT_OR_GITHUB": "GIT",
    "UNHYDRATABLE_DEAD_POINTER": "DEAD",
}
HYDRATION_PRIORITY = {
    "HYDRATABLE_FROM_LOCAL_WORK": 0,
    "HYDRATABLE_FROM_GIT_OR_GITHUB": 1,
    "UNHYDRATABLE_DEAD_POINTER": 2,
}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _count_jsonl_below(base: Path) -> int:
    """Count .jsonl files under one excluded subtree.

    The discovery walk prunes excluded directories in place, so it can no
    longer see their contents.  They still have to be counted for the
    exclusion report; walking only the excluded roots (rather than re-walking
    the whole repository, which is what used to drag work/ and .git/ into the
    scan) preserves the count exactly.
    """
    count = 0
    for _dirpath, _dirnames, filenames in os.walk(base):
        count += sum(1 for name in filenames if name.lower().endswith(".jsonl"))
    return count


def discover_jsonl(root: Path):
    """Return (sorted file paths, sorted excluded names, excluded file count)."""
    found = []
    excluded = set()
    excluded_roots: list[Path] = []
    # Prune excluded directories at the TOP of the walk callback, before
    # os.walk recurses into them: work/, .git/, node_modules/, .venv/ and
    # __pycache__/ are never entered by the discovery walk.
    for dirpath, dirnames, filenames in os.walk(root):
        kept = []
        for name in dirnames:
            if name in EXCLUDE_DIRS:
                excluded.add(name)
                excluded_roots.append(Path(dirpath) / name)
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            if name.lower().endswith(".jsonl"):
                found.append(Path(dirpath) / name)
    # Count the jsonl files hidden by that pruning.  Only the excluded
    # subtrees are walked, not the entire tree a second time, and each
    # excluded file is still counted exactly once.
    excluded_count = 0
    for base in excluded_roots:
        excluded_count += _count_jsonl_below(base)
    found.sort(key=lambda p: p.relative_to(root).as_posix())
    return found, sorted(excluded), excluded_count


def classify_table_role(rel: str) -> str:
    """Return the one audit table role for a repo-relative POSIX path.

    Pattern order matters: test fixtures and governance ledgers are classified
    first; everything else is a trainable table, benchmark task, data split or
    derived task table and is therefore subject to the zero-stub gate.
    """
    path = rel.replace("\\", "/")
    low = path.lower()
    if low.startswith("tests/fixtures/"):
        return "test_fixture"
    base = low.rsplit("/", 1)[-1]
    if base in GOVERNANCE_BASENAMES:
        return "governance_or_quarantine_ledger"
    if any(fragment in low for fragment in GOVERNANCE_PATH_FRAGMENTS):
        return "governance_or_quarantine_ledger"
    return "trainable_or_benchmark"


def assign_layer(rel: str) -> str:
    """Assign a coarse provenance layer from a repo-relative posix path."""
    parts = rel.split("/")
    top = parts[0]
    if rel == "derived/records.jsonl" or rel == "datasets/verified_negatives.jsonl":
        return "v1"
    if top == "jsonl":
        return "v1"
    if top == "jsonl_ml":
        return "v2.2"
    if top in ("jsonl_v3", "derived_v3"):
        return "v3"
    if top == "Vbeta":
        return "vbeta"
    if top in ("V4", "jsonl_v4", "derived_v4", "distribution_v1"):
        return "v4"
    if top == "derived_prove":
        return "prove"
    if top == "wave1":
        return "wave1"
    if top == "benchmark":
        return "benchmark"
    if top == "datasets":
        return "datasets"
    if top == "taxonomy":
        return "taxonomy"
    return "other/" + top


# ---------------------------------------------------------------------------
# Generic string classification helpers
# ---------------------------------------------------------------------------

def leaf_of(path: str) -> str:
    return path.rsplit(".", 1)[-1].rstrip("[]")


def segments_of(path: str):
    return [seg.rstrip("[]") for seg in path.split(".")]


def is_known_code_path(path: str) -> bool:
    if leaf_of(path) in KNOWN_CODE_LEAVES:
        return True
    segs = segments_of(path)
    return any(s in KNOWN_CODE_SEGMENTS for s in segs)


def marker_set(text: str, markers) -> set:
    return {m for m in markers if m in text}


def mostly_special(text: str) -> bool:
    """True when a string is predominantly URLs, hashes/SHAs or file paths."""
    n = len(text)
    if n == 0:
        return True
    url_chars = sum(len(m.group(0)) for m in URL_RE.finditer(text))
    if url_chars / n > 0.35:
        return True
    hex_chars = sum(len(m.group(0)) for m in HEX_RE.finditer(text))
    if hex_chars / n > 0.25:
        return True
    path_chars = 0
    for token in text.split():
        if ("/" in token or "\\" in token) and re.fullmatch(r"[\w./\\:#@\-\[\]]+", token):
            path_chars += len(token)
    if path_chars / n > 0.35:
        return True
    return False


def is_prose(text: str) -> bool:
    if len(text) < 100 or mostly_special(text):
        return False
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")) and text.count('"') >= 4:
        return False  # JSON scaffolding
    letters_spaces = sum(1 for c in text if c.isalpha() or c.isspace())
    if letters_spaces / len(text) < 0.5:
        return False
    if len(ALPHA_RE.findall(text)) < 12:
        return False
    return True


def qualifies_as_code(text: str, path: str) -> bool:
    if len(text) < 50 or mostly_special(text):
        return False
    found = marker_set(text, CODE_MARKERS)
    if not found:
        return False
    if is_known_code_path(path):
        return True
    return len(found) >= 2  # unknown keys need >=2 distinct code markers


def qualifies_as_diff(text: str) -> bool:
    if len(text) < 50:
        return False
    if any(m in text for m in DIFF_MARKERS):
        return True
    plusminus = [ln for ln in text.splitlines() if ln.startswith(("+", "-"))]
    return len(plusminus) >= 2


def qualifies_as_poc(text: str, path: str) -> bool:
    if len(text) < 50:
        return False
    leaf = leaf_of(path)
    known_poc_key = leaf in {"poc", "exploit", "poc_code"} or "poc" in segments_of(path)
    if known_poc_key and any(m in text for m in POC_MARKERS):
        return True
    if ASSERT_RE.search(text) or any(
        m in text for m in ("function test", "def test", "#[test]", "describe(", "forge-std", "vm.", "hardhat")
    ):
        return True
    return False


def qualifies_as_spec(text: str, path: str) -> bool:
    if len(text) < 50:
        return False
    strong = bool(SPEC_DECL_RE.search(text))
    generic = {m for m in ("forall", "env", "=>", "assert") if re.search(r"\b" + re.escape(m) + r"\b", text)}
    if leaf_of(path) in KNOWN_SPEC_LEAVES:
        return strong or bool(generic)
    return strong or len(generic) >= 2


# ---------------------------------------------------------------------------
# Row walking
# ---------------------------------------------------------------------------

def walk_strings(obj, path=""):
    """Yield (dotted_path, string_value) for every string in a JSON row."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from walk_strings(value, path + "." + str(key) if path else str(key))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            yield from walk_strings(value, (path + "." if path else "") + "[" + str(idx) + "]")


def _is_extraction_flag_field(leaf: str) -> bool:
    """Return True only when ``leaf`` names an extraction/metadata flag field.

    Rights-policy false-positive fix
    --------------------------------
    The METADATA_ONLY / POINTER_ONLY sentinel is a meaningful stub marker ONLY
    in fields that record *how content was extracted*. Rights / licensing /
    governance fields sometimes legitimately carry the very same literal string
    as a policy value (e.g. ``data_handling_policy: "METADATA_ONLY"`` in v4
    findings, ``distribution: "METADATA_ONLY"`` in span-task answer keys, or a
    ``license`` value in wave1 rights governance). Treating any such value as a
    stub marker misclassified inline-code+prose rows as METADATA_ONLY_STUB.

    Priority rules (order matters, to preserve the real stub markers):

    1. An EXACT name in FLAG_FIELD_NAMES always wins. This deliberately keeps
       ``data_handling`` and ``redistribution`` as flag fields -- v3 sources use
       ``redistribution: METADATA_ONLY`` as a genuine stub marker, even though
       "redistribution" contains the substring "distribution".
    2. Rights / licensing / governance names are excluded via the tokens
       ``rights``, ``licen[cs]e`` (matched by the "licen" prefix), ``distribution``
       and ``policy``. This excludes ``data_handling_policy`` while rule 1 still
       preserves ``data_handling``.
    3. Otherwise the name qualifies when it contains ``extract`` / ``mode`` /
       ``flag`` / ``handling`` (the generic extraction-flag name family).
    """
    low = leaf.lower()
    if leaf in FLAG_FIELD_NAMES:
        return True
    rights_governance_tokens = ("rights", "licen", "distribution", "policy")
    if any(tok in low for tok in rights_governance_tokens):
        return False
    return any(tok in low for tok in ("extract", "mode", "flag", "handling"))


def explicit_metadata_flag(row: dict, strings) -> bool:
    # The METADATA_ONLY / POINTER_ONLY token is only a stub marker when it sits
    # in an extraction-flag FIELD. The old first loop flagged ANY string whose
    # value equalled the token regardless of field name, which was a false
    # positive for rights-governed fields (data_handling_policy, distribution,
    # license). The exact-value check is retained, so long benchmark input_text
    # values that merely contain the words are still not treated as flags.
    for path, value in strings:
        if not isinstance(value, str):
            continue
        if value.strip().lower() not in METADATA_TOKENS:
            continue
        if _is_extraction_flag_field(leaf_of(path)):
            return True
    # code_reference_only entries are pointer objects (file / commit_sha /
    # source_url / function) with no snippet. An empty array is NOT evidence.
    for key, value in row.items():
        if not (isinstance(key, str) and "code_reference_only" in key):
            continue
        if not value:  # empty list/dict carries no pointer evidence
            continue
        entries = value if isinstance(value, list) else [value]
        pointer_entries = [
            entry for entry in entries
            if isinstance(entry, dict)
            and any(pk in entry for pk in ("file", "source_url", "commit_sha", "function"))
        ]
        if not pointer_entries:
            continue
        has_snippet = False
        for entry in pointer_entries:
            for _p, v in walk_strings(entry):
                if isinstance(v, str) and len(v) >= 50 and not mostly_special(v):
                    has_snippet = True
                    break
            if has_snippet:
                break
        if not has_snippet:
            return True
    return False


def collect_pointers(strings):
    """Return dict of pointer signal booleans plus example strings."""
    signals = {
        "local": False,
        "git": False,
        "advisory_or_pdf": False,
        "placeholder_only": True,
        "examples": [],
    }
    for path, value in strings:
        if not isinstance(value, str):
            continue
        v = value.strip()
        leaf = leaf_of(path)
        if v.lower() in PLACEHOLDERS:
            continue
        signals["placeholder_only"] = False
        low = v.lower()
        normalized = low.replace("\\", "/")

        if "work/sources" in normalized or "clones/" in normalized or normalized.startswith("clones/"):
            signals["local"] = True
        if leaf == "clone_head" or "clone_head" in low:
            signals["local"] = True
        if len(signals["examples"]) < 6 and (
            leaf in POINTER_LEAVES or "http" in low or SHA40_RE.search(v)
            or GHSA_RE.search(v) or CVE_RE.search(v)
        ):
            signals["examples"].append(v[:180])

        if "github.com" in low or GHSA_RE.search(v) or CVE_RE.search(v) or SHA40_RE.search(v):
            signals["git"] = True
        if ISSUE_RE.search(v) or PULL_RE.search(v):
            signals["git"] = True
        if leaf in POINTER_LEAVES and any(m in v for m in ("github.com", "github.io")):
            signals["git"] = True
        if low.endswith(".pdf") or ".pdf#" in low or any(d in low for d in ADVISORY_DOMAINS):
            signals["advisory_or_pdf"] = True
    return signals


def hydration_class(pointers: dict, local_clone_names) -> str:
    if pointers["local"]:
        return "HYDRATABLE_FROM_LOCAL_WORK"
    if pointers["git"]:
        return "HYDRATABLE_FROM_GIT_OR_GITHUB"
    return "UNHYDRATABLE_DEAD_POINTER"


def analyze_row(row: dict, local_clone_names):
    strings = list(walk_strings(row))
    code_chars = diff_chars = poc_chars = prose_chars = spec_chars = 0
    for path, value in strings:
        if not isinstance(value, str):
            continue
        if qualifies_as_code(value, path):
            code_chars += len(value)
        if qualifies_as_diff(value):
            diff_chars += len(value)
        if qualifies_as_poc(value, path):
            poc_chars += len(value)
        if is_prose(value):
            prose_chars += len(value)
        if qualifies_as_spec(value, path):
            spec_chars += len(value)

    flags = {
        "code": code_chars >= 50,
        "diff": diff_chars >= 50,
        "poc": poc_chars >= 50,
        "prose": prose_chars >= 100,
        "spec": spec_chars >= 50,
    }
    flagged = explicit_metadata_flag(row, strings)
    if flagged or not any(flags.values()):
        bucket = "METADATA_ONLY_STUB"
    elif flags["code"] and flags["prose"]:
        bucket = "FULLY_TRAINABLE"
    else:
        bucket = "PARTIAL_TEXT_NO_CODE"

    pointers = collect_pointers(strings)
    hydration = hydration_class(pointers, local_clone_names)
    return {
        "flags": flags,
        "flagged": flagged,
        "bucket": bucket,
        "hydration": hydration,
        "pointers": pointers,
    }


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def hydration_display(counts: dict) -> str:
    present = [(k, counts.get(k, 0)) for k in HYDRATION_NAMES if counts.get(k, 0) > 0]
    if not present:
        return "NONE"
    present.sort(key=lambda item: (-item[1], HYDRATION_PRIORITY[item[0]]))
    return "/".join(f"{HYDRATION_SHORT[k]}({n})" for k, n in present)


def pct(count: int, total: int) -> float:
    return round(100.0 * count / total, 1) if total else 0.0


def markdown_table(file_rows: list) -> str:
    headers = [
        "File", "Layer", "Total Rows", "Fully Trainable", "Partial (Text Only)",
        "Metadata Stub", "% Code", "% Diff", "% PoC", "% Prose", "Hydration Source",
    ]
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for f in file_rows:
        cov = f["coverage_pct"]
        b = f["buckets"]
        cells = [
            f["path"], f["layer"], str(f["total_rows"]), str(b["FULLY_TRAINABLE"]),
            str(b["PARTIAL_TEXT_NO_CODE"]), str(b["METADATA_ONLY_STUB"]),
            f"{cov['pct_code']:.1f}", f"{cov['pct_diff']:.1f}",
            f"{cov['pct_poc']:.1f}", f"{cov['pct_prose']:.1f}",
            f["hydration_source"]["display"],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def hydration_steps(hclass: str, examples) -> list:
    ex = ", ".join(examples[:3]) if examples else "(no concrete pointer found in this row)"
    if hclass == "HYDRATABLE_FROM_LOCAL_WORK":
        return [
            f"Resolve the local clone pointer(s) in the work tree: {ex}.",
            "Open the referenced file under work/sources/ (or the local clone dir) at the recorded "
            "line_start/line_end and extract the exact vulnerable Solidity/Cairo/Rust/Move snippet.",
            "If a vulnerable and a fixed revision both exist locally, produce a unified diff "
            "(diff --git / --- a/ / +++ b/ / @@) and store it in patch.diff / mitigation_diff.",
            "Copy the associated report/issue/judge prose (>=100 chars) into description / "
            "root_cause / security_reasoning; keep the pointer fields as provenance.",
            "Re-run this audit script; the row should move out of METADATA_ONLY_STUB into "
            "FULLY_TRAINABLE (inline code >=50 chars AND inline prose >=100 chars).",
        ]
    if hclass == "HYDRATABLE_FROM_GIT_OR_GITHUB":
        return [
            f"Parse the GitHub/advisory pointer(s): {ex}.",
            "Use the repository + 40-hex commit SHA to fetch the exact source file via the GitHub "
            "REST contents API or the blob URL (raw.githubusercontent.com/<owner>/<repo>/<sha>/<path>).",
            "Fetch the fixed commit/PR/issue when present and generate a unified diff between the "
            "vulnerable and fixed versions; store it in patch.diff / mitigation_diff.",
            "Fetch the issue/PR/judge/sponsor prose and embed >=100 chars into description / "
            "root_cause / security_reasoning / judge_quote.",
            "Embed the retrieved snippet (>=50 chars) and prose, retain commit_sha/source_url as "
            "provenance, and re-run this audit to confirm the row is FULLY_TRAINABLE.",
        ]
    return [
        f"No resolvable code pointer was found (only PDF/advisory/placeholder/no pointer): {ex}.",
        "Locate an alternate first-party source (a public audit report with inline code, a GitHub "
        "repo/commit, or a published PoC) for this finding_id/candidate_id.",
        "If an alternate source is found, embed snippet + unified diff + prose as above; otherwise "
        "mark the row explicitly as unhydratable and exclude it from training.",
        "Do not infer code from the title alone; leave the row as a stub or drop it with a recorded reason.",
    ]


def build_hydration_plan(json_data, stub_rows_by_file, root: Path) -> str:
    layers = {}
    for f in json_data["files"]:
        if not f["has_stubs"]:
            continue
        layers.setdefault(f["layer"], []).append(f)

    out = []
    out.append("# Metadata-stub hydration plan")
    out.append("")
    out.append(
        "Generated by `scripts/audit_trainable_vs_metadata.py`. Read-only diagnostic: no dataset "
        "file is modified by this plan. A row is a stub/partial when it has no inline target source "
        "code or unified diff (and, for stubs, no inline prose >=100 chars, PoC or formal spec)."
    )
    out.append("")

    out.append("## Per-layer summary")
    out.append("")
    out.append("| Layer | Files with stubs | Stub rows | Partial rows | Files |")
    out.append("|---|---:|---:|---:|---|")
    for layer in sorted(layers):
        fs = layers[layer]
        stubs = sum(f["buckets"]["METADATA_ONLY_STUB"] for f in fs)
        partials = sum(f["buckets"]["PARTIAL_TEXT_NO_CODE"] for f in fs)
        out.append(f"| {layer} | {len(fs)} | {stubs} | {partials} | " + ", ".join(f["path"] for f in fs) + " |")
    out.append("")

    callouts = [
        ("wave1/", "wave1"), ("V3 jsonl_v3/", "v3"), ("Vbeta/", "vbeta"),
        ("v2.2 jsonl_ml/", "v2.2"),
        ("V4 jsonl_v4 + derived_v4 + distribution_v1/", "v4"),
        ("v1 files (derived/records.jsonl, datasets/verified_negatives.jsonl, jsonl/*)", "v1"),
    ]
    out.append("### Explicit callouts")
    out.append("")
    for label, layer in callouts:
        fs = layers.get(layer, [])
        if fs:
            stubs = sum(f["buckets"]["METADATA_ONLY_STUB"] for f in fs)
            out.append(
                f"- **{label}**: {len(fs)} file(s) with stubs, {stubs} METADATA_ONLY_STUB row(s) - "
                + ", ".join(f["path"] for f in fs)
            )
        else:
            out.append(f"- **{label}**: no files with stubs detected in this audit.")
    out.append("")

    for f in json_data["files"]:
        if not f["has_stubs"]:
            continue
        key = f["path"]
        sample = stub_rows_by_file.get(key)
        out.append(f"## `{key}`")
        out.append("")
        out.append(f"- Layer: **{f['layer']}**")
        b = f["buckets"]
        out.append(
            f"- Buckets: FULLY_TRAINABLE={b['FULLY_TRAINABLE']}, "
            f"PARTIAL_TEXT_NO_CODE={b['PARTIAL_TEXT_NO_CODE']}, "
            f"METADATA_ONLY_STUB={b['METADATA_ONLY_STUB']}"
        )
        out.append(f"- Dominant hydration source: **{f['hydration_source']['dominant']}** "
                   f"({f['hydration_source']['display']})")
        out.append("")

        if sample:
            out.append("Sample stub record (raw JSON, truncated to ~1800 chars):")
            out.append("")
            out.append("```json")
            out.append(sample["raw"][:1800])
            out.append("```")
            out.append("")

            out.append("What is missing inline:")
            out.append("")
            flags = sample["flags"]
            missing_map = [
                ("code", "target source code / inline snippet (>=50 chars)"),
                ("diff", "unified diff / patch body"),
                ("poc", "PoC / exploit test code"),
                ("prose", "technical prose >=100 chars"),
                ("spec", "formal CVL/Solidity spec / invariant body"),
            ]
            for flag, label in missing_map:
                if not flags[flag]:
                    out.append(f"- {label}")
            if sample["flagged"]:
                out.append("- explicit METADATA_ONLY / POINTER_ONLY flag is present on the row")
            out.append("")

            out.append("Exact hydration steps:")
            out.append("")
            for step in hydration_steps(sample["hydration"], sample["pointers"]["examples"]):
                out.append(f"1. {step}")
            out.append("")
        else:
            out.append("_No sample row retained (file has stubs but no representative row was captured)._")
            out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    root = Path(__file__).resolve().parent.parent
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    json_path = reports / "metadata_vs_trainable_audit.json"
    plan_path = reports / "metadata_stub_hydration_plan.md"
    md_path = reports / "metadata_vs_trainable_audit.md"

    files, excluded, excluded_count = discover_jsonl(root)

    # Names of local clone directories that exist under work/sources/ and V3/clones/.
    local_clone_names = set()
    for base in (root / "work" / "sources", root / "V3" / "clones"):
        try:
            for child in base.iterdir():
                if child.is_dir():
                    local_clone_names.add(child.name.lower())
        except OSError:
            pass

    file_rows = []
    stub_rows_by_file = {}
    total_rows = 0
    total_invalid = 0
    global_buckets = {name: 0 for name in BUCKET_NAMES}
    global_hydration = {name: 0 for name in HYDRATION_NAMES}
    stub_files = []
    by_layer = {}

    for path in files:
        rel = path.relative_to(root).as_posix()
        layer = assign_layer(rel)
        buckets = {name: 0 for name in BUCKET_NAMES}
        coverage_counts = {"pct_code": 0, "pct_diff": 0, "pct_poc": 0,
                           "pct_prose": 0, "pct_spec": 0, "pct_metadata_flagged": 0}
        file_hydration = {name: 0 for name in HYDRATION_NAMES}
        invalid = 0
        valid_rows = 0
        sample = None
        sample_preference = 99

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, TypeError):
                    invalid += 1
                    continue
                if not isinstance(row, dict):
                    invalid += 1
                    continue

                info = analyze_row(row, local_clone_names)
                valid_rows += 1
                b = info["bucket"]
                buckets[b] += 1
                global_buckets[b] += 1
                flags = info["flags"]
                if flags["code"]:
                    coverage_counts["pct_code"] += 1
                if flags["diff"]:
                    coverage_counts["pct_diff"] += 1
                if flags["poc"]:
                    coverage_counts["pct_poc"] += 1
                if flags["prose"]:
                    coverage_counts["pct_prose"] += 1
                if flags["spec"]:
                    coverage_counts["pct_spec"] += 1
                if info["flagged"]:
                    coverage_counts["pct_metadata_flagged"] += 1

                global_hydration[info["hydration"]] += 1
                if b in ("METADATA_ONLY_STUB", "PARTIAL_TEXT_NO_CODE"):
                    file_hydration[info["hydration"]] += 1
                    pref = 0 if b == "METADATA_ONLY_STUB" else 1
                    if pref < sample_preference:
                        sample_preference = pref
                        sample = {
                            "raw": line,
                            "flags": flags,
                            "flagged": info["flagged"],
                            "hydration": info["hydration"],
                            "pointers": info["pointers"],
                        }

        has_stubs = buckets["METADATA_ONLY_STUB"] > 0 or buckets["PARTIAL_TEXT_NO_CODE"] > 0
        display = hydration_display(file_hydration) if has_stubs else "NONE"
        dominant = "NONE"
        if has_stubs:
            dominant_counts = sorted(
                [(k, n) for k, n in file_hydration.items() if n > 0],
                key=lambda item: (-item[1], HYDRATION_PRIORITY[item[0]]),
            )
            dominant = dominant_counts[0][0]

        coverage_pct = {key: pct(value, valid_rows) for key, value in coverage_counts.items()}
        file_row = {
            "path": rel,
            "layer": layer,
            "table_role": classify_table_role(rel),
            "total_rows": valid_rows,
            "invalid_lines": invalid,
            "buckets": buckets,
            "coverage_pct": coverage_pct,
            "hydration_source": {
                "counts": file_hydration,
                "dominant": dominant,
                "display": display,
            },
            "has_stubs": has_stubs,
        }
        file_rows.append(file_row)
        if sample is not None:
            stub_rows_by_file[rel] = sample
        if has_stubs:
            stub_files.append(rel)

        total_rows += valid_rows
        total_invalid += invalid

        layer_stat = by_layer.setdefault(layer, {
            "files": 0, "rows": 0,
            "buckets": {name: 0 for name in BUCKET_NAMES},
            "coverage_pct_avg": {key: 0.0 for key in coverage_counts},
            "_cov_sum": {key: 0.0 for key in coverage_counts},
            "stub_files": [],
        })
        layer_stat["files"] += 1
        layer_stat["rows"] += valid_rows
        for name in BUCKET_NAMES:
            layer_stat["buckets"][name] += buckets[name]
        for key in coverage_counts:
            layer_stat["_cov_sum"][key] += coverage_pct[key]
        if has_stubs:
            layer_stat["stub_files"].append(rel)

    for layer_stat in by_layer.values():
        n = layer_stat["files"] or 1
        for key in layer_stat["coverage_pct_avg"]:
            layer_stat["coverage_pct_avg"][key] = round(layer_stat["_cov_sum"][key] / n, 1)
        del layer_stat["_cov_sum"]

    json_data = {
        "schema_version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "repo_root": "<repo>",
        "scan": {
            "excluded_dirs": excluded,
            "excluded_jsonl_files": excluded_count,
            "total_jsonl_files": len(file_rows),
            "total_rows": total_rows,
            "invalid_lines": total_invalid,
        },
        "definitions": {
            "buckets": {
                "METADATA_ONLY_STUB": "Explicit METADATA_ONLY/POINTER_ONLY flag, or no inline code, diff, PoC, prose >=100 chars and no formal spec.",
                "FULLY_TRAINABLE": "Inline code >=50 chars AND inline technical prose >=100 chars, with no explicit metadata flag.",
                "PARTIAL_TEXT_NO_CODE": "Has inline prose >=100 chars, PoC or formal spec text, but no inline target source code or unified diff.",
                "invalid": "Non-dict or unparseable JSON lines; counted separately and never bucketed.",
            },
            "hydration": {
                "HYDRATABLE_FROM_LOCAL_WORK": "A work/sources/ or local clone-dir path pointer exists (priority 1).",
                "HYDRATABLE_FROM_GIT_OR_GITHUB": "A GitHub URL/repo/commit/PR/issue, GHSA, CVE or 40-hex SHA pointer exists (priority 2).",
                "UNHYDRATABLE_DEAD_POINTER": "Only PDF/advisory/placeholder pointers or no pointer at all.",
                "file_summary_scope": "Per-file counts cover stub+partial rows only; the global summary covers all bucketed rows.",
            },
            "thresholds": {
                "inline_code_min_chars": 50,
                "inline_diff_min_chars": 50,
                "inline_poc_min_chars": 50,
                "inline_prose_min_chars": 100,
                "inline_formal_spec_min_chars": 50,
                "prose_min_letter_space_ratio": 0.5,
                "prose_min_alpha_words": 12,
                "known_code_container_min_code_markers": 1,
                "unknown_key_min_code_markers": 2,
            },
            "notes": [
                "Detection walks every string value recursively; known field paths are additionally recognised.",
                "code_reference_only pointer objects have no snippet and are never counted as inline code.",
                "invariants[].invariant natural-language text is only counted as a formal spec when CVL markers are present.",
                "METADATA_ONLY/POINTER_ONLY must be an exact value (or in a known flag field); the words inside input_text are not flags.",
                "Hydrated rows carry one of " + ", ".join(HYDRATED_HANDLING_VALUES)
                + " instead of METADATA_ONLY; those values are never stub markers.",
            ],
            "data_handling_values": list(HYDRATED_HANDLING_VALUES),
            "table_roles": {
                "trainable_or_benchmark": "Dataset, derived task table, split or benchmark task. Must have 0 METADATA_ONLY_STUB rows (enforced by verify_audit.py).",
                "governance_or_quarantine_ledger": "Provenance, rights, quarantine, dedup, audit or normalization bookkeeping. Stub rows retained for audit trail and dedup accounting.",
                "test_fixture": "Synthetic files under tests/fixtures/**, never training data.",
            },
        },
        "summary": {
            "files": len(file_rows),
            "rows": total_rows,
            "buckets": global_buckets,
            "hydration": global_hydration,
            "invalid_lines": total_invalid,
            "table_roles": {
                role: {
                    "files": sum(1 for f in file_rows if f["table_role"] == role),
                    "METADATA_ONLY_STUB": sum(
                        f["buckets"]["METADATA_ONLY_STUB"] for f in file_rows
                        if f["table_role"] == role),
                }
                for role in TABLE_ROLES
            },
        },
        "by_layer": dict(sorted(by_layer.items())),
        "files": file_rows,
        "stub_files": stub_files,
    }

    with json_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(json_data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    table = markdown_table(file_rows)
    with md_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Trainable vs metadata audit - console table\n\n")
        handle.write("Generated by `scripts/audit_trainable_vs_metadata.py`.\n\n")
        handle.write(table + "\n")

    with plan_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(build_hydration_plan(json_data, stub_rows_by_file, root) + "\n")

    print(table)
    print()
    print(f"Scanned {len(file_rows)} jsonl files ({excluded_count} excluded under "
          f"{', '.join(excluded)}); {total_rows} rows; {total_invalid} invalid lines; "
          f"{len(stub_files)} files contain stub/partial rows.")
    print("Buckets: " + ", ".join(f"{k}={global_buckets[k]}" for k in BUCKET_NAMES))
    return 0


if __name__ == "__main__":
    sys.exit(main())

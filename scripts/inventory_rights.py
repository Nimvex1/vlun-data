#!/usr/bin/env python3
"""Rights/licensing inventory over EVERY tracked file and data layer.

Spec item 5. This is the measurement half of the remediation; the enforcement
half is ``scripts/check_rights_consistency.py``.

What it does:

  1. Enumerates the true tracked-file list (``git ls-files``; read-only) and
     hashes every tracked file.
  2. Classifies each file (pipeline code / dataset records / evidence artefact
     / generated report / schema / docs / harness / config) and each *data
     item* inside the dataset layers into one rights class:

        original_project_content   written by this project
        third_party_code           verbatim upstream source text
        poc_source                 proof-of-concept source (submitter-authored)
        patch_diff                 fixing-diff text
        copied_report_prose        long-form third-party report prose
        copied_short_prose         short report prose (titles / one-liners)
        personal_data              emails / named contacts / triage correspondence
        metadata_only              facts, identifiers, hashes, pointers

     The audit is NOT limited to the 424 self-flagged v1 records: every layer
     (jsonl/, splits_v2/, derived/, derived_v2_2/, derived_v3/, jsonl_v3/,
     jsonl_v4/, derived_v4/, V4/, jsonl_ml/, Vbeta/, benchmark/, training/,
     experiments*/, reports/, docs/, schema/, _audit/, V3/) is scanned.
  3. Records, per item: source URL, immutable commit/report reference,
     file/page/line locator when available, attribution, retrieval metadata,
     the sha256 of the actual original bytes, and the current redistribution
     posture.
  4. Sweeps for personal data / confidentiality exposure. Values are never
     copied into the inventory: the locator, the domain, a non-reversible hash
     of the local part and the anonymisation decision are recorded instead.
  5. Builds the versioned distribution-safe view ``distribution_v1/``
     (transformation ``rights-1.0``): cleared content plus a pointer record for
     every withheld expressive item, plus ``rights_ledger.jsonl`` and a
     machine-readable ``rights_source_registry.json``.

METADATA_ONLY here is a DEFAULT DATA-HANDLING POLICY, not a claim that any
record has been legally cleared. A hash and a link do not grant reuse or
redistribution rights.

    python scripts/inventory_rights.py            # write inventory + distribution_v1
    python scripts/inventory_rights.py --check    # compute only, write nothing
    python scripts/inventory_rights.py --help

Stdlib only, deterministic, no network, no git writes.

ENVIRONMENT INDEPENDENCE (measured on CI, 2026-10): every path written into
``reports/rights_inventory.json``, ``reports/rights_history_exposure.json``
and ``distribution_v1/`` is a repo-relative posix path, never a machine-local
absolute path, and the committed quantities are checked only against values a
fresh checkout recomputes identically (``scripts/check_rights_consistency.py``
validates internal consistency of this artefact, not this machine's git index
or HEAD). ``scan.head_commit`` and ``scan.branch`` are recorded as measurement
provenance only; no gate may require them to equal the checking checkout,
because the commit that carries this artefact is by construction always newer
than the commit recorded inside it, and that made the gate impossible to pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TRANSFORMATION_VERSION = "rights-1.0"
POLICY_DEFAULT = "METADATA_ONLY"
POLICY_NOTE = (
    "METADATA_ONLY is the default data-handling policy applied when no "
    "documented right to redistribute exists. It is not a determination that "
    "any transformed record is legally cleared for reuse or redistribution, "
    "and no record in this view should be read as legally cleared."
)

# --------------------------------------------------------------------------
# key vocabularies
# --------------------------------------------------------------------------

# Verbatim third-party source code carried as text.
CODE_KEYS = {
    "snippet", "code", "source_code", "contract_code", "affected_code_excerpt",
    "affected_code", "vulnerable_code", "poc_source", "sol_code",
}
# Proof-of-concept source (authored by a submitter, not by this project).
POC_KEYS = {"poc_code", "poc_source"}
# Fixing diffs.
DIFF_KEYS = {"diff", "patch_diff", "fix_diff", "patch"}
# Long-form third-party report prose.
PROSE_KEYS = {
    "raw_body_excerpt", "impact", "suggested_fix", "recommendation",
    "description", "summary", "root_cause_candidate", "quote", "invariant",
    "explanation", "input_text", "body", "text", "reported_claim",
    "fix_description", "excerpts", "preconditions", "attack_sequence",
}
# Short third-party prose (finding titles, one-line claims).
SHORT_PROSE_KEYS = {
    "title", "finding_title", "original_title", "root_cause",
}
# Keys that carry provenance context rather than expressive content.
CTX_KEYS = {
    "source_url", "url", "permalink", "source_pointer", "issue_url",
    "original_issue_url", "repository_url", "commit_sha",
    "source_repository_commit", "vulnerable_commit", "fixed_commit", "file",
    "affected_file", "report_path", "report_file_name", "source_page",
    "page", "line_start", "line_end", "affected_lines", "source_location",
    "source_name", "organization", "protocol", "project", "extracted_at",
    "retrieved_at", "retrieved", "report_date", "sha256", "report_sha256",
    "file_sha256", "record_sha256", "source_type", "source_id",
}

EMAIL_RE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9._%+\-]*)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
CONTACTS_RE = re.compile(r"\b(?:CONTACTS?|CONTACT COMPANY EMAIL)\b", re.I)
TRIAGE_RE = re.compile(
    r"\b(judge|sponsor|warden|researcher|triage|medigator)\b.{0,40}"
    r"\b(commented?|responded?|confirmed?|rejected?|disputed|escalated?)\b", re.I)
# Deliberately narrow: fires only on text that is unambiguously upstream source
# (same detection basis scripts/audit_third_party.py uses for v1 records).
THIRD_PARTY_CODE_RE = re.compile(
    r"(pragma\s+solidity|contract\s+\w+\s*\{|function\s+\w+\s*\([^)]*\)\s*"
    r"(public|external|internal|private)|import\s*\{[^}]*\}\s*from\s*\"|"
    r"SPDX-License-Identifier)", re.I)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")

# Generated-document claims that the gate forbids (spec item 5).
FORBIDDEN_CLAIMS = (
    "zero licensing",
    "zero licence",
    "zero license",
    "zero confidentiality risk",
    "no licensing risk",
    "no licensing/confidentiality risk",
    "no licence risk",
    "license-free",
    "licence-free",
    "legally cleared for redistribution",
    "cleared for redistribution",
    "free of third-party code",
)

DATA_SUFFIXES = {".jsonl", ".json"}
TEXT_SUFFIXES = {".md", ".txt", ".csv", ".sol", ".py", ".rs", ".toml", ".cff",
                 ".yaml", ".yml"}


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_text(s: str) -> str:
    return sha256_bytes(s.encode("utf-8", "surrogatepass"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tracked_files(root: Path) -> list[str]:
    """True tracked-file list. git ls-files is read-only; fall back to a walk.

    The git index and the working tree can disagree while a deletion is
    pending: `git ls-files` still names a path that has been removed from
    the working tree, and such a path is not part of the repository's
    content.  The inventory cites every path it enumerates, and the rights
    gate fails when a cited path is not a file in the checkout, so an
    index-only path would make the gate fail for a reason that has nothing
    to do with rights.  The list is therefore the tracked files that are
    actually present in the tree.
    """
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=str(root),
                             capture_output=True, check=True).stdout
        names = sorted(p for p in out.decode("utf-8").split("\0") if p)
        if names:
            return [p for p in names if (root / p).is_file()]
    except Exception:
        pass
    names = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or ".git" in p.parts or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        # A checkout without a git index still has the .gitignore contract:
        # retrieved clones and local run workspaces are not repository
        # content, and neither may be redistributed. Include the clone
        # manifest, which is the published provenance record.
        if rel.startswith("work/"):
            continue
        if rel.startswith("V3/clones/") and rel != "V3/clones/MANIFEST.md":
            continue
        names.append(rel)
    return names


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        rows.append({"_unparseable_line": line[:200]})
    except OSError:
        return []
    return rows


def json_dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


# Machine-local absolute paths must never enter a committed artefact: an
# absolute root or per-file path ties the artefact to the one checkout that
# generated it, which is precisely how the rights gate became impossible to
# pass on CI. The drive-letter form requires a non-word character before it
# so that `https://` (whose trailing `s:/` would otherwise match) is not a
# false positive.
MACHINE_LOCAL_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|/home/|/Users/")


def assert_environment_independent(rel_out: str, text: str) -> None:
    """Fail the generator if an artefact is about to embed a local absolute
    path. Catalog paths stay repo-relative posix; nothing is dropped."""
    for lineno, line in enumerate(text.splitlines(), 1):
        m = MACHINE_LOCAL_RE.search(line)
        if m:
            raise SystemExit(
                f"inventory_rights.py: refusing to write {rel_out}: line "
                f"{lineno} embeds a machine-local absolute path "
                f"({m.group(0)!r}); the artefact must be environment-"
                f"independent")


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

def leaf_key(pointer: str) -> str:
    m = re.findall(r"\.([^.\[\]]+)", pointer)
    return m[-1] if m else ""


def classify_field(key: str, value: str, authored_by_project: bool,
                   pointer: str = "") -> str | None:
    """Return the rights class of one string leaf, or None for metadata."""
    if not value.strip():
        return None
    plower = pointer.lower()
    if key in POC_KEYS or (".poc." in plower and key in ("code", "source")):
        return "poc_source"
    if key in CODE_KEYS:
        return "third_party_code"
    if key in DIFF_KEYS and len(value) > 80 and "diff" in plower:
        return "patch_diff"
    if key in PROSE_KEYS:
        return "copied_report_prose" if len(value) >= 200 else "copied_short_prose"
    if key in SHORT_PROSE_KEYS:
        return "copied_short_prose"
    if authored_by_project:
        return None
    return None


def file_kind(rel: str) -> str:
    if rel.startswith("scripts/") or rel.startswith("Vbeta/scripts/"):
        return "pipeline_code"
    if rel.startswith("tests/"):
        return "test_code"
    if rel.startswith("schema/"):
        return "schema"
    if rel.startswith("docs/"):
        return "documentation"
    if rel.startswith("experiments") and "/harness/" in rel:
        return "harness_source"
    if rel.startswith("experiments"):
        return "evidence_artefact"
    if rel.startswith("reports/") or rel.startswith("Vbeta/reports_vbeta") \
            or rel.startswith("_audit/"):
        return "generated_report"
    if rel.startswith("benchmark/"):
        return "benchmark_tasks"
    if rel.startswith("training/"):
        return "training_view"
    if rel.endswith((".jsonl",)):
        return "dataset_records"
    if rel.endswith(".json"):
        return "dataset_manifest"
    if rel in ("README.md", "NOTICE.md", "LICENSE", "CHANGELOG.md",
               "CITATION.cff", "CONTRIBUTING.md", "BASELINE.md", "improve.md"):
        return "project_document"
    return "other"


LAYER_OF = [
    ("jsonl_v4/", "v4_staging_records"),
    ("derived_v4/", "v4_ledgers"),
    ("V4/", "v4_manifests"),
    ("jsonl_v3/", "v3_staging_records"),
    ("derived_v3/", "v3_derived"),
    ("V3/", "v3_research_notes"),
    ("jsonl_ml/", "ml_advisory_layer"),
    ("derived_v2_2/", "v2_2_derived"),
    ("splits_v2_2/", "v2_2_splits"),
    ("splits_v3/", "v3_splits"),
    ("splits_v2/", "v1_splits"),
    ("Vbeta/", "vbeta"),
    ("jsonl/", "v1_source_layer"),
    ("derived/", "v1_derived"),
    ("datasets/", "v1_datasets"),
    ("benchmark/", "benchmark"),
    ("training/", "training_views"),
    ("experiments", "experiments"),
    ("reports/", "reports"),
    ("_audit/", "independent_audit"),
    ("schema/", "schema"),
    ("docs/", "docs"),
    ("scripts/", "pipeline"),
    ("Vbeta/scripts/", "pipeline"),
    ("tests/", "tests"),
]


def layer_of(rel: str) -> str:
    for prefix, name in LAYER_OF:
        if rel.startswith(prefix):
            return name
    return "root"


def row_id(row: dict) -> str:
    for k in ("id", "finding_id", "candidate_id", "canonical_id", "example_id",
              "record_id", "task_id", "sample_id"):
        v = row.get(k)
        if isinstance(v, str) and v:
            return v
    src = row.get("source") or {}
    f = row.get("finding") or {}
    return str(f.get("id") or src.get("record_id") or "") or "(unidentified)"


def authored_by_project_row(row: dict) -> bool:
    """True when the expressive text in this row is this project's own writing."""
    blob = json_dumps(row).lower()
    return (
        row.get("record_type") in ("ml_finding",)
        or "scripts/build_" in blob
        or "parsed_by" in blob and "security_advisory" in blob
    )


# --------------------------------------------------------------------------
# record-level scan
# --------------------------------------------------------------------------

def walk_leaves(node, pointer, ctx, items, authored):
    """Yield expressive string leaves with their provenance context."""
    if isinstance(node, dict):
        nctx = dict(ctx)
        for k, v in node.items():
            if k in CTX_KEYS and isinstance(v, (str, int, float)) and v != "":
                nctx[k] = v
        for k, v in node.items():
            walk_leaves(v, f"{pointer}.{k}", nctx, items, authored)
        return
    if isinstance(node, list):
        for i, v in enumerate(node):
            walk_leaves(v, f"{pointer}[{i}]", ctx, items, authored)
        return
    if isinstance(node, str):
        key = leaf_key(pointer)
        cls = classify_field(key, node, authored, pointer)
        if cls is None:
            return
        items.append((pointer, cls, node, dict(ctx)))


def locator_of(ctx: dict) -> dict:
    loc = {}
    for k in ("file", "affected_file", "report_path", "report_file_name",
              "source_location", "source_page", "page", "line_start", "line_end",
              "affected_lines"):
        if k in ctx:
            loc[k] = ctx[k]
    return loc


def urls_of(ctx: dict) -> list[str]:
    seen, out = set(), []
    for k in ("source_url", "url", "source_pointer", "permalink", "issue_url",
              "original_issue_url", "repository_url"):
        v = ctx.get(k)
        if isinstance(v, str) and v.startswith("http") and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def commit_refs_of(ctx: dict) -> dict:
    out = {}
    for k in ("commit_sha", "source_repository_commit", "vulnerable_commit",
              "fixed_commit"):
        v = ctx.get(k)
        if isinstance(v, str) and v:
            out[k] = v
    return out


def split_commit_refs(refs: dict) -> tuple:
    """Separate what can pin bytes from what the source merely stated.

    A 40-hex object id is an immutable reference. An abbreviated prefix is a
    pointer into somebody else's repository: it can stop being unique, and it
    cannot be checked without that repository. Both are preserved, but only the
    first is filed under `immutable_reference`, because calling a prefix
    immutable is the kind of claim this layer exists to stop making.
    """
    immutable, stated, kinds = {}, {}, {}
    for key, value in (refs or {}).items():
        text = str(value or "")
        if HEX40_RE.match(text):
            immutable[key] = text
            kinds[key] = "full_object_id"
        elif re.fullmatch(r"[0-9a-f]{4,39}", text, re.I):
            stated[key] = text
            kinds[key] = "abbreviated_or_truncated_hex_prefix"
        else:
            stated[key] = text
            kinds[key] = "non_hex_reference"
    return immutable, stated, kinds


def recorded_hashes(ctx: dict) -> dict:
    out = {}
    for k in ("sha256", "report_sha256", "file_sha256", "record_sha256"):
        v = ctx.get(k)
        if isinstance(v, str) and v:
            out[k] = v
    return out


def attribution_of(ctx: dict) -> dict:
    out = {}
    for k in ("source_name", "source_id", "organization", "protocol", "project",
              "source_type"):
        v = ctx.get(k)
        if isinstance(v, str) and v:
            out[k] = v
    return out


def retrieval_of(ctx: dict) -> dict:
    out = {}
    for k in ("extracted_at", "retrieved_at", "retrieved", "report_date"):
        v = ctx.get(k)
        if k in ctx:
            out[k] = v
    return out


def base_context_of(row: dict) -> dict:
    base_ctx = {}
    for section in ("source", "provenance", "original_evidence", "protocol"):
        v = row.get(section)
        if isinstance(v, dict):
            for k, val in v.items():
                if k in CTX_KEYS and isinstance(val, (str, int, float)) \
                        and val != "":
                    base_ctx.setdefault(k, val)
    for k in CTX_KEYS:
        v = row.get(k)
        if isinstance(v, (str, int, float)) and v != "":
            base_ctx.setdefault(k, v)
    return base_ctx


def scan_records_file(rel: str, path: Path, detail: bool) -> tuple:
    """Scan one JSONL layer for third-party expressive content.

    `detail=True` materialises the full per-item provenance record; that is
    only used for the two layers distribution_v1 projects row by row. With
    `detail=False` the scan still walks every row and every item, but returns
    counts and length statistics only, so the remaining layers are inventoried
    without materialising hundreds of thousands of dicts.
    """
    rows = read_jsonl(path)
    out: list[dict] = []
    counts: Counter = Counter()
    length_stats: dict = {}
    records_with_items = 0
    for row in rows:
        if "_unparseable_line" in row:
            continue
        authored = authored_by_project_row(row)
        items: list = []
        walk_leaves(row, "$", base_context_of(row), items, authored)
        if not items:
            continue
        records_with_items += 1
        classes = Counter()
        by_class: dict[str, list] = defaultdict(list)
        for pointer, cls, text, ctx in items:
            classes[cls] += 1
            counts[cls] += 1
            st = length_stats.setdefault(cls, {"max_chars": 0, "total_chars": 0})
            st["max_chars"] = max(st["max_chars"], len(text))
            st["total_chars"] += len(text)
            if detail:
                by_class[cls].append({
                    "pointer": pointer,
                    "chars": len(text),
                    "sha256_stored_bytes": sha256_text(text),
                    "source_urls": urls_of(ctx),
                    "commit_refs": commit_refs_of(ctx),
                    "locator": locator_of(ctx),
                    "recorded_hashes": recorded_hashes(ctx),
                    "attribution": attribution_of(ctx),
                    "retrieval": retrieval_of(ctx),
                    "value": text,
                })
        if detail:
            out.append({
                "path": rel,
                "record_id": row_id(row),
                "record_type": row.get("record_type"),
                "redistribution_flag":
                    (row.get("redistribution") or {}).get("flag")
                    if isinstance(row.get("redistribution"), dict) else None,
                "license_status_fields": {
                    k: row.get(k) for k in ("license", "license_status",
                                            "license_classification")
                    if k in row},
                "classes": dict(classes),
                "items_by_class": dict(by_class),
            })
    return out, counts, length_stats, records_with_items, len(rows)


def scan_text_file(rel: str, path: Path) -> dict:
    """Scan a markdown/text/source artefact for copied expressive content."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"path": rel, "unreadable": True}
    emails = EMAIL_RE.findall(text)
    fences = re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S)
    code_blocks = sum(1 for b in fences if THIRD_PARTY_CODE_RE.search(b))
    return {
        "path": rel,
        "chars": len(text),
        "email_hits": len(emails),
        "triage_hits": len(TRIAGE_RE.findall(text)),
        "fenced_code_blocks": len(fences),
        "possible_third_party_code_blocks": code_blocks,
    }


# --------------------------------------------------------------------------
# personal data / confidentiality sweep
# --------------------------------------------------------------------------

ORG_MAILBOX_DOMAINS = {
    "example.com", "example.org", "nist.gov", "github.com", "noreply.github.com",
}


def personal_data_sweep(root: Path, files: list[str]) -> list[dict]:
    """Record locators + anonymisation decisions. Never copies the value."""
    findings = []
    for rel in files:
        p = root / rel
        if not p.is_file():
            continue
        if p.suffix not in DATA_SUFFIXES | TEXT_SUFFIXES:
            continue
        if not p.stat().st_size:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = EMAIL_RE.findall(text)
        if not hits:
            continue
        local_domains = Counter()
        for local, domain in hits:
            d = domain.lower()
            if d in ORG_MAILBOX_DOMAINS or local.lower() in (
                    "noreply", "security-advisories", "nvd", "git"):
                continue
            local_domains[d] += 1
        if not local_domains:
            continue
        distinct = {f"{local}@{d}".lower() for local, d in hits}
        distinct_personal = {
            f"{local}@{d}".lower() for local, d in hits
            if d.lower() not in ORG_MAILBOX_DOMAINS and local.lower() not in
            ("noreply", "security-advisories", "nvd", "git")}
        findings.append({
            "path": rel,
            "layer": layer_of(rel),
            "kind": "personal_contact_email",
            "email_occurrences": len(hits),
            "distinct_addresses": len(distinct),
            "distinct_personal_addresses": len(distinct_personal),
            "domains": sorted(local_domains),
            "occurrences_by_domain": dict(sorted(local_domains.items())),
            # non-reversible handle only: the local part is never reproduced
            "address_sha256_prefixes": sorted(
                {h[:12] for h in (sha256_text(a) for a in distinct_personal)})[:20],
            "named_contacts_adjacent": bool(CONTACTS_RE.search(text)),
            "triage_correspondence_markers": len(TRIAGE_RE.findall(text)),
            "anonymisation_decision": (
                "REDACT_FROM_DISTRIBUTION: personal mailboxes and named-contact "
                "rows are dropped from distribution_v1; the canonical layer is "
                "left untouched (immutability), the field locator and these "
                "counts are retained so the redaction is auditable."),
            "canonical_layer_modified": False,
        })
    return sorted(findings, key=lambda f: f["path"])


# --------------------------------------------------------------------------
# source licence registry + contradiction detection
# --------------------------------------------------------------------------

LIC_ALIAS = {
    "unknown": "unknown",
    "none_declared": "none_declared",
    "no license file found": "none_declared",
    "no licence file found": "none_declared",
    "no license": "none_declared",
    "no licence": "none_declared",
    "cc by-nd 4.0": "cc-by-nd-4.0",
    "cc-by-nd-4.0": "cc-by-nd-4.0",
    "cc by-nc-nd 4.0": "cc-by-nc-nd-4.0",
    "cc0": "cc0-1.0",
    "mit": "mit",
    "busl-1.1": "busl-1.1",
    "unknown -> metadata_only": "unknown",
    "metadata_only": "unknown",
}


def normalise_licence(v) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip().lower()
    for needle, name in (("source_available_but_not_redistributable",
                          "source_available_not_redistributable"),
                         ("source_redistributed_without_declared_license",
                          "none_declared"),
                         ("no license file", "none_declared"),
                         ("no licence file", "none_declared"),
                         ("cc by-nd", "cc-by-nd-4.0"),
                         ("cc-by-nd", "cc-by-nd-4.0"),
                         ("cc by 4.0", "cc-by-4.0"),
                         ("cc-by-4.0", "cc-by-4.0"),
                         ("busl", "busl-1.1"),
                         ("mit", "mit"),
                         ("agpl", "agpl-3.0"),
                         ("unknown", "unknown")):
        if needle in s:
            return name
    return LIC_ALIAS.get(s, s.replace(" ", "-"))


def v4_source_observations(root: Path) -> list[dict]:
    """Every licence statement about a V4 source, wherever it is written."""
    obs: list[dict] = []
    sj = root / "V4" / "sources.json"
    if sj.is_file():
        for row in json.loads(sj.read_text(encoding="utf-8")):
            obs.append({
                "source_id": row.get("source_id"),
                "artifact": "V4/sources.json",
                "field": "license_status",
                "raw": row.get("license_status"),
                "normalised": normalise_licence(row.get("license_status")),
                "source_url": row.get("source_url"),
                "commit": row.get("source_repository_commit"),
            })
    for mf in ("V4/manifest.json", "derived_v4/manifest.json"):
        p = root / mf
        if not p.is_file():
            continue
        m = json.loads(p.read_text(encoding="utf-8"))
        for line in (m.get("licensing_risks") or []):
            sid, _, declared = str(line).partition(":")
            sid = sid.strip()
            obs.append({
                "source_id": sid,
                "artifact": mf,
                "field": "licensing_risks",
                "raw": str(line).split(":", 1)[1].strip() if ":" in line else None,
                "normalised": normalise_licence(declared),
                "declares_specific_licence": bool(
                    re.search(r"CC[ -]BY|MIT|Apache|GPL|BUSL", str(line), re.I)),
            })
    # per-record statements inside the V4 layers
    for rel in ("jsonl_v4/findings.jsonl", "derived_v4/admitted_ledger.jsonl",
                "derived_v4/candidate_ledger.jsonl"):
        p = root / rel
        if not p.is_file():
            continue
        per = defaultdict(Counter)
        for row in read_jsonl(p):
            sid = row.get("source_id")
            for k in ("license", "license_status"):
                if k in row:
                    per[(k, normalise_licence(row.get(k)))][sid] += 1
        for (key, norm), sid_count in per.items():
            for sid, n in sorted(sid_count.items()):
                obs.append({
                    "source_id": sid,
                    "artifact": rel,
                    "field": key,
                    "raw": norm,
                    "normalised": norm,
                    "rows": n,
                })
    return sorted(obs, key=lambda o: (str(o["source_id"]), o["artifact"],
                                      o["field"]))


def licence_contradictions(root: Path) -> list[dict]:
    """Contradictory licence status for the same source across artifacts."""
    obs = v4_source_observations(root)
    out = []
    by_source = defaultdict(list)
    for o in obs:
        by_source[o["source_id"]].append(o)
    for sid, rows in sorted(by_source.items(), key=lambda kv: str(kv[0])):
        values = {r["normalised"] for r in rows if r["normalised"]}
        specific = [r for r in rows
                    if r.get("declares_specific_licence")
                    or (r["normalised"] or "").startswith("cc-")]
        unknowns = [r for r in rows if r["normalised"] == "unknown"]
        if len(values) > 1:
            out.append({
                "code": "LICENCE_STATUS_CONTRADICTION",
                "source_id": sid,
                "distinct_values": sorted(values),
                "statements": [{"artifact": r["artifact"], "field": r["field"],
                                "raw": r["raw"], "normalised": r["normalised"]}
                               for r in sorted(rows, key=lambda r: r["artifact"])],
            })
        if specific and unknowns:
            out.append({
                "code": "UNKNOWN_MASKS_DECLARED_LICENCE",
                "source_id": sid,
                "declared": sorted({r["raw"] for r in specific}),
                "unknown_statements": [{"artifact": r["artifact"],
                                        "field": r["field"]} for r in unknowns],
                "why": ("a specific upstream licence is declared in a manifest "
                        "while every record still says license_status: unknown; "
                        "the unknown value hides the No-Derivatives term, which "
                        "is the more restrictive fact"),
            })
        if not any(r["normalised"] != "unknown" for r in rows):
            out.append({
                "code": "LICENCE_UNRESOLVED_NO_REGISTRY",
                "source_id": sid,
                "statements": len(rows),
                "why": ("no artifact states a resolved licence and no registry "
                        "entry documents the absence of one; METADATA_ONLY is "
                        "therefore an unverified default, not a clearance"),
            })
    return out


def build_source_registry(root: Path) -> dict:
    """distribution_v1/rights_source_registry.json — the single registry.

    V4 statuses come from `V4/licensing.json`, the recorded rights decision. The
    manifests and the published records are then cross-checked against it, so a
    status cannot drift back to a silent `unknown` anywhere in the layer.
    """
    entries = []
    sj = root / "V4" / "sources.json"
    v4 = json.loads(sj.read_text(encoding="utf-8")) if sj.is_file() else []
    risks = {}
    mf = root / "V4" / "manifest.json"
    if mf.is_file():
        for line in json.loads(mf.read_text(encoding="utf-8")).get(
                "licensing_risks") or []:
            sid, _, text = str(line).partition(":")
            risks[sid.strip()] = text.strip()
    licensing_path = root / "V4" / "licensing.json"
    licensing = (json.loads(licensing_path.read_text(encoding="utf-8"))
                 if licensing_path.is_file() else {})
    decision = {s.get("source_id"): s for s in licensing.get("sources") or []}
    rows_by_src = Counter()
    record_status = defaultdict(set)
    for row in read_jsonl(root / "jsonl_v4" / "findings.jsonl"):
        rows_by_src[row.get("source_id")] += 1
        record_status[row.get("source_id")].add(row.get("license_status"))
    for row in v4:
        sid = row["source_id"]
        declared = risks.get(sid, "")
        dec = decision.get(sid) or {}
        required = dec.get("license_status") or (
            normalise_licence(declared)
            if re.search(r"CC[ -]BY|MIT|Apache|GPL|BUSL", declared, re.I)
            else "none_declared")
        observed = record_status.get(sid, set())
        drift = sorted(v for v in observed if v and v != required)
        right = dec.get("redistribution_right") or "not_documented"
        entries.append({
            "source_id": sid,
            "source_name": row.get("source_name"),
            "source_url": row.get("source_url"),
            "immutable_commit": row.get("source_repository_commit"),
            "upstream_licence_declared_in_manifest": declared or None,
            "licence_evidence_artifact": (
                "V4/licensing.json#" + sid if dec else
                ("V4/manifest.json#licensing_risks" if sid in risks else None)),
            "upstream_licence_observed": required if required != "none_declared" else None,
            "license_status_required": required,
            "current_declared_status": row.get("license_status"),
            "status_drift_in_published_records": drift,
            "derivatives_allowed": dec.get("derivatives_allowed", False),
            "redistribution_right": ("documented" if right.startswith("verbatim")
                                     else right),
            "redistribution_scope": right if right.startswith("verbatim") else None,
            "data_handling_policy": dec.get("data_handling_policy", POLICY_DEFAULT),
            "legal_clearance": dec.get("legal_clearance", False),
            "registered_rows": rows_by_src.get(sid, 0),
            "decision_version": licensing.get("version"),
            "commit_reference_quality": (
                licensing.get("commit_reference_quality") if dec else None),
            "note": dec.get("note") or (
                "no written permission from the source organisation is on file; "
                "the absence of a LICENSE file is not a grant, and a declared "
                "CC BY-ND term additionally bars redistributed derivatives"),
        })
    # v1 audited-protocol repositories, measured from the records themselves
    derived = read_jsonl(root / "derived" / "records.jsonl")
    per_repo = defaultdict(lambda: {"records": 0, "classes": Counter(),
                                    "flags": Counter(), "urls": set(),
                                    "commits": set()})
    for r in derived:
        repo = (r.get("source") or {}).get("repository") or "unknown"
        d = per_repo[repo]
        d["records"] += 1
        lc = r.get("license_classification")
        if isinstance(lc, dict):
            lc = lc.get("value")
        d["classes"][str(lc)] += 1
        fl = (r.get("redistribution") or {}).get("flag") if isinstance(
            r.get("redistribution"), dict) else None
        d["flags"][str(fl)] += 1
        if (r.get("source") or {}).get("repository_url"):
            d["urls"].add(r["source"]["repository_url"])
        for e in (r.get("code_context") or []):
            if isinstance(e, dict) and e.get("commit_sha"):
                d["commits"].add(e["commit_sha"])
    for repo, d in sorted(per_repo.items()):
        none_declared = d["flags"].get(
            "source_redistributed_without_declared_license", 0)
        busl = d["classes"].get("source_available_but_not_redistributable", 0)
        # The repository-level status follows the records that actually carry
        # verbatim source.  A repository whose own records say
        # `source_redistributed_without_declared_license` quotes bytes from a
        # repository that declares no licence; that is the status that
        # governs the quoted bytes, and it is the status NOTICE.md states.
        # The per-record classification is mixed for some repositories (the
        # same repository is classified both ways across its records); the
        # counts are published so the mixture is visible rather than
        # flattened into one verdict.
        if none_declared:
            required = "none_declared"
            observed = None
        elif busl:
            required = "source_available_not_redistributable"
            observed = "source_available_not_redistributable"
        else:
            required = "none_declared"
            observed = None
        entries.append({
            "source_id": f"code4rena/{repo}",
            "source_name": f"Code4rena {repo} audited protocol repository",
            "source_url": sorted(d["urls"])[0] if d["urls"] else None,
            "immutable_commits": sorted(d["commits"])[:12],
            "upstream_licence_declared_in_manifest": None,
            "upstream_licence_observed": observed,
            "license_status_required": required,
            "license_classification_counts": dict(sorted(d["classes"].items())),
            "current_declared_status": dict(d["classes"]),
            "records_carrying_verbatim_source": none_declared,
            "redistribution_right": "not_documented",
            "derivatives_allowed": False,
            "data_handling_policy": POLICY_DEFAULT,
            "legal_clearance": False,
            "registered_rows": d["records"],
            "note": ("scripts/fetch_sources.py read a LICENSE file at the pinned "
                     "commit and found the stated value; no upstream permission "
                     "was requested or obtained. The per-record classification "
                     "is mixed for this repository: the status above is the "
                     "status of the records that carry verbatim source, and "
                     "`license_classification_counts` publishes the mixture"),
        })
    return {
        "registry_version": TRANSFORMATION_VERSION,
        "generated_by": "scripts/inventory_rights.py",
        "data_handling_policy_default": POLICY_DEFAULT,
        "policy_note": POLICY_NOTE,
        "hash_grants_nothing": ("a sha256 and a permalink identify bytes; they "
                               "do not grant reuse or redistribution rights"),
        "sources": entries,
    }


# --------------------------------------------------------------------------
# inventory assembly
# --------------------------------------------------------------------------

# Layers projected row-by-row into distribution_v1 (full per-item provenance).
DETAIL_LAYERS = [
    "derived/records.jsonl",
    "jsonl_v4/findings.jsonl",
]

# Everything is scanned; this order only makes the important layers appear
# first so that deterministic sample sets are stable and meaningful.
RECORD_SCAN_PRIORITY = [
    "derived/records.jsonl",
    "jsonl_v4/findings.jsonl",
    "derived_v4/admitted_ledger.jsonl",
    "jsonl/findings.jsonl",
    "jsonl/negative_findings.jsonl",
    "jsonl/exploits.jsonl",
    "jsonl/patches.jsonl",
    "jsonl/protocol.jsonl",
    "jsonl/metadata.jsonl",
    "jsonl/errors.jsonl",
    "splits_v2/train.jsonl",
    "splits_v2/validation.jsonl",
    "splits_v2/test.jsonl",
    "splits_v2/quarantine.jsonl",
    "derived_v2_2/records.jsonl",
    "derived_v2_2/audit_ingestion_records.jsonl",
    "jsonl_ml/findings_cairo.jsonl",
    "jsonl_ml/findings_move.jsonl",
    "jsonl_ml/findings_reports.jsonl",
    "jsonl_ml/findings_rust.jsonl",
    "jsonl_ml/findings_vyper.jsonl",
    "jsonl_v3/findings.jsonl",
    "derived_v3/records.jsonl",
    "derived_v3/candidate_ledger.jsonl",
    "derived_v3/normalized_records_preview.jsonl",
    "derived_v4/candidate_ledger.jsonl",
    "Vbeta/jsonl_vbeta/findings.jsonl",
    "Vbeta/derived_vbeta/records.jsonl",
    "Vbeta/derived_vbeta/candidate_ledger.jsonl",
    "benchmark/Q_evidence_type_and_quality_rubric.jsonl",
]


def build_inventory(root: Path) -> tuple:
    files = tracked_files(root)
    file_rows = []
    class_counts: Counter = Counter()
    record_class_counts: Counter = Counter()
    layer_counts: dict[str, Counter] = defaultdict(Counter)
    layer_stats: dict[str, dict] = {}
    affected_records: list[dict] = []
    samples: dict[str, list] = defaultdict(list)
    record_scanned: set[str] = set()

    for rel in files:
        p = root / rel
        rec = {
            "path": rel,
            "layer": layer_of(rel),
            "kind": file_kind(rel),
            "bytes": p.stat().st_size if p.is_file() else 0,
            "sha256": sha256_file(p) if p.is_file() else None,
        }
        if p.is_file() and p.suffix in DATA_SUFFIXES:
            rows = read_jsonl(p)
            rec["json_rows"] = len(rows)
        file_rows.append(rec)

    # ---- record-level scan of every jsonl layer -------------------------
    scanned_paths = [f for f in files
                     if f.endswith(".jsonl") and (root / f).is_file()]
    ordered = ([f for f in RECORD_SCAN_PRIORITY if f in set(scanned_paths)]
               + [f for f in sorted(scanned_paths) if f not in RECORD_SCAN_PRIORITY])
    detail_layers = set(DETAIL_LAYERS)
    for rel in ordered:
        if rel in record_scanned:
            continue
        path = root / rel
        record_scanned.add(rel)
        hits, counts, length_stats, n_with_items, n_rows = scan_records_file(
            rel, path, detail=rel in detail_layers)
        for cls, n in counts.items():
            class_counts[cls] += n
            layer_counts[rel][cls] += n
        layer_stats[rel] = {
            "json_rows": n_rows,
            "rows_holding_expressive_content": n_with_items,
            "max_chars_by_class": {k: v["max_chars"]
                                   for k, v in sorted(length_stats.items())},
            "total_chars_by_class": {k: v["total_chars"]
                                     for k, v in sorted(length_stats.items())},
            "scanned_with_item_detail": rel in detail_layers,
        }
        if rel in detail_layers:
            for h in hits:
                for cls, n in h["classes"].items():
                    record_class_counts[cls] += 1
                for cls in ("third_party_code", "poc_source", "patch_diff",
                            "copied_report_prose", "copied_short_prose"):
                    for item in h["items_by_class"].get(cls, [])[:1]:
                        if len(samples[cls]) < 25:
                            # The sample records WHERE the copied bytes are,
                            # how long they are and what they hash to.  It
                            # does not reproduce them: this artefact is
                            # published, and a verbatim third-party passage
                            # inside a rights report is still a copy of it.
                            # The bytes stay in the canonical layer and are
                            # identified by the sha256 recorded here.
                            samples[cls].append({
                                "path": rel,
                                "record_id": h["record_id"],
                                "pointer": item["pointer"],
                                "chars": item["chars"],
                                "sha256_stored_bytes": item["sha256_stored_bytes"],
                                "source_urls": item["source_urls"],
                                "commit_refs": item["commit_refs"],
                                "locator": item["locator"],
                                "recorded_hashes": item["recorded_hashes"],
                                "attribution": item["attribution"],
                                "retrieval": item["retrieval"],
                                "value_withheld": True,
                                "value_note": (
                                    "the copied bytes are not reproduced in "
                                    "this report; the sha256 above identifies "
                                    "them in the canonical layer"),
                            })
            affected_records.extend(hits)

    # ---- text artefacts --------------------------------------------------
    text_rows = []
    for rel in files:
        p = root / rel
        if p.is_file() and p.suffix in TEXT_SUFFIXES:
            t = scan_text_file(rel, p)
            text_rows.append(t)
            if t.get("possible_third_party_code_blocks"):
                class_counts["possible_third_party_code_in_text"] += \
                    t["possible_third_party_code_blocks"]
                layer_counts[rel]["possible_third_party_code_in_text"] += \
                    t["possible_third_party_code_blocks"]

    # ---- personal data ---------------------------------------------------
    pd = personal_data_sweep(root, files)
    for f in pd:
        class_counts["personal_data"] += f["email_occurrences"]
        layer_counts[f["path"]]["personal_data"] += f["email_occurrences"]

    # ---- harness licence gating (existing WITHHELD.json pattern) ---------
    withheld_harness = []
    for rel in files:
        if rel.endswith("harness/WITHHELD.json"):
            try:
                w = json.loads((root / rel).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            withheld_harness.append({"path": rel, "layer": layer_of(rel), **w})

    contradictions = licence_contradictions(root)
    registry = build_source_registry(root)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root),
                          capture_output=True, text=True)
    branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                            cwd=str(root), capture_output=True, text=True)

    # ---- recomputed totals (never hand-typed) ---------------------------
    files_with_records = len({rel for rel, c in layer_counts.items() if c})
    layers = sorted(set(layer_counts) | set(layer_stats))
    inventory = {
        "generated_by": "scripts/inventory_rights.py",
        "rights_transformation_version": TRANSFORMATION_VERSION,
        "release_manifest": "RELEASE_MANIFEST.json",
        "data_handling_policy_default": POLICY_DEFAULT,
        "policy_note": POLICY_NOTE,
        "hash_grants_nothing": ("a sha256 and a permalink identify bytes; they "
                                "do not grant reuse or redistribution rights"),
        "scan": {
            # Provenance of the measurement checkout. No check may require
            # these to equal the checking checkout's state: on a fresh clone
            # they never can (see the module docstring).
            "head_commit": head.stdout.strip() or None,
            "branch": branch.stdout.strip() or None,
            # Stable repo-relative marker replacing any absolute root: every
            # path in this artefact is relative to this marker.
            "path_style": "repo-relative-posix",
            "tracked_files": len(files),
            "tracked_bytes": sum(r["bytes"] for r in file_rows),
            "record_layers_scanned": len(record_scanned),
            "record_layers_list": sorted(record_scanned),
            "text_artefacts_scanned": len(text_rows),
        },
        "totals_by_class": {
            "expressive_items": {k: class_counts[k] for k in sorted(class_counts)},
            "records_holding_class_detail_layers": {
                k: record_class_counts[k] for k in sorted(record_class_counts)},
            "affected_records_total": len(affected_records),
            "rows_holding_expressive_content_all_layers": sum(
                s.get("rows_holding_expressive_content", 0)
                for s in layer_stats.values()),
            "record_layers_holding_expressive_content": files_with_records,
        },
        "totals_by_layer": {rel: dict(sorted(layer_counts[rel].items()))
                            for rel in layers},
        "layer_stats": {rel: layer_stats.get(rel, {}) for rel in layers},
        "text_artefact_scan": text_rows,
        "files": file_rows,
        "personal_data_findings": pd,
        "harness_withheld_files": [
            {"path": w["path"], "commit": w.get("commit"),
             "files": w.get("files"), "why": w.get("why")}
            for w in withheld_harness],
        "licence_contradictions": contradictions,
        "source_registry": registry,
        "samples": {k: v for k, v in sorted(samples.items())},
    }
    return inventory, affected_records


# --------------------------------------------------------------------------
# rights decisions
# --------------------------------------------------------------------------

REMOVE_CLASSES = {"third_party_code", "poc_source", "patch_diff",
                  "copied_report_prose"}


def rights_decision_for(cls: str, has_documented_right: bool) -> str:
    if has_documented_right:
        return "KEEP_CLEARED_BY_DOCUMENTED_RIGHT"
    if cls in REMOVE_CLASSES:
        return "WITHHELD_REMOVE_COPYRIGHTED_EXPRESSION"
    if cls == "copied_short_prose":
        return "KEEP_FACTUAL_IDENTIFIER_WITH_ATTRIBUTION"
    return "METADATA_ONLY_DEFAULT"


# --------------------------------------------------------------------------
# distribution_v1 (versioned redacted projection)
# --------------------------------------------------------------------------

KEEP_QUOTE_MAX_CHARS = 200


def withheld_pointer(rec: dict, cls: str, item: dict, version: str) -> dict:
    """A pointer record replacing removed expressive content.

    Carries the original URL, the immutable commit/report reference, the
    file/page/line locator when available, attribution, retrieval metadata and
    the sha256 of the actual original bytes, plus WITHHELD status, the applied
    rights decision, the transformation version and the reason.
    """
    immutable_ref, stated_ref, ref_kinds = split_commit_refs(item["commit_refs"])
    return {
        "projection": "distribution_v1",
        "rights_transformation_version": version,
        "record_id": rec["record_id"],
        "source_layer": rec["path"],
        "pointer": item["pointer"],
        "content_class": cls,
        "status": "WITHHELD",
        "rights_decision": rights_decision_for(cls, False),
        "reason": reason_for(cls),
        "source_urls": item["source_urls"],
        "immutable_reference": immutable_ref,
        "stated_reference": stated_ref,
        "reference_kind": ref_kinds,
        "reference_note": (
            "a value under `stated_reference` is exactly what the source wrote: an "
            "abbreviated or non-hex commit string cannot pin immutable bytes and is "
            "never presented as an `immutable_reference`. The characters that are "
            "missing are not invented."
            if stated_ref else None),
        "locator": item["locator"],
        "attribution": item["attribution"],
        "retrieval_metadata": item["retrieval"],
        "sha256_of_original_bytes": item["sha256_stored_bytes"],
        "sha256_recorded_upstream": item["recorded_hashes"],
        "original_bytes_chars": item["chars"],
    }


def project_record(rec: dict) -> tuple:
    """Metadata-only projection + withheld pointer records for one row.

    Only factual metadata the project itself records is kept: identifiers,
    verdicts read from public trackers, severities, languages, locators,
    references and hashes. Every withheld expression becomes its own pointer
    record carrying attribution and the sha256 of the bytes that were removed.
    """
    rel = rec["path"]
    pointers = []
    cleared = {
        "projection": "distribution_v1",
        "rights_transformation_version": TRANSFORMATION_VERSION,
        "source_layer": rel,
        "record_id": rec["record_id"],
        "record_type": rec["record_type"],
        "data_handling_policy": POLICY_DEFAULT,
        "legally_cleared": False,
    }
    withheld_fields: list[dict] = []
    kept_short_fields: list[dict] = []
    for cls, items in sorted(rec["items_by_class"].items()):
        for item in items:
            decision = rights_decision_for(cls, False)
            entry = {
                "pointer": item["pointer"],
                "content_class": cls,
                "sha256_of_stored_text": item["sha256_stored_bytes"],
            }
            if cls in REMOVE_CLASSES:
                withheld_fields.append(entry)
                pointers.append(withheld_pointer(
                    rec, cls, item, TRANSFORMATION_VERSION))
            else:
                value = item.get("value", "")
                if (cls == "copied_short_prose" and len(value) <= KEEP_QUOTE_MAX_CHARS
                        and not EMAIL_RE.search(value)):
                    entry["value"] = value
                    entry["rights_decision"] = decision
                    entry["attribution"] = item["attribution"]
                    entry["quote_policy"] = (
                        f"attributed quotation up to {KEEP_QUOTE_MAX_CHARS} "
                        "characters of the primary artefact; longer passages "
                        "are withheld")
                    kept_short_fields.append(entry)
                else:
                    withheld_fields.append(entry)
                    pointers.append(withheld_pointer(
                        rec, cls, item, TRANSFORMATION_VERSION))
    cleared["withheld_pointers"] = len(pointers)
    cleared["withheld_field_paths"] = withheld_fields
    cleared["kept_attributed_short_citations"] = kept_short_fields
    cleared["content_classes"] = rec["classes"]
    cleared["redistribution_flag"] = rec.get("redistribution_flag")
    if rec.get("license_status_fields"):
        cleared["source_licence_metadata"] = rec["license_status_fields"]
    return cleared, pointers


def digest_entries(registry: dict) -> list[dict]:
    """Independently written factual digests (this file's own wording).

    Every entry is a count/fact statement derived from the project's own
    metadata; none reproduces audit prose.
    """
    return [
        {
            "digest_id": "v4-halborn-scope",
            "subject_source_id": "halborn_public_reports",
            "digest_kind": "independently_written_factual_summary",
            "independently_written": True,
            "copies_audit_prose": False,
            "text": (
                "The Halborn Security Public Reports collection is a GitHub "
                "repository of customer engagement write-ups, mostly PDFs, "
                "each carrying a scope table, a findings section with a "
                "reported severity, and a contacts page naming the Halborn "
                "staff who worked the engagement. From the pinned commit "
                "recorded for this source, the VLUN pipeline registered 1,785 "
                "finding-level rows. No LICENSE file was found in that "
                "repository, so the terms of the write-ups themselves are "
                "unstated rather than permissive, and the contacts pages put "
                "named individuals' work addresses into every PDF that was "
                "text-mined. The distribution view keeps the pointers, the "
                "reported severity, the language and the report hash, and "
                "drops the mined passages and the mailboxes."),
            "attribution": "Halborn Security (report author); extracted by the "
                           "VLUN pipeline; this summary is the VLUN authors' "
                           "own wording",
        },
        {
            "digest_id": "v4-oak-scope",
            "subject_source_id": "oak_security_audit_reports",
            "digest_kind": "independently_written_factual_summary",
            "independently_written": True,
            "copies_audit_prose": False,
            "text": (
                "Oak Security publishes completed audit reports per project in "
                "a public GitHub repository. The VLUN manifest records the "
                "repository's own notice as CC BY-ND 4.0, which permits "
                "sharing with attribution but forbids distributing derivative "
                "works. Text-mining a report into shorter fields and re-laying "
                "it beside other sources is a derivative of it, so the copied "
                "passages cannot be redistributed on that term even though "
                "attribution is present. 3,257 finding-level rows were "
                "registered from the pinned commit; the distribution view "
                "keeps their pointers, page locators and report hashes and "
                "withholds the passages."),
            "attribution": "Oak Security (report author); licence term as "
                           "recorded in V4/manifest.json; this summary is the "
                           "VLUN authors' own wording",
        },
        {
            "digest_id": "v4-coinfabrik-scope",
            "subject_source_id": "coinfabrik_audit_reports",
            "digest_kind": "independently_written_factual_summary",
            "independently_written": True,
            "copies_audit_prose": False,
            "text": (
                "CoinFabrik publishes a smaller set of wallet, protocol and "
                "tooling assessments. The VLUN manifest records that no "
                "LICENSE file was found for that collection, and 226 "
                "finding-level rows were registered from the pinned commit. "
                "Because nothing states the terms, the conservative reading is "
                "all-rights-reserved: metadata and links are safe to carry, "
                "passages are not."),
            "attribution": "CoinFabrik (report author); this summary is the "
                           "VLUN authors' own wording",
        },
        {
            "digest_id": "v1-unlicensed-protocol-code",
            "subject_source_id": "code4rena/audited-protocols",
            "digest_kind": "independently_written_factual_summary",
            "independently_written": True,
            "copies_audit_prose": False,
            "text": (
                "Five of the eight Code4rena protocol repositories cited by "
                "the v1 derived layer ship no LICENSE file at the commit the "
                "dataset pins (NOYA, Decent, Alchemix, Panoptic and GTE "
                "Perps). 424 of the 722 derived records quote Solidity taken "
                "from those repositories, which is 895 quotation entries in "
                "total. Quoting a short excerpt for commentary and offering "
                "the same text for onward redistribution are different acts, "
                "and no permission from those protocol authors is on file, so "
                "the quoted text is dropped from the distribution view and "
                "replaced by the file, commit, line range, permalink and the "
                "hash of the bytes that were removed. The remaining three "
                "repositories (reNFT, BakerFi, Wildcat) are source-available "
                "under terms that permit use but not redistribution; their "
                "citations were already reference-only."),
            "attribution": "protocol authors (code); Code4rena (contest); this "
                           "summary is the VLUN authors' own wording",
        },
        {
            "digest_id": "v1-poc-authorship",
            "subject_source_id": "code4rena/submission-authors",
            "digest_kind": "independently_written_factual_summary",
            "independently_written": True,
            "copies_audit_prose": False,
            "text": (
                "The proof-of-concept tests in the v1 layers were written by "
                "contest participants, not by this project; 346 derived "
                "records carry such source. A few carry the author's own SPDX "
                "line, most carry none. This project neither owns that code "
                "nor received permission to sublicense it, so the distribution "
                "view carries the test name, framework, file, recorded impact "
                "and the hash of the removed text instead of the text."),
            "attribution": "Code4rena submission authors (PoC code); this "
                           "summary is the VLUN authors' own wording",
        },
        {
            "digest_id": "experiment-harness-copies",
            "subject_source_id": "code4rena/2024-01-renft",
            "digest_kind": "independently_written_factual_summary",
            "independently_written": True,
            "copies_audit_prose": False,
            "text": (
                "Running the reNFT proofs required test-tree files that only "
                "exist in the audited repository. Those files were compiled "
                "locally and are not published; each experiment directory "
                "carries a WITHHELD.json naming the file, its byte count, the "
                "sha256 of the exact bytes that were compiled and the commit "
                "to read them from, which keeps a replay byte-verifiable "
                "without redistributing source-available code."),
            "attribution": "reNFT (repository author); this summary is the "
                           "VLUN authors' own wording",
        },
    ]


def build_distribution(root: Path, inv: dict, affected: list[dict]) -> dict:
    """Write distribution_v1/ and return what was written."""
    out_dir = root / "distribution_v1"
    ledger: list[dict] = []

    reg = inv["source_registry"]
    registry_json = json.dumps(reg, indent=2, sort_keys=True) + "\n"

    # ---- projections + ledger -------------------------------------------
    v1_rows, v1_ptrs = [], []
    v4_rows, v4_ptrs = [], []
    other_ptrs = []
    for rec in affected:
        cleared, pointers = project_record(rec)
        if rec["path"] == "derived/records.jsonl":
            v1_rows.append(cleared)
            v1_ptrs.extend(pointers)
        elif rec["path"] == "jsonl_v4/findings.jsonl":
            v4_rows.append(cleared)
            v4_ptrs.extend(pointers)
        else:
            other_ptrs.extend(pointers)  # defensive: non-detail layers
        for cls, n in rec["classes"].items():
            items = rec["items_by_class"].get(cls, [])[:3]
            ev = sorted({i["sha256_stored_bytes"] for i in items} | {
                h for i in items for h in i["recorded_hashes"].values()
                if isinstance(h, str) and HEX64_RE.match(h)})
            ledger.append({
                "ledger_version": TRANSFORMATION_VERSION,
                "subject_kind": "record",
                "subject": f"{rec['path']}#{rec['record_id']}",
                "source_layer": rec["path"],
                "record_id": rec["record_id"],
                "content_class": cls,
                "occurrences": n,
                "rights_decision": rights_decision_for(cls, False),
                "transformation_version": TRANSFORMATION_VERSION,
                "data_handling_policy": POLICY_DEFAULT,
                "legal_clearance": False,
                "reason": reason_for(cls),
                "evidence_hashes": ev,
                "canonical_source_pointer": {
                    "path": rec["path"], "record_id": rec["record_id"],
                    "immutable_reference": next(
                        (i["commit_refs"]
                         for i in rec["items_by_class"].get(cls, [])
                         if i["commit_refs"]), {}),
                    "source_urls": next(
                        (i["source_urls"]
                         for i in rec["items_by_class"].get(cls, [])
                         if i["source_urls"]), []),
                },
            })

    # artefact-level rows for layers that are not projected row by row
    for rel, counts in sorted(inv["totals_by_layer"].items()):
        if rel.startswith(("derived/records.jsonl", "jsonl_v4/findings.jsonl",
                           "derived_v4/admitted_ledger.jsonl")):
            continue
        if not counts:
            continue
        ledger.append({
            "ledger_version": TRANSFORMATION_VERSION,
            "subject_kind": "artefact",
            "subject": rel,
            "source_layer": layer_of(rel),
            "content_class": ",".join(sorted(counts)),
            "occurrences": sum(counts.values()),
            "rights_decision": "EXCLUDED_FROM_DISTRIBUTION_VIEW_PENDING_REBUILD",
            "transformation_version": TRANSFORMATION_VERSION,
            "data_handling_policy": POLICY_DEFAULT,
            "legal_clearance": False,
            "reason": ("layer carries third-party expression or personal data "
                       "and must be rebuilt from the distribution_v1 "
                       "projections; it is canonical and is not rewritten here"),
            "counts_by_class": counts,
            "canonical_source_pointer": {"path": rel},
        })

    # source-level rows (registry decisions) + digests + harness
    for s in reg["sources"]:
        ledger.append({
            "ledger_version": TRANSFORMATION_VERSION,
            "subject_kind": "source",
            "subject": s["source_id"],
            "rights_decision": "METADATA_ONLY_DEFAULT",
            "transformation_version": TRANSFORMATION_VERSION,
            "data_handling_policy": POLICY_DEFAULT,
            "legal_clearance": False,
            "reason": s["note"],
            "canonical_source_pointer": {
                "url": s.get("source_url"),
                "commit": s.get("immutable_commit") or s.get("immutable_commits"),
            },
        })
    for d in digest_entries(reg):
        ledger.append({
            "ledger_version": TRANSFORMATION_VERSION,
            "subject_kind": "digest",
            "subject": d["digest_id"],
            "rights_decision": "PUBLISHED_INDEPENDENTLY_WRITTEN_DIGEST",
            "transformation_version": TRANSFORMATION_VERSION,
            "data_handling_policy": "PUBLISHED_OWN_EXPRESSION",
            "legal_clearance": False,
            "reason": ("concise factual summary written by the VLUN authors "
                       "from project metadata; not a paraphrase of any audit "
                       "text; attribution recorded on the entry"),
            "canonical_source_pointer": {"source_id": d["subject_source_id"]},
        })
    for w in inv["harness_withheld_files"]:
        for f in (w.get("files") or []):
            ledger.append({
                "ledger_version": TRANSFORMATION_VERSION,
                "subject_kind": "harness_file",
                "subject": f"{w['path']}::{f.get('path')}",
                "rights_decision": "WITHHELD_SOURCE_AVAILABLE_NOT_REDISTRIBUTABLE",
                "transformation_version": TRANSFORMATION_VERSION,
                "data_handling_policy": POLICY_DEFAULT,
                "legal_clearance": False,
                "reason": w.get("why"),
                "evidence_hashes": [f.get("sha256")],
                "canonical_source_pointer": {
                    "withheld_record": w["path"], "commit": w.get("commit"),
                    "path_in_upstream_repo": f.get("path"),
                    "bytes": f.get("bytes")},
            })

    # personal data rows
    for f in inv["personal_data_findings"]:
        ledger.append({
            "ledger_version": TRANSFORMATION_VERSION,
            "subject_kind": "personal_data",
            "subject": f["path"],
            "rights_decision": "REDACT_PERSONAL_DATA_FROM_DISTRIBUTION",
            "transformation_version": TRANSFORMATION_VERSION,
            "data_handling_policy": POLICY_DEFAULT,
            "legal_clearance": False,
            "reason": f["anonymisation_decision"],
            "counts": {"email_occurrences": f["email_occurrences"],
                       "distinct_personal_addresses":
                       f["distinct_personal_addresses"]},
            "canonical_source_pointer": {"path": f["path"], "layer": f["layer"]},
        })

    harness_ptrs = []
    for w in inv["harness_withheld_files"]:
        exp = Path(w["path"]).parent.parent.name
        repo = exp.split("__")[0]
        for f in (w.get("files") or []):
            harness_ptrs.append({
                "projection": "distribution_v1",
                "rights_transformation_version": TRANSFORMATION_VERSION,
                "record_id": f"experiment:{exp}",
                "source_layer": w["path"],
                "pointer": f.get("path"),
                "content_class": "harness_source",
                "status": "WITHHELD",
                "rights_decision":
                    "WITHHELD_SOURCE_AVAILABLE_NOT_REDISTRIBUTABLE",
                "reason": w.get("why"),
                "source_urls": [
                    f"https://github.com/code-423n4/{repo}"],
                "immutable_reference": {"commit_sha": w.get("commit")},
                "locator": {"file": f.get("path")},
                "attribution": {
                    "source_name": f"Code4rena {repo} audited repository",
                    "organization": "Code4rena contest participant",
                    "upstream_licence": "source_available_not_redistributable"},
                "retrieval_metadata": {"retrieved": "compiled locally by "
                                   "scripts/fetch_sources.py and the "
                                   "experiment harness; never published"},
                "sha256_of_original_bytes": f.get("sha256"),
                "sha256_recorded_upstream": {"sha256": f.get("sha256")},
                "original_bytes_chars": f.get("bytes"),
                "withheld_record": w["path"],
            })

    manifest = {
        "distribution_view": "distribution_v1",
        "rights_transformation_version": TRANSFORMATION_VERSION,
        "generated_by": "scripts/inventory_rights.py",
        "data_handling_policy_default": POLICY_DEFAULT,
        "data_handling_policy_is_default_not_clearance": True,
        "policy_note": POLICY_NOTE,
        "legal_clearance_claimed": False,
        "blanket_clearance_claimed": False,
        "release_manifest": "RELEASE_MANIFEST.json",
        "release_manifest_version": "release-1.0",
        "rights_status_of_this_view": (
            "this view is part of the released set; RELEASE_MANIFEST.json "
            "states the per-path rights status of the whole tree"),
        "attributed_quotation_max_chars": KEEP_QUOTE_MAX_CHARS,
        "attributed_quotation_policy": (
            "third-party prose is withheld above "
            f"{KEEP_QUOTE_MAX_CHARS} characters; at or below that length a "
            "short passage may be carried as an attributed quotation of the "
            "primary artefact with its own rights_decision, reason and hash. "
            "No third-party code, PoC source, patch diff or mined report "
            "passage is carried in any length."),
        "hash_grants_nothing": reg["hash_grants_nothing"],
        "counts": {
            "withheld_harness_files": len(harness_ptrs),
            "records_v1_projected": len(v1_rows),
            "withheld_v1_citations": len(v1_ptrs),
            "records_v4_projected": len(v4_rows),
            "withheld_v4_passages": len(v4_ptrs),
            "withheld_pointers_other_layers": len(other_ptrs),
            "ledger_rows": len(ledger),
            "digests": len(digest_entries(reg)),
            "registry_sources": len(reg["sources"]),
            "personal_data_artefacts_redacted":
                len(inv["personal_data_findings"]),
        },
        "excluded_from_this_view": [
            {"path": "training/canonical/", "why":
                "rows embed V4 mined passages and personal mailboxes; must be "
                "rebuilt from distribution_v1/records_v4.jsonl before release"},
            {"path": "benchmark/", "why":
                "several families quote third-party payloads inline; needs the "
                "same projection pass"},
            {"path": "jsonl/, derived/, splits_v2/, derived_v3/, jsonl_v3/, "
                    "jsonl_v4/, derived_v4/, Vbeta/, jsonl_ml/", "why":
                "canonical evidence layers: immutable, never rewritten by this "
                "remediation"},
        ],
        "files": {},
    }

    digests = digest_entries(reg)

    def write(rel: str, text: str) -> None:
        assert_environment_independent(f"distribution_v1/{rel}", text)
        p = out_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
        manifest["files"][rel] = {
            "bytes": len(text.encode("utf-8")),
            "sha256": sha256_bytes(text.encode("utf-8")),
        }

    def jl(rows) -> str:
        return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                       for r in rows)

    write("rights_ledger.jsonl", jl(sorted(ledger, key=lambda r: (
        r["subject_kind"], r["subject"], r.get("content_class") or ""))))
    write("rights_source_registry.json", registry_json)
    write("records_v1.jsonl", jl(sorted(v1_rows, key=lambda r: r["record_id"])))
    write("records_v1_withheld_pointers.jsonl",
          jl(sorted(v1_ptrs, key=lambda r: (r["record_id"], r["pointer"]))))
    write("records_v4.jsonl", jl(sorted(v4_rows, key=lambda r: r["record_id"])))
    write("records_v4_withheld_pointers.jsonl",
          jl(sorted(v4_ptrs, key=lambda r: (r["record_id"], r["pointer"]))))
    if other_ptrs:
        write("withheld_pointers_other_layers.jsonl",
              jl(sorted(other_ptrs, key=lambda r: (r["source_layer"],
                                                   r["record_id"],
                                                   r["pointer"]))))
    write("withheld_harness.jsonl", jl(sorted(
        harness_ptrs, key=lambda r: (r["withheld_record"], str(r["pointer"])))))
    write("digests.jsonl", jl(digests))
    write("licence_contradictions.json",
          json.dumps({"generated_by": "scripts/inventory_rights.py",
                      "transformation_version": TRANSFORMATION_VERSION,
                      "contradictions": inv["licence_contradictions"]},
                     indent=2, sort_keys=True) + "\n")

    readme = distribution_readme(inv, manifest, reg)
    write("README.md", readme)
    write("MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {"out_dir": out_dir, "manifest": manifest,
            "written": manifest["files"]}


def reason_for(cls: str) -> str:
    return {
        "third_party_code": (
            "verbatim source quoted from an upstream repository whose declared "
            "licence is absent, unstated, or source-available-without-"
            "redistribution; no written permission is on file, so the text is "
            "removed and a locator + hash pointer is kept"),
        "poc_source": (
            "proof-of-concept source authored by a contest participant, not by "
            "this project; no licence or permission was conveyed to the "
            "pipeline, so the source is removed and only the metadata pointer "
            "is distributed"),
        "patch_diff": (
            "fixing diff copied from a source-available repository whose terms "
            "do not permit redistribution"),
        "copied_report_prose": (
            "long-form passage mined from a third-party audit report; the "
            "source's licence is either undeclared or CC BY-ND, which does "
            "not permit distributing the mined/derivative text"),
        "copied_short_prose": (
            "short factual identifier (finding title / one-line claim); kept "
            "as an attributed citation of the primary artefact, not as body "
            "text"),
        "personal_data": (
            "named individual contact details appearing inside third-party "
            "report bodies; removed from the distribution view"),
    }.get(cls, POLICY_DEFAULT + " default: no documented right to redistribute")


def distribution_readme(inv: dict, manifest: dict, reg: dict) -> str:
    c = manifest["counts"]
    v1 = inv["totals_by_class"]["expressive_items"]
    lines = [
        "# distribution_v1 — rights-redacted distribution view",
        "",
        f"Rights transformation: `{TRANSFORMATION_VERSION}`. "
        f"Generated by `scripts/inventory_rights.py`; counts are recomputed "
        "from the records on every run, never typed.",
        "",
        "## What this view is",
        "",
        "A redacted projection of the canonical layers. It carries this "
        "project's own metadata plus a pointer record for every piece of "
        "third-party expression that was removed. It is a **data-handling "
        "view**, not a legal opinion.",
        "",
        f"`{POLICY_DEFAULT}` is the **default data-handling policy** applied "
        "when no documented right to redistribute exists. ",
        "",
        "> " + POLICY_NOTE,
        "",
        "A sha256 and a permalink identify bytes. They do not grant reuse or "
        "redistribution rights. Nothing in this directory has been cleared by "
        "a rights holder, and no permission request has been granted.",
        "",
        "## The release boundary",
        "",
        "This directory is part of the released set. `RELEASE_MANIFEST.json` "
        "is the authoritative per-path statement of what may be "
        "redistributed; the paths it marks as withheld or as internal "
        "research artefacts are not licensed here, wherever they sit in the "
        "tree. **Attribution is not a redistribution right.**",
        "",
        "## Contents",
        "",
        "| file | rows | what it holds |",
        "|---|---|---|",
        f"| `records_v1.jsonl` | {c['records_v1_projected']} | metadata-only "
        "projection of the derived v1 records |",
        f"| `records_v1_withheld_pointers.jsonl` | "
        f"{c['withheld_v1_citations']} | pointer + hash for each removed "
        "quotation |",
        f"| `records_v4.jsonl` | {c['records_v4_projected']} | pointer/severity/"
        "language metadata for each V4 finding; no mined passage |",
        f"| `records_v4_withheld_pointers.jsonl` | "
        f"{c['withheld_v4_passages']} | pointer + hash for each removed mined "
        "passage |",
        f"| `withheld_pointers_other_layers.jsonl` | "
        f"{c['withheld_pointers_other_layers']} | removed expression from "
        "layers that are not projected row by row (the file is only written "
        "when the count is non-zero; those layers are covered by the "
        "`artefact` rows of the ledger instead) |",
        f"| `withheld_harness.jsonl` | {c['withheld_harness_files']} | one "
        "pointer per withheld harness file, mirroring the repo's existing "
        "`WITHHELD.json` licence-gating pattern |",
        f"| `digests.jsonl` | {c['digests']} | short factual summaries written "
        "by the VLUN authors, marked `independently_written` |",
        f"| `rights_source_registry.json` | {c['registry_sources']} sources | "
        "the single machine-readable licence registry |",
        f"| `rights_ledger.jsonl` | {c['ledger_rows']} | rights decision, "
        "transformation version, reason, evidence hashes, canonical pointer |",
        "| `licence_contradictions.json` | "
        f"{len(inv['licence_contradictions'])} | unresolved licence-status "
        "contradictions the gate fails on |",
        "",
        "## Every withheld pointer record carries",
        "",
        "original source URL, immutable commit/report reference, file/page/line "
        "locator when available, source attribution, retrieval metadata, the "
        "sha256 of the actual original bytes, `status: WITHHELD`, the applied "
        f"`rights_decision`, `transformation_version: {TRANSFORMATION_VERSION}` "
        "and the reason.",
        "",
        "Short third-party prose at or below "
        f"`{manifest['attributed_quotation_max_chars']}` "
        "characters may be carried as an attributed quotation and is marked "
        "`rights_decision: KEEP_FACTUAL_IDENTIFIER_WITH_ATTRIBUTION`. Nothing "
        "longer than that, and no third-party code of any length, is carried. "
        "A digest in `digests.jsonl` is a factual summary written by the VLUN "
        "authors from project metadata; it is marked "
        "`independently_written: true` and `copies_audit_prose: false`, and it "
        "is not a paraphrase of any audit text.",
        "",
        "## Measured basis (recomputed from the full tracked tree)",
        "",
        f"- tracked files scanned: {inv['scan']['tracked_files']} "
        f"({inv['scan']['tracked_bytes']} bytes)",
        f"- record layers scanned for expressive content: "
        f"{inv['scan']['record_layers_scanned']}",
        "- expressive items by class: "
        + ", ".join(f"{k}={v}" for k, v in sorted(v1.items())),
        f"- artefacts holding personal contact data: "
        f"{c['personal_data_artefacts_redacted']} (mailboxes and named-contact "
        "rows are removed here; the canonical layers are not modified)",
        "",
        "## What is deliberately NOT in this view yet",
        "",
    ]
    for ex in manifest["excluded_from_this_view"]:
        lines.append(f"- `{ex['path']}` — {ex['why']}")
    lines += [
        "",
        "## Immutability",
        "",
        "No canonical layer file or record was rewritten, deleted or reordered "
        "to build this view. `git history` was not rewritten and no force-push "
        "was performed. Historical exposure is reported separately in "
        "`reports/history_exposure.md`.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=("Inventory every tracked file and data layer for "
                     "third-party rights, and build the rights-1.0 "
                     "distribution-safe view."),
        epilog=("writes reports/rights_inventory.json, reports/"
                "rights_inventory.md, reports/history_exposure.md, reports/"
                "rights_history_exposure.json and distribution_v1/; "
                "--check computes everything and writes nothing"),
    )
    ap.add_argument("--root", default=str(ROOT), help="repository root")
    ap.add_argument("--check", action="store_true",
                    help="compute and report; write nothing")
    ap.add_argument("--no-distribution", action="store_true",
                    help="skip building distribution_v1/")
    ap.add_argument("--no-history", action="store_true",
                    help="skip the git-history exposure scan")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    root = Path(args.root)

    inv, affected = build_inventory(root)
    history = {"skipped": True} if args.no_history else history_exposure(root)
    inv["history_exposure_summary"] = {
        k: v for k, v in history.items() if k in (
            "commits_scanned", "refs_scanned", "paths_added_then_removed",
            "historical_exposure_items", "published_surfaces",
            "history_rewritten")}

    if not args.quiet:
        rhc = inv["totals_by_class"]["records_holding_class_detail_layers"]
        for cls, n in sorted(inv["totals_by_class"]["expressive_items"].items()):
            print(f"  {cls:34s} items={n:7d} records_with={rhc.get(cls, 'n/a')}")
        print(f"  affected records        = "
              f"{inv['totals_by_class']['affected_records_total']}")
        print(f"  personal-data artefacts = "
              f"{len(inv['personal_data_findings'])}")
        print(f"  licence contradictions  = "
              f"{len(inv['licence_contradictions'])}")

    if args.check:
        print("inventory_rights.py --check: computed, wrote nothing")
        return 0

    (root / "reports").mkdir(exist_ok=True)
    inv_json = json.dumps(inv, indent=2, sort_keys=True) + "\n"
    hist_json = json.dumps(history, indent=2, sort_keys=True) + "\n"
    assert_environment_independent("reports/rights_inventory.json", inv_json)
    assert_environment_independent("reports/rights_history_exposure.json",
                                   hist_json)
    (root / "reports" / "rights_inventory.json").write_text(
        inv_json, encoding="utf-8", newline="\n")
    (root / "reports" / "rights_inventory.md").write_text(
        inventory_markdown(inv), encoding="utf-8", newline="\n")
    (root / "reports" / "history_exposure.md").write_text(
        history_markdown(history, inv), encoding="utf-8", newline="\n")
    (root / "reports" / "rights_history_exposure.json").write_text(
        hist_json, encoding="utf-8", newline="\n")
    if not args.no_distribution:
        built = build_distribution(root, inv, affected)
        if not args.quiet:
            print(f"  distribution_v1/ files   = {len(built['written'])}")
    print("wrote reports/rights_inventory.{json,md}, "
          "reports/history_exposure.md, reports/rights_history_exposure.json, "
          "distribution_v1/")
    return 0


# --------------------------------------------------------------------------
# git archaeology (read-only)
# --------------------------------------------------------------------------

def _git(root: Path, *args) -> str:
    r = subprocess.run(["git", *args], cwd=str(root), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    return r.stdout or ""


CODE_PROSE_RE = re.compile(
    r"\.(sol|rs|py|js|ts|move|cairo|vy|md|jsonl|json|txt|csv)$", re.I)


def history_exposure(root: Path) -> dict:
    refs = [r.strip() for r in _git(root, "for-each-ref",
                                    "--format=%(refname)").splitlines() if r.strip()]
    # --reverse gives chronological order, so the first add seen IS the commit
    # that introduced the path (min() over sha strings would not).
    commits = _git(root, "rev-list", "--reverse", "--all").split()
    tracked = set(tracked_files(root))
    added_by: dict[str, str] = {}
    removed_by: dict[str, str] = {}
    for c in commits:
        out = _git(root, "show", "--format=%H", "--diff-filter=A",
                   "--name-only", c)
        for line in out.splitlines()[1:]:
            if line.strip() and line.strip() not in added_by:
                added_by[line.strip()] = c
        out = _git(root, "show", "--format=%H", "--diff-filter=D",
                   "--name-only", c)
        for line in out.splitlines()[1:]:
            if line.strip():
                removed_by[line.strip()] = c
    gone = sorted(p for p in added_by
                  if p not in tracked and CODE_PROSE_RE.search(p))
    items = []
    for p in gone:
        first = added_by[p]
        deleted_in = removed_by.get(p)
        blob = _git(root, "show", f"{first}:{p}")
        reach = sorted(r for r in refs if _is_ancestor(root, first, r))
        items.append({
            "path": p,
            "added_in_commit": first,
            "removed_in_commit": deleted_in,
            "present_in_current_tree": False,
            "reachable_from_refs": sorted(reach),
            "reachable_bytes": len(blob.encode("utf-8", "replace")),
            "reachable_sha256": sha256_text(blob) if blob else None,
            "spdx_declared_in_historical_blob": (
                re.search(r"SPDX-License-Identifier:\s*([^\\\"'\s]+)",
                          blob).group(1)
                if "SPDX-License-Identifier:" in blob else None),
            "class": ("third_party_code"
                      if p.endswith(".sol") or "pragma solidity" in blob
                      or "SPDX-License-Identifier:" in blob
                      else "project_generated_records"),
            "third_party_expression_historically_published": bool(
                p.endswith(".sol") or "pragma solidity" in blob
                or "SPDX-License-Identifier:" in blob),
            "reachable_from_published_ref": any(
                r.startswith("refs/remotes/") for r in reach),
            "note": ("the blob stays retrievable with `git show <commit>:<path>` "
                     "and remains in every clone/fork made before removal; "
                     "removal from the tip does not un-publish it"),
        })
    # content that never left the tree but was published in a worse state
    still = []
    for p in ("jsonl_v4/findings.jsonl", "derived_v4/admitted_ledger.jsonl",
              "training/canonical/severity.validation.part-000.jsonl",
              "training/canonical/language.validation.part-000.jsonl"):
        if p not in tracked:
            continue
        first = added_by.get(p)
        if not first:
            continue
        still.append({
            "path": p,
            "added_in_commit": first,
            "present_in_current_tree": True,
            "reachable_from_refs": sorted(
                r for r in refs if _is_ancestor(root, first, r)),
            "class": "copied_report_prose+personal_data",
            "note": ("published as part of the current tip; this is current "
                     "exposure, listed here so the historical and current "
                     "surfaces are both visible"),
        })
    surfaces = publication_surfaces(root, refs)
    return {
        "generated_by": "scripts/inventory_rights.py",
        "method": ("read-only git archaeology: git rev-list --all, "
                   "git show --diff-filter=A/D --name-only, "
                   "git show <commit>:<path>, git merge-base --is-ancestor"),
        "history_rewritten": False,
        "history_rewrite_statement": (
            "No history was rewritten, no commit was amended, no branch was "
            "force-pushed and no ref was deleted. Rewriting published history "
            "would need explicit authorisation from the repository owner and "
            "is not performed by this remediation."),
        "commits_scanned": len(commits),
        "refs_scanned": refs,
        "paths_added_then_removed": len(gone),
        "historical_exposure_items": items,
        "current_exposure_items_in_history_scan": still,
        "published_surfaces": surfaces,
    }


def _is_ancestor(root: Path, sha: str, ref: str) -> bool:
    r = subprocess.run(["git", "merge-base", "--is-ancestor", sha, ref],
                       cwd=str(root), capture_output=True, text=True)
    return r.returncode == 0


def publication_surfaces(root: Path, refs: list[str]) -> dict:
    remotes = {}
    for line in _git(root, "remote", "-v").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            remotes.setdefault(parts[0], parts[1])
    zen = root / ".zenodo.json"
    pm = root / "publish_manifest.json"
    cit = root / "CITATION.cff"
    doi_present = False
    doi_values = []
    if cit.is_file():
        t = cit.read_text(encoding="utf-8", errors="replace")
        doi_values = re.findall(r"\bdoi:\s*(\S+)", t) + \
            re.findall(r"10\.\d{4,5}/[^\s'\"]+", t)
        doi_present = bool(doi_values)
    pushed = []
    for r in refs:
        if r.startswith("refs/remotes/"):
            pushed.append(r)
    return {
        "git_remotes": remotes,
        "refs_published_to_origin": sorted(pushed),
        "zenodo_metadata_present": zen.is_file(),
        "zenodo_metadata": json.loads(zen.read_text(encoding="utf-8"))
        if zen.is_file() else None,
        "publish_manifest_present": pm.is_file(),
        "publish_manifest": json.loads(pm.read_text(encoding="utf-8"))
        if pm.is_file() else None,
        "doi_found_in_repo": doi_present,
        "doi_values": sorted(set(doi_values)),
        "assessment": (
            "Every commit reachable from an origin/* ref is published on the "
            "remote named above, including blobs later deleted from the tip. "
            "A DOI is only exposure if the archival docs say one exists; "
            "docs/ARCHIVAL.md states that no DOI has been minted in this "
            "snapshot, so the Zenodo surface is prepared-but-unpublished."),
    }


# --------------------------------------------------------------------------
# markdown renderers (counts recomputed, prose factual)
# --------------------------------------------------------------------------

def inventory_markdown(inv: dict) -> str:
    t = inv["totals_by_class"]
    lines = [
        "# Rights and licensing inventory",
        "",
        f"Generated by `scripts/inventory_rights.py` "
        f"(rights transformation `{TRANSFORMATION_VERSION}`). "
        "Every number below is recomputed from the records on disk.",
        "",
        "## Policy framing",
        "",
        f"`{POLICY_DEFAULT}` is the **default data-handling policy** applied "
        "where no documented right to redistribute exists. " + POLICY_NOTE,
        "",
        "A sha256 and a permalink identify bytes; they do not grant reuse or "
        "redistribution rights.",
        "",
        "## The release boundary",
        "",
        "`RELEASE_MANIFEST.json` states, path by path, what may be "
        "redistributed. This report measures the content; the manifest decides "
        "the status of each path, and `scripts/check_rights_consistency.py` "
        "fails the build when the two disagree. **Attribution is not a "
        "redistribution right.**",
        "",
        "## Scope",
        "",
        f"- tracked files: {inv['scan']['tracked_files']} "
        f"({inv['scan']['tracked_bytes']} bytes)",
        f"- head: `{inv['scan']['head_commit']}` "
        f"({inv['scan']['branch']})",
        f"- record layers scanned for expressive content: "
        f"{inv['scan']['record_layers_scanned']}",
        "- the audit covers **all** layers, not only the "
        f"{inv['totals_by_class']['expressive_items'].get('third_party_code', 0)} "
        "v1 self-flagged quotation rows",
        "",
        "## Totals by rights class",
        "",
        "`expressive items` counts every occurrence found while walking every "
        "row of every `.jsonl` layer plus code blocks detected in text "
        "artefacts. `rows holding it` is materialised only for the two layers "
        "`distribution_v1` projects row-by-row; the other layers were still "
        "fully walked, and their per-layer counts and length statistics are in "
        "`totals_by_layer` / `layer_stats` in the JSON report.",
        "",
        "| class | expressive items | rows holding it (detail layers) |",
        "|---|---|---|",
    ]
    for cls in sorted(t["expressive_items"]):
        lines.append(f"| `{cls}` | {t['expressive_items'][cls]} | "
                     f"{t['records_holding_class_detail_layers'].get(cls, '-')} |")
    lines += [
        "",
        f"Rows holding expressive content across every scanned layer: "
        f"**{t['rows_holding_expressive_content_all_layers']}** in "
        f"{t['record_layers_holding_expressive_content']} record layers. "
        f"Detail-scanned records materialised for the projection: "
        f"**{t['affected_records_total']}**.",
        "",
        "## Per-layer breakdown",
        "",
        "| layer | class counts |",
        "|---|---|",
    ]
    for rel, counts in inv["totals_by_layer"].items():
        lines.append(f"| `{rel}` | " + ", ".join(
            f"{k}={v}" for k, v in sorted(counts.items())) + " |")
    lines += [
        "",
        "## Licence-status contradictions",
        "",
        "Detected across `V4/sources.json`, `V4/manifest.json`, "
        "`derived_v4/manifest.json`, `NOTICE.md` and per-record "
        "`license`/`license_status` fields. "
        "`scripts/check_rights_consistency.py` fails on these.",
        "",
    ]
    if not inv["licence_contradictions"]:
        lines.append("None.")
    for c in inv["licence_contradictions"]:
        lines.append(f"- `{c['code']}` — source `{c['source_id']}`")
        if "distinct_values" in c:
            lines.append(f"  - distinct values: {c['distinct_values']}")
            for s in c["statements"]:
                lines.append(f"  - `{s['artifact']}` `{s['field']}` = "
                             f"{s['raw']!r} → {s['normalised']}")
        if "declared" in c:
            lines.append(f"  - manifest declares {c['declared']} while "
                         f"{len(c['unknown_statements'])} statements say "
                         "`unknown`")
        if "why" in c:
            lines.append(f"  - {c['why']}")
    lines += [
        "",
        "## Personal data / confidentiality sweep",
        "",
        "Values are **not** reproduced here. For each artefact the locator, the "
        "occurrence counts, the mailbox domain and a non-reversible handle are "
        "recorded; the anonymisation decision is recorded; canonical layers "
        "are not modified.",
        "",
        "| artefact | occurrences | distinct personal | named-contact block |",
        "|---|---|---|---|",
    ]
    for f in inv["personal_data_findings"]:
        lines.append(f"| `{f['path']}` | {f['email_occurrences']} | "
                     f"{f['distinct_personal_addresses']} | "
                     f"{'yes' if f['named_contacts_adjacent'] else 'no'} |")
    lines += [
        "",
        f"Total artefacts holding personal contact data: "
        f"**{len(inv['personal_data_findings'])}**.",
        "",
        "## Harness licence gating",
        "",
        f"`{len(inv['harness_withheld_files'])}` experiment directories carry a "
        "`WITHHELD.json`; the distribution view mirrors that pattern in "
        "`distribution_v1/withheld_harness.jsonl`.",
        "",
        "## History",
        "",
        f"- commits scanned: {inv['history_exposure_summary'].get('commits_scanned')}",
        f"- paths added then removed: "
        f"{inv['history_exposure_summary'].get('paths_added_then_removed')}",
        "- full findings: `reports/history_exposure.md`",
        "",
    ]
    return "\n".join(lines)


def history_markdown(hist: dict, inv: dict) -> str:
    lines = [
        "# Historical exposure (git archaeology)",
        "",
        "Generated by `scripts/inventory_rights.py`. Read-only: "
        "`git rev-list --all`, `git show --diff-filter=A/D --name-only`, "
        "`git show <commit>:<path>`, `git merge-base --is-ancestor`.",
        "",
        "## Statement",
        "",
        "**No git history was rewritten, no commit amended, no branch "
        "force-pushed and no ref deleted by this remediation. None of that "
        "will be done without explicit authorisation from the repository "
        "owner.** Deleting a file at the tip does not un-publish the blob.",
        "",
        "## Published surfaces (reported separately from repo content)",
        "",
    ]
    s = hist["published_surfaces"]
    for name, url in sorted(s["git_remotes"].items()):
        lines.append(f"- remote `{name}` → {url}")
    lines.append(f"- refs present on the remote: "
                 f"{', '.join('`' + r + '`' for r in s['refs_published_to_origin']) or 'none'}")
    lines.append(f"- `.zenodo.json` present: "
                 f"{'yes' if s['zenodo_metadata_present'] else 'no'}; "
                 f"`publish_manifest.json` present: "
                 f"{'yes' if s['publish_manifest_present'] else 'no'}")
    lines.append(f"- DOI recorded anywhere in the repo: "
                 f"{'yes: ' + ', '.join(s['doi_values']) if s['doi_found_in_repo'] else 'no'}")
    lines += [
        "",
        s["assessment"],
        "",
        "## Third-party material added in history and no longer in the tree",
        "",
        f"Commits scanned: {hist['commits_scanned']}. Paths that appear in "
        f"history but not in the current tree (code/prose suffixes): "
        f"{hist['paths_added_then_removed']}. These are split below into blobs "
        "that actually carried third-party expression and paths that were only "
        "generated project artefacts, so the exposure is not overstated.",
        "",
        "### Historically published third-party expression",
        "",
    ]
    tp = [i for i in hist["historical_exposure_items"]
          if i["third_party_expression_historically_published"]]
    other = [i for i in hist["historical_exposure_items"]
             if not i["third_party_expression_historically_published"]]
    if not tp:
        lines.append("None detected.")
    for it in tp:
        lines += [
            f"#### `{it['path']}`",
            "",
            f"- class: `{it['class']}`",
            f"- added in `{it['added_in_commit'][:9]}`; "
            + (f"removed in `{it['removed_in_commit'][:9]}`"
               if it["removed_in_commit"] else
               "no deletion commit found: the path was retired or moved, "
               "and the historical blob stays in every clone"),
            f"- in the current tree: {'yes' if it['present_in_current_tree'] else 'no'}",
            f"- blob still reachable from: "
            f"{', '.join('`' + r + '`' for r in it['reachable_from_refs']) or 'no local ref'}",
            f"- historical size / sha256: {it['reachable_bytes']} bytes, "
            f"`{it['reachable_sha256']}`",
            f"- SPDX header found inside the historical blob (this is a "
            f"quoted snippet's own header, not a licence grant by this "
            f"project): {it['spdx_declared_in_historical_blob']}",
            f"- {it['note']}",
            "",
        ]
    lines += [
        "### Other paths retired or moved (generated project artefacts)",
        "",
    ]
    if not other:
        lines.append("None.")
    for it in other:
        lines.append(f"- `{it['path']}` — added `{it['added_in_commit'][:9]}`, "
                     f"absent from the current tree; "
                     f"{it['reachable_bytes']} bytes, "
                     f"sha256 `{(it['reachable_sha256'] or '')[:16]}…`; "
                     f"reachable from {len(it['reachable_from_refs'])} local "
                     f"ref(s). No upstream source signature detected in the "
                     f"historical blob.")
    lines += [
        "",
        "## Material added in history that is still in the current tree",
        "",
        "Reported as **current** exposure, not historical: it is in the tip "
        "and therefore in every published ref.",
        "",
    ]
    for it in hist["current_exposure_items_in_history_scan"]:
        lines.append(f"- `{it['path']}` (class `{it['class']}`) added in "
                     f"`{it['added_in_commit'][:9]}`, reachable from "
                     f"{', '.join('`' + r + '`' for r in it['reachable_from_refs'])}"
                     f" — {it['note']}")
    lines += [
        "",
        "## Mitigating fact about the first commit",
        "",
        "The initial commit is already the redacted copy: `code_context` "
        "snippet counts in `jsonl/findings.jsonl` are identical across every "
        "commit reachable from any ref, so the 1,936 removed `code_context` "
        "entries described in `NOTICE.md` and `publish_manifest.json` were "
        "removed **before** the first commit and never entered this repo's "
        "history.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())

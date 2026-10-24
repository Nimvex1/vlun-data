#!/usr/bin/env python3
"""Rights gate: fail closed on copied content, licence contradictions,
missing attribution and unverifiable hashes in the distribution artefacts.

This is the enforcement half of spec item 5; the measurement half is
``scripts/inventory_rights.py`` (which writes ``reports/rights_inventory.json``
and ``distribution_v1/``). The gate re-reads the canonical layers where a
claim has to be *verified*, not just trusted, and never edits anything.

Checks (each emits machine-readable reasons on stdout as JSON):

  copied content
    DIST_FORBIDDEN_CODE_PRESENT      third-party code / PoC source / patch diff
                                     present in a distribution artefact with no
                                     documented right
    DIST_COPIED_PROSE_OVER_QUOTA     third-party prose longer than the allowed
                                     attributed-quotation quota
    DIGEST_VERBATIM_OVERLAP          a "digest" sharing a contiguous word window
                                     with audit prose (i.e. a paraphrase-shaped
                                     copy rather than an independent summary)
    DIST_PERSONAL_DATA_PRESENT       mailbox / named-contact data in a
                                     distribution artefact
    WITHHELD_FILE_PRESENT            a file the repo declared WITHHELD appears
                                     in the published tree
    ATTRIBUTION_MISSING / DIGEST_MISSING_ATTRIBUTION / POINTER_MISSING_FIELDS

  licence status
    LICENCE_STATUS_CONTRADICTION     one source, >1 licence status across
                                     V4/sources.json, V4/manifest.json,
                                     derived_v4/manifest.json and per-record
                                     license/license_status fields
    UNKNOWN_MASKS_DECLARED_LICENCE   license_status: unknown while a manifest
                                     declares a specific licence (the Oak
                                     Security CC BY-ND 4.0 case)
    LICENCE_UNRESOLVED_NO_REGISTRY   nothing resolves the status
    REGISTRY_STATUS_MISMATCH         an artefact disagrees with
                                     distribution_v1/rights_source_registry.json

  hashes
    INVALID_SHA256                   a hash field that is not 64-hex
    INVALID_COMMIT_REF               a commit field that is not 40-hex
    MANIFEST_HASH_MISMATCH           MANIFEST.json hash != bytes on disk
    HASH_MISMATCH                    a pointer hash != the canonical bytes
    HASH_UNVERIFIABLE                a pointer whose canonical row cannot be
                                     located (fail closed, not skipped)

  framing and counts
    FORBIDDEN_RIGHTS_CLAIM_PHRASE    "zero licensing" / "zero confidentiality
                                     risk" style claims
    POLICY_FRAMING_MISSING           METADATA_ONLY asserted without stating it
                                     is a default data-handling policy and not a
                                     claim of legal clearance
    COUNT_MISMATCH                   a published count that does not equal the
                                     recomputed value. Portability rule: only
                                     quantities any checkout computes
                                     identically are compared — the inventory
                                     artefact is checked for INTERNAL
                                     consistency (row counts vs the entries it
                                     enumerates), never against this
                                     checkout's git index or HEAD
    MISSING_DISTRIBUTION_ARTEFACT    a required file of the view is absent
    INVENTORY_PATH_MISSING           the inventory catalogue cites a repo-
                                     relative path that is not in this tree

    python scripts/check_rights_consistency.py
    python scripts/check_rights_consistency.py --json
    python scripts/check_rights_consistency.py --root tests/fixtures/broken/x --partial

Exit 0 only when every applicable check passes. Stdlib only, read-only.

The report is environment-independent on purpose: it records `"root": "."`
(repo-relative marker) instead of a machine-local absolute path, and no check
compares a committed quantity against this checkout's git index or HEAD. A
gate that can only pass on the exact machine that generated its artefact is
not a gate (measured on CI, 2026-10: this is what made rights-consistency
permanently red on every fresh clone).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inventory_rights import (  # noqa: E402
    CODE_KEYS, DIFF_KEYS, EMAIL_RE, FORBIDDEN_CLAIMS, HEX40_RE, HEX64_RE,
    KEEP_QUOTE_MAX_CHARS, POC_KEYS, POLICY_DEFAULT, PROSE_KEYS,
    TRANSFORMATION_VERSION, licence_contradictions, read_jsonl,
    scan_records_file, sha256_file, sha256_text, tracked_files,
)
from build_release_manifest import (  # noqa: E402
    LICENCE_CC_BY, LICENCE_MIT, MANIFEST_NAME, RELEASED_STATUSES,
    STATUS_VOCABULARY, build as build_release_manifest,
)

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_VIEW_FILES = (
    "README.md", "MANIFEST.json", "rights_ledger.jsonl",
    "rights_source_registry.json", "records_v1.jsonl",
    "records_v1_withheld_pointers.jsonl", "records_v4.jsonl",
    "records_v4_withheld_pointers.jsonl", "digests.jsonl",
    "licence_contradictions.json", "withheld_harness.jsonl",
)
# sentinels this dataset uses deliberately; "unknown" is a counted outcome,
# not a malformed hash
SENTINELS = {"", "unknown", "null", "none", "n/a"}
POINTER_FILES = ("records_v1_withheld_pointers.jsonl",
                 "records_v4_withheld_pointers.jsonl")
PROJECTION_FILES = ("records_v1.jsonl", "records_v4.jsonl")
REQUIRE_FRAMING_DOCS = ("README.md", "NOTICE.md", "docs/DATASHEET.md")
WORD_WINDOW = 10  # contiguous words that make a copy, not a coincidence
# "text" is excluded: digests.jsonl legitimately holds the project's own text
# and is checked for independence and attribution by check_digests() instead.
COPYABLE_PROSE_KEYS = PROSE_KEYS - {"text"}
# reason/source codes look like field values; they are never expressive content
CODE_LIKE = re.compile(r"^[A-Z0-9_]{4,64}$")

# ---------------------------------------------------------------------------
# release manifest
# ---------------------------------------------------------------------------
# The licence tokens a document may use to grant a licence.  A grant that
# names a path the release manifest does not release (or releases under a
# different licence) is a contradiction, not a style question.
GRANT_TOKENS = (
    ("CC-BY-4.0", re.compile(r"cc[ _-]?by[ _-]?4\.0", re.I)),
    ("MIT", re.compile(r"\bmit\b", re.I)),
)
# A path token: a directory-looking token that is not part of a URL.
PATH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_.*\-/])([A-Za-z0-9_*.\-]+)/")
# A negation in front of a licence token makes the token a mention, not a
# grant.
NEGATION_RE = re.compile(r"\b(not|no|never|without|nor)\b", re.I)
# The prose documents the grant scan applies to.  A JSON manifest states its
# licences in fields, and those are checked field by field instead.
PROSE_SUFFIXES = (".md", ".cff", ".txt", ".rst")
# Whole-repository licence declarations (CITATION.cff, .zenodo.json).
REPO_LICENCE_FIELDS = ("CITATION.cff", ".zenodo.json")
# The phrases the licence and the notice must contain, whitespace-collapsed.
PHRASE_RELEASE_MANIFEST = "release_manifest.json"
PHRASE_RELEASED_SET = "released set"
PHRASE_NOT_LICENSED = "not licensed here"
PHRASE_NON_COVERAGE = (
    "does not cover",
    "not licensed here",
    "no licence is applied",
    "licenses nothing",
)
PHRASE_ATTRIBUTION_NOT_A_GRANT = (
    "attribution is not a redistribution right",
    "attribution is not a licence",
    "attribution does not grant",
)
PHRASE_THIRD_PARTY = (
    "third-party source",
    "proof-of-concept",
    "report prose",
    "personal data",
)


class Gate:
    def __init__(self, root: Path, partial: bool):
        self.root = root
        self.partial = partial
        self.reasons: list[dict] = []
        self.limits: list[dict] = []

    def fail(self, code: str, artifact: str, detail: str, **extra) -> None:
        r = {"code": code, "artifact": artifact, "detail": detail}
        r.update(extra)
        self.reasons.append(r)

    def has(self, rel: str) -> bool:
        return (self.root / rel).is_file()

    def req(self, rel: str) -> bool:
        """Required-artefact presence; skipped in --partial fixture mode."""
        if self.has(rel):
            return True
        if not self.partial:
            self.fail("MISSING_DISTRIBUTION_ARTEFACT", rel,
                      "a required file of the distribution view is absent")
        return False


# ---------------------------------------------------------------------------
# copied-content detection
# ---------------------------------------------------------------------------

def forbidden_key_set() -> set:
    return CODE_KEYS | POC_KEYS | DIFF_KEYS | COPYABLE_PROSE_KEYS


def strings_of(node, pointer="$"):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from strings_of(v, f"{pointer}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from strings_of(v, f"{pointer}[{i}]")
    elif isinstance(node, str):
        yield pointer, node


def leaf_key(pointer: str) -> str:
    parts = [p for p in pointer.replace("[", ".[").split(".") if p]
    return parts[-1].rstrip("]") if parts else ""


def check_distribution_content(g: Gate, view: Path) -> None:
    banned = forbidden_key_set()
    artefacts = [p for p in sorted(view.glob("*.jsonl"))
                 + sorted(view.glob("*.json"))
                 if p.name != "digests.jsonl"]
    for p in artefacts:
        rel = p.relative_to(g.root).as_posix()
        if p.suffix == ".json":
            try:
                rows = [json.loads(p.read_text(encoding="utf-8"))]
            except (OSError, json.JSONDecodeError) as exc:
                g.fail("INVALID_JSON", rel, str(exc))
                continue
        else:
            rows = read_jsonl(p)
        for row in rows:
            rid = str(row.get("record_id") or row.get("digest_id")
                      or row.get("subject") or "")
            for pointer, text in strings_of(row):
                key = leaf_key(pointer)
                if not text.strip():
                    continue
                if key == "code" and CODE_LIKE.match(text.strip()):
                    continue
                if key in banned and len(text.strip()) > 40:
                    g.fail("DIST_FORBIDDEN_CODE_PRESENT", rel,
                           f"third-party code/prose is present in a "
                           f"distribution artefact with no documented right "
                           f"to redistribute (field {pointer!r}, "
                           f"{len(text)} chars)", record_id=rid,
                           field=pointer, chars=len(text))
                if EMAIL_RE.search(text):
                    g.fail("DIST_PERSONAL_DATA_PRESENT", rel,
                           f"a personal mailbox/triage address is present in a "
                           f"distribution artefact at {pointer!r}; anonymise it",
                           record_id=rid, field=pointer)
            # attributed quotations: length quota + attribution are mandatory
            for kept in (row.get("kept_attributed_short_citations") or []):
                val = kept.get("value")
                if not isinstance(val, str):
                    continue
                if len(val) > KEEP_QUOTE_MAX_CHARS:
                    g.fail("DIST_COPIED_PROSE_OVER_QUOTA", rel,
                           f"quoted third-party prose at {kept.get('pointer')!r} "
                           f"is {len(val)} chars, above the "
                           f"{KEEP_QUOTE_MAX_CHARS}-char attributed-quotation "
                           f"quota", record_id=rid)
                if not kept.get("attribution"):
                    g.fail("ATTRIBUTION_MISSING", rel,
                           f"an attributed quotation at "
                           f"{kept.get('pointer')!r} carries no attribution",
                           record_id=rid)
                if kept.get("sha256_of_stored_text") != sha256_text(val):
                    g.fail("HASH_MISMATCH", rel,
                           f"the recorded quotation hash does not match the "
                           f"bytes being distributed at "
                           f"{kept.get('pointer')!r}", record_id=rid)
            # withheld pointer records must be complete
            if row.get("status") == "WITHHELD":
                need = ("pointer", "content_class", "rights_decision",
                        "rights_transformation_version", "reason",
                        "sha256_of_original_bytes", "record_id", "source_layer",
                        "status")
                missing = [k for k in need if not row.get(k)]
                if missing:
                    g.fail("POINTER_MISSING_FIELDS", rel,
                           "a WITHHELD pointer record is incomplete",
                           missing=missing, record_id=rid)
                if not (row.get("source_urls") or row.get("attribution")):
                    g.fail("ATTRIBUTION_MISSING", rel,
                           "a WITHHELD pointer carries neither a source URL "
                           "nor an attribution", record_id=rid)
                h = row.get("sha256_of_original_bytes")
                if h and not HEX64_RE.match(str(h)):
                    g.fail("INVALID_SHA256", rel,
                           "sha256_of_original_bytes is not 64-hex",
                           observed=h, record_id=rid)
                for field, refs in (row.get("immutable_reference")
                                    or {}).items():
                    for ref in ([refs] if isinstance(refs, str) else []):
                        if ref.strip().lower() in SENTINELS:
                            continue
                        if not HEX40_RE.match(ref):
                            g.fail("INVALID_COMMIT_REF", rel,
                                   f"{field}={ref!r} is not a 40-hex commit: a "
                                   f"truncated or invented reference cannot "
                                   f"pin immutable bytes",
                                   observed=ref, record_id=rid)
                for field, refs in (row.get("sha256_recorded_upstream")
                                    or {}).items():
                    for val in ([refs] if isinstance(refs, str) else []):
                        if val.strip().lower() in SENTINELS:
                            continue
                        if not HEX64_RE.match(val):
                            g.fail("INVALID_SHA256", rel,
                                   f"upstream-recorded hash {field}={val!r} "
                                   f"is not 64-hex", observed=val,
                                   record_id=rid)


def audit_prose_windows(g: Gate, limit_files=()) -> set[str]:
    """10-word windows of canonical third-party expression.

    Built from the layers that actually hold copied report prose and quoted
    source, so a "digest" that re-uses an audit's own sentences is caught
    structurally instead of by eye.
    """
    windows: set[str] = set()
    sources = list(limit_files) or ["jsonl_v4/findings.jsonl",
                                    "derived/records.jsonl"]
    for rel in sources:
        p = g.root / rel
        if not p.is_file():
            continue
        for row in read_jsonl(p):
            for _pointer, text in strings_of(row):
                if len(text) < 300:
                    continue
                words = text.split()
                if len(words) <= WORD_WINDOW:
                    continue
                for i in range(len(words) - WORD_WINDOW + 1):
                    windows.add(" ".join(words[i:i + WORD_WINDOW]).lower())
    return windows


def check_digests(g: Gate, view: Path) -> None:
    p = view / "digests.jsonl"
    if not g.req("distribution_v1/digests.jsonl") or not p.is_file():
        return
    windows = None  # built lazily: only if a digest is long enough to matter
    for row in read_jsonl(p):
        did = row.get("digest_id", "(no id)")
        text = row.get("text", "")
        if row.get("independently_written") is not True:
            g.fail("DIGEST_NOT_INDEPENDENT", "distribution_v1/digests.jsonl",
                   "a digest is not marked independently_written: true, so it "
                   "cannot be presented as the project's own summary",
                   digest_id=did)
        if row.get("copies_audit_prose") is not False:
            g.fail("DIGEST_NOT_INDEPENDENT", "distribution_v1/digests.jsonl",
                   "a digest does not assert copies_audit_prose: false",
                   digest_id=did)
        if not row.get("attribution"):
            g.fail("DIGEST_MISSING_ATTRIBUTION",
                   "distribution_v1/digests.jsonl",
                   "a digest carries no attribution", digest_id=did)
        if row.get("digest_kind") != "independently_written_factual_summary":
            g.fail("DIGEST_NOT_INDEPENDENT", "distribution_v1/digests.jsonl",
                   "digest_kind must state that the text is an independently "
                   "written factual summary", digest_id=did)
        words = text.split()
        if len(words) > WORD_WINDOW:
            if windows is None:
                windows = audit_prose_windows(g)
            for i in range(len(words) - WORD_WINDOW + 1):
                w = " ".join(words[i:i + WORD_WINDOW]).lower()
                if w in windows:
                    g.fail("DIGEST_VERBATIM_OVERLAP",
                           "distribution_v1/digests.jsonl",
                           f"digest {did!r} reproduces a contiguous "
                           f"{WORD_WINDOW}-word window of third-party report "
                           f"text; a digest must be written in the project's "
                           f"own words", digest_id=did, window=w)
                    break


def check_withheld_files_really_absent(g: Gate) -> None:
    """The repo's WITHHELD.json pattern: a declared-withheld file may not
    appear in the published tree or in the distribution view."""
    tracked = tracked_files(g.root)
    withheld_names = set()
    for rel in tracked:
        if not rel.endswith("WITHHELD.json"):
            continue
        try:
            w = json.loads((g.root / rel).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            g.fail("INVALID_JSON", rel, "WITHHELD.json is not readable JSON")
            continue
        for f in w.get("files") or []:
            name = str(f.get("path") or "")
            if name:
                withheld_names.add(name)
            h = f.get("sha256")
            if h and not HEX64_RE.match(str(h)):
                g.fail("INVALID_SHA256", rel,
                       "a withheld-file hash is not 64-hex", observed=h)
            if not f.get("sha256") or not f.get("bytes"):
                g.fail("POINTER_MISSING_FIELDS", rel,
                       "a WITHHELD.json entry carries no hash or byte count, "
                       "so the removed bytes cannot be verified later")
    if not withheld_names:
        return
    for rel in tracked:
        base = Path(rel).name
        if base in withheld_names and "WITHHELD" not in rel:
            g.fail("WITHHELD_FILE_PRESENT", rel,
                   f"{base} is declared WITHHELD for licensing reasons but is "
                   f"present in the tracked tree")


# ---------------------------------------------------------------------------
# licence status reconciliation
# ---------------------------------------------------------------------------

def check_licence_status(g: Gate) -> None:
    for c in licence_contradictions(g.root):
        g.fail(c["code"], "V4/sources.json + V4/manifest.json + "
                          "derived_v4/manifest.json + per-record fields",
               _contradiction_detail(c), source_id=c.get("source_id"),
               distinct_values=c.get("distinct_values"))

    reg_path = g.root / "distribution_v1" / "rights_source_registry.json"
    if not reg_path.is_file():
        if not g.partial:
            g.fail("MISSING_DISTRIBUTION_ARTEFACT",
                   "distribution_v1/rights_source_registry.json",
                   "no machine-readable licence registry, so contradictory "
                   "statuses cannot be reconciled")
        return
    try:
        reg = json.loads(reg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        g.fail("INVALID_JSON", "distribution_v1/rights_source_registry.json",
               str(exc))
        return
    by_id = {s.get("source_id"): s for s in reg.get("sources") or []}
    # every V4 source must resolve to the registry's required status
    sj = g.root / "V4" / "sources.json"
    if sj.is_file():
        try:
            rows = json.loads(sj.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            g.fail("INVALID_JSON", "V4/sources.json", str(exc))
            rows = []
        for row in rows:
            sid = row.get("source_id")
            want = by_id.get(sid, {}).get("license_status_required")
            got = row.get("license_status")
            if want and got != want:
                g.fail("REGISTRY_STATUS_MISMATCH", "V4/sources.json",
                       f"source {sid} declares license_status={got!r} while "
                       f"the rights registry requires {want!r}; the two must "
                       f"be reconciled so a stale 'unknown' cannot pass",
                       source_id=sid, observed=got, required=want)
            if row.get("source_repository_commit") and not HEX40_RE.match(
                    str(row["source_repository_commit"])):
                g.fail("INVALID_COMMIT_REF", "V4/sources.json",
                       "source_repository_commit is not 40-hex",
                       observed=row.get("source_repository_commit"))
    # the registry may never present itself as legal clearance
    if reg.get("data_handling_policy_default") != POLICY_DEFAULT:
        g.fail("POLICY_FRAMING_MISSING",
               "distribution_v1/rights_source_registry.json",
               "the registry does not state METADATA_ONLY as its default "
               "data-handling policy")
    for s in reg.get("sources") or []:
        if s.get("legal_clearance") is not False:
            g.fail("POLICY_FRAMING_MISSING",
                   "distribution_v1/rights_source_registry.json",
                   f"registry source {s.get('source_id')} asserts a legal "
                   f"clearance that no document in the repo supports")
        if s.get("redistribution_right") not in ("not_documented",
                                                "documented"):
            g.fail("POLICY_FRAMING_MISSING",
                   "distribution_v1/rights_source_registry.json",
                   "redistribution_right must be an explicit verdict",
                   source_id=s.get("source_id"),
                   observed=s.get("redistribution_right"))


def _contradiction_detail(c: dict) -> str:
    if c["code"] == "UNKNOWN_MASKS_DECLARED_LICENCE":
        return (f"source {c['source_id']} has license_status 'unknown' in "
                f"{len(c['unknown_statements'])} statements while a manifest "
                f"declares {c['declared']}. An undeclared status cannot mask a "
                f"No-Derivatives term: " + c["why"])
    if c["code"] == "LICENCE_STATUS_CONTRADICTION":
        return (f"source {c['source_id']} carries contradictory licence "
                f"statuses {c['distinct_values']}")
    return f"source {c['source_id']}: {c.get('why', '')}"


# ---------------------------------------------------------------------------
# hash verification
# ---------------------------------------------------------------------------

def canonical_pointer_hashes(g: Gate) -> dict:
    """(source_layer, record_id, pointer) -> sha256 of the bytes on disk."""
    out = {}
    for rel in ("derived/records.jsonl", "jsonl_v4/findings.jsonl"):
        p = g.root / rel
        if not p.is_file():
            continue
        hits, _c, _s, _n, _r = scan_records_file(rel, p, detail=True)
        for h in hits:
            for items in h["items_by_class"].values():
                for i in items:
                    out[(rel, h["record_id"], i["pointer"])] = \
                        i["sha256_stored_bytes"]
    return out


UNIVERSAL_HASH_CLAIM = re.compile(
    r"every withheld (?:snippet|citation)[^.\n]{0,240}?sha256", re.I | re.S)


def check_upstream_hash_gap(g: Gate, view: Path) -> None:
    """The withheld pointers that carry a locally computed hash but no hash the
    upstream source itself recorded.

    This is a limitation of the retrieved evidence, not automatically a
    violation: it becomes one only while a published document still claims every
    citation keeps a sha256. So the gap is measured, reported as a noted
    limitation, and fails the gate if some document overstates it.
    """
    missing = 0
    total = 0
    for rel in POINTER_FILES:
        p = view / rel
        if not p.is_file():
            continue
        for row in read_jsonl(p):
            total += 1
            rec = row.get("sha256_recorded_upstream") or {}
            if not any(k in rec for k in ("sha256", "report_sha256",
                                          "file_sha256")):
                missing += 1
    if not total:
        return
    overstating = []
    for rel in REQUIRE_FRAMING_DOCS + ("distribution_v1/README.md",):
        p = g.root / rel
        if not p.is_file():
            continue
        if UNIVERSAL_HASH_CLAIM.search(p.read_text(encoding="utf-8", errors="replace")):
            overstating.append(rel)
    g.limits.append({
        "code": "UPSTREAM_HASH_NOT_RECORDED",
        "artifact": "distribution_v1/" + ", ".join(POINTER_FILES),
        "pointers_without_an_upstream_hash": missing, "of": total,
        "detail": (f"{missing} of {total} withheld pointers carry the hash this project "
                   "computed when it retrieved the file, but no hash recorded by the "
                   "upstream source itself; a retrieved hash is evidence of what was "
                   "fetched, not a publisher-attested digest"),
    })
    if missing and overstating:
        g.fail("ORIGINAL_HASH_NOT_RECORDED_UPSTREAM", ", ".join(overstating),
               f"{missing} of {total} withheld pointers carry the hash this project "
               "computed but no hash recorded upstream, while the document still "
               "claims every withheld citation keeps a sha256; narrow the claim to "
               "the pointers that actually carry one")


def check_hashes(g: Gate, view: Path) -> None:
    mp = view / "MANIFEST.json"
    if mp.is_file():
        try:
            man = json.loads(mp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            g.fail("INVALID_JSON", "distribution_v1/MANIFEST.json", str(exc))
            man = {}
        for rel, meta in (man.get("files") or {}).items():
            p = view / rel
            if not p.is_file():
                g.fail("MISSING_DISTRIBUTION_ARTEFACT",
                       f"distribution_v1/{rel}",
                       "listed in MANIFEST.json but absent from the view")
                continue
            got = sha256_file(p)
            if got != meta.get("sha256"):
                g.fail("MANIFEST_HASH_MISMATCH", f"distribution_v1/{rel}",
                       "the recorded sha256 does not match the bytes on disk",
                       expected=meta.get("sha256"), observed=got)
            if meta.get("bytes") != p.stat().st_size:
                g.fail("COUNT_MISMATCH", f"distribution_v1/{rel}",
                       "the recorded byte size does not match the file",
                       expected=meta.get("bytes"),
                       observed=p.stat().st_size)
        for rel in REQUIRED_VIEW_FILES:
            if rel == "MANIFEST.json":
                continue  # the manifest cannot carry its own hash
            if rel not in (man.get("files") or {}) and not g.partial:
                g.fail("MISSING_DISTRIBUTION_ARTEFACT",
                       f"distribution_v1/{rel}",
                       "required file of the view is not even listed")
    # pointer hashes vs canonical bytes
    canon = None
    for rel in POINTER_FILES:
        p = view / rel
        if not p.is_file():
            continue
        if canon is None:
            canon = canonical_pointer_hashes(g)
        layer = {"records_v1_withheld_pointers.jsonl": "derived/records.jsonl",
                 "records_v4_withheld_pointers.jsonl":
                     "jsonl_v4/findings.jsonl"}[rel]
        for row in read_jsonl(p):
            key = (layer, row.get("record_id"), row.get("pointer"))
            want = row.get("sha256_of_original_bytes")
            if want and not HEX64_RE.match(str(want)):
                g.fail("INVALID_SHA256", f"distribution_v1/{rel}",
                       "sha256_of_original_bytes is not 64-hex",
                       observed=want, record_id=row.get("record_id"))
                continue
            actual = canon.get(key)
            if actual is None:
                g.fail("HASH_UNVERIFIABLE", f"distribution_v1/{rel}",
                       "the canonical row/pointer behind this withheld hash "
                       "could not be located, so the hash cannot be verified "
                       "(fail closed: an unverifiable hash is not evidence)",
                       record_id=row.get("record_id"),
                       pointer=row.get("pointer"))
            elif actual != want:
                g.fail("HASH_MISMATCH", f"distribution_v1/{rel}",
                       "the withheld hash does not match the bytes still "
                       "present in the canonical layer",
                       record_id=row.get("record_id"),
                       pointer=row.get("pointer"), expected=want,
                       observed=actual)
    # ledger evidence hashes must be well formed and traceable
    lp = view / "rights_ledger.jsonl"
    if lp.is_file():
        for row in read_jsonl(lp):
            for h in row.get("evidence_hashes") or []:
                if h and not HEX64_RE.match(str(h)):
                    g.fail("INVALID_SHA256", "distribution_v1/rights_ledger.jsonl",
                           "a ledger evidence hash is not 64-hex",
                           observed=h, subject=row.get("subject"))
            if row.get("transformation_version") != TRANSFORMATION_VERSION:
                g.fail("POLICY_FRAMING_MISSING",
                       "distribution_v1/rights_ledger.jsonl",
                       "a ledger row does not record the rights transformation "
                       "version", subject=row.get("subject"))
            for k in ("rights_decision", "reason"):
                if not row.get(k):
                    g.fail("POINTER_MISSING_FIELDS",
                           "distribution_v1/rights_ledger.jsonl",
                           f"a ledger row carries no {k}",
                           subject=row.get("subject"))


# ---------------------------------------------------------------------------
# framing, claims and counts
# ---------------------------------------------------------------------------

def check_claims_and_framing(g: Gate) -> None:
    docs = [f for f in ("README.md", "NOTICE.md", "CHANGELOG.md",
                        "distribution_v1/README.md",
                        "reports/rights_inventory.md",
                        "reports/history_exposure.md",
                        "docs/DATASHEET.md") if g.has(f)]
    docs += [f for f in sorted(str(p.relative_to(g.root).as_posix())
                               for p in (g.root / "docs").glob("*.md"))] \
        if (g.root / "docs").is_dir() else []
    for rel in sorted(set(docs)):
        text = (g.root / rel).read_text(encoding="utf-8", errors="replace")
        low = text.lower()
        for phrase in FORBIDDEN_CLAIMS:
            if phrase in low:
                line = next((i + 1 for i, ln in enumerate(text.splitlines())
                             if phrase in ln.lower()), None)
                g.fail("FORBIDDEN_RIGHTS_CLAIM_PHRASE", rel,
                       f"generated documentation claims {phrase!r}; the "
                       f"measured corpus contains unlicensed third-party "
                       f"source and mined report prose, so no such claim is "
                       f"supportable", line=line)
    for rel in REQUIRE_FRAMING_DOCS:
        if not g.has(rel) or g.partial:
            continue
        text = (g.root / rel).read_text(encoding="utf-8", errors="replace")
        # whitespace-collapsed: a wrapped line must not turn a present statement
        # into a missing one, which would make the gate depend on line length
        low = " ".join(text.lower().split())
        if "metadata_only" in low or "metadata only" in low:
            ok = ("default data-handling policy" in low
                  or "default handling policy" in low) and (
                  "not a claim" in low or "not a determination" in low
                  or "not legal clearance" in low)
            if not ok:
                g.fail("POLICY_FRAMING_MISSING", rel,
                       "METADATA_ONLY is asserted without stating that it is a "
                       "default data-handling policy and not a claim that "
                       "every transformed record has been legally cleared")
    # the view itself must say so
    vr = g.root / "distribution_v1" / "README.md"
    if vr.is_file():
        low = " ".join(vr.read_text(encoding="utf-8", errors="replace").lower().split())
        if "default data-handling policy" not in low or \
                "not a determination" not in low and "not a legal opinion" \
                not in low:
            g.fail("POLICY_FRAMING_MISSING", "distribution_v1/README.md",
                   "the distribution view must state METADATA_ONLY as a "
                   "default data-handling policy, not as blanket clearance")


def check_counts(g: Gate, view: Path) -> None:
    mp = view / "MANIFEST.json"
    if not mp.is_file():
        return
    try:
        man = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if man.get("data_handling_policy_default") != POLICY_DEFAULT:
        g.fail("POLICY_FRAMING_MISSING", "distribution_v1/MANIFEST.json",
               "no METADATA_ONLY default policy recorded")
    if man.get("data_handling_policy_is_default_not_clearance") is not True:
        g.fail("POLICY_FRAMING_MISSING", "distribution_v1/MANIFEST.json",
               "the manifest must state that METADATA_ONLY is a default "
               "policy, not a clearance claim")
    if man.get("legal_clearance_claimed") is not False or \
            man.get("blanket_clearance_claimed") is not False:
        g.fail("POLICY_FRAMING_MISSING", "distribution_v1/MANIFEST.json",
               "the manifest claims a legal clearance")
    want = {
        "records_v1_projected": "records_v1.jsonl",
        "records_v4_projected": "records_v4.jsonl",
        "withheld_v1_citations": "records_v1_withheld_pointers.jsonl",
        "withheld_v4_passages": "records_v4_withheld_pointers.jsonl",
    }
    counts = man.get("counts") or {}
    for key, rel in want.items():
        p = view / rel
        if not p.is_file():
            continue
        observed = len(read_jsonl(p))
        if counts.get(key) != observed:
            g.fail("COUNT_MISMATCH", f"distribution_v1/{rel}",
                   f"count {key}={counts.get(key)} but the artefact holds "
                   f"{observed} rows; counts are recomputed from records, "
                   f"never typed", expected=counts.get(key), observed=observed)
    lp = view / "rights_ledger.jsonl"
    if lp.is_file():
        observed = len(read_jsonl(lp))
        if counts.get("ledger_rows") != observed:
            g.fail("COUNT_MISMATCH", "distribution_v1/rights_ledger.jsonl",
                   f"ledger_rows={counts.get('ledger_rows')} but the file "
                   f"holds {observed} rows", expected=counts.get("ledger_rows"),
                   observed=observed)
    dp = view / "digests.jsonl"
    if dp.is_file():
        observed = len(read_jsonl(dp))
        if counts.get("digests") != observed:
            g.fail("COUNT_MISMATCH", "distribution_v1/digests.jsonl",
                   f"digests={counts.get('digests')} but the file holds "
                   f"{observed}", expected=counts.get("digests"),
                   observed=observed)
    # cross-check against the inventory totals so the two cannot drift
    ip = g.root / "reports" / "rights_inventory.json"
    if ip.is_file():
        try:
            inv = json.loads(ip.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            g.fail("INVALID_JSON", "reports/rights_inventory.json", str(exc))
            return
        per_layer = sum(sum(c.values())
                        for c in inv.get("totals_by_layer", {}).values())
        total = sum(inv.get("totals_by_class", {}).get(
            "expressive_items", {}).values())
        if per_layer != total:
            g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                   f"sum over layers ({per_layer}) != the reported grand "
                   f"total ({total})", expected=total, observed=per_layer)
        # PORTABILITY RULE (measured on CI 2026-10, all four matrix jobs):
        # a check may only compare quantities that any checkout computes
        # identically. The previous version compared the stored
        # `scan.tracked_files` with `len(git ls-files)` HERE and the stored
        # `scan.head_commit` with `git rev-parse HEAD` HERE. Both stored
        # values describe the generating checkout: the index legitimately
        # differs on a fresh clone, and the commit that carries the artefact
        # is by construction always newer than the commit recorded inside
        # it, so the equality could only ever hold on the exact machine and
        # exact staging state that generated the file. That is not a gate.
        # CHOSEN SEMANTICS: internal consistency (option (b) of the design
        # note), not like-for-like recomputation — the inventory's own row
        # count must equal the number of entries it enumerates, its totals
        # must equal the sums of those entries, and every path it cites must
        # exist in this checkout. `scan.head_commit` and `scan.branch` stay
        # as measurement provenance and are never compared against the
        # checking checkout.
        scan = inv.get("scan", {})
        catalog = inv.get("files") or []
        if scan.get("tracked_files") != len(catalog):
            g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                   "the inventory states a tracked-file count that does not "
                   "equal the number of file rows it itself enumerates; the "
                   "artefact is internally inconsistent, rerun "
                   "scripts/inventory_rights.py",
                   expected=len(catalog), observed=scan.get("tracked_files"))
        catalog_bytes = sum(int(r.get("bytes") or 0) for r in catalog)
        if scan.get("tracked_bytes") not in (None, catalog_bytes):
            g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                   "the inventory's tracked-bytes total does not equal the "
                   "sum of the byte counts of its own file rows",
                   expected=catalog_bytes, observed=scan.get("tracked_bytes"))
        layers_list = scan.get("record_layers_list") or []
        if scan.get("record_layers_scanned") != len(layers_list):
            g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                   "the inventory states a record-layer count that does not "
                   "equal the number of layers it enumerates",
                   expected=len(layers_list),
                   observed=scan.get("record_layers_scanned"))
        text_rows = inv.get("text_artefact_scan") or []
        if scan.get("text_artefacts_scanned") != len(text_rows):
            g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                   "the inventory states a text-artefact count that does not "
                   "equal the number of text rows it enumerates",
                   expected=len(text_rows),
                   observed=scan.get("text_artefacts_scanned"))
        # every path the inventory cites must exist in this checkout; the
        # catalogue is repo-relative so this holds identically on any clone
        # of a commit whose inventory was regenerated for that tree.
        missing = sorted({str(r.get("path")) for r in catalog
                          if r.get("path") and not (g.root / str(r["path"])).is_file()})
        for rel in missing[:20]:
            g.fail("INVENTORY_PATH_MISSING", "reports/rights_inventory.json",
                   f"the inventory catalogue cites `{rel}`, which is not a "
                   f"file in this checkout; the inventory was generated "
                   f"against a different tree, rerun "
                   f"scripts/inventory_rights.py", path=rel)
        if len(missing) > 20:
            g.fail("INVENTORY_PATH_MISSING", "reports/rights_inventory.json",
                   f"{len(missing)} inventoried paths are absent from this "
                   f"checkout (first 20 reported separately)",
                   path_count=len(missing))


# ---------------------------------------------------------------------------
# release manifest
# ---------------------------------------------------------------------------

def collapse_text(text: str) -> str:
    return " ".join(text.lower().split())


def paragraphs(text: str) -> list[str]:
    return [p for p in re.split(r"\n\s*\n", text) if p.strip()]


SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?])\s+|\n")


def sentence_before(paragraph: str, start: int) -> str:
    """The part of the sentence that precedes a token."""
    left = 0
    for m in SENTENCE_BREAK_RE.finditer(paragraph, 0, start):
        left = m.end()
    return paragraph[left:start]


def grant_licences(paragraph: str) -> set[str]:
    """The licences a paragraph actually grants.

    A mention is not a grant: "it is **not** covered by the MIT grant" names
    MIT and grants nothing, so a negation in the same sentence removes it.
    """
    out = set()
    for name, rx in GRANT_TOKENS:
        for m in rx.finditer(paragraph):
            if NEGATION_RE.search(sentence_before(paragraph, m.start())):
                continue
            out.add(name)
    return out


def path_tokens(paragraph: str) -> set[str]:
    return {m.group(1) for m in PATH_TOKEN_RE.finditer(paragraph)}


def group_matches(group: str, top: str) -> bool:
    """Does a top-level directory belong to a named path group?

    `jsonl*` matches jsonl/, jsonl_v3/, jsonl_ml/ and jsonl_v4/; `reports`
    matches only reports/.
    """
    if group.endswith("*"):
        return top.startswith(group[:-1])
    return top == group


def manifest_groups(manifest: dict) -> dict:
    """Named path group -> the manifest paths it covers."""
    out: dict[str, list[str]] = {}
    for path in manifest.get("paths") or {}:
        top = path.split("/")[0]
        for group in {p.split("/")[0] for p in manifest.get("paths") or {}}:
            if group_matches(group, top):
                out.setdefault(group, []).append(path)
    return out


def check_release_manifest(g: Gate) -> dict | None:
    """The release manifest must exist, be reproducible, and describe the tree."""
    target = g.root / MANIFEST_NAME
    if not target.is_file():
        if not g.partial:
            g.fail("RELEASE_MANIFEST_MISSING", MANIFEST_NAME,
                   "there is no release manifest, so nothing states which "
                   "paths may be redistributed; run "
                   "python scripts/build_release_manifest.py")
        return None
    try:
        committed = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        g.fail("INVALID_JSON", MANIFEST_NAME, str(exc))
        return None
    recomputed = build_release_manifest(g.root)
    if json.dumps(committed, sort_keys=True) != json.dumps(recomputed, sort_keys=True):
        g.fail("RELEASE_MANIFEST_NOT_REPRODUCIBLE", MANIFEST_NAME,
               "the committed release manifest differs from the manifest the "
               "builder recomputes from this tree; rerun "
               "python scripts/build_release_manifest.py")
    paths = committed.get("paths") or {}
    statuses = committed.get("statuses") or {}
    licences = committed.get("path_licences") or {}
    for path, status in sorted(paths.items()):
        if status not in STATUS_VOCABULARY:
            g.fail("RELEASE_STATUS_UNKNOWN", MANIFEST_NAME,
                   f"path {path!r} carries the unknown rights status "
                   f"{status!r}", path=path)
        if not (g.root / path).is_file():
            g.fail("RELEASE_PATH_MISSING", MANIFEST_NAME,
                   f"the manifest releases {path!r}, but that file is not in "
                   f"this checkout", path=path)
    # every file in the tree must be classified: a path that is neither
    # released nor explicitly withheld is an accident, not a decision
    for path in tracked_files(g.root):
        if path not in paths:
            g.fail("RELEASE_PATH_UNCLASSIFIED", MANIFEST_NAME,
                   f"{path!r} is in the tree but carries no rights status in "
                   f"the release manifest; rerun "
                   f"python scripts/build_release_manifest.py", path=path)
    # the per-path licence must follow the manifest's own documented rule
    rule = (committed.get("policy") or {}).get("licence_assignment_rule")
    if not rule:
        g.fail("POLICY_FRAMING_MISSING", MANIFEST_NAME,
               "the manifest does not state the rule that assigns a licence "
               "to each released path")
    for path, status in sorted(paths.items()):
        if status not in RELEASED_STATUSES:
            if path in licences:
                g.fail("RELEASE_LICENCE_MISMATCH", MANIFEST_NAME,
                       f"{path!r} is not released but carries a licence",
                       path=path)
            continue
        want = LICENCE_MIT if path.startswith(("scripts/", "tests/")) \
            else LICENCE_CC_BY
        if licences.get(path) != want:
            g.fail("RELEASE_LICENCE_MISMATCH", MANIFEST_NAME,
                   f"{path!r} is released with licence "
                   f"{licences.get(path)!r}; the manifest's own rule assigns "
                   f"{want!r}", path=path, expected=want,
                   observed=licences.get(path))
    # a released path's content must not contradict its declared status
    detail = recomputed.get("path_status_detail") or {}
    for path, status in sorted(paths.items()):
        if status not in RELEASED_STATUSES:
            continue
        ev = (detail.get(path) or {}).get("evidence") or {}
        longest = int(ev.get("longest_verbatim_span_chars") or 0)
        code_spans = int(ev.get("verbatim_code_spans") or 0)
        if ev.get("personal_data_strings"):
            g.fail("RELEASED_PATH_CONTAINS_PERSONAL_DATA", path,
                   f"the manifest releases this path, but it carries "
                   f"{ev['personal_data_strings']} string(s) with named "
                   f"individuals' mailbox addresses")
        if code_spans:
            g.fail("RELEASED_PATH_CONTAINS_COPIED_CONTENT", path,
                   f"the manifest releases this path, but it carries "
                   f"{code_spans} verbatim run(s) of third-party source "
                   f"code; the project's own policy never carries "
                   f"third-party code, not even a short quotation of it")
        elif longest > KEEP_QUOTE_MAX_CHARS:
            g.fail("RELEASED_PATH_CONTAINS_COPIED_CONTENT", path,
                   f"the manifest releases this path, but it carries a "
                   f"verbatim run of {longest} characters of third-party "
                   f"text, above the {KEEP_QUOTE_MAX_CHARS}-character "
                   f"attributed-quotation quota")
        if ev.get("verbatim_third_party_strings") and status in (
                "project_own", "metadata_only"):
            g.fail("RELEASED_PATH_STATUS_CONTRADICTION", path,
                   f"the manifest declares this path {status!r}, but the "
                   f"file carries {ev['verbatim_third_party_strings']} "
                   f"verbatim third-party quotation(s)")
    return committed


def grant_contradictions(g: Gate, manifest: dict, text: str, rel: str) -> list[dict]:
    """Grants in a document that contradict the release manifest."""
    if not (rel.endswith(PROSE_SUFFIXES) or rel == "LICENSE"):
        return []
    groups = manifest_groups(manifest)
    statuses = manifest.get("paths") or {}
    licences = manifest.get("path_licences") or {}
    out = []
    for para in paragraphs(text):
        granted = grant_licences(para)
        if not granted:
            continue
        for group in sorted(path_tokens(para)):
            covered = groups.get(group) or []
            if not covered:
                continue
            for path in covered:
                status = statuses.get(path)
                if status not in RELEASED_STATUSES:
                    out.append({"path": path, "group": group, "status": status,
                                "granted": sorted(granted),
                                "why": "the path is not released"})
                    break
                if licences.get(path) not in granted:
                    out.append({"path": path, "group": group, "status": status,
                                "granted": sorted(granted),
                                "why": f"the path is released under "
                                       f"{licences.get(path)!r}, which this "
                                       f"grant does not name"})
                    break
    return out


def repo_level_licence_claim(g: Gate, rel: str) -> str | None:
    """A whole-repository licence field (CITATION.cff, .zenodo.json)."""
    p = g.root / rel
    if not p.is_file():
        return None
    text = p.read_text(encoding="utf-8", errors="replace")
    if rel.endswith(".cff"):
        m = re.search(r"^license:\s*(\S+)\s*$", text, re.M)
        return m.group(1) if m else None
    try:
        doc = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None
    value = doc.get("license")
    return value if isinstance(value, str) else None


def check_licence_scope(g: Gate, manifest: dict) -> None:
    """LICENSE must state the release scope and must not over-grant."""
    p = g.root / "LICENSE"
    if not p.is_file():
        if not g.partial:
            g.fail("MISSING_DISTRIBUTION_ARTEFACT", "LICENSE",
                   "the licence is absent")
        return
    text = p.read_text(encoding="utf-8", errors="replace")
    low = collapse_text(text)
    if PHRASE_RELEASE_MANIFEST not in low:
        g.fail("LICENCE_MISSING_RELEASE_MANIFEST", "LICENSE",
               "the licence does not point at the release manifest, so it "
               "cannot state which paths are licensed")
    if PHRASE_RELEASED_SET not in low or PHRASE_NOT_LICENSED not in low:
        g.fail("LICENCE_MISSING_RELEASED_SET_RULE", "LICENSE",
               "the licence does not state the rule that a path outside the "
               "released set is not licensed here")
    if not any(p in low for p in PHRASE_NON_COVERAGE):
        g.fail("LICENCE_MISSING_NON_COVERAGE", "LICENSE",
               "the licence does not say that it does not cover the material "
               "it does not own")
    if not any(p in low for p in PHRASE_THIRD_PARTY):
        g.fail("LICENCE_MISSING_NON_COVERAGE", "LICENSE",
               "the licence does not name the third-party material it does "
               "not license")
    if not any(p in low for p in PHRASE_ATTRIBUTION_NOT_A_GRANT):
        g.fail("LICENCE_MISSING_ATTRIBUTION_NOT_A_GRANT", "LICENSE",
               "the licence does not say that attribution is not a "
               "redistribution right")
    for c in grant_contradictions(g, manifest, text, "LICENSE"):
        g.fail("LICENCE_GRANTS_OVER_WITHHELD_PATH", "LICENSE",
               f"the licence grants {c['granted']} over `{c['group']}`, but "
               f"{c['path']} is {c['status']!r} in the release manifest: "
               f"{c['why']}", path=c["path"], group=c["group"],
               granted=c["granted"])


def check_notice_scope(g: Gate, manifest: dict) -> None:
    p = g.root / "NOTICE.md"
    if not p.is_file():
        if not g.partial:
            g.fail("MISSING_DISTRIBUTION_ARTEFACT", "NOTICE.md",
                   "the notice is absent")
        return
    text = p.read_text(encoding="utf-8", errors="replace")
    low = collapse_text(text)
    if not any(phrase in low for phrase in PHRASE_ATTRIBUTION_NOT_A_GRANT):
        g.fail("NOTICE_MISSING_ATTRIBUTION_NOT_A_GRANT", "NOTICE.md",
               "the notice does not say that attribution is not a "
               "redistribution right")
    declared = {q.get("id") for q in (manifest.get("open_questions") or [])}
    mentioned = set(re.findall(r"\bOQ-\d{3}\b", text))
    if not mentioned:
        g.fail("NOTICE_MISSING_OPEN_QUESTIONS", "NOTICE.md",
               "the notice lists no open question, so the cases that need "
               "human legal review are not published")
    for oid in sorted(declared - mentioned):
        g.fail("NOTICE_OPEN_QUESTION_MISSING", "NOTICE.md",
               f"open question {oid} is declared in the release manifest but "
               f"is not listed in the notice")
    for oid in sorted(mentioned - declared):
        g.fail("NOTICE_OPEN_QUESTION_MISMATCH", "NOTICE.md",
               f"the notice lists {oid}, which the release manifest does not "
               f"declare")
    for c in grant_contradictions(g, manifest, text, "NOTICE.md"):
        g.fail("NOTICE_GRANTS_OVER_WITHHELD_PATH", "NOTICE.md",
               f"the notice grants {c['granted']} over `{c['group']}`, but "
               f"{c['path']} is {c['status']!r} in the release manifest: "
               f"{c['why']}", path=c["path"], group=c["group"],
               granted=c["granted"])
    # the attribution table must name every source the registry records
    reg = g.root / "distribution_v1" / "rights_source_registry.json"
    if reg.is_file():
        try:
            registry = json.loads(reg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for s in registry.get("sources") or []:
            sid = s.get("source_id")
            if sid and sid not in text:
                g.fail("NOTICE_ATTRIBUTION_MISSING", "NOTICE.md",
                       f"the notice does not attribute the source {sid!r}, "
                       f"which the rights registry records")


def check_publish_manifest_scope(g: Gate, manifest: dict) -> None:
    p = g.root / "publish_manifest.json"
    if not p.is_file():
        if not g.partial:
            g.fail("MISSING_DISTRIBUTION_ARTEFACT", "publish_manifest.json",
                   "the publish manifest is absent")
        return
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        g.fail("INVALID_JSON", "publish_manifest.json", str(exc))
        return
    if doc.get("release_manifest") != MANIFEST_NAME:
        g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
               "the publish manifest does not point at the release manifest",
               observed=doc.get("release_manifest"))
    if doc.get("release_manifest_version") != manifest.get("manifest_version"):
        g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
               "the publish manifest states a different release-manifest "
               "version than the manifest itself",
               expected=manifest.get("manifest_version"),
               observed=doc.get("release_manifest_version"))
    for key in ("covers_third_party_material", "legal_clearance_claimed",
                "attribution_is_not_a_right_grant",
                "hash_or_url_is_not_a_right_grant", "not_a_legal_clearance"):
        if key not in doc:
            g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
                   f"the publish manifest does not state {key!r}")
    if doc.get("covers_third_party_material") is not False:
        g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
               "the publish manifest claims it covers third-party material")
    if doc.get("legal_clearance_claimed") is not False:
        g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
               "the publish manifest claims a legal clearance")
    if doc.get("attribution_is_not_a_right_grant") is not True:
        g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
               "the publish manifest does not state that attribution is not a "
               "redistribution right")
    stated = doc.get("licences_of_released_paths") or {}
    known = set((manifest.get("licences") or {}).keys())
    for key, value in stated.items():
        if key == "note":
            continue
        if value not in known:
            g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
                   f"the publish manifest names the licence {value!r}, which "
                   f"the release manifest does not know", observed=value)
    for c in grant_contradictions(g, manifest, p.read_text(encoding="utf-8"),
                                  "publish_manifest.json"):
        g.fail("PUBLISH_MANIFEST_MISMATCH", "publish_manifest.json",
               f"the publish manifest grants {c['granted']} over "
               f"`{c['group']}`, but {c['path']} is {c['status']!r} in the "
               f"release manifest", path=c["path"])


def check_foreign_statements(g: Gate, manifest: dict) -> None:
    """Statements this remediation does not own must not over-grant silently.

    A contradiction in a document this remediation cannot edit is a declared
    open case: it is published in the manifest and in NOTICE.md, and the
    gate reports it.  A contradiction that is NOT declared is a failure: the
    statement would otherwise pass unnoticed.
    """
    declared_paths = set()
    for q in manifest.get("open_questions") or []:
        for path in q.get("paths") or []:
            declared_paths.add(path)
    statements = (manifest.get("shipped_rights_statements") or {}).get(
        "not_owned_by_this_remediation") or []
    for rel in statements:
        p = g.root / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        found = grant_contradictions(g, manifest, text, rel)
        claim = repo_level_licence_claim(g, rel)
        if claim and any(s not in RELEASED_STATUSES
                         for s in (manifest.get("paths") or {}).values()):
            found.append({"path": rel, "group": "(whole repository)",
                          "status": "repository-level licence claim",
                          "granted": [claim],
                          "why": "the manifest releases only part of the tree"})
        if not found:
            continue
        if rel in declared_paths:
            g.limits.append({
                "code": "DECLARED_OPEN_RIGHTS_CONTRADICTION",
                "artifact": rel,
                "detail": (f"{rel} still grants rights the release manifest "
                           f"does not support: "
                           + "; ".join(sorted({c['why'] + ' (' + c['path'] + ')'
                                               for c in found}))
                           + ". The contradiction is declared as an open "
                             "question and needs the document's owner to fix "
                             "the text; see NOTICE.md."),
            })
            continue
        for c in found:
            g.fail("UNDECLARED_RIGHTS_CONTRADICTION", rel,
                   f"{rel} grants {c['granted']} over {c['path']} "
                   f"({c['status']!r} in the release manifest) and the "
                   f"contradiction is not declared as an open question",
                   path=c["path"])


def check_inventory_agreement(g: Gate, manifest: dict) -> None:
    """The inventory must agree with the release manifest about the policy."""
    p = g.root / "reports" / "rights_inventory.json"
    if not p.is_file():
        return
    try:
        inv = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if inv.get("data_handling_policy_default") != POLICY_DEFAULT:
        g.fail("POLICY_FRAMING_MISSING", "reports/rights_inventory.json",
               "the inventory does not state METADATA_ONLY as its default "
               "data-handling policy")
    if inv.get("hash_grants_nothing") is None:
        g.fail("POLICY_FRAMING_MISSING", "reports/rights_inventory.json",
               "the inventory does not state that a hash grants nothing")
    reg = g.root / "distribution_v1" / "rights_source_registry.json"
    if reg.is_file():
        try:
            registry = json.loads(reg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if registry.get("data_handling_policy_default") != POLICY_DEFAULT:
            g.fail("POLICY_FRAMING_MISSING",
                   "distribution_v1/rights_source_registry.json",
                   "the registry does not state METADATA_ONLY as its default "
                   "data-handling policy")


# ---------------------------------------------------------------------------

def run(root: Path, partial: bool = False) -> tuple:
    g = Gate(root, partial)
    view = root / "distribution_v1"
    if view.is_dir():
        check_distribution_content(g, view)
        check_digests(g, view)
        check_upstream_hash_gap(g, view)
        check_hashes(g, view)
        check_counts(g, view)
    elif not partial:
        g.fail("MISSING_DISTRIBUTION_ARTEFACT", "distribution_v1/",
               "the versioned distribution-safe view does not exist; run "
               "python scripts/inventory_rights.py")
    check_licence_status(g)
    check_withheld_files_really_absent(g)
    check_claims_and_framing(g)
    manifest = check_release_manifest(g)
    if manifest is not None:
        check_licence_scope(g, manifest)
        check_notice_scope(g, manifest)
        check_publish_manifest_scope(g, manifest)
        check_foreign_statements(g, manifest)
        check_inventory_agreement(g, manifest)
    return (1 if g.reasons else 0), collapse(g.reasons), g.limits


def collapse(reasons: list[dict], threshold: int = 5) -> list[dict]:
    """One aggregated finding per (code, artifact) once a check repeats."""
    grouped: dict = {}
    for r in reasons:
        grouped.setdefault((r["code"], r["artifact"]), []).append(r)
    out = []
    for (code, artifact), rows in grouped.items():
        if len(rows) <= threshold:
            out.extend(rows)
            continue
        out.append({
            "code": code, "artifact": artifact,
            "count": len(rows),
            "detail": f"{len(rows)} findings of this kind; first few: "
                      + " || ".join(r["detail"] for r in rows[:3]),
            "examples": rows[:3],
        })
    return sorted(out, key=lambda r: (-r.get("count", 1), r["code"],
                                      r["artifact"]))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=("Fail on copied third-party content, contradictory "
                     "licence status, missing attribution, invalid hashes, "
                     "unsupportable rights claims and drifted counts in the "
                     "distribution artefacts."),
        epilog=("exit 0 = clean; exit 1 = at least one reason in the JSON "
                "reason list; exit 2 = the gate could not run"))
    ap.add_argument("--root", default=str(ROOT), help="repository root")
    ap.add_argument("--partial", action="store_true",
                    help="fixture mode: do not report artefacts that are "
                         "absent from a deliberately minimal tree")
    ap.add_argument("--json", action="store_true",
                    help="print only the machine-readable reason list")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"check_rights_consistency.py: no such root {root}",
              file=sys.stderr)
        return 2
    code, reasons, limits = run(root, args.partial)

    payload = {
        "generated_by": "scripts/check_rights_consistency.py",
        "rights_transformation_version": TRANSFORMATION_VERSION,
        # repo-relative marker, never an absolute machine path (see the
        # module docstring): artefact paths in every finding below are
        # relative to this checkout root.
        "root": ".",
        "path_style": "repo-relative-posix",
        "policy_default": POLICY_DEFAULT,
        "policy_is_default_not_clearance": True,
        "reasons": reasons,
        "noted_limitations": limits,
        "reason_count": len(reasons),
        "codes": sorted({r["code"] for r in reasons}),
        "exit_code": code,
    }
    if not args.json and not args.quiet:
        for r in reasons:
            print(f"  [FAIL] {r['code']} {r['artifact']}: {r['detail']}")
        if not reasons:
            print("  rights gate: no findings")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

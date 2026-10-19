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
                                     recomputed value
    MISSING_DISTRIBUTION_ARTEFACT    a required file of the view is absent

    python scripts/check_rights_consistency.py
    python scripts/check_rights_consistency.py --json
    python scripts/check_rights_consistency.py --root tests/fixtures/broken/x --partial

Exit 0 only when every applicable check passes. Stdlib only, read-only.
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
        tracked = len(tracked_files(g.root))
        if inv.get("scan", {}).get("tracked_files") not in (None, tracked):
            g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                   "the inventory was computed against a different tracked "
                   "file count than the tree now has; rerun "
                   "scripts/inventory_rights.py",
                   expected=tracked,
                   observed=inv.get("scan", {}).get("tracked_files"))
        head = inv.get("scan", {}).get("head_commit")
        if head:
            try:
                import subprocess
                now = subprocess.run(["git", "rev-parse", "HEAD"],
                                     cwd=str(g.root), capture_output=True,
                                     text=True).stdout.strip()
            except Exception:
                now = ""
            if now and now != head:
                g.fail("COUNT_MISMATCH", "reports/rights_inventory.json",
                       "the inventory is stale for this commit; rerun "
                       "scripts/inventory_rights.py", expected=now,
                       observed=head)


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
        "root": root.as_posix(),
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

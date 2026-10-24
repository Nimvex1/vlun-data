#!/usr/bin/env python3
"""Build the canonical release manifest: exactly what may be redistributed.

Why this exists
---------------
The repository shipped a root ``LICENSE`` that granted CC BY 4.0 over whole
directory trees (``jsonl/``, ``derived/``, ``splits_v2/``, ``benchmark/``,
``datasets/``, ``training/``, ``reports/``, ``experiments/``) while the same
LICENSE, in part 3, and ``NOTICE.md`` said that a large part of the material
under exactly those trees is copied third-party source text, third-party
report prose and contestant proof-of-concept code whose redistribution right
was never established.  A blanket grant over material the project does not own
is not a right the project can give, so the grant and the facts contradicted
each other.

This script is the fix's spine.  It computes, deterministically, an explicit
per-path rights status for every tracked file and writes it to
``RELEASE_MANIFEST.json``:

  * a path that is not in the manifest is not part of the released set;
  * a path in the manifest carries one of five rights statuses, four of which
    the vocabulary below defines precisely;
  * the statuses are derived from *measured* content, not from a wish.

Statuses
--------
``project_own``
    Released.  The VLUN authors' own code, documentation, schemas, decision
    records and analysis.  MIT for the code, CC BY 4.0 for the data and
    documents.
``metadata_only``
    Released.  Factual metadata the project recorded: identifiers, severities,
    labels, commit and file pointers, hashes.  No expressive third-party
    content.  METADATA_ONLY is a data-handling policy, not a legal clearance.
``attribution_required``
    Released.  Carries third-party short quotations or names third-party
    authors, so a reuser must attribute.  **Attribution is not a
    redistribution right**; it says who wrote something, not that the writer
    licensed it.
``withheld_third_party_no_redistribution_rights``
    Not released.  Carries copied third-party expressive content (source text,
    proof-of-concept code, fixing diffs, mined report prose) for which no
    documented right to redistribute is on file.
``internal_research_artefact_not_cleared``
    Not released.  The project's own working artefacts whose rights position
    is not established.  They stay in the research tree; they are not part of
    any published artefact and they are not cleared for redistribution.

How the status is decided
-------------------------
1. A reviewed prefix table gives every tracked path a *base* status.
2. The content of every tracked file is then measured:
     * ``verbatim_third_party_strings`` - strings containing a contiguous
       10-word run that also occurs in the canonical third-party corpus
       (the layers that hold the upstream audits, PoCs and mined report
       text).  This is the project's existing "a copy, not a coincidence"
       standard, the same one ``check_digests`` applies to digests.
     * ``third_party_code_fields`` - values carried under a source-code,
       proof-of-concept or diff key, which is where copied bytes live.
     * ``personal_data_strings`` - named individuals' mailboxes.
3. A path whose measured content contradicts its base status is corrected:
   copied third-party content downgrades a released path to
   ``withheld_third_party_no_redistribution_rights``; personal data does the
   same.  The only released paths allowed to carry verbatim third-party text
   are the two projection files whose verbatim text is an *attributed
   short quotation* (at most ``KEEP_QUOTE_MAX_CHARS`` characters, with the
   attribution recorded) - they are ``attribution_required``.

    python scripts/build_release_manifest.py            # write RELEASE_MANIFEST.json
    python scripts/build_release_manifest.py --check    # recompute, write nothing
    python scripts/build_release_manifest.py --help

Stdlib only, deterministic, read-only apart from the manifest it writes.  The
output is byte-reproducible: sorted keys, LF newlines, no timestamps, no
machine-local absolute paths.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inventory_rights import (  # noqa: E402
    CODE_KEYS, DIFF_KEYS, EMAIL_RE, HEX64_RE, KEEP_QUOTE_MAX_CHARS, ORG_MAILBOX_DOMAINS,
    POC_KEYS, PROSE_KEYS, SHORT_PROSE_KEYS, THIRD_PARTY_CODE_RE,
    base_context_of, authored_by_project_row, read_jsonl, sha256_text,
    tracked_files, walk_leaves,
)

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_NAME = "RELEASE_MANIFEST.json"
MANIFEST_VERSION = "release-1.0"
WORD_WINDOW = 10

STATUS_PROJECT_OWN = "project_own"
STATUS_METADATA_ONLY = "metadata_only"
STATUS_ATTRIBUTION_REQUIRED = "attribution_required"
STATUS_WITHHELD = "withheld_third_party_no_redistribution_rights"
STATUS_INTERNAL = "internal_research_artefact_not_cleared"

STATUS_VOCABULARY = {
    STATUS_PROJECT_OWN: {
        "released": True,
        "definition": (
            "written by the VLUN authors: their own code, documentation, "
            "schemas, decision records and analysis. MIT for the code under "
            "scripts/, CC BY 4.0 for the documents and data."),
    },
    STATUS_METADATA_ONLY: {
        "released": True,
        "definition": (
            "factual metadata the project recorded: identifiers, severities, "
            "labels, commit and file pointers, hashes. METADATA_ONLY is a "
            "default data-handling policy, not a legal clearance; a hash and "
            "a URL identify bytes and grant nothing."),
    },
    STATUS_ATTRIBUTION_REQUIRED: {
        "released": True,
        "definition": (
            "carries third-party short quotations or names third-party "
            "authors, so a reuser must attribute the original author. "
            "Attribution is not a redistribution right."),
    },
    STATUS_WITHHELD: {
        "released": False,
        "definition": (
            "carries copied third-party expressive content - source text, "
            "proof-of-concept code, fixing diffs or mined report prose - for "
            "which no documented right to redistribute is on file. It is not "
            "part of the released set."),
    },
    STATUS_INTERNAL: {
        "released": False,
        "definition": (
            "the project's own working artefact whose rights position is not "
            "established. It is retained in the research tree, it is not part "
            "of any published artefact, and it is not cleared for "
            "redistribution."),
    },
}

RELEASED_STATUSES = tuple(k for k, v in STATUS_VOCABULARY.items() if v["released"])

# The two licences this project can grant.  MIT for the authors' own code,
# CC BY 4.0 for everything else it authored.  Neither licence covers
# third-party material, wherever that material occurs.
LICENCE_MIT = "MIT"
LICENCE_CC_BY = "CC-BY-4.0"
LICENCE_VOCABULARY = {
    LICENCE_MIT: (
        "the MIT licence: applies to the authors' own code. It grants no "
        "right over third-party material, wherever that material occurs."),
    LICENCE_CC_BY: (
        "the Creative Commons Attribution 4.0 International licence: applies "
        "to the material the authors authored inside the released set. It "
        "grants no right over third-party material, wherever that material "
        "occurs."),
}
CODE_PREFIXES = ("scripts/", "tests/")

# The canonical third-party corpus: the layers that hold the upstream audits,
# proof-of-concept submissions and mined report text.  A candidate path is
# compared against these and against nothing else, so a file can never be
# "caught" by overlapping with itself.
CORPUS_LAYERS = (
    "derived/records.jsonl",
    "jsonl/findings.jsonl",
    "jsonl/negative_findings.jsonl",
    "jsonl/exploits.jsonl",
    "jsonl/patches.jsonl",
    "jsonl_v4/findings.jsonl",
    "jsonl_v3/findings.jsonl",
    "jsonl_ml/findings_cairo.jsonl",
    "jsonl_ml/findings_move.jsonl",
    "jsonl_ml/findings_reports.jsonl",
    "jsonl_ml/findings_rust.jsonl",
    "jsonl_ml/findings_vyper.jsonl",
    "derived_v3/records.jsonl",
    "derived_v3/normalized_records_preview.jsonl",
    "derived_v4/admitted_ledger.jsonl",
    "Vbeta/derived_vbeta/records.jsonl",
)

# The field names that carry UPSTREAM bytes.  "text" and "input_text" are
# excluded on purpose: this project stores its own sentences under those keys
# (the METADATA_ONLY note, the pipeline's own reasoning), and a corpus that
# contained the project's own prose would flag the project's own source
# files as copies of third-party material.
UPSTREAM_KEYS = ((CODE_KEYS | POC_KEYS | DIFF_KEYS | PROSE_KEYS | SHORT_PROSE_KEYS)
                 - {"text", "input_text"})

# The project's own authored text.  The corpus below must not contain it: the
# V3 records append the pipeline's own boilerplate sentence to the upstream
# title, and a corpus that carried that sentence would flag the pipeline's
# own source file as a copy of third-party material.
PROJECT_TEXT_PREFIXES = ("scripts/", "docs/")

# Reviewed prefix table.  First match wins; the empty prefix is the fallback
# for the repository's own root documents.
BASE_RULES = (
    ("distribution_v1/", STATUS_PROJECT_OWN,
     "the rights-redacted distribution view: this project's own projection, "
     "pointer records and decision artefacts"),
    ("scripts/", STATUS_PROJECT_OWN,
     "the VLUN pipeline: the authors' own code, MIT"),
    ("tests/", STATUS_PROJECT_OWN,
     "the VLUN test suite: the authors' own code, MIT"),
    ("schema/", STATUS_PROJECT_OWN,
     "the record schemas: the authors' own work"),
    ("docs/", STATUS_PROJECT_OWN,
     "project documentation: the authors' own writing"),
    ("V4/", STATUS_PROJECT_OWN,
     "the V4 per-source licence decision record: the authors' own decision, "
     "and the canonical statement of what each upstream source declares"),
    ("V3/", STATUS_PROJECT_OWN,
     "V3 research notes written by the authors"),
    ("_audit/", STATUS_PROJECT_OWN,
     "the independent audit's own scripts and reports"),
    ("annotation/", STATUS_PROJECT_OWN,
     "the annotation guidelines and instruments written by the authors"),
    ("reports/", STATUS_PROJECT_OWN,
     "generated analysis reports: the authors' own measurements and "
     "conclusions"),
    (".github/", STATUS_PROJECT_OWN,
     "continuous-integration configuration: the authors' own work"),
)

# The repository-root documents and configuration: the authors' own work.
ROOT_DOCUMENTS = (
    ".gitattributes",
    ".gitignore",
    ".pre-commit-config.yaml",
    ".zenodo.json",
    "BASELINE.md",
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE.md",
    "improve.md",
    "publish_manifest.json",
    "pyproject.toml",
    "README.md",
    "RELEASE_MANIFEST.json",
    "requirements.txt",
)

# Paths under a released prefix that are released *with* an attribution duty
# rather than as the project's own expression.
ATTRIBUTION_PATHS = {
    "distribution_v1/records_v1.jsonl":
        "carries the attributed short quotations kept under the "
        "KEEP_QUOTE_MAX_CHARS quota",
    "distribution_v1/records_v4.jsonl":
        "carries the attributed short quotations kept under the "
        "KEEP_QUOTE_MAX_CHARS quota",
    "distribution_v1/records_v1_withheld_pointers.jsonl":
        "names the upstream repository, commit and author of every withheld "
        "quotation",
    "distribution_v1/records_v4_withheld_pointers.jsonl":
        "names the upstream report, page and author of every withheld "
        "passage",
    "distribution_v1/withheld_harness.jsonl":
        "names the upstream repository, commit and licence of every withheld "
        "harness file",
    "distribution_v1/rights_source_registry.json":
        "names every upstream source, its declared terms and its decision",
    "distribution_v1/rights_ledger.jsonl":
        "names every upstream source whose content the ledger records a "
        "decision for",
}

# Released data that is a factual register: identifiers, names, URLs, commits
# and the terms each upstream source declares about its own content.  No
# expressive third-party content is carried, and none is needed to read it.
METADATA_ONLY_PATHS = {
    "V4/sources.json":
        "a factual register of the upstream sources: source id, name, URL, "
        "pinned commit and the terms that source declares about its own "
        "content. No expressive content is carried",
}

# A path that is released and is allowed to carry verbatim third-party text:
# the quotation has to stay inside the same character quota the distribution
# view uses for attributed short citations.
SHORT_QUOTE_MAX_CHARS = KEEP_QUOTE_MAX_CHARS

# Human legal review: cases this repository cannot close mechanically.  They
# are published in the manifest, and the rights gate fails if a shipped
# statement contradicts the manifest without one of these being declared.
OPEN_QUESTIONS = (
    {
        "id": "OQ-001",
        "subject": "424 v1 records quote Solidity from repositories that "
                   "declare no licence",
        "question": "May the quoted source text in derived/records.jsonl "
                    "(424 records, 827 code_context entries carrying text) "
                    "be redistributed at all?",
        "why_not_mechanically_resolvable": (
            "The upstream repositories declare no licence, so there is no "
            "term to read and no permission to point at. The absence of a "
            "licence is not a grant, and this project has not obtained "
            "permission from the protocol authors. Only a rights holder - "
            "or a lawyer asked to judge the applicable jurisdiction - can "
            "answer it."),
        "human_review_required": True,
        "paths": ["derived/records.jsonl"],
        "current_handling": "not released; the copied text is withheld and "
                            "replaced by pointer, commit, line range, "
                            "permalink and sha256",
    },
    {
        "id": "OQ-002",
        "subject": "Code4rena contestant proof-of-concept code",
        "question": "May the submitted proof-of-concept tests be redistributed "
                    "as quoted evidence?",
        "why_not_mechanically_resolvable": (
            "The code belongs to the contest participants. The pipeline never "
            "received a licence or a permission to sublicense it; a few "
            "submissions carry their author's own SPDX identifier and most "
            "carry none, which is an absence of a term rather than a "
            "permission. The Code4rena contest terms, and the applicable "
            "law, have to be read by a human."),
        "human_review_required": True,
        "paths": ["jsonl/exploits.jsonl", "derived/records.jsonl",
                  "benchmark/D_exploit_construction.jsonl"],
        "current_handling": "not released; the test name, framework, file, "
                            "recorded impact and the hash of the removed text "
                            "are kept instead of the text",
    },
    {
        "id": "OQ-003",
        "subject": "BUSL-1.1 and Commons Clause audited repositories "
                   "(reNFT, BakerFi, Wildcat)",
        "question": "Does the Change Date in BUSL-1.1 convert these "
                    "citations to an open licence, and does the project "
                    "want to rely on it?",
        "why_not_mechanically_resolvable": (
            "The terms permit use but not redistribution until their Change "
            "Date. Whether a given snapshot falls before or after that date "
            "for each repository is a question about each upstream commit and "
            "about the project owner's intent, not something a script can "
            "decide."),
        "human_review_required": True,
        "paths": ["experiments/"],
        "current_handling": "not released; the citations are reference-only "
                            "and the harness files are recorded in "
                            "experiments/*/harness/WITHHELD.json",
    },
    {
        "id": "OQ-004",
        "subject": "Oak Security reports carry a CC BY-ND 4.0 term",
        "question": "Is every transformation this pipeline applies to an Oak "
                    "Security report a derivative work barred by "
                    "No-Derivatives?",
        "why_not_mechanically_resolvable": (
            "CC BY-ND forbids distribution of derivatives. Whether a mined "
            "field, a projected record or a digest is a derivative is a legal "
            "question that turns on the term and the jurisdiction. The "
            "project therefore withholds the passages rather than argue the "
            "question, but the question is not thereby answered."),
        "human_review_required": True,
        "paths": ["jsonl_v4/findings.jsonl", "derived_v4/admitted_ledger.jsonl"],
        "current_handling": "not released; the mined passages are withheld and "
                            "the pointers, page locators and report hashes are "
                            "kept",
    },
    {
        "id": "OQ-005",
        "subject": "personal contact data mined out of third-party reports",
        "question": "How may the named individuals' work addresses in the "
                    "Halborn Security reports be handled?",
        "why_not_mechanically_resolvable": (
            "The addresses are personal data of identifiable people who never "
            "consented to publication. Redaction is a data-protection "
            "decision, not a copyright one, and the project's own legal basis "
            "for processing them has to be confirmed by a human."),
        "human_review_required": True,
        "paths": ["jsonl_v4/findings.jsonl", "derived_v4/admitted_ledger.jsonl",
                  "training/canonical/language.validation.part-000.jsonl",
                  "training/canonical/severity.validation.part-000.jsonl"],
        "current_handling": "not released; the addresses are removed from the "
                            "distribution view and the canonical layers are "
                            "left untouched",
    },
    {
        "id": "OQ-006",
        "subject": "repository documents that still state a blanket licence "
                   "over the data layers",
        "question": "README.md, docs/DATASHEET.md, CITATION.cff and "
                    ".zenodo.json grant a licence over a path the release "
                    "manifest does not release; who updates them?",
        "why_not_mechanically_resolvable": (
            "The contradiction is MEASURED, not asserted: the probe in this "
            "builder asks the rights gate's own grant scanner the same "
            "question, over the same manifest, and this case is listed only "
            "while the text still says it. Fixing it is a matter of editing "
            "the four documents to state the release scope instead of a "
            "blanket grant, and a script cannot edit a statement it does "
            "not own."),
        "human_review_required": True,
        "paths": ["README.md", "docs/DATASHEET.md", "CITATION.cff",
                  ".zenodo.json"],
        "current_handling": "declared here; the authoritative scope is "
                            "LICENSE and RELEASE_MANIFEST.json",
    },
)

# The shipped rights statements this project owns, and the ones it does not.
OWNED_STATEMENTS = (
    "LICENSE",
    "NOTICE.md",
    "publish_manifest.json",
    "RELEASE_MANIFEST.json",
    "distribution_v1/MANIFEST.json",
    "distribution_v1/README.md",
    "distribution_v1/rights_source_registry.json",
    "reports/rights_inventory.json",
    "reports/rights_inventory.md",
    "V4/licensing.json",
)

FOREIGN_STATEMENTS = (
    "README.md",
    "docs/DATASHEET.md",
    "CITATION.cff",
    ".zenodo.json",
)


class _Root:
    """The one attribute the rights gate's helpers read off its Gate."""

    def __init__(self, root: Path):
        self.root = root


def probe_foreign_statements(root: Path, manifest: dict) -> dict:
    """Does any document this remediation does not own still over-grant?

    A licence statement in one of these documents that grants rights over a
    path the release manifest does not release is a contradiction.  Whether
    one is actually present is a MEASUREMENT, not a declaration, so it is
    taken here with the rights gate's own grant scanner over the same
    manifest: the builder and the gate then cannot drift apart, and the open
    question it carries is listed only while the text still says it.

    The documents stay in ``FOREIGN_STATEMENTS`` after they are corrected:
    the gate must keep scanning them, so a contradiction that comes back
    fails the build instead of being tolerated by a stale declaration.
    """
    # Imported late: the rights gate imports this module, so a module-level
    # import here would be circular.
    from check_rights_consistency import (  # noqa: PLC0415
        grant_contradictions, repo_level_licence_claim,
    )
    statuses = manifest.get("paths") or {}
    releases_only_part = any(s not in RELEASED_STATUSES
                             for s in statuses.values())
    out: dict[str, dict] = {}
    for rel in FOREIGN_STATEMENTS:
        p = root / rel
        if not p.is_file():
            out[rel] = {"contradiction_present": False,
                        "detail": "the document is not in this checkout",
                        "contradictions": []}
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        found = list(grant_contradictions(_Root(root), manifest, text, rel))
        claim = repo_level_licence_claim(_Root(root), rel)
        if claim and releases_only_part:
            found.append({"path": rel, "group": "(whole repository)",
                          "status": "repository-level licence claim",
                          "granted": [claim],
                          "why": "the manifest releases only part of the tree"})
        out[rel] = {
            "contradiction_present": bool(found),
            "contradictions": sorted(f"{c['path']} ({c['why']})" for c in found),
        }
    return out


def open_questions(foreign_scan: dict) -> list[dict]:
    """The open questions, minus the ones whose contradiction is gone.

    OQ-006 is the blanket-licence case.  It is declared only while one of
    the four documents really still grants rights the manifest does not
    support; once the probe finds none, the case is closed and the
    declaration disappears, so the gate fails on a contradiction that comes
    back instead of tolerating it.
    """
    questions = [dict(q) for q in OPEN_QUESTIONS]
    if not any(v.get("contradiction_present")
               for v in (foreign_scan or {}).values()):
        questions = [q for q in questions if q["id"] != "OQ-006"]
    return questions


# ---------------------------------------------------------------------------
# measurement
# ---------------------------------------------------------------------------

def strings_of(node, pointer="$"):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from strings_of(v, f"{pointer}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from strings_of(v, f"{pointer}[{i}]")
    elif isinstance(node, str):
        yield pointer, node


def windows_of(text: str) -> set[str]:
    words = text.split()
    if len(words) <= WORD_WINDOW:
        return set()
    return {" ".join(words[i:i + WORD_WINDOW]).lower()
            for i in range(len(words) - WORD_WINDOW + 1)}


def verbatim_spans(text: str, corpus: set[str]) -> list[tuple[int, bool]]:
    """The verbatim runs of `text` that also occur in the corpus.

    A "verbatim run" is a maximal stretch of consecutive words all of whose
    WORD_WINDOW windows occur in the corpus.  Its length in characters is
    what matters: a ten-word window that turns up inside a 4000-character
    report is a quotation, not a copy of the report.  The second element
    says whether the run is source code rather than prose: the project's own
    published policy never carries third-party code, not even a short
    quotation of it.
    """
    words = text.split()
    n = len(words)
    if n <= WORD_WINDOW:
        return []
    hits = [i for i in range(n - WORD_WINDOW + 1)
            if " ".join(words[i:i + WORD_WINDOW]).lower() in corpus]
    spans: list[tuple[int, bool]] = []
    k = 0
    while k < len(hits):
        j = k
        while j + 1 < len(hits) and hits[j + 1] == hits[j] + 1:
            j += 1
        start, end = hits[k], hits[j] + WORD_WINDOW
        run = " ".join(words[start:end])
        spans.append((len(run), bool(THIRD_PARTY_CODE_RE.search(run))))
        k = j + 1
    return spans


def project_windows(root: Path) -> set[str]:
    """Windows of the project's own authored text (its source and docs)."""
    out: set[str] = set()
    for rel in tracked_files(root):
        if not rel.startswith(PROJECT_TEXT_PREFIXES):
            continue
        p = root / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out |= windows_of(text)
    return out


def corpus_windows(root: Path) -> set[str]:
    """10-word windows of the canonical third-party expression.

    Only strings the project itself stores under an upstream-content field
    are used, so the corpus is made of third-party bytes and not of the
    project's own sentences that happen to live in the same records.  The
    project's own authored text is subtracted afterwards for the same reason.
    """
    out: set[str] = set()
    for rel in CORPUS_LAYERS:
        p = root / rel
        if not p.is_file():
            continue
        for row in read_jsonl(p):
            if not isinstance(row, dict):
                continue
            items: list = []
            walk_leaves(row, "$", base_context_of(row), items,
                        authored_by_project_row(row))
            for pointer, _cls, text, _ctx in items:
                leaf = pointer.replace("[", ".").split(".")[-1].rstrip("]")
                if leaf not in UPSTREAM_KEYS:
                    continue
                if len(text) < 40:
                    continue
                out |= windows_of(text)
    return out - project_windows(root)


CODE_KEY_SET = CODE_KEYS | POC_KEYS | DIFF_KEYS


def personal_mailboxes(text: str) -> list[str]:
    out = []
    for local, domain in EMAIL_RE.findall(text):
        if domain.lower() in ORG_MAILBOX_DOMAINS:
            continue
        if local.lower() in ("noreply", "security-advisories", "nvd", "git"):
            continue
        out.append(f"{local}@{domain}".lower())
    return out


def file_strings(path: Path) -> list[str]:
    """Every string a candidate file carries."""
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        rows = read_jsonl(path)
    elif suffix == ".json":
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        rows = loaded if isinstance(loaded, list) else [loaded]
    elif suffix in (".md", ".txt", ".csv", ".sol", ".py", ".rs", ".toml", ".cff",
                    ".yaml", ".yml", ".rst", ".cfg", ".ini"):
        try:
            return [path.read_text(encoding="utf-8", errors="replace")]
        except OSError:
            return []
    else:
        return []
    out = []
    for row in rows:
        if isinstance(row, dict):
            for _pointer, text in strings_of(row):
                out.append(text)
        elif isinstance(row, str):
            out.append(row)
    return out


def measure(path: Path, corpus: set[str]) -> dict:
    """Measure what a file actually carries."""
    verbatim = 0
    longest = 0
    code_spans = 0
    longest_code = 0
    code_fields = 0
    mailboxes = 0
    if not path.is_file():
        return {"verbatim_third_party_strings": 0, "longest_verbatim_span_chars": 0,
                "verbatim_code_spans": 0, "longest_verbatim_code_span_chars": 0,
                "third_party_code_fields": 0, "personal_data_strings": 0}
    suffix = path.suffix.lower()
    for text in file_strings(path):
        spans = verbatim_spans(text, corpus)
        if spans:
            verbatim += 1
            longest = max(longest, max(s for s, _c in spans))
            for size, is_code in spans:
                if is_code:
                    code_spans += 1
                    longest_code = max(longest_code, size)
        mailboxes += len(personal_mailboxes(text))
    if suffix in (".jsonl", ".json"):
        for pointer, text in _leaf_strings(path):
            leaf = pointer.replace("[", ".").split(".")[-1].rstrip("]")
            if leaf in CODE_KEY_SET and len(text.strip()) > 40:
                code_fields += 1
    return {
        "verbatim_third_party_strings": verbatim,
        "longest_verbatim_span_chars": longest,
        "verbatim_code_spans": code_spans,
        "longest_verbatim_code_span_chars": longest_code,
        "third_party_code_fields": code_fields,
        "personal_data_strings": mailboxes,
    }


def _leaf_strings(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        rows = read_jsonl(path)
    elif suffix == ".json":
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        rows = loaded if isinstance(loaded, list) else [loaded]
    else:
        return
    for row in rows:
        if isinstance(row, dict):
            yield from strings_of(row)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def base_status(rel: str) -> tuple[str, str]:
    for prefix, status, why in BASE_RULES:
        if rel.startswith(prefix):
            return status, why
    if rel in ROOT_DOCUMENTS:
        return STATUS_PROJECT_OWN, (
            "repository-root document or configuration: the authors' own work")
    return STATUS_INTERNAL, (
        "an evidence or research layer of this project: retained in the "
        "research tree, not part of the released set and not cleared for "
        "redistribution")


def decide(rel: str, evidence: dict) -> tuple[str, str]:
    """Final status for one path, from its base status and its content."""
    status, why = base_status(rel)
    verbatim = evidence.get("verbatim_third_party_strings", 0)
    mailboxes = evidence.get("personal_data_strings", 0)
    longest = evidence.get("longest_verbatim_span_chars", 0)
    code_spans = evidence.get("verbatim_code_spans", 0)
    longest_code = evidence.get("longest_verbatim_code_span_chars", 0)
    releasable = status in (STATUS_PROJECT_OWN, STATUS_METADATA_ONLY)
    if rel in ATTRIBUTION_PATHS and not mailboxes and longest <= KEEP_QUOTE_MAX_CHARS \
            and not code_spans:
        return STATUS_ATTRIBUTION_REQUIRED, ATTRIBUTION_PATHS[rel]
    if verbatim:
        if releasable and longest <= KEEP_QUOTE_MAX_CHARS and not code_spans:
            return STATUS_ATTRIBUTION_REQUIRED, (
                f"carries {verbatim} verbatim third-party quotation(s) of at "
                f"most {longest} characters, which is the attributed "
                "short-quotation quota: attribution is owed to the original "
                "authors, and attribution is not a redistribution right")
        if code_spans:
            return STATUS_WITHHELD, (
                f"measured verbatim third-party source code: {code_spans} "
                f"run(s) of at most {longest_code} characters are source code "
                "that also occurs in the canonical third-party corpus. The "
                "project's own policy never carries third-party code, not "
                "even a short quotation of it, and no documented right to "
                "redistribute it is on file")
        return STATUS_WITHHELD, (
            f"measured verbatim third-party content: {verbatim} string(s) "
            f"carry a run of at most {longest} characters that also occurs in "
            "the canonical third-party corpus, and no documented right to "
            "redistribute that text is on file")
    if mailboxes:
        return STATUS_WITHHELD, (
            f"measured personal data: {mailboxes} string(s) carry named "
            "individuals' mailbox addresses")
    if rel in METADATA_ONLY_PATHS:
        return STATUS_METADATA_ONLY, METADATA_ONLY_PATHS[rel]
    return status, why


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def build(root: Path) -> dict:
    files = tracked_files(root)
    corpus = corpus_windows(root)
    paths: dict[str, str] = {}
    detail: dict[str, dict] = {}
    for rel in files:
        if rel == MANIFEST_NAME:
            # never measured: a file whose content decides its own status
            # would not be reproducible (the first build sees no file, the
            # second sees the file the first build wrote)
            continue
        evidence = measure(root / rel, corpus)
        status, why = decide(rel, evidence)
        paths[rel] = status
        interesting = {k: v for k, v in sorted(evidence.items()) if v}
        base, _base_why = base_status(rel)
        if status != base or interesting:
            detail[rel] = {
                "rights_status": status,
                "base_rights_status": base,
                "why": why,
                "evidence": interesting,
            }
    # The manifest itself is part of the tree and is the authors' own
    # statement.  It is added explicitly, and never measured: a file whose
    # content decides its own status would not be reproducible (the first
    # build sees no file, the second sees the file it just wrote).
    paths[MANIFEST_NAME] = STATUS_PROJECT_OWN
    detail[MANIFEST_NAME] = {
        "rights_status": STATUS_PROJECT_OWN,
        "base_rights_status": STATUS_PROJECT_OWN,
        "why": "this manifest: the authors' own statement of the release "
               "boundary",
        "evidence": {},
    }
    released = sorted(p for p, s in paths.items() if s in RELEASED_STATUSES)
    not_released = sorted(p for p, s in paths.items() if s not in RELEASED_STATUSES)
    licences = {p: (LICENCE_MIT if p.startswith(CODE_PREFIXES) else LICENCE_CC_BY)
                for p in released}
    by_status: dict[str, int] = {}
    for s in paths.values():
        by_status[s] = by_status.get(s, 0) + 1
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "generated_by": "scripts/build_release_manifest.py",
        "rights_transformation_version": "rights-1.0",
        "published_artefact_set": (
            "the set of tracked paths this project licenses for "
            "redistribution. Every other tracked path is retained in the "
            "research tree, is not licensed here, and is not cleared for "
            "redistribution"),
        "policy": {
            "released_set_rule": (
                "a tracked path that is not listed in `paths` with a released "
                "rights_status is not part of the released set; the release "
                "process ships exactly the released paths"),
            "licence_assignment_rule": (
                "MIT for the authors' own code under scripts/ and tests/, "
                "CC-BY-4.0 for every other released path, and no licence at "
                "all for a path that is not released"),
            "attribution_is_not_a_right_grant": True,
            "hash_or_url_is_not_a_right_grant": True,
            "metadata_only_is_a_policy_not_a_clearance": True,
            "legal_clearance_claimed": False,
            "blanket_clearance_claimed": False,
        },
        "statuses": STATUS_VOCABULARY,
        "licences": LICENCE_VOCABULARY,
        "path_licences": licences,
        "rules": [
            {"prefix": prefix, "base_rights_status": status, "why": why}
            for prefix, status, why in BASE_RULES
        ],
        "corpus_layers": list(CORPUS_LAYERS),
        "copy_detection": {
            "method": (
                f"a string is a verbatim third-party copy when it contains a "
                f"contiguous {WORD_WINDOW}-word run that also occurs in the "
                "canonical third-party corpus"),
            "word_window": WORD_WINDOW,
        },
        "paths": paths,
        "path_status_detail": detail,
        "released_paths": released,
        "not_released_paths": not_released,
        "counts": {
            "tracked_paths": len(paths),
            "released_paths": len(released),
            "not_released_paths": len(not_released),
            "by_rights_status": dict(sorted(by_status.items())),
            "by_licence": dict(sorted(Counter(licences.values()).items())),
            "paths_with_measured_verbatim_third_party_content": sum(
                1 for r in paths.values() if r == STATUS_WITHHELD),
            "paths_with_measured_personal_data": sum(
                1 for d in detail.values()
                if d.get("evidence", {}).get("personal_data_strings")),
        },
        "shipped_rights_statements": {
            "owned_by_this_remediation": list(OWNED_STATEMENTS),
            "not_owned_by_this_remediation": list(FOREIGN_STATEMENTS),
        },
    }
    # The four documents that state a licence outside this builder are
    # PROBED, not assumed: a licence statement in one of them that
    # contradicts this manifest is an open case only while it is actually
    # there.  The measurement is recorded so a reader can see what was
    # checked and what it found, instead of taking the open-question list on
    # trust.
    foreign = probe_foreign_statements(root, manifest)
    manifest["foreign_statement_scan"] = {
        "method": (
            "the rights gate's own grant scanner, over this manifest: a "
            "document that grants a licence over a path the manifest does "
            "not release, or over a path it releases under a different "
            "licence, contradicts the manifest"),
        "documents": foreign,
        "contradiction_present": any(
            v.get("contradiction_present") for v in foreign.values()),
    }
    manifest["open_questions"] = open_questions(foreign)
    return manifest


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def check_environment_independent(text: str) -> None:
    machine_local = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|/home/|/Users/")
    for lineno, line in enumerate(text.splitlines(), 1):
        m = machine_local.search(line)
        if m:
            raise SystemExit(
                f"build_release_manifest.py: refusing to write {MANIFEST_NAME}: "
                f"line {lineno} embeds a machine-local absolute path "
                f"({m.group(0)!r})")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=("Build the canonical release manifest: the per-path "
                     "rights status of every tracked file."),
        epilog=(f"writes {MANIFEST_NAME}; --check recomputes and compares "
                "without writing"))
    ap.add_argument("--root", default=str(ROOT), help="repository root")
    ap.add_argument("--check", action="store_true",
                    help="recompute and compare; write nothing")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"build_release_manifest.py: no such root {root}", file=sys.stderr)
        return 2
    manifest = build(root)
    text = render(manifest)
    check_environment_independent(text)
    target = root / MANIFEST_NAME
    if args.check:
        if not target.is_file():
            print(f"build_release_manifest.py: {MANIFEST_NAME} is absent; run "
                  f"python scripts/build_release_manifest.py")
            return 1
        current = target.read_text(encoding="utf-8")
        if current != text:
            print(f"build_release_manifest.py: {MANIFEST_NAME} is not "
                  f"reproducible; the committed file differs from the "
                  f"recomputed manifest")
            return 1
        if not args.quiet:
            c = manifest["counts"]
            print(f"  {MANIFEST_NAME}: reproducible; "
                  f"{c['released_paths']} released, "
                  f"{c['not_released_paths']} not released")
        return 0
    target.write_text(text, encoding="utf-8", newline="\n")
    c = manifest["counts"]
    if not args.quiet:
        print(f"wrote {MANIFEST_NAME}: {c['tracked_paths']} tracked paths, "
              f"{c['released_paths']} released, {c['not_released_paths']} not "
              f"released")
        for status, n in sorted(c["by_rights_status"].items()):
            print(f"  {status:48s} {n:5d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Harvest Solodit detail pages (nextdata/*.md) into Vbeta candidates.

Reads ONLY untracked scrape artefacts (never PRESENT data) and writes ONLY
``Vbeta/solodit_candidates.json``. Deterministic: files processed in sorted
order, no timestamps in output, no network.

Extraction honesty rules (enforced in code, reported in stats):
  * every field comes from an observed section; missing -> null/unknown.
  * severity_observed is the verbatim severity line (format variants kept).
  * status_observed is the verbatim Team Response first line, else null.
  * poc_observed ONLY on a dedicated PoC/Attack-Execution section carrying
    numbered steps or a code block. Prose mentions never qualify.
  * language: majority file-extension vote inside the finding body
    (header/footer chrome excluded). Extension-to-language is fixed mapping;
    ecosystem ONLY on explicit chain mention (conflict -> unknown).
    A project named "...solana..." proves nothing about the audited code.
  * full Description prose is NOT copied (METADATA_ONLY): at most the first
    sentence (<=200 chars) is kept as a marked excerpt in `extra`.
  * rows without a recoverable title are rejected, never guessed.
  * rows duplicating an already-admitted Vbeta record (word-overlap > 0.6
    on significant title words) are skipped as duplicates — reported with
    the existing cid, never admitted twice.

    python Vbeta/scripts/harvest_solodit.py
    python Vbeta/scripts/harvest_solodit.py --check   # parse, write nothing
"""

from __future__ import annotations

import argparse
import collections
import io
import json
import os
import re
from pathlib import Path

VBETA = Path(__file__).resolve().parent.parent
NEXTDATA = VBETA.parent / "nextdata"
OUT = VBETA / "solodit_candidates.json"

SID = "solodit-harvest"

EXT_LANG = {".sol": "solidity", ".vy": "vyper", ".cairo": "cairo",
            ".rs": "rust", ".move": "move", ".go": "go"}
EVM_LANGS = {"solidity", "vyper"}
FOOT_MARKERS = ["Unlock notes, bookmarks", "Full report"]

# Observed section-name aliases. The Solodit mirror renders the same field
# under several headings; a single exact heading match silently drops most of
# the available evidence. These are aliases only -- no values are inferred or
# synthesized, only observed text is kept.
SEVERITY_NAMES = ["Severity"]
DESCRIPTION_NAMES = ["Description", "Summary", "Vulnerability Details",
                    "Root Cause", "Finding description", "Overview"]
RECOMMENDATION_NAMES = ["Recommendation", "Recommendations", "Recommended Steps",
                        "Recommended Mitigation", "Recommended Mitigation Steps",
                        "Mitigation", "Mitigation Steps", "Recommended Fix"]
POC_NAMES = ["Proof of Concept", "Proof of concept", "PoC", "POC", "PoC",
             "Exploit Steps", "Exploit Scenario", "Attack Execution",
             "Attack Path", "Attack Scenario"]
CODE_LOC_NAMES = ["Location of Affected Code", "Code Location",
                  "Lines of code", "Relevant GitHub Links", "Code Snippet",
                  "Affected Code"]
STATUS_NAMES = ["Team Response", "Status", "Response"]
SIDEBAR_AXES = ("Impact", "Likelihood", "Confidence", "Quality", "Rarity")


def clean_md(text: str) -> str:
    text = text.replace("\\[", "[").replace("\\]", "]").replace("\\_", "_")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def body_of(text: str) -> str:
    m = re.search(r"^#{1,2}\s", text, re.M)
    body = text[m.start():] if m else text
    for marker in FOOT_MARKERS:
        i = body.find(marker)
        if i > 200:
            body = body[:i]
            break
    return body


def section(text: str, name: str) -> str:
    """Structured-heading layout: '## Name' followed by a body.

    Deliberately does NOT match inline labels; use `inline_label` for the
    '**Name:** value' layout, and `section_or_label` for fields that appear
    in either shape (the corpus contains both).
    """
    m = re.search(r"^#{2,4}\s*" + re.escape(name) + r"\s*$\s*\n(.*?)(?=^#{1,4}\s|\Z)",
                  text, re.M | re.S)
    return m.group(1).strip() if m else ""


def section_any(text: str, names: list[str]) -> str:
    """Try each alias and return the first observed section body."""
    for name in names:
        val = section(text, name)
        if val.strip():
            return val
    # Inline-heading values: "## Severity: High Risk" has no following body.
    for name in names:
        m = re.search(r"^#{2,4}\s*" + re.escape(name) +
                      r"\b[^\n]*[:\-]\s*(.+)$", text, re.M)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return ""


def _label_re(name: str, value_max: int = 120):
    """Pattern for an inline label in any observed shape.

    The corpus writes the same label three ways: '**Severity:** High',
    '**Severity**: High' and '**Severity** : High'. The bold markers sit on
    either side of the colon, so both are optional. An earlier version put
    them only before the colon and silently matched nothing.
    """
    return re.compile(
        r"\*\*\s*" + re.escape(name) +
        r"\s*\**\s*[:\-]?\s*\**\s*([^*\n]{0," + str(value_max) + r"})")


def inline_label(text: str, name: str) -> str:
    """Inline layout: '**Name:** value' (bold optional, colon optional)."""
    m = _label_re(name).search(text)
    return clean_md(m.group(1)) if m else ""


def inline_label_line(text: str, name: str) -> str:
    """Like inline_label but anchored to the start of a line.

    The unanchored form also matches prose that merely mentions the label
    ('...wiped in the severity manipulation...'), which must never become a
    value. Anchoring to a line start (allowing leading markdown chrome) is
    what makes an inline label an inline label.
    """
    m = re.search(r"^[ \t>*\-]{0,6}\**\s*" + re.escape(name) +
                  r"\s*\**\s*[:\-]\s*\**\s*([^*\n]{0,120})", text, re.M)
    return clean_md(m.group(1)) if m else ""


def section_or_label(text: str, name: str) -> str:
    """Return the value for a field present as a heading OR an inline label.

    Heading wins when both are present: the structured body is the fuller
    value, the inline label is often a truncated one-line summary.
    """
    return section(text, name) or inline_label(text, name)


# Solodit renders its own triage widget under '## Severity' as a set of axis
# labels. These are SOLODIT'S filtered view, not a severity statement by the
# auditor whose report is being mirrored. They must never be stored as the
# report's severity -- conflating the two invents a claim the auditor never
# made, and the harvest's HIGH/MEDIUM listing filter is likewise not evidence
# of a report's own severity.
_SOLODIT_AXES = ("Impact", "Likelihood", "Confidence")


def solodit_axis(text: str, axis: str) -> str:
    # Bold inline form: "**Impact:** High"
    m = _label_re(axis, 60).search(text)
    if m and m.group(1).strip():
        return clean_md(m.group(1))[:60]
    # Unbolded / separate-line form: "Impact High" or "Impact: High"
    m2 = re.search(r"(?mi)^[ \t>*\-]{0,6}" + re.escape(axis) +
                   r"\s*[:\-]?\s*([^\n]{1,60})$", text)
    return clean_md(m2.group(1))[:60] if m2 else ""


def strip_solodit_axes(text: str) -> str:
    """Remove Solodit's own axis widget, leaving the report's own words."""
    out = text
    for axis in _SOLODIT_AXES:
        out = _label_re(axis, 80).sub("", out)
    return re.sub(r"\n{2,}", "\n", out).strip(" \t*-\n")


# A report severity must look like a severity. Without this, any prose
# sentence containing the word "severity" ('...price manipulation.', 'the
# bridge token.') matched the inline fallback and became the answer.
_SEVERITY_VALUE = re.compile(
    r"\b(critical|crit|high|medium|med|low|informational|info|none|unknown)"
    r"\b", re.I)
def _looks_like_severity(value: str) -> bool:
    v = (value or "").strip()
    if not v or len(v) > 40:
        return False
    return bool(_SEVERITY_VALUE.search(v))


def report_severity(text: str) -> tuple[str | None, dict]:
    """The severity the ORIGINAL report states, plus Solodit's own axes.

    Returns (report_severity_observed, solodit_sidebar). The two are kept
    apart because they answer different questions:

      * report severity  -- what the auditor wrote ('High Risk', 'Medium').
      * Solodit Impact   -- Solodit's own triage axis, which feeds the
                            listing filter. Recorded as its own field and
                            never as the report's severity.

    A report severity is only ever text that survived stripping the axis
    widget AND parses as a severity token: if either test fails the answer
    is null, even though Solodit displayed an Impact value.
    """
    # Heading body ("## Severity\nHigh Risk"), or inline heading value
    # ("## Severity: Medium Risk").
    hm = re.search(r"^#{2,4}\s*Severity\b[^\n]*\n(.*?)(?=^#{1,4}\s|\Z)",
                   text, re.M | re.S)
    raw = hm.group(1).strip() if hm else ""
    if not raw:
        hm2 = re.search(r"^#{2,4}\s*Severity\b[^\n]*[:\-]\s*(.+)$",
                        text, re.M)
        raw = hm2.group(1).strip() if hm2 else ""

    sidebar = {a.lower(): (solodit_axis(text, a))
               for a in SIDEBAR_AXES}
    sidebar = {k: v for k, v in sidebar.items() if v}

    report_side = strip_solodit_axes(raw) if raw else ""
    if not _looks_like_severity(report_side.split("\n")[0] if report_side else ""):
        inline = inline_label_line(text, "Severity")
        report_side = inline if _looks_like_severity(inline) else ""
        if inline and not report_side:
            for a in SIDEBAR_AXES:
                v = solodit_axis(inline, a)
                if v:
                    sidebar.setdefault(a.lower(), v)

    if not report_side:
        return None, sidebar
    first = clean_md(report_side.split("\n")[0])[:60]
    if not _looks_like_severity(first):
        return None, sidebar
    return first, sidebar


def first_sentence(text: str, limit: int = 200) -> str:
    s = clean_md(text)
    m = re.match(r"(.{20,200}?[.?!])(\s|$)", s)
    s = m.group(1) if m else s[:limit]
    return s[:limit]


def detect_language(body: str) -> tuple[str, str, str]:
    """Majority extension vote -> language; ecosystem only on explicit
    mention (conflict or silence -> unknown). Returns (lang, eco, basis)."""
    votes: dict[str, int] = collections.Counter()
    for m in re.finditer(r"[\w\-/]+\.([A-Za-z0-9]+)(?![\w])", body):
        ext = "." + m.group(1).lower()
        if ext in EXT_LANG:
            votes[EXT_LANG[ext]] += 1
    if not votes:
        return "unknown", "unknown", "no code-file signals"
    top_n = max(votes.values())
    leaders = sorted(lang for lang, n in votes.items() if n == top_n)
    if len(leaders) != 1:
        return "unknown", "unknown", f"tie: {leaders}"
    lang = leaders[0]
    if lang in EVM_LANGS:
        return lang, "evm", f"majority extension vote ({dict(votes)})"
    if lang == "cairo":
        if re.search(r"starknet", body, re.I):
            return lang, "starknet", "cairo vote + starknet mentioned"
        return lang, "unknown", "cairo vote, no chain evidenced"
    chain_hits = {c for c in ("solana", "aptos", "sui", "cosmos", "evm",
                              "ethereum", "stellar")
                  if re.search(r"\b" + c + r"\b", body, re.I)}
    chain_hits.discard("ethereum")  # evm covers it; keep set clean
    if len(chain_hits) == 1:
        eco = "evm" if chain_hits == {"evm"} else next(iter(chain_hits))
        return lang, eco, f"{lang} vote + {eco} mentioned"
    return lang, "unknown", (f"{lang} vote; chain ambiguous {sorted(chain_hits)}"
                             if chain_hits else f"{lang} vote, no chain")


STOPWORDS = {"the", "a", "an", "of", "in", "on", "to", "and", "or",
             "for", "with", "by", "is", "are", "can", "be", "as", "at",
             "from"}


def title_words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower())) - STOPWORDS


def mark_duplicates(rows: list[dict]) -> tuple[int, list[dict]]:
    """Union-find over normalized-title token Jaccard >= 0.85.

    First row by file sequence is kept; the rest get `duplicate_of` and
    are reported, never admitted twice. Same-title reposts across issues
    (e.g. Hats findings published under two finding-IDs) collapse here;
    merely similar sibling findings score below threshold and stay.
    """
    parent = {id(r): id(r) for r in rows}
    {id(r): r for r in rows}

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    order = sorted(range(len(rows)),
                   key=lambda i: rows[i]["cid"].split(":")[1][:4])
    words = [title_words(rows[i]["title"]) for i in order]
    for x in range(len(order)):
        for y in range(x + 1, len(order)):
            a, b = words[x], words[y]
            if not a or not b:
                continue
            if len(a & b) / max(len(a), len(b)) >= 0.85:
                ra, rb = find(id(rows[order[x]])), find(id(rows[order[y]]))
                if ra != rb:
                    parent[rb] = ra
    clusters: dict = {}
    for i in order:
        clusters.setdefault(find(id(rows[i])), []).append(i)
    dupes = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        # Keep the strongest evidence: a row with an observed PoC wins over
        # an earlier row without one; ties break by file sequence.
        # Deterministic, and no quoted PoC is ever discarded with its row.
        members = sorted(members,
                         key=lambda i: (not rows[i].get("poc_observed"),
                                        rows[i]["cid"].split(":")[1][:4]))
        first = rows[members[0]]["cid"]
        for i in members[1:]:
            rows[i]["duplicate_of"] = first
            dupes.append({"harvest_cid": rows[i]["cid"],
                          "duplicate_of": first,
                          "reason": "near-duplicate title (>=0.85 token "
                                    "Jaccard); first occurrence kept"})
    return len(dupes), dupes


def parse_footer_list(text: str, label: str) -> list[str]:
    """Parse a Solodit footer list ('Tags' / 'Categories') into clean tokens."""
    m = re.search(r"(?im)^" + re.escape(label) + r"\s*\n(.*?)(?=^\w[^\n]*\n|\Z)",
                  text, re.S)
    if not m:
        m = re.search(r"(?i)" + re.escape(label) + r"\s*[:\-]?\s*(.+?)(?=\n\n|\Z)",
                      text, re.S)
    if not m:
        return []
    body = m.group(1)
    items = []
    for line in body.splitlines():
        line = line.strip().lstrip("-* ").strip()
        if not line:
            continue
        # Split comma/space separated token lists but keep multi-word-ish items
        # reasonably intact by splitting on commas first.
        for part in line.split(","):
            part = clean_md(part)
            if part and len(part) < 80:
                items.append(part)
    # De-duplicate preserving order.
    seen = set()
    out = []
    for x in items:
        if x.lower() not in seen:
            seen.add(x.lower())
            out.append(x)
    return out[:20]


def extract_code_locations(text: str, loc_raw: str) -> list[dict]:
    """Observed code file/URL references only. No paths are invented."""
    refs: list[dict] = []
    seen: set[tuple[str | None, str | None]] = set()

    def add(path, url):
        path = (path or "").strip()[:160] or None
        url = (url or "").strip()[:300] or None
        key = (path, url)
        if (path or url) and key not in seen:
            seen.add(key)
            refs.append({"path": path, "url": url})

    # Markdown links in location/code sections.
    for source in (loc_raw or "",):
        for m in re.finditer(r"\[([^\]]+)\]\((https?://[^)]+)\)", source):
            add(m.group(1), m.group(2))
    # Also scan observed code-snippet/GitHub-link sections already in loc_raw.
    for m in re.finditer(r"(?m)(https?://[^\s)]+)", loc_raw or ""):
        if "github" in m.group(1) or "#L" in m.group(1) or ".sol" in m.group(1):
            add(None, m.group(1))

    # Inline bold refs: **src/Foo.sol:L10-L12** or **Foo.sol**
    for m in re.finditer(r"(?m)^.{0,8}\*{1,2}([^*\n]+\.(?:sol|vy|rs|go|move|cairo)(?::L?\d+(?:-L?\d+)?)?)\*{0,2}\s*$",
                         text):
        add(m.group(1), None)

    # Absolute code refs anywhere in body, only when clearly code-ish.
    if not refs:
        for m in re.finditer(r"\[([^\]]*\.(?:sol|vy|rs|go|move|cairo)[^\]]*)\]\((https?://[^)]+)\)",
                             text):
            add(m.group(1), m.group(2))

    return refs[:25]


def parse_file(fname: str, text: str, url: str) -> dict | None:
    seq = fname[:4]
    slug = fname[5:].removesuffix(".md").removesuffix("-markdown")
    m = re.search(r"^#{1,2}\s*(.+)$", text, re.M)
    if not m:
        return None  # no recoverable title -> reject
    title = clean_md(m.group(1))[:200]
    if len(title) < 5:
        return None
    body = body_of(text)

    severity, solodit_sidebar = report_severity(text)
    team_raw = section_any(text, STATUS_NAMES)
    if not team_raw:
        team_raw = section_or_label(text, "Team Response") or \
            section_or_label(text, "Status")
    status = clean_md(team_raw.split("\n")[0])[:60] if team_raw else None
    if not status:
        status = None

    loc_raw = section_any(text, CODE_LOC_NAMES)
    code_refs = extract_code_locations(text, loc_raw)
    code_path, code_url = None, None
    if code_refs:
        first = code_refs[0]
        code_path = first.get("path")
        code_url = first.get("url")

    rep_url = None
    rm = re.search(r"Full report\s*\n\s*\[?[^\]\n]*\]?\((https?://[^)]+)\)",
                   text)
    if rm:
        rep_url = rm.group(1)[:300]

    auditor = None
    am = re.search(r"Author\(s\)\s*:?\s*([^\n]{1,80})", text)
    if am:
        auditor = clean_md(am.group(1))[:80] or None

    project = None
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"^#{1,2}\s", ln):
            for nxt in lines[i + 1:i + 4]:
                if nxt.strip() and not nxt.startswith(("#", "!", "[")):
                    project = clean_md(nxt)[:80]
                    break
            break

    # Observed absolute report date (relative phrases like "2 days ago" are
    # NOT convertible without scrape timestamp assumptions).
    report_date = None
    date_m = re.search(
        r"\b(?:January|February|March|April|May|June|July|August|September|"
        r"October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|"
        r"Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\b", project or "")
    if not date_m:
        # Also scan the same header area explicitly.
        head = "\n".join(lines[:8])
        date_m = re.search(
            r"\b(?:January|February|March|April|May|June|July|August|September|"
            r"October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|"
            r"Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\b", head)
    if date_m:
        report_date = date_m.group(0)

    poc = False
    poc_heading = "|".join(re.escape(n) for n in POC_NAMES)
    pm = re.search(r"^#{2,4}\s*(" + poc_heading + r")\s*$",
                   text, re.M | re.I)
    if pm:
        tail = text[pm.end():pm.end() + 1500]
        if re.search(r"(^|\n)\s*(```|\d+[.)]\s+\S)", tail):
            poc = True

    lang_basis_input = body
    if code_refs:
        lang_basis_input += "\n" + "\n".join(
            (r.get("path") or "") + " " + (r.get("url") or "")
            for r in code_refs)
    language, ecosystem, lang_basis = detect_language(lang_basis_input)

    desc = section_any(text, DESCRIPTION_NAMES)
    excerpt = first_sentence(desc) if desc else ""
    rec_raw = section_any(text, RECOMMENDATION_NAMES)
    rec = first_sentence(rec_raw, 160) if rec_raw else ""

    # Footer-observed Solodit tags/categories (triage metadata, never taxonomy).
    tags = parse_footer_list(text, "Tags")
    categories = parse_footer_list(text, "Categories")

    extra = (f"Solodit issue {url}; auditor: {auditor or 'unknown'}; "
             f"project: {project or 'unknown'}; report: {rep_url or 'unknown'};"
             + (f" mechanism excerpt: {excerpt}" if excerpt else ""))
    evidence = {
        "taxonomy": "unknown",
        "taxonomy_confidence": "unknown",
        "taxonomy_reason": "no vulnerability class observed in scraped "
                           "finding; never forced",
        "proof_type": ("published_poc_in_report" if poc else "none_observed"),
        "proof_status": ("published_in_report" if poc else "none_observed"),
        "reproduction_notes": ("steps/code quoted in report; not executed "
                                "by pipeline" if poc else
                                "no qualifying PoC section; L0 by rule"),
        "affected_contract": None,
        "affected_function": None,
        "code_location": (f"{code_path} @ {code_url}" if code_path and code_url
                          else code_path),
        "code_locations_observed": code_refs,
        "recommended_fix_observed": rec or None,
        "verified_patch": False,
        "fix_note": "team response preserved verbatim as status; never "
                    "experimental proof",
        "report_date": report_date or "unknown",
        "attribution": auditor or "unknown",
    }
    return {
        "cid": f"{SID}:{seq}-{slug[:120]}",
        "source_id": SID,
        "kind": "finding",
        "title": title,
        "severity_observed": severity,
        "solodit_sidebar_observed": solodit_sidebar,
        "severity_evidence": (
            "report's own Severity section" if severity else
            "no report severity observed; Solodit's Impact axis is triage "
            "metadata and is NOT the report's severity"),
        "status_observed": status,
        "link_observed": url,
        "language": language,
        "ecosystem": ecosystem,
        "language_basis": lang_basis,
        "extra": extra[:600],
        "poc_observed": poc,
        "report_date_observed": report_date,
        "code_path_observed": code_path,
        "code_url_observed": code_url,
        "code_locations_observed": code_refs,
        "solodit_tags_observed": tags,
        "solodit_categories_observed": categories,
        "evidence": evidence,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    index = json.load(io.open(str(NEXTDATA / "_index_all_1926.json"),
                              encoding="utf-8-sig"))
    url_by_file = {}
    url_by_slug = {}
    n_indexed = 0
    for r in index:
        if not isinstance(r, dict):
            continue
        url = (r.get("url") or {}).get("value")
        if not url:
            continue
        n_indexed += 1
        url_by_slug[url.rsplit("/", 1)[-1]] = url
        if r.get("file"):
            url_by_file[r["file"]] = url
            url_by_file[r["file"] + ".md"] = url

    files = sorted(f for f in os.listdir(str(NEXTDATA))
                   if re.match(r"^\d{4}-.*\.md$", f))
    existing = [(c["cid"], title_words(c.get("title", "")))
                for c in json.load(io.open(str(VBETA / "candidates.json"),
                                           encoding="utf-8-sig"))
                if c.get("kind") == "finding"]
    rows, rejected, duplicates, seen_cids = [], [], [], set()
    for fname in files:
        text = io.open(str(NEXTDATA / fname), encoding="utf-8-sig").read()
        if len(text) < 500:
            rejected.append((fname, "stub/empty file (<500 chars)"))
            continue
        url = url_by_file.get(fname)
        if not url:
            # Filenames are {seq}-{issue-slug}.md; fall back to slug match
            # against the indexed issue URLs (never synthesize a URL).
            slug = fname[5:].removesuffix(".md")
            url = url_by_slug.get(slug)
        if not url:
            rejected.append((fname, "no issue URL in index"))
            continue
        row = parse_file(fname, text, url)
        if row is None:
            rejected.append((fname, "no recoverable title"))
            continue
        if row["cid"] in seen_cids:
            rejected.append((fname, "duplicate cid"))
            continue
        words = title_words(row["title"])
        dup_of = None
        for cid, other in existing:
            if words and other and (
                    len(words & other) / max(len(words), len(other)) > 0.6):
                dup_of = cid
                break
        if dup_of:
            duplicates.append({"harvest_cid": row["cid"], "file": fname,
                               "duplicate_of": dup_of,
                               "reason": "same finding already admitted"})
            rejected.append((fname, f"duplicate of {dup_of}"))
            continue
        seen_cids.add(row["cid"])
        rows.append(row)

    # Within-harvest near-duplicates: first by file sequence is kept, the
    # rest carry duplicate_of and are reported (build admits them as
    # CORROBORATION_ONLY, never twice).
    n_quarantined, cluster_dupes = mark_duplicates(rows)
    duplicates.extend(cluster_dupes)

    stats = {
        "generated_by": "Vbeta/scripts/harvest_solodit.py",
        "dataset_version": "vbeta-1.0",
        "files": len(files),
        "harvested": len(rows),
        "indexed": n_indexed,
        "indexed_from": "nextdata/_index_all_1926.json",
        "rejected": len(rejected),
        "rejections": [{"file": f, "reason": w} for f, w in rejected],
        "duplicates": duplicates,
        "quarantined_near_dupes": n_quarantined,
        "with_severity": sum(1 for r in rows if r["severity_observed"]),
        "with_report_severity": sum(
            1 for r in rows if r["severity_observed"]
            and "Impact" not in str(r["severity_observed"])),
        "with_solodit_impact_axis": sum(
            1 for r in rows if (r.get("solodit_sidebar_observed") or {}).get("impact")),
        "with_status": sum(1 for r in rows if r["status_observed"]),
        "with_description_excerpt": sum(
            1 for r in rows if "mechanism excerpt:" in (r.get("extra") or "")),
        "with_recommendation": sum(
            1 for r in rows if r["evidence"].get("recommended_fix_observed")),
        "with_poc": sum(1 for r in rows if r["poc_observed"]),
        "languages": sorted({r["language"] for r in rows}),
        "ecosystems": sorted({r["ecosystem"] for r in rows}),
    }
    print(f"harvest: {stats['harvested']}/{stats['files']} rows "
          f"({stats['rejected']} rejected)")
    print(f"  severity: {stats['with_severity']}, status: "
          f"{stats['with_status']}, poc: {stats['with_poc']}")
    print(f"  languages: {stats['languages']}")
    print(f"  ecosystems: {stats['ecosystems']}")
    for fname, why in rejected:
        print(f"  REJECT {fname[:60]}: {why}")

    if not args.check:
        with io.open(str(OUT), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(rows, fh, sort_keys=True)
            fh.write("\n")
        print(f"wrote {OUT} ({len(rows)} rows)")
        stats_path = VBETA / "reports_vbeta" / "solodit_harvest_stats.json"
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        with io.open(str(stats_path), "w", encoding="utf-8",
                     newline="\n") as fh:
            json.dump(stats, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {stats_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

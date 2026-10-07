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
import sys
from pathlib import Path

VBETA = Path(__file__).resolve().parent.parent
NEXTDATA = VBETA.parent / "nextdata"
OUT = VBETA / "solodit_candidates.json"

SID = "solodit-harvest"

EXT_LANG = {".sol": "solidity", ".vy": "vyper", ".cairo": "cairo",
            ".rs": "rust", ".move": "move", ".go": "go"}
EVM_LANGS = {"solidity", "vyper"}
FOOT_MARKERS = ["Unlock notes, bookmarks", "Full report"]


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
    m = re.search(r"^#{2,4}\s*" + re.escape(name) + r"\s*\n(.*?)(?=^#{1,4}\s|\Z)",
                  text, re.M | re.S)
    return m.group(1).strip() if m else ""


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
    leaders = sorted(l for l, n in votes.items() if n == top_n)
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
    by_id = {id(r): r for r in rows}

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

    sev_raw = section(text, "Severity")
    severity = clean_md(sev_raw.split("\n")[0])[:60] if sev_raw else None
    if not severity:
        severity = None
    team_raw = section(text, "Team Response")
    status = clean_md(team_raw.split("\n")[0])[:60] if team_raw else None
    if not status:
        status = None

    loc_raw = section(text, "Location of Affected Code")
    code_path, code_url = None, None
    if loc_raw:
        lm = re.search(r"\[([^\]]+)\]\((https?://[^)]+)\)", loc_raw)
        if lm:
            code_path, code_url = lm.group(1)[:160], lm.group(2)[:300]
        else:
            code_path = clean_md(loc_raw.split("\n")[0])[:160] or None

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

    poc = False
    pm = re.search(r"^#{2,4}\s*(Proof of Concept|Attack Execution|"
                   r"Exploit Steps|\bPoC\b)\s*$", text, re.M | re.I)
    if pm:
        tail = text[pm.end():pm.end() + 1500]
        if re.search(r"(^|\n)\s*(```|\d+[.)]\s+\S)", tail):
            poc = True

    language, ecosystem, lang_basis = detect_language(body)

    desc = section(text, "Description")
    excerpt = first_sentence(desc) if desc else ""
    rec_raw = section(text, "Recommendation")
    rec = first_sentence(rec_raw, 160) if rec_raw else ""

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
        "recommended_fix_observed": rec or None,
        "verified_patch": False,
        "fix_note": "team response preserved verbatim as status; never "
                    "experimental proof",
        "report_date": "unknown",
        "attribution": auditor or "unknown",
    }
    return {
        "cid": f"{SID}:{seq}-{slug[:120]}",
        "source_id": SID,
        "kind": "finding",
        "title": title,
        "severity_observed": severity,
        "status_observed": status,
        "link_observed": url,
        "language": language,
        "ecosystem": ecosystem,
        "language_basis": lang_basis,
        "extra": extra[:600],
        "poc_observed": poc,
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
    for r in index:
        if not isinstance(r, dict):
            continue
        url = (r.get("url") or {}).get("value")
        if not url:
            continue
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
        "rejected": len(rejected),
        "rejections": [{"file": f, "reason": w} for f, w in rejected],
        "duplicates": duplicates,
        "quarantined_near_dupes": n_quarantined,
        "with_severity": sum(1 for r in rows if r["severity_observed"]),
        "with_status": sum(1 for r in rows if r["status_observed"]),
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

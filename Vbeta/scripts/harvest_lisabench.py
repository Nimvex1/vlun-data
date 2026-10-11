#!/usr/bin/env python3
"""Harvest LISABench (10,185 finding JSONs) into Vbeta candidates.

Reads ONLY untracked work/sources/lisa-bench (never PRESENT data) and writes
ONLY ``Vbeta/lisabench_candidates.json``. Deterministic: numeric file order,
no timestamps, no network.

Row contract:
  * title/Impact verbatim (GAS kept as published class, not remapped);
  * link_observed is the per-finding issue URL from `Content` when present,
    else the contest `Source` URL (recorded as link_kind finding/contest —
    both observed, never synthesised);
  * status stays null (no disposition field exists) -> IMPORT_AS_UNVERIFIED;
  * language from the first Code filename extension (observed per row);
    ecosystem only on explicit chain evidence, else unknown;
  * Code[] file CONTENT is never copied (METADATA_ONLY): filenames only;
  * dedup key (platform, contest, finding-id): first file wins, rest link
    as duplicates; exact-title overlap vs already-admitted rows rejects.

    python Vbeta/scripts/harvest_lisabench.py
    python Vbeta/scripts/harvest_lisabench.py --check
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
from pathlib import Path

VBETA = Path(__file__).resolve().parent.parent
LISA = VBETA.parent / "work" / "sources" / "lisa-bench" / "dataset"
OUT = VBETA / "lisabench_candidates.json"

SID = "lisabench"

STOPWORDS = {"the", "a", "an", "of", "in", "on", "to", "and", "or",
             "for", "with", "by", "is", "are", "can", "be", "as", "at",
             "from"}

EXT_LANG = {".sol": ("solidity", "evm"), ".vy": ("vyper", "evm"),
            ".cairo": ("cairo", None), ".rs": ("rust", None),
            ".move": ("move", None), ".go": ("go", None)}


def title_words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower())) - STOPWORDS


def clean(text: str, limit: int) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())[:limit]


def platform_of(url: str) -> str:
    u = (url or "").lower()
    if "sherlock" in u:
        return "sherlock"
    if "code4rena" in u:
        return "code4rena"
    if "codehawks" in u or "codehawks" in u:
        return "codehawks"
    if "cantina" in u:
        return "cantina"
    return "unknown"


def contest_of(url: str) -> str:
    m = re.search(r"/contests?/(\d+)", url or "")
    if m:
        return "contest-" + m.group(1)
    m = re.search(r"code-423n4/([\w.-]+)", url or "")
    if m:
        return m.group(1)
    m = re.search(r"sherlock-audit/([\w.-]+?)(?:-judging|/issues|$)", url or "")
    if m:
        return m.group(1)
    return "unknown"


def fid_of(title: str) -> str:
    m = re.match(r"\[?([A-Z]+-\d+)\]?:?", (title or "").strip())
    return m.group(1) if m else "unknown"


def parse() -> tuple[list[dict], list[tuple[str, str]], dict]:
    files = sorted((f for f in os.listdir(str(LISA))
                    if re.match(r"^\d+\.json$", f)),
                   key=lambda f: int(f.split(".")[0]))

    have = json.load(io.open(str(VBETA / "candidates.json"),
                             encoding="utf-8-sig"))
    for extra in ("solodit_candidates.json", "web3bugs_candidates.json",
                  "scabench_candidates.json"):
        p = VBETA / extra
        if p.exists():
            have = have + json.load(io.open(str(p), encoding="utf-8-sig"))
    existing = [(c["cid"], title_words(c.get("title", ""))) for c in have
                if c.get("kind") == "finding"]

    rows, rejected, seen_keys = [], [], set()
    stats = {"no_title": 0, "no_link": 0, "dup_resident": 0, "dup_lisa": 0}
    for fname in files:
        try:
            r = json.load(io.open(str(LISA / fname), encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            rejected.append((fname, "unreadable JSON"))
            continue
        title = clean(r.get("Title"), 220)
        if len(title) < 5:
            stats["no_title"] += 1
            rejected.append((fname, "no recoverable title"))
            continue
        content = r.get("Content") or ""
        m = re.search(r"Source:\s*(https?://\S+)", content)
        issue_url = m.group(1).rstrip(").,") if m else None
        contest_url = (r.get("Source") or "").strip() or None
        link = issue_url or contest_url
        if not link or not link.startswith("https://"):
            stats["no_link"] += 1
            rejected.append((fname, "no usable link"))
            continue
        platform = platform_of(contest_url or issue_url or "")
        contest = contest_of(issue_url or contest_url or "")
        fid = fid_of(title)
        key = (platform, contest, fid)
        # Dedup keys only count when fully evidenced; an "unknown" component
        # would collapse unrelated rows (4,615 false collisions measured).
        key_ok = (platform != "unknown" and contest != "unknown"
                  and fid != "unknown")
        if key_ok and key in seen_keys:
            stats["dup_lisa"] += 1
            rejected.append((fname, f"duplicate key {key}"))
            continue
        seen_keys.add(key)
        words = title_words(title)
        dup_of = None
        for ecid, other in existing:
            if words and other and (
                    len(words & other) / max(len(words), len(other)) > 0.6):
                dup_of = ecid
                break
        if dup_of:
            stats["dup_resident"] += 1
            rejected.append((fname, f"duplicate of {dup_of}"))
            continue
        sev = clean(r.get("Impact"), 40) or None
        language, ecosystem = "unknown", "unknown"
        code_names = [c.get("filename") for c in (r.get("Code") or [])
                      if c.get("filename")]
        if code_names:
            m2 = re.search(r"\.(sol|vy|cairo|rs|move|go)\b", code_names[0])
            if m2:
                lang, eco = EXT_LANG["." + m2.group(1)]
                language = lang
                if eco:
                    ecosystem = eco
        attrib = None
        fm = re.search(r"Found by\s+([^\n]{1,80})", content)
        if fm:
            attrib = clean(fm.group(1), 80)
        excerpt = ""
        dm = re.match(r"(.{20,200}?[.?!])(\s|$)",
                      re.sub(r"\s+", " ", content.strip()))
        if dm:
            excerpt = dm.group(1)[:200]
        cid = f"{SID}:{fname.split('.')[0]}"
        rows.append({
            "cid": cid,
            "source_id": SID,
            "kind": "finding",
            "title": title,
            "severity_observed": sev,
            "status_observed": None,
            "link_observed": link,
            "language": language,
            "ecosystem": ecosystem,
            "extra": (f"LISABench file {fname}; platform {platform}; "
                      f"contest {contest}; finding {fid}; link_kind "
                      f"{'finding-issue' if issue_url else 'contest'}; "
                      f"finder: {attrib or 'unknown'}; "
                      f"code files: {len(code_names)} (names only)"
                      + (f"; mechanism excerpt: {excerpt}" if excerpt else "")
                      )[:600],
            "poc_observed": False,
            "evidence": {
                "taxonomy": "unknown",
                "taxonomy_confidence": "unknown",
                "taxonomy_reason": "no vulnerability class observed; "
                                   "never forced",
                "proof_type": "none_observed",
                "proof_status": "none_observed",
                "reproduction_notes": "no qualifying PoC section; L0 by rule",
                "affected_contract": None,
                "affected_function": None,
                "code_location": None,
                "recommended_fix_observed": None,
                "verified_patch": False,
                "fix_note": "no fix evidence in source row",
                "report_date": "unknown",
                "attribution": ("finder %s via LISABench; contest %s" % (
                    attrib or "unknown", contest)),
            },
        })
    return rows, rejected, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    rows, rejected, stats = parse()
    print(f"harvest: {len(rows)}/{len(rows) + len(rejected)} rows "
          f"({len(rejected)} rejected)")
    print(f"  dedup-key collisions: {stats['dup_lisa']}, "
          f"resident overlaps: {stats['dup_resident']}, "
          f"no-link: {stats['no_link']}, no-title: {stats['no_title']}")
    if not args.check:
        with io.open(str(OUT), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(rows, fh, sort_keys=True)
            fh.write("\n")
        print(f"wrote {OUT} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

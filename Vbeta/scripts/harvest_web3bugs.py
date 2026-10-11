#!/usr/bin/env python3
"""Harvest Web3Bugs (ICSE'23 Code4rena survey) into Vbeta candidates.

Reads ONLY untracked work/sources/Web3Bugs (never PRESENT data) and writes
ONLY ``Vbeta/web3bugs_candidates.json``. Deterministic: CSV order, no
timestamps, no network.

Row contract (all verified before harvest):
  * every row carries a description AND a canonical C4 report URL;
  * every Bug ID is H-* (High); severity_observed is "High" verbatim;
  * labels (L1/S1-1/...) are oracle-difficulty classes from the paper, NOT
    severities — stored as externally_attributed difficulty signal, never
    as severity;
  * window 2021-04..2022-12 predates resident v1 scope; title overlap vs
    already-admitted Vbeta rows is still checked (>0.6 → rejected);
  * language/ecosystem solidity/evm: Code4rena contests of record in this
    window are Solidity; .sol contracts tree ships per contest.

    python Vbeta/scripts/harvest_web3bugs.py
    python Vbeta/scripts/harvest_web3bugs.py --check  # parse, write nothing
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
from pathlib import Path

VBETA = Path(__file__).resolve().parent.parent
WB = VBETA.parent / "work" / "sources" / "Web3Bugs"
OUT = VBETA / "web3bugs_candidates.json"

SID = "web3bugs"

STOPWORDS = {"the", "a", "an", "of", "in", "on", "to", "and", "or",
             "for", "with", "by", "is", "are", "can", "be", "as", "at",
             "from"}


def title_words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower())) - STOPWORDS


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().strip('"').strip())


def parse() -> tuple[list[dict], list[tuple[str, str]]]:
    bugs_path = WB / "results" / "bugs.csv"
    contests_path = WB / "results" / "contests.csv"
    # skipinitialspace=True is load-bearing: the file writes `, "..."` (a
    # space before the opening quote), which the csv module otherwise parses
    # as an unquoted field and splits on inner commas (27 rows mis-split
    # without it, putting description tails in the Reference column).
    with io.open(str(bugs_path), encoding="utf-8-sig") as fh:
        bugs = list(csv.DictReader(fh, skipinitialspace=True))
    with io.open(str(contests_path), encoding="utf-8-sig") as fh:
        contests = {r["ID"].strip(): r for r in
                    csv.DictReader(fh, skipinitialspace=True)}

    have = json.load(io.open(str(VBETA / "candidates.json"),
                             encoding="utf-8-sig"))
    solo_path = VBETA / "solodit_candidates.json"
    if solo_path.exists():
        have = have + json.load(io.open(str(solo_path), encoding="utf-8-sig"))
    existing = [(c["cid"], title_words(c.get("title", ""))) for c in have
                if c.get("kind") == "finding"]

    rows, rejected, seen = [], [], set()
    for r in bugs:
        cid_num = (r.get("Contest ID") or "").strip()
        bug_id = (r.get("Bug ID") or "").strip()
        desc = clean(r.get("Bug Description"))
        ref = (r.get("Reference") or "").strip()
        label = (r.get("Bug Label") or "").strip()
        diff = (r.get("Difficulty") or "").strip()
        contest = contests.get(cid_num, {})
        cname = (contest.get("Name") or "").strip() or "unknown"
        if not desc or not ref:
            rejected.append((f"{cid_num}:{bug_id}", "missing description/reference"))
            continue
        title = f"[{bug_id}] {desc[:160]}"
        cid = f"{SID}:{cid_num}-{bug_id.replace(' ', '')}"
        if cid in seen:
            rejected.append((cid, "duplicate cid"))
            continue
        words = title_words(title)
        dup_of = None
        for ecid, other in existing:
            if words and other and (
                    len(words & other) / max(len(words), len(other)) > 0.6):
                dup_of = ecid
                break
        if dup_of:
            rejected.append((cid, f"duplicate of {dup_of}"))
            continue
        seen.add(cid)
        rows.append({
            "cid": cid,
            "source_id": SID,
            "kind": "finding",
            "title": title,
            "severity_observed": "High",
            "status_observed": None,
            "link_observed": ref,
            "language": "solidity",
            "ecosystem": "evm",
            "extra": (f"Web3Bugs contest {cid_num} ({cname}); oracle-difficulty "
                      f"label {label or 'unknown'}, difficulty {diff or 'unknown'}; "
                      f"C4 report: {ref}"),
            "poc_observed": False,
            "evidence": {
                "taxonomy": "unknown",
                "taxonomy_confidence": "unknown",
                "taxonomy_reason": "no vulnerability class observed; never forced",
                "proof_type": "none_observed",
                "proof_status": "none_observed",
                "reproduction_notes": "no PoC section; L0 by rule",
                "affected_contract": None,
                "affected_function": None,
                "code_location": None,
                "recommended_fix_observed": None,
                "verified_patch": False,
                "fix_note": "no fix evidence in source row",
                "report_date": "unknown",
                "attribution": "Web3Bugs (ICSE'23); original: Code4rena report",
                "oracle_label": label or None,
                "label_note": "paper oracle-difficulty class (O/L/S/SC/SE), "
                              "not a severity; externally_attributed",
            },
        })
    return rows, rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    rows, rejected = parse()
    print(f"harvest: {len(rows)}/{len(rows) + len(rejected)} rows "
          f"({len(rejected)} rejected)")
    for cid, why in rejected:
        print(f"  REJECT {cid[:70]}: {why}")
    if not args.check:
        with io.open(str(OUT), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(rows, fh, sort_keys=True)
            fh.write("\n")
        print(f"wrote {OUT} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

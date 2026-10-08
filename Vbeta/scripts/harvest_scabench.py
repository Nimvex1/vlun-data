#!/usr/bin/env python3
"""Harvest ScaBench (2024-08..2025-08 contest findings) into Vbeta candidates.

Reads ONLY untracked work/sources/scabench (never PRESENT data) and writes
ONLY ``Vbeta/scabench_candidates.json``. Deterministic: project/vuln order
as stored, no timestamps, no network.

Row contract:
  * title/severity from the vuln object, verbatim; status stays null (the
    file carries no explicit disposition field — debate text is mined for
    attribution only, never promoted to a verdict);
  * link_observed is the project's commit-pinned tree_url (meets the
    citation bar: repo URL + exact commit);
  * language/ecosystem stay unknown (no per-row language evidence in the
    file; platform+era is not evidence);
  * adjudication mining: submitter handle (-> externally_attributed),
    judge/sponsor/mitigation mention flags (-> observed_fact that the
    thread contains them);
  * title overlap vs already-admitted Vbeta rows (>0.6 -> rejected).

    python Vbeta/scripts/harvest_scabench.py
    python Vbeta/scripts/harvest_scabench.py --check
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from pathlib import Path

VBETA = Path(__file__).resolve().parent.parent
SCA = VBETA.parent / "work" / "sources" / "scabench"
SRC_FILE = (SCA / "datasets" / "curated-2025-08-18"
            / "curated-2025-08-18.json")
OUT = VBETA / "scabench_candidates.json"

SID = "scabench"

STOPWORDS = {"the", "a", "an", "of", "in", "on", "to", "and", "or",
             "for", "with", "by", "is", "are", "can", "be", "as", "at",
             "from"}


def title_words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower())) - STOPWORDS


def clean(text: str, limit: int) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())[:limit]


def parse() -> tuple[list[dict], list[tuple[str, str]]]:
    doc = json.load(io.open(str(SRC_FILE), encoding="utf-8-sig"))
    projs = doc if isinstance(doc, list) else doc.get("projects", doc)

    have = json.load(io.open(str(VBETA / "candidates.json"),
                             encoding="utf-8-sig"))
    for extra in ("solodit_candidates.json", "web3bugs_candidates.json"):
        p = VBETA / extra
        if p.exists():
            have = have + json.load(io.open(str(p), encoding="utf-8-sig"))
    existing = [(c["cid"], title_words(c.get("title", ""))) for c in have
                if c.get("kind") == "finding"]

    rows, rejected, seen = [], [], set()
    for p in projs:
        trees = [c.get("tree_url") for c in (p.get("codebases") or [])
                 if c.get("tree_url")]
        repos = [c.get("repo_url") for c in (p.get("codebases") or [])
                 if c.get("repo_url")]
        commits = sorted({c.get("commit") for c in (p.get("codebases") or [])
                          if c.get("commit")})
        # Prefer the commit-pinned tree URL; fall back to the observed repo
        # URL (never synthesised) with the commit recorded alongside.
        link = trees[0] if trees else (repos[0] if repos else None)
        link_note = ("tree_url (commit-pinned)" if trees
                     else ("repo_url + commit %s (tree URL not stored "
                           "upstream; not synthesised here)"
                           % (commits[0][:12] if commits else "unknown")))
        if not link:
            for v in p.get("vulnerabilities", []):
                rejected.append((str(v.get("finding_id")),
                                 "no commit-pinned codebase link"))
            continue
        for v in p.get("vulnerabilities", []):
            fid = str(v.get("finding_id") or "").strip()
            title = clean(v.get("title"), 200)
            sev = clean(v.get("severity"), 40)
            desc = v.get("description") or ""
            if not fid or not title:
                rejected.append((fid or "?", "missing finding_id/title"))
                continue
            cid = f"{SID}:{fid}"
            if cid in seen:
                rejected.append((cid, "duplicate cid"))
                continue
            words = title_words(f"[{fid}] {title}")
            dup_of = None
            for ecid, other in existing:
                if words and other and (
                        len(words & other) / max(len(words), len(other))
                        > 0.6):
                    dup_of = ecid
                    break
            if dup_of:
                rejected.append((cid, f"duplicate of {dup_of}"))
                continue
            seen.add(cid)
            m_sub = re.search(r"^Submitted by\s+([^\n]{1,60})", desc, re.M)
            submitter = clean(m_sub.group(1), 60) if m_sub else None
            debate = sorted(m for m in
                            ("Judge", "Sponsor", "Mitigation", "disagree")
                            if re.search(m, desc, re.I))
            excerpt = ""
            dm = re.match(r"(.{20,200}?[.?!])(\s|$)",
                          re.sub(r"\s+", " ", desc.strip()))
            if dm:
                excerpt = dm.group(1)[:200]
            rows.append({
                "cid": cid,
                "source_id": SID,
                "kind": "finding",
                "title": f"[{fid}] {title}"[:220],
                "severity_observed": sev or None,
                "status_observed": None,
                "link_observed": link,
                "language": "unknown",
                "ecosystem": "unknown",
                "extra": (f"ScaBench {p.get('project_id')} "
                          f"({p.get('platform')}); submitter: "
                          f"{submitter or 'unknown'}; debate markers: "
                          f"{','.join(debate) or 'none'}; codebase: {link} "
                          f"[{link_note}]"
                          + (f"; mechanism excerpt: {excerpt}"
                             if excerpt else ""))[:600],
                "poc_observed": False,
                "evidence": {
                    "taxonomy": "unknown",
                    "taxonomy_confidence": "unknown",
                    "taxonomy_reason": "no vulnerability class observed; "
                                       "never forced",
                    "proof_type": "none_observed",
                    "proof_status": "none_observed",
                    "reproduction_notes": "no qualifying PoC section; "
                                          "L0 by rule",
                    "affected_contract": None,
                    "affected_function": None,
                    "code_location": None,
                    "recommended_fix_observed": None,
                    "verified_patch": False,
                    "fix_note": "no fix evidence in source row",
                    "report_date": "unknown",
                    "attribution": ("submitter %s via ScaBench; original: "
                                    "%s contest" % (submitter or "unknown",
                                                    p.get("platform"))),
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

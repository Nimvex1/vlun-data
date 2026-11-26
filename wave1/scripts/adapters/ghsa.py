"""ghsa.py - Source #3 `ghsa_web3_netnew` reference resolution (Wave-1).

METADATA ONLY.  This module no longer re-harvests advisories or rewrites the
candidate/admitted layers: it reads the already-admitted GHSA metadata and
resolves exact fixing commits from cached advisory/OSV payloads.

Exact fixing commit policy:
  * For each admitted row with fix_commit_basis == 'patched_version_tag', inspect
    cached payloads in work/sources/_api_cache/*.json and the GHSA candidate rows
    for GitHub commit URLs (/commit/<40hex>) and PR URLs (/pull/<n>).
  * A 40-hex commit URL wins: fix_commit is replaced with that SHA and the basis
    becomes 'osv_reference_commit'.
  * A PR URL with no commit URL records pr_number and sets the basis to
    'osv_reference_pr'.  The tag-derived SHA is retained; NO SHA is invented.
  * Nothing found: the tag-derived SHA and its original basis are retained.

This module writes ONLY its owned report.  Benchmark families are derived by
markdown.py from the admitted data using the helpers exported here.

Usage: python wave1/scripts/adapters/ghsa.py
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

# _common.py lives in wave1/scripts/, this file in wave1/scripts/adapters/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    WORK_SOURCES,
    WAVE1,
    guard_scratch,
    guard_wave1,
    norm_id,
    norm_repo_slug,
    read_jsonl,
    utc_now,
    write_json,
)

SOURCE = "ghsa_web3_netnew"
CAND_DIR = WAVE1 / "03_candidates" / SOURCE
ADMIT_DIR = WAVE1 / "04_admitted" / SOURCE
API_CACHE = WORK_SOURCES / "_api_cache"
REPORT_PATH = WAVE1 / "reports_wave1" / "ghsa_harvest.json"

_GHSA = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.I)
_SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
_GITHUB_REPO = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)", re.I)
_RAW_COMMIT = re.compile(r"/commit/([0-9a-f]{40})\b", re.I)
_RAW_PR = re.compile(r"/pull/(\d+)\b")
_URL_REF = re.compile(
    r"https?://github\.com/([^/\s]+)/([^/\s]+)/"
    r"(?:commit/([0-9a-fA-F]{40})|pull/(\d+))\b",
    re.I,
)


def is_sha40(value: object) -> bool:
    s = str(value or "")
    return _SHA40.fullmatch(s) is not None


def _repo_from_url(url: object) -> str:
    m = _GITHUB_REPO.search(str(url or ""))
    return norm_repo_slug(m.group(1) + "/" + m.group(2)) if m else ""


def _reference_urls(value: object) -> list[str]:
    """URL strings from an OSV-style `references` list."""
    urls: list[str] = []
    if not isinstance(value, list):
        return urls
    for item in value:
        if isinstance(item, dict):
            for key in ("url", "href", "link"):
                if item.get(key):
                    urls.append(str(item[key]))
        elif item:
            urls.append(str(item))
    return urls


def _harvest_text(text: str, repo_hint: str, out: dict) -> None:
    """Collect GitHub commit/PR references from one blob of cached text."""
    for m in _URL_REF.finditer(text):
        repo = norm_repo_slug(m.group(1) + "/" + m.group(2))
        if m.group(3):
            out["commits"].add((repo, m.group(3).lower()))
        elif m.group(4):
            out["prs"].add((repo, m.group(4)))
    # Bare /commit/<sha> and /pull/<n> references use the advisory's own repo.
    if repo_hint:
        for sha in _RAW_COMMIT.findall(text):
            out["commits"].add((repo_hint, sha.lower()))
        for num in _RAW_PR.findall(text):
            out["prs"].add((repo_hint, num))


def _payloads():
    """Yield (location, json_value) from the cached API payloads."""
    if API_CACHE.exists():
        for p in sorted(API_CACHE.glob("*.json")):
            try:
                yield str(p.relative_to(WORK_SOURCES)), json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"[ghsa] skipping unreadable cache payload {p.name}: {exc}")
                continue
    for p in (CAND_DIR / "candidates.jsonl", CAND_DIR / "findings.jsonl",
              ADMIT_DIR / "findings.jsonl"):
        fp = guard_scratch(p)
        if fp.exists():
            for i, row in enumerate(read_jsonl(fp)):
                yield f"{p.relative_to(WAVE1)}#{i}", row


def build_reference_index() -> dict:
    """Map GHSA id -> {'commits': {(repo, sha)}, 'prs': {(repo, number)}}.

    The primary source is an OSV-style `references` array.  The cached GitHub
    advisory payloads in this checkout have no such array, so as a documented
    fallback the same commit/PR URLs are also harvested from the advisory's
    cached `description`/`summary`/`details` text.  Both paths carry real URLs
    from disk; nothing is synthesized.
    """
    index: dict[str, dict] = {}

    def bucket(ghsa_id: str) -> dict:
        return index.setdefault(ghsa_id.upper(), {"commits": set(), "prs": set()})

    def walk(value: object, ghsa_id: str, repo_hint: str, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            gid = ghsa_id or norm_id(value.get("ghsa_id") or value.get("id") or "")
            if not _GHSA.fullmatch(gid):
                gid = ghsa_id
            hint = repo_hint or _repo_from_url(
                value.get("html_url") or value.get("url") or value.get("permalink"))
            if gid:
                b = bucket(gid)
                _harvest_text(" ".join(_reference_urls(value.get("references"))), hint, b)
                # fallback: cached advisory prose fields (no references array here)
                for key in ("description", "summary", "details"):
                    if value.get(key):
                        _harvest_text(str(value[key]), hint, b)
            for k, v in value.items():
                if k in ("description", "summary", "details", "references"):
                    continue
                walk(v, gid, hint, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, ghsa_id, repo_hint, depth + 1)

    for _location, payload in _payloads():
        walk(payload, "", "")
    return index


def upgrade_ghsa_row(row: dict, index: dict) -> tuple[dict, str]:
    """Return (possibly upgraded row copy, outcome status).

    status is one of: sha_upgraded, pr_recorded, unchanged, not_applicable.
    """
    if row.get("fix_commit_basis") != "patched_version_tag":
        return row, "not_applicable"
    gid = norm_id(row.get("ghsa_id") or "")
    entry = index.get(gid, {"commits": set(), "prs": set()})
    repo = norm_repo_slug(row.get("repo_slug") or "")

    commits = sorted({sha for r, sha in entry.get("commits", set()) if r == repo and is_sha40(sha)})
    prs = sorted({int(n) for r, n in entry.get("prs", set()) if r == repo and str(n).isdigit()})

    if commits:
        out = dict(row)
        out["fix_commit"] = commits[0]
        out["fix_commit_basis"] = "osv_reference_commit"
        return out, "sha_upgraded"
    if prs:
        out = dict(row)
        out["pr_number"] = prs[0]
        out["fix_commit_basis"] = "osv_reference_pr"
        return out, "pr_recorded"
    return row, "unchanged"


def stratified_split(rows: list[dict], group_fn, label_fn) -> dict[str, str]:
    """Deterministic 70/15/15 split, stratified by firm/repo."""
    from _common import sha256_text

    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(str(group_fn(r)), []).append(r)
    assign: dict[str, str] = {}
    for group in sorted(groups):
        grp = sorted(groups[group],
                     key=lambda r: (sha256_text(group + "|" + r["candidate_id"]), r["candidate_id"]))
        n = len(grp)
        if n >= 3:
            n_train = max(0, min(round(n * 0.70), n - 2))
            n_val = max(1, min(round(n * 0.15), n - n_train - 1))
        else:
            n_train, n_val = (1 if n else 0), 0
        for i, r in enumerate(grp):
            assign[r["candidate_id"]] = ("train" if i < n_train
                                         else "val" if i < n_train + n_val else "test")
    labels = {label_fn(r) for r in rows}
    for target in ("val", "test"):
        held = {label_fn(r) for r in rows if assign[r["candidate_id"]] == target}
        for lab in sorted(labels - held):
            pool = ([r for r in rows if label_fn(r) == lab and assign[r["candidate_id"]] == "train"]
                    or [r for r in rows if label_fn(r) == lab
                        and assign[r["candidate_id"]] not in ("train", target)])
            if pool:
                assign[min(pool, key=lambda r: r["candidate_id"])["candidate_id"]] = target
    return assign


def main() -> None:
    rows = [r for r in read_jsonl(guard_wave1(ADMIT_DIR / "findings.jsonl"))]
    index = build_reference_index()

    outcomes: Counter = Counter()
    details: list[dict] = []
    upgraded: list[dict] = []
    for row in rows:
        new_row, status = upgrade_ghsa_row(row, index)
        outcomes[status] += 1
        if status in ("sha_upgraded", "pr_recorded"):
            rec = {
                "candidate_id": row["candidate_id"],
                "ghsa_id": row.get("ghsa_id"),
                "repo_slug": row.get("repo_slug"),
                "status": status,
                "old_fix_commit": row.get("fix_commit"),
                "new_fix_commit": new_row.get("fix_commit"),
                "old_basis": row.get("fix_commit_basis"),
                "new_basis": new_row.get("fix_commit_basis"),
                "pr_number": new_row.get("pr_number"),
            }
            details.append(rec)
            upgraded.append(new_row)

    report = {
        "built_at": utc_now(),
        "source": SOURCE,
        "admitted": len(rows),
        "admitted_by_label": dict(sorted(Counter(str(r.get("label")) for r in rows).items())),
        "admitted_with_fix_commit": sum(1 for r in rows if is_sha40(r.get("fix_commit"))),
        "fix_commit_basis_in_admitted": dict(sorted(
            Counter(str(r.get("fix_commit_basis") or "") for r in rows).items())),
        "osv_reference_scan": {
            "patched_version_tag_rows": sum(
                1 for r in rows if r.get("fix_commit_basis") == "patched_version_tag"),
            "commit_sha_upgrades": outcomes["sha_upgraded"],
            "pr_only_records": outcomes["pr_recorded"],
            "unchanged": outcomes["unchanged"],
            "not_applicable": outcomes["not_applicable"],
            "sha_upgraded_rows": outcomes["sha_upgraded"],
            "upgrades": details,
        },
        "benchmark_rows_written": {},
        "notes": [
            "METADATA_ONLY: no advisory prose vendored; this module only reads admitted metadata "
            "and cached payloads and writes its own report.",
            "Cached GitHub advisory payloads in work/sources/_api_cache have no OSV `references` "
            "array, so commit/PR URLs were harvested from the cached advisory description as a "
            "documented fallback; every URL recorded here was read from disk.",
            "A 40-hex commit URL replaces the tag-derived SHA (basis=osv_reference_commit). "
            "A PR URL alone records pr_number with basis=osv_reference_pr and RETAINS the "
            "tag-derived SHA - no SHA is invented.",
            "No candidate/admitted/invariants/PRESENT/benchmark files are written by this module; "
            "markdown.py derives severity_reconciliation from the admitted data with these same "
            "upgrade helpers, so reruns are idempotent.",
        ],
    }
    write_json(guard_wave1(REPORT_PATH), report)
    print(f"[ghsa] admitted={len(rows)} basis=patched_version_tag:"
          f"{report['osv_reference_scan']['patched_version_tag_rows']} "
          f"sha_upgraded={outcomes['sha_upgraded']} pr_recorded={outcomes['pr_recorded']} "
          f"unchanged={outcomes['unchanged']}")


if __name__ == "__main__":
    main()

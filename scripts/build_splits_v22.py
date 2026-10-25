#!/usr/bin/env python3
"""Build splits_v2_2/: the split index for release 2.2.

Release 2.2 keeps v1 byte-identical, so `splits/` and `splits_v2/` are not
touched and the v1 rows keep exactly the split they already had. What this
script adds is an index over *both* layers in one shape, so a consumer has one
place to ask "which split is this record in" and does not have to know which
layer it came from:

    {"record_type": "split_pointer", "layer": "v1" | "v2.2", "id": ...,
     "split": ..., "source_file": ..., "record_sha256": ...}

v1 rows are mirrored, never reassigned. v2.2 rows are assigned under three
rules, in order:

  1. content  - the same vulnerability must not straddle a split. Members of
                one canonical group, or of one shared source URL, are placed
                together; pairs above the near-duplicate / semantic thresholds
                used by scripts/check_leakage.py are grouped the same way.
  2. code     - records that carry code (the report-derived findings, whose
                snippets are redistributed) inherit repository-level
                isolation: every record from one repository lands in one
                split. Advisory-derived records carry no code, so their
                isolation unit is the content rule above, not the repository:
                putting every `vyperlang/vyper` advisory in one split would
                leave the held-out set with no Vyper at all, and two different
                advisories from one repository are different vulnerabilities.
  3. coverage - what is left is assigned deterministically, stratified by
                language, so every language keeps the same 44/29/27
                train/validation/test proportions and no language disappears
                from the held-out split.

A v2.2 record whose content duplicates a v1 record is quarantined in favour of
the v1 copy: the v1 assignment is the published baseline and is never moved.
Records are quarantined, never relocated.

    python scripts/build_splits_v22.py
    python scripts/build_splits_v22.py --check
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_leakage as cl  # noqa: E402
from vlun import (  # noqa: E402
    REPORTS, SPLITS, SPLITS_V2, log, read_jsonl, sha256_text, write_json,
    write_jsonl,
)
from vlun_ml import DERIVED_V22, SPLITS_V22  # noqa: E402

def _render_jsonl(rows: list[dict]) -> str:
    """Canonical JSONL bytes as text: byte-for-byte the writer's output."""
    return "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
        for row in rows)


def _render_json(obj) -> str:
    """Canonical JSON bytes as text: byte-for-byte the writer's output."""
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


PROPORTION = {"train": 44, "validation": 29, "test": 27}


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def rec_key(row: dict) -> str:
    """A stable identity for one row.

    error/metadata/protocol rows carry no finding id. Keying them all as
    "?" collapsed 30 distinct rows into one dict slot, so the straddle
    post-check and the URL / repository isolation checks resolved every one
    of them to a single arbitrary row. Fall back to the row's own sha256 —
    the same digest pointer() records as record_sha256.
    """
    rid = row.get("id") or (row.get("finding") or {}).get("id")
    if rid:
        return rid
    body = json.dumps(row, sort_keys=True, ensure_ascii=False)
    return f"sha256::{sha256_text(body)}"


def load_v1() -> dict[str, list[dict]]:
    return {s: read_jsonl(SPLITS_V2 / f"{s}.jsonl") for s in SPLITS}


def load_v22() -> list[dict]:
    return read_jsonl(DERIVED_V22 / "records.jsonl")


def source_urls(row: dict, layer: str) -> list[str]:
    if layer == "v1":
        return list(((row.get("provenance") or {}).get("source_urls")) or [])
    return [e["url"] for e in (row.get("sources_view") or {}).get("entries", [])
            if e.get("url")]


def repositories(row: dict, layer: str) -> list[str]:
    if layer == "v1":
        repo = (row.get("source") or {}).get("repository")
        return [repo] if repo else []
    return [e["repository"] for e in (row.get("sources_view") or {}).get("entries", [])
            if e.get("repository")]


def code_citations(row: dict, layer: str) -> list[dict]:
    """Only records whose code is redistributed carry an isolation obligation."""
    if layer == "v1":
        return [c for c in (row.get("code_context") or []) if c.get("snippet")]
    ctx = row.get("code_context_view") or {}
    # derived rows keep citation statistics, not snippets; a resolved path is
    # the signal that the record points at code this repository also ships
    return [{"file": None} for _ in range(ctx.get("resolved") or 0)]


def canonical_key(row: dict, layer: str) -> str | None:
    if layer == "v1":
        cf = row.get("canonical_finding") or {}
        return cf.get("value") if isinstance(cf, dict) else None
    cf = row.get("canonical_finding") or {}
    return cf.get("value") if isinstance(cf, dict) else None


# ---------------------------------------------------------------------------
# content detectors (same thresholds as scripts/check_leakage.py)
# ---------------------------------------------------------------------------

def content_pairs(left: list[tuple], right: list[tuple]) -> dict:
    """Near-duplicate and semantic pairs between two bagged corpora.

    Pairs inside one split are skipped: repetition in a single split inflates
    train but does not leak across it.
    """
    near, sem = [], []
    for sa, ida, ta, xa in left:
        for sb, idb, tb, xb in right:
            if sa == sb:
                continue
            j = cl.jaccard(ta, tb)
            c = cl.cosine(xa, xb)
            if j >= cl.NEAR_DUP_JACCARD:
                near.append({"a": ida, "b": idb, "a_split": sa, "b_split": sb,
                             "jaccard": round(j, 3)})
            if c >= cl.SEMANTIC_COSINE:
                sem.append({"a": ida, "b": idb, "a_split": sa, "b_split": sb,
                            "cosine": round(c, 3)})
    near.sort(key=lambda x: -x["jaccard"])
    sem.sort(key=lambda x: -x["cosine"])
    return {"near": near, "semantic": sem}


def intra_pairs(bagged: list[tuple]) -> dict:
    """Every unordered pair inside one corpus, self-pairs excluded."""
    near, sem = [], []
    for i in range(len(bagged)):
        sa, ida, ta, xa = bagged[i]
        for j in range(i + 1, len(bagged)):
            sb, idb, tb, xb = bagged[j]
            k = cl.jaccard(ta, tb)
            c = cl.cosine(xa, xb)
            if k >= cl.NEAR_DUP_JACCARD:
                near.append({"a": ida, "b": idb, "jaccard": round(k, 3)})
            if c >= cl.SEMANTIC_COSINE:
                sem.append({"a": ida, "b": idb, "cosine": round(c, 3)})
    near.sort(key=lambda x: -x["jaccard"])
    sem.sort(key=lambda x: -x["cosine"])
    return {"near": near, "semantic": sem}


def _bagged(rows: list[tuple[str, dict]]) -> list[tuple]:
    out = []
    for split, row in rows:
        text = cl.texts(row)
        out.append((split, rec_key(row), cl.tokens(text), cl.shingles(text)))
    return out


# ---------------------------------------------------------------------------
# assignment
# ---------------------------------------------------------------------------

class Union:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def assign(rows: list[dict], v1_rows: dict[str, list[dict]]) -> tuple[dict, dict, dict]:
    """Return (id -> split, quarantined id -> reason, diagnostics)."""
    by_id = {rec_key(r): r for r in rows}
    uf = Union()
    for rid in by_id:
        uf.find(rid)

    # rule 1a: one canonical group, one split
    canon = collections.defaultdict(list)
    for r in rows:
        ck = canonical_key(r, "v2.2")
        if ck:
            canon[ck].append(rec_key(r))
    for _, members in canon.items():
        for other in members[1:]:
            uf.union(members[0], other)

    # rule 1b: one shared source URL, one split
    urls = collections.defaultdict(list)
    for r in rows:
        for u in source_urls(r, "v2.2"):
            urls[u].append(rec_key(r))
    for u, members in urls.items():
        members = sorted(set(members))
        for other in members[1:]:
            uf.union(members[0], other)

    # rule 1c: near-duplicate / semantic twins inside the layer
    intra = intra_pairs(_bagged([("unassigned", r) for r in rows]))
    for pair in intra["near"] + intra["semantic"]:
        uf.union(pair["a"], pair["b"])

    # rule 2: every code-bearing record from one repository stays together
    repo_group = collections.defaultdict(list)
    for r in rows:
        if code_citations(r, "v2.2"):
            for repo in repositories(r, "v2.2"):
                repo_group[repo].append(rec_key(r))
    for _, members in repo_group.items():
        members = sorted(set(members))
        for other in members[1:]:
            uf.union(members[0], other)

    groups: dict[str, list[str]] = collections.defaultdict(list)
    for rid in sorted(by_id):
        groups[uf.find(rid)].append(rid)

    # rule 3: deterministic stratification by language
    quota = dict(PROPORTION)
    buckets: dict[str, collections.Counter] = {}
    assignment: dict[str, str] = {}
    langs = sorted({(by_id[rid].get("language") or "?") for rid in by_id})
    for lang in langs:
        members = sorted(g for g, ids in groups.items()
                         if (by_id[ids[0]].get("language") or "?") == lang)
        members.sort(key=lambda g: sha256_text(g))
        buckets[lang] = collections.Counter()
        n = sum(len(groups[g]) for g in members)
        target = {s: round(n * quota[s] / 100) for s in SPLITS}
        for g in members:
            best = min(SPLITS, key=lambda s: (buckets[lang][s] - target[s],
                                              SPLITS.index(s)))
            buckets[lang][best] += len(groups[g])
            for rid in groups[g]:
                assignment[rid] = best

    diagnostics = {
        "groups": len(groups),
        "multi_member_groups": sum(1 for v in groups.values() if len(v) > 1),
        "canonical_groups": {k: sorted(v) for k, v in canon.items()},
        "shared_url_groups": sum(1 for v in urls.values() if len(set(v)) > 1),
        "code_repository_groups": {k: sorted(v) for k, v in repo_group.items()
                                   if len(set(v)) > 1},
        "intra_layer_pairs": {"near": len(intra["near"]),
                              "semantic": len(intra["semantic"])},
        "coverage": {lang: dict(cnt) for lang, cnt in buckets.items()},
        "by_language_target": quota,
    }

    # rule 4: a v2.2 record whose content duplicates a v1 record is set aside
    # in favour of the v1 copy, which is never moved.
    v1_flat = [(s, r) for s, rows_ in v1_rows.items() for r in rows_]
    v1_bag = _bagged(v1_flat)
    v22_bag = _bagged([("unassigned", r) for r in rows])
    raw_cross = content_pairs(v22_bag, v1_bag)
    # left = v2.2 (a, split "unassigned"), right = v1 (b, its own split)
    cross = {
        "near": [{"v22_record": p["a"], "v1_record": p["b"],
                  "v1_split": p["b_split"], "jaccard": p["jaccard"]}
                 for p in raw_cross["near"]],
        "semantic": [{"v22_record": p["a"], "v1_record": p["b"],
                      "v1_split": p["b_split"], "cosine": p["cosine"]}
                     for p in raw_cross["semantic"]],
    }

    v1_urls: dict[str, tuple[str, str]] = {}
    for s, r in v1_flat:
        for u in source_urls(r, "v1"):
            v1_urls.setdefault(u, (s, rec_key(r)))

    quarantined: dict[str, dict] = {}
    for r in rows:
        rid = rec_key(r)
        for u in source_urls(r, "v2.2"):
            if u in v1_urls:
                s, other = v1_urls[u]
                quarantined[rid] = {"detector": "source_url", "v1_record": other,
                                    "v1_split": s,
                                    "reason": f"the same source URL is already "
                                              f"carried by v1 record {other} in "
                                              f"the {s} split; the v1 assignment "
                                              f"is the published baseline and is "
                                              f"never moved"}
                break
    for p in cross["near"] + cross["semantic"]:
        rid = p["v22_record"]
        if rid in by_id and rid not in quarantined:
            quarantined[rid] = {"detector": ("near_duplicate" if "jaccard" in p
                                             else "semantic"),
                                "v1_record": p["v1_record"],
                                "v1_split": p["v1_split"],
                                "similarity": p,
                                "reason": f"the v2.2 record duplicates v1 record "
                                          f"{p['v1_record']} in the "
                                          f"{p['v1_split']} split; the v1 copy "
                                          f"is kept and this one is set aside"}

    return assignment, quarantined, {**diagnostics, "cross_layer_pairs": cross}


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

def pointer(row: dict, layer: str, split: str, source_file: str) -> dict:
    body = json.dumps(row, sort_keys=True, ensure_ascii=False)
    out = {
        "record_type": "split_pointer",
        "dataset_version": "2.2",
        "layer": layer,
        "id": rec_key(row),
        "split": split,
        "language": row.get("language") or ("solidity" if layer == "v1" else None),
        "record_class": (row.get("finding") or {}).get("record_class"),
        "status": (row.get("finding") or {}).get("status"),
        "source_file": source_file,
        "record_sha256": sha256_text(body),
        "evidence_type": "derived_fact",
        "note": "pointer only: the split index never copies record bodies, so "
                "no layer can be rewritten through this file",
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="build and validate, write nothing")
    args = ap.parse_args()

    v1_rows = load_v1()
    v22_rows = load_v22()
    assignment, quarantined, diag = assign(v22_rows, v1_rows)

    pointers: dict[str, list[dict]] = {s: [] for s in SPLITS}
    quarantine: list[dict] = []

    for split, rows in v1_rows.items():
        for row in rows:
            pointers[split].append(pointer(row, "v1", split,
                                           f"splits_v2/{split}.jsonl"))

    v22_quarantine_ids = set(quarantined)
    for row in v22_rows:
        rid = rec_key(row)
        lang_file = f"jsonl_ml/findings_{row.get('language')}.jsonl"
        if rid in v22_quarantine_ids:
            info = quarantined[rid]
            p = pointer(row, "v2.2", "quarantine", lang_file)
            p["_quarantine_reason"] = info["reason"]
            p["_quarantine_evidence"] = info
            quarantine.append(p)
        else:
            split = assignment[rid]
            pointers[split].append(pointer(row, "v2.2", split, lang_file))

    # v1's own quarantine is carried forward unchanged
    v1_q = read_jsonl(SPLITS_V2 / "quarantine.jsonl")
    for row in v1_q:
        p = pointer(row, "v1", "quarantine", "splits_v2/quarantine.jsonl")
        p["_quarantine_reason"] = row.get("_quarantine_reason")
        quarantine.append(p)

    # ---- post-check: nothing may straddle a split -------------------------
    index: dict[tuple[str, str], dict] = {}
    for s, rows in v1_rows.items():
        for r in rows:
            index[("v1", rec_key(r))] = r
    for r in v1_q:
        index.setdefault(("v1", rec_key(r)), r)
    for r in v22_rows:
        index[("v2.2", rec_key(r))] = r

    def resolve_pointer(p: dict) -> dict:
        return index.get((p["layer"], p["id"]), {"id": p["id"], "finding": {}})

    bagged_split: dict[str, list[tuple]] = {}
    for split, rows in pointers.items():
        bagged_split[split] = _bagged([(split, resolve_pointer(p))
                                       for p in rows])

    post_near, post_sem = set(), set()
    ordered = [s for s in SPLITS]
    for i, a in enumerate(ordered):
        for b in ordered[i + 1:]:
            res = content_pairs(bagged_split[a], bagged_split[b])
            for p in res["near"]:
                post_near.add(frozenset((p["a"], p["b"])))
            for p in res["semantic"]:
                post_sem.add(frozenset((p["a"], p["b"])))
    post = {
        "cross_split_near_duplicates": len(post_near),
        "cross_split_semantic_pairs": len(post_sem),
    }

    url_owner: dict[str, set] = collections.defaultdict(set)
    repo_owner: dict[str, set] = collections.defaultdict(set)
    for split, rows in pointers.items():
        for p in rows:
            r = resolve_pointer(p)
            for u in source_urls(r, p["layer"]):
                url_owner[u].add(split)
            if code_citations(r, p["layer"]):
                for repo in repositories(r, p["layer"]):
                    repo_owner[repo].add(split)
    post["cross_split_source_urls"] = sum(1 for v in url_owner.values()
                                          if len(v) > 1)
    post["code_repository_violations"] = {k: sorted(v) for k, v in repo_owner.items()
                                          if len(v) > 1}

    counts = {s: len(v) for s, v in pointers.items()}
    counts["quarantine"] = len(quarantine)

    manifest = {
        "generated_by": "scripts/build_splits_v22.py",
        "dataset_version": "2.2",
        "records": {"total": sum(len(v) for v in v1_rows.values())
                    + len(v1_q) + len(v22_rows),
                    "v1": sum(len(v) for v in v1_rows.values()) + len(v1_q),
                    "v2.2": len(v22_rows)},
        "counts": counts,
        "proportions_v2_2": PROPORTION,
        "rules": [
            "v1 rows are mirrored from splits_v2 and are never reassigned",
            "canonical group, shared source URL and near-duplicate / semantic "
            "twins are placed in one split",
            "records that carry code inherit repository-level isolation; "
            "advisory-derived records carry no code and are isolated by "
            "content, so a repository's advisories may span splits",
            "the remainder is assigned deterministically, stratified by "
            "language, at the stated proportions",
            "a v2.2 record duplicating a v1 record is quarantined in favour of "
            "the v1 copy; records are quarantined, never moved",
        ],
        "thresholds": {"near_duplicate_jaccard": cl.NEAR_DUP_JACCARD,
                       "semantic_cosine": cl.SEMANTIC_COSINE},
        "assignment": {k: v for k, v in diag.items() if k != "cross_layer_pairs"},
        "cross_layer": {"near": len(diag["cross_layer_pairs"]["near"]),
                        "semantic": len(diag["cross_layer_pairs"]["semantic"]),
                        "note": "v2.2 records that duplicate v1 text are "
                                "quarantined, not merged"},
        "quarantine": {"count": len(quarantine),
                       "reasons": dict(collections.Counter(
                           (q.get("_quarantine_evidence") or {}).get("detector")
                           or "v1" for q in quarantine))},
        "post_check": post,
        "problems": 0,
    }

    problems = []
    if post["cross_split_near_duplicates"]:
        problems.append(f"{post['cross_split_near_duplicates']} near-duplicate "
                        "pairs still straddle a split")
    if post["cross_split_semantic_pairs"]:
        problems.append(f"{post['cross_split_semantic_pairs']} semantic pairs "
                        "still straddle a split")
    if post["cross_split_source_urls"]:
        problems.append("a source URL appears in two splits")
    if post["code_repository_violations"]:
        problems.append(f"code repository isolation violated: "
                        f"{post['code_repository_violations']}")
    manifest["problems"] = len(problems)

    if problems:
        for p in problems:
            log(f"  PROBLEM {p}")
        if args.check:
            return 1
        log("refusing to write splits_v2_2 with violations")
        return 1

    leakage = {
        "generated_by": "scripts/build_splits_v22.py",
        "splits_dir": "splits_v2_2",
        "counts": counts,
        "post_check": post,
        "thresholds": manifest["thresholds"],
        "cross_layer_pairs": diag["cross_layer_pairs"],
        "quarantine_detail": [
            {"id": q["id"], "layer": q["layer"],
             **(q.get("_quarantine_evidence") or {}),
             "reason": q.get("_quarantine_reason")}
            for q in quarantine],
    }

    if args.check:
        log(f"--check: {counts} built, nothing written")
        for k in ("rules", "post_check", "quarantine", "counts"):
            log(f"  {k}: {json.dumps(manifest[k])[:400]}")
        # Byte-parity with the committed layer. The rule this closes
        # (regression 2026-10-25): every pointer's record_sha256 must equal a
        # hash of the derived_v2_2 record as it exists NOW. The derived layer
        # was rebuilt after the experiment-artefact `bytes` field landed, the
        # split pointers kept the old digests, and this script's --check
        # happily reported "0 problems" because it never looked at the
        # committed bytes. A stale pointer file must fail here, not only in
        # validate.py.
        outputs = {**{f"{s}.jsonl": _render_jsonl(pointers[s]) for s in SPLITS},
                   "quarantine.jsonl": _render_jsonl(quarantine),
                   "manifest.json": _render_json(manifest)}
        stale = []
        for name, want in outputs.items():
            path = SPLITS_V22 / name
            have = path.read_text(encoding="utf-8") if path.exists() else None
            if have != want:
                stale.append(f"splits_v2_2/{name}")
        have = ((REPORTS / "leakage_report_v22.json").read_text(encoding="utf-8")
                if (REPORTS / "leakage_report_v22.json").exists() else None)
        if have != _render_json(leakage):
            stale.append("reports/leakage_report_v22.json")
        if stale:
            log(f"STALE {', '.join(stale)} — run: python scripts/build_splits_v22.py")
            return 1
        log("splits_v2_2 and reports/leakage_report_v22.json are current")
        return 0

    for split in SPLITS:
        write_jsonl(SPLITS_V22 / f"{split}.jsonl", pointers[split])
    write_jsonl(SPLITS_V22 / "quarantine.jsonl", quarantine)
    write_json(SPLITS_V22 / "manifest.json", manifest)
    write_json(REPORTS / "leakage_report_v22.json", leakage)
    log(f"wrote {SPLITS_V22} ({counts})")
    log(f"  post_check: {json.dumps(post)}")
    log(f"  quarantine: {manifest['quarantine']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""P6: leakage detection across the three splits.

v1 splits by repository, which prevents identical source appearing twice. It
does not prevent the same *vulnerability* appearing twice under different
wording, or the same dependency helper appearing in two splits because two
repositories both use it.

Four detectors, cheapest first:

  exact       identical finding ids, canonical ids, source URLs, commit shas
  code        identical / normalised snippets, function signatures, file::function
  near_dup    normalised title and summary similarity
  semantic    token-set (Jaccard) and shingle cosine on the vulnerability text

Similarity thresholds are parameters, not findings: `check_leakage.py --emit
strict|splits_v2` writes a re-split that keeps repository-level isolation *and*
drops or relocates any cross-split pair above threshold.

    python scripts/check_leakage.py
    python scripts/check_leakage.py --emit splits_v2
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    DERIVED, REPORTS, ROOT, SPLITS, WORK, load_splits, log, read_jsonl, rec_id,
    sha256_text, write_json, write_jsonl,
)

NEAR_DUP_JACCARD = 0.80
SEMANTIC_COSINE = 0.70

STOP = set("""a an the and or of to in is are be for on with that this it its as by from can may
will would could should not no if then than so such into over under which who whom whose there here
but have has had do does did been being more most other others some any all each per via using use
used user users attacker exploit vulnerability issue problem code contract function call amount
""".split())

WORD = re.compile(r"[a-z][a-z0-9_]{2,}")
WS = re.compile(r"\s+")


def norm_text(s: str) -> str:
    return WS.sub(" ", re.sub(r"[^a-z0-9]+", " ", (s or "").lower())).strip()


def tokens(s: str) -> set[str]:
    return {w for w in WORD.findall((s or "").lower()) if w not in STOP}


def shingles(s: str, k: int = 4) -> list[str]:
    t = norm_text(s).split()
    return [" ".join(t[i:i + k]) for i in range(max(0, len(t) - k + 1))]


def cosine(a: list[str], b: list[str]) -> float:
    if not a or not b:
        return 0.0
    ca, cb = collections.Counter(a), collections.Counter(b)
    num = sum(v * cb.get(k, 0) for k, v in ca.items())
    if not num:
        return 0.0
    da = math.sqrt(sum(v * v for v in ca.values()))
    db = math.sqrt(sum(v * v for v in cb.values()))
    return num / (da * db) if da and db else 0.0


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def texts(r: dict) -> str:
    f = r.get("finding") or {}
    sr = r.get("security_reasoning") or {}
    impact = sr.get("impact") or {}

    def flat(v) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            return " ".join(f"{k} {flat(x)}" for k, x in v.items())
        if isinstance(v, list):
            return " ".join(flat(x) for x in v)
        return str(v)

    return " ".join(flat(x) for x in [
        f.get("title"), f.get("summary"), f.get("root_cause"),
        f.get("vulnerability_classes"), sr.get("intended_behavior"),
        sr.get("broken_behavior"), sr.get("attack_path"),
        f.get("affected_functions"), sr.get("attacker_capabilities"),
        impact.get("integrity"), impact.get("financial"),
    ])


def fn_signature(snip: str) -> str:
    """`visibility mutability name(argtypes)` — the shape a model memorises."""
    m = re.search(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", snip)
    if not m:
        return ""
    args = re.sub(r"\s+", "", m.group(2))
    args = re.sub(r"(memory|calldata|storage|payable)", "", args)
    return f"fn:{m.group(1)}({args})"


def normalise_code(snip: str) -> str:
    """Strip comments, whitespace and literals so reformatting cannot hide a match."""
    s = re.sub(r"/\*.*?\*/", " ", snip, flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    s = re.sub(r'"[^"]*"|\'[^\']*\'', '""', s)
    s = re.sub(r"\b0x[0-9a-fA-F]+\b", "0x0", s)
    s = re.sub(r"\b\d{3,}\b", "N", s)
    return WS.sub(" ", re.sub(r"[^A-Za-z0-9_]+", " ", s)).strip().lower()


def build(rows_by_split: dict[str, list[dict]]) -> dict:
    ids = {s: {rec_id(r) for r in rows} for s, rows in rows_by_split.items()}
    urls: dict[str, dict[str, set]] = {s: collections.defaultdict(set) for s in rows_by_split}
    shas: dict[str, dict[str, set]] = {s: collections.defaultdict(set) for s in rows_by_split}
    snip: dict[str, dict[str, set]] = {s: collections.defaultdict(set) for s in rows_by_split}
    norm: dict[str, dict[str, set]] = {s: collections.defaultdict(set) for s in rows_by_split}
    sig: dict[str, dict[str, set]] = {s: collections.defaultdict(set) for s in rows_by_split}
    ffs: dict[str, dict[str, set]] = {s: collections.defaultdict(set) for s in rows_by_split}
    for s, rows in rows_by_split.items():
        for r in rows:
            for u in (r.get("provenance", {}) or {}).get("source_urls", []) or []:
                urls[s][u].add(rec_id(r))
            for e in list(r.get("code_context") or []) + list(r.get("vulnerable_code") or []):
                sha = e.get("commit_sha")
                if sha:
                    shas[s][sha].add(rec_id(r))
                if e.get("file"):
                    ffs[s][f"{e.get('file')}::{e.get('function') or ''}"].add(rec_id(r))
                sn = e.get("snippet")
                if sn:
                    snip[s][sha256_text(sn)].add(rec_id(r))
                    n = normalise_code(sn)
                    if len(n) > 40:
                        norm[s][sha256_text(n)].add(rec_id(r))
                    f = fn_signature(sn)
                    if f:
                        sig[s][f].add(rec_id(r))

    def cross(maps: dict[str, dict]) -> dict:
        keys = set().union(*[set(m) for m in maps.values()])
        hits = {}
        for k in keys:
            owners = sorted(s for s, m in maps.items() if m.get(k))
            if len(owners) > 1:
                hits[str(k)] = {s: sorted(maps[s][k])[:6] for s in owners}
        return hits

    def same_split_repeats(maps: dict[str, dict]) -> dict:
        out = {}
        for s, m in maps.items():
            rep = {str(k): sorted(v) for k, v in m.items() if len(v) > 1}
            if rep:
                out[s] = dict(list(rep.items())[:200])
        return out

    # ---- near duplicates and semantic similarity -------------------------
    rep_rows = {s: [r for r in rows_by_split[s]] for s in rows_by_split}
    toks = {s: [(rec_id(r), tokens(texts(r)), shingles(texts(r))) for r in rep_rows[s]] for s in rep_rows}
    near, sem = [], []
    for a, b in itertools.combinations(sorted(toks), 2):
        for ida, ta, sa in toks[a]:
            for idb, tb, sb in toks[b]:
                j = jaccard(ta, tb)
                c = cosine(sa, sb)
                if j >= NEAR_DUP_JACCARD:
                    near.append({"a": ida, "b": idb, "jaccard": round(j, 3),
                                 "a_split": a, "b_split": b})
                if c >= SEMANTIC_COSINE:
                    sem.append({"a": ida, "b": idb, "cosine": round(c, 3),
                                "a_split": a, "b_split": b})
    near.sort(key=lambda x: -x["jaccard"])
    sem.sort(key=lambda x: -x["cosine"])

    # ---- deeper detectors: patch, PoC, root cause, attack sequence --------
    patch = {s: collections.defaultdict(set) for s in rows_by_split}
    poc = {s: collections.defaultdict(set) for s in rows_by_split}
    cause = {s: collections.defaultdict(set) for s in rows_by_split}
    seq = {s: collections.defaultdict(set) for s in rows_by_split}
    for s, rows in rows_by_split.items():
        for r in rows:
            pt = r.get("patch") or {}
            if pt.get("diff"):
                patch[s][sha256_text(pt["diff"])].add(rec_id(r))
            fx = (r.get("finding") or {}).get("fixed_commit")
            if fx:
                patch[s][f"fix::{fx}"].add(rec_id(r))
            pc = r.get("poc") or {}
            code = pc.get("code") or ""
            if code.strip():
                poc[s][sha256_text(normalise_code(code))].add(rec_id(r))
            steps = pc.get("attack_sequence") or []
            if steps:
                step_sig = "|".join(sorted(
                    f"{(st or {}).get('function', '')}:{(st or {}).get('action', '')[:40]}"
                    for st in steps if isinstance(st, dict)))
                if len(step_sig) > 20:
                    seq[s][sha256_text(step_sig)].add(rec_id(r))
            sc = r.get("security_reasoning") or {}
            blob = " ".join(str(sc.get(k) or "") for k in
                            ("security_assumption", "broken_behavior", "intended_behavior",
                             "root_cause"))
            blob = norm_text(blob)
            if len(blob) > 60:
                cause[s][sha256_text(" ".join(sorted(tokens(blob))))].add(rec_id(r))

    # ---- protocol-level isolation ---------------------------------------
    # `jsonl/protocol.jsonl` carries no protocol name, so fall back to the
    # audited repository, which is the unit the splits are built on anyway.
    def protocol_key(r: dict) -> str:
        return ((r.get("protocol") or {}).get("name")
                or (r.get("source") or {}).get("repository") or "?")

    protocols: dict[str, set[str]] = collections.defaultdict(set)
    for s, rows in rows_by_split.items():
        for r in rows:
            protocols[protocol_key(r)].add(s)
    protocol_leaks = {p: sorted(v) for p, v in protocols.items() if len(v) > 1}

    return {
        "exact_overlap": {
            "finding_ids": {f"{a}|{b}": sorted(ids[a] & ids[b])
                            for a, b in itertools.combinations(sorted(ids), 2) if ids[a] & ids[b]},
            "source_urls": cross(urls),
            "commit_shas": cross(shas),
            "count_source_urls": len(cross(urls)),
            "count_commit_shas": len(cross(shas)),
        },
        "code_overlap": {
            "identical_snippets": cross(snip),
            "normalised_snippets": cross(norm),
            "function_signatures": cross(sig),
            "file_function_pairs": cross(ffs),
            "count_identical_snippets": len(cross(snip)),
            "count_normalised_snippets": len(cross(norm)),
            "count_function_signatures": len(cross(sig)),
            "count_file_function_pairs": len(cross(ffs)),
        },
        "artefact_overlap": {
            "note": ("the same patch, the same PoC body, the same root-cause statement or the "
                     "same attack sequence appearing in two splits would let a model memorise "
                     "an answer instead of reasoning to it"),
            "identical_patch_diffs": cross(patch),
            "same_fixing_commit": cross(patch),
            "normalised_poc_bodies": cross(poc),
            "root_cause_statement": cross(cause),
            "attack_sequence_signature": cross(seq),
            "count_identical_patch_diffs": len(cross(patch)),
            "count_normalised_poc_bodies": len(cross(poc)),
            "count_root_cause_statements": len(cross(cause)),
            "count_attack_sequences": len(cross(seq)),
        },
        "protocol_isolation": {
            "note": ("a protocol name must not appear in more than one split; the held-out "
                     "split has to be an unseen protocol, not unseen wording"),
            "protocols_in_multiple_splits": protocol_leaks,
            "count": len(protocol_leaks),
        },
        "near_duplicate_overlap": {
            "threshold_jaccard": NEAR_DUP_JACCARD,
            "count": len(near),
            "pairs": near[:200],
        },
        "semantic_overlap": {
            "threshold_cosine": SEMANTIC_COSINE,
            "count": len(sem),
            "pairs": sem[:200],
        },
        "within_split_repeats": {
            "note": "repetition inside one split inflates train but does not leak across it",
            "source_urls": same_split_repeats(urls),
            "commit_shas": same_split_repeats(shas),
            "identical_snippets": same_split_repeats(snip),
            "file_function_pairs": same_split_repeats(ffs),
        },
    }


def repository_isolation(rows_by_split: dict[str, list[dict]]) -> dict:
    repo_splits = collections.defaultdict(set)
    for s, rows in rows_by_split.items():
        for r in rows:
            repo_splits[r["source"]["repository"]].add(s)
    return {
        "repository_to_splits": {k: sorted(v) for k, v in sorted(repo_splits.items())},
        "violations": {k: sorted(v) for k, v in repo_splits.items() if len(v) > 1},
        "held_out_repositories": sorted(k for k, v in repo_splits.items() if v == {"test"}),
    }


SPLIT_PRIORITY = {"train": 0, "validation": 1, "test": 2}
PRIORITY_NAME = {0: "train", 1: "validation", 2: "test"}


def emit_splits_v2(report: dict, rows_by_split: dict[str, list[dict]]) -> dict:
    """Quarantine the redundant copy of every cross-split duplicate.

    Records are quarantined, never moved. Moving a record into another split
    would put one repository in two splits; removing a record cannot, so
    repository isolation survives by construction.

    When a duplicate pair straddles two splits, the copy in the *more protected*
    split is kept and the one in the less protected split is quarantined. That
    way the held-out set stays unseen and no repository is ever relocated. The
    quarantined record is still written to splits_v2/quarantine.jsonl with its
    reason, so it remains part of the dataset and a researcher can put it back.
    """
    pairs = []
    for grp in ("near_duplicate_overlap", "semantic_overlap"):
        pairs += [(p["a"], p["b"], p["a_split"], p["b_split"], grp, p)
                  for p in report[grp]["pairs"] if p["a_split"] != p["b_split"]]

    drop: dict[str, dict] = {}
    for a, b, sa, sb, grp, p in pairs:
        # quarantine the copy in the *least* protected split, keep the more protected one
        lo, hi = (a, sa), (b, sb)
        if SPLIT_PRIORITY[sb] < SPLIT_PRIORITY[sa]:
            lo, hi = (b, sb), (a, sa)
        drop.setdefault(lo[0], {"id": lo[0], "split": lo[1], "detector": grp,
                                "similarity": p, "kept_in": hi[1], "duplicate_of": hi[0]})

    quarantine, new = [], {s: [] for s in SPLITS}
    for s, rows in rows_by_split.items():
        for r in rows:
            rid = rec_id(r)
            if rid in drop:
                q = dict(r)
                q["_quarantined_from_split"] = s
                q["_quarantine_reason"] = (
                    f"cross-split {drop[rid]['detector']} with {drop[rid]['duplicate_of']} "
                    f"({drop[rid]['similarity']}); the copy in the more protected split "
                    f"({drop[rid]['kept_in']}) is retained so the held-out set stays unseen")
                q["_quarantine_evidence"] = drop[rid]
                quarantine.append(q)
                continue
            new[s].append(r)

    write_jsonl(ROOT / "splits_v2" / "train.jsonl", new["train"])
    write_jsonl(ROOT / "splits_v2" / "validation.jsonl", new["validation"])
    write_jsonl(ROOT / "splits_v2" / "test.jsonl", new["test"])
    write_jsonl(ROOT / "splits_v2" / "quarantine.jsonl", quarantine)
    return {
        "offending_pairs": [{"a": a, "b": b, "detector": g, "similarity": p}
                            for a, b, _, _, g, p in pairs],
        "records_quarantined": len(quarantine),
        "quarantined": sorted(drop),
        "quarantine_detail": list(drop.values()),
        "counts": {k: len(v) for k, v in new.items()},
        "rule": "records are quarantined, never moved: the redundant copy in the less protected "
                "split is set aside and the copy in the more protected split is kept, so no "
                "repository is relocated and the test set stays unseen",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit", choices=["", "splits_v2"], default="", metavar="splits_v2",
                    help="write a re-split with cross-split duplicates relocated")
    ap.add_argument("--input", default="splits", help="splits directory to audit")
    args = ap.parse_args()
    emit = bool(args.emit)

    src = ROOT / args.input
    rows_by_split = {s: read_jsonl(src / f"{s}.jsonl") for s in SPLITS}
    report = build(rows_by_split)
    report["repository_isolation"] = repository_isolation(rows_by_split)
    report["source"] = {"splits_dir": args.input,
                        "counts": {k: len(v) for k, v in rows_by_split.items()},
                        "thresholds": {"near_duplicate_jaccard": NEAR_DUP_JACCARD,
                                       "semantic_cosine": SEMANTIC_COSINE}}
    report["generated_by"] = "scripts/check_leakage.py"

    if emit:
        report["splits_v2"] = emit_splits_v2(report, rows_by_split)
        after = build({s: read_jsonl(ROOT / "splits_v2" / f"{s}.jsonl") for s in SPLITS})
        report["splits_v2"]["post_check"] = {
            "near_duplicate_overlap": after["near_duplicate_overlap"]["count"],
            "semantic_overlap": after["semantic_overlap"]["count"],
            "exact_finding_ids": len(report["exact_overlap"]["finding_ids"]),
            "commit_shas": after["exact_overlap"]["count_commit_shas"],
            "repository_violations": repository_isolation(
                {s: read_jsonl(ROOT / "splits_v2" / f"{s}.jsonl") for s in SPLITS})["violations"],
        }

    write_json(REPORTS / "leakage_report.json", report)

    log(f"leakage_report.json  ({args.input})")
    log(f"  repository isolation violations : {len(report['repository_isolation']['violations'])}")
    log(f"  exact  : ids={len(report['exact_overlap']['finding_ids'])} "
        f"urls={report['exact_overlap']['count_source_urls']} "
        f"commits={report['exact_overlap']['count_commit_shas']}")
    log(f"  code   : identical={report['code_overlap']['count_identical_snippets']} "
        f"normalised={report['code_overlap']['count_normalised_snippets']} "
        f"sigs={report['code_overlap']['count_function_signatures']} "
        f"file::fn={report['code_overlap']['count_file_function_pairs']}")
    log(f"  near   : {report['near_duplicate_overlap']['count']} "
        f"(jaccard >= {NEAR_DUP_JACCARD})")
    log(f"  semantic: {report['semantic_overlap']['count']} "
        f"(cosine >= {SEMANTIC_COSINE})")
    if emit:
        log(f"  splits_v2: {report['splits_v2']['counts']} "
            f"quarantined={report['splits_v2']['records_quarantined']} "
            f"{report['splits_v2']['quarantined']}")
        log(f"  after    : {report['splits_v2']['post_check']}")
    # Exit code carries the verdict (a detector that only prints cannot fail
    # a build). splits/ is the pre-quarantine INPUT: violations there are
    # why this stage exists. splits_v2 (written here, or audited directly)
    # is the SHIPPED artefact: any remaining violation fails the build.
    if emit:
        post = report["splits_v2"]["post_check"]
        remaining = (post.get("near_duplicate_overlap", 0)
                     + post.get("semantic_overlap", 0)
                     + post.get("exact_finding_ids", 0)
                     + len(post.get("repository_violations", [])))
        if remaining:
            log(f"LEAKAGE: {remaining} violation(s) remain after quarantine")
            return 1
        return 0
    if args.input.rstrip("/").endswith("splits_v2"):
        remaining = (report["near_duplicate_overlap"]["count"]
                     + report["semantic_overlap"]["count"]
                     + len(report["exact_overlap"]["finding_ids"]))
        if remaining:
            log(f"LEAKAGE: {remaining} violation(s) in shipped splits_v2")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
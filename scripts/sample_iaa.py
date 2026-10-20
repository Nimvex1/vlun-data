#!/usr/bin/env python3
"""Reproducible stratified draw for the item-14 inter-annotator-agreement study.

Writes annotation/iaa_v1/sample.jsonl: the BLINDED worksheet rows annotators receive.
It contains no gold answer - the dataset's own severity labels, C4 classes, root-cause
candidate text and taxonomy/assignments_v1.jsonl labels are deliberately excluded, so an
annotator cannot anchor on them. The record id is enough for scoring afterwards.

Sampling design (documented in annotation/iaa_v1/protocol.md):
  stratum = (severity band, evidence band, root-cause-label status, source project size)
  target n = 300 over the 722 records in derived/records.jsonl
  allocation = proportional (largest remainder), strata capped at their population,
  leftover quota redistributed to the largest remaining strata; ties broken by the
  lexicographic stratum key, so the draw is byte-reproducible.

usage:
    python scripts/sample_iaa.py --seed 20261018 --target 300
    python scripts/sample_iaa.py --check        # fail (exit 1) if the file would change
"""
from __future__ import annotations

import argparse
import json
import os
import csv
import random
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDS = os.path.join("derived", "records.jsonl")
ASSIGN = os.path.join("taxonomy", "assignments_v1.jsonl")
OUT = os.path.join("annotation", "iaa_v1", "sample.jsonl")
BLANK_DIR = os.path.join("annotation", "iaa_v1", "blank")
TEMPLATE_COLUMNS = [
    "sample_id", "record_id", "annotator_id", "annotator_kind", "annotated_at_utc",
    "rc_labels", "rc_primary", "unlabelled_or_wrong_category", "unlabelled_reason",
    "severity_tier", "evidence_ceiling", "invariant_stated", "flag_new_category",
    "adjudication_flag", "notes",
]
DEFAULT_SEED = 20261018
DEFAULT_TARGET = 300
TIER_RANK = {"qa": 1, "low": 1, "medium": 2, "high": 3, "critical": 3, "": 0, "info": 0, "informational": 0}


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def severity_band(sev):
    rank = TIER_RANK.get(str(sev or "").strip().lower(), 0)
    return "S0-none" if rank == 0 else "S%d" % rank


def evidence_band(level):
    if level in ("L4", "L5", "L6"):
        return "E-high"
    if level == "L2":
        return "E-L2"
    return "E-low"


def label_band(row):
    if row is None:
        return "A-out-of-pool"
    if row["unlabelled"]:
        return "A-unlabelled"
    if row["assignment_basis"] == "adjudicated_candidate":
        return "A-adjudicated"
    return "A-rule"


def build(records, assignments, seed, target):
    by_id = {r["id"]: r for r in records}
    arow = {a["record_id"]: a for a in assignments}
    strata = defaultdict(list)
    for r in records:
        a = arow.get(r["id"])
        key = (severity_band((r.get("finding") or {}).get("severity")),
               evidence_band(a["evidence_level"] if a else "L0"),
               label_band(a))
        strata["/".join(key)].append(r["id"])
    for k in strata:
        strata[k].sort()

    total = sum(len(v) for v in strata.values())
    quota = max(1, min(target, total))
    # proportional largest-remainder allocation, capped at stratum size
    keys = sorted(strata)
    raw = {k: quota * len(strata[k]) / total for k in keys}
    alloc = {k: int(raw[k]) for k in keys}
    alloc = {k: min(alloc[k], len(strata[k])) for k in keys}
    short = quota - sum(alloc.values())
    order = sorted(keys, key=lambda k: (-(raw[k] - int(raw[k])), -len(strata[k]), k))
    i = 0
    while short > 0 and order:
        k = order[i % len(order)]
        if alloc[k] < len(strata[k]):
            alloc[k] += 1
            short -= 1
        i += 1
        if i > 10 * len(order) * max(1, quota):
            break
    if short > 0:  # every stratum saturated
        quota = sum(alloc.values())

    rng = random.Random(seed)
    picked = []
    for k in keys:
        pool = list(strata[k])
        rng.shuffle(pool)
        for rid in pool[: alloc[k]]:
            picked.append((rid, k))
    picked.sort()

    rows = []
    for rid, k in picked:
        r = by_id[rid]
        sr = r.get("security_reasoning") or {}
        cc = (r.get("code_context") or [])[:3]
        rows.append({
            "sample_id": "%s::%s" % (k, rid),
            "record_id": rid,
            "stratum": k,
            "seed": seed,
            "draw_version": "iaa-draw-1.0",
            "blinded": True,
            "hidden_from_annotator": ["finding.severity", "taxonomy.class", "taxonomy.category",
                                      "root_cause_candidate", "security_reasoning.broken_behavior",
                                      "security_reasoning.invariants", "taxonomy/assignments_v1.jsonl labels"],
            "visible": {
                "protocol": (r.get("protocol") or {}).get("name"),
                "source_layer": r.get("source_layer_version"),
                "title": (r.get("finding") or {}).get("title"),
                "sponsor_status": (r.get("finding") or {}).get("status"),
                "intended_behaviour": sr.get("intended_behavior") or None,
                "security_assumption": sr.get("security_assumption") or None,
                "attack_path": (sr.get("attack_path") or [])[:6],
                "attacker_constraints": (r.get("attacker_model") or {}).get("attacker_constraints")[:3],
                "code_context": [{"file": c.get("file"), "contract": c.get("contract"),
                                  "function": c.get("function"), "line_start": c.get("line_start"),
                                  "line_end": c.get("line_end"), "commit_sha": c.get("commit_sha"),
                                  "snippet": (c.get("snippet") or "")[:1400],
                                  "line_range_verified": c.get("line_range_verified")} for c in cc],
                "poc": {"available": bool((r.get("poc") or {}).get("available")),
                        "has_code": bool((r.get("poc") or {}).get("code")),
                        "setup": ((r.get("poc") or {}).get("setup") or "")[:600],
                        "expected_impact": ((r.get("poc") or {}).get("expected_impact") or "")[:400],
                        "observed_impact": ((r.get("poc") or {}).get("observed_impact") or "")[:400]},
                "patch": {"available": bool((r.get("patch") or {}).get("available"),),
                          "has_diff": bool((r.get("patch") or {}).get("diff")),
                          "explanation": ((r.get("patch") or {}).get("explanation") or "")[:800]},
                "verification": {"attempted": (r.get("verification") or {}).get("attempted"),
                                 "verdict": (r.get("verification") or {}).get("verdict"),
                                 "poc_type": (r.get("verification") or {}).get("poc_type"),
                                 "failure_reason": (r.get("verification") or {}).get("failure_reason"),
                                 "test_evidence": (r.get("verification") or {}).get("test_evidence")},
                "evidence_types_present": (r.get("evidence") or {}).get("evidence_types_present"),
            },
        })
    return rows, alloc, strata, quota


def render(rows, seed, target, alloc, strata, records, assignments):
    header = {
        "draw_version": "iaa-draw-1.0",
        "generated_by": "scripts/sample_iaa.py",
        "seed": seed,
        "target_n": target,
        "population": len(records),
        "pool_with_assignments": len(assignments),
        "realised_n": len(rows),
        "strata_axes": ["severity band (S0-none,S1,S2,S3)",
                        "evidence band (E-low = L0/L1, E-L2, E-high = L4-L6)",
                        "root-cause label status (A-adjudicated, A-rule, A-unlabelled, A-out-of-pool)"],
        "allocation": {k: alloc[k] for k in sorted(alloc)},
        "stratum_population": {k: len(strata[k]) for k in sorted(strata)},
        "blinding": "gold fields listed in hidden_from_annotator per row are not present in this file",
        "note": "this is a sampling artefact only; no annotations have been collected, so no agreement "
                "statistic exists (see annotation/iaa_v1/protocol.md)",
    }
    body = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in rows)
    return json.dumps(header, ensure_ascii=False, separators=(",", ":")) + "\n" + body


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--target", type=int, default=DEFAULT_TARGET)
    ap.add_argument("--check", action="store_true", help="exit 1 if the committed draw would change")
    ap.add_argument("--write-templates", action="store_true",
                    help="emit blank/annotator_{1,2,3}.template.csv with the drawn rows prefilled and every answer column empty")
    args = ap.parse_args(argv)

    records = load_jsonl(os.path.join(args.root, RECORDS))
    apath = os.path.join(args.root, ASSIGN)
    assignments = load_jsonl(apath) if os.path.exists(apath) else []
    rows, alloc, strata, quota = build(records, assignments, args.seed, args.target)
    text = render(rows, args.seed, args.target, alloc, strata, records, assignments)
    out = os.path.join(args.root, OUT)
    if args.write_templates:
        bdir = os.path.join(args.root, BLANK_DIR)
        os.makedirs(bdir, exist_ok=True)
        for n in (1, 2, 3):
            path = os.path.join(bdir, "annotator_%d.template.csv" % n)
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(TEMPLATE_COLUMNS)
                for r in rows:
                    w.writerow([r["sample_id"], r["record_id"], "", "", "", "", "", "", "", "", "", "", "", "", ""])
            print("wrote %s (%d blank rows, no responses invented)" % (path, len(rows)))
        return 0
    if args.check:
        cur = open(out, encoding="utf-8").read() if os.path.exists(out) else None
        if cur != text:
            print("DRIFT: %s would change" % OUT, file=sys.stderr)
            return 1
        print("OK: realised n=%d over %d strata, byte-stable" % (len(rows), len(strata)))
        return 0
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote %s: realised n=%d (target %d) over %d strata, seed %d"
          % (OUT, len(rows), args.target, len(strata), args.seed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

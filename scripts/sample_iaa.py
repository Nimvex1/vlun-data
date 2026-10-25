#!/usr/bin/env python3
"""Versioned stratified draw for the item-14 inter-annotator-agreement study.

annotation/iaa_v1/sample.jsonl is a FROZEN artefact: the blank annotator templates were
generated from it, so it is validated against annotation/iaa_v1/frozen_sample.json rather
than regenerated. A fresh draw must be versioned separately:

    python scripts/sample_iaa.py --check
    python scripts/sample_iaa.py --redraw --out annotation/iaa_v2 \
        --draw-version iaa-draw-2.0 --seed 20261024 --rationale "why a new draw exists"

The sample file contains no gold answer: the dataset's own severity labels, C4 classes,
root-cause candidate text and taxonomy/assignments_v1.jsonl labels are deliberately
excluded, so an annotator cannot anchor on them. The record id is enough for scoring.

Sampling design (documented in annotation/iaa_v1/protocol.md):
  stratum = (severity band, evidence band, root-cause-label status)
  target n = 300 over the records in derived/records.jsonl
  allocation = proportional (largest remainder), strata capped at their population,
  leftover quota redistributed to the largest remaining strata; ties broken by the
  lexicographic stratum key, so a draw is byte-reproducible from the same inputs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDS = os.path.join("derived", "records.jsonl")
ASSIGN = os.path.join("taxonomy", "assignments_v1.jsonl")
V1_DIR = os.path.join("annotation", "iaa_v1")
OUT = os.path.join(V1_DIR, "sample.jsonl")
FROZEN = os.path.join(V1_DIR, "frozen_sample.json")
BLANK_DIR = os.path.join(V1_DIR, "blank")
TEMPLATE_COLUMNS = [
    "sample_id", "record_id", "annotator_id", "annotator_kind", "annotated_at_utc",
    "rc_labels", "rc_primary", "unlabelled_or_wrong_category", "unlabelled_reason",
    "severity_tier", "evidence_ceiling", "invariant_stated", "flag_new_category",
    "adjudication_flag", "notes",
]
TEMPLATES = ("annotator_1.template.csv", "annotator_2.template.csv", "annotator_3.template.csv")
DEFAULT_TARGET = 300
TIER_RANK = {"qa": 1, "low": 1, "medium": 2, "high": 3, "critical": 3, "": 0, "info": 0, "informational": 0}


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


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


def build(records, assignments, seed, target, draw_version):
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
            "draw_version": draw_version,
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


def render(rows, seed, target, alloc, strata, records, assignments, draw_version, rationale):
    header = {
        "draw_version": draw_version,
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
        "rationale": rationale,
        "note": "this is a sampling artefact only; no annotations have been collected, so no agreement "
                "statistic exists (see annotation/iaa_v1/protocol.md)",
    }
    body = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in rows)
    return json.dumps(header, ensure_ascii=False, separators=(",", ":")) + "\n" + body


def frozen_errors(root):
    """Validate the frozen v1 artefact against its committed manifest."""
    fdir = os.path.join(root, V1_DIR)
    manifest_path = os.path.join(fdir, "frozen_sample.json")
    if not os.path.exists(manifest_path):
        return ["%s is missing: the v1 sample has no frozen provenance record" % FROZEN]
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    errors = []
    sample_path = os.path.join(fdir, "sample.jsonl")
    if not os.path.exists(sample_path):
        return ["%s is missing" % OUT]
    if sha256_file(sample_path) != manifest.get("sample_sha256"):
        errors.append("%s does not match the frozen sha256 in %s" % (OUT, FROZEN))
    with open(sample_path, encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
    header = json.loads(lines[0])
    for key in ("draw_version", "seed", "target_n", "population", "realised_n"):
        if header.get(key) != manifest.get(key):
            errors.append("sample header %s=%r != frozen %r" % (key, header.get(key), manifest.get(key)))
    rows = [json.loads(line) for line in lines[1:]]
    if len(rows) != manifest.get("realised_n"):
        errors.append("sample has %d rows, frozen manifest says %r"
                      % (len(rows), manifest.get("realised_n")))
    for name, expected in (manifest.get("templates") or {}).items():
        path = os.path.join(root, BLANK_DIR, name)
        if not os.path.exists(path):
            errors.append("%s is missing" % path)
        elif sha256_file(path) != expected:
            errors.append("%s does not match the frozen template sha256" % path)
    sample_ids = {r["sample_id"] for r in rows}
    for name in manifest.get("templates") or {}:
        path = os.path.join(root, BLANK_DIR, name)
        if not os.path.exists(path):
            continue
        with open(path, newline="", encoding="utf-8") as fh:
            template_ids = {r["sample_id"] for r in csv.DictReader(fh)}
        if template_ids != sample_ids:
            errors.append("%s rows do not match the frozen sample (templates came from a "
                          "different draw)" % path)
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--check", action="store_true",
                    help="validate the frozen v1 sample and templates against frozen_sample.json")
    ap.add_argument("--redraw", action="store_true",
                    help="create a separately versioned sample; never writes annotation/iaa_v1")
    ap.add_argument("--out", help="output directory for --redraw (e.g. annotation/iaa_v2)")
    ap.add_argument("--draw-version", help="version string for --redraw (must not be iaa-draw-1.0)")
    ap.add_argument("--seed", type=int, help="explicit seed for --redraw")
    ap.add_argument("--target", type=int, default=DEFAULT_TARGET)
    ap.add_argument("--rationale", help="why a new draw is required (recorded in the header)")
    ap.add_argument("--write-templates", action="store_true",
                    help="with --redraw: also emit blank annotator CSVs into <out>/blank")
    args = ap.parse_args(argv)

    if args.check:
        errors = frozen_errors(args.root)
        if errors:
            for error in errors:
                print("DRIFT: %s" % error, file=sys.stderr)
            return 1
        with open(os.path.join(args.root, FROZEN), encoding="utf-8") as fh:
            manifest = json.load(fh)
        print("OK: frozen %s, n=%d, seed=%d, templates match"
              % (manifest["draw_version"], manifest["realised_n"], manifest["seed"]))
        return 0

    if not args.redraw:
        ap.error("refusing to overwrite the frozen v1 sample; use --check or --redraw "
                 "--out <new dir> --draw-version <v> --seed <n> --rationale <text>")
    missing = [name for name in ("out", "draw_version", "seed", "rationale")
               if getattr(args, name) in (None, "")]
    if missing:
        ap.error("--redraw requires %s" % ", ".join("--" + m.replace("_", "-") for m in missing))
    if args.draw_version == "iaa-draw-1.0":
        ap.error("--draw-version iaa-draw-1.0 is the frozen v1 draw; choose a new version")
    out_dir = os.path.normpath(os.path.join(args.root, args.out))
    v1_dir = os.path.normpath(os.path.join(args.root, V1_DIR))
    if out_dir == v1_dir or v1_dir.startswith(out_dir + os.sep):
        ap.error("--out must not be annotation/iaa_v1 or contain it")

    records = load_jsonl(os.path.join(args.root, RECORDS))
    apath = os.path.join(args.root, ASSIGN)
    assignments = load_jsonl(apath) if os.path.exists(apath) else []
    rows, alloc, strata, quota = build(records, assignments, args.seed, args.target,
                                       args.draw_version)
    text = render(rows, args.seed, args.target, alloc, strata, records, assignments,
                  args.draw_version, args.rationale)
    os.makedirs(out_dir, exist_ok=True)
    sample_path = os.path.join(out_dir, "sample.jsonl")
    with open(sample_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    template_hashes = {}
    if args.write_templates:
        bdir = os.path.join(out_dir, "blank")
        os.makedirs(bdir, exist_ok=True)
        for n in (1, 2, 3):
            path = os.path.join(bdir, TEMPLATES[n - 1])
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(TEMPLATE_COLUMNS)
                for r in rows:
                    w.writerow([r["sample_id"], r["record_id"], "", "", "", "", "", "", "", "", "", "", "", "", ""])
            template_hashes[TEMPLATES[n - 1]] = sha256_file(path)
            print("wrote %s (%d blank rows, no responses invented)" % (path, len(rows)))
    manifest = {
        "draw_version": args.draw_version,
        "seed": args.seed,
        "target_n": args.target,
        "population": len(records),
        "pool_with_assignments": len(assignments),
        "realised_n": len(rows),
        "selection": "proportional largest-remainder stratified draw over (severity band, "
                     "evidence band, root-cause label status); seeded shuffle",
        "rationale": args.rationale,
        "sample_sha256": sha256_file(sample_path),
        "templates": template_hashes,
    }
    with open(os.path.join(out_dir, "frozen_sample.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote %s: realised n=%d (target %d) over %d strata, seed %d, version %s"
          % (sample_path, len(rows), args.target, len(strata), args.seed, args.draw_version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

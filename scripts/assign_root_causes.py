#!/usr/bin/env python3
"""Assign root-cause labels from the closed vocabulary in taxonomy/root_cause_v1.jsonl.

This is an OVERLAY. It never edits derived/records.jsonl or any other canonical
file; it writes taxonomy/assignments_v1.jsonl and reports/root_cause_taxonomy_stats.json.

How a label is produced, in decreasing precedence:

1. `adjudicated_candidate` - the 40 candidates in derived/root_cause_candidates.jsonl
   were read one by one and their labels recorded in ADJUDICATED below. This is the
   validation step described in taxonomy/derivation_log.md; a candidate whose text is
   an editorial lead-in rather than a cause statement is left unlabelled.
2. `v1_class_rule` - the record's v1 `taxonomy.class` string is mapped through
   CLASS_RULES. Several class strings name an impact ("Blocked withdrawals"), a
   primitive ("Flash-loan interaction") or a component ("AMM invariant logic") rather
   than a cause; those map to an unlabelled outcome with a reason instead of being
   forced into the nearest leaf.
3. `unlabelled` - nothing grounded the record. No label is invented to fill a bucket.

Evidence level per record is derived from the record's own fields (see
evidence_level()) and a label is `provisional` when the record sits below the
category's minimum evidence level. Deterministic, stdlib only.

usage:
    python scripts/assign_root_causes.py             # write outputs
    python scripts/assign_root_causes.py --check     # fail (exit 1) on drift
    python scripts/assign_root_causes.py --help
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY = os.path.join("taxonomy", "root_cause_v1.jsonl")
RECORDS = os.path.join("derived", "records.jsonl")
CANDIDATES = os.path.join("derived", "root_cause_candidates.jsonl")
PATCHES = os.path.join("reports", "patch_verification_v2.json")
OUT_ASSIGN = os.path.join("taxonomy", "assignments_v1.jsonl")
OUT_STATS = os.path.join("reports", "root_cause_taxonomy_stats.json")

TAXONOMY_VERSION = "root-cause-1.0"
SENTINEL = "RC-99"

# ---------------------------------------------------------------------------
# 1. hand-adjudicated candidate labels (see taxonomy/derivation_log.md)
# ---------------------------------------------------------------------------
ADJUDICATED = {
    "2024-01-decent/H-01": (["RC-01", "RC-02"], "RC-01"),
    "2024-01-decent/H-02": (["RC-14", "RC-04"], "RC-14"),
    "2024-01-decent/H-03": (["RC-07", "RC-02"], "RC-07"),
    "2024-01-decent/H-04": (["RC-03", "RC-04"], "RC-03"),
    "2024-01-renft/H-01": (["RC-02"], "RC-02"),
    "2024-01-renft/H-03": (["RC-17"], "RC-17"),
    "2024-01-renft/H-04": (["RC-07"], "RC-07"),
    "2024-01-renft/H-05": ([], None),
    "2024-01-renft/H-06": (["RC-08"], "RC-08"),
    "2024-01-renft/H-07": (["RC-08"], "RC-08"),
    "2024-04-noya/H-03": (["RC-19", "RC-09"], "RC-19"),
    "2024-04-noya/H-04": (["RC-05", "RC-18"], "RC-05"),
    "2024-04-noya/H-09": (["RC-18"], "RC-18"),
    "2024-04-noya/H-10": (["RC-21"], "RC-21"),
    "2024-04-noya/H-11": (["RC-18", "RC-10"], "RC-18"),
    "2024-04-noya/H-12": (["RC-07"], "RC-07"),
    "2024-04-noya/H-16": (["RC-03"], "RC-03"),
    "2024-04-noya/H-17": (["RC-03"], "RC-03"),
    "2024-04-noya/H-19": (["RC-09"], "RC-09"),
    "2024-04-noya/H-21": (["RC-06", "RC-10"], "RC-06"),
    "2024-08-wildcat/H-01": (["RC-13", "RC-15"], "RC-13"),
    "2024-12-bakerfi/H-01": (["RC-09", "RC-21"], "RC-09"),
    "2024-12-bakerfi/H-02": (["RC-01"], "RC-01"),
    "2024-12-bakerfi/H-03": (["RC-06"], "RC-06"),
    "2024-12-bakerfi/H-04": (["RC-09"], "RC-09"),
    "2024-12-bakerfi/H-05": (["RC-16"], "RC-16"),
    "2024-12-bakerfi/H-06": (["RC-01"], "RC-01"),
    "2024-12-bakerfi/H-07": (["RC-01"], "RC-01"),
    "2025-06-panoptic/H-01": (["RC-11"], "RC-11"),
    "2025-06-panoptic/H-02": (["RC-10"], "RC-10"),
    "2025-08-gte-perps/H-01": (["RC-15"], "RC-15"),
    "2025-08-gte-perps/H-02": (["RC-15"], "RC-15"),
    "2025-08-gte-perps/H-03": (["RC-10"], "RC-10"),
    "2025-08-gte-perps/H-04": (["RC-10"], "RC-10"),
    "2025-08-gte-perps/H-05": (["RC-10"], "RC-10"),
    "2025-08-gte-perps/H-06": (["RC-02"], "RC-02"),
    "2025-08-gte-perps/H-07": (["RC-06", "RC-08"], "RC-06"),
    "2025-08-gte-perps/H-08": (["RC-20"], "RC-20"),
    "2025-08-gte-perps/H-09": (["RC-16", "RC-15"], "RC-16"),
    "2025-08-gte-perps/H-10": (["RC-12"], "RC-12"),
}

UNLABELLED_CANDIDATE_REASON = {
    "2024-01-renft/H-05": (
        "the candidate text is the report's editorial lead-in ('takes advantage of multiple "
        "bugs'); it states no cause, so no leaf's inclusion rule is satisfied"
    ),
}

# ---------------------------------------------------------------------------
# 2. v1 class string -> labels (or an explicit unlabelled reason)
# ---------------------------------------------------------------------------
CLASS_RULES = {
    # access / trust boundary
    "Missing authorisation check": (["RC-01"], "RC-01"),
    "Privilege escalation": (["RC-01"], "RC-01"),
    "Incorrect authorisation check": (["RC-01"], "RC-01"),
    "Initializer access": (["RC-01", "RC-22"], "RC-01"),
    "Arbitrary recipient": (["RC-01"], "RC-01"),
    "Approval misuse": (["RC-01"], "RC-01"),
    "Trust-boundary failure": (["RC-02"], "RC-02"),
    # cross-domain
    "Bridge authorisation": (["RC-04"], "RC-04"),
    "Message verification": (["RC-04"], "RC-04"),
    "Broken cross-contract invariant": (["RC-18"], "RC-18"),
    "Inconsistent cross-contract state": (["RC-18"], "RC-18"),
    "Incompatible protocol assumptions": (["RC-18"], "RC-18"),
    "Unsafe composability": (["RC-17"], "RC-17"),
    # liveness
    "Gas exhaustion": (["RC-15"], "RC-15"),
    "Unbounded iteration": (["RC-15"], "RC-15"),
    # ordering / interleaving
    "classic reentrancy": (["RC-17"], "RC-17"),
    "Callback abuse": (["RC-17"], "RC-17"),
    "unsafe external call ordering": (["RC-17", "RC-16"], "RC-17"),
    "Unvalidated return value": (["RC-05"], "RC-05"),
    "Flash-loan interaction": (None, "the v1 class names an attack primitive (a way of funding "
                                      "and composing the call), not a cause; the record's own prose "
                                      "does not state which check is missing"),
    # verification
    "Slippage": (["RC-03"], "RC-03"),
    "Oracle manipulation": (["RC-19"], "RC-19"),
    "Stale price": (["RC-19"], "RC-19"),
    "Missing domain separation": (["RC-23"], "RC-23"),
    "Signature replay": (["RC-23"], "RC-23"),
    "Signature malleability": (["RC-23"], "RC-23"),
    "Incorrect nonce handling": (["RC-23"], "RC-23"),
    "Authorisation signature bug": (["RC-23"], "RC-23"),
    # state
    "Wrong variable or branch": (["RC-07"], "RC-07"),
    "Missing state update": (["RC-06"], "RC-06"),
    "Storage collision": (["RC-22"], "RC-22"),
    "Unauthorised upgrade": (["RC-22", "RC-01"], "RC-22"),
    "Unsafe delegatecall": (["RC-22", "RC-02"], "RC-22"),
    "Timelock bypass": (["RC-08"], "RC-08"),
    # computation
    "Rounding error": (["RC-13"], "RC-13"),
    "Inflation": (["RC-13"], "RC-13"),
    "Asset/share mismatch": (["RC-09"], "RC-09"),
    "Incorrect reserves": (["RC-10"], "RC-10"),
    "Incorrect balance accounting": (["RC-10"], "RC-10"),
    "Incorrect collateral accounting": (["RC-10"], "RC-10"),
    "Incorrect debt accounting": (["RC-10"], "RC-10"),
    "Leverage accounting": (["RC-10", "RC-03"], "RC-10"),
    "Bad debt": (["RC-03"], "RC-03"),
    "Fee miscalculation": (["RC-12", "RC-06"], "RC-12"),
    "Reward accounting": (["RC-12"], "RC-12"),
    "AMM invariant logic": (None, "the v1 class names the component (an AMM pair's logic), not a "
                                  "cause; the record must state which quantity, bound, or update fails"),
    # token-standard assumptions
    "Non-standard ERC20 assumption": (["RC-18"], "RC-18"),
    "Rebasing token mishandling": (["RC-18", "RC-10"], "RC-18"),
    "ERC4626 non-compliance": (["RC-18", "RC-09"], "RC-18"),
    "ERC721 assumption break": (["RC-18"], "RC-18"),
    "ERC1155 assumption break": (["RC-18"], "RC-18"),
    # impact-named classes
    "Blocked withdrawals": (None, "the v1 class names the impact (withdrawals stop); the cause is "
                                  "one of RC-05, RC-15 or RC-01 and is not stated by the record"),
    "Blocked liquidation": (None, "the v1 class names the impact; the failing cause is not stated"),
    "Permanent DoS": (None, "the v1 class names the impact (a permanent availability loss), not the cause"),
    "Temporary DoS": (None, "the v1 class names the impact, not the cause"),
    "Griefing": (None, "the v1 class names an attacker motive/primitive, not a cause"),
    "Liquidation failure": (None, "the v1 class names the impact of a failure whose cause is unstated"),
    "Insolvency": (None, "the v1 class names the impact (the protocol cannot pay), not the cause"),
    "Missing kill switch": (None, "an absent operational control is not a defect in the code's own logic; "
                                  "the vocabulary has no leaf for 'no pause mechanism' (coverage gap G-1)"),
    "Emergency control weakness": (None, "the class describes a governance posture, not a code-level cause "
                                         "(coverage gap G-1)"),
    "Incorrect hash construction": (["RC-23"], "RC-23"),
}

# classes whose label is upgraded by an explicit keyword in the record's own reasoning
SECONDARY_KEYWORDS = [
    (("blocklist", "blacklist", "reverts on transfer", "transfer reverts"), ["RC-05"]),
    (("front-run", "frontrun", "sandwich", "ordering", "same block"), ["RC-16"]),
    (("reenter", "callback", "untrusted token can call back"), ["RC-17"]),
    (("decimals", "scale", "1e18", "precision of units"), ["RC-09"]),
    (("unbounded loop", "for loop over", "iterate over the queue", "array of"), ["RC-15"]),
]

LADDER = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]
MAX_LABELS = 3


def load_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def evidence_level(rec, l6_ids):
    """Return (level, basis) for one derived record."""
    v = rec.get("verification") or {}
    p = rec.get("poc") or {}
    rid = rec["id"]
    if rid in l6_ids:
        return "L6", "the same test observed the violation at the audited revision and the fixed revision blocked it (reports/patch_verification_v2.json, fix_effectiveness=effective)"
    if v.get("verdict") == "reproduced":
        return "L5", "verification.verdict=reproduced: an executed run observed the claimed violation"
    if v.get("attempted") and v.get("test_evidence"):
        return "L4", "verification.test_evidence records an executed run (forge_status present) without a reproduced verdict"
    if p.get("available") and p.get("code"):
        return "L2", "PoC quoted from the report plus source reconstructed at the pinned commit; nothing executed, so the ladder's compile step (L3) is not attested"
    if any(c.get("file_resolved") and c.get("line_range_verified") for c in (rec.get("code_context") or [])):
        return "L2", "code_context resolved to a file and line range verified against the pinned commit"
    if any(c.get("snippet") for c in (rec.get("code_context") or [])):
        return "L1", "code quoted without verification against the pinned revision"
    return "L0", "prose only: the record carries no verifiable code context"


def root_cause_bearing(rec, candidate_ids):
    sr = rec.get("security_reasoning") or {}
    return (rec["id"] in candidate_ids
            or bool((sr.get("broken_behavior") or "").strip())
            or bool(sr.get("invariants"))
            or bool(((rec.get("finding") or {}).get("root_cause") or "").strip()))


def assign(rec, candidate_ids, l6_ids, taxonomy):
    rid = rec["id"]
    level, basis = evidence_level(rec, l6_ids)
    labels, primary, method = [], None, None
    reason = None
    if rid in ADJUDICATED:
        labels, primary = list(ADJUDICATED[rid][0]), ADJUDICATED[rid][1]
        method = "adjudicated_candidate"
        if not labels:
            reason = UNLABELLED_CANDIDATE_REASON.get(
                rid, "the candidate does not state a cause that satisfies any leaf's inclusion rules")
    else:
        cls = str((rec.get("taxonomy") or {}).get("class") or "")
        rule = CLASS_RULES.get(cls)
        if rule and rule[0]:
            labels, primary, method = list(rule[0]), rule[1], "v1_class_rule"
        elif rule:
            reason, method = rule[1], "v1_class_rule"
        else:
            reason = ("the record's v1 class %r carries no rule in this version of the vocabulary, so the "
                      "record is left unlabelled rather than forced into the nearest leaf" % (cls or "None"))
            method = "v1_class_rule" if cls else "no_class"
    # secondary upgrade from the record's own reasoning text
    if labels:
        text = json.dumps({k: v for k, v in rec.items() if k in ("security_reasoning", "finding")},
                          ensure_ascii=False).lower()
        extra = set()
        for keys, adds in SECONDARY_KEYWORDS:
            if any(k in text for k in keys):
                extra.update(adds)
        for lab in sorted(extra):
            if lab not in taxonomy or lab in labels or len(labels) >= MAX_LABELS:
                continue
            blocked = set()
            for held in labels:
                blocked |= {r["with"] for r in (taxonomy[held].get("exclusive_with") or [])}
            blocked |= {r["with"] for r in (taxonomy[lab].get("exclusive_with") or [])}
            if lab in blocked or (blocked & set(labels)):
                continue
            labels.append(lab)
    labels = [l for l in labels if l != SENTINEL][:3]
    unlabelled = not labels
    if unlabelled:
        labels = [SENTINEL]
        primary = SENTINEL
        if reason is None:
            reason = "no grounded cause present in the record"
    meets = {}
    for lab in labels:
        if lab == SENTINEL:
            continue
        minlev = taxonomy[lab]["minimum_evidence_level"]["level"]
        meets[lab] = LADDER.index(level) >= LADDER.index(minlev)
    status = "asserted" if not unlabelled and all(meets.values()) else ("provisional" if not unlabelled else "unlabelled")
    out = {
        "taxonomy_version": TAXONOMY_VERSION,
        "record_id": rid,
        "labels": labels,
        "primary": primary,
        "unlabelled": unlabelled,
        "assignment_status": status,
        "assignment_basis": method,
        "confidence": {"adjudicated_candidate": "high", "v1_class_rule": "medium",
                       "no_class": "low"}.get(method, "low"),
        "evidence_level": level,
        "evidence_basis": basis,
        "meets_minimum_evidence": meets,
        "provisional_labels": sorted(l for l, ok in meets.items() if not ok),
        "v1_class": str((rec.get("taxonomy") or {}).get("class") or ""),
    }
    if unlabelled:
        out["unlabelled_reason"] = reason
    return out


def build(records, candidates, taxonomy, l6_ids):
    candidate_ids = {c["record_id"] for c in candidates}
    rows = []
    for rec in records:
        if not root_cause_bearing(rec, candidate_ids):
            continue
        rows.append(assign(rec, candidate_ids, l6_ids, taxonomy))
    rows.sort(key=lambda r: r["record_id"])
    return rows


def stats(rows, records, candidates, taxonomy):
    n_labels = Counter()
    n_facet = Counter()
    n_status = Counter()
    n_basis = Counter()
    n_level = Counter()
    n_prov = Counter()
    n_unl = Counter()
    multi = 0
    for r in rows:
        n_status[r["assignment_status"]] += 1
        n_basis[r["assignment_basis"]] += 1
        n_level[r["evidence_level"]] += 1
        if len(r["labels"]) > 1 and not r["unlabelled"]:
            multi += 1
        for lab in r["labels"]:
            n_labels[lab] += 1
            if lab != SENTINEL:
                n_facet[taxonomy[lab]["parent"]] += 1
        for lab in r["provisional_labels"]:
            n_prov[lab] += 1
        if r["unlabelled"]:
            n_unl[r["unlabelled_reason"][:60]] += 1
    cand_rows = [r for r in rows if r["assignment_basis"] == "adjudicated_candidate"]
    return {
        "generated_by": "scripts/assign_root_causes.py",
        "taxonomy_version": TAXONOMY_VERSION,
        "note": ("overlay only; derived/records.jsonl is untouched. Labels are a project-local closed "
                 "vocabulary, not a community standard, and every v1_class_rule label is an "
                 "unadjudicated draft pending the IAA study in annotation/iaa_v1/."),
        "counts": {
            "records_total": len(records),
            "candidates_total": len(candidates),
            "records_in_assignment_pool": len(rows),
            "records_out_of_pool": len(records) - len(rows),
            "labelled": sum(1 for r in rows if not r["unlabelled"]),
            "unlabelled": sum(1 for r in rows if r["unlabelled"]),
            "multi_label": multi,
            "asserted_at_or_above_minimum_evidence": n_status.get("asserted", 0),
            "provisional_below_minimum_evidence": n_status.get("provisional", 0),
        },
        "per_label": dict(sorted(n_labels.items())),
        "per_facet": dict(sorted(n_facet.items())),
        "per_assignment_status": dict(sorted(n_status.items())),
        "per_assignment_basis": dict(sorted(n_basis.items())),
        "per_evidence_level": dict(sorted(n_level.items())),
        "provisional_by_label": dict(sorted(n_prov.items())),
        "unlabelled_reasons_top": dict(sorted(n_unl.items(), key=lambda kv: (-kv[1], kv[0]))[:15]),
        "candidate_adjudication": {
            "candidates": len(candidates),
            "labelled": sum(1 for r in cand_rows if not r["unlabelled"]),
            "unlabelled": [r["record_id"] for r in cand_rows if r["unlabelled"]],
            "unlabelled_reasons": {r["record_id"]: r.get("unlabelled_reason")
                                   for r in cand_rows if r["unlabelled"]},
        },
        "categories_defined": sum(1 for e in taxonomy.values() if e["level"] == "leaf"),
        "categories_never_used": sorted(e for e in taxonomy
                                        if taxonomy[e]["level"] == "leaf" and n_labels.get(e, 0) == 0),
    }


def render_assignments(rows):
    return "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and exit 1 if the committed outputs differ")
    ap.add_argument("--root", default=ROOT, help="repository root (default: this script's parent)")
    args = ap.parse_args(argv)
    root = args.root

    records = load_jsonl(os.path.join(root, RECORDS))
    candidates = load_jsonl(os.path.join(root, CANDIDATES))
    tax_entries = load_jsonl(os.path.join(root, TAXONOMY))
    taxonomy = {e["id"]: e for e in tax_entries}
    l6_ids = set()
    ppath = os.path.join(root, PATCHES)
    if os.path.exists(ppath):
        with open(ppath, encoding="utf-8") as fh:
            pdoc = json.load(fh)
        l6_ids = {p["finding_id"] for p in pdoc.get("records", [])
                  if p.get("fix_effectiveness") == "effective"}

    rows = build(records, candidates, taxonomy, l6_ids)
    assign_text = render_assignments(rows)
    stat_text = json.dumps(stats(rows, records, candidates, taxonomy), ensure_ascii=False, indent=2,
                           sort_keys=True) + "\n"

    if args.check:
        drift = []
        for path, text in ((OUT_ASSIGN, assign_text), (OUT_STATS, stat_text)):
            full = os.path.join(root, path)
            cur = open(full, encoding="utf-8").read() if os.path.exists(full) else None
            if cur != text:
                drift.append(path)
        if drift:
            print("DRIFT: %s" % ", ".join(drift), file=sys.stderr)
            return 1
        print("OK: %d assignments, byte-stable" % len(rows))
        return 0

    with open(os.path.join(root, OUT_ASSIGN), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(assign_text)
    with open(os.path.join(root, OUT_STATS), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(stat_text)
    print("wrote %s (%d rows) and %s" % (OUT_ASSIGN, len(rows), OUT_STATS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

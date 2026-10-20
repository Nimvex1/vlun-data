#!/usr/bin/env python3
"""Gate for the root-cause taxonomy (item 16) and its assignment overlay.

Enforces, and exits non-zero with a reason list on any violation:

* the vocabulary is closed and self-consistent: unique ids, every leaf has a parent
  facet that exists, every composable_with/exclusive_with reference exists, facets are
  not assignable, the RC-99 sentinel is not assignable as a cause;
* no category lacks a definition, an inclusion rule, or at least two exclusion rules;
* no impact / primitive / component leakage into a root-cause field (lexical screen plus
  a required defect verb - see LEAK_* below; this is a screen, not a semantic judge);
* every category declares a minimum evidence level drawn from the repo ladder L0-L6,
  with a reason;
* every SWC/CWE map entry is justified and its identifier is one this project actually
  verified against the upstream registry, or the map is explicitly `no_map` with a reason;
* every citation resolves: external citations must match the verified-registry snapshot
  below, dataset citations must name a record id that exists in derived/records.jsonl,
  and every positive/negative example must name an existing record (negatives must say
  why not);
* every assignment uses an existing category id and an existing record id, respects the
  multi-label cap and the exclusivity table, records an evidence level, and its
  meets_minimum_evidence flags agree with the category's declared floor;
* `--check` regenerates taxonomy/assignments_v1.jsonl and
  reports/root_cause_taxonomy_stats.json and fails if the committed bytes differ.

usage:
    python scripts/validate_taxonomy.py
    python scripts/validate_taxonomy.py --check
    python scripts/validate_taxonomy.py --taxonomy <file> --assignments <file> ...   # fixtures
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LADDER = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]
SENTINEL = "RC-99"
MAX_LABELS = 3

# Impact language: what the weakness produces, never why the code fails.
LEAK_IMPACT = [
    "drain", "drained", "theft", "steal", "stolen", "loss of funds", "fund loss", "money is lost",
    "loses funds", "denial of service", "permanently locked", "blocked withdrawal", "unprofitable",
    "revenue", "insolvent", "insolvency", "attacker gains", "attacker profits", "unfair",
]
# Primitive language: how the attacker reaches the effect.
LEAK_PRIMITIVE = [
    "reentrancy", "reentrant call", "flash loan", "front-run", "frontrun", "sandwich", "griefing",
    "signature replay", "donation attack", "attack sequence",
]
# Component language: where the defect sits, which is location not cause.
LEAK_COMPONENT = [
    "the oracle", "the router", "the vault", "the bridge", "the connector", "the pair contract",
    "the escrow", "the accountant", "in accountingmanager", "in the factory",
]
DEFECT_MARKERS = [
    "not ", "no ", "without", "never", "omit", "miss", "fail", "absent", "unbounded",
    "unvalidated", "incorrect", "wrong", "mismatch", "assum", "ignor", "lack", "before",
    "cannot", "different", "opposite", "exclud",
]

# Verified registry snapshot, taken by this project on 2026-10-18 (HTTP 200 plus the
# identifier/name read off the fetched page). Anything not listed here is unverified and
# therefore rejected, which is what stops an invented SWC/CWE number from entering the
# taxonomy. The SWC registry is frozen since 2020 and unmaintained; EthTrust is cited as
# its maintained successor where relevant.
VERIFIED_SWC = {
    "SWC-100": "Function Default Visibility", "SWC-101": "Integer Overflow and Underflow",
    "SWC-104": "Unchecked Call Return Value", "SWC-105": "Unprotected Ether Withdrawal",
    "SWC-107": "Reentrancy", "SWC-108": "State Variable Default Visibility",
    "SWC-109": "Uninitialized Storage Pointer", "SWC-112": "Delegatecall to Untrusted Callee",
    "SWC-113": "DoS with Failed Call", "SWC-114": "Transaction Order Dependence",
    "SWC-116": "Block values as a proxy for time", "SWC-117": "Signature Malleability",
    "SWC-121": "Missing Protection against Signature Replay Attacks",
    "SWC-122": "Lack of Proper Signature Verification",
    "SWC-124": "Message call with hardcoded gas amount",
    "SWC-126": "Insufficient Gas Griefing", "SWC-128": "DoS With Block Gas Limit",
    "SWC-129": "Typographical Error", "SWC-135": "Code With No Effects",
}
VERIFIED_CWE = {
    "CWE-20": "Improper Input Validation", "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-252": "Unchecked Return Value", "CWE-284": "Improper Access Control",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-400": "Uncontrolled Resource Consumption", "CWE-480": "Use of Incorrect Operator",
    "CWE-664": "Improper Control of a Resource Through its Lifetime",
    "CWE-665": "Improper Initialization", "CWE-682": "Incorrect Calculation",
    "CWE-696": "Incorrect Behavior Order",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions",
    "CWE-710": "Improper Adherence to Coding Standards",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-841": "Improper Enforcement of Behavioral Workflow",
    "CWE-863": "Incorrect Authorization",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
}
ALLOWED_EXTERNAL_URLS = (
    {"https://swcregistry.io/docs/%s" % k: "SWC registry: " + v for k, v in VERIFIED_SWC.items()}
    | {"https://cwe.mitre.org/data/definitions/%s.html" % k.split("-")[1]: "CWE: " + v
       for k, v in VERIFIED_CWE.items()}
    | {"https://entethalliance.org/specs/ethtrust-sl": "EEA EthTrust Security Levels specification",
       "https://github.com/SmartContractSecurity/SWC-registry": "Smart Contract Weakness Classification registry (repository)"}
)
RELATIONS = {"exact", "narrow", "partial"}


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                rows.append({"__parse_error__": "%s:%d %s" % (path, i, exc)})
    return rows


def check_taxonomy(entries, record_ids, errors):
    if any("__parse_error__" in e for e in entries):
        errors.extend(e["__parse_error__"] for e in entries if "__parse_error__" in e)
        return {}, set()
    seen = set()
    facets, leaves = set(), set()
    for e in entries:
        if e["id"] in seen:
            errors.append("duplicate id %s" % e["id"])
        seen.add(e["id"])
        if e.get("level") == "facet":
            facets.add(e["id"])
        if e.get("level") == "leaf":
            leaves.add(e["id"])
    for e in entries:
        eid = e["id"]
        if not (e.get("definition") or "").strip():
            errors.append("%s: empty definition" % eid)
        if not e.get("inclusion_rules"):
            errors.append("%s: no inclusion rules" % eid)
        if len(e.get("exclusion_rules") or []) < 2:
            errors.append("%s: needs at least two exclusion rules" % eid)
        parent = e.get("parent")
        if e.get("level") == "leaf" and parent not in facets:
            errors.append("%s: parent %r is not a declared facet" % (eid, parent))
        if e.get("level") == "facet" and parent is not None:
            errors.append("%s: facet must have parent null" % eid)
        if e.get("level") == "facet" and e.get("assignable"):
            errors.append("%s: facets are not assignable" % eid)

        rcs = e.get("root_cause_statement") or {}
        cause = (rcs.get("cause") or "").lower()
        if e.get("level") == "leaf":
            if len(cause) < 40:
                errors.append("%s: root_cause_statement.cause too short to state a cause" % eid)
            hits = [w for w in LEAK_IMPACT if w in cause]
            if hits:
                errors.append("%s: impact language in root-cause field: %s" % (eid, ", ".join(hits)))
            hits = [w for w in LEAK_PRIMITIVE if w in cause]
            if hits:
                errors.append("%s: primitive language in root-cause field: %s" % (eid, ", ".join(hits)))
            hits = [w for w in LEAK_COMPONENT if w in cause]
            if hits:
                errors.append("%s: component language in root-cause field: %s" % (eid, ", ".join(hits)))
            if not any(m in cause for m in DEFECT_MARKERS):
                errors.append("%s: root-cause field states no defect (no negation/omission marker)" % eid)
            for axis in ("not_impact", "not_primitive", "not_component"):
                if not (rcs.get(axis) or "").strip():
                    errors.append("%s: root_cause_statement missing %s" % (eid, axis))

        mel = e.get("minimum_evidence_level") or {}
        if e.get("level") in ("leaf", "sentinel") or True:
            if mel.get("level") not in LADDER:
                errors.append("%s: minimum_evidence_level.level %r not in the ladder" % (eid, mel.get("level")))
            if not (mel.get("reason") or "").strip():
                errors.append("%s: minimum_evidence_level has no reason" % eid)

        for kind, verified, url_fmt in (("swc_map", VERIFIED_SWC, "https://swcregistry.io/docs/%s"),
                                        ("cwe_map", VERIFIED_CWE, "https://cwe.mitre.org/data/definitions/%s.html")):
            m = e.get(kind)
            if not isinstance(m, dict):
                errors.append("%s: missing %s" % (eid, kind))
                continue
            entries_m = m.get("entries") or []
            if not entries_m:
                if not m.get("no_map"):
                    errors.append("%s: %s has no entries and no explicit no_map" % (eid, kind))
                elif not (m.get("no_map_reason") or "").strip():
                    errors.append("%s: %s no_map without a reason" % (eid, kind))
            for it in entries_m:
                pid = it.get("id")
                if pid not in verified:
                    errors.append("%s: %s cites %s, which this project has not verified against the upstream registry"
                                  % (eid, kind, pid))
                    continue
                expected = url_fmt % pid if kind == "swc_map" else url_fmt % pid.split("-")[1]
                if it.get("url") != expected:
                    errors.append("%s: %s %s url %r != verified %r" % (eid, kind, pid, it.get("url"), expected))
                if (it.get("justification") or "").strip() == "":
                    errors.append("%s: %s %s has no justification" % (eid, kind, pid))
                if it.get("relation") not in RELATIONS:
                    errors.append("%s: %s %s relation %r not in %s"
                                  % (eid, kind, pid, it.get("relation"), sorted(RELATIONS)))
                if m.get("no_map"):
                    errors.append("%s: %s is both no_map and carries entries" % (eid, kind))

        for c in e.get("citations") or []:
            kind = c.get("kind")
            if kind == "external":
                url = c.get("url")
                if url not in ALLOWED_EXTERNAL_URLS:
                    errors.append("%s: citation url not in the verified registry snapshot: %r" % (eid, url))
                elif not (c.get("title") or "").strip() or not (c.get("verified_on") or "").strip():
                    errors.append("%s: external citation lacks title or verified_on: %r" % (eid, url))
            elif kind == "dataset_record":
                if c.get("record_id") not in record_ids:
                    errors.append("%s: citation names a record id that does not exist: %r"
                                  % (eid, c.get("record_id")))
            else:
                errors.append("%s: citation of unknown kind %r" % (eid, kind))

        if e.get("level") == "leaf":
            if not e.get("positive_examples"):
                errors.append("%s: leaf with no positive example" % eid)
            for p in e.get("positive_examples") or []:
                if p.get("record_id") not in record_ids:
                    errors.append("%s: positive example %s is not a record in derived/records.jsonl"
                                  % (eid, p.get("record_id")))
                if not (p.get("why") or "").strip():
                    errors.append("%s: positive example %s lacks a why" % (eid, p.get("record_id")))
            if not e.get("negative_examples"):
                errors.append("%s: leaf with no negative example" % eid)
            for n in e.get("negative_examples") or []:
                if n.get("record_id") not in record_ids:
                    errors.append("%s: negative example %s is not a record in derived/records.jsonl"
                                  % (eid, n.get("record_id")))
                if not (n.get("why_not") or "").strip():
                    errors.append("%s: negative example %s lacks the reason it must not be labelled this way"
                                  % (eid, n.get("record_id")))
        comp = {r["with"] for r in (e.get("composable_with") or [])}
        excl = {r["with"] for r in (e.get("exclusive_with") or [])}
        if comp & excl:
            errors.append("%s: declares both composition and exclusivity with %s"
                          % (eid, ", ".join(sorted(comp & excl))))
        for ref in (e.get("composable_with") or []) + (e.get("exclusive_with") or []):
            if ref.get("with") not in seen:
                errors.append("%s: composition references unknown category %r" % (eid, ref.get("with")))
            if ref.get("with") == eid:
                errors.append("%s: composition references itself" % eid)
            if not (ref.get("rule") or "").strip():
                errors.append("%s: composition with %s has no rule" % (eid, ref.get("with")))
    return {e["id"]: e for e in entries if "__parse_error__" not in e}, leaves


def check_assignments(rows, taxonomy, leaves, record_ids, errors):
    exclusions = {}
    for eid, e in taxonomy.items():
        for ref in e.get("exclusive_with") or []:
            exclusions.setdefault(frozenset((eid, ref["with"])), set()).add(eid)
    for r in rows:
        rid = r.get("record_id")
        if "__parse_error__" in r:
            errors.append(r["__parse_error__"])
            continue
        if rid not in record_ids:
            errors.append("assignment for unknown record id %r" % rid)
        labels = r.get("labels") or []
        if not labels:
            errors.append("%s: no labels and no sentinel" % rid)
        if len(labels) > MAX_LABELS:
            errors.append("%s: %d labels exceeds the multi-label cap of %d" % (rid, len(labels), MAX_LABELS))
        for lab in labels:
            if lab not in taxonomy:
                errors.append("%s: label %r is outside the closed vocabulary" % (rid, lab))
        if r.get("unlabelled"):
            if labels != [SENTINEL]:
                errors.append("%s: unlabelled rows must carry exactly [%s]" % (rid, SENTINEL))
            if not (r.get("unlabelled_reason") or "").strip():
                errors.append("%s: unlabelled without a reason" % rid)
            if r.get("assignment_status") != "unlabelled":
                errors.append("%s: unlabelled row with status %r" % (rid, r.get("assignment_status")))
        else:
            if SENTINEL in labels:
                errors.append("%s: sentinel mixed into a labelled row" % rid)
            for lab in labels:
                if lab not in taxonomy:
                    continue  # already reported as outside the closed vocabulary
                if not taxonomy[lab].get("assignable"):
                    errors.append("%s: label %s is not assignable" % (rid, lab))
            for pair in exclusions:
                if labels and set(labels) >= set(pair):
                    errors.append("%s: labels %s are declared mutually exclusive" % (rid, sorted(pair)))
        lvl = r.get("evidence_level")
        if lvl not in LADDER:
            errors.append("%s: evidence_level %r not in the ladder" % (rid, lvl))
        if not (r.get("evidence_basis") or "").strip():
            errors.append("%s: evidence level without a basis string" % rid)
        meets = r.get("meets_minimum_evidence") or {}
        for lab, ok in meets.items():
            if lab not in taxonomy:
                errors.append("%s: meets_minimum_evidence names unknown %s" % (rid, lab))
                continue
            if taxonomy[lab].get("level") == "sentinel":
                continue
            floor = taxonomy[lab]["minimum_evidence_level"]["level"]
            expected = LADDER.index(lvl) >= LADDER.index(floor) if lvl in LADDER else False
            if expected != ok:
                errors.append("%s: meets_minimum_evidence[%s]=%s contradicts %s at %s (floor %s)"
                              % (rid, lab, ok, rid, lvl, floor))
        if r.get("assignment_status") == "asserted" and any(not v for v in meets.values()):
            errors.append("%s: status asserted while a label is below its evidence floor" % rid)
    return rows


def regenerate(root):
    spec = importlib.util.spec_from_file_location(
        "assign_root_causes", os.path.join(root, "scripts", "assign_root_causes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    records = mod.load_jsonl(os.path.join(root, mod.RECORDS))
    candidates = mod.load_jsonl(os.path.join(root, mod.CANDIDATES))
    tax = {e["id"]: e for e in mod.load_jsonl(os.path.join(root, mod.TAXONOMY))}
    l6 = set()
    ppath = os.path.join(root, mod.PATCHES)
    if os.path.exists(ppath):
        with open(ppath, encoding="utf-8") as fh:
            l6 = {p["finding_id"] for p in json.load(fh).get("records", [])
                  if p.get("fix_effectiveness") == "effective"}
    rows = mod.build(records, candidates, tax, l6)
    return mod.render_assignments(rows), json.dumps(
        mod.stats(rows, records, candidates, tax), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--taxonomy", default=os.path.join(ROOT, "taxonomy", "root_cause_v1.jsonl"))
    ap.add_argument("--assignments", default=os.path.join(ROOT, "taxonomy", "assignments_v1.jsonl"))
    ap.add_argument("--records", default=os.path.join(ROOT, "derived", "records.jsonl"))
    ap.add_argument("--check", action="store_true", help="also require byte-stable regeneration")
    args = ap.parse_args(argv)

    record_ids = set()
    with open(args.records, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                record_ids.add(json.loads(line)["id"])

    errors = []
    entries = load_jsonl(args.taxonomy)
    taxonomy, leaves = check_taxonomy(entries, record_ids, errors)
    rows = load_jsonl(args.assignments)
    check_assignments(rows, taxonomy, leaves, record_ids, errors)

    if args.check:
        want_assign, want_stats = regenerate(args.root)
        got_assign = open(os.path.join(args.root, "taxonomy", "assignments_v1.jsonl"),
                          encoding="utf-8").read()
        got_stats = open(os.path.join(args.root, "reports", "root_cause_taxonomy_stats.json"),
                         encoding="utf-8").read()
        if want_assign != got_assign:
            errors.append("regeneration is not byte-stable: taxonomy/assignments_v1.jsonl would change")
        if want_stats != got_stats:
            errors.append("regeneration is not byte-stable: reports/root_cause_taxonomy_stats.json would change")

    if errors:
        print("TAXONOMY GATE FAILED (%d):" % len(errors), file=sys.stderr)
        for e in errors:
            print("  - %s" % e, file=sys.stderr)
        return 1
    print("OK: %d vocabulary entries (%d assignable leaves), %d assignments, closed vocabulary enforced"
          % (len(entries), len(leaves), len(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

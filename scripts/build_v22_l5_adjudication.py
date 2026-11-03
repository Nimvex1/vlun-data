#!/usr/bin/env python3
"""Rebuild reports/v2_2/l5_adjudication.json from the committed run artefacts.

The v2.2 source layer (jsonl_ml/findings_*.jsonl) publishes 35 records whose
record claims verification level L5 ("the claimed security violation was
experimentally reproduced"). The first adjudication of those 35 claims was
written from prose reasoning and was never derivable from the bytes in
experiments_v2_2/. This script makes it a deterministic function of those
bytes. Nothing is re-run here: the inputs are exactly the committed
`experiments_v2_2/<experiment_id>/result.json` (keys `expectation.declared`,
`expectation.met`, `failing_tests`, `passing_tests`) and `stdout.txt`, plus
each record's `experiment.tests_observed` citations.

The rule (also published verbatim in the output file's `rule` header)
---------------------------------------------------------------------
For each source record whose `experiment.level == "L5"`, look at every entry
in `experiment.tests_observed` (falling back to parsing the cited artefact
when a record cites an artefact with no per-test rows):

  1. SUPPORTED (stays L5) iff ANY cited test satisfies one of:
     (a) the artefact's `expectation.declared` names that test in a `fail`
         list, the test's observed status in the artefact is fail, and the
         `[FAIL: <reason>]` reason is non-empty (the harness declared the
         property assertion failing, and it failed for a stated reason);
     (b) the artefact's `expectation.declared` uses `stdout_contains` (a
         declared differential/observation harness) and the expectation is
         `met` with the named lines present in `stdout.txt`;
     (c) the test passed AND its `Logs:` block in `stdout.txt` contains at
         least one `= <numeric value>` line — the harness printed the
         affected quantity, so the state is observed, not merely executed.
  2. WEAK (L4, provisional) when the test is present in the artefact and
     passed but satisfies none of 1a-1c: the committed artefact declares only
     `all_pass` and records no claim-specific observation, and no test body
     is published, so the violation is not demonstrable from the artefact.
  3. UNSUPPORTED when (i) the cited artefact's stdout is empty or the cited
     test is absent from it (L1, reason insufficient_evidence), or (ii) the
     record's own published text classifies it as a negative control or as
     mitigated in practice (L4, reason names that class). These are L4/L1,
     not L0: attribution, ids, provenance, `outcome` and `why_no_L6` stay
     untouched in the source layer.

Every entry carries `evidence`: a one-line quote taken verbatim from the
artefact bytes (the `[FAIL: ...]` line, the `Logs:` key=value line, the
`[PASS] ...` line, or `stdout.txt is 0 bytes`).

Determinism contract
--------------------
Same bytes in, same bytes out: entries are sorted by record_id, the JSON is
canonical (sorted keys, indent 2, ensure_ascii False), newlines are LF and
the file ends with a single trailing newline. Run it twice and compare
sha256. The computed partition is cross-checked against the review verdicts
recorded 2026-11-01 (EXPECTED below); if the artefacts ever stop yielding
that partition this script refuses to write and prints the offending record
with its artefact quote, so a silent re-inversion cannot happen again.

    python scripts/build_v22_l5_adjudication.py            # rebuild
    python scripts/build_v22_l5_adjudication.py --stdout   # print, write nothing
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PASS_RE = re.compile(r"^\[PASS\] ([^(\s]+)\(\)")
FAIL_RE = re.compile(r"^\[FAIL: (.*?)\] ([^(\s]+)\(\)")
NUMERIC_RHS_RE = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")

L5 = "L5"
# The literals the rule greps the record's own published text for. Case is
# significant: SC-5's title carries the "(NEGATIVE CONTROL)" tag and O-01's
# title says "mitigated in practice", while the mode-a summaries use a
# mixed-case "Negative control:" to describe a fixed-revision comparison,
# which is not a classification of the record itself.
NEGATIVE_CONTROL = "NEGATIVE CONTROL"
MITIGATED = "mitigated in practice"

WEAK_REASON = (
    "Rule 2: the committed artefact declares only `all_pass` and records no "
    "claim-specific observation, and no test body is published, so the "
    "violation is not demonstrable from the artefact."
)

# The partition the 2026-11-01 artefact read produced. Cross-check only: the
# verdicts below are what the rule must reproduce from the bytes; if it ever
# computes something else the script stops instead of publishing a new file.
EXPECTED_SUPPORTED = {
    "solidity:zentory-contracts-audit/H2",
    "vyper:GHSA-6j9c-gvcw-74fj",
    "solidity:zentory-mode-a/H-1",
    "solidity:zentory-mode-a/H-2",
    "solidity:zentory-mode-a/H-3",
}
EXPECTED_UNSUPPORTED = {
    "solidity:zentory-self-audit/M-09": "L1",
    "solidity:zentory-self-audit/SC-5": "L4",
    "solidity:zentory-self-audit/O-01": "L4",
}


class BuilderError(RuntimeError):
    """The artefacts do not yield the adjudication (missing file, unparsable
    run, or a verdict outside the rule)."""


# ---------------------------------------------------------------------------
# artefact reading
# ---------------------------------------------------------------------------

def norm_name(name):
    if not isinstance(name, str):
        return None
    return name.strip().removesuffix("()").strip() or None


class Artefact:
    """One committed run: result.json + stdout.txt, read from bytes only."""

    def __init__(self, root: Path, experiment_id: str):
        self.id = experiment_id
        self.dir_rel = f"experiments_v2_2/{experiment_id}"
        d = root / self.dir_rel
        rp, sp = d / "result.json", d / "stdout.txt"
        if not rp.is_file():
            raise BuilderError(f"{rp}: committed artefact result.json missing")
        if not sp.is_file():
            raise BuilderError(f"{sp}: committed artefact stdout.txt missing")
        self.result = json.loads(rp.read_text(encoding="utf-8"))
        self.stdout = sp.read_text(encoding="utf-8")
        self.stdout_bytes = len(sp.read_bytes())
        self.declared = (self.result.get("expectation") or {}).get("declared") or {}
        self.met = (self.result.get("expectation") or {}).get("met")
        self.passes = {}   # test name -> raw stdout [PASS] line
        self.logs = {}     # test name -> verbatim Logs-block lines
        self.fails = {}    # test name -> {"reason": str, "line": str}
        self._parse_forge()

    def _parse_forge(self):
        cur = None
        for line in self.stdout.split("\n"):
            m = PASS_RE.match(line)
            if m:
                cur = m.group(1)
                self.passes.setdefault(cur, line)
                self.logs.setdefault(cur, [])
                continue
            m = FAIL_RE.match(line)
            if m:
                if m.group(2) not in self.fails:
                    self.fails[m.group(2)] = {"reason": m.group(1), "line": line}
                cur = None
                continue
            if cur is not None:
                if line.strip() == "Logs:":
                    continue  # forge prints the block header at column 0
                if line.startswith((" ", "\t")):
                    self.logs[cur].append(line)
                else:
                    cur = None

    def numeric_log_line(self, test):
        """First verbatim Logs line shaped `key = <numeric value>`."""
        for line in self.logs.get(test, []):
            if "=" in line:
                rhs = line.split("=", 1)[1].strip()
                if NUMERIC_RHS_RE.fullmatch(rhs):
                    return line
        return None

    def stdout_contains_met(self):
        """Clause 1b: declared stdout_contains harness, met, lines present."""
        names = self.declared.get("stdout_contains")
        if not isinstance(names, list) or not names:
            return None
        if self.met is not True:
            return None
        present = []
        for want in names:
            hit = next((ln for ln in self.stdout.split("\n") if want in ln), None)
            if hit is None:
                return None
            present.append(hit)
        return present

    def declared_fail(self):
        return {norm_name(t) for t in (self.declared.get("fail") or [])}


# ---------------------------------------------------------------------------
# rule
# ---------------------------------------------------------------------------

def record_text(rec: dict) -> str:
    f = rec.get("finding") or {}
    return " ".join(str(f.get(k) or "") for k in ("title", "summary", "root_cause"))


def classify(rec: dict, get_art: callable):
    """Apply the docstring rule to one L5 record; return (verdict, payload)."""
    exp = rec.get("experiment") or {}
    obs = exp.get("tests_observed") or []
    ids = exp.get("experiment_ids") or []
    arts = []
    for e in obs:
        if e.get("experiment_id"):
            arts.append(e["experiment_id"])
    for i in ids:
        if i not in arts:
            arts.append(i)

    def clause_hit(e):
        """Clauses 1a/1b/1c for one tests_observed entry, in rule order."""
        art = get_art(e["experiment_id"])
        t = norm_name(e.get("test"))
        if t and t in art.declared_fail() and t in art.fails \
                and art.fails[t]["reason"].strip():
            return ("SUPPORTED", {
                "clause": "1a", "artefact": art,
                "evidence_line": art.fails[t]["line"],
                "reason": (f"Rule 1a: the artefact's declared expectation names "
                           f"{t} in its fail list, the committed stdout records "
                           f"it failing, and the [FAIL: <reason>] reason is "
                           f"non-empty, so the claimed violation was "
                           f"experimentally reproduced."),
            })
        present = art.stdout_contains_met()
        if present:
            return ("SUPPORTED", {
                "clause": "1b", "artefact": art,
                "evidence_line": present[0],
                "reason": ("Rule 1b: the artefact's declared expectation is a "
                           "stdout_contains differential harness, result.json "
                           "records it met, and the named CHECK lines are "
                           "present verbatim in stdout.txt."),
            })
        if t and t in art.passes:
            line = art.numeric_log_line(t)
            if line:
                return ("SUPPORTED", {
                    "clause": "1c", "artefact": art,
                    "evidence_line": line,
                    "reason": (f"Rule 1c: {t} passed and its Logs block in "
                               f"stdout.txt prints the affected quantity, so "
                               f"the state is observed, not merely executed."),
                })
        return None

    # 1: any cited test satisfying 1a, 1b or 1c (tests_observed order).
    for e in obs:
        if e.get("experiment_id") and norm_name(e.get("test")):
            hit = clause_hit(e)
            if hit:
                return hit
    # 1b fallback: a record citing an artefact with no per-test rows is
    # adjudicated from the declared harness itself.
    for eid in arts:
        art = get_art(eid)
        present = art.stdout_contains_met()
        if present:
            return ("SUPPORTED", {
                "clause": "1b", "artefact": art,
                "evidence_line": present[0],
                "reason": ("Rule 1b: the artefact's declared expectation is a "
                           "stdout_contains differential harness, result.json "
                           "records it met, and the named CHECK lines are "
                           "present verbatim in stdout.txt; the record cites "
                           "this artefact and has no per-test rows."),
            })

    # 3(i): empty stdout, or the cited test absent from the artefact.
    for eid in arts:
        art = get_art(eid)
        if art.stdout_bytes == 0:
            return "UNSUPPORTED", {
                "clause": "3i", "artefact": art, "level_after": "L1",
                "evidence_line": "stdout.txt is 0 bytes",
                "reason": ("Rule 3(i): the cited artefact's stdout.txt is empty "
                           "(0 bytes) and the run recorded no tests, so nothing "
                           "was observed: insufficient_evidence; demoted to L1. "
                           "Attribution, ids and provenance stay untouched."),
            }
    for e in obs:
        t = norm_name(e.get("test"))
        if t is None or not e.get("experiment_id"):
            continue
        art = get_art(e["experiment_id"])
        if t not in art.passes and t not in art.fails:
            return "UNSUPPORTED", {
                "clause": "3i", "artefact": art, "level_after": "L1",
                "evidence_line": (art.stdout.split("\n", 1)[0][:120]
                                  or "stdout.txt is 0 bytes"),
                "reason": (f"Rule 3(i): the cited test {t} is absent from "
                           f"{art.dir_rel}/stdout.txt, so nothing was observed: "
                           f"insufficient_evidence; demoted to L1."),
            }

    # 3(ii): the record's own published text names the class.
    text = record_text(rec)
    if NEGATIVE_CONTROL in text or MITIGATED in text:
        klass = ("a negative control (its published title carries the "
                 "(NEGATIVE CONTROL) tag)" if NEGATIVE_CONTROL in text
                 else "mitigated in practice (its published title says so)")
        art = get_art(obs[0]["experiment_id"]) if obs else get_art(arts[0])
        quote = ""
        if obs:
            t = norm_name(obs[0].get("test"))
            quote = art.passes.get(t) or art.fails.get(t, {}).get("line") or ""
        return "UNSUPPORTED", {
            "clause": "3ii", "artefact": art, "level_after": "L4",
            "evidence_line": quote,
            "reason": (f"Rule 3(ii): the record's own published text classifies "
                       f"it as {klass}; the run executed but demonstrates no "
                       f"violation; demoted to L4, not L0: attribution, outcome "
                       f"and why_no_L6 stay intact."),
        }

    # 2: WEAK - present, passed, no clause 1 evidence.
    if obs and all(norm_name(e.get("test")) in get_art(e["experiment_id"]).passes
                   for e in obs if norm_name(e.get("test"))):
        art = get_art(obs[0]["experiment_id"])
        t = norm_name(obs[0]["test"])
        return "WEAK", {
            "clause": "2", "artefact": art, "evidence_line": art.passes[t],
            "reason": WEAK_REASON,
        }
    raise BuilderError(
        f"{rec.get('id')}: the artefacts match no clause of the rule "
        f"(tests_observed={json.dumps(obs)[:200]}); refusing to guess.")


# ---------------------------------------------------------------------------
# document assembly
# ---------------------------------------------------------------------------

def l5_records(root: Path) -> list:
    out = []
    for path in sorted((root / "jsonl_ml").glob("findings_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if (rec.get("experiment") or {}).get("level") == L5:
                out.append(rec)
    return out


RULE_HEADER = {
    "supported_1a": "the artefact's expectation.declared names the cited test "
                    "in a fail list, the artefact records the test failing, and "
                    "the [FAIL: <reason>] reason is non-empty",
    "supported_1b": "the artefact's expectation.declared uses stdout_contains "
                    "(a declared differential/observation harness) and the "
                    "expectation is met with the named lines present in stdout.txt",
    "supported_1c": "the cited test passed and its Logs block in stdout.txt "
                    "contains at least one `= <numeric value>` line: the harness "
                    "printed the affected quantity, so the state is observed, "
                    "not merely executed",
    "weak": "the test is present in the artefact and passed but satisfies none "
            "of 1a-1c: the committed artefact declares only all_pass and "
            "records no claim-specific observation, and no test body is "
            "published, so the violation is not demonstrable from the artefact "
            "(L4, provisional)",
    "unsupported": "(i) the cited artefact's stdout is empty or the cited test "
                   "is absent from it: L1, insufficient_evidence; or (ii) the "
                   "record's own published text classifies it as a negative "
                   "control or as mitigated in practice: L4, reason names the "
                   "class. L4/L1, never L0: attribution, ids, provenance, "
                   "outcome and why_no_L6 stay intact",
}


def build_document(root: Path) -> dict:
    cache = {}

    def get_art(eid):
        if eid not in cache:
            cache[eid] = Artefact(root, eid)
        return cache[eid]

    entries = []
    for rec in l5_records(root):
        verdict, hit = classify(rec, get_art)
        exp = rec.get("experiment") or {}
        rid = rec["id"]
        if verdict == "SUPPORTED":
            level_after, status_after, provisional = "L5", "experimentally_verified", False
        elif verdict == "WEAK":
            level_after, status_after, provisional = "L4", "experimentally_verified_provisional", True
        else:
            level_after = hit["level_after"]
            provisional = False
            status_after = ("reported_claim" if level_after == "L1"
                            else "executed_not_violation")
        tests = sorted({norm_name(e.get("test")) or e.get("poc_file")
                        for e in (exp.get("tests_observed") or [])
                        if norm_name(e.get("test")) or e.get("poc_file")})
        ev = hit["evidence_line"]
        evidence = (f"{hit['artefact'].dir_rel}/stdout.txt: {ev}"
                    if ev != "stdout.txt is 0 bytes"
                    else f"{hit['artefact'].dir_rel}/stdout.txt is 0 bytes")
        entries.append({
            "record_id": rid,
            "verdict": verdict,
            "level_before": L5,
            "level_after": level_after,
            "status_after": status_after,
            "provisional": provisional,
            "experiment_ids": sorted(exp.get("experiment_ids") or []),
            "tests": tests,
            "reason": hit["reason"],
            "evidence": evidence,
        })

    entries.sort(key=lambda e: e["record_id"])
    counts = {"L5_records": len(entries)}
    for v in ("SUPPORTED", "WEAK", "UNSUPPORTED"):
        counts[v] = sum(1 for e in entries if e["verdict"] == v)

    doc = {
        "record_type": "l5_adjudication",
        "dataset_version": "2.2",
        "adjudication_source": "reports/v2_2/l5_adjudication.json",
        "generated_by": "scripts/build_v22_l5_adjudication.py",
        "expected_records": len(entries),
        "counts": counts,
        "rule": RULE_HEADER,
        "analyst_review": {
            "applied_by": "scripts/build_derived_v22.py (derived experiment_view "
                          "only; jsonl_ml is not rewritten)",
            "level_ladder": "L0 prose, L1 PoC code quoted, L2 reconstructed, "
                            "L3 compiles, L4 executes, L5 claimed security "
                            "violation reproduced, L6 L5 plus a fixed-revision "
                            "contrast (scripts/poc_classification.py)",
            "method": "the file is derived from artefact bytes by "
                      "scripts/build_v22_l5_adjudication.py: for every L5 claim "
                      "the script reads the cited committed run artefacts in "
                      "experiments_v2_2/ (result.json expectation.declared, "
                      "expectation.met, failing/passing tests, stdout.txt "
                      "[FAIL]/[PASS]/Logs lines) and applies the published "
                      "rule; no prose-only reasoning and no re-run of any test",
            "performed_at": "2026-11-01",
            "performed_by": "scripts/build_v22_l5_adjudication.py "
                            "(artefact-grounded re-adjudication; rule 1a/1b/1c, "
                            "2, 3 as published in the `rule` header)",
            "scope": "every v2.2 record whose source experiment claimed L5: 35 "
                     "records across jsonl_ml/findings_reports.jsonl and "
                     "jsonl_ml/findings_vyper.jsonl",
            "status_after_values": {
                "executed_not_violation": "the run executed and demonstrates no violation",
                "experimentally_verified": "the claim is demonstrated by the observed run",
                "experimentally_verified_provisional": "the run is observed but the L5 claim is provisional",
                "reported_claim": "nothing was executed that asserts the claim",
            },
            "tests_field": "tests lists the test functions or PoC script paths "
                           "the record observed. It is empty only where the run "
                           "reported no named test (vyper-optimizer-ternary); "
                           "there the stdout CHECK markers cited in evidence "
                           "are the assertion record.",
            "verdict_definitions": {
                "SUPPORTED": "a cited test satisfies rule 1a, 1b or 1c from the "
                             "committed artefact bytes; L5 stands",
                "UNSUPPORTED": "rule 3: the artefact observed nothing (empty "
                               "stdout or absent test: L1) or the record's own "
                               "text classifies it (negative control / "
                               "mitigated in practice: L4)",
                "WEAK": "rule 2: the run is present and passed but the "
                        "artefact records no claim-specific observation; L4, "
                        "provisional L5 candidate",
            },
        },
        "adjudications": entries,
    }
    return doc


def canonical_bytes(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n").encode("utf-8")


def verify_expected(doc: dict) -> list:
    """Compare the computed partition with the 2026-11-01 artefact read."""
    problems = []
    sup = {e["record_id"] for e in doc["adjudications"] if e["verdict"] == "SUPPORTED"}
    uns = {e["record_id"]: e["level_after"] for e in doc["adjudications"]
           if e["verdict"] == "UNSUPPORTED"}
    weak = sum(1 for e in doc["adjudications"] if e["verdict"] == "WEAK")
    if sup != EXPECTED_SUPPORTED:
        for rid in sorted(sup - EXPECTED_SUPPORTED):
            e = next(x for x in doc["adjudications"] if x["record_id"] == rid)
            problems.append(f"unexpected SUPPORTED {rid}: {e['evidence']}")
        for rid in sorted(EXPECTED_SUPPORTED - sup):
            problems.append(f"expected SUPPORTED but computed otherwise: {rid}")
    if uns != EXPECTED_UNSUPPORTED:
        problems.append(f"UNSUPPORTED partition differs: computed {uns}, "
                        f"expected {EXPECTED_UNSUPPORTED}")
    if weak != 27:
        problems.append(f"WEAK count computed {weak}, expected 27")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(ROOT),
                    help="tree holding experiments_v2_2/ and jsonl_ml/")
    ap.add_argument("--out", default=str(ROOT / "reports/v2_2/l5_adjudication.json"))
    ap.add_argument("--stdout", action="store_true",
                    help="print the document instead of writing it")
    args = ap.parse_args(argv)

    root = Path(args.root)
    doc = build_document(root)
    data = canonical_bytes(doc)

    problems = verify_expected(doc)
    if problems:
        print("STOP: the artefacts do not yield the reviewed partition "
              "(the rule or the bytes changed; nothing was written):",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 2

    if args.stdout:
        sys.stdout.write(data.decode("utf-8"))
        return 0
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes, sha256 "
          f"{hashlib.sha256(data).hexdigest()})")
    print(f"counts: {json.dumps(doc['counts'], sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

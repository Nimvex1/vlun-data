#!/usr/bin/env python3
"""Chance-corrected agreement statistics for the item-14 IAA study. Stdlib only.

Computes, for every pair of annotators and for the pooled data:
  * Cohen's kappa (nominal) on the primary root-cause label;
  * weighted kappa with linear and quadratic weights on the two ordinal constructs
    (severity tier 0-3, evidence ceiling L0-L6);
  * Krippendorff's alpha with nominal distance for labels and ordinal distance for the
    ordinal constructs, over all annotators at once;
  * percentile bootstrap 95% confidence intervals, resampled by record (paired), seeded.

Honesty guards, which are the point of this script as much as the maths:
  * if annotation/iaa_v1/responses/ holds no completed responses it reports
    `measured: false` with the reason and no numbers at all;
  * rows that declare `annotator_kind` other than `human` (e.g. an LLM, or the same model
    answering twice) are excluded and the exclusion is reported. LLM self-consistency is
    never presented as inter-annotator agreement;
  * fewer than two distinct human annotator ids -> `measured: false`.

usage:
    python scripts/iaa_statistics.py                 # write reports/iaa_status.json
    python scripts/iaa_statistics.py --responses DIR # fixtures
    python scripts/iaa_statistics.py --check          # byte-stability of the report
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESPONSES = os.path.join("annotation", "iaa_v1", "responses")
OUT = os.path.join("reports", "iaa_status.json")
ORDINAL_TIER = ["0", "1", "2", "3"]
ORDINAL_LEVEL = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]


# --------------------------------------------------------------- statistics
def _confusion(a, b):
    cats = sorted(set(a) | set(b))
    idx = {c: i for i, c in enumerate(cats)}
    m = [[0] * len(cats) for _ in cats]
    for x, y in zip(a, b):
        m[idx[x]][idx[y]] += 1
    return cats, idx, m


def cohens_kappa(a, b):
    """Unweighted Cohen's kappa on two equal-length nominal sequences."""
    n = len(a)
    if n == 0 or len(b) != n:
        return None
    cats, idx, m = _confusion(a, b)
    po = sum(m[i][i] for i in range(len(cats))) / n
    ra = Counter(a)
    rb = Counter(b)
    pe = sum(ra[c] * rb[c] for c in cats) / (n * n)
    if math.isclose(pe, 1.0):
        return None
    return (po - pe) / (1 - pe)


def _weights(cats, kind):
    k = len(cats)
    w = [[0.0] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            d = abs(i - j)
            if kind == "linear":
                w[i][j] = d / (k - 1) if k > 1 else 0.0
            elif kind == "quadratic":
                w[i][j] = (d / (k - 1)) ** 2 if k > 1 else 0.0
            else:
                w[i][j] = 0.0 if i == j else 1.0
    return w


def weighted_kappa(a, b, kind="linear", cats=None):
    """Cohen's weighted kappa: 1 - sum(w*O) / sum(w*E), over an ordered category axis.

    kind='nominal' reproduces unweighted kappa, which is the check used in
    tests/test_iaa_statistics.py.
    """
    n = len(a)
    if n == 0 or len(b) != n:
        return None
    present = set(a) | set(b)
    if cats is None:
        cats = sorted(present)
    else:
        cats = [c for c in cats if c in present]
    if len(cats) < 2:
        return None
    idx = {c: i for i, c in enumerate(cats)}
    if kind == "nominal":
        return cohens_kappa(a, b)
    w = _weights(cats, kind)
    o = [[0] * len(cats) for _ in cats]
    for x, y in zip(a, b):
        o[idx[x]][idx[y]] += 1
    ra, rb = Counter(a), Counter(b)
    # both terms are per-item means: the observed cell counts are proportions (divide by n),
    # the expected cells are already proportions (divide by n*n).
    num = sum(w[i][j] * o[i][j] for i in range(len(cats)) for j in range(len(cats))) / n
    exp = sum(w[i][j] * ra[cats[i]] * rb[cats[j]] for i in range(len(cats)) for j in range(len(cats))) / (n * n)
    if math.isclose(exp, 0.0):
        return None
    return 1 - num / exp


def krippendorff_alpha(units, kind="nominal", values=None):
    """units: list of dict {annotator_id: value}; kind: 'nominal' or 'ordinal'.

    Pairwise formulation: for every unit, the mean squared disagreement over its ordered
    pairs of distinct values, averaged across units (Do), compared with the same quantity
    computed over the pooled value multiset (Dc). alpha = 1 - Do / Dc. Units with fewer
    than two values are skipped: they cannot disagree and would inflate agreement.
    """
    obs = []
    for u in units:
        vals = [v for v in u.values() if v not in (None, "")]
        if len(vals) >= 2:
            obs.append(vals)
    if not obs:
        return None
    pool = [v for vals in obs for v in vals]
    m_all = len(pool)
    if m_all < 2:
        return None
    if kind == "nominal":
        def dist(x, y):
            return 0.0 if x == y else 1.0
    else:
        cats = list(values) if values else sorted(set(pool))
        order = {c: i for i, c in enumerate(cats)}
        freq = Counter(pool)

        def dist(x, y):
            if x == y:
                return 0.0
            lo, hi = sorted((order[x], order[y]))
            s = sum(freq[c] for c in cats if lo <= order[c] <= hi)
            return ((s - (freq[x] + freq[y]) / 2.0) ** 2) / (m_all * (m_all - 1))

    def mean_sq(vals):
        m = len(vals)
        cnt = Counter(vals)
        tot = 0.0
        for c in cnt:
            for k in cnt:
                if c == k:
                    continue
                tot += cnt[c] * cnt[k] * dist(c, k)
        return tot / (m * (m - 1))

    do = sum(mean_sq(v) for v in obs) / len(obs)
    dc = mean_sq(pool)
    if math.isclose(dc, 0.0):
        return None
    return 1 - do / dc


def bootstrap_ci(stat_fn, units, seed=20261018, reps=2000, alpha=0.05):
    rng = random.Random(seed)
    point = stat_fn(units)
    if point is None:
        return None
    draws = []
    n = len(units)
    for _ in range(reps):
        sample = [units[rng.randrange(n)] for _ in range(n)]
        v = stat_fn(sample)
        if v is not None:
            draws.append(v)
    if not draws:
        return {"point": point, "ci95_low": None, "ci95_high": None, "replicates": 0}
    draws.sort()
    lo = draws[int(math.floor(alpha / 2 * len(draws)))]
    hi = draws[min(len(draws) - 1, int(math.ceil((1 - alpha / 2) * len(draws))) - 1)]
    return {"point": point, "ci95_low": lo, "ci95_high": hi, "replicates": len(draws)}


# --------------------------------------------------------------- response loading
def read_responses(dirpath):
    rows = []
    if not os.path.isdir(dirpath):
        return rows, ["responses directory absent: %s" % os.path.relpath(dirpath, os.getcwd()).replace("\\", "/")]
    notes = []
    files = sorted(f for f in os.listdir(dirpath) if f.endswith(".csv") and not f.endswith(".template.csv"))
    if not files:
        notes.append("no completed response files in %s (only .template.csv blanks ship here)" % dirpath)
    for f in files:
        with open(os.path.join(dirpath, f), newline="", encoding="utf-8") as fh:
            rd = csv.DictReader(fh)
            if rd.fieldnames is None:
                continue
            if "annotator_id" not in rd.fieldnames or "annotator_kind" not in rd.fieldnames:
                notes.append("%s lacks annotator_id/annotator_kind columns; skipped" % f)
                continue
            for r in rd:
                r = {k: (v.strip() if isinstance(v, str) else v) for k, v in r.items()}
                r["__file__"] = f
                rows.append(r)
    return rows, notes


def analyse(rows):
    humans = [r for r in rows if str(r.get("annotator_kind", "")).lower() == "human"]
    excluded = Counter(str(r.get("annotator_kind", "") or "unset") for r in rows
                       if str(r.get("annotator_kind", "")).lower() != "human")
    annotators = sorted({r["annotator_id"] for r in humans})
    out = {
        "annotators_seen": len(annotators),
        "human_rows": len(humans),
        "non_human_rows_excluded": dict(excluded),
    }
    if len(annotators) < 2:
        out["measurable"] = False
        out["reason"] = ("fewer than two distinct human annotator ids have completed responses "
                         "(found: %s)" % (annotators or "none"))
        return out
    by_item = defaultdict(dict)
    for r in humans:
        by_item[r["record_id"]][r["annotator_id"]] = r
    pairs = []
    for i, a in enumerate(annotators):
        for b in annotators[i + 1:]:
            pairs.append((a, b))
    stats = {}
    for a, b in pairs:
        common = sorted(k for k, v in by_item.items() if a in v and b in v)
        prim_a = [by_item[k][a].get("rc_primary") for k in common]
        prim_b = [by_item[k][b].get("rc_primary") for k in common]
        sev_a = [by_item[k][a].get("severity_tier") for k in common]
        sev_b = [by_item[k][b].get("severity_tier") for k in common]
        ev_a = [by_item[k][a].get("evidence_ceiling") for k in common]
        ev_b = [by_item[k][b].get("evidence_ceiling") for k in common]
        stats["%s|%s" % (a, b)] = {
            "n_common": len(common),
            "kappa_primary_label": cohens_kappa(prim_a, prim_b),
            "weighted_kappa_severity_linear": weighted_kappa(sev_a, sev_b, "linear", ORDINAL_TIER),
            "weighted_kappa_severity_quadratic": weighted_kappa(sev_a, sev_b, "quadratic", ORDINAL_TIER),
            "weighted_kappa_evidence_linear": weighted_kappa(ev_a, ev_b, "linear", ORDINAL_LEVEL),
            "weighted_kappa_evidence_quadratic": weighted_kappa(ev_a, ev_b, "quadratic", ORDINAL_LEVEL),
        }
    def units(field, allowed=None):
        us = []
        for k, v in by_item.items():
            u = {aid: r.get(field) for aid, r in v.items()
                 if r.get(field) not in (None, "") and (allowed is None or r.get(field) in allowed)}
            if len(u) >= 2:
                us.append(u)
        return us
    pooled = {
        "alpha_primary_label_nominal": bootstrap_ci(lambda us: krippendorff_alpha(us, "nominal"),
                                                    units("rc_primary")),
        "alpha_severity_ordinal": bootstrap_ci(
            lambda us: krippendorff_alpha(us, "ordinal", ORDINAL_TIER), units("severity_tier", ORDINAL_TIER)),
        "alpha_evidence_ordinal": bootstrap_ci(
            lambda us: krippendorff_alpha(us, "ordinal", ORDINAL_LEVEL), units("evidence_ceiling", ORDINAL_LEVEL)),
    }
    out["measurable"] = True
    out["per_pair"] = stats
    out["pooled"] = pooled
    out["n_items_any"] = len(by_item)
    return out


NON_HUMAN_KINDS = {"llm", "llm_self_consistency", "model", "self_consistency", "agent", "automated"}


def audit_report(doc, responses_dir=None):
    """Return a list of reasons a report's agreement claim is unsupported.

    Guards the two failure modes this study must not ship:
      * a numeric agreement reported while the responses directory has nothing in it;
      * LLM self-consistency (or one annotator answering twice) presented as human
        inter-annotator agreement.
    """
    violations = []
    st = doc.get("statistics") or {}
    kinds = {str(k).lower() for k in (st.get("non_human_rows_excluded") or {})}
    if doc.get("measured"):
        humans = 0
        ids = set()
        all_rows = []
        if responses_dir:
            all_rows, _ = read_responses(responses_dir)
            hu = [r for r in all_rows if str(r.get("annotator_kind", "")).lower() == "human"]
            humans = len(hu)
            ids = {r.get("annotator_id") for r in hu}
        has_number = any(v is not None for row in (st.get("per_pair") or {}).values()
                         for k, v in row.items() if k != "n_common") or st.get("pooled")
        if not all_rows:
            violations.append("report claims measured agreement but the responses directory contains no completed rows")
        elif humans == 0:
            violations.append("report claims measured agreement over %d rows, none of them annotated as human; "
                              "LLM self-consistency is not inter-annotator agreement" % len(all_rows))
        elif len(ids) < 2:
            violations.append("report claims measured agreement with %d distinct human annotator id(s); "
                              "a second pass by the same annotator or model is self-consistency, not IAA"
                              % len(ids))
        if st.get("annotators_seen", 0) < 2:
            violations.append("measured=true while statistics.annotators_seen=%s" % st.get("annotators_seen"))
        if not has_number:
            violations.append("measured=true but the report carries no statistic value")
        if kinds and kinds <= NON_HUMAN_KINDS and humans == 0:
            violations.append("all annotator kinds are non-human (%s)" % ", ".join(sorted(kinds)))
    return violations


def report(responses_dir, root=ROOT):
    rows, notes = read_responses(responses_dir)
    a = analyse(rows) if rows else {"measurable": False,
                                   "reason": "no responses collected; annotation/iaa_v1/responses/ holds only blank templates",
                                   "annotators_seen": 0, "human_rows": 0, "non_human_rows_excluded": {}}
    doc = {
        "generated_by": "scripts/iaa_statistics.py",
        "study": "annotation/iaa_v1 (item 14)",
        "measured": bool(a.get("measurable")),
        "measured_reason": None if a.get("measurable") else a.get("reason"),
        "what_would_be_reported": ("Cohen's kappa on the primary root-cause label, linear and quadratic "
                                   "weighted kappa on severity tier and evidence ceiling, Krippendorff's "
                                   "alpha (nominal + ordinal) with 2000-replicate percentile bootstrap CIs"),
        "guard": ("a numeric agreement is emitted only from >=2 distinct human annotator ids; LLM "
                  "self-consistency or repeated passes by one annotator are never reported as IAA"),
        "responses_dir": os.path.relpath(responses_dir, root).replace("\\", "/"),
        "responses_present": len(rows),
        "notes": notes,
        "statistics": a,
    }
    doc["audit_violations"] = audit_report(doc, responses_dir)
    if doc["audit_violations"]:
        doc["measured"] = False
        doc["measured_reason"] = "audit blocked the claim: " + "; ".join(doc["audit_violations"])
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--responses", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--check", action="store_true", help="exit 1 if the committed report would change")
    ap.add_argument("--audit-report", default=None, metavar="JSON",
                    help="audit an existing report file against a responses dir and exit 1 on violation")
    args = ap.parse_args(argv)
    responses = args.responses or os.path.join(args.root, RESPONSES)
    if args.audit_report:
        with open(args.audit_report, encoding="utf-8") as fh:
            doc = json.load(fh)
        bad = audit_report(doc, responses)
        if bad:
            print("IAA AUDIT FAILED:", file=sys.stderr)
            for b in bad:
                print("  - %s" % b, file=sys.stderr)
            return 1
        print("OK: report's agreement claim is supported by the responses present")
        return 0
    doc = report(responses, args.root)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    out = args.out or os.path.join(args.root, OUT)
    if args.check:
        cur = open(out, encoding="utf-8").read() if os.path.exists(out) else None
        if cur != text:
            print("DRIFT: %s would change" % out, file=sys.stderr)
            return 1
        print("OK: measured=%s, byte-stable" % doc["measured"])
        return 0
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote %s (measured=%s)" % (out, doc["measured"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

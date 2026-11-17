#!/usr/bin/env python3
"""P2b: nearby false hypotheses for confirmed High/Medium findings.

A finding teaches "report a bug". A counterexample next to it teaches "do not
report a bug" — and it has to come from the same code, or the model learns to
ignore context.

Each counterexample names a specific function, states a hypothesis an auditor
might form about it, and then refutes that hypothesis using a fact read off that
function's own source. The vulnerable function is never used as the subject, so
a counterexample can never contradict its own finding.

    python scripts/build_counterexamples.py

The counts it publishes come from source it reads out of the git-ignored `work/`
tree, so the write path fails closed against the published totals when those
inputs are absent; `--allow-shrink` is the reviewed-migration escape hatch.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import counterexample_pairs as cp
import solidity_facts as sf  # noqa: E402
from vlun import (  # noqa: E402
    DATASET_VERSION, DERIVED, JSONL, REPORTS, WORK, log, sha256_text, write_json,
    write_jsonl,
)

GUARDED = re.compile(r"\b(only[A-Z]\w*|whenNotPaused|nonReentrant|checkRole\w*)\b")
OPEN_CALL = re.compile(r"\b(external|public)\b")

STATS_JSON = REPORTS / "counterexample_stats.json"
LAYER_JSONL = DERIVED / "counterexamples.jsonl"


def candidate_functions(row: dict) -> list[tuple[dict, dict]]:
    """Every function of the record's *enclosing contract*, not just the cited one.

    The cited snippet is usually the vulnerable function itself, which makes a
    counterexample impossible by construction. scripts/fetch_sources.py retrieves
    the whole file at the pinned commit, so the rest of the contract is
    available and is where nearby false hypotheses actually live.
    """
    import local_sources as ls

    out, seen = [], set()
    owner = f"{row['source'].get('organization', 'code-423n4')}/{row['source']['repository']}"
    entries = list(row.get("code_context") or []) + list(row.get("vulnerable_code") or []) \
        + list(row.get("code_reference_only") or [])
    for e in entries:
        if not (e.get("commit_sha") and e.get("file")):
            continue
        if e.get("snippet"):
            a = sf.analyse(e["snippet"], e.get("function"))
            blob = ({"functions": a["functions"], "commit_sha": e.get("commit_sha"),
                     "source_url": e.get("source_url"), "file": e.get("file"),
                     "contract": e.get("contract"), "sha256": sha256_text(e["snippet"]),
                     "verified": bool(e.get("line_range_verified"))})
        else:
            analysed = ls.analyse_cited(owner, e, allow_text=False)
            if not analysed.get("retrieved_locally"):
                continue
            blob = {"functions": analysed.get("functions") or [],
                    "commit_sha": e.get("commit_sha"), "source_url": e.get("source_url"),
                    "file": e.get("file"),
                    "contract": e.get("contract") or (analysed.get("contracts") or [{}])[0].get("name"),
                    "sha256": analysed.get("sha256"), "verified": False,
                    "source": "enclosing contract retrieved at the pinned commit"}
        for fn in blob["functions"]:
            key = (blob["file"], fn["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append((fn, blob))
    return out


def counterexamples_for(row: dict) -> list[dict]:
    f = row.get("finding") or {}
    if (f.get("record_class") or "") != "judged":
        return []
    if (f.get("severity") or "") not in ("high", "medium"):
        return []
    vulnerable = {x.split(".")[-1] for x in (f.get("affected_functions") or [])}
    for cls in (f.get("vulnerability_classes") or []):
        vulnerable |= set(re.findall(r"`(\w+)`", cls))

    out = []
    for fn, blob in candidate_functions(row):
        if fn["name"] in vulnerable:
            continue  # never refute the finding's own subject
        ce = _refute(fn, blob, f)
        if ce:
            ce["provenance"] = {
                "commit_sha": blob.get("commit_sha"), "source_url": blob.get("source_url"),
                "snippet_sha256": blob.get("sha256"),
                "line": fn["declared_at_line"],
                "line_range_verified": blob.get("verified"),
                "code_scope": blob.get("source", "snippet quoted in the dataset"),
            }
            out.append(ce)
    seen, uniq = set(), []
    for ce in out:
        k = (ce["subject_function"], ce["type"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(ce)
    return uniq[:4]


def _refute(fn: dict, blk: dict, finding: dict) -> dict | None:
    name, mods, sig = fn["name"], fn["modifiers"], fn["signals"]
    roles = fn["required_roles"]

    if roles:
        return {
            "type": "access_control_refutation",
            "subject_function": name,
            "subject_file": blk.get("file"),
            "subject_contract": blk.get("contract"),
            "hypothesis": f"`{name}` can be called by any address to drain funds or change state.",
            "refutation": f"`{name}` is declared with {', '.join(mods)}, so only "
                          f"{', '.join(roles)} can reach it.",
            "evidence_type": "derived_fact",
            "rule": "onlyX-style modifier on the function declaration",
            "rule_source": "scripts/solidity_facts.py:functions",
            "applies_to_finding": finding.get("id"),
        }
    if fn["visibility"] in ("internal", "private"):
        return {
            "type": "reachability_refutation",
            "subject_function": name,
            "subject_file": blk.get("file"),
            "subject_contract": blk.get("contract"),
            "hypothesis": f"an external attacker can reach `{name}` directly.",
            "refutation": f"`{name}` is declared `{fn['visibility']}`, so it is not part of the "
                          "contract's external interface.",
            "evidence_type": "derived_fact",
            "rule": "function visibility in the declaration",
            "rule_source": "scripts/solidity_facts.py:functions",
            "applies_to_finding": finding.get("id"),
        }
    if sig.get("has_reentrancy_guard"):
        return {
            "type": "reentrancy_refutation",
            "subject_function": name,
            "subject_file": blk.get("file"),
            "subject_contract": blk.get("contract"),
            "hypothesis": f"`{name}` can be re-entered to drain state.",
            "refutation": "`nonReentrant` is present, so a re-entrant call is rejected before "
                          "the body runs.",
            "evidence_type": "derived_fact",
            "rule": "nonReentrant token on the declaration or in the body",
            "rule_source": "scripts/solidity_facts.py:_signals",
            "applies_to_finding": finding.get("id"),
        }
    auth_guards = [g for g in fn["guards"]
                   if re.search(r"msg\.sender|tx\.origin|_?owner|_?admin|_?governor|_?guardian",
                                f"{g.get('subject','')} {g.get('comparison','')}", re.I)]
    if auth_guards:
        g = auth_guards[0]
        return {
            "type": "authorisation_guard_refutation",
            "subject_function": name,
            "subject_file": blk.get("file"),
            "subject_contract": blk.get("contract"),
            "hypothesis": f"`{name}` performs an unauthorised state change.",
            "refutation": f"line {g['line']} guards on `{g['subject']} {g['operator']} "
                          f"{str(g.get('comparison'))[:60]}` before the body proceeds.",
            "evidence_type": "derived_fact",
            "rule": "require/revert comparing caller identity",
            "rule_source": "scripts/solidity_facts.py:_guards",
            "applies_to_finding": finding.get("id"),
        }
    if fn["mutability"] in ("view", "pure"):
        return {
            "type": "mutability_refutation",
            "subject_function": name,
            "subject_file": blk.get("file"),
            "subject_contract": blk.get("contract"),
            "hypothesis": f"`{name}` can be used to modify protocol state.",
            "refutation": f"`{name}` is `{fn['mutability']}`, so it cannot write storage.",
            "evidence_type": "derived_fact",
            "rule": "function mutability in the declaration",
            "rule_source": "scripts/solidity_facts.py:functions",
            "applies_to_finding": finding.get("id"),
        }
    return None


# ---------------------------------------------------------------------------
# Write-path input guard (see also build_all.CANONICAL_LAYERS).
#
# WHY THIS EXISTS. `candidate_functions()` reads the whole enclosing contract at
# the pinned commit through scripts/local_sources.py, i.e. the git-ignored
# `work/source_manifest.json` + `work/sources/` bytes and the `work/repos/`
# clones. On a checkout that holds none of them the snippets quoted in
# `jsonl/findings.jsonl` are all there is, so the run still "works": it just
# publishes a smaller truth. The offline run this guard was written after
# published `total_counterexamples` 99 -> 12 and `api_sibling_pairs` 71 -> 0
# while `derived_siblings/tasks.jsonl` still held 221 rows, and
# scripts/generate_readme.py:392,818 then asserted that zero in README prose.
#
# WHY A FLOOR AND NOT A NOSE. Every field guarded below is a discovery count:
# more retrieved source can only ever produce more counterexamples and more
# API-sibling pairs, and no normal edit deletes one. A count that moves DOWNWARD
# while nobody added a candidate is therefore not a measurement of the data, it
# is a measurement of what this machine could read. So the published totals are
# the floor, and the absent input trees are checked separately - either trip
# refuses the write.
# ---------------------------------------------------------------------------
def retrieval_inputs() -> list[Path]:
    """The git-ignored inputs this generator enumerates, and nothing else."""
    return [WORK / "source_manifest.json", WORK / "sources", WORK / "repos"]


def published_stats() -> dict:
    if not STATS_JSON.exists():
        return {}
    try:
        return json.loads(STATS_JSON.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def published_layer_records() -> int:
    if not LAYER_JSONL.exists():
        return 0
    return sum(1 for line in LAYER_JSONL.read_text(encoding="utf-8").splitlines()
               if line.strip())


def write_guard(stats: dict, out: list[dict]) -> list[str]:
    """Reasons this run must not overwrite the published counterexample layer."""
    reasons: list[str] = []
    old = published_stats()

    missing = [p for p in retrieval_inputs() if not p.exists()]
    if len(missing) == len(retrieval_inputs()):
        reasons.append(
            "none of the retrieved-source inputs this generator enumerates is on disk: "
            + ", ".join(p.as_posix() for p in retrieval_inputs())
            + " (git-ignored; populated by scripts/fetch_sources.py). Without them only "
              "the snippets quoted in jsonl/findings.jsonl are analysable, which is a "
              "different and smaller artefact than the published one")

    for field in ("total_counterexamples", "api_sibling_pairs",
                  "records_with_api_sibling_pairs",
                  "records_with_at_least_one_counterexample",
                  "confirmed_high_medium_records"):
        old_v, new_v = old.get(field), stats.get(field)
        if isinstance(old_v, int) and isinstance(new_v, int) and new_v < old_v:
            reasons.append(
                f"{STATS_JSON.as_posix()}: {field} {old_v} -> {new_v} "
                f"({old_v - new_v} fewer published values; the field can only grow while "
                "the retrieved sources are present)")

    for field in ("by_type", "api_sibling_pair_types"):
        old_map = old.get(field) or {}
        new_map = stats.get(field) or {}
        lost = {k: (v, new_map.get(k, 0)) for k, v in old_map.items()
                if new_map.get(k, 0) < v}
        if lost:
            reasons.append(f"{STATS_JSON.as_posix()}: {field} "
                           + ", ".join(f"{k} {o} -> {n}"
                                       for k, (o, n) in sorted(lost.items())))

    old_records = published_layer_records()
    if old_records and len(out) < old_records:
        reasons.append(
            f"{LAYER_JSONL.as_posix()}: {old_records} published records -> {len(out)}. "
            "Rewriting it smaller deletes the refutations, `api_sibling_pairs` arrays "
            "and provenance hashes those rows carry")

    return reasons


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--allow-shrink", action="store_true",
                    help="let this run publish smaller counterexample counts than the "
                         "files already on disk instead of refusing (use only for a "
                         "reviewed, documented migration)")
    args = ap.parse_args(argv)
    rows = [json.loads(line) for line in open(JSONL / "findings.jsonl", encoding="utf-8") if line.strip()]
    hm = [r for r in rows if r["finding"].get("record_class") == "judged"
          and r["finding"].get("severity") in ("high", "medium")]
    out, with_ce = [], 0
    for r in rows:
        ces = counterexamples_for(r)
        if ces:
            with_ce += 1
            out.append({
                "record_type": "counterexample_set",
                "dataset_version": DATASET_VERSION,
                "finding_id": r["finding"].get("id"),
                "severity": r["finding"].get("severity"),
                "vulnerable_functions": r["finding"].get("affected_functions") or [],
                "counterexamples": ces,
                "original_evidence": {
                    "file": "jsonl/findings.jsonl",
                    "record_id": r["finding"].get("id"),
                    "record_sha256": sha256_text(json.dumps(r, sort_keys=True, ensure_ascii=False)),
                    "title": r["finding"].get("title"),
                    "vulnerability_classes": r["finding"].get("vulnerability_classes"),
                },
            })

    # why the other H/M records have none, so the gap is measured not guessed
    # ---------------------------------------------------------------- v2.1
    # API-sibling pairs. These are the counterexamples worth having: the same
    # category, the same API shape, a different security property, and a guard
    # that is actually declared in the retrieved source.
    import local_sources as ls
    pair_stats = collections.Counter()
    pairs_total = 0
    records_with_pairs = 0
    by_id = {o["finding_id"]: o for o in out}
    for r in hm:
        rid = (r.get("finding") or {}).get("id")
        owner = f"{r['source'].get('organization', 'code-423n4')}/{r['source']['repository']}"
        entries = []
        seen = set()
        for e in (list(r.get("code_context") or []) + list(r.get("vulnerable_code") or [])
                  + list(r.get("code_reference_only") or [])):
            key = (e.get("commit_sha"), e.get("file"))
            if not key[0] or not key[1] or key in seen:
                continue
            seen.add(key)
            entries.append(ls.analyse_cited(owner, e, allow_text=False))
        pairs = cp.pairs_for_record(r, entries)
        if not pairs:
            continue
        records_with_pairs += 1
        pairs_total += len(pairs)
        for pr in pairs:
            pair_stats[pr["type"]] += 1
        rec = by_id.get(rid)
        if rec is None:
            rec = {"record_type": "counterexample_set", "finding_id": rid,
                   "severity": (r.get("finding") or {}).get("severity"),
                   "vulnerable_functions": [], "counterexamples": [],
                   "original_evidence": {"source": "derived",
                                         "dataset_version": r.get("dataset_version")}}
            out.append(rec)
            by_id[rid] = rec
        rec["api_sibling_pairs"] = pairs
        rec["has_api_sibling_pairs"] = True

    reasons = collections.Counter()
    for r in hm:
        if counterexamples_for(r):
            continue
        codes = list(r.get("code_context") or []) + list(r.get("vulnerable_code") or []) \
            + list(r.get("code_reference_only") or [])
        cands = candidate_functions(r)
        if not codes:
            reasons["no_code_cited_by_the_record"] += 1
        elif not cands:
            reasons["cited_files_not_retrieved"] += 1
        else:
            reasons["every_cited_function_is_the_vulnerable_one_or_has_no_refutable_property"] += 1

    stats = {
        "generated_by": "scripts/build_counterexamples.py",
        "confirmed_high_medium_records": len(hm),
        "records_with_at_least_one_counterexample": with_ce,
        "records_without": len(hm) - with_ce,
        "records_without_reason": dict(reasons),
        "total_counterexamples": sum(len(o["counterexamples"]) for o in out),
        "by_type": dict(collections.Counter(
            ce["type"] for o in out for ce in o["counterexamples"])),
        "counterexamples_on_the_vulnerable_function": 0,
        "api_sibling_pairs": pairs_total,
        "records_with_api_sibling_pairs": records_with_pairs,
        "api_sibling_pair_types": dict(pair_stats),
        "api_sibling_note": ("an API-sibling pair contrasts two entry points of the same shape "
                             "in one contract where exactly one declares an authorisation "
                             "guard. It is a stronger teaching signal than a generic "
                             "access-control refutation because the two members are "
                             "genuinely similar code."),
        "note": "every counterexample refutes a hypothesis about a function the finding did NOT "
                "name as vulnerable, so it can never contradict its own finding. Records with no "
                "counterexample are counted with the reason rather than padded with a weak one.",
    }
    blocks = [] if args.allow_shrink else write_guard(stats, out)
    if blocks:
        log("REFUSED: scripts/build_counterexamples.py wrote nothing. This run cannot see "
            "the retrieved-source inputs the published counterexample layer was built from.")
        for block in blocks:
            log(f"  - {block}")
        log(f"  it would have overwritten {LAYER_JSONL.as_posix()} and "
            f"{STATS_JSON.as_posix()} with the smaller result above - and README's "
            "API-sibling sentence reads that file, so a zero here becomes a published "
            "claim. Re-run with --allow-shrink only as a reviewed migration (the same "
            "wording as build_all.py --allow-canonical-rewrite).")
        return 1

    DERIVED.mkdir(parents=True, exist_ok=True)
    write_jsonl(DERIVED / "counterexamples.jsonl", out)
    write_json(STATS_JSON, stats)
    if args.allow_shrink:
        log("NOTE: --allow-shrink was given, so the published counts may now be smaller "
            "than the files this run replaced. That is a migration, not a rebuild.")
    log(f"wrote derived/counterexamples.jsonl ({len(out)} records, "
        f"{stats['total_counterexamples']} counterexamples)")
    log(f"  H/M with counterexample: {with_ce}/{len(hm)}")
    log(f"  without, by reason: {dict(reasons)}")
    log(f"  by type: {stats['by_type']}")
    log(f"  API-sibling pairs: {pairs_total} on {records_with_pairs} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
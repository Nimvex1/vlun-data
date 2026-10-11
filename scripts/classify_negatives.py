#!/usr/bin/env python3
"""Three honest classes of hard negative, plus duplicate corroboration.

The v2 dataset reported 443 of 458 rejections as `blocking_condition: unknown`,
which is defensible but throws away real evidence. Two things can be stated
without inventing anything:

  1. **Corroboration.** A submission rejected as a *duplicate* whose claim matches
     a *confirmed* finding from the same audit — same code target, or the same
     title — is not a false positive. The underlying issue was validated by the
     judges; only this copy was redundant. Recording that is strictly better than
     `unknown`, and it is mechanical.

  2. **Attribution.** When a sponsor or judge published a reason, that reason is
     attributed verbatim. Nine records qualify.

The third class, an *experimentally demonstrated* non-exploit, is reserved for
records where an exploit was actually attempted and observed to fail. It is the
hardest class and it is counted honestly: where no attempt was possible the
record says which controlled reason applies (`rpc_unavailable`,
`requires_harness_reconstruction`, ...) instead of claiming a negative.

The original verdict is never overwritten. A corroborated duplicate keeps
`duplicate`; this file only adds what the public record additionally supports.

    python scripts/build_hard_negatives.py
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_hard_negatives as v2  # noqa: E402  (reuse the v2 derivation)
from vlun import JSONL, REPORTS, log, read_jsonl, write_json  # noqa: E402

# The classes, strongest evidence first. This is the v2.1 hard-negative
# EVIDENCE taxonomy; it is deliberately NOT `vlun_v3.NEGATIVE_CLASSES`, which
# is the closed `negative_class` schema for v3 records (schema_terms.py owns
# that name). The two answer different questions and must never be conflated.
HARD_NEGATIVE_CLASSES = (
    "experimentally_verified",   # the exploit was attempted and observed to fail
    "attributed",                # a named judge or sponsor published the reason
    "corroborated_duplicate",    # the claim is validated elsewhere; this copy is redundant
    "derived_from_code",         # a guard in the cited source blocks the claim's own target
    "unknown",                   # only a rejection, duplicate or dispute label is public
)


def norm_title(t: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def _tokens(text: str) -> frozenset:
    return frozenset(re.findall(r"[a-z0-9]+", (text or "").lower()))


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


SNIPPET_JACCARD_THRESHOLD = 0.6


def finding_index(findings: list[dict]) -> dict:
    """Indexes over the published findings, every one scoped to its audit.

    A corroboration is only evidence if the confirming finding belongs to the
    SAME audit as the rejected copy: the same boilerplate title filed against two
    different audits is the leakage case, not corroboration.
    """
    by_target: dict[tuple, list[dict]] = {}   # (repo, file, function) -> entries
    by_title: dict[tuple, list[dict]] = {}    # (repo, norm title)   -> entries
    by_id: dict[str, dict] = {}               # finding id          -> entry
    tokens_by_repo: dict[str, list[tuple[dict, frozenset]]] = {}
    for f in findings:
        v = (f.get("validation") or {}).get("status")
        fi = f.get("finding") or {}
        repo = (f.get("source") or {}).get("repository")
        entry = {"id": fi.get("id"), "status": v, "severity": fi.get("severity"),
                 "title": fi.get("title"), "repo": repo}
        by_id[fi.get("id")] = entry
        toks = frozenset()
        for c in (f.get("code_context") or []):
            by_target.setdefault((repo, c.get("file"), c.get("function")), []).append(entry)
            t = _tokens(c.get("snippet") or "")
            if len(t) > len(toks):
                toks = t
        if toks:
            tokens_by_repo.setdefault(repo, []).append((entry, toks))
        by_title.setdefault((repo, norm_title(fi.get("title"))), []).append(entry)
    return {"by_target": by_target, "by_title": by_title, "by_id": by_id,
            "tokens_by_repo": tokens_by_repo}


def corroborate(row: dict, index: dict) -> dict | None:
    """Find a published finding in the same audit that carries the same claim.

    Four mechanical methods, strongest first; all of them are recorded when they
    fire, and the `method` field lists every method that produced a CONFIRMED
    match, so the class evidence states exactly how the corroboration was made.
    """
    repo = (row.get("source") or {}).get("repository")
    hits: dict[str, dict] = {}

    def add(entry: dict, method: str) -> None:
        h = hits.setdefault(entry["id"], {"entry": entry, "methods": set()})
        h["methods"].add(method)

    # 1. an explicit duplicate_of pointer that resolves to a finding id
    dup_of = ((row.get("validation") or {}).get("duplicate_of") or "").strip()
    pointed = index["by_id"].get(dup_of)
    if pointed is not None:
        add(pointed, "explicit duplicate_of pointer to a published finding")

    # 2. same code target (file::function), same audit
    for c in (row.get("code_context") or []):
        for e in index["by_target"].get((repo, c.get("file"), c.get("function")), []):
            add(e, "same code target (file::function) within the same audit")

    # 3. identical normalised title, same audit
    for e in index["by_title"].get((repo, norm_title((row.get("finding") or {}).get("title"))), []):
        add(e, "identical normalised title within the same audit")

    # 4. snippet similarity (token Jaccard) against same-audit findings
    neg_toks = frozenset()
    for c in (row.get("code_context") or []):
        t = _tokens(c.get("snippet") or "")
        if len(t) > len(neg_toks):
            neg_toks = t
    if neg_toks:
        best = 0.0
        best_entry = None
        for entry, toks in index["tokens_by_repo"].get(repo, []):
            j = _jaccard(neg_toks, toks)
            if j > best:
                best, best_entry = j, entry
        if best_entry is not None and best >= SNIPPET_JACCARD_THRESHOLD:
            add(best_entry, f"snippet similarity: token Jaccard {best:.2f} >= "
                            f"{SNIPPET_JACCARD_THRESHOLD} with a finding of the same audit")

    if not hits:
        return None
    confirmed = sorted(h for h, x in hits.items() if x["entry"]["status"] == "confirmed")
    other = sorted(h for h, x in hits.items() if x["entry"]["status"] != "confirmed")
    confirmed_methods = sorted(m for h, x in hits.items()
                               if x["entry"]["status"] == "confirmed" for m in x["methods"])
    return {"candidates": sorted(hits), "confirmed": confirmed,
            "other_status": other,
            "method": ("; ".join(confirmed_methods) if confirmed_methods
                       else "matched a published finding of the same audit that is not "
                            "confirmed"),
            "scoping": "matches are scoped to the same audit; a same-title claim in a "
                       "different audit is the leakage case, not corroboration"}


def classify_negative(derived: dict, row: dict, corr: dict | None,
                      executed: dict | None) -> dict:
    """Exactly one class, with the evidence that put it there."""
    blocking = derived.get("blocking_condition") or {}
    etype = blocking.get("evidence_type")
    basis = ((row.get("negative_analysis") or {}).get("rejection_basis"))

    if executed and executed.get("status") in ("false_positive_verified",
                                               "claim_misunderstood"):
        return {"negative_class": "experimentally_verified",
                "class_evidence": {"evidence_type": "experimentally_verified",
                                   "detail": executed},
                "is_false_positive": True}
    if executed and executed.get("status") == "exploit_reproduced":
        # The attack the submission described was executed and it *worked* on the
        # audited revision. The record is therefore not a false positive at all.
        return {"negative_class": "corroborated_duplicate",
                "class_evidence": {
                    "evidence_type": "experimentally_verified",
                    "detail": {
                        "experiment": executed,
                        "reading": ("the submitted attack was reconstructed and executed "
                                    "against the audited revision, and it succeeded. The "
                                    "submission was rejected as a duplicate, not because the "
                                    "claim was wrong. This is experimental confirmation that "
                                    "the underlying vulnerability is real."),
                        "therefore_false_positive": False,
                    }},
                "is_false_positive": False}
    if basis == "public_judge_or_sponsor_comment" and etype == "reported_claim":
        return {"negative_class": "attributed",
                "class_evidence": {"evidence_type": "externally_attributed",
                                   "detail": blocking},
                "is_false_positive": None}
    if corr and corr.get("confirmed"):
        return {"negative_class": "corroborated_duplicate",
                "class_evidence": {
                    "evidence_type": "derived_fact",
                    "detail": {
                        "corroborating_findings": corr["confirmed"],
                        "method": corr["method"],
                        "reading": ("the same claim was accepted as a confirmed finding in "
                                    "this audit. This submission was rejected as redundant; "
                                    "that is a statement about duplication, NOT evidence "
                                    "that the vulnerability is absent."),
                        "therefore_false_positive": False,
                    }},
                "is_false_positive": False}
    if etype == "derived_fact" and (blocking.get("confidence") == "high"):
        return {"negative_class": "derived_from_code",
                "class_evidence": {"evidence_type": "derived_fact", "detail": blocking},
                "is_false_positive": None}
    return {"negative_class": "unknown",
            "class_evidence": {
                "evidence_type": "unknown",
                "detail": {
                    "public_evidence": (row.get("validation") or {}).get("all_public_statuses"),
                    "reason": ("no judge or sponsor reasoning is public, no confirmed finding "
                               "carries the same claim, and no guard was mechanically located "
                               "on the claim's own target"),
                }},
            "is_false_positive": None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-stats", default=str(REPORTS / "negative_verification_stats.json"))
    args = ap.parse_args()

    negatives = read_jsonl(JSONL / "negative_findings.jsonl")
    findings = read_jsonl(JSONL / "findings.jsonl")
    index = finding_index(findings)

    executed_path = REPORTS / "negative_experiments.json"
    executed: dict[str, dict] = {}
    if executed_path.exists():
        for e in json.loads(executed_path.read_text(encoding="utf-8")).get("experiments", []):
            executed[e["finding_id"]] = e

    out_rows = []
    tally = collections.Counter()
    fp_tally = collections.Counter()
    exp_tally = collections.Counter()
    blockers = collections.Counter()
    for row in negatives:
        derived = v2.build_negative(row)
        corr = corroborate(row, index)
        rid = (row.get("finding") or {}).get("id") or v2.rec_id(row)
        cls = classify_negative(derived, row, corr, executed.get(rid))
        tally[cls["negative_class"]] += 1
        fp_tally[str(cls["is_false_positive"])] += 1
        if cls["negative_class"] == "experimentally_verified":
            blockers["none"] += 1
        elif executed.get(rid):
            blockers[(executed[rid].get("status") or "unknown")] += 1
        else:
            blockers["not_attempted"] += 1
        if rid in executed:
            exp_tally[executed[rid].get("status") or "unknown"] += 1
        out_rows.append({
            "finding_id": rid,
            "repository": row["source"]["repository"],
            "original_verdict": (row.get("validation") or {}).get("status"),
            "original_duplicate_of": (row.get("validation") or {}).get("duplicate_of"),
            "duplicate": (row.get("validation") or {}).get("duplicate"),
            **cls,
            "corroboration": corr,
            "blocking_condition": derived.get("blocking_condition"),
            "attacker_model": derived.get("attacker_model"),
            "negative_reasoning": derived.get("negative_reasoning"),
            "quality": derived.get("quality"),
            "code_resolved": bool(row.get("code_context")),
            "executed_disproof": executed.get(rid),
        })

    doc = {
        "generated_by": "scripts/build_hard_negatives.py (v2.1 classification)",
        "total": len(out_rows),
        "by_class": dict(tally),
        "class_vocabulary": list(HARD_NEGATIVE_CLASSES),
        "is_false_positive": dict(fp_tally),
        "blocking_reason": dict(blockers),
        "executed_negative_experiments": dict(exp_tally),
        "corroborated_by_confirmed_finding":
            sum(1 for r in out_rows if r["negative_class"] == "corroborated_duplicate"),
        "attributed_by_named_source":
            sum(1 for r in out_rows if r["negative_class"] == "attributed"),
        "experimentally_verified":
            sum(1 for r in out_rows if r["negative_class"] == "experimentally_verified"),
        "guarantee": (
            "A record is only `experimentally_verified` when an exploit was executed and "
            "observed to fail. A `corroborated_duplicate` record is explicitly NOT a false "
            "positive: the claim was validated elsewhere and only this copy was redundant. "
            "The original verdict is never overwritten."),
        "known_ceiling": {
            "largest_cluster": "2024-04-noya AccountingManager / connector functions",
            "blocker": "rpc_unavailable",
            "detail": ("the NOYA test fixtures create a mainnet fork in `setUp()`; without "
                       "an archive endpoint (`VLUN_RPC_URL`) no exploit attempt can be "
                       "executed against those contracts, so those negatives stay "
                       "`unknown` rather than being given an invented reason"),
        },
        "records": out_rows,
    }
    write_json(Path(args.out_stats), doc)
    log(f"negative_verification_stats.json: {dict(tally)}")
    log(f"  corroborated={doc['corroborated_by_confirmed_finding']} "
        f"attributed={doc['attributed_by_named_source']} "
        f"experimental={doc['experimentally_verified']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
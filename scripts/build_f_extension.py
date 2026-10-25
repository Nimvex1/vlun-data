#!/usr/bin/env python3
"""Build the VLUN F-extension: F-A rejection-evidence vectors and F-B duplicate-radar pairs.

The committed `F_false_positive_rejection` family asks one binary question and can
score 17 of its 458 rows, because the only public evidence for the rest is a
rejection label. This extension keeps that family untouched and adds two richer
tasks over the same canonical evidence:

  Fa_rejection_evidence_axis_vector
      one task per rejected submission; the model labels each of the six
      rejection-evidence axes supported / not_supported / unknown from an
      evidence packet, and states which supported axes are technical
      explanations of why the claim is false.

  Fb_duplicate_radar_pair
      one task per (candidate submission, accepted finding) pair; the model
      decides same_vulnerability / distinct_vulnerability / ambiguous without
      seeing the duplicate label, the `duplicate_of` pointer or the target id.

Gold labels are the canonical axes layer (`derived_rejections/rejection_corpus.jsonl`)
re-expressed as answers; nothing here invents a reason to complete a row. A row is
`unlabeled` when the packet cannot carry the evidence an axis needs, and a pair is
`ambiguous` when the relationship cannot be established - never forced into the
negative class.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from vlun import (  # noqa: E402
    BENCH, DERIVED, JSONL, carry_foreign_task_entries, log, read_jsonl,
    write_json, write_jsonl,
)

CORPUS = ROOT / "derived_rejections" / "rejection_corpus.jsonl"
NEGATIVES = JSONL / "negative_findings.jsonl"
FINDINGS = JSONL / "findings.jsonl"
HARD_NEGATIVES = DERIVED / "hard_negatives.jsonl"
ROOT_CAUSES = ROOT / "taxonomy" / "assignments_v1.jsonl"

FA_NAME = "Fa_rejection_evidence_axis_vector"
FB_NAME = "Fb_duplicate_radar_pair"
EXTENSION_VERSION = "vlun-f-extension/2.0"
DEFINITIONS_VERSION = "rejection-definitions-1.0"
LABEL_PROVENANCE_VERSION = "fb-label-provenance-1.0"

# The six axes, in the order the corpus defines them. Names are the metric names
# from scripts/build_rejection_corpus.py METRICS - they are not renamed here.
AXES = (
    "rejection_status_publicly_reported",
    "reason_attributed_to_judge_or_sponsor",
    "reason_supported_by_cited_code",
    "claim_corroborated_as_duplicate_of_confirmed_finding",
    "exploit_attempted_and_claimed_violation_not_demonstrated",
    "unknown_or_insufficient_evidence",
)

# What each axis needs inside the packet before it can be scored at all, and what
# an evidenced negative looks like. A requirement with no observed evidence makes
# the axis non-assessable; an unassessable axis gets no `not_supported` gold.
AXIS_REQUIREMENTS = {
    "rejection_status_publicly_reported": ("public_statuses",),
    "reason_attributed_to_judge_or_sponsor": ("attributed_statements",),
    "reason_supported_by_cited_code": ("claim_code_targets", "code_citations"),
    "claim_corroborated_as_duplicate_of_confirmed_finding": ("duplicate_pointer",),
    "exploit_attempted_and_claimed_violation_not_demonstrated": ("exploit_attempt",),
    "unknown_or_insufficient_evidence": (),
}

# The assessability contract, published in the stats file and the report. The
# judge/sponsor axis is the load-bearing case: the source layer records no
# completeness signal for the public comment thread, so an empty statement list
# cannot establish "no attribution exists" and the axis is unassessable.
AXIS_ASSESSABILITY = {
    "rejection_status_publicly_reported": {
        "evidence_required": (
            "a public status list or public label phrase carried in the packet"),
        "evidenced_negative": (
            "a packet carrying a non-duplicate public status (rejected/disputed) and no "
            "duplicate label"),
        "unassessable_when": "the packet carries neither a status nor a label phrase",
        "reasoning_kind": "input_observable",
    },
    "reason_attributed_to_judge_or_sponsor": {
        "evidence_required": (
            "at least one attributed statement with author/role/URL, or an authoritative "
            "completeness record showing the full public thread carries none"),
        "evidenced_negative": (
            "an authoritative completeness record that the public thread was fully "
            "captured and holds no judge or sponsor statement"),
        "unassessable_when": (
            "the statement list is empty: `jsonl/negative_findings.jsonl` records no "
            "comment-count or crawl-completeness field, and `rejection_basis: label_only` "
            "describes the extraction, not the public record, so absence is not proof"),
        "reasoning_kind": "reasoning",
    },
    "reason_supported_by_cited_code": {
        "evidence_required": (
            "a claim code target plus a citation whose body is cleared for "
            "redistribution or whose mechanical structure is carried"),
        "evidenced_negative": (
            "a cleared citation or observed structure on the claimed target with no "
            "refuting gate"),
        "unassessable_when": (
            "no code target, no citation, or every citation body withheld with no "
            "observed structure"),
        "reasoning_kind": "reasoning",
    },
    "claim_corroborated_as_duplicate_of_confirmed_finding": {
        "evidence_required": (
            "a published duplicate pointer that resolves to an accepted confirmed or "
            "acknowledged finding, or a public status record that was expected to carry "
            "a pointer and carries none"),
        "evidenced_negative": (
            "no pointer on a record whose public status is rejected/disputed and whose "
            "status labels name no duplicate: the source records a status for every "
            "submission in this corpus, so it was expected to carry a pointer if the "
            "submission had been deduplicated"),
        "unassessable_when": (
            "no pointer and no public status, or a duplicate-labelled record with no "
            "pointer string"),
        "reasoning_kind": "input_observable",
    },
    "exploit_attempted_and_claimed_violation_not_demonstrated": {
        "evidence_required": (
            "a recorded exploit-attempt status (including `not_attempted`)"),
        "evidenced_negative": (
            "a recorded attempt whose blocker or result shows the violation was not "
            "demonstrated"),
        "unassessable_when": "the exploit-attempt record is absent",
        "reasoning_kind": "input_observable",
    },
    "unknown_or_insufficient_evidence": {
        "evidence_required": (
            "the corpus synthesis of the axes above over the public record"),
        "evidenced_negative": (
            "a positive evidence axis is supported, so the record is not merely "
            "unknown"),
        "unassessable_when": "never: the synthesis is defined for every corpus record",
        "reasoning_kind": "meta",
    },
}

TECHNICAL_AXES = (
    "reason_attributed_to_judge_or_sponsor",
    "reason_supported_by_cited_code",
    "exploit_attempted_and_claimed_violation_not_demonstrated",
)

ANSWERS = ("supported", "not_supported", "unknown")
PAIR_ANSWERS = ("same_vulnerability", "distinct_vulnerability", "ambiguous")

# F-B label provenance. There are no human reviews of these pairs: every label is
# either carried by a published pointer or derived by a documented rule. The tiers
# keep those two apart, and the cohort separates the labels the evidence supports
# from the weak, target-only labels that are reported but not a headline.
PAIR_LABEL_TIERS = (
    "pointer_supported_positive",
    "rule_derived_target_and_root_cause_negative",
    "ambiguous_shared_target_no_pointer",
    "ambiguous_target_separation_without_root_cause",
    "ambiguous_pointer_unresolved",
)
PRIMARY_COHORT = "primary"
EXPLORATORY_COHORT = "exploratory"


def pair_label(*, pointer_resolved: bool = False, shared_target: bool = False,
               neg_rc: str | None = None, fin_rc: str | None = None) -> dict | None:
    """The documented label rule, in one place.

    * a resolved published pointer is a pointer-supported positive;
    * a shared code target without a pointer is ambiguous - a shared target is not
      the same claim;
    * a distinct label needs disjoint targets AND a documented root-cause/scope
      difference; targets alone do not prove distinct root causes, so a target-only
      pair is an exploratory ambiguous label;
    * equal root-cause labels block the pair entirely (it is a duplicate shape).
    """
    if pointer_resolved:
        return {
            "relationship": "same_vulnerability",
            "tier": "pointer_supported_positive",
            "cohort": PRIMARY_COHORT,
            "adjudication": "pointer_resolved_to_accepted_finding",
            "basis": ["published duplicate_of pointer resolves to an accepted finding"],
        }
    if shared_target:
        return {
            "relationship": "ambiguous",
            "tier": "ambiguous_shared_target_no_pointer",
            "cohort": PRIMARY_COHORT,
            "adjudication": "shared_code_target_without_pointer",
            "basis": ["shared file::function target in the same audit with no pointer; "
                      "a shared target is not the same claim"],
        }
    if neg_rc and fin_rc and neg_rc == fin_rc:
        return None
    if neg_rc and fin_rc:
        return {
            "relationship": "distinct_vulnerability",
            "tier": "rule_derived_target_and_root_cause_negative",
            "cohort": PRIMARY_COHORT,
            "adjudication": "rule_derived_target_separation_and_root_cause_difference",
            "basis": ["cited code targets are disjoint",
                      f"recorded root-cause labels differ ({neg_rc} vs {fin_rc})"],
        }
    return {
        "relationship": "ambiguous",
        "tier": "ambiguous_target_separation_without_root_cause",
        "cohort": EXPLORATORY_COHORT,
        "adjudication": "target_separation_without_root_cause_rule",
        "basis": ["cited code targets are disjoint",
                  "at least one side has no root-cause label, so target separation "
                  "alone does not establish a distinct root cause"],
    }


def unresolved_label() -> dict:
    return {
        "relationship": "ambiguous",
        "tier": "ambiguous_pointer_unresolved",
        "cohort": EXPLORATORY_COHORT,
        "adjudication": "pointer_does_not_resolve",
        "basis": ["the published pointer names a finding absent from the accepted layer"],
    }

# A duplicate-radar input must not state the answer. Contest report titles and
# narratives sometimes carry the triage outcome ("duplicate of #12", "not a
# vulnerability", "by design"), so any side carrying such a phrase is dropped from
# the pair pool rather than shipped as a task whose label is in the prompt.
JUDGEMENT_PHRASES = re.compile(
    r"\b(duplicate|duplicated|dup of|rejected|disputed|invalid|withdrawn|nullified|"
    r"ineligible|won'?t fix|not a vulnerability|not vulnerable|by design|out of scope|"
    r"known issue|already reported|labelled|labeled)\b", re.IGNORECASE)


def leak_free(*texts: str | None) -> bool:
    return not any(JUDGEMENT_PHRASES.search(t or "") for t in texts)

FA_PROMPT = (
    "A rejected security-submission evidence packet is given. For each of the six "
    "rejection-evidence axes answer exactly one of supported, not_supported, unknown, "
    "where 'supported' means the packet contains evidence that satisfies the axis "
    "definition and 'not_supported' means the packet shows the condition does not hold "
    "(for example an exploit was recorded as not attempted). Then list which supported "
    "axes are technical explanations of why the claim is false: a publicly reported "
    "status and a duplicate corroboration are not technical explanations of falsity. "
    "Axes are independent and may hold together; they are not mutually exclusive classes."
)

FB_PROMPT = (
    "Two security submissions from the same audit are given: a candidate and a "
    "comparison finding. Decide whether they describe the same vulnerability "
    "(same root cause such that one fix would address both), a distinct "
    "vulnerability, or ambiguous when the evidence does not establish either. "
    "The published status, the duplicate pointer and the identifiers of the two "
    "records are deliberately withheld; do not infer them."
)


def _load(path: Path) -> list[dict]:
    return read_jsonl(path) if path.exists() else []


def _stable_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:20]


def _tokenize(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_]{4,}", (text or "").lower())}


def claim_text(rec: dict) -> str:
    finding = rec.get("finding") or {}
    analysis = rec.get("negative_analysis") or {}
    return " ".join(filter(None, [finding.get("title"),
                                  analysis.get("why_it_looked_plausible")]))


def _excerpt(statement: dict) -> dict:
    """Evidence-only projection of an attributed statement.

    The corpus records the matched phrase rule next to the quote; carrying the rule
    into the packet would hand the model the classifier that produced the label.
    """
    out = {}
    for key in ("author", "role", "excerpt", "url", "excerpt_sha256", "excerpt_chars"):
        if statement.get(key) not in (None, "", []):
            out[key] = statement[key]
    return out


def code_citations(rec: dict, allowed_snippets: set[str] | None) -> list[dict]:
    """Cited code for the packet, with withheld text marked as withheld.

    Rights rule copied from the committed F family: snippet bytes only travel when
    their sha256 is in the redistribution-cleared set, otherwise the citation is a
    location, never a body of code.
    """
    blocks = []
    for entry in (rec.get("code_context") or [])[:6]:
        snippet = entry.get("snippet") or ""
        digest = hashlib.sha256(snippet.encode("utf-8")).hexdigest() if snippet else None
        cleared = bool(allowed_snippets) and digest in allowed_snippets
        blocks.append({
            "file": entry.get("file"),
            "contract": entry.get("contract"),
            "function": entry.get("function"),
            "line_start": entry.get("line_start"),
            "line_end": entry.get("line_end"),
            "commit_sha": entry.get("commit_sha"),
            "code": snippet[:4000] if cleared else None,
            "text_withheld": not cleared,
        })
    return blocks


def observed_structure(hard_negative: dict | None) -> list[dict]:
    """Guard/modifier facts, stripped of every derived conclusion.

    `blocking_condition`, `why_exploit_fails`, `attacker_limitations` and
    `actual_protocol_behavior` all restate the answer for the code-supported axis, so
    they stay out of the packet. Only the mechanically observable shape travels.
    """
    if not hard_negative:
        return []
    out = []
    for fact in (hard_negative.get("observed_code_facts") or [])[:6]:
        signals = fact.get("signals") or {}
        guards = [{"kind": g.get("kind"), "subject": g.get("subject"),
                   "operator": g.get("operator"), "line": g.get("line")}
                  for g in (fact.get("guards") or []) if isinstance(g, dict)]
        out.append({
            "file": fact.get("file"),
            "function": fact.get("function"),
            "modifiers": sorted(fact.get("modifiers") or []),
            "guards": sorted(guards, key=lambda g: (g.get("line") or 0,
                                                    g.get("subject") or "")),
            "required_roles": sorted(fact.get("required_roles") or []),
            "mutability": fact.get("mutability"),
            "external_call_present": bool(signals.get("has_external_call")),
            "delegatecall_present": bool(signals.get("has_delegatecall")),
        })
    return out


def build_packet(corpus_row: dict, negative: dict,
                 hard_negative: dict | None) -> tuple[dict, dict, list[str]]:
    validation = negative.get("validation") or {}
    axes = corpus_row.get("axes") or {}
    original = corpus_row.get("original_verdict") or {}
    att = axes.get("attributed_reason") or {}
    exp = axes.get("exploit_attempt") or {}
    corr = axes.get("duplicate_corroboration") or {}

    allowed = {e.get("snippet_sha256") for e in (hard_negative or {}).get("relevant_code") or []
               if e.get("snippet_sha256")}
    targets = [f"{e.get('file')}::{e.get('function')}"
               for e in (negative.get("code_context") or []) if e.get("file")]

    statements = [_excerpt(s) for s in (att.get("statements") or [])]
    participants = [_excerpt(s) for s in (att.get("participant_statements") or [])]

    # Axis 4 evidence: the pointer string as published, plus the standing of the
    # finding it names. The pointer is the evidence the axis is about; what the
    # corpus concluded from it (`corroborated`, `best_confidence`) is the answer.
    pointer = validation.get("duplicate_of") or None
    pointer_context = None
    if pointer:
        methods = [m for m in (corr.get("methods") or [])
                   if m.get("method") == "explicit_duplicate_of_pointer"
                   and m.get("corroborating_finding") == pointer]
        pointer_context = {
            "published_pointer": pointer,
            "pointer_resolves_in_this_dataset": bool(methods),
            "target_status": (methods[0].get("corroborating_status") if methods else None),
            "target_url": (methods[0].get("corroborating_issue_url") if methods else None),
        }

    packet: dict = {
        "audit": corpus_row.get("audit"),
        "repository": corpus_row.get("repository"),
        "public_statuses": sorted(original.get("all_public_statuses") or []),
        "public_label_phrases": sorted(original.get("public_labels") or []),
        "judge_decision": validation.get("judge_decision") or None,
        "sponsor_position": validation.get("sponsor_position") or None,
        "attributed_statements": statements,
        "participant_statements": participants,
        "claim": {
            "title": (negative.get("finding") or {}).get("title"),
            "plausibility_narrative": ((negative.get("negative_analysis") or {})
                                       .get("why_it_looked_plausible")),
            "claimed_impact": ((negative.get("security_reasoning") or {})
                               .get("impact") or {}).get("value")
            if isinstance((negative.get("security_reasoning") or {}).get("impact"), dict)
            else (negative.get("security_reasoning") or {}).get("impact"),
        },
        "claim_code_targets": targets,
        "code_citations": code_citations(negative, allowed),
        "observed_code_structure": observed_structure(hard_negative),
        "duplicate_pointer": pointer_context,
        "exploit_attempt": {
            "status": exp.get("status"),
            "blocker": exp.get("blocker"),
            "artefact": (exp.get("experiment") or {}).get("artifact")
            if isinstance(exp.get("experiment"), dict) else None,
        },
        "source_urls": sorted((negative.get("provenance") or {}).get("source_urls") or [])[:4],
    }

    assessable: dict[str, bool] = {}
    missing: dict[str, list[str]] = {}
    for axis, required in AXIS_REQUIREMENTS.items():
        absent = [name for name in required if packet.get(name) in (None, [], "", {})]
        # A recorded "not attempted" is evidence about the exploit axis, so the key
        # being present with a null sub-field does not make it non-assessable.
        if axis == "exploit_attempted_and_claimed_violation_not_demonstrated":
            absent = [] if isinstance(packet.get("exploit_attempt"), dict) else ["exploit_attempt"]
        if axis == "rejection_status_publicly_reported":
            absent = [] if packet["public_statuses"] or packet["public_label_phrases"] else ["public_statuses"]
        if axis == "reason_attributed_to_judge_or_sponsor":
            # No completeness signal exists for the public comment thread: the record
            # layer carries no comment count or crawl marker, and `rejection_basis`
            # describes the extraction. An empty statement list therefore cannot
            # establish "no attribution exists" and the axis stays unassessable.
            absent = ([] if packet["attributed_statements"]
                      else ["attributed_statement_or_thread_completeness_record"])
        if axis == "claim_corroborated_as_duplicate_of_confirmed_finding":
            # Absence of a pointer is evidence only where the source was expected to
            # carry one. Every record in this corpus carries a public status; a
            # rejected/disputed record with no duplicate label and no pointer is an
            # evidenced negative. A duplicate-labelled record with no pointer is not.
            if packet["duplicate_pointer"] is None:
                duplicate_labelled = (
                    "duplicate" in packet["public_statuses"]
                    or any("duplicate" in phrase.lower()
                           for phrase in packet["public_label_phrases"]))
                if not packet["public_statuses"] and not packet["public_label_phrases"]:
                    absent = ["duplicate_pointer_or_public_status_record"]
                elif duplicate_labelled:
                    absent = ["duplicate_pointer_for_duplicate_labelled_record"]
                else:
                    absent = []
        assessable[axis] = not absent
        if absent:
            missing[axis] = absent

    # A code citation with every body withheld cannot ground the code axis.
    if packet["code_citations"] and not any(c["code"] for c in packet["code_citations"]) \
            and not packet["observed_code_structure"]:
        assessable["reason_supported_by_cited_code"] = False
        missing["reason_supported_by_cited_code"] = ["cleared_code_text_or_structure"]

    return packet, assessable, missing


def axis_gold(corpus_row: dict) -> dict:
    metrics = corpus_row.get("metrics") or {}
    axes = corpus_row.get("axes") or {}
    gold = {}
    for axis in AXES:
        value = metrics.get(axis)
        if isinstance(value, bool):
            gold[axis] = "supported" if value else "not_supported"
        else:
            gold[axis] = "unknown"
    technical = [axis for axis in TECHNICAL_AXES
                 if ((axes.get({
                     "reason_attributed_to_judge_or_sponsor": "attributed_reason",
                     "reason_supported_by_cited_code": "code_supported_reason",
                     "exploit_attempted_and_claimed_violation_not_demonstrated":
                         "exploit_attempt",
                 }[axis]) or {}).get("is_technical_explanation"))
                 and gold.get(axis) == "supported"]
    return {"axes": gold, "technical_explanation_axes": technical,
            "counts_as_technical_reason_for_falsity": bool(
                (corpus_row.get("technical_verification") or {}).get(
                    "counts_as_technical_reason_for_why_the_claim_is_false")),
            "primary_reason_class": corpus_row.get("primary_reason_class"),
            "is_false_positive": corpus_row.get("is_false_positive")}


def build_fa_rows(corpus: list[dict], negatives_by_id: dict, hard_by_id: dict,
                  splits: dict[str, str]) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    accounting = collections.Counter()
    per_axis_assessable = collections.Counter()
    for record in corpus:
        fid = record.get("finding_id")
        negative = negatives_by_id.get(fid)
        if not negative:
            accounting["skipped_no_negative_record"] += 1
            continue
        packet, assessable, missing = build_packet(record, negative,
                                                  hard_by_id.get(fid))
        gold = axis_gold(record)
        unassessed = [axis for axis in AXES if not assessable[axis]]
        # An unassessable axis gets no gold: the corpus boolean is not evidence, so
        # the answer key records `unknown` and lists the axis as withheld instead of
        # emitting a `not_supported` gold from an empty evidence list.
        for axis in unassessed:
            gold["axes"][axis] = "unknown"
        gold["technical_explanation_axes"] = [
            axis for axis in gold["technical_explanation_axes"] if axis not in unassessed]
        for axis in AXES:
            if assessable[axis]:
                per_axis_assessable[axis] += 1
        if not unassessed:
            status = "labeled"
        elif len(unassessed) == len(AXES):
            status = "unlabeled"
        else:
            status = "partial"
        accounting[status] += 1
        assessed = [a for a in AXES if assessable[a]]
        rows.append({
            "task": FA_NAME,
            # The shared row contract: the id carries the family key and the split,
            # so a row cannot be moved between splits without changing its identity.
            "split": splits.get(fid, "unknown"),
            "id": f"FA::{splits.get(fid, 'unknown')}::{fid}",
            "input": {"prompt": FA_PROMPT,
                      "axis_definitions": AXIS_DEFINITIONS,
                      "axes_to_answer": list(AXES),
                      "answer_vocab": list(ANSWERS),
                      "evidence_packet": packet,
                      "independence_note": (
                          "the six axes are independent and overlapping; a duplicate "
                          "corroboration is not proof that the underlying claim is "
                          "false, and a status label is not a technical reason")},
            "answer_key": {**gold, "assessed_axes": assessed,
                           "withheld_gold_axes": unassessed},
            "answer_key_status": status,
            "answer_key_evidence_level": "derived_fact",
            "assessed_axes": assessed,
            "unassessed_axes": {axis: missing.get(axis, []) for axis in unassessed},
            "unlabelled_reason": (
                None if status == "labeled" else
                "the packet cannot carry the evidence for: "
                + ", ".join(f"{a} ({'+'.join(missing.get(a, []))})" for a in unassessed)),
            "evidence_type": "derived_fact",
            "source": {"record_id": fid,
                       "source_layer": (record.get("provenance") or {}).get("source_layer"),
                       "source_url": (record.get("provenance") or {}).get("source_url")},
        })
    return rows, {"accounting": dict(accounting),
                  "per_axis_assessable": dict(per_axis_assessable)}


def build_fb_pairs(corpus: list[dict], negatives_by_id: dict, findings_by_id: dict):
    """Positives from resolved pointers, negatives from adjudicated distinctness."""
    positives: list[tuple[dict, dict, dict]] = []
    ambiguous: list[tuple[dict, dict, dict]] = []
    pointer_by_negative: dict[str, str] = {}

    for record in corpus:
        fid = record["finding_id"]
        negative = negatives_by_id.get(fid)
        if not negative:
            continue
        axes_corr = (record.get("axes") or {}).get("duplicate_corroboration") or {}
        explicit = [m for m in (axes_corr.get("methods") or [])
                    if m.get("method") == "explicit_duplicate_of_pointer"]
        target_id = explicit[0]["corroborating_finding"] if explicit else None
        if target_id:
            pointer_by_negative[fid] = target_id
            target = findings_by_id.get(target_id)
            if target is None:
                ambiguous.append((negative, None, {
                    **unresolved_label(),
                    "why": "published pointer names a finding absent from the accepted layer",
                }))
                continue
            positives.append((negative, target, {
                **pair_label(pointer_resolved=True),
                "target_status": explicit[0].get("corroborating_status"),
                "confidence": explicit[0].get("confidence"),
            }))
            continue
        same_target = [m for m in (axes_corr.get("methods") or [])
                       if m.get("method") == "same_code_target_same_audit"
                       and m.get("corroborating_finding") in findings_by_id]
        if same_target:
            # A shared file::function with an accepted finding, and no pointer: the
            # corpus rule says a shared target is not the same claim, so neither a
            # positive nor a defensible negative can be established. These become
            # the ambiguous class and are counted apart from the negatives.
            chosen = sorted(same_target, key=lambda m: m["corroborating_finding"])[:1]
            for method in chosen:
                target = findings_by_id[method["corroborating_finding"]]
                ambiguous.append((negative, target, {
                    **pair_label(shared_target=True),
                    "why": "shared code target in the same audit without a pointer; "
                           "a shared target is not the same claim",
                    "method": method.get("method"),
                }))

    negatives, weak, blocked = build_distinct_pairs(corpus, negatives_by_id,
                                                    findings_by_id, pointer_by_negative)
    return positives, negatives, ambiguous + weak, pointer_by_negative, blocked


def _targets(rec: dict) -> set[str]:
    out = set()
    for entry in (rec.get("code_context") or []):
        if entry.get("file"):
            out.add(f"{entry['file']}::{entry.get('function') or ''}")
    return out


def _files(rec: dict) -> set[str]:
    return {e.get("file") for e in (rec.get("code_context") or []) if e.get("file")}


def build_distinct_pairs(corpus: list[dict], negatives_by_id: dict,
                         findings_by_id: dict, pointer_by_negative: dict):
    """Rule-derived negative candidates and weak target-only pairs.

    A distinct label needs disjoint cited targets AND a recorded root-cause
    difference on both sides. A pair separated only by its code target is returned
    in the weak pool as an exploratory ambiguous label: different code targets do
    not prove distinct root causes. No human reviewed any pair.
    """
    root_cause = {}
    for row in _load(ROOT_CAUSES):
        if not row.get("unlabelled") and row.get("primary") != "RC-99":
            root_cause[row["record_id"]] = row["primary"]

    audits: dict[str, list[dict]] = collections.defaultdict(list)
    for finding in findings_by_id.values():
        audits[(finding.get("source") or {}).get("repository")].append(finding)

    corpus_by_id = {r["finding_id"]: r for r in corpus}
    pairs: list[tuple[dict, dict, dict]] = []
    weak: list[tuple[dict, dict, dict]] = []
    blocked = collections.Counter()
    for fid, negative in negatives_by_id.items():
        record = corpus_by_id.get(fid)
        if record is None:
            continue
        audit = (negative.get("source") or {}).get("repository")
        canonical = pointer_by_negative.get(fid)
        claim_targets, claim_files = _targets(negative), _files(negative)
        neg_rc = root_cause.get(fid)
        text = claim_text(negative)
        candidates = []
        for finding in audits.get(audit, []):
            aid = (finding.get("finding") or {}).get("id")
            if aid == canonical:
                continue
            shared_targets = claim_targets & _targets(finding)
            shared_files = claim_files & _files(finding)
            finding_rc = root_cause.get(aid)
            if neg_rc and finding_rc and neg_rc == finding_rc:
                blocked["same_root_cause_label"] += 1
                continue
            if shared_targets:
                blocked["shared_function_target"] += 1
                continue
            overlap = _tokenize(text) & _tokenize(claim_text(finding))
            base = _tokenize(text) | _tokenize(claim_text(finding))
            similarity = (len(overlap) / len(base)) if base else 0.0
            if similarity > 0.6:
                blocked["claim_text_too_similar"] += 1
                continue
            label = pair_label(neg_rc=neg_rc, fin_rc=finding_rc)
            if label is None:
                blocked["same_root_cause_label"] += 1
                continue
            hardness = "different_function_same_file" if shared_files else "different_file"
            if neg_rc and finding_rc:
                hardness += "_and_different_root_cause"
            if hardness == "different_file":
                # A pair separated only by "different file, no root-cause label on
                # either side" is an easy negative: it tests nothing a keyword search
                # would not answer. It is excluded rather than used to pad the class.
                blocked["cross_file_separation_without_root_cause_evidence"] += 1
                continue
            candidates.append({
                "finding": finding,
                "hardness": hardness,
                "similarity": round(similarity, 3),
                "label": label,
                "shared_file": sorted(shared_files)[:1],
            })
        # One pair per candidate submission, strongest label first: a documented
        # root-cause difference outranks a target-only pair, then same-file hardness.
        # Two pairs per submission would turn one submission into two "independent"
        # examples, which is exactly the inflation this task forbids.
        candidates.sort(key=lambda c: (
            0 if c["label"]["relationship"] == "distinct_vulnerability" else 1,
            0 if c["hardness"].startswith("different_function_same_file") else 1,
            0 if "different_root_cause" in c["hardness"] else 1,
            c["similarity"] * -1,
            (c["finding"].get("finding") or {}).get("id", "")))
        for candidate in candidates[:1]:
            meta = {**candidate["label"], "hardness": candidate["hardness"],
                    "claim_text_overlap": candidate["similarity"]}
            if candidate["label"]["relationship"] == "distinct_vulnerability":
                meta["distinctness_evidence"] = candidate["label"]["basis"]
                pairs.append((negative, candidate["finding"], meta))
            else:
                weak.append((negative, candidate["finding"], {
                    **meta,
                    "why": "disjoint code targets but no recorded root-cause difference "
                           "on both sides; target separation alone does not establish a "
                           "distinct root cause",
                }))
    return pairs, weak, blocked


def _side(rec: dict | None, hard_by_id: dict, label: str) -> dict:
    """Model-facing side of a pair. No status, no verdict, no pointer, no record id."""
    if rec is None:
        return {"missing": True}
    fid = (rec.get("finding") or {}).get("id")
    reasoning = rec.get("security_reasoning") or {}
    impact = reasoning.get("impact")
    return {
        "role": label,
        "title": (rec.get("finding") or {}).get("title"),
        "protocol": (rec.get("protocol") or {}).get("name"),
        "severity_as_published": (rec.get("finding") or {}).get("severity") or None,
        "claimed_behaviour": reasoning.get("broken_behavior") or None,
        "claimed_impact": impact if isinstance(impact, (str, dict)) else None,
        "attack_path": (reasoning.get("attack_path") or [])[:4],
        "code_citations": code_citations(rec, {
            e.get("snippet_sha256") for e in (hard_by_id.get(fid) or {}).get("relevant_code") or []
            if e.get("snippet_sha256")}),
        "asserted_actor": ((hard_by_id.get(fid) or {}).get("attacker_model") or {})
        .get("attacker_kind"),
        "remediation_context": reasoning.get("expected_behavior_per_remediation") or None,
    }


def build_fb_rows(positives, negatives, ambiguous, hard_by_id, splits) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    skipped: dict[str, int] = collections.Counter()
    groups: dict[str, list[str]] = collections.defaultdict(list)

    def add(candidate: dict, target: dict | None, meta: dict):
        cid = (candidate.get("finding") or {}).get("id")
        tid = ((target or {}).get("finding") or {}).get("id") if target else "unresolved"
        if not cid or (cid, tid) in seen:
            return
        seen.add((cid, tid))
        side_candidate = _side(candidate, hard_by_id, "candidate")
        side_target = _side(target, hard_by_id, "comparison")
        texts = [value for side in (side_candidate, side_target)
                 for key in ("title", "claimed_behaviour", "claimed_impact")
                 if isinstance((value := side.get(key)), str)]
        if not leak_free(*texts):
            skipped["judgement_phrase_in_model_input"] += 1
            return
        split_candidate = splits.get(cid)
        split_target = splits.get(tid) if tid != "unresolved" else split_candidate
        if split_candidate != split_target:
            # One side is train and the other is test: shipping the pair would put a
            # protected evaluation record next to its own training twin.
            skipped["pair_straddles_the_published_split"] += 1
            return
        split = split_candidate or "unknown"
        gold = meta.get("relationship") or meta["pair_class"]
        tier = meta.get("tier")
        if tier is None:
            tier = ("ambiguous_pointer_unresolved" if gold == "ambiguous" and target is None
                    else "pointer_supported_positive" if gold == "same_vulnerability"
                    else "rule_derived_target_and_root_cause_negative"
                    if gold == "distinct_vulnerability"
                    else "ambiguous_target_separation_without_root_cause")
        cohort = meta.get("cohort") or (
            EXPLORATORY_COHORT if tier.startswith("ambiguous_pointer")
            or tier == "ambiguous_target_separation_without_root_cause"
            else PRIMARY_COHORT)
        basis = meta.get("basis") or ([meta["why"]] if meta.get("why") else [])
        evidence = {"same_vulnerability": "externally_attributed",
                    "distinct_vulnerability": "derived_fact",
                    "ambiguous": "unknown"}[gold]
        row = {
            "task": FB_NAME,
            "split": split,
            "id": f"FB::{split}::{_stable_id('Fb', cid, tid)}",
            "input": {"prompt": FB_PROMPT,
                      "answer_vocab": list(PAIR_ANSWERS),
                      "candidate_submission": side_candidate,
                      "comparison_finding": side_target,
                      "withheld": ["published status", "duplicate label",
                                   "duplicate_of pointer", "record identifiers",
                                   "adjudication metadata"],
                      "triage_policy": (
                          "Code4rena treats reports sharing one root cause as duplicates; "
                          "Immunefi additionally asks whether the same fix addresses both and "
                          "whether the relevant files or endpoints differ")},
            "answer_key": {"relationship": gold,
                           "adjudication_rule": meta.get("adjudication") or meta.get("why"),
                           "label_provenance": {
                               "version": LABEL_PROVENANCE_VERSION,
                               "tier": tier,
                               "cohort": cohort,
                               "basis": basis,
                               "human_reviewed": False,
                               "rule": (
                                   "a published duplicate_of pointer that resolves to an "
                                   "accepted finding" if tier == "pointer_supported_positive"
                                   else "documented builder rule applied to public evidence; "
                                   "no human review"),
                           },
                           "distinctness_evidence": meta.get("distinctness_evidence"),
                           "hardness": meta.get("hardness"),
                           "claim_text_overlap": meta.get("claim_text_overlap",
                                                         meta.get("similarity"))},
            "answer_key_status": "labeled" if target is not None else "unlabeled",
            "answer_key_evidence_level": evidence,
            "unlabelled_reason": (None if target is not None else
                                  "the published pointer does not resolve in the accepted layer"),
            "evidence_type": evidence,
            "source": {"record_id": cid, "candidate_record_id": cid,
                       "comparison_record_id": tid},
        }
        rows.append(row)
        groups[cid].append(row["id"])
        if tid != "unresolved":
            groups[tid].append(row["id"])

    for candidate, target, meta in positives:
        add(candidate, target, meta)
    for candidate, target, meta in negatives:
        add(candidate, target, meta)
    for candidate, target, meta in ambiguous:
        add(candidate, target, meta)

    rows.sort(key=lambda r: r["id"])
    classes = collections.Counter(r["answer_key"]["relationship"] for r in rows)
    tiers = collections.Counter(
        (r["answer_key"].get("label_provenance") or {}).get("tier", "unrecorded")
        for r in rows)
    cohorts = collections.Counter(
        (r["answer_key"].get("label_provenance") or {}).get("cohort", "unrecorded")
        for r in rows)
    stats = {
        "pair_rows": len(rows),
        "by_relationship": dict(classes),
        "by_label_tier": dict(tiers),
        "by_label_cohort": dict(cohorts),
        "by_split": dict(collections.Counter(r["split"] for r in rows)),
        "unique_candidate_submissions": len({r["source"]["candidate_record_id"] for r in rows}),
        "unique_canonical_findings": len({r["source"]["comparison_record_id"] for r in rows
                                         if r["source"]["comparison_record_id"] != "unresolved"}),
        "confirmed_duplicate_pairs": classes["same_vulnerability"],
        "rule_derived_distinct_pairs": classes["distinct_vulnerability"],
        "ambiguous_unscorable_pairs": sum(1 for r in rows if r["answer_key_status"] == "unlabeled"),
        "ambiguous_class_pairs": classes["ambiguous"],
        "excluded_pairs": dict(skipped),
        "distinct_independent_projects": None,
    }
    return rows, stats, groups


# ---------------------------------------------------------------------------
# Grouped splitting: a submission, its canonical finding, their root-cause label
# and their audit travel together, so no pair is ever split across train/test.
# ---------------------------------------------------------------------------
class DisjointSet:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def published_splits(splits_dir: Path) -> dict[str, str]:
    """The repo's split authority is `splits_v2`; the extension inherits it.

    A second, self-made assignment moves records between train and test behind the
    training corpus's back - which is exactly what the protected-evaluation leakage
    check catches. Inheriting keeps the new families comparable with family F.
    """
    mapping: dict[str, str] = {}
    for split in ("train", "validation", "test"):
        for rec in _load(splits_dir / f"{split}.jsonl"):
            if rec.get("_quarantined_from_split"):
                continue
            fid = (rec.get("finding") or {}).get("id")
            if fid:
                mapping.setdefault(fid, split)
    return mapping


def build_groups(corpus, negatives_by_id, findings_by_id, pointer_by_negative,
                 splits: dict[str, str]) -> dict:
    """Cluster each submission with its canonical finding and audit, then measure
    whether the published split ever puts a cluster on both sides of a boundary.

    Root-cause labels are deliberately NOT union nodes - the same RC id in two
    contests is not the same cluster, and linking them globally merges every record
    into one component.
    """
    ds = DisjointSet()
    for record in corpus:
        fid = record["finding_id"]
        ds.find(f"neg:{fid}")
        ds.union(f"neg:{fid}", "audit:" + (record.get("audit") or "unknown"))
        canonical = pointer_by_negative.get(fid)
        if canonical:
            ds.find(f"fin:{canonical}")
            ds.union(f"neg:{fid}", f"fin:{canonical}")
    for finding in findings_by_id.values():
        fid = (finding.get("finding") or {}).get("id")
        ds.find(f"fin:{fid}")
        ds.union(f"fin:{fid}", "audit:" + ((finding.get("source") or {}).get("repository")))

    members: dict[str, list[str]] = collections.defaultdict(list)
    for item in ds.parent:
        members[ds.find(item)].append(item)

    straddling = 0
    for items in members.values():
        seen = {splits[item.split(":", 1)[1]] for item in items
                if item.split(":", 1)[1] in splits}
        if len(seen) > 1:
            straddling += 1
    audits: dict[str, set[str]] = collections.defaultdict(set)
    for fid, split in splits.items():
        audits[fid.split("/")[0]].add(split)
    return {
        "clusters": len(members),
        "cluster_members": sum(len(v) for v in members.values()),
        "clusters_straddling_split": straddling,
        "audits": len(audits),
        "audits_straddling_split": sum(1 for v in audits.values() if len(v) > 1),
        "by_split_records": dict(collections.Counter(splits.values())),
        "largest_components": sorted((len(v) for v in members.values()), reverse=True)[:5],
    }


def stats_report(corpus, fa_rows, fb_stats, groups, blocked) -> dict:
    axes_supported = collections.Counter()
    for row in fa_rows:
        for axis, value in (row["answer_key"]["axes"]).items():
            if value == "supported":
                axes_supported[axis] += 1
    projects = collections.Counter()
    for record in corpus:
        projects[record.get("audit")] += 1
    corr = collections.Counter()
    for record in corpus:
        methods = (record.get("axes") or {}).get("duplicate_corroboration") or {}
        if methods.get("explicit_pointer"):
            corr["explicit_pointer"] += 1
        elif any(m.get("method") == "duplicate_of_issue_number_unresolved"
                 for m in (methods.get("methods") or [])):
            corr["pointer_names_an_unresolved_issue"] += 1
        else:
            corr["no_duplicate_pointer_at_all"] += 1
    fb_stats["corpus_pointer_evidence"] = dict(corr)
    fb_stats["corpus_records_with_no_positive_pair"] = (
        corr["pointer_names_an_unresolved_issue"] + corr["no_duplicate_pointer_at_all"])
    fb_stats["distinct_independent_projects"] = len(projects)
    # Per-axis coverage plus the trivial per-axis baseline. Axes 1, 4 and 5 are
    # evidence-given (a status is quoted, a pointer's resolution is mechanical, an
    # attempt status is recorded), so a model that copies them is not demonstrating
    # triage judgement; the baseline makes that visible instead of hiding it in an
    # overall accuracy number.
    per_axis = {}
    for axis in AXES:
        values = [row["answer_key"]["axes"][axis] for row in fa_rows
                  if axis in row["assessed_axes"]]
        if not values:
            per_axis[axis] = {"coverage": 0}
            continue
        supported = sum(1 for v in values if v == "supported")
        unknown = sum(1 for v in values if v == "unknown")
        per_axis[axis] = {
            "coverage": len(values),
            "supported_rate": round(supported / len(values), 4),
            "unknown_rate": round(unknown / len(values), 4),
            "majority_baseline_accuracy": round(
                max(supported, len(values) - supported - unknown, unknown) / len(values), 4),
            "evidence_given_in_packet": axis in (
                "rejection_status_publicly_reported",
                "claim_corroborated_as_duplicate_of_confirmed_finding",
                "exploit_attempted_and_claimed_violation_not_demonstrated"),
        }
    return {
        "schema_version": EXTENSION_VERSION,
        "definitions_version": DEFINITIONS_VERSION,
        "generated_by": "scripts/build_f_extension.py",
        "corpus_records": len(corpus),
        "fa": {
            "rows": len(fa_rows),
            "by_answer_key_status": dict(collections.Counter(
                r["answer_key_status"] for r in fa_rows)),
            "scorable_rows": sum(1 for r in fa_rows if r["answer_key_status"] == "labeled"),
            "axes_supported": dict(axes_supported),
            "assessability": {axis: sum(1 for r in fa_rows if axis in r["assessed_axes"])
                              for axis in AXES},
            "per_axis_metrics": per_axis,
            "technical_explanation_rows": sum(1 for r in fa_rows
                                              if r["answer_key"]["technical_explanation_axes"]),
            "by_split": dict(collections.Counter(r["split"] for r in fa_rows)),
            "unique_source_records": len({r["source"]["record_id"] for r in fa_rows}),
        },
        "fb": fb_stats,
        "blocking_counts": dict(blocked),
        "independent_projects_in_corpus": dict(projects),
        "split_grouping": {
            "method": ("inherits the published splits_v2 assignment; clusters are "
                       "submission + canonical finding + audit and are measured against "
                       "that assignment rather than re-derived"),
            "clusters": groups["clusters"],
            "cluster_members": groups["cluster_members"],
            "clusters_straddling_split": groups["clusters_straddling_split"],
            "audits": groups["audits"],
            "audits_straddling_split": groups["audits_straddling_split"],
            "by_split_records": groups["by_split_records"],
            "project_held_out_credible": groups["audits"] >= 10,
            "limitation": (
                f"{groups['audits']} audit projects exist in this corpus, so the split is "
                "project-disjoint (measured, not assumed) but a project-held-out split rests "
                "on a handful of projects and per-project metrics stay noisy"),
        },
        "non_additivity": ("axis totals overlap and are not additive; a record may support "
                           "several axes at once"),
    }


AXIS_DEFINITIONS = {
    "rejection_status_publicly_reported": (
        "the contest page publicly records a status for this submission; a fact about "
        "the contest record, not a reason the claim is false"),
    "reason_attributed_to_judge_or_sponsor": (
        "a named judge or the sponsor published a statement, carried verbatim with author, "
        "role and URL, that addresses this submission; split by rule into a technical "
        "refutation and a design-intent or scope exclusion"),
    "reason_supported_by_cited_code": (
        "a guard mechanically located on the function the submission says the attacker "
        "calls removes the standing the submission's own text claims; a gate elsewhere, "
        "or a claim about a privileged actor, is context only"),
    "claim_corroborated_as_duplicate_of_confirmed_finding": (
        "the same claim was accepted as a confirmed or acknowledged finding in the same "
        "audit, so the underlying issue is real and only this copy was redundant; never a "
        "technical explanation of falsity"),
    "exploit_attempted_and_claimed_violation_not_demonstrated": (
        "an exploit was reconstructed and executed against the pinned revision and the "
        "claimed violation was not observed; the only axis that can establish a false "
        "positive by experiment"),
    "unknown_or_insufficient_evidence": (
        "only a rejection, duplicate or dispute label is public, no attributed reason "
        "exists, no gate refutes the claim's own standing and no exploit was attempted; "
        "a valid answer, not a pipeline failure"),
}


def emit(dest: Path, fa_rows: list[dict], fb_rows: list[dict], stats: dict,
         manifest_previous: dict | None = None) -> dict[str, bytes]:
    """Write every artefact under `dest` and return the bytes that were written."""
    written: dict[str, bytes] = {}
    benchmark = dest / "benchmark"
    reports = dest / "reports"

    def capture(path: Path) -> None:
        written[path.relative_to(dest).as_posix()] = path.read_bytes()

    write_jsonl(benchmark / f"{FA_NAME}.jsonl", fa_rows)
    write_jsonl(benchmark / f"{FB_NAME}.jsonl", fb_rows)
    write_json(reports / "f_extension_stats.json", stats)
    capture(benchmark / f"{FA_NAME}.jsonl")
    capture(benchmark / f"{FB_NAME}.jsonl")
    capture(reports / "f_extension_stats.json")

    manifest_path = benchmark / "manifest.json"
    if manifest_previous is None:
        try:
            manifest_previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest_previous = {}
    manifest = json.loads(json.dumps(manifest_previous))
    manifest.setdefault("tasks", {})
    own = {FA_NAME, FB_NAME}
    for name, rows in ((FA_NAME, fa_rows), (FB_NAME, fb_rows)):
        statuses = collections.Counter(r["answer_key_status"] for r in rows)
        scorable = statuses.get("labeled", 0)
        manifest["tasks"][name] = {
            "file": f"benchmark/{name}.jsonl",
            "status": "headline",
            "tasks": len(rows),
            "labeled": scorable,
            "partial": statuses.get("partial", 0),
            "unlabeled": statuses.get("unlabeled", 0),
            "scorable": scorable,
            "unscorable": len(rows) - scorable,
            "answer_key_evidence_levels": dict(collections.Counter(
                r.get("answer_key_evidence_level") or "not_recorded" for r in rows)),
            "by_split": dict(collections.Counter(r["split"] for r in rows)),
            "duplicate_rows_dropped": 0,
            "scoring_status": "partial" if scorable < len(rows) else "scorable",
            "scoring_note": (
                "F-A scores a six-axis evidence vector with per-axis assessability; a row is "
                "scorable only when the packet carries the evidence for every axis. F-B scores "
                "same/distinct/ambiguous for a candidate-comparison pair with the triage "
                "outcome withheld from both sides; the ambiguous class is scorable because the "
                "insufficiency is itself established by the recorded evidence (no pointer, or "
                "a shared code target and nothing more), and such pairs are never counted as "
                "confirmed negatives."),
        }
    carry_foreign_task_entries(manifest, manifest_previous, own)
    write_json(manifest_path, manifest)
    capture(manifest_path)

    markdown = render_markdown(stats, manifest)
    md_path = reports / "f_extension.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8", newline="\n")
    capture(md_path)
    return written


def render_markdown(stats: dict, manifest: dict) -> str:
    fa, fb = stats["fa"], stats["fb"]
    lines = [
        "# VLUN F-extension: rejection evidence and duplicate radar",
        "",
        f"Built by `scripts/build_f_extension.py` at `{EXTENSION_VERSION}` from "
        f"{stats['corpus_records']} canonical rejection-corpus records.",
        "",
        "## F-A six-axis rejection evidence",
        "",
        f"- task rows: {fa['rows']} over {fa['unique_source_records']} distinct submissions",
        f"- scorable (every axis assessable): {fa['scorable_rows']}",
        f"- partial (some axes unassessable): {fa['by_answer_key_status'].get('partial', 0)}",
        f"- rows carrying a technical explanation of falsity: "
        f"{fa['technical_explanation_rows']}",
        f"- splits: {fa['by_split']}",
        "",
    ]
    lines += [
        "| axis | coverage | supported | unknown | majority baseline | evidence given in packet |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for axis in AXES:
        metrics = fa["per_axis_metrics"][axis]
        lines.append(
            f"| `{axis}` | {metrics.get('coverage', 0)} | "
            f"{metrics.get('supported_rate', 0):.3f} | {metrics.get('unknown_rate', 0):.3f} | "
            f"{metrics.get('majority_baseline_accuracy', 0):.3f} | "
            f"{'yes' if metrics.get('evidence_given_in_packet') else 'no'} |")
    lines += [
        "",
        "An axis whose evidence is given in the packet is answered by reading, not by "
        "triage: the majority baseline is published so a headline accuracy over these "
        "axes cannot be mistaken for judgement. The discriminating axes are the "
        "attributed-reason, code-supported and unknown axes, plus the field that says "
        "which supported axes are technical explanations of falsity.",
        "",
        "Axis totals overlap. They are not additive and must not be summed.",
        "",
        "## F-B pre-submission duplicate radar",
        "",
        f"- pairs: {fb['pair_rows']}",
        f"- confirmed duplicate pairs (published pointer resolves): "
        f"{fb['confirmed_duplicate_pairs']}",
        f"- rule-derived distinct pairs (disjoint targets AND a recorded root-cause "
        f"difference; no human adjudication): {fb['rule_derived_distinct_pairs']}",
        f"- ambiguous class: {fb['ambiguous_class_pairs']}",
        f"- label tiers: {fb['by_label_tier']}",
        f"- label cohorts: {fb['by_label_cohort']}",
        f"- pairs whose pointer does not resolve (unscorable): "
        f"{fb['ambiguous_unscorable_pairs']}",
        f"- unique candidate submissions: {fb['unique_candidate_submissions']}",
        f"- unique canonical findings: {fb['unique_canonical_findings']}",
        f"- by split: {fb['by_split']}",
        f"- pointer evidence across the corpus: {fb['corpus_pointer_evidence']}",
        f"- records that can yield no positive pair (no pointer, or a pointer to an "
        f"issue this dataset cannot resolve): "
        f"{fb['corpus_records_with_no_positive_pair']}",
        f"- blocked pair shapes: {stats['blocking_counts']}",
        "",
        "## Split integrity",
        "",
        f"The extension inherits the published `splits_v2` assignment. Clusters "
        f"(submission + its canonical finding + its audit) number "
        f"{stats['split_grouping']['clusters']} over "
        f"{stats['split_grouping']['cluster_members']} members; "
        f"{stats['split_grouping']['clusters_straddling_split']} clusters straddle a split "
        f"and {stats['split_grouping']['audits_straddling_split']} of "
        f"{stats['split_grouping']['audits']} audits do. Any F-B pair whose two sides would "
        f"land on different splits is dropped rather than shipped: "
        f"{fb['excluded_pairs'].get('pair_straddles_the_published_split', 0)} pairs so far.",
        "",
        f"Independent audit projects in the corpus: "
        f"{len(stats['independent_projects_in_corpus'])} "
        f"({', '.join(f'{k} {v}' for k, v in sorted(stats['independent_projects_in_corpus'].items()))}).",
        "",
        "## Limits",
        "",
        "- no independent human adjudication sample was collected for this extension, so no "
        "inter-annotator agreement is claimed anywhere in these numbers; the gold is the "
        "documented rule applied to public evidence, and the published floors are what a "
        "trivial predictor reaches on the same denominators,",
        "- F-A `observed_code_structure` is projected from `derived/hard_negatives.jsonl`; "
        "that layer rebuilds byte-identically (re-verified 2026-10-24: `python "
        "scripts/build_hard_negatives.py` reproduces the committed file exactly), so a "
        "change to it must be rebuilt into the F-A packets with "
        "`python scripts/build_f_extension.py`",
        "- the pool is drawn from public Code4rena contest records, so the underlying "
        "statuses are memorizable; this is an open-key evaluation, not a holdout,",
        "- with the projects available here a project-held-out split is not credible and "
        "is not claimed,",
        f"- manifest scorable counts: F-A {manifest['tasks'][FA_NAME]['scorable']}, "
        f"F-B {manifest['tasks'][FB_NAME]['scorable']}.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="regenerate into a temp tree and byte-compare; write nothing")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--splits", default="splits_v2",
                    help="split authority the extension inherits (record ids per split)")
    args = ap.parse_args()

    corpus = _load(CORPUS)
    if not corpus:
        log("no rejection corpus: F-extension skipped")
        return 2
    negatives = _load(NEGATIVES)
    findings = _load(FINDINGS)
    hard = _load(HARD_NEGATIVES)
    negatives_by_id = {(r.get("finding") or {}).get("id"): r for r in negatives}
    findings_by_id = {(r.get("finding") or {}).get("id"): r for r in findings}
    hard_by_id = {r["source_record"]["id"]: r for r in hard}

    splits = published_splits(ROOT / args.splits)
    fa_rows, fa_meta = build_fa_rows(corpus, negatives_by_id, hard_by_id, splits)
    (positives, distinct_pairs, ambiguous, pointer_by_negative,
     blocked) = build_fb_pairs(corpus, negatives_by_id, findings_by_id)
    groups = build_groups(corpus, negatives_by_id, findings_by_id, pointer_by_negative, splits)
    fb_rows, fb_stats, _ = build_fb_rows(positives, distinct_pairs, ambiguous,
                                        hard_by_id, splits)
    stats = stats_report(corpus, fa_rows, fb_stats, groups, dict(blocked))
    stats["fa"]["status_accounting"] = fa_meta["accounting"]
    stats["fa"]["per_axis_assessable_crosscheck"] = fa_meta["per_axis_assessable"]

    manifest_previous = None
    if args.check:
        dest = Path(tempfile.mkdtemp(prefix="vlun-fx-"))
        (dest / "benchmark").mkdir(parents=True, exist_ok=True)
        shutil.copy2(BENCH / "manifest.json", dest / "benchmark" / "manifest.json")
        manifest_previous = json.loads((BENCH / "manifest.json").read_text(encoding="utf-8"))
    else:
        dest = ROOT
        manifest_previous = None
    written = emit(dest, fa_rows, fb_rows, stats, manifest_previous)
    if args.check:
        drift = []
        for name, data in written.items():
            current = ROOT / name
            if not current.exists() or current.read_bytes() != data:
                drift.append(name)
        if drift:
            print("F-extension drift (rebuild with scripts/build_f_extension.py): "
                  + ", ".join(sorted(drift)))
            return 1
        print(f"F-extension current: {len(written)} artefacts byte-identical")
    elif not args.quiet:
        print(f"built F-A {len(fa_rows)} rows (scorable "
              f"{stats['fa']['scorable_rows']}), F-B {len(fb_rows)} pairs "
              f"(duplicate {fb_stats['confirmed_duplicate_pairs']}, distinct "
              f"{fb_stats['rule_derived_distinct_pairs']}, ambiguous "
              f"{fb_stats['ambiguous_class_pairs']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

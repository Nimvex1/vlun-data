#!/usr/bin/env python3
"""Build benchmark families K-Q: the v2.2 benchmark layer.

`scripts/build_benchmark.py` writes families A-J from the v1 layer and rewrites
`benchmark/manifest.json` from scratch, so this script must run *after* it and
merges its seven families into the manifest rather than replacing it. The gate
(`scripts/validate.py`, check `v2.2/benchmark_manifest_covers_every_family`)
fails if any family in `vlun.BENCHMARK_FAMILIES` is missing, so neither script
can be run alone and still ship.

Seven families, one task per v2.2 record (family M is emitted only for records
whose experiment actually ran):

    K  language/ecosystem routing      label: language + ecosystem
    L  severity reconciliation         label: severity + who published it
    M  experiment level classification label: L0-L6 level + outcome
    N  attacker identity extraction    label: identity + the source sentence
    O  record class and scope          label: record_class
    P  provenance tier and rights      label: tier, origin, licence, rights
    Q  evidence typing + quality rubric label: per-field evidence types, the
                                       record's strongest/weakest, and the
                                       published quality labels

Three rules make the result usable rather than decorative:

 1. tasks are drawn from splits_v2_2, whose v2.2 rows have already had
    cross-split duplicates quarantined, so a test task cannot be a reworded
    train task. A task's `split` is the split of the record it came from.
 2. the *model-facing payload is `input` only*. Task ids and `source` blocks
    carry the record id for traceability and must not be shown to a model: a
    record id carries its language prefix, which is family K's answer.
 3. a task is labelled only where an answer key genuinely exists in the record.
    Where it does not, the task is written with `answer_key_status:
    "partial"` or `"unlabeled"` plus a reason, and is excluded from the metrics.

Nothing here invents an answer: every answer key is copied out of
derived_v2_2/records.jsonl, jsonl_ml/ or experiments_v2_2/index.json, and the
prose a model is shown comes from the immutable jsonl_ml layer (the derived
record carries no summary), re-read through the pointer and verified against
its sha256.

    python scripts/build_benchmark_v22.py
    python scripts/build_benchmark_v22.py --check
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    ATTACKER_KINDS, BENCHMARK_FAMILIES, BENCH, DATASET_VERSION, RETIRED_FAMILIES, ROOT, SPLITS, log, read_jsonl, retired_manifest_entry, sha256_text, write_json, write_jsonl,
)
from vlun_ml import (  # noqa: E402
    DERIVED_V22, EXPERIMENTS_V22, FAMILY_LANGUAGES, ML_JSONL, SOURCE_TIERS,
    SPLITS_V22,
)

V22_FAMILIES = {k: v for k, v in BENCHMARK_FAMILIES.items() if v[1] == "v2.2"}

RECORD_CLASSES = (
    "advisory", "audit_finding", "incident", "judged", "negative_control",
    "observation", "out_of_scope", "overstated_by_the_report", "scope_risk",
    "vulnerability",
)

# How each record_class came to be recorded. This is what family O's
# answer-key evidence type is set from, and it is the ingest rule, not a guess:
# a publisher's own advisory/incident/post-mortem class is a reported claim, a
# judge's verdict is attributed to that judge, and the section-derived classes
# of the report layer are computed by scripts/build_ml_ingest.py.
CLASS_EVIDENCE = {
    "advisory": ("reported_claim",
                 "the publisher files this record as an advisory, so the class "
                 "is its own claim"),
    "incident": ("reported_claim",
                 "the class comes from a published incident write-up"),
    "vulnerability": ("reported_claim",
                      "the class is the registry's or publisher's own tagging of "
                      "a reported vulnerability"),
    "judged": ("externally_attributed",
               "the class is a named auditor's or judge's verdict on the finding"),
    "audit_finding": ("derived_fact",
                      "assigned by scripts/build_ml_ingest.classify() from the "
                      "report section the finding was parsed out of"),
    "observation": ("derived_fact", "assigned from the report's ADDITIONAL "
                                    "OBSERVATIONS section by the ingest rule"),
    "out_of_scope": ("derived_fact", "assigned from the report's OUT OF SCOPE "
                                     "section by the ingest rule"),
    "scope_risk": ("derived_fact", "assigned from the report's SCOPE-RISK "
                                   "section by the ingest rule"),
    "overstated_by_the_report": ("derived_fact",
                                 "assigned from the report's OVERSTATED section "
                                 "by the ingest rule"),
    "negative_control": ("derived_fact",
                         "assigned from the report's NEGATIVE CONTROL section by "
                         "the ingest rule"),
}

EVIDENCE_VOCABULARY = {
    "observed_fact": "read directly out of a retrieved artefact",
    "reported_claim": "stated by an identifiable external source (report, judge, "
                      "sponsor)",
    "derived_fact": "computed by this pipeline, rule stated in code",
    "experimentally_verified": "produced by actually compiling and running "
                               "something",
    "externally_attributed": "attributed to a named third party (judge, sponsor, "
                             "label)",
    "unverified": "asserted somewhere but not checked here",
    "unknown": "no defensible value available",
}

LADDER = (
    "experimentally_verified", "observed_fact", "derived_fact", "reported_claim",
    "externally_attributed", "unverified", "unknown",
)

# The rubric scripts/build_derived_v22.py applies, restated as rules so family Q
# grades the application of a published rubric rather than recall of the code.
QUALITY_RUBRIC = {
    "provenance": "high when every source is hashed and the best tier is 0 or 1; "
                  "medium when payloads are hashed or the best tier is 3 or "
                  "better; low otherwise; none when no source resolves",
    "code_context": "none when the record cites no code; medium when every "
                    "citation resolves and every line range is verified; low "
                    "when citations exist but do not all resolve or no line "
                    "range is verified",
    "verification": "experimentally_verified when an experiment is present and "
                    "all of its artefacts are on disk; incomplete when an "
                    "experiment is present but an artefact is missing; "
                    "reported_claim when any claim is typed reported_claim; "
                    "otherwise unverified",
    "attacker_model": "high when an identity is recorded, medium when an actor is "
                      "named without a standing, low otherwise",
    "taxonomy": "mapped when classes are present and the v1 vocabulary maps them; "
                "classes_present_unmapped when classes are present but do not "
                "map; no_classes when the publisher supplied no class",
    "licensing": "mixed when at least one licence is declared and at least one "
                 "source is not redistributable; declared when licences are "
                 "declared and all are redistributable; "
                 "unknown_not_redistributable when none is declared",
    "reasoning": "medium when a root cause or summary exists and the summary is "
                 "longer than 200 characters; otherwise low",
    "note": "each dimension is an ordinal label with a stated basis; no weighted "
            "aggregate is produced. The record also carries negative_reasoning "
            "and no_numerical_severity_score, but both are constant across this "
            "layer, so they are stated here rather than graded: every record has "
            "no negative reasoning and no numerical severity score.",
}

_PAYLOAD_HASH_RE = re.compile(r'"[a-z_]*sha256"\s*:\s*"[0-9a-f]{64}"', re.I)


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def _text(value) -> str:
    """A prose field is either a string or a claim dict; both are prose."""
    if isinstance(value, dict):
        return str(value.get("value") or "")
    return str(value or "")


def load_all() -> dict:
    derived = {r["id"]: r for r in read_jsonl(DERIVED_V22 / "records.jsonl")}
    findings = {}
    for path in sorted(ML_JSONL.glob("findings_*.jsonl")):
        for row in read_jsonl(path):
            findings[row["id"]] = row
    sources = {}
    for path in sorted(ML_JSONL.glob("sources_*.jsonl")):
        for row in read_jsonl(path):
            sources[row["source_id"]] = row

    pointers: dict[str, str] = {}
    for split in SPLITS:
        for p in read_jsonl(SPLITS_V22 / f"{split}.jsonl"):
            if p.get("layer") == "v2.2":
                pointers[p["id"]] = split

    runs = {}
    index = EXPERIMENTS_V22 / "index.json"
    if index.exists():
        doc = json.loads(index.read_text(encoding="utf-8"))
        for e in doc.get("experiments", []):
            runs[e.get("experiment_id")] = e
    return {"derived": derived, "findings": findings, "sources": sources,
            "pointers": pointers, "runs": runs}


def source_rows(bundle: dict, finding: dict) -> list[dict]:
    out = []
    for sid in finding.get("source_ids") or []:
        s = bundle["sources"].get(sid)
        if s is not None:
            out.append(s)
    return out


def has_payload_hash(source: dict) -> bool:
    return bool(_PAYLOAD_HASH_RE.search(json.dumps(source.get("retrieval") or {})))


def prose_view(finding: dict) -> dict:
    f = finding.get("finding") or {}
    return {"title": _text(f.get("title")),
            "summary": _text(f.get("summary")),
            "root_cause": _text(f.get("root_cause"))}


def base_task(key: str, split: str, rid: str, inp: dict, answer: dict,
              status: str, level: str, basis: str | None = None,
              reason: str | None = None) -> dict:
    name = BENCHMARK_FAMILIES[key][0]
    row = {
        "task": name,
        "split": split,
        "id": f"{key}::{split}::{rid}",
        "layer": "v2.2",
        "input": inp,
        "answer_key": answer,
        "answer_key_status": status,
        "unlabelled_reason": reason,
        "answer_key_evidence_level": level,
        "evidence_type": level,
        "source": {"record_id": rid, "finding_id": rid},
    }
    if basis:
        row["answer_key_basis"] = basis
    return row


# ---------------------------------------------------------------------------
# K - language and ecosystem routing
# ---------------------------------------------------------------------------

def task_k(split: str, bundle: dict, rec: dict, finding: dict) -> dict:
    rows = source_rows(bundle, finding)
    advisory_only = bool(rows) and all(
        s.get("evidence_origin") == "security_advisory" for s in rows)
    # A registry publishes the ecosystem of its own advisories, so language and
    # ecosystem are read out of a retrieved payload. Where a report or a
    # write-up is among the sources, the ingest assigned them from the code the
    # report cites, which is a rule this pipeline states rather than a fact a
    # publisher published.
    if advisory_only:
        level, basis = "observed_fact", (
            "every source of this record is a machine-read security advisory, so "
            "the ecosystem is published by the registry itself")
    else:
        level, basis = "derived_fact", (
            "at least one source is a report or write-up, so language and "
            "ecosystem are assigned by the ingest rule from the code it cites")
    inp = {
        "prose": prose_view(finding),
        "affected_components": list((finding.get("finding") or {})
                                    .get("affected_components") or []),
        # no source_id, no language, no ecosystem: the record id carries the
        # language prefix, so neither may appear in the payload.
        "sources": [{"title": s.get("title"), "url": s.get("url"),
                     "repository": s.get("repository"),
                     "published_at": s.get("published_at")} for s in rows],
        "prompt": "Which language and which ecosystem does this finding concern? "
                  "Answer {\"language\": ..., \"ecosystem\": ...} using the "
                  "dataset's own vocabulary.",
    }
    answer = {"language": rec["language"], "ecosystem": rec["ecosystem"]}
    return base_task("K", split, rec["id"], inp, answer, "labeled", level, basis)


# ---------------------------------------------------------------------------
# L - severity reconciliation
# ---------------------------------------------------------------------------

def task_l(split: str, bundle: dict, rec: dict, finding: dict) -> dict:
    rows = source_rows(bundle, finding)
    published = [{"source_id": s.get("source_id"), "title": s.get("title"),
                  "severity": (s.get("severity") or {}).get("value"),
                  "note": (s.get("severity") or {}).get("note")}
                 for s in rows]
    values = sorted({p["severity"] for p in published if p["severity"]})
    conflict = len(values) > 1
    f = rec["finding"]
    severity, attribution = f.get("severity"), f.get("severity_source")
    if not severity:
        status, reason = "unlabeled", (
            "no source publishes a severity for this record, so there is no "
            "rating to reconcile and none is invented here")
        level = "unknown"
    elif attribution:
        status, reason, level = "labeled", None, "reported_claim"
    else:
        status, reason, level = "partial", (
            "the rating is recorded but no source states where it came from, so "
            "the attribution half of this key cannot be graded"), "reported_claim"
    inp = {
        "prose": prose_view(finding),
        "published_severities": published,
        "prompt": "Consolidate what these publishers published. Answer "
                  "{\"severity\": ..., \"severity_source\": ..., "
                  "\"sources_in_conflict\": ...}. Where publishers disagree, "
                  "name the one the recorded attribution names; where none "
                  "publishes a rating, answer null rather than guessing.",
    }
    answer = {"severity": severity, "severity_source": attribution,
              "sources_in_conflict": conflict,
              "conflicting_values": values if conflict else []}
    basis = ("a severity is a published rating: the key is the value this "
             "dataset recorded and the attribution recorded with it, copied "
             "from the record")
    return base_task("L", split, rec["id"], inp, answer, status, level, basis,
                     reason)


# ---------------------------------------------------------------------------
# M - experiment level classification
# ---------------------------------------------------------------------------

def _stdout_tail(exp: dict, limit: int = 4000) -> str | None:
    rel = exp.get("stdout_artifact")
    if not rel:
        return None
    path = ROOT / rel
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > limit:
        return "..." + text[-limit:]
    return text


def task_m(split: str, bundle: dict, rec: dict, finding: dict) -> dict | None:
    exp = finding.get("experiment")
    if not exp:
        return None
    run = {k: exp.get(k) for k in (
        "command", "commit_sha", "executed", "exit_code", "experiment_ids",
        "fixed_revision_executed", "fixed_version", "match_kinds", "seconds",
        "tests_in_suite", "tests_observed", "toolchain", "verdict_met")}
    run["artefacts"] = [{"path": exp.get(k), "exists": (ROOT / exp[k]).exists()}
                        for k in ("result_artifact", "stdout_artifact",
                                  "stderr_artifact") if exp.get(k)]
    run["stdout_tail"] = _stdout_tail(exp)
    why = next((exp.get(k) for k in ("why_no_L6", "why_no_L5", "why_no_L4")
                if exp.get(k)), None)
    inp = {
        "prose": prose_view(finding),
        "run": run,
        "ladder": [
            "L0 a prose claim, no proof shape",
            "L1 a proof of concept quoted from a source",
            "L2 a proof of concept reconstructed by this pipeline",
            "L3 it compiles or is accepted by the compiler",
            "L4 it executes",
            "L5 it reproduces the claimed violation on the audited code",
            "L6 L5 on the vulnerable revision AND it stops on the fixed one",
        ],
        "prompt": "This run actually executed. Which level of the ladder does it "
                  "earn and what was the outcome? Answer {\"level\": ..., "
                  "\"outcome\": ..., \"evidence_type\": ..., "
                  "\"why_not_higher\": ...}.",
    }
    answer = {"level": exp.get("level"), "outcome": exp.get("outcome"),
              "evidence_type": "experimentally_verified",
              "why_not_higher": why}
    basis = ("the level is what this run earned under the ladder: L3-L6 are only "
             "reachable by an artefact that exists on disk, and the key is read "
             "from the record's own experiment block")
    return base_task("M", split, rec["id"], inp, answer, "labeled",
                     "experimentally_verified", basis)


# ---------------------------------------------------------------------------
# N - attacker identity extraction
# ---------------------------------------------------------------------------

def task_n(split: str, bundle: dict, rec: dict, finding: dict) -> dict:
    am = rec["attacker_model"]
    identity = am.get("identity") or "unknown"
    mentioned = bool(am.get("actor_mentioned"))
    if identity != "unknown":
        status, level, reason = "labeled", "reported_claim", None
    elif mentioned:
        status, level = "partial", "reported_claim"
        reason = ("a source sentence names an actor but never says whether it is "
                  "privileged, so the sentence can be graded and the standing "
                  "cannot")
    else:
        status, level, reason = "unlabeled", "unknown", (
            "no source sentence in this record names who acts; unknown is "
            "recorded rather than inferred")
    inp = {
        "prose": prose_view(finding),
        "attacker_vocabulary": list(ATTACKER_KINDS),
        "prompt": "Who does a source sentence say can act? Answer {\"identity\": "
                  "... (one of attacker_vocabulary, or unknown), "
                  "\"attributed_sentence\": <the exact sentence, or null>}. "
                  "Quote the sentence; do not paraphrase it.",
    }
    answer = {"identity": identity,
              "attributed_sentence": am.get("attributed_sentence"),
              "actor_mentioned": mentioned}
    basis = ("the sentence is quoted verbatim from the record's own prose, so a "
             "reader can check the attribution without trusting the classifier")
    return base_task("N", split, rec["id"], inp, answer, status, level, basis,
                     reason)


# ---------------------------------------------------------------------------
# O - record class and scope
# ---------------------------------------------------------------------------

def task_o(split: str, bundle: dict, rec: dict, finding: dict) -> dict:
    rows = source_rows(bundle, finding)
    f = rec["finding"]
    cls = f.get("record_class") or "unknown"
    level, basis = CLASS_EVIDENCE.get(cls, ("derived_fact",
                                            "assigned by the ingest rule"))
    inp = {
        "prose": prose_view(finding),
        "sources": [{"title": s.get("title"), "url": s.get("url"),
                     "published_at": s.get("published_at")} for s in rows],
        "affected_components": list(f.get("affected_components") or []),
        "class_vocabulary": list(RECORD_CLASSES),
        "prompt": "What kind of record is this? Answer {\"record_class\": ...} "
                  "using one value of class_vocabulary. A scope verdict that the "
                  "report itself prints is a report claim, not an inference.",
    }
    answer = {"record_class": cls}
    return base_task("O", split, rec["id"], inp, answer, "labeled", level, basis)


# ---------------------------------------------------------------------------
# P - provenance tier and redistribution rights
# ---------------------------------------------------------------------------

def task_p(split: str, bundle: dict, rec: dict, finding: dict) -> dict:
    rows = source_rows(bundle, finding)
    observed, answers = [], []
    for s in rows:
        lic = s.get("license") or {}
        observed.append({
            "source_id": s.get("source_id"),
            "title": s.get("title"),
            "url": s.get("url"),
            "published_at": s.get("published_at"),
            "verification_status": (s.get("verification") or {}).get("status"),
            "retrieval_method": (s.get("retrieval") or {}).get("method"),
            "payload_hash_present": has_payload_hash(s),
            "declared_licence_note": lic.get("note"),
        })
        answers.append({"source_id": s.get("source_id"),
                        "source_tier": s.get("source_tier"),
                        "evidence_origin": s.get("evidence_origin"),
                        "content_license": lic.get("content_license"),
                        "redistributable": lic.get("redistributable")})
    sv = rec["sources_view"]
    inp = {
        "sources": observed,
        "tier_rules": {str(k): v for k, v in SOURCE_TIERS.items()},
        "prompt": "Classify each source under the tier rules and state its "
                  "redistribution rights. Answer {\"sources\": [{\"source_id\": "
                  "... \"source_tier\": ..., \"evidence_origin\": ..., "
                  "\"content_license\": ..., \"redistributable\": ...}], "
                  "\"highest_authority_tier\": ..., "
                  "\"any_not_redistributable\": ...}. Where no licence is "
                  "declared, answer \"unknown\" and false.",
    }
    answer = {"sources": answers,
              "highest_authority_tier": sv.get("highest_authority_tier"),
              "tiers_present": sv.get("tiers_present"),
              "origins_present": sv.get("origins_present"),
              "any_not_redistributable": sv.get("any_not_redistributable")}
    basis = ("tier and origin are assigned by the admission rule in "
             "scripts/vlun_ml.py from what the source is; the licence is read "
             "from the source record's own declaration, and an undeclared "
             "licence stays unknown rather than being guessed")
    return base_task("P", split, rec["id"], inp, answer, "labeled",
                     "derived_fact", basis)


# ---------------------------------------------------------------------------
# Q - evidence typing and the quality rubric
# ---------------------------------------------------------------------------

def task_q(split: str, bundle: dict, rec: dict, finding: dict) -> dict:
    ev_blocks = {}
    for name, block in (finding.get("evidence") or {}).items():
        if isinstance(block, dict) and "evidence_type" in block:
            ev_blocks[name] = {"value": block.get("value"),
                               "note": block.get("note"),
                               "source_refs": block.get("source_refs")}
    sv, cc, exp, tax, att = (rec["sources_view"], rec["code_context_view"],
                             rec["experiment_view"], rec["taxonomy"],
                             rec["attacker_model"])
    summary = rec["evidence_summary"]
    counts = summary.get("counts") or {}
    inp = {
        "prose": prose_view(finding),
        "claims": ev_blocks,
        "observations": {
            "sources": {"count": sv.get("count"),
                        "tiers_present": sv.get("tiers_present"),
                        "all_payloads_hashed": bool(sv.get("count")) and all(
                            e.get("payload_hash_present")
                            for e in sv.get("entries") or []),
                        "declared_licences": sv.get("license_breakdown", {}).get("declared"),
                        "any_not_redistributable": sv.get("any_not_redistributable")},
            "code": {"citations": cc.get("citations"), "resolved": cc.get("resolved"),
                     "line_range_verified": cc.get("line_range_verified"),
                     "commit_pinned": cc.get("commit_pinned")},
            "experiment": {"present": exp.get("present"),
                           "artefacts_all_present": exp.get("artefacts_all_present")},
            "attacker": {"identity_recorded": att.get("identity") not in (None, "unknown"),
                         "actor_mentioned": att.get("actor_mentioned")},
            "taxonomy": {"classes": tax.get("classes"),
                         "mapped_to_v1": tax.get("mapped_to_v1_vocabulary")},
            "has_reported_claim": bool(counts.get("reported_claim")),
            "has_root_cause": bool(_text((finding.get("finding") or {})
                                         .get("root_cause")).strip()),
        },
        "evidence_ladder": list(LADDER),
        "evidence_vocabulary": dict(EVIDENCE_VOCABULARY),
        "quality_rubric": dict(QUALITY_RUBRIC),
        "prompt": "Type every claim under evidence_vocabulary, then rank the "
                  "record under evidence_ladder and apply quality_rubric to the "
                  "observations. Answer {\"field_evidence_types\": {...}, "
                  "\"strongest\": ..., \"weakest\": ..., \"quality\": "
                  "{\"provenance\": ..., \"code_context\": ..., "
                  "\"verification\": ..., \"attacker_model\": ..., "
                  "\"taxonomy\": ..., \"licensing\": ..., \"reasoning\": ...}}. "
                  "Produce no aggregate score.",
    }
    q = rec["quality"]
    answer = {
        "field_evidence_types": {name: block["evidence_type"]
                                 for name, block in
                                 (finding.get("evidence") or {}).items()
                                 if isinstance(block, dict)
                                 and "evidence_type" in block},
        "strongest": summary.get("strongest"),
        "weakest": summary.get("weakest"),
        "quality": {k: q.get(k) for k in (
            "provenance", "code_context", "verification", "attacker_model",
            "taxonomy", "licensing", "reasoning")},
    }
    basis = ("both halves are rule application: the evidence types are the "
             "closed vocabulary applied to each claim, and the quality labels "
             "are the published rubric applied to the observations; the key "
             "grades the seven varying dimensions, since negative_reasoning and "
             "no_numerical_severity_score are constant across the layer")
    return base_task("Q", split, rec["id"], inp, answer, "labeled",
                     "derived_fact", basis)


BUILDERS = {"K": task_k, "L": task_l, "M": task_m, "N": task_n, "O": task_o,
            "P": task_p, "Q": task_q}


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def build() -> tuple[dict[str, list[dict]], dict]:
    bundle = load_all()
    derived, findings, pointers = (bundle["derived"], bundle["findings"],
                                   bundle["pointers"])

    problems = []
    for rid in pointers:
        if rid not in derived:
            problems.append(f"{rid}: split pointer has no derived_v2_2 record")
        if rid not in findings:
            problems.append(f"{rid}: split pointer has no jsonl_ml record")
    for rid, rec in derived.items():
        if rid not in pointers:
            problems.append(f"{rid}: derived record is in no split")
        elif sha256_text(json.dumps(rec, sort_keys=True, ensure_ascii=False)) != \
                next((p["record_sha256"] for p in
                      read_jsonl(SPLITS_V22 / f"{pointers[rid]}.jsonl")
                      if p["id"] == rid and p.get("layer") == "v2.2"), None):
            problems.append(f"{rid}: record sha256 does not match its split pointer")

    tasks: dict[str, list[dict]] = {k: [] for k in V22_FAMILIES}
    if not problems:
        for split in SPLITS:
            for p in read_jsonl(SPLITS_V22 / f"{split}.jsonl"):
                if p.get("layer") != "v2.2" or p.get("split") != split:
                    continue
                rid = p["id"]
                rec, finding = derived[rid], findings[rid]
                for key, build_one in BUILDERS.items():
                    row = build_one(split, bundle, rec, finding)
                    if row is not None:
                        tasks[key].append(row)
    return tasks, {"problems": problems, "pointers": len(pointers),
                   "derived": len(derived)}


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

def manifest_entry(key: str, rows: list[dict]) -> dict:
    name = BENCHMARK_FAMILIES[key][0]
    st = collections.Counter(r["answer_key_status"] for r in rows)
    scorable = st.get("labeled", 0)
    entry = {
        "file": f"benchmark/{name}.jsonl",
        "status": "headline",
        "layer": "v2.2",
        "question": BENCHMARK_FAMILIES[key][2],
        "tasks": len(rows),
        "labeled": st.get("labeled", 0),
        "partial": st.get("partial", 0),
        "unlabeled": st.get("unlabeled", 0),
        "scorable": scorable,
        "unscorable": len(rows) - scorable,
        "answer_key_evidence_levels": dict(collections.Counter(
            r.get("answer_key_evidence_level") or "not_recorded" for r in rows)),
        "by_split": dict(collections.Counter(r["split"] for r in rows)),
        "by_language": dict(collections.Counter(
            r["source"]["record_id"].split(":", 1)[0] for r in rows)),
        "languages_allowed": list(FAMILY_LANGUAGES.get(key, [])),
        "duplicate_rows_dropped": 0,
    }
    if name == "Q_evidence_type_and_quality_rubric":
        entry["scoring_status"] = "descriptive/non-scorable"
        entry["scoring_note"] = "judge-graded rubric dict (partial credit by definition)"
    return entry


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="build and validate, write nothing")
    args = ap.parse_args()

    tasks, info = build()
    if info["problems"]:
        for p in info["problems"]:
            log(f"  PROBLEM {p}")
        log(f"refusing to write benchmark K-Q: {len(info['problems'])} problem(s)")
        return 1

    manifest_path = BENCH / "manifest.json"
    if not manifest_path.exists():
        log("benchmark/manifest.json does not exist: run scripts/build_benchmark.py "
            "first, which owns families A-J and writes the manifest this script "
            "merges into")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = [BENCHMARK_FAMILIES[k][0] for k in BENCHMARK_FAMILIES
               if BENCHMARK_FAMILIES[k][1] == "v1"
               and BENCHMARK_FAMILIES[k][0] not in manifest.get("tasks", {})]
    if missing:
        log(f"manifest is missing families {missing}: run scripts/build_benchmark.py first")
        return 1

    BENCH.mkdir(parents=True, exist_ok=True)
    for key in V22_FAMILIES:
        if f"{BENCHMARK_FAMILIES[key][0]}.jsonl" in RETIRED_FAMILIES:
            # Frozen under benchmark/retired_families/; carry the manifest
            # entry, rebuild no rows.
            carried = retired_manifest_entry(manifest, BENCHMARK_FAMILIES[key][0])
            if carried is not None:
                carried["status"] = "retired"
                manifest["tasks"][BENCHMARK_FAMILIES[key][0]] = carried
                log(f"  {BENCHMARK_FAMILIES[key][0]:34s} retired, entry carried")
            else:
                raise SystemExit(
                    f"retired family {BENCHMARK_FAMILIES[key][0]} has no "
                    "manifest entry to carry and its rows are not rebuilt by "
                    "design: the retirement bookkeeping was lost upstream "
                    "(an A-J pass rewrote benchmark/manifest.json without "
                    "carrying foreign entries). Restore the committed "
                    "manifest instead of dropping the entry.")
            continue
        rows = tasks[key]
        seen, uniq, dropped = set(), [], 0
        for r in rows:
            if r["id"] in seen:
                dropped += 1
                continue
            seen.add(r["id"])
            uniq.append(r)
        entry = manifest_entry(key, uniq)
        entry["duplicate_rows_dropped"] = dropped
        manifest["tasks"][BENCHMARK_FAMILIES[key][0]] = entry
        if not args.check:
            write_jsonl(BENCH / f"{BENCHMARK_FAMILIES[key][0]}.jsonl", uniq)
        log(f"  {BENCHMARK_FAMILIES[key][0]:34s} tasks={entry['tasks']:4d} "
            f"labeled={entry['labeled']:4d} partial={entry['partial']:4d} "
            f"unlabeled={entry['unlabeled']:4d} "
            f"splits={entry['by_split']}")

    manifest["dataset_version"] = DATASET_VERSION
    manifest["splits_source_v2_2"] = "splits_v2_2"
    manifest["generated_by"] = ("scripts/build_benchmark.py (families A-J) + "
                                "scripts/build_benchmark_v22.py (families K-Q)")
    manifest["families"] = sorted(manifest["tasks"])
    manifest["notes"] = {
        "model_facing_payload": "the `input` object of each task; task ids and "
                                "`source` blocks carry the record id for "
                                "traceability and a record id carries its "
                                "language prefix, which is family K's answer",
        "v2_2_layer": "families K-Q are built from derived_v2_2/records.jsonl "
                      "over splits_v2_2, so a task's split is the split of its "
                      "record; A-J keep the v1 assignment unchanged",
        "unlabelled": "a task whose answer key does not exist in the record is "
                      "written with answer_key_status partial or unlabeled and a "
                      "reason, and is excluded from every metric",
    }
    log(f"manifest families: {len(manifest['tasks'])} "
        f"({manifest['families'][0]}..{manifest['families'][-1]})")

    if args.check:
        log("--check: everything built, nothing written")
        return 0
    write_json(manifest_path, manifest)
    log(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

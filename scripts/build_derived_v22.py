#!/usr/bin/env python3
"""Build derived_v2_2/records.jsonl: the derived layer over the multi-language
ML records.

`jsonl/` is the immutable v1 evidence and `jsonl_ml/` is the immutable v2.2
source layer; neither is written by this script. Every derived record here
points back at its source row by file, id and sha256, and adds only what a
pipeline can establish from the records plus what is actually on disk:

    evidence_summary       which evidence types the record carries, and the
                           strongest/weakest of them under a stated ladder
    sources_view           the registry(s) behind the record: tier, origin,
                           licence, retrieval, payload hashes
    code_context_view      citation resolution, line ranges, commit pinning
    experiment_view        the recorded experiment and whether its artefacts
                           still exist as named (checked against the disk,
                           never taken from the record's word)
    taxonomy               v1 taxonomy lookup plus how each class string is
                           shaped (CWE id, C4 string, report label)
    attacker_model         reported only when a source sentence says so, and
                           then the sentence is quoted; otherwise unknown
    state_transition       not asserted: no source in this layer publishes an
                           attack sequence as structured data
    quality                per-dimension ordinal labels with their basis; no
                           aggregate score

    python scripts/build_derived_v22.py
    python scripts/build_derived_v22.py --check
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_derived as bd  # noqa: E402
import taxonomy as tx  # noqa: E402
from vlun import DATASET_VERSION, ROOT, log, sha256_text, write_json, write_jsonl  # noqa: E402
from vlun_ml import DERIVED_V22, EXPERIMENTS_V22, ML_JSONL  # noqa: E402

# The ladder a record's evidence is read against, strongest first. The order is
# a convention of this dataset, stated so a reader can disagree with it
# explicitly rather than guess at it.
LADDER = (
    "experimentally_verified",
    "observed_fact",
    "derived_fact",
    "reported_claim",
    "externally_attributed",
    "unverified",
    "unknown",
)

CWE_RE = re.compile(r"^CWE-\d+$", re.I)
C4_RE = re.compile(r"^(?:[A-Z][\w&/ -]+/)+")


def load_layer() -> tuple[list[dict], dict[str, dict]]:
    findings, sources = [], {}
    for path in sorted(ML_JSONL.glob("findings_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                findings.append(json.loads(line))
    for path in sorted(ML_JSONL.glob("sources_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                sources[row["source_id"]] = row
    return findings, sources


def load_runs() -> dict[str, dict]:
    index = EXPERIMENTS_V22 / "index.json"
    if not index.exists():
        return {}
    try:
        data = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {e["experiment_id"]: e for e in data.get("experiments", [])}


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------

def evidence_summary(ev: dict) -> dict:
    counts = collections.Counter()
    for value in (ev or {}).values():
        if isinstance(value, dict) and "evidence_type" in value:
            counts[value["evidence_type"]] += 1
    present = [t for t in LADDER if counts.get(t)]
    return {
        "fields": sum(counts.values()),
        "counts": dict(counts),
        "types_present": present,
        "strongest": present[0] if present else None,
        "weakest": present[-1] if present else None,
        "ladder": list(LADDER),
        "ladder_note": "the ladder is this dataset's convention for summarising "
                       "a record in one word; every field keeps its own type",
    }


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------

def sources_view(finding: dict, registry: dict[str, dict]) -> dict:
    entries, missing = [], []
    for sid in finding.get("source_ids") or []:
        src = registry.get(sid)
        if src is None:
            missing.append(sid)
            continue
        lic = src.get("license") or {}
        entries.append({
            "source_id": sid,
            "title": src.get("title"),
            "source_tier": src.get("source_tier"),
            "evidence_origin": src.get("evidence_origin"),
            "url": src.get("url"),
            "repository": src.get("repository"),
            "published_at": src.get("published_at"),
            "verification_status": (src.get("verification") or {}).get("status"),
            "content_license": lic.get("content_license"),
            "redistributable": lic.get("redistributable"),
            "payload_hash_present": _has_payload_hash(src),
        })
    tiers = sorted({e["source_tier"] for e in entries
                    if e["source_tier"] is not None})
    origins = sorted({e["evidence_origin"] for e in entries if e["evidence_origin"]})
    licenses = sorted({e["content_license"] or "unknown" for e in entries})
    declared = sum(1 for e in entries
                   if (e["content_license"] or "unknown") != "unknown")
    return {
        "count": len(entries),
        "entries": entries,
        "missing_source_ids": missing,
        "tiers_present": tiers,
        "origins_present": origins,
        "highest_authority_tier": tiers[0] if tiers else None,
        "content_licenses": licenses,
        "license_breakdown": {
            "declared": declared,
            "unknown": len(entries) - declared,
            "redistributable_true": sum(1 for e in entries
                                        if e["redistributable"] is True),
            "redistributable_false": sum(1 for e in entries
                                         if e["redistributable"] is False),
            "redistributable_unspecified": sum(1 for e in entries
                                               if e["redistributable"] is None),
        },
        "any_not_redistributable": any(e["redistributable"] is False
                                       for e in entries),
        "note": "tier and origin are as published by the registry; a tier 4 "
                "source never carries a severity in this dataset",
    }


def _has_payload_hash(src: dict) -> bool:
    blob = json.dumps(src.get("retrieval") or {})
    return bool(re.search(r'"[a-z_]*sha256"\s*:\s*"[0-9a-f]{64}"', blob, re.I))


# ---------------------------------------------------------------------------
# code context
# ---------------------------------------------------------------------------

def code_context_view(finding: dict) -> dict:
    ctx = finding.get("code_context") or []
    resolutions = collections.Counter(c.get("resolution") for c in ctx)
    langs = collections.Counter(c.get("language") for c in ctx)
    commit_pinned = [c for c in ctx if c.get("commit_sha")]
    verified = [c for c in ctx if c.get("line_range_verified")]
    resolved = [c for c in ctx if c.get("resolved_path")]
    offchain = (finding.get("provenance") or {}).get("offchain_citations") or []
    if not ctx:
        note = ("this record cites no code location; the claim comes from a "
                "registry entry rather than from a cited file")
    elif not commit_pinned:
        note = ("no citation carries a commit pin: the paths and lines are "
                "recorded as published, and a commit was never guessed")
    elif len(commit_pinned) == len(ctx):
        note = "every citation carries a commit pin"
    else:
        note = (f"{len(commit_pinned)} of {len(ctx)} citations carry a commit "
                "pin; the rest are path-and-line only")
    return {
        "citations": len(ctx),
        "resolved": len(resolved),
        "resolution": {str(k): v for k, v in sorted(resolutions.items(),
                                                    key=lambda kv: str(kv[0]))},
        "languages": {str(k): v for k, v in sorted(langs.items())},
        "line_range_verified": len(verified),
        "commit_pinned": len(commit_pinned),
        "commit_note": "commit_sha is a 40-hex sha or null; it is never guessed",
        "external_dependencies": sum(1 for c in ctx
                                     if c.get("resolution") == "external_dependency"),
        "offchain_citations": len(offchain),
        "note": note,
    }


# ---------------------------------------------------------------------------
# experiment
# ---------------------------------------------------------------------------

def _artefact(rel: str) -> dict:
    path = ROOT / rel
    info = {"path": rel, "exists": path.exists()}
    if path.exists():
        info["bytes"] = path.stat().st_size
        info["sha256"] = sha256_text(path.read_text(encoding="utf-8",
                                                    errors="replace"))
    return info


def experiment_view(finding: dict) -> dict:
    exp = finding.get("experiment")
    if not exp:
        return {
            "present": False,
            "executed": False,
            "level": None,
            "outcome": None,
            "artefacts": [],
            "artefacts_all_present": None,
            "evidence_type": "unknown",
            "note": "no experiment was recorded for this finding; its evidence "
                    "stays a published claim",
        }
    artefacts = [_artefact(exp[k]) for k in
                 ("result_artifact", "stdout_artifact", "stderr_artifact")
                 if exp.get(k)]
    status = finding.get("finding", {}).get("status")
    return {
        "present": True,
        "executed": bool(exp.get("executed")),
        "level": exp.get("level"),
        "outcome": exp.get("outcome"),
        "outcome_basis": exp.get("outcome_basis"),
        "experiment_ids": exp.get("experiment_ids") or [],
        "fixed_revision_executed": bool(exp.get("fixed_revision_executed")),
        "why_not_higher": exp.get("why_no_L6") or exp.get("why_no_L5")
                          or exp.get("why_no_L4"),
        "artefacts": artefacts,
        "artefacts_all_present": bool(artefacts) and all(a["exists"]
                                                         for a in artefacts),
        "finding_status": status,
        "evidence_type": "experimentally_verified"
                         if status == "experimentally_verified" else "unknown",
    }


# ---------------------------------------------------------------------------
# taxonomy
# ---------------------------------------------------------------------------

def class_kind(value: str) -> str:
    if CWE_RE.match(value.strip()):
        return "cwe"
    if "/" in value and C4_RE.match(value.strip()):
        return "c4"
    if re.match(r"^[A-Z]{2}\d+", value.strip()):
        return "report_label"
    return "free_text"


def taxonomy_view(finding: dict) -> dict:
    f = finding.get("finding") or {}
    classes = f.get("vulnerability_classes") or []
    kinds = collections.Counter(class_kind(c) for c in classes)
    lookup = tx.classify({"vulnerability_classes": classes})
    if not classes:
        note = ("this finding carries no vulnerability class from its "
                "publisher: its record_class holds the judge's verdict "
                f"({f.get('record_class') or 'none'}) and nothing is "
                "substituted for a missing class")
    else:
        note = lookup.get("note")
    v1_lookup = {k: lookup.get(k) for k in
                 ("category", "family", "class", "subtype", "evidence_type")}
    # Pointer follows the taxonomy table only when the lookup derived one;
    # unknown lookups stay ref-less like their source (scripts/taxonomy.py).
    if lookup.get("source_refs"):
        v1_lookup["source_refs"] = list(lookup["source_refs"])
    return {
        "classes": list(classes),
        "class_kinds": dict(kinds),
        "class_kinds_note": "cwe ids come from the advisory, c4 strings from "
                            "the v1/Code4rena vocabulary, report_label from a "
                            "report's own id scheme, free_text from a "
                            "publisher that publishes no scheme",
        "primary_class": classes[0] if classes else None,
        "v1_lookup": v1_lookup,
        "mapped_to_v1_vocabulary": bool(classes) and lookup.get("category") != "Unknown",
        "note": note,
        "policy": "class strings are preserved verbatim; the v1 taxonomy is "
                  "consulted, never used to overwrite a publisher's wording",
    }


# ---------------------------------------------------------------------------
# attacker model
# ---------------------------------------------------------------------------

ACTOR_MENTION_RE = re.compile(
    r"\b(attacker|attacker-chosen|attacker-controlled|malicious (?:actor|user|caller|"
    r"third party|address|contract|token|oracle)|unauthori[sz]ed (?:user|caller|actor)|"
    r"any (?:user|caller|third party)|compromised)\b", re.I)


def attacker_view(finding: dict) -> dict:
    f = finding.get("finding") or {}
    text = " ".join(str(f.get(k) or "") for k in ("title", "summary",
                                                  "root_cause"))
    sentences = [s for s in bd.SENTENCE_RE.split(text) if s.strip()]
    kind, sentence = bd.reported_attacker_kind(sentences)
    unprivileged = bool(bd.UNPRIVILEGED_ASSERTION.search(text))

    mentioned, mention_sentence = False, None
    for s in sentences:
        if ACTOR_MENTION_RE.search(s or ""):
            mentioned = True
            mention_sentence = " ".join((s or "").split())[:400]
            break
    else:
        m = ACTOR_MENTION_RE.search(text)
        if m:
            mentioned = True
            mention_sentence = " ".join(text[max(0, m.start() - 120):
                                             m.end() + 200].split())[:400]

    view = {
        "identity": kind or "unknown",
        "actor_mentioned": mentioned,
        "attributed_sentence": sentence or mention_sentence,
        "unprivileged_claimed_in_prose": unprivileged,
        "vocabulary": list(bd.ATTACKER_KINDS),
    }
    if kind:
        view.update({
            "evidence_type": "reported_claim",
            "basis": "a source sentence states the actor's standing, so the "
                     "kind is a reported claim and the sentence is quoted",
        })
    elif mentioned:
        view.update({
            "evidence_type": "reported_claim",
            "basis": "the source names an actor but never says whether it is "
                     "privileged, so the actor is reported and the kind stays "
                     "unknown",
            "note": "identity is the privilege question, not the existence "
                    "question; answering it here would be inference",
        })
    else:
        view.update({
            "evidence_type": "unknown",
            "basis": "no source sentence in this record names who acts",
            "note": "unknown is recorded rather than inferred: an absent "
                    "statement about the actor is not evidence that anyone "
                    "may act",
        })
    return view


# ---------------------------------------------------------------------------
# state transition
# ---------------------------------------------------------------------------

def state_transition_view(finding: dict) -> dict:
    return {
        "present": False,
        "evidence_type": "unknown",
        "steps": [],
        "reason": "no source in this layer publishes an attack sequence as "
                  "structured data: the records carry prose summaries and, "
                  "where a PoC ran, the run itself. Steps are never generated "
                  "from prose",
        "poc_pointer": bool(finding.get("experiment")),
    }


# ---------------------------------------------------------------------------
# quality
# ---------------------------------------------------------------------------

def quality_view(ev: dict, src: dict, cc: dict, exp: dict, tax: dict,
                 att: dict) -> dict:
    payload_ok = bool(src["entries"]) and all(e["payload_hash_present"]
                                              for e in src["entries"])
    tier = src["highest_authority_tier"]
    if src["count"] == 0:
        provenance, prov_basis = "none", {"reason": "no source record resolves"}
    elif tier is not None and tier <= 1 and payload_ok:
        provenance = "high"
        prov_basis = {"tier": tier, "payloads_hashed": True}
    elif payload_ok or (tier is not None and tier <= 3):
        provenance = "medium"
        prov_basis = {"tier": tier, "payloads_hashed": payload_ok}
    else:
        provenance = "low"
        prov_basis = {"tier": tier, "payloads_hashed": payload_ok}

    if cc["citations"] and cc["resolved"] == cc["citations"]:
        code = "medium" if cc["line_range_verified"] else "low"
    elif cc["citations"]:
        code = "low"
    else:
        code = "none"

    if exp["present"] and exp["artefacts_all_present"]:
        verification = "experimentally_verified"
    elif exp["present"]:
        verification = "incomplete"
    elif (ev.get("counts") or {}).get("reported_claim"):
        verification = "reported_claim"
    else:
        verification = "unverified"

    return {
        "provenance": provenance,
        "provenance_basis": prov_basis,
        "code_context": code,
        "code_context_basis": {"citations": cc["citations"],
                               "resolved": cc["resolved"],
                               "line_range_verified": cc["line_range_verified"],
                               "commit_pinned": cc["commit_pinned"]},
        "verification": verification,
        "verification_basis": {"experiment_present": exp["present"],
                               "artefacts_all_present": exp["artefacts_all_present"]},
        "taxonomy": "mapped" if tax["mapped_to_v1_vocabulary"] else
                    ("classes_present_unmapped" if tax["classes"] else "no_classes"),
        "attacker_model": ("high" if att.get("identity") != "unknown" else
                           ("medium" if att.get("actor_mentioned") else "low")),
        "attacker_model_basis": {"identity": att.get("identity"),
                                 "actor_mentioned": att.get("actor_mentioned")},
        "licensing": ("mixed" if (src["license_breakdown"]["declared"]
                                  and src["any_not_redistributable"])
                      else ("declared" if src["license_breakdown"]["declared"]
                            else "unknown_not_redistributable")),
        "licensing_basis": src["license_breakdown"],
        "reasoning": "low",
        "negative_reasoning": "none",
        "no_numerical_severity_score": True,
        "scoring_note": "each dimension is an ordinal label with a stated "
                        "basis; no weighted aggregate is produced",
    }


# ---------------------------------------------------------------------------
# record assembly
# ---------------------------------------------------------------------------

def build_record(finding: dict, registry: dict[str, dict]) -> dict:
    row_json = json.dumps(finding, sort_keys=True, ensure_ascii=False)
    ev = evidence_summary(finding.get("evidence") or {})
    src = sources_view(finding, registry)
    cc = code_context_view(finding)
    exp = experiment_view(finding)
    tax = taxonomy_view(finding)
    att = attacker_view(finding)
    st = state_transition_view(finding)
    f = finding.get("finding") or {}

    quality = quality_view(ev, src, cc, exp, tax, att)
    quality["reasoning"] = "medium" if (f.get("root_cause") or f.get("summary")) \
        and len(str(f.get("summary") or "")) > 200 else "low"

    # Pointer the corroboration judgement at the analysis that produced it
    # (hand-authored Zentory authorship reasoning in build_ml_ingest.py).
    # Unknown judgements stay ref-less: they claim nothing.
    corrob = finding.get("corroboration_independence")
    if isinstance(corrob, dict) and corrob.get("evidence_type") == "observed_fact":
        corrob = dict(corrob)
        corrob["source_refs"] = ["rule:build_ml_ingest.py"]

    return {
        "record_type": "derived_finding_v22",
        "dataset_version": DATASET_VERSION,
        "source_layer_version": "2.2",
        "id": finding.get("id"),
        "language": finding.get("language"),
        "ecosystem": finding.get("ecosystem"),
        "finding": {
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "severity_source": f.get("severity_source"),
            "record_class": f.get("record_class"),
            "status": f.get("status"),
            "vulnerability_classes": f.get("vulnerability_classes"),
            "affected_components": f.get("affected_components"),
            "affected_versions": f.get("affected_versions"),
            "patched_versions": f.get("patched_versions"),
        },
        "evidence_summary": ev,
        "sources_view": src,
        "code_context_view": cc,
        "experiment_view": exp,
        "taxonomy": tax,
        "attacker_model": att,
        "security_state_transition": st,
        "canonical_finding": finding.get("canonical_finding"),
        "duplicate_reports": finding.get("duplicate_reports") or [],
        "independent_confirmation_count":
            finding.get("independent_confirmation_count"),
        "corroboration_independence": corrob,
        "quality": quality,
        "original_pointer": {
            "layer": "jsonl_ml",
            "file": f"jsonl_ml/findings_{finding.get('language')}.jsonl"
                    if finding.get("language") != "solidity"
                    else "jsonl_ml/findings_reports.jsonl",
            "record_id": finding.get("id"),
            "record_sha256": sha256_text(row_json),
            "note": "pointer only: the source layer is immutable and is never "
                    "rewritten by this script",
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="build and validate, write nothing")
    args = ap.parse_args()

    findings, registry = load_layer()
    rows = [build_record(f, registry) for f in findings]

    problems = []
    for r in rows:
        if not r["id"]:
            problems.append("a record has no id")
        if r["original_pointer"]["file"].endswith(".jsonl"):
            src_file = ML_JSONL / Path(r["original_pointer"]["file"]).name
            if not src_file.exists():
                problems.append(f"{r['id']}: source file missing")
        if r["experiment_view"]["present"] and \
                not r["experiment_view"]["artefacts_all_present"]:
            problems.append(f"{r['id']}: an experiment artefact is missing on disk")
        if r["sources_view"]["missing_source_ids"]:
            problems.append(f"{r['id']}: unresolved source ids "
                            f"{r['sources_view']['missing_source_ids']}")
    if problems:
        for p in problems:
            log(f"  PROBLEM {p}")
        return 1

    manifest = {
        "generated_by": "scripts/build_derived_v22.py",
        "records": len(rows),
        "by_language": dict(collections.Counter(r["language"] for r in rows)),
        "by_status": dict(collections.Counter(
            r["finding"]["status"] or "unknown" for r in rows)),
        "by_record_class": dict(collections.Counter(
            r["finding"]["record_class"] or "none" for r in rows)),
        "evidence_strongest": dict(collections.Counter(
            (r["evidence_summary"]["strongest"] or "none") for r in rows)),
        "with_experiment": sum(1 for r in rows if r["experiment_view"]["present"]),
        "experiment_artefacts_all_present": sum(
            1 for r in rows if r["experiment_view"]["artefacts_all_present"]),
        "experiment_levels": dict(collections.Counter(
            (r["experiment_view"]["level"] or "none") for r in rows)),
        "code_citations": sum(r["code_context_view"]["citations"] for r in rows),
        "code_citations_resolved": sum(r["code_context_view"]["resolved"]
                                       for r in rows),
        "code_citations_commit_pinned": sum(
            r["code_context_view"]["commit_pinned"] for r in rows),
        "attacker_identity": dict(collections.Counter(
            r["attacker_model"]["identity"] for r in rows)),
        "actor_mentioned": sum(1 for r in rows
                               if r["attacker_model"]["actor_mentioned"]),
        "state_transition_present": sum(
            1 for r in rows if r["security_state_transition"]["present"]),
        "taxonomy_mapped": sum(
            1 for r in rows if r["taxonomy"]["mapped_to_v1_vocabulary"]),
        "canonical_groups": len({r["canonical_finding"]["value"] for r in rows
                                 if (r.get("canonical_finding") or {}).get("value")}),
        "not_redistributable": sum(
            1 for r in rows if r["sources_view"]["any_not_redistributable"]),
        "quality": {dim: dict(collections.Counter(
            str(r["quality"][dim]) for r in rows))
            for dim in ("provenance", "code_context", "verification",
                        "attacker_model", "taxonomy", "licensing",
                        "reasoning")},
        "problems": len(problems),
    }

    if args.check:
        log(f"--check: {len(rows)} records built, nothing written")
        for k, v in manifest.items():
            if k not in ("generated_by",):
                log(f"  {k}: {v}")
        return 0

    write_jsonl(DERIVED_V22 / "records.jsonl", rows)
    write_json(DERIVED_V22 / "manifest.json", manifest)
    log(f"wrote {DERIVED_V22 / 'records.jsonl'} ({len(rows)})")
    log(f"wrote {DERIVED_V22 / 'manifest.json'}")
    for k in ("by_language", "by_status", "with_experiment",
              "experiment_levels", "evidence_strongest", "attacker_identity"):
        log(f"  {k}: {manifest[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

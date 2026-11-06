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
                           never taken from the record's word), plus the
                           adjudicated level where an artefact-grounded
                           adjudication exists
    taxonomy               v1 taxonomy lookup plus how each class string is
                           shaped (CWE id, C4 string, report label)
    attacker_model         reported only when a source sentence says so, and
                           then the sentence is quoted; otherwise unknown
    state_transition       not asserted: no source in this layer publishes an
                           attack sequence as structured data
    quality                per-dimension ordinal labels with their basis; no
                           aggregate score

Adjudicated L5 levels
---------------------
`jsonl_ml/` is immutable, so the re-adjudication of the 35 records whose source
experiment claims L5 is committed separately in
`reports/v2_2/l5_adjudication.json` and applied here, in the derived view only.
That file is not prose: `scripts/build_v22_l5_adjudication.py` derives it,
deterministically, from the committed run artefacts in `experiments_v2_2/`
(`result.json` expectations and test lists, `stdout.txt` `[FAIL:]`, `[PASS]`
and `Logs:` lines), under the rule published in its own header:

    experiment_view.level              the adjudicated level (L5, or the
                                       demoted L4/L1)
    experiment_view.level_before       what the source experiment claimed (L5)
    experiment_view.adjudication_verdict  SUPPORTED / WEAK / UNSUPPORTED
    experiment_view.status_after       the adjudicated verification status
    experiment_view.verification_provisional  true only for WEAK
    experiment_view.l5_candidate       true for WEAK: L4 today, L5 candidate
    experiment_view.demoted_from_L5    true for UNSUPPORTED
    experiment_view.adjudication_reason / provisional_reason / demotion_reason
                                       the review's one-line basis, verbatim

Coverage is validated against the source layer, not the derived one: the
adjudication must name exactly the records whose source experiment says L5,
with the same experiment ids and only tests the run actually observed. A
mismatch fails the build instead of producing a quieter wrong count.

Level coherence, adjudicated or not
-----------------------------------
Only L5 and L6 earn a reproduction claim. So every built view passes through
`enforce_level_coherence`, and a view at L0-L4 -- or with no level at all --
has `outcome` and `evidence_type` restated (`reproduced` becomes
`executed_violation_not_demonstrated` where something ran and
`no_committed_observation` where nothing did; the experiment-derived evidence
type becomes `observed_fact`, or `reported_claim` at L0-L1), with the raw
values kept under `outcome_before_adjudication` /
`evidence_type_before_adjudication` and the restated observation pointing at the
run artefacts. `evidence_summary` counts the record's fields the same way, and
`--check` fails if any of the four published places still says reproduction.
This is not only an adjudication matter: a record the adjudication never
visits can carry `outcome: "reproduced"` at L3 with an artefact that declares
only `all_pass`, and publishing it unchanged is the same overclaim in a place
nobody looked.

`quality.verification` is a closed set, owned by scripts/schema_terms.py as
`QUALITY_VERIFICATION_STATES` (`experimentally_verified`,
`executed_not_demonstrated` -- artefacts on disk, level below L5 -- `incomplete`,
`reported_claim`, `unverified`); the builder refuses a bucket outside it and the
v2.2 gate re-checks every published record.

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
from schema_terms import QUALITY_VERIFICATION_STATES  # noqa: E402
from vlun import DATASET_VERSION, ROOT, log, sha256_text, write_json, write_jsonl  # noqa: E402
from vlun_ml import (  # noqa: E402
    DERIVED_V22, EXPERIMENTS_V22, ML_JSONL, REPORTS_V22,
)

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

# ---------------------------------------------------------------------------
# L5 adjudication
# ---------------------------------------------------------------------------

# The artefact-grounded re-adjudication of the records whose source experiment
# claims L5 is a committed adjudication file, not a rewrite of the source
# layer: `jsonl_ml/` keeps saying what the pipeline observed, and this derived
# layer records what the committed run bytes establish (see
# scripts/build_v22_l5_adjudication.py for how the file is derived).
ADJUDICATION = REPORTS_V22 / "l5_adjudication.json"
ADJUDICATION_SOURCE = "reports/v2_2/l5_adjudication.json"
ADJUDICATION_VERDICTS = ("SUPPORTED", "WEAK", "UNSUPPORTED")
ADJUDICATION_KEYS = ("record_id", "verdict", "level_before", "level_after",
                     "status_after", "provisional", "experiment_ids", "tests",
                     "reason", "evidence")
L5 = "L5"

# The level/provisional pair each verdict must declare. A supported claim stays
# at L5; a weak one drops to L4 and keeps its L5 candidacy visible; an
# unsupported one drops below L5 and may never be marked provisional.
ADJUDICATION_LEVELS = {
    "SUPPORTED": ("L5", False),
    "WEAK": ("L4", True),
}
UNSUPPORTED_LEVELS = ("L1", "L4")

# ---------------------------------------------------------------------------
# Level coherence: a record below L5 may never assert reproduction
# ---------------------------------------------------------------------------
# The adjudication demotes 30-odd records, but the claim it demotes is a claim
# about a LEVEL. `outcome: "reproduced"` and an evidence type of
# `experimentally_verified` are separate assertions the source row carries, and
# a record outside the adjudication's reach can state them at L3 with nothing
# but `all_pass` behind it (vyper:CVE-2024-24567). So the rule is stated once
# here and applied to EVERY built view, adjudicated or not: only L5 and L6 earn
# a reproduction claim, and anything below restates it exactly the way a
# demotion does, with the raw values kept under `*_before_adjudication`.
EXPERIMENTAL_LEVELS = ("L5", "L6")
REPRODUCTION_OUTCOMES = ("reproduced",)
# What a restated view says its run did. These are `experiment_view.outcome`
# strings, not quality buckets: the outcome describes the run, the bucket
# describes how the record is graded, and the two are different words.
OUTCOME_EXECUTED_NOT_DEMONSTRATED = "executed_violation_not_demonstrated"
OUTCOME_NO_COMMITTED_OBSERVATION = "no_committed_observation"
# The `quality.verification` bucket for an executed run whose committed bytes do
# not demonstrate the violation.
BUCKET_EXECUTED_NOT_DEMONSTRATED = "executed_not_demonstrated"
# At L2-L4 something was built or run, so a restated record still holds an
# observation; at L0, L1 or with no level at all nothing was observed.
OBSERVATION_LEVELS = ("L2", "L3", "L4")

# The closed set of `quality.verification` labels this layer may publish
# (single source: scripts/schema_terms.py, enforced by the v2.2 gate).
VERIFICATION_LABELS = QUALITY_VERIFICATION_STATES

# Import-time guard: every bucket quality_view() can emit must be in that
# closed set, so a new bucket here without a vocabulary entry fails at import
# rather than shipping a quality class no reader can look up.
_UNLISTED_BUCKETS = sorted({
    "experimentally_verified", BUCKET_EXECUTED_NOT_DEMONSTRATED, "incomplete",
    "reported_claim", "unverified"} - set(QUALITY_VERIFICATION_STATES))
if _UNLISTED_BUCKETS:
    raise ImportError(
        "build_derived_v22: quality.verification buckets "
        f"{_UNLISTED_BUCKETS} are not in schema_terms."
        "QUALITY_VERIFICATION_STATES")


def below_l5(level) -> bool:
    """True for every level that cannot carry an experimental reproduction claim.

    `None` -- an experiment recorded with no level at all -- is below L5: the
    ladder earns L5 by demonstrating a violation, and a record that never says
    which level it claims has demonstrated nothing.
    """
    return level not in EXPERIMENTAL_LEVELS


def restated_outcome(level) -> str:
    """The outcome a view below L5 publishes instead of a reproduction claim."""
    return (OUTCOME_EXECUTED_NOT_DEMONSTRATED if level in OBSERVATION_LEVELS
            else OUTCOME_NO_COMMITTED_OBSERVATION)


def restated_evidence_type(level) -> str:
    """The evidence type a restated claim takes: an observation, or a claim."""
    return "observed_fact" if level in OBSERVATION_LEVELS else "reported_claim"


def restate_below_l5(view: dict, note: str) -> dict:
    """Restate a view whose own level does not reach L5.

    One implementation, used both by an adjudication demotion and by the
    general gate in `enforce_level_coherence`, so the two cannot drift. Only a
    view that actually asserts reproduction is touched: `outcome` naming a
    reproduction, or an `evidence_type` of `experimentally_verified`. The raw
    values stay published under `outcome_before_adjudication` /
    `evidence_type_before_adjudication`, and the restated observation cites the
    run artefacts as its source, because an `observed_fact` with no pointer is
    rejected by the pointer gate.
    """
    if not below_l5(view.get("level")):
        return view
    if view.get("outcome") not in REPRODUCTION_OUTCOMES and \
            view.get("evidence_type") != "experimentally_verified":
        return view
    out = dict(view)
    level = out.get("level")
    if out.get("outcome") in REPRODUCTION_OUTCOMES:
        out["outcome_before_adjudication"] = out["outcome"]
        out["outcome"] = restated_outcome(level)
    if out.get("evidence_type") == "experimentally_verified":
        out["evidence_type_before_adjudication"] = out["evidence_type"]
        out["evidence_type"] = restated_evidence_type(level)
        # A restated fact must still point at the bytes it rests on: an
        # `observed_fact` with no source is rejected by the pointer gate, and
        # the run artefacts are exactly that source.
        out["source_refs"] = [a["path"] for a in out.get("artefacts") or []
                              if a.get("exists")]
    out["sub_l5_restatement"] = note
    return out


def enforce_level_coherence(view: dict) -> dict:
    """The general gate: no published view claims reproduction below L5.

    The adjudication overlay already does this for the records it governs; this
    closes the class for every other record the layer publishes, adjudicated or
    not, so a source row that says `reproduced` at L3 cannot reach the published
    layer unchanged. It never changes a `level`: lowering one is an evidentiary
    claim this script does not own, and the artefacts behind these records are
    not re-read here.
    """
    if not view.get("present"):
        return view
    note = (f"level {view.get('level') or 'none'} is below L5: the run's own "
            f"claim ({view.get('outcome')!r} / "
            f"{view.get('evidence_type')!r}) is restated exactly as it is for "
            "an adjudicated demotion, and the raw values are kept under "
            "*_before_adjudication")
    return restate_below_l5(view, note)


class AdjudicationError(ValueError):
    """The L5 adjudication is missing, malformed, or does not cover the L5
    claims in the source layer exactly."""


def load_adjudication(path: Path | None = None) -> dict[str, dict]:
    """Read and validate the committed L5 adjudication.

    Returns `record_id -> entry`. The file is the review's evidence: every
    entry must carry its verdict, the level before and after, the adjudicated
    status, its provisional flag, the experiment ids and tests it speaks about,
    a one-line reason and an artefact reference. Anything missing or internally
    inconsistent raises, so a malformed review cannot be applied silently.
    """
    path = Path(path) if path is not None else ADJUDICATION
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AdjudicationError(f"{path}: cannot read ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise AdjudicationError(f"{path}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict) or data.get("record_type") != "l5_adjudication":
        raise AdjudicationError(f"{path}: record_type is not 'l5_adjudication'")
    entries = data.get("adjudications")
    if not isinstance(entries, list) or not entries:
        raise AdjudicationError(f"{path}: 'adjudications' must be a non-empty list")
    expected = data.get("expected_records")
    if isinstance(expected, bool) or not isinstance(expected, int):
        raise AdjudicationError(f"{path}: 'expected_records' must be an integer")
    if len(entries) != expected:
        raise AdjudicationError(
            f"{path}: expected_records={expected} but {len(entries)} entries")

    out: dict[str, dict] = {}
    for i, e in enumerate(entries):
        where = f"{path}: adjudications[{i}]"
        if not isinstance(e, dict):
            raise AdjudicationError(f"{where} is not an object")
        missing = [k for k in ADJUDICATION_KEYS if k not in e]
        if missing:
            raise AdjudicationError(f"{where} is missing {missing}")
        rid = e["record_id"]
        if not isinstance(rid, str) or not rid.strip():
            raise AdjudicationError(f"{where}: record_id must be a non-empty string")
        if rid in out:
            raise AdjudicationError(f"{path}: duplicate record_id {rid!r}")
        verdict = e["verdict"]
        if verdict not in ADJUDICATION_VERDICTS:
            raise AdjudicationError(
                f"{where}: verdict {verdict!r} not in {list(ADJUDICATION_VERDICTS)}")
        if e["level_before"] != L5:
            raise AdjudicationError(f"{where}: level_before must be {L5}")
        if not isinstance(e["provisional"], bool):
            raise AdjudicationError(f"{where}: provisional must be a boolean")
        if verdict == "UNSUPPORTED":
            if e["level_after"] not in UNSUPPORTED_LEVELS:
                raise AdjudicationError(
                    f"{where}: an unsupported claim demotes to one of "
                    f"{list(UNSUPPORTED_LEVELS)}, got {e['level_after']!r}")
        else:
            want_level, want_provisional = ADJUDICATION_LEVELS[verdict]
            if e["level_after"] != want_level:
                raise AdjudicationError(
                    f"{where}: a {verdict} claim must end at {want_level}, "
                    f"got {e['level_after']!r}")
            if e["provisional"] is not want_provisional:
                raise AdjudicationError(
                    f"{where}: provisional must be {want_provisional} for "
                    f"{verdict}")
        if e["provisional"] is not (verdict == "WEAK"):
            raise AdjudicationError(
                f"{where}: only WEAK is provisional, got provisional="
                f"{e['provisional']} for {verdict}")
        for key in ("status_after", "reason", "evidence"):
            if not isinstance(e[key], str) or not e[key].strip():
                raise AdjudicationError(f"{where}: {key} must be a non-empty string")
        for key in ("experiment_ids", "tests"):
            if not isinstance(e[key], list) or \
                    not all(isinstance(x, str) and x for x in e[key]):
                raise AdjudicationError(
                    f"{where}: {key} must be a list of non-empty strings")
        if not e["experiment_ids"]:
            raise AdjudicationError(f"{where}: experiment_ids must not be empty")
        out[rid] = e

    declared = data.get("counts")
    if not isinstance(declared, dict):
        raise AdjudicationError(f"{path}: 'counts' must be an object")
    counts = collections.Counter(e["verdict"] for e in entries)
    if declared.get("L5_records") != len(entries):
        raise AdjudicationError(
            f"{path}: counts.L5_records={declared.get('L5_records')!r} but "
            f"{len(entries)} entries")
    for verdict in ADJUDICATION_VERDICTS:
        if declared.get(verdict) != counts.get(verdict, 0):
            raise AdjudicationError(
                f"{path}: counts.{verdict}={declared.get(verdict)!r} but "
                f"{counts.get(verdict, 0)} entries")
    return out


def _observed_names(exp: dict) -> set[str]:
    """Every test or PoC script name this run is recorded as having seen."""
    return {h.get(k) for h in exp.get("tests_observed") or []
            for k in ("test", "poc_file") if h.get(k)}


def check_adjudication(findings: list[dict],
                       adjudications: dict[str, dict]) -> None:
    """Fail unless the adjudication covers exactly the L5 claims in the layer.

    Coverage is measured against the SOURCE experiment level, so a rebuild is
    idempotent: the source keeps claiming L5, the adjudication keeps governing
    those same ids, and the derived view changes instead. Each entry is also
    tied to its run: the experiment ids must be the record's and every test it
    names must be one the record observed. An adjudication about some other
    record, or about a test nobody ran, is refused rather than applied.
    """
    source_l5 = {f.get("id") for f in findings
                 if (f.get("experiment") or {}).get("level") == L5}
    unknown = sorted(set(adjudications) - source_l5)
    missing = sorted(source_l5 - set(adjudications))
    problems = []
    if unknown:
        problems.append(
            f"{len(unknown)} adjudicated record(s) do not claim L5 in the "
            f"source layer: {unknown[:5]}")
    if missing:
        problems.append(
            f"{len(missing)} L5 record(s) have no adjudication: {missing[:5]}")
    for rid in sorted(set(adjudications) & source_l5):
        entry = adjudications[rid]
        finding = next(f for f in findings if f.get("id") == rid)
        exp = finding.get("experiment") or {}
        want_ids = sorted(exp.get("experiment_ids") or [])
        if sorted(entry["experiment_ids"]) != want_ids:
            problems.append(
                f"{rid}: adjudication experiment_ids "
                f"{sorted(entry['experiment_ids'])} != record {want_ids}")
        extra = sorted(set(entry["tests"]) - _observed_names(exp))
        if extra:
            problems.append(
                f"{rid}: adjudication names tests the run never observed: "
                f"{extra}")
    if problems:
        raise AdjudicationError(f"{ADJUDICATION_SOURCE}: " + "; ".join(problems))


def apply_adjudication(view: dict, entry: dict | None) -> dict:
    """Overlay an adjudication entry onto an experiment_view.

    Only the level and the adjudication's own fields are set. `outcome`,
    `outcome_basis`, the artefacts and the ids stay exactly what the run
    produced: an adjudication re-reads a run, it does not replace it. A
    demoted (UNSUPPORTED) record keeps those evidence fields but no longer
    reads as fully verified: its level drops to L4/L1, `demoted_from_L5` and
    `demotion_reason` name the demotion, and `evidence_type` follows the
    adjudicated status so the strongest label is `observed_fact` (executed,
    violation not demonstrated) or `reported_claim` (nothing observed), never
    `experimentally_verified`.
    """
    if entry is None:
        return view
    out = dict(view)
    out.update({
        "level": entry["level_after"],
        "level_before": entry["level_before"],
        "status_after": entry["status_after"],
        "adjudication_verdict": entry["verdict"],
        "verification_provisional": bool(entry["provisional"]),
        "adjudication_reason": entry["reason"],
        "adjudication_source": ADJUDICATION_SOURCE,
    })
    if entry["verdict"] == "WEAK":
        out["l5_candidate"] = True
        out["provisional_reason"] = entry["reason"]
    elif entry["verdict"] == "UNSUPPORTED":
        out["demoted_from_L5"] = True
        out["demotion_reason"] = entry["reason"]
    if entry["level_after"] != entry["level_before"]:
        # A demotion re-reads the run; it must not leave the run's own claim of
        # reproduction standing next to a lower level. The restatement is the
        # shared one (`restate_below_l5`), so a demoted record and a record that
        # simply never claimed L5 are restated identically, and the raw values
        # stay auditable under `*_before_adjudication`.
        out = restate_below_l5(
            out, f"adjudicated {entry['verdict']} demotes {entry['level_before']} "
                 f"to {entry['level_after']}: the run's own claim is restated and "
                 "kept under *_before_adjudication")
    return out


def level_outcome_disagreements(record: dict) -> list[str]:
    """Every way this built record still asserts reproduction below L5.

    The restatement in `enforce_level_coherence` is supposed to leave nothing
    for this function to find, so a non-empty answer means a reproduction claim
    reached the published layer next to a level that does not earn one -- in any
    of the four places a reader can look: the view's outcome, its evidence type,
    the record's evidence summary, and the quality bucket.
    """
    view = record.get("experiment_view") or {}
    if not view.get("present") or not below_l5(view.get("level")):
        return []
    rid = record.get("id")
    disagree = []
    if view.get("outcome") in REPRODUCTION_OUTCOMES:
        disagree.append(f"{rid}: outcome={view['outcome']!r} at level "
                        f"{view.get('level') or 'none'}")
    if view.get("evidence_type") == "experimentally_verified":
        disagree.append(f"{rid}: evidence_type='experimentally_verified' at "
                        f"level {view.get('level') or 'none'}")
    if (record.get("evidence_summary") or {}).get("counts", {}) \
            .get("experimentally_verified"):
        disagree.append(
            f"{rid}: evidence_summary counts experimentally_verified="
            f"{record['evidence_summary']['counts']['experimentally_verified']} "
            f"at level {view.get('level') or 'none'}")
    if view.get("artefacts_all_present") and \
            (record.get("quality") or {}).get("verification") == "experimentally_verified":
        disagree.append(f"{rid}: quality.verification='experimentally_verified' "
                        f"at level {view.get('level') or 'none'}")
    return disagree


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

def field_evidence_types(ev: dict, exp: dict | None = None) -> dict:
    """Each evidence field's type as the PUBLISHED layer counts it.

    The source row's own map is the starting point; where the experiment view
    sits below L5, every field that claimed `experimentally_verified` is counted
    at the view's restated type instead. A field earns that type only from a
    run, so a view whose run does not demonstrate the violation cannot keep the
    claim in any field.

    The test is the LEVEL, not the presence of a restatement marker: a view
    published before the marker existed is counted the same way as one
    published after it, so a consumer reading the current layer and a consumer
    reading a freshly rebuilt one cannot disagree.

    This is the single implementation: `evidence_summary` aggregates over it and
    benchmark family Q's answer key reads per-field types from it, so a consumer
    cannot count a field at a type the derived layer refuses to publish.
    """
    override = None
    if (exp and exp.get("present") and below_l5(exp.get("level"))
            and exp.get("evidence_type") not in (None, "experimentally_verified")):
        override = exp.get("evidence_type")
    out = {}
    for key, value in (ev or {}).items():
        if isinstance(value, dict) and "evidence_type" in value:
            et = value["evidence_type"]
            if override and et == "experimentally_verified":
                et = override
            out[key] = et
    return out


def evidence_summary(ev: dict, exp: dict | None = None) -> dict:
    """Summarise a record's evidence fields under the stated ladder.

    `exp` is the adjudicated experiment view. Where a re-read puts the record
    below L5, its experiment-derived fields are counted at the restated type:
    the summary describes what this layer claims, and a record whose run no
    longer demonstrates the violation must not be summarised as
    `experimentally_verified` while its level says otherwise.
    """
    types = field_evidence_types(ev, exp)
    counts = collections.Counter(types.values())
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


def experiment_view(finding: dict, adjudication: dict | None = None) -> dict:
    """The recorded run, with the adjudicated level overlaid when one exists.

    `level` is the level a reader should use. Where a per-test review exists,
    `level_before` keeps the source claim and the review's verdict is carried
    alongside; where none exists, `level` is exactly what the source says.

    Whatever the level ends up being, the view then passes through
    `enforce_level_coherence`: a level below L5 never publishes a reproduction
    claim, whether or not the record was one of the adjudicated 35.
    """
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
    # A record may cite several runs while the source row names the artefact
    # paths of only one of them. `artefacts` has to name every cited run, or
    # `artefacts_all_present` reads as a claim about all of them while pointing
    # at a single one.
    seen_paths = {a["path"] for a in artefacts}
    for eid in (exp.get("experiment_ids") or []):
        for name in ("result.json", "stdout.txt", "stderr.txt"):
            rel = f"experiments_v2_2/{eid}/{name}"
            if rel in seen_paths or not (ROOT / rel).is_file():
                continue
            seen_paths.add(rel)
            artefacts.append(_artefact(rel))
    status = finding.get("finding", {}).get("status")
    view = {
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
    return enforce_level_coherence(apply_adjudication(view, adjudication))


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

    if exp["present"] and exp["artefacts_all_present"] and exp.get("level") in ("L5", "L6"):
        verification = "experimentally_verified"
    elif exp["present"] and exp["artefacts_all_present"]:
        # The run completed and its artefacts are on disk, but the committed
        # bytes do not demonstrate the claimed violation. A record adjudicated
        # below L5 must not read as `experimentally_verified` next to its own
        # level, so artefact presence alone names a separate bucket.
        verification = BUCKET_EXECUTED_NOT_DEMONSTRATED
    elif exp["present"]:
        verification = "incomplete"
    elif (ev.get("counts") or {}).get("reported_claim"):
        verification = "reported_claim"
    else:
        verification = "unverified"
    # `quality.verification` is a closed set (scripts/schema_terms.py); the
    # bucket is checked against it here as well as by the v2.2 gate, so an
    # unlisted label cannot be written by this builder in the first place.
    if verification not in VERIFICATION_LABELS:
        raise AssertionError(
            f"quality.verification bucket {verification!r} is not in "
            f"{list(VERIFICATION_LABELS)}")

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

def build_record(finding: dict, registry: dict[str, dict],
                 adjudications: dict[str, dict] | None = None) -> dict:
    row_json = json.dumps(finding, sort_keys=True, ensure_ascii=False)
    src = sources_view(finding, registry)
    cc = code_context_view(finding)
    adjudication = (adjudications or {}).get(finding.get("id"))
    exp = experiment_view(finding, adjudication)
    ev = evidence_summary(finding.get("evidence") or {}, exp)
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


def experiment_level_counts(rows: list[dict]) -> dict:
    """The manifest's experiment-level counters, taken from the built views.

    `experiment_levels` counts the level a reader sees (`experiment_view.level`,
    i.e. after adjudication). The three named counters are the adjudication
    totals, recomputed from the built views on every run; they must sum to the
    number of L5 claims the adjudication covers, so a level change cannot drift
    away from its verdict. No count is hard-coded here: `load_adjudication`
    already refuses a file whose declared `counts` disagree with its entries.
    """
    views = [r.get("experiment_view") or {} for r in rows]
    return {
        "experiment_levels": dict(collections.Counter(
            (v.get("level") or "none") for v in views)),
        "experiment_levels_verified_l5": sum(
            1 for v in views if v.get("adjudication_verdict") == "SUPPORTED"),
        "experiment_levels_provisional": sum(
            1 for v in views if v.get("verification_provisional")),
        "experiment_levels_demoted": sum(
            1 for v in views if v.get("demoted_from_L5")),
    }


def build_manifest(rows: list[dict], problems: list[str]) -> dict:
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
    manifest.update(experiment_level_counts(rows))
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="build and validate, write nothing")
    args = ap.parse_args()

    findings, registry = load_layer()
    try:
        adjudications = load_adjudication()
        check_adjudication(findings, adjudications)
    except AdjudicationError as exc:
        log(f"  PROBLEM {exc}")
        return 1
    rows = [build_record(f, registry, adjudications) for f in findings]

    problems = []
    for r in rows:
        if not r["id"]:
            problems.append("a record has no id")
        if r["original_pointer"]["file"].endswith(".jsonl"):
            src_file = ML_JSONL / Path(r["original_pointer"]["file"]).name
            if not src_file.exists():
                problems.append(f"{r['id']}: source file missing")
        if r["sources_view"]["missing_source_ids"]:
            problems.append(f"{r['id']}: unresolved source ids "
                            f"{r['sources_view']['missing_source_ids']}")
        if r["quality"]["verification"] not in VERIFICATION_LABELS:
            problems.append(f"{r['id']}: quality.verification "
                            f"{r['quality']['verification']!r} is outside the "
                            "closed vocabulary")
        if r["experiment_view"]["present"] and \
                not r["experiment_view"]["artefacts_all_present"]:
            problems.append(f"{r['id']}: an experiment artefact is missing on disk")
        problems += level_outcome_disagreements(r)
    if problems:
        for p in problems:
            log(f"  PROBLEM {p}")
        return 1

    manifest = build_manifest(rows, problems)

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
              "experiment_levels", "experiment_levels_verified_l5",
              "experiment_levels_provisional", "experiment_levels_demoted",
              "evidence_strongest", "attacker_identity"):
        log(f"  {k}: {manifest[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

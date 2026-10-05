"""Schema, vocabularies and validators for the multi-language source layer.

`jsonl/` is the immutable Solidity evidence layer of v1 and is never written by
this pipeline. VLUN v2.2 adds Vyper, Rust, Move and Cairo records, and they need
their own layer for two reasons:

  * they are not Code4rena submission records, so the v1 record shape does not
    fit them (advisory, incident, compiler bug, audit contest);
  * a reader must be able to tell "this finding was fetched from a vendor
    advisory" from "this finding was executed in our harness" without trusting
    prose.

So every claim in this layer is wrapped with the same closed evidence
vocabulary the Solidity layer uses (scripts/vlun.py), every source carries the
tier it was admitted under, and every record carries how it was verified.

    jsonl_ml/sources.jsonl     what we fetched, from where, tier, verification
    jsonl_ml/findings.jsonl    one record per reported finding, language-tagged
    derived_v2_2/records.jsonl the derived view (scripts/build_derived_v22.py)

Nothing here is ever written by hand: build them with the scripts. Run
`python scripts/check_ml_layer.py` to validate the layer.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ML_JSONL = ROOT / "jsonl_ml"
DERIVED_V22 = ROOT / "derived_v2_2"
EXPERIMENTS_V22 = ROOT / "experiments_v2_2"
REPORTS_V22 = ROOT / "reports" / "v2_2"
SPLITS_V22 = ROOT / "splits_v2_2"

# ---------------------------------------------------------------------------
# languages and ecosystems
# ---------------------------------------------------------------------------

# `language` is what a model is asked to reason about; `ecosystem` is the
# package/toolchain namespace the finding was filed under. They differ: a Rust
# record can be a Substrate runtime bug or a CosmWasm contract bug, and both are
# "rust", but they have different compilers and different failure modes.
#
# `solidity` is here because v2.2 ingests standalone audit reports that are not
# Code4rena submissions and therefore do not fit the v1 `jsonl/` record shape.
# Those records live in this layer too; the immutable v1 layer is untouched.
LANGUAGES = ("vyper", "rust", "move", "cairo", "solidity")

ECOSYSTEMS = {
    "vyper": ("vyper",),
    "rust": ("cosmwasm", "substrate", "anchor", "solana", "wasmtime", "rust_runtime"),
    "move": ("sui", "aptos"),
    "cairo": ("starknet", "cairo", "scarb"),
    "solidity": ("evm", "ethereum", "base", "hyperevm", "arbitrum", "optimism",
                 "polygon", "bsc"),
}

# ---------------------------------------------------------------------------
# evidence origin: WHERE the finding was first made public
# ---------------------------------------------------------------------------

# Distinct from `evidence_tier`, which says how much we trust it, and from
# `evidence_type` (scripts/vlun.py), which says how a single value came to exist.
EVIDENCE_ORIGIN = (
    "security_advisory",  # vendor/first-party advisory (GHSA, CWAA, CVE)
    "audit",              # named professional audit report with a scope
    "bug_bounty",         # competitive or private bounty program result
    "competitive_audit",  # CodeHawks / Sherlock / Code4rena-style contest
    "incident",           # funds actually lost, post-mortem published
    "postmortem",         # retrospective without a confirmed loss figure
    "compiler_bug",       # defect in the language implementation itself
    "protocol_bug",       # defect in one protocol's code
    "research",           # academic or vendor research write-up
    "dataset",            # a published dataset, used for discovery only
)

# ---------------------------------------------------------------------------
# source tiers (section 6 of the hardening brief). Lower is stronger.
# ---------------------------------------------------------------------------

SOURCE_TIERS = {
    0: "first-party authoritative: vendor advisory, CVE record, published "
       "incident or post-mortem from the affected project",
    1: "named professional audit report that states a commit and a scope",
    2: "competitive audit contest with public findings and judging "
       "(CodeHawks, Code4rena, Sherlock, Immunefi)",
    3: "public portfolio, blog or researcher write-up: usable for discovery, "
       "never sufficient on its own for a confirmed label",
    4: "dataset or aggregator: discovery only, never a sole basis for a label",
}

TIER_MIN_FOR_LABEL = 2  # a confirmed label needs tier <= 2
# A tier-4 source may only ever produce a discovery pointer, never a finding
# with a severity. Encoded as a rule rather than a comment so the checker can
# enforce it.
TIER4_DISCOVERY_ONLY = True

# ---------------------------------------------------------------------------
# how the record was verified by us
# ---------------------------------------------------------------------------

VERIFICATION_STATUS = (
    "retrieved_via_api_and_hashed",  # we pulled it from a machine API and hashed the payload
    "retrieved_and_read",            # we fetched the document and read it
    "url_confirmed_resolvable",      # we only proved the URL answers 200
    "secondary_citation",            # another record cites it; we did not fetch it
    "unverified",
)

VERIFICATION_EVIDENCE = {
    "retrieved_via_api_and_hashed": "observed_fact",
    "retrieved_and_read": "observed_fact",
    "url_confirmed_resolvable": "observed_fact",
    "secondary_citation": "reported_claim",
    "unverified": "unverified",
}

# ---------------------------------------------------------------------------
# experiment levels, identical to the Solidity layer
# ---------------------------------------------------------------------------

EXPERIMENT_LEVELS = tuple(f"L{i}" for i in range(7))

# ---------------------------------------------------------------------------
# which languages each v2.2 benchmark family may be built from
# ---------------------------------------------------------------------------

# Every K-Q task is drawn from splits_v2_2, so a family's tasks inherit the
# split of the record they came from; this records what each family may cover.
# The question each family asks is declared once, in scripts/vlun.py
# (BENCHMARK_FAMILIES), because scripts/validate.py reads it there.
FAMILY_LANGUAGES = {
    "K": LANGUAGES,   # language/ecosystem routing from prose
    "L": LANGUAGES,   # severity reconciliation across publishers
    "M": LANGUAGES,   # experiment level classification for executed runs
    "N": LANGUAGES,   # attacker identity extraction from a source sentence
    "O": LANGUAGES,   # record class and scope judgment
    "P": LANGUAGES,   # source tier, origin and redistribution rights
    "Q": LANGUAGES,   # evidence typing plus the published quality rubric
}

ML_ID_RE = re.compile(r"^[a-z0-9_]+:[A-Za-z0-9._\-/]+$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
# a local file is a real, hashable artefact: v2.2 evidence can be an on-disk
# report as easily as a URL, so both schemes are admitted (and told apart).
URL_RE = re.compile(r"^(?:https?|file)://")

EVIDENCE_TYPES = (
    "observed_fact",
    "reported_claim",
    "derived_fact",
    "experimentally_verified",
    "externally_attributed",
    "unverified",
    "unknown",
)

REQUIRED_SOURCE_KEYS = (
    "record_type", "source_id", "language", "ecosystem", "title",
    "source_tier", "evidence_origin", "url", "identifiers",
    "retrieved_at", "verification", "license",
)

REQUIRED_FINDING_KEYS = (
    "record_type", "dataset_version", "schema_version", "language", "ecosystem", "id",
    "source", "finding", "evidence", "provenance",
)


def claim(value, etype, refs=None, note=None):
    """Wrap a value the way the Solidity layer does, with a closed vocabulary."""
    if etype not in EVIDENCE_TYPES:
        raise ValueError(f"evidence_type {etype!r} not in {EVIDENCE_TYPES}")
    d = {"value": value if value not in ("", None) else None, "evidence_type": etype,
         "source_refs": list(refs or [])}
    if note:
        d["note"] = note
    return d


def unknown(note=None, refs=None):
    return claim(None, "unknown", refs, note)


def ml_id(language: str, native_id: str) -> str:
    return f"{language}:{native_id}"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{lineno} invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    tmp.replace(path)


def _parts(prefix: str) -> list[Path]:
    """Per-language part files, so each language's research pass writes its own.

    `jsonl_ml/sources_rust.jsonl` and friends are merged read-only at load time;
    no script ever rewrites another language's part file, which keeps concurrent
    research passes from clobbering each other.
    """
    if not ML_JSONL.exists():
        return []
    return sorted(p for p in ML_JSONL.glob(f"{prefix}_*.jsonl"))


def load_sources() -> list[dict]:
    rows: list[dict] = []
    for p in _parts("sources"):
        rows.extend(read_jsonl(p))
    if not rows and (ML_JSONL / "sources.jsonl").exists():
        rows = read_jsonl(ML_JSONL / "sources.jsonl")
    return rows


def load_findings() -> list[dict]:
    rows: list[dict] = []
    for p in _parts("findings"):
        rows.extend(read_jsonl(p))
    if not rows and (ML_JSONL / "findings.jsonl").exists():
        rows = read_jsonl(ML_JSONL / "findings.jsonl")
    return rows


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------

def source_record(*, source_id: str, language: str, ecosystem: str, title: str,
                  source_tier: int, evidence_origin: str, url: str,
                  retrieved_at: str, verification_status: str,
                  identifiers: dict | None = None, repository: str | None = None,
                  published_at: str | None = None, affected: list | None = None,
                  fix: dict | None = None, license: dict | None = None,
                  retrieval: dict | None = None, notes: str = "",
                  severity: dict | None = None) -> dict:
    if language not in LANGUAGES:
        raise ValueError(f"language {language!r} not in {LANGUAGES}")
    if ecosystem not in ECOSYSTEMS[language]:
        raise ValueError(f"ecosystem {ecosystem!r} not valid for {language}")
    if source_tier not in SOURCE_TIERS:
        raise ValueError(f"tier {source_tier!r} not in {SOURCE_TIERS}")
    if evidence_origin not in EVIDENCE_ORIGIN:
        raise ValueError(f"origin {evidence_origin!r} not in {EVIDENCE_ORIGIN}")
    if verification_status not in VERIFICATION_STATUS:
        raise ValueError(f"verification {verification_status!r} not in {VERIFICATION_STATUS}")
    rec = {
        "record_type": "ml_source",
        "source_id": source_id,
        "language": language,
        "ecosystem": ecosystem,
        "title": title,
        "source_tier": source_tier,
        "evidence_origin": evidence_origin,
        "url": url,
        "repository": repository,
        "identifiers": identifiers or {},
        "published_at": published_at,
        "retrieved_at": retrieved_at,
        "retrieval": retrieval or {"method": "unknown"},
        "verification": {
            "status": verification_status,
            "evidence_type": VERIFICATION_EVIDENCE[verification_status],
        },
        "severity": severity or claim(None, "unknown", None, "no severity published"),
        "affected": affected or [],
        "fix": fix or {"commit": None, "url": None,
                       "evidence_type": "unknown"},
        "license": license or {"content_license": "unknown", "redistributable": False,
                               "evidence_type": "unknown"},
        "notes": notes,
    }
    return rec


def finding_record(*, language: str, ecosystem: str, finding_id: str, title: str,
                   source_ids: list[str], source: dict, severity: dict,
                   finding: dict, evidence: dict, provenance: dict,
                   code_context: list | None = None, patch: dict | None = None,
                   experiment: dict | None = None,
                   dataset_version: str, schema_version: str) -> dict:
    if language not in LANGUAGES:
        raise ValueError(f"language {language!r} not in {LANGUAGES}")
    return {
        "record_type": "ml_finding",
        "dataset_version": dataset_version,
        "schema_version": schema_version,
        "language": language,
        "ecosystem": ecosystem,
        "id": ml_id(language, finding_id),
        "source_ids": list(source_ids),
        "source": source,
        "finding": {
            "id": ml_id(language, finding_id),
            "title": title,
            "severity": severity.get("value"),
            "severity_source": severity.get("source"),
            "record_class": finding.get("record_class"),
            "status": finding.get("status"),
            "vulnerability_classes": finding.get("vulnerability_classes") or [],
            "summary": finding.get("summary"),
            "root_cause": finding.get("root_cause"),
            "affected_components": finding.get("affected_components") or [],
            "affected_functions": finding.get("affected_functions") or [],
            "affected_versions": finding.get("affected_versions"),
            "patched_versions": finding.get("patched_versions"),
        },
        "evidence": evidence,
        "code_context": code_context or [],
        "patch": patch or {"present": False, "evidence_type": "unknown"},
        "experiment": experiment,
        "provenance": provenance,
    }


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _need(cond, msg, out):
    if not cond:
        out.append(msg)


def validate_source(rec: dict) -> list[str]:
    out: list[str] = []
    for k in REQUIRED_SOURCE_KEYS:
        _need(k in rec, f"missing key {k}", out)
    _need(rec.get("record_type") == "ml_source", "record_type must be ml_source", out)
    _need(ML_ID_RE.match(rec.get("source_id") or ""),
          f"source_id {rec.get('source_id')!r} must be '<language>:<native-id>'", out)
    lang = rec.get("language")
    _need(lang in LANGUAGES, f"language {lang!r} invalid", out)
    if lang in ECOSYSTEMS:
        _need(rec.get("ecosystem") in ECOSYSTEMS[lang],
              f"ecosystem {rec.get('ecosystem')!r} not valid for {lang}", out)
    _need(rec.get("source_tier") in SOURCE_TIERS, "source_tier must be 0..4", out)
    _need(rec.get("evidence_origin") in EVIDENCE_ORIGIN,
          f"evidence_origin {rec.get('evidence_origin')!r} invalid", out)
    _need(rec.get("url") and URL_RE.match(rec["url"]), "url must be http(s)", out)
    ver = rec.get("verification") or {}
    _need(ver.get("status") in VERIFICATION_STATUS, f"verification {ver.get('status')!r}", out)
    _need(ver.get("evidence_type") in EVIDENCE_TYPES, "verification.evidence_type invalid", out)
    if ver.get("status") in VERIFICATION_EVIDENCE:
        _need(ver.get("evidence_type") == VERIFICATION_EVIDENCE[ver["status"]],
              "verification.evidence_type must match the status", out)
    lic = rec.get("license") or {}
    _need(lic.get("redistributable") in (True, False),
          "license.redistributable must be a bool", out)
    # A tier-4 source is discovery only: it may not carry a severity, because a
    # severity copied from an aggregator is an unaudited label.
    if rec.get("source_tier") == 4:
        _need((rec.get("severity") or {}).get("value") in (None, ""),
              "a tier-4 source is discovery only and may not carry a severity", out)
    if rec.get("fix"):
        sha = (rec.get("fix") or {}).get("commit")
        _need(sha is None or SHA40_RE.match(sha),
              f"fix.commit {sha!r} must be a full 40-hex sha or null", out)
    return out


def validate_finding(rec: dict) -> list[str]:
    out: list[str] = []
    for k in REQUIRED_FINDING_KEYS:
        _need(k in rec, f"missing key {k}", out)
    _need(rec.get("record_type") == "ml_finding", "record_type must be ml_finding", out)
    _need(rec.get("language") in LANGUAGES, f"language {rec.get('language')!r} invalid", out)
    _need(rec.get("id") == f"{rec.get('language')}:{(rec.get('finding') or {}).get('id', '').split(':', 1)[-1]}",
          "id must be '<language>:<native-id>' and match finding.id", out)
    _need(isinstance(rec.get("source_ids"), list) and rec.get("source_ids"),
          "source_ids must be a non-empty list", out)
    sev = (rec.get("finding") or {}).get("severity")
    _need(sev in (None, "", "critical", "high", "medium", "low", "informational",
                  "none", "unknown"),
          f"severity {sev!r} outside the closed vocabulary", out)
    ev = rec.get("evidence") or {}
    for field, val in ev.items():
        if isinstance(val, dict) and "evidence_type" in val:
            _need(val["evidence_type"] in EVIDENCE_TYPES,
                  f"evidence.{field}.evidence_type {val['evidence_type']!r} invalid", out)
    # Nothing may claim experimental verification without an experiment record.
    exp = rec.get("experiment")
    if exp:
        _need(exp.get("level") in EXPERIMENT_LEVELS, "experiment.level must be L0..L6", out)
        _need(exp.get("result_artifact") is not None,
              "an experiment must name a result artefact", out)
        if exp.get("level") in ("L3", "L4", "L5", "L6"):
            _need(exp.get("executed") is True,
                  f"{exp.get('level')} requires executed=True", out)
    else:
        for field, val in ev.items():
            if isinstance(val, dict) and val.get("evidence_type") == "experimentally_verified":
                out.append(f"evidence.{field} claims experimentally_verified with no "
                           f"experiment record")
    for cc in rec.get("code_context") or []:
        sha = cc.get("commit_sha")
        _need(sha is None or SHA40_RE.match(sha),
              f"code_context.commit_sha {sha!r} must be a 40-hex sha", out)
        _need(cc.get("language") in LANGUAGES + ("solidity",),
              f"code_context.language {cc.get('language')!r} invalid", out)
    return out


def check_layer() -> tuple[int, list[str]]:
    """Validate everything in jsonl_ml/. Returns (records, errors)."""
    errors: list[str] = []
    total = 0
    for rec in load_sources():
        total += 1
        errors += [f"sources.jsonl {rec.get('source_id')}: {e}"
                   for e in validate_source(rec)]
    seen: set[str] = set()
    for rec in load_sources():
        sid = rec.get("source_id")
        if sid in seen:
            errors.append(f"sources.jsonl duplicate source_id {sid}")
        seen.add(sid)
    findings = load_findings()
    known = {r.get("source_id") for r in load_sources()}
    for rec in findings:
        total += 1
        errors += [f"findings.jsonl {rec.get('id')}: {e}" for e in validate_finding(rec)]
        for sid in rec.get("source_ids") or []:
            if sid not in known:
                errors.append(f"findings.jsonl {rec.get('id')}: unknown source_id {sid}")
    fids: dict[str, int] = {}
    for rec in findings:
        fids[rec.get("id")] = fids.get(rec.get("id"), 0) + 1
    errors += [f"findings.jsonl duplicate id {k} x{v}" for k, v in fids.items() if v > 1]
    return total, errors

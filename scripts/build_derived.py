#!/usr/bin/env python3
"""Build the derived record layer: evidence semantics, attacker model,
state transition, code context, taxonomy and quality dimensions.

`jsonl/` is never touched. Every record produced here embeds the v1 evidence
under `original_evidence` so the separation required by the brief is visible in
the data, not just in the docs:

    original_evidence        what the Code4rena artefact actually said
    evidence                 how each new field came to exist
    security_state_transition causal chain, only where sources support one
    attacker_model           who can act, with what, and under what constraints
    code_context_expanded   dependency-aware, commit-pinned, licence-gated
    taxonomy                 normalised category/family/class/subtype
    quality                  transparent per-dimension assessment

Rules that keep this honest:
  * no invariant is invented; `invariants: []` is a valid and counted outcome
  * a state transition is only emitted when the attack path plus the PoC code
    supply steps; otherwise every field is explicitly null with a reason
  * attacker kind is mechanical: a role gate implies `privileged`, and no
    observed gate does not imply `unprivileged`

    python scripts/build_derived.py
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_sources as ls  # noqa: E402
import solidity_facts as sf  # noqa: E402
import taxonomy as tx  # noqa: E402
from vlun import (  # noqa: E402
    ATTACKER_KINDS, DATASET_VERSION, DERIVED, INVARIANT_SOURCES, JSONL, confidence_from_evidence, log, rec_id, sha256_text, write_json, write_jsonl,
)

# ---------------------------------------------------------------------------
# evidence helpers
# ---------------------------------------------------------------------------

VULN_ASSERTION = re.compile(
    r"\b(steal|drain|withdraw|lose|loss|exploit|manipulat|bypass|free\b|reentran|"
    r"selfdestruct|freeze|lock(ed)?|hijack|front-?run|flash\s*loan)", re.I)
# An external dependency only counts as the *actor* when a source says an
# attacker controls it. Merely mentioning an oracle or a token is not that.
DEPENDENCY_AS_ACTOR = re.compile(
    r"\b(attacker[- ]controlled|attacker (?:can )?(?:control|deploy|operate)|"
    r"malicious (?:oracle|token|bridge|feed|dependency|implementation)|"
    r"compromised (?:oracle|bridge|token|dependency)|collude\w*|"
    r"caller supplies|user[- ]supplied (?:oracle|price|collateral)|"
    r"a malicious|an attacker[- ]controlled|attacker chooses)\b", re.I)
PRIVILEGE_ASSERTION = re.compile(
    r"\b(owner|admin|governance|governor|keeper|manager|maintainer|operator|guardian|"
    r"privileged|malicious (?:admin|owner|keeper|governance)|compromis)", re.I)
EXTERNAL_DEPENDENCY_MENTION = re.compile(
    r"\b(oracle|bridge|token|price feed|aggregator|third[- ]party|external dependenc)", re.I)
MISCONFIG_ASSERTION = re.compile(
    r"\b(misconfigur|wrong(ly)? (?:set|configured)|incorrect(?:ly)? (?:set|configured)|"
    r"missing (?:config|environment)|not set|unset|omitted)\b", re.I)
_MUTABLE_BLOB_RE = re.compile(
    r"^(https://github\.com/([^/]+/[^/]+)/blob/)(main|master)(/.*)?$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def pin_provenance_urls(prov: dict, source: dict) -> dict:
    """Rewrite audit-repo /blob/main|master/ links to the audited revision.

    Only links into the record's own audit repository (code-423n4/<repository>)
    can be pinned from in-record data, using source.commit_sha. Third-party
    links, and links without a known sha, are NOT rewritten: they are listed
    in the new source_urls_unpinned array so no branch link looks pinned.
    source_urls itself keeps every URL — leakage, permalink and split
    consumers read that array, and moving entries would silently change
    their counts.
    """
    prov = dict(prov or {})
    if prov.get("source_urls") is None:
        return prov
    repo = (source or {}).get("repository") or ""
    sha = (source or {}).get("commit_sha") or ""
    audited = "code-423n4/" + repo
    pinnable = bool(_SHA40.match(str(sha)))
    out_urls, unpinned = [], []
    for u in prov.get("source_urls") or []:
        if not isinstance(u, str):
            out_urls.append(u)
            continue
        m = _MUTABLE_BLOB_RE.match(u)
        if not m:
            out_urls.append(u)
            continue
        if m.group(2) == audited and pinnable:
            out_urls.append(m.group(1) + str(sha) + (m.group(4) or ""))
        else:
            out_urls.append(u)
            if u not in unpinned:
                unpinned.append(u)
    prov["source_urls"] = out_urls
    if unpinned:
        prov["source_urls_unpinned"] = unpinned
    return prov


def evidence(value, etype, refs=None, confidence=None, note=None):
    d = {"value": value if value not in ("", None) else None, "evidence_type": etype,
         "source_refs": refs or []}
    if confidence:
        d["confidence"] = confidence
    if note:
        d["note"] = note
    return d


# ---------------------------------------------------------------------------
# attacker model
# ---------------------------------------------------------------------------

UNPRIVILEGED_ASSERTION = re.compile(
    r"\b(anyone|any user|arbitrary|any caller|permissionless|unrestricted|"
    r"missing access control|no access control|lacks? access control|lacking access control|"
    r"without (?:any )?(?:restriction|permission|authorization|check)|"
    r"malicious user|any third party|unauthori[sz]ed|publicly callable)\b", re.I)


SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n")

REPORTED_ACTOR_RULES = (
    ("unprivileged", re.compile(
        r"\b(any user|anyone|any caller|any third party|an arbitrary (?:user|caller|address)|"
        r"an unprivileged|any external (?:caller|actor)|a malicious user|"
        r"without any (?:privilege|permission|restriction))\b", re.I)),
    ("privileged", re.compile(
        r"\b(the (?:owner|admin|governance|governor|keeper|manager|maintainer|operator|guardian)|"
        r"a malicious (?:owner|admin|keeper|governance|manager)|"
        r"the (?:protocol )?(?:admin|governance team)|a privileged|"
        r"compromised (?:owner|admin|keeper|governance))\b", re.I)),
    ("malicious_dependency", re.compile(
        r"\b(an? attacker[- ]controlled (?:token|oracle|bridge|contract|implementation|feed)|"
        r"a malicious (?:oracle|token|bridge|contract|implementation)|"
        r"a compromised (?:oracle|bridge|dependency)|collud\w+ (?:with|against))\b", re.I)),
    ("honest_but_misconfigured", re.compile(
        r"\b(misconfigur\w+|incorrectly (?:set|configured)|wrongly (?:set|configured)|"
        r"the (?:owner|admin) (?:sets|sets? up|configures) (?:it|this|the) \w+ incorrectly)\b", re.I)),
)


def reported_attacker_kind(sentences: list[str]):
    """Kind + the exact sentence that states it, when a source says so outright.

    This is `reported_claim`, not inference: the sentence is returned so a reader
    can check the attribution without trusting the classifier.
    """
    for kind, pat in REPORTED_ACTOR_RULES:
        for s in sentences:
            m = pat.search(s or "")
            if m:
                return kind, " ".join((s or "").split())[:400]
    return None, None


def attacker_model(row: dict, ctx: list[dict], finding: dict) -> dict:
    """Separate *who* from *what*. Mechanical where code allows it."""
    roles, conds, gates, signals = set(), set(), [], collections.Counter()
    for c in ctx:
        for fn in (c.get("functions") or []):
            roles.update(fn.get("required_roles") or [])
            conds.update(fn.get("operational_conditions") or [])
        t = c.get("target_function")
        if t:
            gates.append(sf.access_control_summary({"target_function": t}))
            for k, v in (t.get("signals") or {}).items():
                if v:
                    signals[k] += 1
    # Pointer the observation at the rule that produced its verdict. Unknown
    # observations stay ref-less: they claim nothing.
    for g in gates:
        if isinstance(g, dict) and g.get("evidence_type") == "derived_fact":
            g["source_refs"] = ["rule:solidity_facts.py:functions"]

    prose = " ".join(str(x) for x in [
        finding.get("title"), finding.get("summary"), finding.get("root_cause"),
        " ".join((row.get("security_reasoning") or {}).get("attacker_capabilities") or []),
        " ".join((row.get("security_reasoning") or {}).get("attack_prerequisites") or []),
    ])

    unprivileged_claim = bool(UNPRIVILEGED_ASSERTION.search(prose))
    gate_open = bool(gates) and gates[0]["verdict"] in (
        "no_check_observed", "input_guards_present_no_role_check")

    if signals.get("uses_tx_origin"):
        kind = "honest_but_misconfigured" if roles else "unprivileged"
        why = ("`tx.origin` is used for authorisation; any EOA can set it, so the 'actor' is a "
               "legitimate-looking caller whose origin is wrong")
    elif roles:
        kind, why = "privileged", "every cited entry point carries an access-control modifier"
    elif DEPENDENCY_AS_ACTOR.search(prose):
        kind, why = "malicious_dependency", ("a source states the attack needs an "
                                             "attacker-controlled external contract")
    elif MISCONFIG_ASSERTION.search(prose):
        kind, why = "honest_but_misconfigured", ("a source states the attack needs a legitimate "
                                                  "actor to have configured something wrongly")
    elif unprivileged_claim and gate_open:
        kind, why = "unprivileged", ("a source asserts unprivileged reach and no role gate was "
                                     "observed on the cited entry point")
    else:
        kind = "unknown"
        why = ("no source states who acts, and the cited code does not settle it: "
               + ("entry points observed carry guards, but none clearly gate caller identity"
                  if gates else "no analysable entry point is in the record"))

    external_deps = sorted({(c.get("file") or "").split("/")[0] + "/" + (c.get("file") or "").split("/")[1]
                            for c in ctx
                            if (c.get("file") or "").count("/") > 1
                            and not (c.get("file") or "").startswith(f"{row['source']['repository']}/")})

    # Sources that name the actor outright. Checked after the mechanical rules
    # so observed code always wins over prose.
    src_sentences = []
    for field in ("title", "summary", "root_cause"):
        src_sentences += [s for s in SENTENCE_RE.split(str(finding.get(field) or "")) if s.strip()]
    sr = row.get("security_reasoning") or {}
    for field in ("attacker_capabilities", "attack_prerequisites", "attacker_limitations",
                  "intended_behavior", "broken_behavior"):
        for v in (sr.get(field) or []):
            src_sentences += [s for s in SENTENCE_RE.split(str(v)) if s.strip()]
    for k in ("integrity", "financial", "protocol_state", "availability", "confidentiality"):
        src_sentences += [s for s in SENTENCE_RE.split(str((sr.get("impact") or {}).get(k) or "")) if s.strip()]
    rep_kind, rep_sentence = reported_attacker_kind(src_sentences)
    basis = "derived_fact"
    if kind == "unknown" and rep_kind:
        kind, why, basis = rep_kind, f"a source names the actor: \"{rep_sentence}\"", "reported_claim"
    if kind == "unknown":
        # an unresolved record has no basis at all; leaving it as derived_fact
        # would make the basis counts disagree with the kind counts
        basis = "unknown"

    caps, prereqs = [], []
    for c in (row.get("security_reasoning") or {}).get("attacker_capabilities") or []:
        caps.append({"value": c, "evidence_type": "reported_claim"})
    for p in (row.get("security_reasoning") or {}).get("attack_prerequisites") or []:
        prereqs.append({"value": p, "evidence_type": "reported_claim"})

    # mechanical capability statements, with the rule that produced them
    for c in ctx:
        t = c.get("target_function")
        if not t:
            continue
        s = t.get("signals") or {}
        if s.get("has_delegatecall"):
            caps.append({"value": "the analysed function performs a delegatecall",
                         "evidence_type": "derived_fact",
                         "source_refs": ["rule:build_derived.py:attacker_model"],
                         "note": "rule: delegatecall token present in the stripped body"})
        if s.get("uses_tx_origin"):
            caps.append({"value": "the analysed function reads tx.origin",
                         "evidence_type": "derived_fact",
                         "source_refs": ["rule:build_derived.py:attacker_model"],
                         "note": "rule: tx.origin token present in the stripped body"})
        if s.get("has_external_call"):
            caps.append({"value": "the analysed function makes an external call",
                         "evidence_type": "derived_fact",
                         "source_refs": ["rule:build_derived.py:attacker_model"],
                         "note": "rule: `.call(` / typed external call present"})
        if s.get("has_contract_creation"):
            prereqs.append({"value": "the analysed function deploys a contract",
                            "evidence_type": "derived_fact",
                            "note": "rule: `new X{` or create/create2 present"})
    for p in (row.get("security_reasoning") or {}).get("environment_assumptions") or []:
        prereqs.append({"value": p, "evidence_type": "reported_claim"})

    return {
        "attacker_identity": {
            "value": kind,
            "evidence_type": basis if kind != "unknown" else "unknown",
            "source_refs": (["rule:build_derived.py:attacker_model"]
                            if kind != "unknown" and basis == "derived_fact"
                            else []),
            "basis": basis,
            "why": why,
            "attributed_sentence": rep_sentence if basis == "reported_claim" else None,
            "vocabulary": list(ATTACKER_KINDS),
            "rule": "role modifier present -> privileged; tx.origin authorisation -> "
                    "honest_but_misconfigured; an explicit attacker-controlled-external-contract "
                    "statement -> malicious_dependency; an explicit configuration-error statement -> "
                    "honest_but_misconfigured; unprivileged only when a source asserts it AND an "
                    "open gate was actually observed. Everything else is unknown.",
            "unprivileged_claimed_in_prose": unprivileged_claim,
            "external_dependencies_involved": external_deps,
        },
        "attacker_capabilities": caps[:12],
        "attacker_prerequisites": prereqs[:12],
        "attacker_constraints": (row.get("security_reasoning") or {}).get("attacker_limitations") or [],
        "trusted_roles": sorted(roles),
        "required_permissions": [
            {"role": r, "evidence_type": "derived_fact",
             "source_refs": ["rule:solidity_facts.py:functions"],
             "note": f"observed modifier {m}"}
            for r, m in sorted({(rr, mm) for c in ctx for f in (c.get("functions") or [])
                                for rr, mm in zip(f.get("required_roles") or [], f.get("modifiers") or [])})
        ],
        "required_assets": evidence(None, "unknown",
                                    note="the record does not state what capital or assets the "
                                         "attacker must bring"),
        "required_market_conditions": evidence(None, "unknown",
                                               note="not stated in the record"),
        "required_cross_contract_state": evidence(
            sorted({(c.get("file") or "").split("/")[0] + "/" + (c.get("file") or "").split("/")[1]
                    for c in ctx if (c.get("file") or "").count("/") > 1
                    and not c.get("file", "").startswith(f"{row['source'].get('repository')}/")})
            or None,
            "derived_fact" if any((c.get("file") or "").count("/") > 1 and
                                  not c.get("file", "").startswith(f"{row['source']['repository']}/")
                                  for c in ctx) else "unknown",
            refs=(["rule:build_derived.py:attacker_model"]
                  if any((c.get("file") or "").count("/") > 1 and
                         not c.get("file", "").startswith(f"{row['source']['repository']}/")
                         for c in ctx) else None),
            note="other owners/repositories whose code the finding's reasoning touches"),
        "access_control_observations": gates[:8],
        "mechanical_signal_counts": dict(signals),
    }


# ---------------------------------------------------------------------------
# state transition
# ---------------------------------------------------------------------------

def state_transition(row: dict, ex: dict | None, ctx: list[dict]) -> dict:
    """Causal chain. Steps come from the report's attack path or the PoC code.

    No numeric state is fabricated. `initial_state` / `final_state` stay empty
    unless an exploit row or the PoC body states a concrete balance or storage
    value, and every such value carries the sentence it came from.
    """
    sr = row.get("security_reasoning") or {}
    path = sr.get("attack_path") or []
    steps, _refs = [], []

    for i, p in enumerate(path, 1):
        if isinstance(p, dict):
            steps.append({
                "step": p.get("step", i), "actor": p.get("actor"),
                "action": p.get("action"), "contract": p.get("contract"),
                "function": p.get("function"), "state_change": p.get("state_change") or None,
                "evidence_type": "reported_claim",
            })
        else:
            steps.append({"step": i, "actor": None, "action": p, "contract": None,
                          "function": None, "state_change": None,
                          "evidence_type": "reported_claim"})
    for st in (ex or {}).get("attack_sequence") or []:
        steps.append({"step": len(steps) + 1, "actor": st.get("actor"),
                      "action": st.get("action"), "contract": st.get("contract"),
                      "function": st.get("function"),
                      "state_change": st.get("state_change") or None,
                      "evidence_type": "reported_claim"})

    code = (ex or {}).get("code") or ""
    # numeric transitions, but only ones the PoC text literally asserts
    numbers = re.findall(r"assert(?:Eq|Ge|Lt|True)?\s*\(\s*([\w\.\[\]]+)\s*,\s*([^)]{1,80})\)", code)
    numeric = [{"subject": a.strip(), "expected": b.strip(), "evidence_type": "observed_fact",
                "source": "assertion in the PoC quoted from the report"} for a, b in numbers[:8]]

    impact = sr.get("impact") or {}
    inv = sr.get("invariants") or []
    violated = inv[0].get("invariant") if inv and isinstance(inv[0], dict) else None

    has_steps = bool(steps)
    return {
        "present": has_steps,
        "initial_state": evidence(None, "unknown" if not numeric else "observed_fact",
                                  note="no initial balances or storage values are stated by any source"
                                       if not numeric else None),
        "actors": sorted({s["actor"] for s in steps if s.get("actor")}),
        "transactions": [s for s in steps if s.get("contract") or s.get("function")][:20],
        "intermediate_state_changes": [s["state_change"] for s in steps if s.get("state_change")][:20],
        "final_state": evidence(None, "unknown",
                                note="no final balances or storage values are stated by any source"),
        "violated_property": evidence(violated, "reported_claim" if violated else "unknown"),
        "attacker_gain": evidence(impact.get("financial") or None,
                                  "reported_claim" if impact.get("financial") else "unknown"),
        "victim_loss": evidence(impact.get("financial") or None,
                                "reported_claim" if impact.get("financial") else "unknown"),
        "asserted_numeric_transitions": numeric,
        "step_evidence": "attack_path from the report" if steps else None,
        "reconstruction_rule": "steps are transcribed, never generated; an empty transactions list "
                               "means no source described a sequence",
    }


# ---------------------------------------------------------------------------
# code context
# ---------------------------------------------------------------------------

def expanded_context(row: dict) -> list[dict]:
    return ls.enrich_all(row)


def dependency_graph(ctx: list[dict]) -> dict:
    """Which contracts, libraries and interfaces the finding's code touches."""
    contracts = sorted({c.get("contract") or (c.get("contracts") or [{}])[0].get("name")
                        for c in ctx if (c.get("contract") or (c.get("contracts") or [{}])[0].get("name"))})
    repos = sorted({(c.get("file") or "").split("/")[0] + "/" + (c.get("file") or "").split("/")[1]
                    for c in ctx if (c.get("file") or "").count("/") > 1})
    return {"contracts_touched": contracts[:20],
            "repositories_touched": repos[:20],
            "cross_repository": len(repos) > 1}


def invariants_block(row: dict, ctx: list[dict]) -> dict:
    """Preserve v1 invariants and classify their source. Never add one."""
    sr = row.get("security_reasoning") or {}
    inv = sr.get("invariants") or []
    out = []
    for i, v in enumerate(inv if isinstance(inv, list) else [inv]):
        if isinstance(v, str):
            out.append({"invariant": v, "evidence_type": "reported_claim",
                        "source_type": _inv_source(sr, row), "origin": "v1"})
        elif isinstance(v, dict):
            out.append({
                "invariant": v.get("invariant") or v.get("statement") or v.get("text"),
                "evidence_type": "reported_claim",
                "source_type": v.get("source_type") or _inv_source(sr, row),
                "origin": "v1", "note": v.get("source") or v.get("source_note"),
            })
    return {
        "invariants": out,
        "count": len(out),
        "source_vocabulary": list(INVARIANT_SOURCES),
        "record_level_source": sr.get("invariant_source") or "none",
        "policy": "an invariant is recorded only when a report sentence, NatSpec, a test assertion "
                  "or an executed run states one; empty is a valid outcome and is counted as such",
    }


def _inv_source(sr: dict, row: dict) -> str:
    s = (sr.get("invariant_source") or "").lower()
    if "nat" in s or "@notice" in s or "@dev" in s:
        return "nat_spec"
    if "report" in s or "finding" in s or "prose" in s:
        return "explicit_report"
    if "remediat" in s:
        return "protocol_documentation"
    return "explicit_report" if sr.get("invariants") else "none"


# ---------------------------------------------------------------------------
# quality
# ---------------------------------------------------------------------------

def quality_block(row: dict, ctx: list[dict], att: dict, st: dict, inv: dict,
                  license_class: str) -> dict:
    sr = row.get("security_reasoning") or {}
    prov = row.get("provenance") or {}
    etypes = []

    permalinks = [u for u in prov.get("source_urls", []) if "/blob/" in u]
    etypes.append("observed_fact" if permalinks else "unknown")
    if prov.get("judge_and_sponsor_quotes"):
        etypes.append("reported_claim")
    etypes.append(att["attacker_identity"]["evidence_type"])
    if st["present"]:
        etypes.append("reported_claim")

    return {
        "provenance": confidence_from_evidence(etypes[:1]) if permalinks else "low",
        "provenance_basis": {"blob_permalinks": len(permalinks),
                             "judge_or_sponsor_quotes": len(prov.get("judge_and_sponsor_quotes") or []),
                             "license": license_class,
                             "license_verified_in_source": bool(prov.get("license_verified"))},
        "code_context": ("high" if len(ctx) >= 3 else "medium" if ctx else "none"),
        "code_context_basis": {"files_analysed": len(ctx),
                               "files_retrieved_locally": sum(1 for c in ctx if c.get("retrieved_locally")),
                               "contract_level": sum(1 for c in ctx if c.get("contracts")),
                               "state_variables": sum(len(c.get("state_variables") or []) for c in ctx)},
        "dynamic_verification": (row.get("_verification_verdict") or "not_attempted"),
        "reasoning": ("high" if sr.get("intended_behavior") and sr.get("attack_path") else
                      "medium" if sr.get("intended_behavior") else "low"),
        "attacker_model": ("high" if att["attacker_identity"]["evidence_type"] != "unknown" else "low"),
        "state_transition": ("high" if st.get("transactions") else "none"),
        "invariants": ("high" if inv["count"] else "none"),
        "negative_reasoning": "none",
        "label_quality": ("high" if row.get("validation", {}).get("evidence") else "medium"),
        "no_numerical_severity_score": True,
        "scoring_note": "each dimension is an ordinal label with a stated basis; no weighted "
                        "aggregate score is produced because no validated weighting exists",
    }


# ---------------------------------------------------------------------------
# record assembly
# ---------------------------------------------------------------------------

def build_record(row: dict, verification_index: dict) -> dict:
    finding = row.get("finding") or {}
    rid = rec_id(row)
    license_class = ls.classify_record_code(row)
    ctx = expanded_context(row)
    att = attacker_model(row, ctx, finding)
    ex = verification_index.get(rid)
    st = state_transition(row, ex, ctx)
    inv = invariants_block(row, ctx)
    row_v = row.get("_verification_verdict")

    overall = confidence_from_evidence(
        [att["attacker_identity"]["evidence_type"]] +
        (["reported_claim"] if st["present"] else []))

    return {
        "record_type": "derived_finding",
        "dataset_version": DATASET_VERSION,
        "source_layer_version": "1.0",
        "id": rid,
        "evidence": {
            "schema": {"value": None, "evidence_type": "observed_fact",
                       "source_refs": [],
                       "note": "evidence_type vocabulary: observed_fact | reported_claim | "
                               "derived_fact | experimentally_verified | externally_attributed | "
                               "unverified | unknown"},
            "record_confidence": {"value": overall, "evidence_type": "derived_fact",
                                  "note": "weakest link across the record's derived claims"},
            "evidence_types_present": sorted(set(
                [att["attacker_identity"]["evidence_type"], "observed_fact", "reported_claim"]
                + ([ "experimentally_verified"] if row_v in ("reproduced", "not_reproduced") else []))),
        },
        "finding": {
            "id": finding.get("id"), "title": finding.get("title"),
            "severity": finding.get("severity"), "severity_source": finding.get("severity_source"),
            "record_class": finding.get("record_class"), "status": finding.get("status"),
            "judge_status": finding.get("judge_status"),
            "sponsor_response": finding.get("sponsor_response"),
            "vulnerability_classes": finding.get("vulnerability_classes"),
            "duplicate_of": (row.get("validation") or {}).get("duplicate_of") or None,
        },
        "taxonomy": tx.classify(finding),
        "security_state_transition": st,
        "attacker_model": att,
        "invariants": inv,
        "code_context_expanded": ctx,
        "dependency_graph": dependency_graph(ctx),
        "code_context": row.get("code_context") or [],
        "code_reference_only": row.get("code_reference_only") or [],
        "security_reasoning": row.get("security_reasoning") or {},
        "poc": row.get("poc") or {},
        "patch": row.get("patch") or {},
        "validation": row.get("validation") or {},
        "verification": _verification_block(rid, ex),
        "license_classification": license_class,
        "redistribution": ls.redistribution_flag(row),
        "quality": quality_block(row, ctx, att, st, inv, license_class),
        "protocol": row.get("protocol") or {},
        "source": row.get("source") or {},
        "provenance": row.get("provenance") or {},
        "original_evidence": {
            # A pointer, not an embedding. The verbatim record lives in jsonl/ and
            # is never rewritten; embedding a second copy here would triple the
            # repository size and add nothing a reader cannot look up. The sha256
            # makes the pointer checkable.
            "family": "negative_findings.jsonl" if row.get("negative_analysis") else "findings.jsonl",
            "file": "jsonl/negative_findings.jsonl" if row.get("negative_analysis")
            else "jsonl/findings.jsonl",
            "record_id": rid,
            "record_sha256": sha256_text(json.dumps(row, sort_keys=True, ensure_ascii=False)),
            "negative_analysis": row.get("negative_analysis"),
            "classifier_evidence": row.get("classifier_evidence"),
            "confidence_v1": row.get("confidence"),
            "v1_schema": {
                "poc": row.get("poc") or {},
                "patch": row.get("patch") or {},
                "validation": row.get("validation") or {},
                "security_reasoning": row.get("security_reasoning") or {},
        "provenance": pin_provenance_urls(row.get("provenance"), row.get("source")),
            },
        },
    }


def _verification_block(rid: str, ex: dict | None) -> dict:
    if not ex:
        return {"attempted": False,
                "reason": "no exploit row for this finding, so no PoC was executed",
                "evidence_type": "unknown"}
    return {
        "attempted": True,
        "verdict": ex["verdict"],
        "failure_reason": ex.get("failure_reason"),
        "poc_type": ex.get("poc_type"),
        "evidence_type": ("experimentally_verified" if ex["verdict"] in ("reproduced", "not_reproduced")
                          else "unknown"),
        "test_evidence": ex.get("evidence"),
    }


def load_verification_index() -> dict:
    idx = {}
    run_dir = Path(__file__).resolve().parent.parent / "work" / "poc_runs"
    if not run_dir.exists():
        return idx
    for f in sorted(run_dir.glob("*.json")):
        if f.name == "_all.json":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for v in data.get("verdicts", []):
            idx[v["finding_id"]] = v
    return idx


def main() -> int:
    vidx = load_verification_index()
    out = []
    for fam in ("findings.jsonl", "negative_findings.jsonl"):
        for line in open(JSONL / fam, encoding="utf-8"):
            if not line.strip():
                continue
            row = json.loads(line)
            v = vidx.get(row.get("finding", {}).get("id"))
            if v:
                row["_verification_verdict"] = v["verdict"]
            out.append(build_record(row, {row.get("finding", {}).get("id"): v} if v else {}))
    write_jsonl(DERIVED / "records.jsonl", out)

    man = {
        "generated_by": "scripts/build_derived.py",
        "records": len(out),
        "files": {"records.jsonl": len(out)},
        "attacker_kind": dict(collections.Counter(
            r["attacker_model"]["attacker_identity"]["value"] for r in out)),
        "attacker_kind_basis": dict(collections.Counter(
            r["attacker_model"]["attacker_identity"].get("basis") or "unknown" for r in out)),
        "attacker_identity_unknown": sum(
            1 for r in out if r["attacker_model"]["attacker_identity"]["evidence_type"] == "unknown"),
        "state_transition_present": sum(1 for r in out if r["security_state_transition"]["present"]),
        "state_transition_with_transactions": sum(
            1 for r in out if r["security_state_transition"]["transactions"]),
        "with_invariant": sum(1 for r in out if r["invariants"]["count"]),
        "code_context_analysed_files": sum(len(r["code_context_expanded"]) for r in out),
        "code_context_files_retrieved": sum(
            1 for r in out for c in r["code_context_expanded"] if c.get("retrieved_locally")),
        "license_classes": dict(collections.Counter(r["license_classification"] for r in out)),
        "redistribution_flagged": dict(collections.Counter(
            r["redistribution"]["flag"] or "none" for r in out)),
        "quality_code_context": dict(collections.Counter(r["quality"]["code_context"] for r in out)),
        "quality_attacker_model": dict(collections.Counter(r["quality"]["attacker_model"] for r in out)),
        "quality_state_transition": dict(collections.Counter(r["quality"]["state_transition"] for r in out)),
        "taxonomy_top_level": dict(collections.Counter(
            r["taxonomy"]["category"] for r in out)),
        "dynamic_verification": dict(collections.Counter(r["quality"]["dynamic_verification"] for r in out)),
        "invariants_invented": 0,
        "numeric_state_values_invented": 0,
    }
    write_json(DERIVED / "manifest.json", man)
    log(f"wrote derived/records.jsonl ({len(out)})")
    for k, v in man.items():
        if k not in ("generated_by", "records", "files"):
            log(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
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

import argparse
import collections
import copy
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_sources as ls  # noqa: E402
import solidity_facts as sf  # noqa: E402
import taxonomy as tx  # noqa: E402
from vlun import (  # noqa: E402
    ATTACKER_KINDS, DATASET_VERSION, DERIVED, INVARIANT_SOURCES, JSONL, REPORTS, ROOT, confidence_from_evidence, log, rec_id, sha256_text, write_json, write_jsonl,
)

# ---------------------------------------------------------------------------
# record hash scheme (versioned)
# ---------------------------------------------------------------------------
#
# `original_evidence.record_sha256` is the digest that identifies the v1 row a
# derived record was built from. Two schemes have been used, and a digest
# alone does not say which one produced it, so every record now states the
# scheme it follows. The three scheme ids:
#
#   "v1-committed-row"
#       sha256(json.dumps(row, sort_keys=True, ensure_ascii=False)) over the
#       v1 row exactly as it is committed in jsonl/. Reproducible from a
#       fresh checkout on any machine.
#
#   "v1-builder-row+verification-verdict"
#       the same digest, but over the row AS THE BUILDER SAW IT: before
#       hashing, the builder injects the private key "_verification_verdict"
#       into the row, taken from work/poc_runs/ - a git-ignored, machine-local
#       directory of PoC verdicts. The digest therefore covers a byte space
#       that is NOT reconstructible from the repository alone: a fresh
#       checkout has no work/poc_runs/, so the builder would hash a
#       different row and get a different digest. 155 of the 722 committed v1
#       records carry such a digest; the other 567 carry a plain
#       committed-row digest.
#
#   "v2-committed-row" (current scheme)
#       sha256(json.dumps(committed_row, sort_keys=True, ensure_ascii=False))
#       over the v1 row exactly as it is committed in jsonl/, with no
#       builder-injected key of any kind. The value depends only on committed
#       bytes, so it is reproducible from a fresh checkout on any machine.
#
# The historical `record_sha256` values are NOT rewritten and are never
# recomputed from a machine-local directory: they are carried forward
# verbatim from the committed layer, and `record_sha256_version` states which
# scheme each one follows. `record_sha256_v2` is the new, unambiguous digest
# and is recomputed on every build. A digest is only ever reported as
# reproduced when the bytes it claims to identify are available; see
# `verify_record_hashes`.
RECORD_HASH_SCHEME_COMMITTED_ROW = "v1-committed-row"
RECORD_HASH_SCHEME_BUILDER_ROW = "v1-builder-row+verification-verdict"
RECORD_HASH_SCHEME_V2 = "v2-committed-row"
RECORD_HASH_SCHEME_UNKNOWN = "v1-unknown"

# The private key the builder injects before hashing (see the scheme notes).
_VERIFICATION_KEY = "_verification_verdict"


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

    The result belongs in the record's TOP-LEVEL provenance: that is the
    layer the project owns and rewrites, and it is what
    scripts/validate_checks.py checks (provenance.source_urls must be
    immutable, or declared in provenance.source_urls_unpinned). The
    original_evidence.v1_schema.provenance mirror stays verbatim v1 - it is
    the frozen source layer, and the permalink gate exempts it by design.
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

    # A pointer is stated only when there is something to point at. The
    # published layer carries `source_refs` on exactly the 147 records whose
    # identity was derived by a rule, and no `source_refs` key at all on the
    # 575 whose identity was quoted from a source or left unknown. An empty
    # list would claim a pointer that does not exist, so the key is omitted
    # instead of emitted empty.
    identity = {
        "value": kind,
        "evidence_type": basis if kind != "unknown" else "unknown",
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
    }
    if kind != "unknown" and basis == "derived_fact":
        identity["source_refs"] = ["rule:build_derived.py:attacker_model"]

    return {
        "attacker_identity": identity,
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

def canonical_row_hash(row: dict) -> str:
    """The v2 digest: sha256 over the canonical JSON of a committed row.

    Canonical means `json.dumps(row, sort_keys=True, ensure_ascii=False)`
    encoded as UTF-8 - the same serialisation `scripts/check_manifests.py`
    uses for the v1 split pointers, so a v1 row and its derived record can
    be checked with one function.
    """
    return sha256_text(json.dumps(row, sort_keys=True, ensure_ascii=False))


def determine_record_hash_scheme(digest: str, committed_sha: str,
                                 committed_row: dict | None,
                                 verdict: str | None) -> str:
    """Which scheme produced `digest`? Proved, not guessed.

    `committed_sha` is the v2 digest of the v1 row as it is committed in
    jsonl/. `committed_row` is that same pristine row (needed to rebuild the
    injected variant) and `verdict` is the PoC verdict the builder would
    have injected, when it has one.
    """
    if digest == committed_sha:
        return RECORD_HASH_SCHEME_COMMITTED_ROW
    if verdict is not None and committed_row is not None:
        injected = dict(committed_row)
        injected[_VERIFICATION_KEY] = verdict
        if digest == canonical_row_hash(injected):
            return RECORD_HASH_SCHEME_BUILDER_ROW
    return RECORD_HASH_SCHEME_UNKNOWN


def _builder_injected_verdict(rec: dict):
    """The verdict the builder injected when the historical digest was made.

    `verification.prior_verdict` keeps the single-revision PoC verdict after an
    accepted L6 claim replaces `verification.verdict`, so a builder-row digest
    stays reconstructible. Records without the key use `verdict` exactly as
    before.
    """
    ver = rec.get("verification") or {}
    if "prior_verdict" in ver:
        return ver.get("prior_verdict")
    return ver.get("verdict")


def load_legacy_record_hashes(path: Path | None = None) -> dict[str, dict]:
    """The historical digests of the committed layer, by record id.

    The historical `record_sha256` of a record may cover a byte space that
    cannot be rebuilt from the repository (a digest over a row with a
    machine-local PoC verdict injected into it). Such a digest is a
    historical fact, not a computed value: it is carried forward verbatim
    and never silently recalculated. This reads the committed layer so a
    rebuild reproduces it byte for byte on any machine.
    """
    path = path or (DERIVED / "records.jsonl")
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = rec.get("id")
        ev = rec.get("original_evidence") or {}
        if rid and ev.get("record_sha256"):
            out[rid] = {
                "record_sha256": ev.get("record_sha256"),
                "record_sha256_version": ev.get("record_sha256_version"),
            }
    return out


def committed_source_rows() -> dict[str, dict]:
    """The v1 rows as they are committed in jsonl/, by record id.

    These are the bytes the record hashes identify. They are read from the
    committed source layer, never from a working copy.
    """
    out: dict[str, dict] = {}
    for fam in ("findings.jsonl", "negative_findings.jsonl"):
        path = JSONL / fam
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                row = json.loads(line)
                out[rec_id(row)] = row
    return out


def migrate_record_hashes(path: Path | None = None) -> dict:
    """Add the versioned record-hash fields to the committed layer in place.

    The derived layer is not a clean rebuild on an arbitrary machine. A
    rebuild re-resolves the cited code against the git-ignored work/ state;
    where that state is missing the rebuild degrades the immutable commit
    pins (473 citations fall back to a branch name) and re-introduces the
    taxonomy drift the committed layer was migrated away from. The
    repository's own practice is therefore that a builder change is carried
    into the committed layer surgically, with the builder's own function, so
    the layer keeps the pins it already has.

    This is that migration for the record hash scheme. It rewrites exactly
    three fields per record - `original_evidence.record_sha256_version`,
    `.record_sha256_v2` and `.record_sha256_v2_version` - and never the
    historical `.record_sha256`. The scheme of a historical digest is proved
    from committed bytes alone: the v1 source row, and the record's own
    `verification.verdict` for the records whose digest covers a row with a
    PoC verdict injected into it. No machine-local state is consulted, so
    the migration produces the same bytes on every machine.
    """
    path = path or (DERIVED / "records.jsonl")
    records = [json.loads(line) for line in
               path.read_text(encoding="utf-8").splitlines() if line.strip()]
    committed = committed_source_rows()
    counts: collections.Counter = collections.Counter()
    for rec in records:
        rid = rec.get("id")
        row = committed.get(rid)
        ev = dict(rec.get("original_evidence") or {})
        digest = ev.get("record_sha256")
        version = ev.get("record_sha256_version")
        if not version and digest and row is not None:
            version = determine_record_hash_scheme(
                digest, canonical_row_hash(row), row,
                _builder_injected_verdict(rec))
        if not version:
            version = RECORD_HASH_SCHEME_UNKNOWN
        ev["record_sha256_version"] = version
        ev["record_sha256_v2"] = (canonical_row_hash(row)
                                  if row is not None else None)
        ev["record_sha256_v2_version"] = RECORD_HASH_SCHEME_V2
        rec["original_evidence"] = ev
        counts[version] += 1
    write_jsonl(path, records)
    # The manifest is the layer's own index; it states the same scheme mix
    # the full build writes, so a reader sees it without reading 722 rows.
    man_path = path.parent / "manifest.json"
    if man_path.exists():
        man = json.loads(man_path.read_text(encoding="utf-8"))
        man["record_hash_scheme"] = dict(counts)
        man["record_hash_scheme_v2"] = RECORD_HASH_SCHEME_V2
        write_json(man_path, man)
    return {"records": len(records), "schemes": dict(counts)}


def record_hash_report(records: list[dict],
                       committed_rows: dict[str, dict]) -> dict:
    """The verification result for the record hashes, as a report.

    It says, per record, whether the historical digest reproduces against
    the bytes it claims to identify, under the scheme the record states. A
    digest is never reported as reproduced when the bytes it covers are not
    available.
    """
    reproduced: collections.Counter = collections.Counter()
    schemes: collections.Counter = collections.Counter()
    problems = verify_record_hashes(records, committed_rows)
    for rec in records:
        ev = rec.get("original_evidence") or {}
        version = ev.get("record_sha256_version") or RECORD_HASH_SCHEME_UNKNOWN
        schemes[version] += 1
        row = committed_rows.get(rec.get("id"))
        digest = ev.get("record_sha256")
        ok = False
        if row is not None and digest:
            if version == RECORD_HASH_SCHEME_COMMITTED_ROW:
                ok = digest == canonical_row_hash(row)
            elif version == RECORD_HASH_SCHEME_BUILDER_ROW:
                verdict = _builder_injected_verdict(rec)
                if verdict is not None:
                    injected = dict(row)
                    injected[_VERIFICATION_KEY] = verdict
                    ok = digest == canonical_row_hash(injected)
            elif version == RECORD_HASH_SCHEME_V2:
                ok = digest == canonical_row_hash(row)
        reproduced["reproduced" if ok else "not_reproduced"] += 1
    return {
        "generated_by": "scripts/build_derived.py",
        "layer": "derived/records.jsonl",
        "records": len(records),
        "scheme": {
            RECORD_HASH_SCHEME_COMMITTED_ROW:
                "sha256(json.dumps(row, sort_keys=True, ensure_ascii=False)) "
                "over the v1 row exactly as it is committed in jsonl/. "
                "Reproducible from a fresh checkout on any machine.",
            RECORD_HASH_SCHEME_BUILDER_ROW:
                "the same digest over the row as the builder saw it: the "
                "builder injects the private key '_verification_verdict' "
                "into the row before hashing it, from work/poc_runs/ - a "
                "git-ignored, machine-local directory. The digest therefore "
                "covers a byte space that a fresh checkout cannot rebuild. "
                "The verdict itself is committed data (verification.verdict), "
                "so the digest is still checkable everywhere.",
            RECORD_HASH_SCHEME_V2:
                "sha256(json.dumps(committed_row, sort_keys=True, "
                "ensure_ascii=False)) over the v1 row exactly as it is "
                "committed in jsonl/, with no builder-injected key. The value "
                "depends only on committed bytes.",
            RECORD_HASH_SCHEME_UNKNOWN:
                "the digest matches neither scheme; it is carried forward "
                "unchanged and is not reported as verified.",
        },
        "fields": {
            "record_sha256": "the historical digest, carried forward "
                             "verbatim; never recalculated",
            "record_sha256_version": "the scheme the historical digest "
                                     "follows",
            "record_sha256_v2": "the digest under the current scheme",
            "record_sha256_v2_version": "the scheme of record_sha256_v2",
        },
        "by_scheme": dict(sorted(schemes.items())),
        "historical_digest": {
            "reproduced": reproduced["reproduced"],
            "not_reproduced": reproduced["not_reproduced"],
            "note": "reproduced means the historical digest was recomputed "
                    "from the bytes it claims to identify, under the scheme "
                    "the record states, and matched. A digest whose bytes are "
                    "not available is counted as not reproduced, never as "
                    "verified.",
        },
        "v2_digest": {
            "reproduced": sum(
                1 for rec in records
                if (rec.get("original_evidence") or {}).get("record_sha256_v2")
                == canonical_row_hash(committed_rows[rec["id"]])
                if rec.get("id") in committed_rows),
            "not_reproduced": sum(
                1 for rec in records
                if rec.get("id") not in committed_rows
                or (rec.get("original_evidence") or {}).get("record_sha256_v2")
                != canonical_row_hash(committed_rows[rec["id"]])),
        },
        "problems": problems[:50],
        "problem_count": len(problems),
    }


def verify_record_hashes(records: list[dict], committed_rows: dict[str, dict],
                         verdicts: dict[str, str] | None = None
                         ) -> list[dict]:
    """Check every derived record's digests against the bytes they claim.

    `committed_rows` maps a record id to the v1 row as it is committed in
    jsonl/. `verdicts` maps a record id to the PoC verdict the builder
    injects; when it is absent the record's own `verification.verdict` is
    used, which is committed data and therefore available everywhere.

    Returns one dict per problem, each with the record id, the field at
    fault and what was expected. A record is accepted only when it states a
    scheme, its `record_sha256` reproduces under that scheme (or is carried
    forward as a historical digest whose scheme is stated), and its
    `record_sha256_v2` reproduces under the v2 scheme. A digest is never
    reported as reproduced when the bytes it covers are not available.
    """
    verdicts = verdicts or {}
    problems: list[dict] = []
    for rec in records:
        rid = rec.get("id")
        ev = rec.get("original_evidence") or {}
        version = ev.get("record_sha256_version")
        digest = ev.get("record_sha256")
        v2 = ev.get("record_sha256_v2")
        v2_version = ev.get("record_sha256_v2_version")
        row = committed_rows.get(rid)
        if not version:
            problems.append({"id": rid, "field": "record_sha256_version",
                             "problem": "missing scheme marker: a digest "
                                        "without a stated scheme is not "
                                        "checkable"})
            continue
        if version not in (RECORD_HASH_SCHEME_COMMITTED_ROW,
                           RECORD_HASH_SCHEME_BUILDER_ROW,
                           RECORD_HASH_SCHEME_V2,
                           RECORD_HASH_SCHEME_UNKNOWN):
            problems.append({"id": rid, "field": "record_sha256_version",
                             "problem": f"unknown scheme {version!r}"})
            continue
        if v2_version != RECORD_HASH_SCHEME_V2:
            problems.append({"id": rid, "field": "record_sha256_v2_version",
                             "problem": f"expected {RECORD_HASH_SCHEME_V2!r}, "
                                        f"got {v2_version!r}"})
        if row is None:
            problems.append({"id": rid, "field": "record_sha256",
                             "problem": "no committed source row: the bytes "
                                        "the digest claims to identify are "
                                        "not available, so the digest cannot "
                                        "be verified"})
            continue
        want_v2 = canonical_row_hash(row)
        if v2 != want_v2:
            problems.append({"id": rid, "field": "record_sha256_v2",
                             "problem": "does not match the committed source "
                                        "row under the v2 scheme"})
        if version == RECORD_HASH_SCHEME_COMMITTED_ROW:
            if digest != want_v2:
                problems.append({"id": rid, "field": "record_sha256",
                                 "problem": "does not match the committed "
                                            "source row"})
        elif version == RECORD_HASH_SCHEME_BUILDER_ROW:
            # The PoC verdict is committed data: the record carries it in
            # `verification.verdict`, so the historical digest can be
            # checked on any machine, not only where work/poc_runs/ exists.
            verdict = (verdicts.get(rid)
                       or _builder_injected_verdict(rec))
            if verdict is None:
                problems.append({"id": rid, "field": "record_sha256",
                                 "problem": "historical digest over a row "
                                            "with an injected PoC verdict; "
                                            "the verdict is not available on "
                                            "this machine, so the digest is "
                                            "carried forward and not claimed "
                                            "to be verified"})
            else:
                injected = dict(row)
                injected[_VERIFICATION_KEY] = verdict
                if digest != canonical_row_hash(injected):
                    problems.append({"id": rid, "field": "record_sha256",
                                     "problem": "does not match the source "
                                                "row with the injected PoC "
                                                "verdict"})
        elif version == RECORD_HASH_SCHEME_V2:
            if digest != want_v2:
                problems.append({"id": rid, "field": "record_sha256",
                                 "problem": "does not match the committed "
                                            "source row under the v2 scheme"})
    return problems


def build_record(row: dict, verification_index: dict,
                 committed_sha: str | None = None,
                 committed_row: dict | None = None,
                 legacy: dict | None = None,
                 authoritative: dict | None = None) -> dict:
    finding = row.get("finding") or {}
    rid = rec_id(row)
    license_class = ls.classify_record_code(row)
    ctx = expanded_context(row)
    att = attacker_model(row, ctx, finding)
    ex = verification_index.get(rid)
    st = state_transition(row, ex, ctx)
    inv = invariants_block(row, ctx)
    row_v = row.get("_verification_verdict")

    # The v2 digest: over the committed source row, with no injected key.
    if committed_sha is None and committed_row is not None:
        committed_sha = canonical_row_hash(committed_row)

    # The historical digest. When the committed layer already carries one it
    # is carried forward verbatim and never recomputed: for 155 of the 722
    # committed records it covers a byte space (the source row with a
    # machine-local PoC verdict injected into it) that cannot be rebuilt from
    # the repository alone. A digest whose scheme is not stated is proved
    # from the bytes instead of assumed.
    legacy_digest = (legacy or {}).get("record_sha256")
    legacy_version = (legacy or {}).get("record_sha256_version")
    if not legacy_digest:
        legacy_digest = sha256_text(json.dumps(row, sort_keys=True,
                                                ensure_ascii=False))
    if not legacy_version and committed_sha is not None:
        legacy_version = determine_record_hash_scheme(
            legacy_digest, committed_sha, committed_row,
            row.get(_VERIFICATION_KEY))
    if not legacy_version:
        legacy_version = RECORD_HASH_SCHEME_UNKNOWN

    overall = confidence_from_evidence(
        [att["attacker_identity"]["evidence_type"]] +
        (["reported_claim"] if st["present"] else []))

    verification = _verification_block(rid, ex, authoritative,
                                       finding_id=finding.get("id") or rid)
    # The record-level summary names `experimentally_verified` when the
    # verification block attests it - a two-revision L6 result is execution
    # evidence even when the old single-revision PoC index had no run for it.
    experimentally_verified = (
        verification.get("evidence_type") == "experimentally_verified")

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
                + (["experimentally_verified"]
                   if experimentally_verified
                   or row_v in ("reproduced", "not_reproduced") else []))),
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
        "verification": verification,
        "license_classification": license_class,
        "redistribution": ls.redistribution_flag(row),
        "quality": quality_block(row, ctx, att, st, inv, license_class),
        "protocol": row.get("protocol") or {},
        "source": row.get("source") or {},
        # The pinned provenance lives at the TOP level: this is the layer the
        # project owns and rewrites, so the immutable permalinks belong here.
        # scripts/validate_checks.py reads exactly these two fields
        # (provenance.source_urls / provenance.source_urls_unpinned) and
        # exempts the original_evidence mirror, so a pin written only into the
        # mirror would leave the shipped layer citing a mutable branch.
        "provenance": pin_provenance_urls(row.get("provenance"),
                                          row.get("source")),
        "original_evidence": {
            # A pointer, not an embedding. The verbatim record lives in jsonl/ and
            # is never rewritten; embedding a second copy here would triple the
            # repository size and add nothing a reader cannot look up. The sha256
            # makes the pointer checkable.
            "family": "negative_findings.jsonl" if row.get("negative_analysis") else "findings.jsonl",
            "file": "jsonl/negative_findings.jsonl" if row.get("negative_analysis")
            else "jsonl/findings.jsonl",
            "record_id": rid,
            # The historical digest, carried forward verbatim, and the scheme
            # it follows. See the record hash scheme notes at the top of this
            # file: a digest alone does not say which bytes it covers.
            "record_sha256": legacy_digest,
            "record_sha256_version": legacy_version,
            # The current scheme: the digest of the committed source row, with
            # no builder-injected key. Reproducible from a fresh checkout.
            "record_sha256_v2": committed_sha,
            "record_sha256_v2_version": RECORD_HASH_SCHEME_V2,
            "negative_analysis": row.get("negative_analysis"),
            "classifier_evidence": row.get("classifier_evidence"),
            "confidence_v1": row.get("confidence"),
            "v1_schema": {
                "poc": row.get("poc") or {},
                "patch": row.get("patch") or {},
                "validation": row.get("validation") or {},
                "security_reasoning": row.get("security_reasoning") or {},
                # The mirror is verbatim: it is the v1 row as it was
                # committed, mutable branch refs and all. Pinning happens in
                # the top-level provenance; a mirror that had been rewritten
                # would no longer be evidence of what v1 said.
                "provenance": row.get("provenance") or {},
            },
        },
    }


# ---------------------------------------------------------------------------
# verification: authoritative L6 merge
# ---------------------------------------------------------------------------
#
# Two evidence sources feed `verification`:
#
#   work/poc_runs/*.json
#       one single-revision PoC attempt per finding (git-ignored; used when
#       present). A run that "reproduced" a vulnerability on the audited
#       revision says nothing about the fixed revision, so this index can
#       never produce an L6 claim.
#
#   reports/verified_experiments.json
#       the controlled two-revision experiments. This is the only source from
#       which L6 may be emitted, and only when the report's own evidence
#       passes every gate in `evaluate_l6_claim`: the finding id matches, two
#       distinct full 40-hex commits resolved, byte-identical harness and test
#       file digests, the declared fail->pass polarity on both sides, and no
#       compile error or timeout.
#
# Severity, labels, a single passing run or a report verdict alone are never
# enough. When the prior index contradicts an accepted L6 claim the conflict
# is recorded: a weaker prior verdict (not_executed / inconclusive) is
# superseded by the authoritative L6 block, a stronger one (reproduced /
# not_reproduced) is kept and the conflict is stated.

L6_REPORT_VERDICT = "l6_verified_patch"
L6_LEVEL = "L6"
L6_STATUS = "VERIFIED_TWO_REVISION"
L6_EVIDENCE_TYPE = "experimentally_verified"
AUTHORITATIVE_SOURCE = "reports/verified_experiments.json"
PRIOR_SOURCE = "work/poc_runs"

# Prior verdicts an accepted two-revision claim may supersede. Anything else
# (reproduced, not_reproduced, or a value this builder does not know) is a
# stronger, executed outcome: it is never overwritten, only flagged.
L6_OVERRIDABLE_PRIOR_VERDICTS = frozenset(
    {"not_executed", "not_attempted", "inconclusive", None})

_TEST_STATUS_ALIASES = {
    "success": "pass", "pass": "pass", "passed": "pass",
    "failure": "fail", "fail": "fail", "failed": "fail",
}
# A run that never produced a pass/fail outcome cannot support any level.
_NON_OUTCOME_STATUSES = ("compile_error", "timeout", "toolchain_failure")


def _norm_test_status(value):
    """Normalise a forge per-test status to `pass` / `fail` (or None)."""
    if isinstance(value, dict):
        value = value.get("status")
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    return _TEST_STATUS_ALIASES.get(key, key)


def _authoritative_side(experiment: dict, label: str) -> dict:
    """One revision of an authoritative experiment, from the report itself."""
    revs = experiment.get("revisions") or {}
    side = revs.get(label)
    if isinstance(side, dict) and side:
        return side
    two = experiment.get("two_revision_evidence") or {}
    side = two.get(label)
    return side if isinstance(side, dict) else {}


def prior_verdict_is_stronger(prior: dict | None) -> bool:
    """Is the single-revision PoC verdict too strong for L6 to overwrite?"""
    if not isinstance(prior, dict) or not prior:
        return False
    return prior.get("verdict") not in L6_OVERRIDABLE_PRIOR_VERDICTS


def evaluate_l6_claim(finding_id: str, experiment: dict | None) -> dict:
    """Decide whether one report entry is an L6 claim this layer may emit.

    Pure: it reads only the passed dict. Every gate has to hold; the returned
    `reasons` list says which one did not, so a downgrade is never silent.
    """
    reasons: list[str] = []
    if not isinstance(experiment, dict):
        return {"accepted": False, "report_verdict": None,
                "reasons": ["no authoritative experiment recorded for this finding"],
                "evidence": None}

    verdict = experiment.get("verdict")
    if experiment.get("finding_id") != finding_id:
        reasons.append(
            f"the authoritative experiment names {experiment.get('finding_id')!r}, "
            f"not {finding_id!r}")
    if verdict != L6_REPORT_VERDICT:
        reasons.append(f"the report verdict is {verdict!r}, not {L6_REPORT_VERDICT!r}")

    two = experiment.get("two_revision_evidence") or {}
    if two.get("status") != L6_STATUS:
        reasons.append(f"the two-revision evidence status is {two.get('status')!r}, "
                       f"not {L6_STATUS!r}")
    if two.get("missing_evidence"):
        reasons.append("the report still lists missing evidence: "
                       + "; ".join(str(m) for m in two.get("missing_evidence") or []))

    vulnerable = _authoritative_side(experiment, "vulnerable")
    fixed = _authoritative_side(experiment, "fixed")
    v_commit, f_commit = vulnerable.get("commit"), fixed.get("commit")
    for label, commit in (("vulnerable", v_commit), ("fixed", f_commit)):
        if not (isinstance(commit, str) and _SHA40.match(commit)):
            reasons.append(f"the {label} revision does not name a full 40-hex commit")
    if (isinstance(v_commit, str) and isinstance(f_commit, str)
            and _SHA40.match(v_commit) and _SHA40.match(f_commit)
            and v_commit == f_commit):
        reasons.append("the vulnerable and fixed revisions name the same commit")

    resolution = two.get("commit_resolution") or {}
    if resolution.get("status") != "resolved":
        reasons.append(f"the commit resolution status is {resolution.get('status')!r}, "
                       "not 'resolved'")
    else:
        unresolved = [c for c in resolution.get("unresolved") or [] if c]
        if unresolved:
            reasons.append("the commit resolution lists unresolved commits: "
                           + ", ".join(str(c) for c in unresolved))
        resolved = {c for c in resolution.get("resolved") or [] if isinstance(c, str)}
        if resolved and not {v_commit, f_commit}.issubset(resolved):
            reasons.append("the recorded revisions are not both in the resolved commits")

    if two.get("harness_digests_match") is not True:
        reasons.append("the two revisions did not run byte-identical harness bytes")
    if two.get("test_file_digests_match") is not True:
        reasons.append("the two revisions did not run the same test file bytes")
    v_harness, f_harness = vulnerable.get("harness_digest"), fixed.get("harness_digest")
    if not (isinstance(v_harness, str) and v_harness and v_harness == f_harness):
        reasons.append("the per-side harness digests are not equal")

    v_status, f_status = vulnerable.get("status"), fixed.get("status")
    v_declared = vulnerable.get("declared_expected_status")
    f_declared = fixed.get("declared_expected_status")
    for label, status in (("vulnerable", v_status), ("fixed", f_status)):
        if status in _NON_OUTCOME_STATUSES:
            reasons.append(f"the {label} run ended in {status}, which is not an outcome")
    property_polarity = (v_declared == "fail" and f_declared == "pass"
                         and v_status == "fail" and f_status == "pass")
    if not property_polarity:
        reasons.append(
            "the recorded outcomes do not match the declared fail->pass property "
            f"polarity (vulnerable {v_status!r}, declared {v_declared!r}; "
            f"fixed {f_status!r}, declared {f_declared!r})")

    v_tests = vulnerable.get("per_test_status") or {}
    f_tests = fixed.get("per_test_status") or {}
    tests = {}
    for name in sorted(set(v_tests) | set(f_tests)):
        tests[name] = {"vulnerable": _norm_test_status(v_tests.get(name)),
                       "fixed": _norm_test_status(f_tests.get(name))}
    if not tests:
        reasons.append("no per-test status is recorded, so the test names and "
                       "statuses cannot be stated")

    if reasons:
        return {"accepted": False, "report_verdict": verdict,
                "reasons": reasons, "evidence": None}

    test_files = sorted(
        {n for n in (vulnerable.get("harness_file_digests") or {})
         if isinstance(n, str) and n.endswith(".t.sol")}
        | {n for n in (fixed.get("harness_file_digests") or {})
           if isinstance(n, str) and n.endswith(".t.sol")}
        | {n for n in (two.get("test_files") or []) if isinstance(n, str)})
    return {
        "accepted": True,
        "report_verdict": verdict,
        "reasons": [],
        "evidence": {
            "source": AUTHORITATIVE_SOURCE,
            "report_verdict": verdict,
            "classification": experiment.get("classification"),
            "repository": resolution.get("repository"),
            "commits": {"vulnerable": v_commit, "fixed": f_commit},
            "commit_resolution": resolution.get("status"),
            "harness_digest": v_harness,
            "test_files": test_files,
            "tests": tests,
        },
    }


def _l6_verification_block(claim: dict, prior: dict | None) -> dict:
    ev = claim["evidence"] or {}
    return {
        "attempted": True,
        "level": L6_LEVEL,
        "status": L6_STATUS,
        "verdict": L6_REPORT_VERDICT,
        "failure_reason": None,
        "poc_type": ev.get("classification") or (prior or {}).get("poc_type"),
        "evidence_type": L6_EVIDENCE_TYPE,
        "test_evidence": {"per_test_status": ev.get("tests") or {}},
        "evidence": ev,
    }


def _evidence_conflict(prior: dict, claim: dict, resolution: str,
                       reason: str) -> dict:
    ev = claim.get("evidence") or {}
    prior = prior or {}
    return {
        "prior": {
            "source": PRIOR_SOURCE,
            "verdict": prior.get("verdict"),
            "failure_reason": prior.get("failure_reason"),
            "poc_type": prior.get("poc_type"),
            "test_evidence": prior.get("evidence") or {},
        },
        "new": {
            "source": AUTHORITATIVE_SOURCE,
            "verdict": L6_REPORT_VERDICT,
            "level": L6_LEVEL,
            "status": L6_STATUS,
            "commits": ev.get("commits"),
            "harness_digest": ev.get("harness_digest"),
        },
        "resolution": resolution,
        "reason": reason,
    }


def _prior_verification_block(ex: dict | None) -> dict:
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


def merge_verification(prior: dict | None, authoritative: dict | None,
                       finding_id: str) -> dict:
    """Merge the single-revision PoC index with the authoritative L6 report.

    Pure helper (no file I/O) so the merge can be tested without rebuilding
    the 722-record layer. `prior` is one work/poc_runs verdict (or None);
    `authoritative` is one reports/verified_experiments.json entry (or None).
    """
    block = _prior_verification_block(prior)
    claim = evaluate_l6_claim(finding_id, authoritative)

    if not claim["accepted"]:
        if claim["report_verdict"] == L6_REPORT_VERDICT:
            # The report claims L6 but a gate failed: keep the lower block and
            # state exactly why the claim was not promoted.
            block = dict(block)
            block["l6_rejected"] = {
                "report_verdict": claim["report_verdict"],
                "reasons": list(claim["reasons"]),
            }
        return block

    if prior_verdict_is_stronger(prior):
        # A single-revision outcome (L5 reproduced, or a not_reproduced run) is
        # not overwritten by a two-revision claim; the disagreement is recorded.
        block = dict(block)
        block["evidence_conflict"] = _evidence_conflict(
            prior, claim, "prior_kept",
            "the prior PoC index records an executed verdict that is not "
            "superseded by the two-revision claim; the prior block is kept")
        return block

    l6 = _l6_verification_block(claim, prior)
    if isinstance(prior, dict) and prior:
        l6["prior_verdict"] = prior.get("verdict")
        l6["evidence_conflict"] = _evidence_conflict(
            prior, claim, "authoritative_l6_kept",
            "the prior PoC index has no two-revision comparison "
            f"(verdict {prior.get('verdict')!r}), so the authoritative L6 "
            "evidence is kept and the prior verdict is preserved above")
    return l6


# The record fields a verification block is allowed to drive. Everything else on
# a record is left exactly as published, because those fields are computed from
# the audited source trees (`V1/clones/`), which a checkout that has only the
# published layer does not hold.
L6_SURGICAL_FIELDS = ("verification", "evidence")


def derive_l6_record(rec: dict, prior: dict | None,
                     authoritative_entry: dict | None) -> int:
    """Apply the authoritative two-revision L6 evidence to one published record.

    Returns 1 when the record changed. Only the verification block and the
    derived-flag list it feeds are written; a record whose clone-dependent
    fields cannot be recomputed here keeps them byte-identical, so the layer
    gains the L6 evidence and loses nothing.
    """
    fid = (rec.get("finding") or {}).get("id") or rec.get("id")
    block = merge_verification(prior, authoritative_entry, fid)
    before = json.dumps({k: rec.get(k) for k in L6_SURGICAL_FIELDS},
                        sort_keys=True)
    rec["verification"] = block
    ev = rec.get("evidence")
    if isinstance(ev, dict) and isinstance(ev.get("evidence_types_present"), list):
        types = set(ev["evidence_types_present"])
        if block.get("evidence_type") == L6_EVIDENCE_TYPE:
            types.add(L6_EVIDENCE_TYPE)
        elif prior and prior.get("verdict") in ("reproduced", "not_reproduced"):
            # The flag came from the single-revision verdict, which is kept.
            types.add(L6_EVIDENCE_TYPE)
        else:
            types.discard(L6_EVIDENCE_TYPE)
        ev["evidence_types_present"] = sorted(types)
    after = json.dumps({k: rec.get(k) for k in L6_SURGICAL_FIELDS}, sort_keys=True)
    return 0 if before == after else 1


def verification_level_counts(records: list) -> dict:
    """Level distribution over the derived records' verification blocks.

    Only records whose block states a level are counted; a single-revision PoC
    verdict is not a level, so `dynamic_verification` stays a separate axis.
    """
    out: dict[str, int] = {}
    for r in records:
        lvl = (r.get("verification") or {}).get("level")
        if lvl:
            out[lvl] = out.get(lvl, 0) + 1
    return out


def derive_l6_in_place(root: Path) -> dict:
    """Merge the authoritative L6 evidence into the published layer, in place.

    A full rebuild is not the carry-in path on a checkout that has no `V1/clones/`
    and no git-ignored `work/poc_runs/`: the same-record comparison shows 390
    of 722 records otherwise changing their code-context, licence and
    redistribution fields for reasons that have nothing to do with L6. This mode
    writes only the verification block and its derived flag.
    """
    path = root / "derived" / "records.jsonl"
    records = [json.loads(line) for line in
               path.read_text(encoding="utf-8").splitlines() if line.strip()]
    priors = load_committed_verification(path)
    authoritative = load_authoritative_verification(
        root / "reports" / "verified_experiments.json")
    changed = 0
    for rec in records:
        fid = (rec.get("finding") or {}).get("id") or rec.get("id")
        claims_l6 = (rec.get("verification") or {}).get("level") == L6_LEVEL
        if fid not in authoritative and not claims_l6:
            # A record the report does not mention is left alone - unless it is
            # already published as L6. Skipping those too would make a withdrawn
            # or deleted experiment invisible: the stale L6 block, its
            # `experimentally_verified` flag and the manifest count would survive
            # every future run. Visiting it with no authoritative entry demotes
            # it back to its single-revision verdict.
            continue
        changed += derive_l6_record(rec, priors.get(fid), authoritative.get(fid))
    levels = verification_level_counts(records)
    if changed:
        write_jsonl(path, records)
    manifest_path = root / "derived" / "manifest.json"
    if manifest_path.exists():
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
        man["derived_verification_levels"] = levels
        write_json(manifest_path, man)
    return {"records": len(records), "changed": changed,
            "levels": levels, "authoritative": len(authoritative),
            "priors": len(priors)}


def _verification_block(rid: str, ex: dict | None,
                        authoritative: dict | None = None,
                        finding_id: str | None = None) -> dict:
    return merge_verification(ex, authoritative, finding_id or rid)


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


def load_committed_verification(path: Path | None = None) -> dict[str, dict]:
    """The published derived layer, read back as the PoC verdict index.

    `work/poc_runs/` is git-ignored and machine-local, so a fresh checkout has
    no single-revision verdicts to inject - yet 155 of the 722 published records
    carry one, and 140 of those (`not_executed`) exist nowhere else in the
    repository. Rebuilding without them would delete real execution findings and
    break the digests that were taken over the row with the verdict injected.
    The committed layer is the durable copy of that index, so it is read back
    here: the same carry-forward rule already applied to the historical record
    digests (see the record-hash scheme notes at the top of this module).

    An L6 block is not a single-revision verdict, so it is never fed back as
    one; where an L6 block superseded a prior verdict, the prior is taken from
    the `evidence_conflict.prior` record the merge itself wrote, which makes a
    second rebuild produce byte-identical output to the first.
    """
    path = path or (DERIVED / "records.jsonl")
    idx: dict[str, dict] = {}
    if not path.exists():
        return idx
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        fid = (rec.get("finding") or {}).get("id") or rec.get("id")
        if not fid:
            continue
        ver = rec.get("verification") or {}
        prior = (ver.get("evidence_conflict") or {}).get("prior")
        if isinstance(prior, dict) and prior.get("verdict"):
            idx[fid] = {"finding_id": fid, "verdict": prior["verdict"],
                        "failure_reason": prior.get("failure_reason"),
                        "poc_type": prior.get("poc_type"),
                        "evidence": prior.get("test_evidence")}
            continue
        verdict = ver.get("verdict")
        if not verdict or verdict == L6_REPORT_VERDICT:
            continue
        idx[fid] = {"finding_id": fid, "verdict": verdict,
                    "failure_reason": ver.get("failure_reason"),
                    "poc_type": ver.get("poc_type"),
                    "evidence": ver.get("test_evidence")}
    return idx


def load_authoritative_verification(path: Path | None = None) -> dict[str, dict]:
    """The controlled two-revision experiments, keyed by finding id.

    This is the only source from which an L6 level can be emitted. A missing or
    malformed report yields an empty index, never an inferred claim.
    """
    path = path or (REPORTS / "verified_experiments.json")
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, dict] = {}
    for exp in doc.get("experiments") or []:
        if isinstance(exp, dict) and isinstance(exp.get("finding_id"), str):
            out[exp["finding_id"]] = exp
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write-record-hash-report", action="store_true",
                    help="write reports/record_hash_verification.json")
    ap.add_argument("--migrate-record-hashes", action="store_true",
                    help="add the versioned record-hash fields to the "
                         "committed derived layer in place, without a "
                         "rebuild (see migrate_record_hashes)")
    ap.add_argument("--derive-l6-only", action="store_true",
                    help="merge the authoritative two-revision L6 evidence into "
                         "the published derived layer in place, touching only "
                         "each record's verification block and its derived "
                         "flag (see derive_l6_in_place)")
    args = ap.parse_args()
    if args.derive_l6_only:
        res = derive_l6_in_place(ROOT)
        log(f"derived/records.jsonl: {res['records']} records, "
            f"{res['changed']} changed, levels={res['levels']}, "
            f"authoritative={res['authoritative']}, priors={res['priors']}")
        return 0
    if args.migrate_record_hashes:
        res = migrate_record_hashes()
        log(f"migrated record hashes in derived/records.jsonl: {res}")
        return 0
    if args.write_record_hash_report:
        records = [json.loads(line) for line in
                   (DERIVED / "records.jsonl").read_text(
                       encoding="utf-8").splitlines() if line.strip()]
        rep = record_hash_report(records, committed_source_rows())
        out = REPORTS / "record_hash_verification.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        write_json(out, rep)
        log(f"wrote {out.relative_to(ROOT)}: {rep['records']} records, "
            f"reproduced={rep['historical_digest']['reproduced']} "
            f"not_reproduced={rep['historical_digest']['not_reproduced']}")
        return 0
    vidx = load_verification_index()
    # The machine-local PoC index is absent on a fresh checkout; the published
    # layer holds the same verdicts, so they are carried forward instead of
    # being rebuilt as "no run". Where poc_runs does exist it is the primary
    # source and wins per finding.
    for fid, entry in load_committed_verification().items():
        vidx.setdefault(fid, entry)
    # The controlled two-revision experiments. This is merged in addition to
    # the single-revision PoC index; it is the only source that can emit L6.
    authoritative = load_authoritative_verification()
    # The historical digests of the committed layer, carried forward verbatim.
    legacy_hashes = load_legacy_record_hashes()
    out = []
    for fam in ("findings.jsonl", "negative_findings.jsonl"):
        for line in open(JSONL / fam, encoding="utf-8"):
            if not line.strip():
                continue
            row = json.loads(line)
            rid = rec_id(row)
            # The digest of the row as it is committed, computed before the
            # builder injects anything into it. The pristine row is kept so
            # the injected variant can be rebuilt when a verdict exists.
            committed_sha = canonical_row_hash(row)
            committed_row = None
            v = vidx.get(row.get("finding", {}).get("id"))
            if v:
                committed_row = copy.deepcopy(row)
                row[_VERIFICATION_KEY] = v["verdict"]
            out.append(build_record(row, {rid: v} if v else {},
                                    committed_sha=committed_sha,
                                    committed_row=committed_row,
                                    legacy=legacy_hashes.get(rid),
                                    authoritative=authoritative.get(
                                        row.get("finding", {}).get("id"))))
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
        "derived_verification_levels": verification_level_counts(out),
        # The record hash scheme is stated per record (original_evidence.
        # record_sha256_version); the counters say how many records follow
        # each scheme, so a reader can see the mix without reading 722 rows.
        "record_hash_scheme": dict(collections.Counter(
            (r["original_evidence"] or {}).get("record_sha256_version")
            or "none" for r in out)),
        "record_hash_scheme_v2": RECORD_HASH_SCHEME_V2,
    }
    write_json(DERIVED / "manifest.json", man)
    log(f"wrote derived/records.jsonl ({len(out)})")
    for k, v in man.items():
        if k not in ("generated_by", "records", "files"):
            log(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
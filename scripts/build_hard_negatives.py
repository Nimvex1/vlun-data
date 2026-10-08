#!/usr/bin/env python3
"""P2: turn the rejection corpus into hard negatives.

v1 stores a label plus a one-line reason. Where the code is in hand, this adds
a structured, mechanically grounded explanation of *why the claim does not
hold* — and where the code is not conclusive, it says so.

The hard rule: a blocking condition is only asserted when one of these is true

  1. a public judge/sponsor comment states it      -> reported_claim
  2. the code mechanically shows a gate that the
     claim's own text denies                       -> derived_fact

A gate is mechanical in exactly three forms, all read off the function the
claim itself names:

  a. an onlyX-style modifier on the declaration,
  b. an inline caller-identity check (`require(msg.sender == x)` and the like)
     in the function body,
  c. internal/private visibility, which blocks a direct external call.

Anything else is `unknown`. Inventing a plausible-sounding rejection reason is
the exact failure mode this dataset exists to prevent, so `unknown` is a
first-class, counted outcome.

    python scripts/build_hard_negatives.py
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solidity_facts as sf  # noqa: E402
from vlun import (  # noqa: E402
    DERIVED, JSONL, REPORTS, log, rec_id, sha256_text, snippet_entries, write_json, write_jsonl,
)

# A claim that asserts unprivileged reach. Only such a claim can be *contradicted*
# by a gate observed in code — a claim that never asserts unauthenticated
# access is not refuted by the presence of a modifier. The vocabulary is kept
# tight: each alternative must literally deny that caller identity matters.
UNPRIVILEGED_ASSERTION = re.compile(
    r"\b(anyone|any user|any address|any account|any wallet|any party|any caller|"
    r"any external (?:caller|account|party|user|contract)|arbitrary|"
    r"permissionless|unrestricted|unauthenticated|unprotected|"
    r"missing access control|no access control|lacks? access control|lacking access control|"
    r"without (?:any )?(?:restriction|permission|authorization|check)|"
    r"malicious user|any third party|unauthori[sz]ed|publicly callable)\b", re.I)


def _fn_in_claim(fname: str | None, claim_text: str) -> bool:
    return bool(fname) and fname.lower() in claim_text.lower()


def evidence(value, etype, refs=None, confidence=None, note=None):
    d = {"value": value if value not in ("", None) else None, "evidence_type": etype,
         "source_refs": refs or []}
    if confidence:
        d["confidence"] = confidence
    if note:
        d["note"] = note
    return d


def code_refs(row) -> list[str]:
    urls = [u for u in (row.get("provenance", {}) or {}).get("source_urls", []) if "/blob/" in u]
    return urls[:6]


def code_block(row) -> list[dict]:
    """Code entries for a record, each pinned and hashed."""
    out = []
    for e in snippet_entries(row):
        out.append({
            "file": e.get("file"), "contract": e.get("contract"), "function": e.get("function"),
            "line_start": e.get("line_start"), "line_end": e.get("line_end"),
            "commit_sha": e.get("commit_sha"), "source_url": e.get("source_url"),
            "line_range_verified": bool(e.get("line_range_verified")),
            "documented_intent": e.get("documented_intent") or None,
            "snippet_sha256": sha256_text(e["snippet"]),
            "snippet": e["snippet"],
        })
    return out


def _caller_identity_guards(fn: dict) -> list[dict]:
    """Body guards that compare the caller's identity against something else.

    `require(msg.sender == owner)` and its siblings are mechanically equivalent
    to a role modifier. Only equality/inequality comparisons whose checked side
    names msg.sender or tx.origin qualify; input validation (`amount > 0`) does
    not.
    """
    out = []
    for g in fn.get("guards", []):
        subject = (g.get("subject") or "")
        comparison = (g.get("comparison") or "")
        if g.get("operator") not in ("==", "!="):
            continue
        caller_side = None
        if "msg.sender" in subject:
            caller_side, other = subject, comparison
        elif "msg.sender" in comparison:
            caller_side, other = comparison, subject
        else:
            continue
        # the other side must name some identity that is not the caller itself
        other_id = other.replace("msg.sender", "").strip()
        if not other_id:
            continue
        out.append({"kind": "inline_caller_identity_check",
                    "guard": f"{subject} {g['operator']} {comparison}",
                    "operator": g["operator"],
                    "required_identity": other_id[:80],
                    "line": g.get("line")})
    return out


def gate_for(snippets: list[dict], claim_text: str = "") -> dict | None:
    """First mechanically observed gate across the record's code.

    Three gate kinds, in order of how directly they contradict an unprivileged
    reach assertion: a modifier role on the declaration, an inline caller-identity
    check in the body, and internal/private visibility. `named_in_claim` says
    whether the gated function is the one the submission actually talks about.
    When it is not, the gate is real but cannot be used to refute the claim, so
    the caller records it at low confidence instead of dropping it.
    """
    fallback = None
    for blk in snippets:
        a = sf.analyse(blk["snippet"], blk.get("function"))
        for fn in a["functions"]:
            named = _fn_in_claim(fn["name"], claim_text)
            gate = None
            if fn["required_roles"]:
                gate = {"kind": "modifier_role_gate",
                        "file": blk["file"], "commit_sha": blk["commit_sha"],
                        "function": fn["name"], "line": fn["declared_at_line"],
                        "modifiers": fn["modifiers"], "roles": fn["required_roles"],
                        "visibility": fn["visibility"],
                        "evidence_type": "derived_fact",
                        "rule": "onlyX-style modifier on the function declaration",
                        "rule_source": "scripts/solidity_facts.py:functions"}
            else:
                id_guards = _caller_identity_guards(fn)
                if id_guards:
                    g = id_guards[0]
                    gate = {"kind": "inline_caller_identity_check",
                            "file": blk["file"], "commit_sha": blk["commit_sha"],
                            "function": fn["name"], "line": g["line"],
                            "modifiers": fn["modifiers"], "roles": [],
                            "guard": g["guard"], "required_identity": g["required_identity"],
                            "visibility": fn["visibility"],
                            "evidence_type": "derived_fact",
                            "rule": "inline caller-identity check in the function body",
                            "rule_source": "scripts/solidity_facts.py:_guards"}
                elif fn["visibility"] in ("internal", "private"):
                    gate = {"kind": "internal_visibility_gate",
                            "file": blk["file"], "commit_sha": blk["commit_sha"],
                            "function": fn["name"], "line": fn["declared_at_line"],
                            "modifiers": fn["modifiers"], "roles": [],
                            "visibility": fn["visibility"],
                            "evidence_type": "derived_fact",
                            "rule": "internal/private visibility blocks a direct external call",
                            "rule_source": "scripts/solidity_facts.py:functions"}
            if gate is None:
                continue
            gate["named_in_claim"] = named
            if named:
                return gate
            if fallback is None:
                fallback = gate
    return fallback


def build_negative(row: dict) -> dict:
    rid = rec_id(row)
    na = row.get("negative_analysis") or {}
    finding = row.get("finding") or {}
    snippets = code_block(row)
    claim_text = " ".join(str(x) for x in [
        na.get("why_it_looked_plausible"), finding.get("title"),
        (finding.get("summary") or ""), (finding.get("root_cause") or "")])
    refs = code_refs(row)
    basis = na.get("rejection_basis") or "unknown"

    # ---- blocking condition: only asserted with a licence -----------------
    blocking = evidence(None, "unknown")
    if basis == "public_judge_or_sponsor_comment":
        stmts = na.get("judge_and_sponsor_statements") or []
        if stmts:
            first = stmts[0]
            text = first.get("text") if isinstance(first, dict) else str(first)
            role = first.get("role") if isinstance(first, dict) else None
            blocking = evidence(text, "reported_claim",
                                refs=[u for u in refs[:3]] + (na.get("judge_and_sponsor_statements") or [{}])
                                if isinstance(na.get("judge_and_sponsor_statements"), list) else refs[:3],
                                note=f"attributed to {role}" if role else None)
    elif UNPRIVILEGED_ASSERTION.search(claim_text):
        gate = gate_for(snippets, claim_text)
        if gate and gate["named_in_claim"]:
            if gate["kind"] == "modifier_role_gate":
                statement = (f"the claim's own target `{gate['function']}` in {gate['file']} is "
                             f"declared with {', '.join(gate['modifiers'])}, so reaching it "
                             f"requires {', '.join(gate['roles'])}")
            elif gate["kind"] == "inline_caller_identity_check":
                statement = (f"the claim's own target `{gate['function']}` in {gate['file']} "
                             f"contains `{gate['guard']}`, so reaching it requires being "
                             f"{gate['required_identity']}")
            else:
                statement = (f"the claim's own target `{gate['function']}` in {gate['file']} is "
                             f"`{gate['visibility']}`, so an external caller cannot reach it "
                             f"directly")
            blocking = evidence(
                statement,
                "derived_fact",
                refs=[f"{gate['file']}@{gate['commit_sha']}#L{gate['line']}"],
                confidence="high",
                note=f"rule: {gate['rule']} ({gate['rule_source']})")
        elif gate:
            blocking = evidence(
                f"a gate ({gate['rule']}) is present on "
                f"`{gate['function']}` in {gate['file']}, but that function is not the one the "
                f"submission names, so it does not by itself refute the claim",
                "derived_fact",
                refs=[f"{gate['file']}@{gate['commit_sha']}#L{gate['line']}"],
                confidence="low",
                note="a gate on a neighbouring function is context, not a refutation")

    # ---- actual protocol behaviour ---------------------------------------
    observed = []
    for blk in snippets[:4]:
        a = sf.analyse(blk["snippet"], blk.get("function"))
        t = a.get("target_function")
        observed.append({
            "file": blk["file"], "function": blk.get("function"),
            "documented_intent": blk.get("documented_intent"),
            "visibility": (t or {}).get("visibility"), "mutability": (t or {}).get("mutability"),
            "modifiers": (t or {}).get("modifiers"), "required_roles": (t or {}).get("required_roles"),
            "guards": (t or {}).get("guards", [])[:4],
            "signals": (t or {}).get("signals"),
            "evidence_type": "observed_fact",
            "source": {"commit_sha": blk["commit_sha"], "source_url": blk["source_url"],
                       "snippet_sha256": blk["snippet_sha256"],
                       "line_range_verified": blk["line_range_verified"]},
        })

    why_fails = evidence(None, "unknown")
    if blocking["evidence_type"] in ("reported_claim", "derived_fact"):
        kind = (blocking.get("note") or "")
        why_fails = evidence(
            ("the path the claim depends on is not externally reachable, so the claimed "
             "external attack cannot be executed as stated"
             if "internal/private visibility" in kind else
             "the path the claim depends on requires a caller the claim does not control, so an "
             "unprivileged attacker cannot reach it"),
            "derived_fact" if blocking["evidence_type"] == "derived_fact" else "reported_claim",
            refs=blocking["source_refs"])

    verdict_et = {"public_judge_or_sponsor_comment": "reported_claim",
                  "public_discussion_no_verdict_attributed": "reported_claim",
                  "label_only": "externally_attributed"}.get(basis, "unknown")

    return {
        "record_type": "hard_negative",
        "dataset_version": "2.0",
        "source_record": {"family": "negative_findings.jsonl", "id": rid,
                          "finding_id": finding.get("id"), "repository": row["source"]["repository"]},
        "verdict": {
            "value": "not_a_vulnerability",
            "evidence_type": verdict_et,
            "rejection_basis": basis,
            "source_label": finding.get("status"),
            "source_refs": (row.get("validation", {}) or {}).get("evidence", [])[:4],
        },
        "candidate_claim": evidence(na.get("why_it_looked_plausible") or finding.get("title"),
                                    "reported_claim", refs=refs[:4]),
        "why_claim_looks_plausible": evidence(na.get("why_it_looked_plausible"), "reported_claim", refs=refs[:4]),
        "relevant_code": snippets,
        "observed_code_facts": observed,
        "actual_protocol_behavior": evidence(None, "unknown",
                                              note="the rejection reason in the source is a label; "
                                                   "no public statement of the correct behaviour exists"),
        "blocking_condition": blocking,
        "why_exploit_fails": why_fails,
        "attacker_model": attacker_model(snippets),
        "original_evidence": {
            "negative_analysis": na,
            "validation": row.get("validation"),
            "finding": {k: finding.get(k) for k in
                        ("id", "title", "severity", "status", "record_class", "summary", "root_cause")},
            "provenance": row.get("provenance"),
        },
        "quality": quality(verdict_et, blocking, snippets, basis),
    }


def attacker_model(snippets: list[dict]) -> dict:
    roles, conds, gates = set(), set(), []
    restricted = False
    for blk in snippets:
        a = sf.analyse(blk["snippet"], blk.get("function"))
        for fn in a["functions"]:
            roles.update(fn["required_roles"])
            conds.update(fn["operational_conditions"])
            if _caller_identity_guards(fn):
                restricted = True
        t = a.get("target_function")
        if t:
            if t["visibility"] in ("internal", "private"):
                restricted = True
            gates.append(sf.access_control_summary(a))
    if roles or restricted:
        kind = "privileged"
    elif any(g["verdict"] == "no_check_observed" for g in gates):
        kind = "unprivileged"
    else:
        kind = "unknown"
    return {
        "attacker_kind": kind,
        "evidence_type": "derived_fact" if kind != "unknown" else "unknown",
        "required_roles": sorted(roles),
        "trusted_roles": sorted(roles),
        "operational_conditions": sorted(conds),
        "per_function_access_control": gates[:6],
        "rule": ("any onlyX modifier, inline caller-identity check, or internal/private "
                 "visibility on a cited function implies a restricted caller"),
    }


def quality(verdict_et, blocking, snippets, basis) -> dict:
    grounded = blocking["evidence_type"] in ("reported_claim", "derived_fact")
    return {
        "provenance": "high" if verdict_et != "unknown" else "low",
        "code_context": "high" if snippets else "none",
        "negative_reasoning": ("code_grounded" if grounded else
                               ("label_only" if basis == "label_only" else "reported_only")),
        "dynamic_verification": "not_attempted",
        "evidence_types_present": sorted({verdict_et, blocking["evidence_type"]}),
    }


def main() -> int:
    rows = [json.loads(l) for l in open(JSONL / "negative_findings.jsonl", encoding="utf-8") if l.strip()]
    out = [build_negative(r) for r in rows]
    write_jsonl(DERIVED / "hard_negatives.jsonl", out)

    grounded = sum(1 for o in out if o["blocking_condition"]["evidence_type"] == "derived_fact")
    reported = sum(1 for o in out if o["blocking_condition"]["evidence_type"] == "reported_claim")
    with_code = sum(1 for o in out if o["relevant_code"])
    stats = {
        "generated_by": "scripts/build_hard_negatives.py",
        "total": len(out),
        "with_redistributed_code": with_code,
        "with_reference_only_code": sum(1 for o in out if not o["relevant_code"]),
        "blocking_condition_derived_from_code": grounded,
        "blocking_condition_reported_by_source": reported,
        "blocking_condition_unknown": len(out) - grounded - reported,
        "verdict_attribution": dict(collections.Counter(o["verdict"]["evidence_type"] for o in out)),
        "attacker_kind": dict(collections.Counter(o["attacker_model"]["attacker_kind"] for o in out)),
        "negative_reasoning": dict(collections.Counter(o["quality"]["negative_reasoning"] for o in out)),
        "invariants_invented": 0,
        "note": "blocking_condition is unknown for the majority. That is the correct answer "
                "when the only public evidence is a rejection label.",
    }
    write_json(REPORTS / "hard_negative_stats.json", stats)
    log(f"wrote derived/hard_negatives.jsonl ({len(out)})")
    log(f"  code available          : {with_code}")
    log(f"  blocking cond. derived  : {grounded}")
    log(f"  blocking cond. reported : {reported}")
    log(f"  blocking cond. unknown  : {stats['blocking_condition_unknown']}")
    log(f"  attacker kind           : {stats['attacker_kind']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
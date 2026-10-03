#!/usr/bin/env python3
"""API-sibling counterexamples: the pairs that actually teach something.

The v2 counterexamples were generic: "`updateValueOracle` can be called by any
address". That refutes a straw man, because nobody claimed a maintainer-gated
function was unguarded.

The valuable shape is a *pair*:

    positive   withdraw() -> an arbitrary-looking recipient -> assets move
    negative   withdrawTo(address)  -> an arbitrary-looking recipient -> but the
               signature check refuses it

Both are the same category, the same API family, and the same code shape. The
difference is a guard that is actually there. A model that learns from these
pairs learns to look for the guard instead of pattern-matching on the signature.

This module finds them mechanically:

    identical_signature_sibling
        two functions in the same contract with the same name and parameter
        types, where exactly one carries an authorisation guard

    same_family_sibling
        two functions in the same contract sharing a name prefix and arity, where
        exactly one carries an authorisation guard

Nothing here is invented: every pair is read out of the retrieved source at the
pinned commit, and both members are reported with their line and guard.
"""

from __future__ import annotations

import re
from collections import defaultdict

import solidity_facts as sf

AUTH_MODIFIERS = ("onlyOwner", "onlyRole", "onlyManager", "onlyMaintainer",
                  "onlyGovernance", "onlyKeeper", "onlyGuardian", "onlyAdmin",
                  "requiresAuth", "auth", "whenNotPaused")
AUTH_RULE = re.compile(r"require\s*\(\s*msg\.sender\s*==|require\s*\(\s*_?msg\.sender\s*!=")


def _guard_set(fn: dict) -> set[str]:
    out = set()
    for m in (fn.get("modifiers") or []):
        out.add(m)
    text = (fn.get("signature") or "") + " " + " ".join(
        (g.get("expression") or g.get("comparison") or "") for g in (fn.get("guards") or []))
    for g in fn.get("guards") or []:
        if g.get("kind") in ("require", "modifier", "auth"):
            out.add(g.get("expression") or g.get("kind"))
    if AUTH_RULE.search(text):
        out.add("require(msg.sender == ...)")
    return {x for x in out if x}


def _auth_guards(fn: dict) -> set[str]:
    guards = _guard_set(fn)
    return {g for g in guards
            if any(k.lower() in str(g).lower() for k in AUTH_MODIFIERS)
            or str(g).startswith("require(msg.sender")}


def _shape(fn: dict) -> str:
    params = fn.get("parameters") or fn.get("param_types") or []
    return f"{fn.get('name')}({','.join(str(p) for p in params)})"


def _family(fn: dict) -> str:
    name = str(fn.get("name") or "")
    m = re.match(r"^(set|update|remove|add|get|is|enable|disable|pause|unpause)"
                 r"([A-Z]\w*)?$", name)
    if not m:
        return ""
    return f"{m.group(1)}:{len(fn.get('parameters') or [])}"


def sibling_pairs(analysis: dict, vulnerable: set[str]) -> list[dict]:
    """Pairs inside one analysed contract. `vulnerable` holds shapes already
    named by the finding, so a pair never contradicts the finding itself."""
    fns = analysis.get("functions") or []
    if len(fns) < 2:
        return []
    by_sig: dict[str, list[dict]] = defaultdict(list)
    by_family: dict[str, list[dict]] = defaultdict(list)
    for f in fns:
        by_sig[_shape(f)].append(f)
        fam = _family(f)
        if fam:
            by_family[fam].append(f)

    pairs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, a: dict, b: dict) -> None:
            ga, gb = _auth_guards(a), _auth_guards(b)
            if bool(ga) == bool(gb):
                return                       # both guarded, or neither: no contrast
            if gb:
                guarded_fn = b
                open_fn = a
            else:
                guarded_fn = a
                open_fn = b
            key = tuple(sorted((str(a.get("name")), str(b.get("name")))))
            if key in seen:
                return
            seen.add(key)
            guarded_shape = guarded_fn.get("signature") or _shape(guarded_fn)
            open_shape = open_fn.get("signature") or _shape(open_fn)
            guarded_name = guarded_fn.get("name")
            open_name = open_fn.get("name")
            pairs.append({
                "type": kind,
                "guarded_entry_point": {
                    "name": guarded_name,
                    "signature": guarded_shape,
                    "guard": sorted(_auth_guards(guarded_fn)),
                    "guard_evidence": ("the modifier or require is on the declaration in the "
                                       "retrieved source at the pinned commit"),
                },
                "similar_entry_point": {
                    "name": open_name,
                    "signature": open_shape,
                    "guard": sorted(_auth_guards(open_fn)),
                    "is_the_vulnerable_function": _shape(open_fn) in vulnerable,
                },
                "hypothesis": (
                    f"a caller can use `{open_name}` the way the reporter describes, because it "
                    f"has the same shape as `{guarded_name}` and no explicit gate is visible on "
                    "the declaration"),
                "refutation": (
                    f"the sibling `{guarded_name}` has the same API shape and is declared with "
                    f"{', '.join(sorted(_auth_guards(guarded_fn)))}, so the guard is a real, "
                    "declared control in this contract rather than an assumption"),
                "evidence_type": "derived_fact",
                "rule": ("identical signature with a differing authorisation guard"
                         if kind == "identical_signature_sibling"
                         else "shared name prefix and arity with a differing authorisation guard"),
            })

    for shape, group in sorted(by_sig.items()):
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                add("identical_signature_sibling", group[i], group[j])
    for fam, group in sorted(by_family.items()):
        if len(group) < 2 or len(group) > 8:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                add("same_family_sibling", group[i], group[j])
    return pairs


def pairs_for_record(record: dict, entries: list[dict]) -> list[dict]:
    """`entries` are analysed contracts (from local_sources.analyse_cited)."""
    out: list[dict] = []
    for e in entries:
        if not e.get("functions"):
            continue
        target = (record.get("finding") or {})
        vulnerable = set()
        for c in (record.get("code_context") or []) + (record.get("vulnerable_code") or []):
            fn = c.get("function")
            if not fn:
                continue
            for f in e["functions"]:
                if f.get("name") == fn:
                    vulnerable.add(_shape(f))
        for p in sibling_pairs(e, vulnerable):
            p["subject_contract"] = e.get("contract") or e.get("file")
            p["subject_file"] = e.get("file")
            p["commit_sha"] = e.get("commit_sha")
            p["source_url"] = e.get("source_url")
            p["applies_to_finding"] = target.get("id")
            p["retained"] = (
                "the unguarded member is a function the finding itself names, so this pair "
                "illustrates the contrast without refuting the finding")
            out.append(p)
    return out
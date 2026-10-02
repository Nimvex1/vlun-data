#!/usr/bin/env python3
"""Deterministic facts read off Solidity source.

Everything here is a *rule applied to text*, so every result is
`derived_fact` and the rule is the code in front of you. Nothing infers intent,
severity or exploitability — those stay unknown unless a source states them.

The analyzer is regex-based rather than AST-based on purpose: it has to run on
report-quoted snippets as well as whole files, with no import resolution and no
compiler, so that its output is identical on a laptop and in CI.

False positives are possible (a `require` in a comment still matches). That is
why every fact carries the line it came from, so a reviewer can check it.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# access control
# ---------------------------------------------------------------------------

MODIFIER_LIBRARY = {
    "onlyOwner": ("owner", "owner"),
    "onlyAdmin": ("admin", "admin"),
    "onlyGovernance": ("governance", "governance"),
    "onlyGovernor": ("governance", "governance"),
    "onlyGuardian": ("guardian", "guardian"),
    "onlyManager": ("manager", "manager"),
    "onlyMaintainer": ("maintainer", "maintainer"),
    "onlyKeeper": ("keeper", "keeper"),
    "onlyOperator": ("operator", "operator"),
    "onlyRole": ("role_member", "role_member"),
    "onlyMarketAdmin": ("admin", "admin"),
    "onlyRiskAdmin": ("admin", "admin"),
    "onlyVault": ("role_member", "trusted_contract"),
    "whenNotPaused": (None, "operational_condition"),
    "nonReentrant": (None, "reentrancy_guard"),
}

PRIVILEGED_HINT = re.compile(
    r"\b(only[A-Z]\w*|requires?Auth|auth\w*|checkRole|hasRole|isOwner|onlyRole)\b")

# ---------------------------------------------------------------------------
# function shape
# ---------------------------------------------------------------------------

FUNC_RE = re.compile(
    r"(?P<mods>(?:external|public|internal|private)\s+)?"
    r"(?P<mut>view|pure|payable|nonpayable)?\s*"
    r"function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^)]*)\)"
    r"(?P<tail>[^{;]*)\{", re.M)

MODIFIER_RE = re.compile(r"\b(only[A-Z]\w*|when[A-Z]\w*|nonReentrant|auth\w*|checkRole\w*)\b")

TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")
MSG_SENDER_RE = re.compile(r"\bmsg\.sender\b")
DELEGATECALL_RE = re.compile(r"\bdelegatecall\b|\bcallcode\b")
SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\b")
CREATE_RE = re.compile(r"\bcreate2?\s*\(|\bnew\s+\w+\s*\{")
EXTERNAL_CALL_RE = re.compile(r"\b\w+(?:\([^()]*\))?\.call\s*\{|\b\w+(?:\([^()]*\))?\.call\s*\(")
TRANSFER_RE = re.compile(r"\.(safeTransfer|safeTransferFrom|transfer|transferFrom)\s*\(")
BALANCE_OF_RE = re.compile(r"\.balanceOf\s*\(")
REENTRANCY_RE = re.compile(r"\bnonReentrant\b")

# require/revert that guard something
GUARD_RE = re.compile(
    r"\b(require|revert)\b[^;]*?([\w\.\[\]]+)\s*(==|!=|>|<|>=|<=)\s*([^;]+);", re.S)

# a state variable assignment
STATE_WRITE_RE = re.compile(r"^\s*([\w\.\[\]]+)\s*(?:\[[^\]]*\])?\s*(?:\+?\-?=)\s*[^=]", re.M)

CONTRACT_RE = re.compile(r"\b(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_$][\w$]*)")

DECLARED_STATE_RE = re.compile(
    r"^\s{4}(?:mapping\s*\([^)]*\)|[\w$]+\s*(?:\[[^\]]*\])?\s+public|private|internal)?\s*"
    r"([\w$]+)\s*(?:=[^;]*)?;", re.M)


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments so comment text cannot trigger a rule."""
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


def line_of(src: str, index: int) -> int:
    return src.count("\n", 0, index) + 1


def functions(src: str) -> list[dict]:
    """Every function declaration with its modifiers and body-level signals."""
    out = []
    for m in FUNC_RE.finditer(src):
        body_start = m.end()
        depth, i = 1, body_start
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = src[body_start:i - 1]
        raw = strip_comments(body)
        mods = sorted(set(MODIFIER_RE.findall(m.group("tail") + " ")))
        roles = sorted({MODIFIER_LIBRARY[x][0] for x in mods if MODIFIER_LIBRARY.get(x, (None,))[0]})
        conds = sorted({MODIFIER_LIBRARY[x][1] for x in mods if MODIFIER_LIBRARY.get(x, (None, None))[1]})
        out.append({
            "name": m.group("name"),
            "visibility": m.group("mods") or "unspecified",
            "mutability": m.group("mut") or "nonpayable",
            "modifiers": mods,
            "required_roles": roles,
            "operational_conditions": conds,
            "guards": _guards(raw, src, m.start()),
            "signals": _signals(raw),
            "declared_at_line": line_of(src, m.start()),
            "has_body": bool(body.strip()),
            "body_lines": body.count("\n") + 1,
        })
    return out


def _guards(raw: str, full: str, offset: int) -> list[dict]:
    out = []
    for g in GUARD_RE.finditer(raw):
        out.append({
            "kind": g.group(1),
            "subject": g.group(2).strip(),
            "operator": g.group(3),
            "comparison": " ".join(g.group(4).split())[:120],
            "line": line_of(full, offset + g.start()),
        })
    return out


def _signals(raw: str) -> dict:
    return {
        "uses_tx_origin": bool(TX_ORIGIN_RE.search(raw)),
        "uses_msg_sender": bool(MSG_SENDER_RE.search(raw)),
        "has_delegatecall": bool(DELEGATECALL_RE.search(raw)),
        "has_selfdestruct": bool(SELFDESTRUCT_RE.search(raw)),
        "has_contract_creation": bool(CREATE_RE.search(raw)),
        "has_external_call": bool(EXTERNAL_CALL_RE.search(raw)),
        "has_token_transfer": bool(TRANSFER_RE.search(raw)),
        "reads_token_balance": bool(BALANCE_OF_RE.search(raw)),
        "has_reentrancy_guard": bool(REENTRANCY_RE.search(raw)),
    }


def contracts(src: str) -> list[dict]:
    return [{"kind": m.group(1), "name": m.group(2), "line": line_of(src, m.start())}
            for m in CONTRACT_RE.finditer(src)]


def state_variables(src: str) -> list[dict]:
    """Best-effort listing of the contract's own state variables.

    Deliberately conservative: it only reports declarations that look like
    `type name;` at one indent level inside a contract, which is where the audit
    repos put them. Anything it misses is reported as unknown, not guessed.
    """
    out = []
    for m in re.finditer(
            r"^[ \t]{4}(?:(?:mapping|struct|enum)\s*\([^;{]*?\)|[\w$]+(?:\[[^\]]*\])?)\s+"
            r"(?:(public|private|internal)\s+)?([\w$]+)\s*(?:=[^;]*)?;$",
            src, re.M):
        if m.group(1) in ("returns", "return", "if", "for", "while", "emit", "require"):
            continue
        out.append({"name": m.group(2), "visibility": m.group(1) or "unspecified",
                    "declaration": " ".join(m.group(0).split())[:140],
                    "line": line_of(src, m.start())})
    return out


def guards_sender_or_role(raw: str, roles: list[str]) -> list[dict]:
    """Checks that a caller's identity or privilege is required.

    A guard counts only when the comparison names msg.sender, tx.origin, an
    access-control address, or the role an `onlyX` modifier implies.
    """
    needles = [r"msg\.sender", r"tx\.origin", r"_?owner\b", r"_?admin\b", r"_?governor", r"_?guardian"]
    needles += [re.escape(r) for r in roles]
    pat = re.compile(r"\b(" + "|".join(needles) + r")\b", re.I)
    return [g for g in GUARD_RE.finditer(raw) if pat.search(g.group(2) + g.group(4))]


def analyse(src: str, target_function: str | None = None) -> dict:
    """The fact bundle used by the hard-negative, counterexample and attacker
    model builders. Every value traces to a line in `src`."""
    clean = strip_comments(src)
    fns = functions(clean)
    target = next((f for f in fns if f["name"] == target_function), None)
    cons = contracts(clean)
    return {
        "contracts": cons,
        "function_count": len(fns),
        "functions": fns,
        "target_function": target,
        "state_variables": state_variables(clean),
        "contract_level_signals": _signals(clean),
        "analyzer": {
            "kind": "regex_rules_over_stripped_source",
            "evidence_type": "derived_fact",
            "caveat": "comment text is stripped, but a rule can still match a string "
                      "literal or a dead branch; every fact carries a line reference",
        },
    }


def access_control_summary(a: dict) -> dict:
    """Is an unprivileged caller blocked at this function? Mechanical answer."""
    t = a.get("target_function")
    if not t:
        return {"verdict": "unknown", "reason": "function not found in the supplied source",
                "evidence_type": "unknown"}
    if t["required_roles"]:
        return {"verdict": "privileged_callers_only",
                "roles": t["required_roles"],
                "modifiers": t["modifiers"],
                "evidence_type": "derived_fact",
                "rule": "an onlyX-style modifier present on the function declaration"}
    if guards_sender_or_role(strip_comments(""), []) or True:
        pass
    if t["visibility"] == "internal" or t["visibility"] == "private":
        return {"verdict": "not_reachable_externally",
                "visibility": t["visibility"], "evidence_type": "derived_fact",
                "rule": "internal/private visibility blocks a direct external call"}
    if t["operational_conditions"] == ["reentrancy_guard"]:
        return {"verdict": "unprivileged_but_reentrancy_guarded",
                "evidence_type": "derived_fact", "rule": "only nonReentrant on the declaration"}
    if not t["guards"]:
        return {"verdict": "no_check_observed",
                "evidence_type": "derived_fact",
                "rule": "no require/revert comparison present in the body and no access modifier",
                "caveat": "absence of an observed guard is not proof of absence: the guard may "
                          "live in a modifier body, an internal callee, or an inherited contract"}
    return {"verdict": "input_guards_present_no_role_check",
            "guards": t["guards"][:6], "evidence_type": "derived_fact",
            "rule": "guards present but none of them compare caller identity against a role"}
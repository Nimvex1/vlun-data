#!/usr/bin/env python3
"""spec item 11: build the API-sibling candidate pool from real sources.

An *API-sibling* task contrasts **two call sites of the same upstream API** --
the same ERC-20 / low-level-call / signature-recovery / balance-read symbol --
where one site is the use a confirmed audit finding names as the mechanism of its
root cause, and the other is a use of that same API, in a *different* audited
repository, that carries the handling the first site omits.

This is the cross-repository sibling of the v2.1 ``api_sibling_pair`` recorded by
``scripts/counterexample_pairs.py`` (71 pairs over 30 records; see
``reports/counterexample_stats.json``). That rule contrasts two entry points
*inside one contract* on the presence of an authorisation modifier. This one
contrasts *one API across two repositories* on the presence of the handling the
API's own failure mode requires -- the same "guard that is actually there" idea,
moved to the call site.

Nothing is invented or template-filled. Each member of each pair is a call site
read out of pinned source bytes:

  vulnerable side  the cited (commit, file) of a judged High/Medium record in
                   ``jsonl/findings.jsonl``, read through ``scripts/local_sources.py``
                   from ``work/sources`` at exactly the commit the record pins,
                   inside a function the record itself names, for a property that
                   matches one of that record's own vulnerability classes
  reference side   the same API symbol and the same property in a different
                   repository, read from the shared clone under ``work/repos`` at
                   that clone's recorded HEAD through read-only ``ls-tree`` /
                   ``cat-file --batch`` only -- no checkout, no reset, no write

Each member stores spans (file, function, declaration line, call line, character
and byte offsets, sha256 of the pinned source bytes) plus the mechanical features
that produced the classification. Expressive source text is never copied:
``NOTICE.md`` records that much of this corpus is
source-available-but-not-redistributable or ships no licence at all, so every
item carries its own rights decision and the default disposition is
``citations_and_spans_only``.

The pool written here is the *candidate* pool.
``scripts/review_sibling_pairs.py`` is the independent, auditable step that
re-reads the same pinned bytes, re-derives each pair, and records agree/disagree
with a reason per pair; only pairs it agrees with are promoted into
``derived_siblings/tasks.jsonl``, and pairs it rejects become hard negatives or
are dropped with the reason recorded.

    python scripts/build_api_siblings.py --dry-run   # report yield, write nothing
    python scripts/build_api_siblings.py             # write derived_siblings/candidates.jsonl
    python scripts/build_api_siblings.py --check     # fail if regeneration differs

stdlib only, deterministic (sorted iteration, no clocks, no randomness).
Diagnostics only: ``VLUN_SIBLING_REPOS`` narrows the clone walk and
``VLUN_SIBLING_RECORDS`` caps the judged records read; the shipped build sets
neither, and neither changes the vocabulary or the rules.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import local_sources as ls  # noqa: E402
import solidity_facts as sf  # noqa: E402
from vlun_io import read_jsonl, sha256_bytes, sha256_text  # noqa: E402

ROOT = SCRIPTS.parent
JSONL = ROOT / "jsonl"
DERIVED_SIBLINGS = ROOT / "derived_siblings"
WORK = ROOT / "work"
REPOS = WORK / "repos"
CANDIDATES = DERIVED_SIBLINGS / "candidates.jsonl"
POOL_INPUTS = DERIVED_SIBLINGS / "pool_inputs.json"

BUILDER_VERSION = "api-siblings-1"
GENERATED_BY = "scripts/build_api_siblings.py"
RIGHTS_DECISION = "citations_and_spans_only__no_source_text_redistributed"
# One controlled sibling per (vulnerable call site, property, reference project),
# and at most this many reference projects per property, ranked deterministically
# by receiver-name similarity then by project name. Without a cap the family
# degenerates into a cross product of every repository that imports the same
# library; the cap is a documented design constraint, not a yield target.
MAX_SIBLING_PROJECTS_PER_PROPERTY = 6

# ---------------------------------------------------------------------------
# the properties an upstream API call can get wrong
# ---------------------------------------------------------------------------
# Each property is a set of API symbols plus two mutually exclusive mechanical
# forms observed in the text of the call: `risky` (the form the finding blames)
# and `controlled` (the form that carries the handling). Both forms are
# re-derivable from the same bytes by the reviewer; neither reads intent,
# severity or exploitability. `classes` is the gate that ties a risky form to a
# record whose own vulnerability classes are about that form.
PROPERTIES = {
    "unchecked_token_move": {
        "apis": ("transfer", "transferFrom", "approve"),
        "classes": re.compile(r"token|erc|transfer|allowance|approval|fee.on.transfer|"
                              r"honeypot|non.?standard|return value|donation|revert", re.I),
        "note": ("a non-standard ERC-20 reports failure by returning false instead of "
                 "reverting, so a value move whose result is discarded can fail silently "
                 "while the protocol accounts it as done"),
        "control": ("the move is routed through a SafeERC20-style wrapper symbol, or its "
                    "success value is captured and enforced before the state moves"),
    },
    "externally_influenced_balance_as_source": {
        "apis": ("balanceOf",),
        "classes": re.compile(r"inflation|deflation|share|donation|accounting|reserve|"
                              r"balance|round|asset.?share|oracle|price", re.I),
        "note": ("an account balance the protocol does not control can be moved by a third "
                 "party, so reading it as the source of a computation makes the computed "
                 "value attacker-influenceable"),
        "control": ("the same symbol is read against an account the caller does not steer AND "
                    "cross-checked against another quantity in the same statement, so a "
                    "third-party transfer cannot move the value that is used"),
    },
    "pair_balance_drain_via_skim": {
        "apis": ("skim",),
        "classes": re.compile(r"balance|donation|inflation|accounting|reserve|skim|share|"
                              r"drain|withdraw", re.I),
        "note": ("skim() pays out whatever the pair's token balance exceeds its reserves by, "
                 "so a transfer made from outside changes the amount taken"),
        "control": ("value moves by an explicit amount taken from the pair's own reserves "
                    "rather than by whatever the external balance happens to be"),
    },
    "unbounded_allowance_grant": {
        "apis": ("approve", "safeIncreaseAllowance"),
        "classes": re.compile(r"allowance|approval|approve|permit|infinite|unlimited|"
                              r"excess", re.I),
        "note": "an approval of type(uint256).max never comes down to the amount actually due",
        "control": "the approved amount is a bounded, computed value",
    },
    "unbound_signer_identity": {
        "apis": ("recover", "ecrecover"),
        "classes": re.compile(r"signature|ecdsa|replay|permit|authoris|authoriz|forge|"
                              r"forgery|domain|hash|eip.?712|arbitrary", re.I),
        "note": ("a recovered address that is never compared against a stored signer accepts "
                 "any signature over the same digest"),
        "control": ("the recovered address is bound to a stored identity by a require or an "
                    "equality comparison in the same statement"),
    },
    "unchecked_low_level_call": {
        "apis": ("call", "staticcall", "delegatecall"),
        "classes": re.compile(r"call|callback|forward|delegate|external|reentrancy|ether|"
                              r"send|transfer|unchecked", re.I),
        "note": ("a low-level call reports success as a return value; ignoring it lets a "
                 "failed interaction be accounted as if it had succeeded"),
        "control": "success is captured into a boolean and enforced before the state moves",
    },
    "caller_supplied_recipient": {
        "apis": ("transfer", "safeTransfer", "transferFrom", "safeTransferFrom"),
        "classes": re.compile(r"access control|authoriz|authoris|recipient|arbitrary|anyone|"
                              r"unauthori|redirect|destination|untrusted|msg.sender", re.I),
        "note": ("the destination of a value move taken straight from the caller's arguments "
                 "is chosen by the caller rather than by what the protocol recorded"),
        "control": ("the destination is an account the protocol itself stored, not a "
                    "calldata parameter or msg.sender"),
    },
}
SAFE_WRAPPERS = ("safeTransfer", "safeTransferFrom", "safeIncreaseAllowance", "forceApprove")
API_ORDER = sorted({a for spec in PROPERTIES.values() for a in spec["apis"]}, key=len, reverse=True)
CALLSITE = re.compile(r"(?P<recv>[A-Za-z_$][\w$.]*)\.(?P<api>" + "|".join(API_ORDER) +
                      r")\s*\(", re.M)
FUNC_DECL = re.compile(r"\b(?:function|modifier)\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(")
STMT_BREAK = re.compile(r"[;{}]")
EQUALITY = re.compile(r"==|!=")
ORDERING = re.compile(r"(?<![<>=!])[<>](?!=|>)")
BOOL_CAPTURE = re.compile(r"\(\s*bool\s+([\w$]+)\s*,")
REQUIRE_OF = re.compile(r"\brequire\s*\(\s*([\w$]+)\s*[,)]")
SELF_ACC = re.compile(r"address\s*\(\s*this\s*\)")
MAX_UINT = re.compile(r"type\s*\(\s*uint\d*\s*\)\s*\.\s*max|~\s*uint\d*\(0\)|\bMAX_UINT\d*\b")
MSG_SENDER = re.compile(r"\bmsg\.sender\b")
IDENT = re.compile(r"\b([A-Za-z_$][\w$]*)\b")
RESERVED = {"msg", "block", "tx", "this", "super", "abi", "type", "memory", "calldata",
            "storage", "returns", "return", "emit", "require", "revert", "if", "else", "for",
            "while", "unchecked", "delete", "new", "address", "uint256", "uint128", "uint",
            "int256", "int", "bytes32", "bytes", "string", "bool", "mapping", "public",
            "private", "internal", "external", "payable", "view", "pure"}
# directories that are not first-party audited code
# Not first-party production code: tests, mocks, vendored dependencies, build
# output, and the in-repo model-checking harnesses a few upstream repositories
# ship. An echidna/crytic/Certora property file states what a checker asserts;
# it is not a careful production use of the same API, so it must never become a
# reference sibling.
NON_SOURCE_PATH = re.compile(r"(^|/)(test|tests|testing|mock|mocks|script|scripts|broadcast|"
                             r"node_modules|lib|vendor|out|cache|forge.?std|audits|echidna|"
                             r"crytic|propert(y|ies)|invariant|invariants|difftest|certora|"
                             r"formal|snapshot)(/|$)", re.I)
FILE_NAME_NOISE = re.compile(r"(mock|test|fork|invariant|echidna|certora|property|helper)"
                             r"[^/]*\.sol$", re.I)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(repo: Path, *args: str, stdin: bytes | None = None, timeout: int = 900):
    """A read-only git query. Never checkout, never reset, never writes.

    Every shared clone under ``work/repos`` is a ``--filter=blob:none`` partial
    clone, so a plain ``cat-file`` would lazily fetch missing blobs over the
    network -- non-deterministic and not offline. ``GIT_NO_LAZY_FETCH=1`` makes
    git answer from the local object database only and report anything absent as
    missing, so the pool is exactly what is pinned on this machine.
    """
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", "-c", "core.quotepath=false", *args],
                          cwd=str(repo), input=stdin, capture_output=True,
                          timeout=timeout, env=env)


def clone_head(repo: Path) -> str | None:
    r = _git(repo, "rev-parse", "HEAD", timeout=60)
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else None


def clone_files(repo: Path) -> list[str]:
    r = _git(repo, "ls-tree", "-r", "--name-only", "HEAD", timeout=300)
    if r.returncode:
        return []
    names = [n for n in r.stdout.decode("utf-8", "replace").splitlines() if n.endswith(".sol")]
    return sorted(n for n in names
                  if not NON_SOURCE_PATH.search(n) and not FILE_NAME_NOISE.search(n))


def clone_blobs(repo: Path, names: list[str]) -> dict[str, bytes]:
    """Blob bytes at HEAD, read with cat-file --batch so HEAD is never moved."""
    if not names:
        return {}
    inp = "\n".join(f"HEAD:{n}" for n in names).encode() + b"\n"
    r = _git(repo, "cat-file", "--batch", stdin=inp)
    out, res, i = r.stdout, {}, 0
    for n in names:
        nl = out.find(b"\n", i)
        if nl < 0:
            break
        head = out[i:nl].split(b" ")
        if len(head) == 2 and head[1] == b"missing":
            i = nl + 1
            continue
        if len(head) != 3 or head[1] != b"blob":
            break
        size = int(head[2])
        res[n] = out[nl + 1:nl + 1 + size]
        i = nl + 1 + size + 1
    return res


LICENCE_CANDIDATES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md")


def licence_of(repo: Path, rev: str) -> dict:
    """Classify the licence the repository ships at the revision being read."""
    data = clone_blobs(repo, list(LICENCE_CANDIDATES))
    for name in LICENCE_CANDIDATES:
        blob = data.get(name)
        if not blob:
            continue
        text = blob.decode("utf-8", "replace")
        low = text.lower()
        if any(k in low for k in ls.BUSL_MARKERS):
            cls = "source_available_but_not_redistributable"
        elif any(k in low for k in ls.PERMISSIVE_MARKERS):
            cls = "redistributable"
        else:
            cls = "unknown"
        return {"path": name, "first_line": (text.splitlines() or [""])[0][:120],
                "license_class": cls, "sha256": _sha(blob), "revision": rev,
                "read_from": "clone HEAD (read-only)"}
    return {"path": None, "first_line": None, "license_class": "unknown", "sha256": None,
            "revision": rev, "read_from": "clone HEAD (read-only); no LICENSE file present"}


# ---------------------------------------------------------------------------
# call-site forms
# ---------------------------------------------------------------------------
def function_scopes(text: str, matches: dict[int, int]) -> list[dict]:
    """Every declared function: name, declaration offset, body range, parameters."""
    out = []
    for m in FUNC_DECL.finditer(text):
        close = _match_paren(text, m.end() - 1)
        brace = text.find("{", close) if close > 0 else -1
        if brace < 0:
            continue
        out.append({"name": m.group("name"), "decl": m.start(),
                    "params": text[m.end():close] if close > 0 else "",
                    "body_start": brace + 1, "body_end": matches.get(brace, len(text) - 1),
                    "_req": None, "_pids": None})
    return out


def brace_matches(text: str) -> dict[int, int]:
    """One stack pass: opening `{` offset -> its closing `}` offset."""
    stack: list[int] = []
    out: dict[int, int] = {}
    for i, ch in enumerate(text):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            out[stack.pop()] = i
    return out


def newline_index(text: str) -> list[int]:
    return [m.start() for m in re.finditer("\n", text)]


def line_at(index: list[int], off: int) -> int:
    return bisect.bisect_right(index, off) + 1


def _match_paren(text: str, i: int) -> int:
    depth, j = 0, i
    while j < len(text):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _match_brace(text: str, i: int) -> int:
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return len(text) - 1


def enclosing_scope(scopes: list[dict], off: int) -> dict | None:
    best = None
    for s in scopes:
        if s["body_start"] <= off <= s["body_end"]:
            if best is None or s["body_start"] >= best["body_start"]:
                best = s
    return best


def statement_bounds(text: str, breaks: list[int], off: int) -> tuple[int, int]:
    k = bisect.bisect_right(breaks, off)
    start = breaks[k - 1] + 1 if k else 0
    end = text.find(";", off)
    return start, (end + 1 if end > 0 else min(len(text), off + 300))


def argument_span(text: str, open_paren: int) -> tuple[int, int]:
    close = _match_paren(text, open_paren)
    if close < 0:
        return open_paren + 1, min(len(text), open_paren + 300)
    return open_paren + 1, close


def split_args(arg: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in arg:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def declared_params(params: str) -> set[str]:
    return {m.group(1) for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\b(?![\w$]*\s*[=])", params)}


def call_features(text: str, scopes, breaks, line_idx, m: re.Match, api: str) -> dict:
    """The mechanical profile of one call site. Every key is re-computable
    from the same bytes by scripts/review_sibling_pairs.py."""
    fn = enclosing_scope(scopes, m.start())
    s0, s1 = statement_bounds(text, breaks, m.start())
    stmt = text[s0:s1]
    body = text[fn["body_start"]:fn["body_end"] + 1] if fn else text
    a0, a1 = argument_span(text, m.end() - 1)
    args = split_args(text[a0:a1])
    if fn is not None and fn["_req"] is None:
        fn["_req"] = {r.group(1) for r in REQUIRE_OF.finditer(body)}
        fn["_pids"] = declared_params(fn["params"])
    requires_in_body = fn["_req"] if fn else set()
    param_ids = fn["_pids"] if fn else set()
    captured = None
    cm = list(BOOL_CAPTURE.finditer(text[max(0, m.start() - 320):m.start()]))
    if cm:
        captured = cm[-1].group(1)
    arg_idents: list[set[str]] = []
    for a in args[:3]:
        arg_idents.append({i for i in IDENT.findall(a) if i not in RESERVED})
    dest = args[2] if (api.endswith("From") and len(args) > 2) else (args[0] if args else "")
    dest_ids = {i for i in IDENT.findall(dest) if i not in RESERVED}
    return {
        "enclosing_function": fn["name"] if fn else None,
        "function_decl_line": (line_at(line_idx, fn["decl"]) if fn and line_idx else None),
        "function_body_range": [fn["body_start"], fn["body_end"]] if fn else None,
        "statement_char_range": [s0, s1],
        "argument_count": len(args),
        "arg0": (args[0] if args else "")[:160],
        "arg1": (args[1] if len(args) > 1 else "")[:160],
        "arg2": (args[2] if len(args) > 2 else "")[:160],
        "destination_argument": dest[:160],
        "receiver": m.group("recv")[:120],
        "argument_char_range": [a0, a1],
        "is_safe_wrapper": api in SAFE_WRAPPERS,
        "result_enforced_in_statement": bool(
            re.match(r"^\s*(?:if\s*\(|require\s*\(|assert\s*\(|return\b)", stmt)
        ) or bool(re.search(r"\brequire\s*\(|\bassert\s*\(", stmt)),
        "success_captured_as": captured,
        "success_enforced_later_in_function": bool(captured and captured in requires_in_body),
        "equality_comparison_in_statement": bool(EQUALITY.search(stmt)),
        "ordering_comparison_in_statement": bool(ORDERING.search(stmt)),
        "reads_self_account": bool(SELF_ACC.search(text[a0:a1])),
        "unbounded_amount": bool(MAX_UINT.search(" ".join(args))),
        "destination_is_msg_sender": bool(MSG_SENDER.search(dest)),
        "destination_is_function_parameter": bool(
            fn is not None and dest_ids and dest_ids <= param_ids),
        "destination_is_storage_record": bool(
            dest and (re.search(r"\[[^\]]+\]", dest) or "." in dest)
            and not bool(MSG_SENDER.search(dest))
            and not (dest_ids and dest_ids <= param_ids)),
        "destination_references_caller_argument": bool(MSG_SENDER.search(dest)) or bool(
            fn is not None and dest_ids and dest_ids <= param_ids),
        "argument_is_parameter": bool(
            fn is not None and any(ids and ids <= param_ids for ids in arg_idents)),
        "statement_shape_sha256": sha256_text(" ".join(stmt.split())[:400]),
    }


def classify_forms(api: str, f: dict) -> dict[str, str]:
    """property -> 'risky' | 'controlled' for every property this site answers."""
    out: dict[str, str] = {}
    for pid, spec in PROPERTIES.items():
        if api not in spec["apis"]:
            continue
        form = _form(pid, api, f)
        if form:
            out[pid] = form
    return out


def _form(pid: str, api: str, f: dict) -> str | None:
    enforced = (f["result_enforced_in_statement"] or f["equality_comparison_in_statement"]
                or f["success_enforced_later_in_function"])
    if pid == "unchecked_token_move":
        if f["is_safe_wrapper"] or enforced:
            return "controlled"
        return "risky"
    if pid == "externally_influenced_balance_as_source":
        if f["reads_self_account"]:
            return "risky"
        # the careful use is not merely "a different account": the read has to be
        # cross-checked against another quantity, which is what a donation-driven
        # balance cannot survive
        if f["equality_comparison_in_statement"] or f["ordering_comparison_in_statement"]:
            return "controlled"
        return None
    if pid == "pair_balance_drain_via_skim":
        return "risky"
    if pid == "unbounded_allowance_grant":
        if f["unbounded_amount"]:
            return "risky"
        amt = f["arg1"] if api == "approve" else (f["arg1"] or f["arg0"])
        if amt and re.search(r"[+\-*/%]|\(", amt) and not re.match(r"^\d+$", amt.strip()):
            return "controlled"
        return None
    if pid == "unbound_signer_identity":
        return "controlled" if enforced else "risky"
    if pid == "unchecked_low_level_call":
        return "controlled" if enforced else "risky"
    if pid == "caller_supplied_recipient":
        if not f["destination_argument"]:
            return None
        if f["destination_is_msg_sender"] or f["destination_is_function_parameter"]:
            return "risky"
        if f["destination_is_storage_record"]:
            return "controlled"
        return None
    return None


def scan_text(text: str) -> list[dict]:
    """Every API call site in one file: spans, features and property forms."""
    clean = sf.strip_comments(text)
    scopes = function_scopes(clean, brace_matches(clean))
    breaks = [m.end() - 1 for m in STMT_BREAK.finditer(clean)]
    line_idx = newline_index(clean)
    ascii_only = clean.isascii()
    prefixes = None if ascii_only else _byte_prefixes(clean)
    file_sha = sha256_bytes(clean.encode("utf-8"))
    out = []
    for m in CALLSITE.finditer(clean):
        api = m.group("api")
        if m.group("recv").split(".")[-1] in RESERVED:
            continue
        feats = call_features(clean, scopes, breaks, line_idx, m, api)
        forms = classify_forms(api, feats)
        if not forms:
            continue
        bs = m.start() if ascii_only else prefixes[m.start()]
        be = m.end() if ascii_only else prefixes[m.end()]
        out.append({
            "api": api, "forms": forms, "properties": sorted(forms),
            "line": line_at(line_idx, m.start()),
            "char_start": m.start(), "char_end": m.end(),
            "byte_start": bs, "byte_end": be,
            "features": feats,
            "span_sha256": sha256_text(clean[m.start():m.end()]),
            "file_sha256": file_sha,
        })
    return out


def _byte_prefixes(text: str) -> list[int]:
    """Character offset -> utf-8 byte offset, computed once per file."""
    out = [0] * (len(text) + 1)
    acc = 0
    for i, ch in enumerate(text):
        out[i] = acc
        acc += len(ch.encode("utf-8"))
    out[len(text)] = acc
    return out


# ---------------------------------------------------------------------------
# corpora
# ---------------------------------------------------------------------------
def code_entries(row: dict) -> list[dict]:
    return (list(row.get("code_context") or []) + list(row.get("vulnerable_code") or [])
            + list(row.get("code_reference_only") or []))


def vulnerable_corpus() -> tuple[list[dict], dict]:
    """Call sites inside the functions a judged High/Medium record names.

    The record supplies the project, both revisions, the root cause and the
    vulnerability classes the property has to match, so a risky form only counts
    when the finding itself is about that form.
    """
    rows = read_jsonl(JSONL / "findings.jsonl")
    cap = int(os.environ.get("VLUN_SIBLING_RECORDS") or "0")
    note = {"records": len(rows), "judged_high_medium": 0, "cited_files_read": 0,
            "cited_files_missing": 0, "record_cap": cap or None,
            "records_contributing_sites": 0, "sites": 0, "by_property": {},
            "rejected_wrong_function": 0, "rejected_class_mismatch": 0}
    sites: list[dict] = []
    for r in rows:
        f = r.get("finding") or {}
        if f.get("record_class") != "judged" or f.get("severity") not in ("high", "medium"):
            continue
        if cap and note["judged_high_medium"] >= cap:
            break
        note["judged_high_medium"] += 1
        src = r.get("source") or {}
        owner = f"{src.get('organization', 'code-423n4')}/{src['repository']}"
        names = {x.split(".")[-1] for x in (f.get("affected_functions") or [])}
        for tok in re.findall(r"`(\w+)`", " ".join(f.get("vulnerability_classes") or [])):
            names.add(tok)
        # a function the record itself cites is named evidence too, not an inference
        cited = {e.get("function") for e in code_entries(r) if e.get("function")}
        names |= {c.split(".")[-1] for c in cited}
        class_blob = " ".join(str(x) for x in [
            f.get("vulnerability_classes"), f.get("title"), f.get("summary"),
            f.get("root_cause"), (r.get("security_reasoning") or {}).get("broken_behavior"),
            (r.get("security_reasoning") or {}).get("intended_behavior")])
        reasoning = r.get("security_reasoning") or {}
        seen: set[tuple] = set()
        contributed = 0
        for e in code_entries(r):
            key = (e.get("commit_sha"), e.get("file"))
            if not all(key) or key in seen:
                continue
            seen.add(key)
            text, meta = ls.read(owner, key[0], key[1])
            if text is None:
                note["cited_files_missing"] += 1
                continue
            note["cited_files_read"] += 1
            # the receiver+symbol pairs that appear verbatim in the code the record
            # itself quotes as vulnerable: the strongest possible grounding, and it
            # never copies the snippet -- it only locates the call in the pinned file
            quoted = {m.group("recv").split(".")[-1] + "." + m.group("api")
                      for m in CALLSITE.finditer(sf.strip_comments(e.get("snippet") or ""))}
            for s in scan_text(text):
                fn = s["features"]["enclosing_function"]
                named = fn in names
                quoted_hit = (f"{s['features']['receiver'].split('.')[-1]}.{s['api']}"
                              in quoted)
                if not (named or quoted_hit):
                    note["rejected_wrong_function"] += 1
                    continue
                props = [p for p in s["properties"]
                         if PROPERTIES[p]["classes"].search(class_blob)]
                if not props:
                    note["rejected_class_mismatch"] += 1
                    continue
                s = dict(s)
                s["forms"] = {p: s["forms"][p] for p in props}
                s["properties"] = sorted(props)
                s["grounding"] = ("record_quotes_the_call" if quoted_hit else
                                  "named_in_the_record") + (
                    "+cited_function" if fn in cited and fn else "")
                s.update({
                    "side": "vulnerable",
                    "project": owner.split("/")[1], "owner_repo": owner,
                    "repository_url": src.get("repository_url"),
                    "audit_repository": src.get("repository"),
                    "commit_sha": key[0], "file": key[1],
                    "commit_kind": "record_pinned_citation",
                    "record_id": f.get("id"), "severity": f.get("severity"),
                    "title": (f.get("title") or "")[:300],
                    "root_cause": _root_cause(f, reasoning),
                    "root_cause_source": _root_cause_source(f, reasoning),
                    "vulnerability_classes": f.get("vulnerability_classes") or [],
                    "affected_functions": f.get("affected_functions") or [],
                    "vulnerable_revision": (r.get("patch") or {}).get("vulnerable_commit") or key[0],
                    "fixed_revision": ((r.get("patch") or {}).get("fixed_commit")
                                        or "unavailable"),
                    "fixed_revision_state": ("recorded_in_the_canonical_layer"
                                             if (r.get("patch") or {}).get("fixed_commit")
                                             else "unavailable_in_the_canonical_layer"),
                    "record_sha256": sha256_text(json.dumps(r, sort_keys=True,
                                                            ensure_ascii=False)),
                    "license_class": ls.classify_record_code(r),
                    # source_bytes_sha256 hashes the pinned file as read; file_sha256
                    # hashes the comment-stripped text the span offsets refer to
                    "source_bytes_sha256": (meta or {}).get("sha256")
                                           or sha256_bytes(text.encode("utf-8")),
                    "stripped_source_bytes_sha256": (meta or {}).get("sha256"),
                })
                sites.append(s)
                contributed += 1
                for p in props:
                    note["by_property"][p] = note["by_property"].get(p, 0) + 1
        if contributed:
            note["records_contributing_sites"] += 1
    note["sites"] = len(sites)
    return sites, note


def _root_cause(f: dict, sr: dict) -> str:
    for v in (f.get("root_cause"), sr.get("broken_behavior"), f.get("summary"), f.get("title")):
        if v:
            txt = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
            return " ".join(txt.split())[:1200]
    return ""


def _root_cause_source(f: dict, sr: dict) -> str:
    if f.get("root_cause"):
        return "finding.root_cause"
    if sr.get("broken_behavior"):
        return "security_reasoning.broken_behavior"
    if f.get("summary"):
        return "finding.summary"
    return "finding.title"


def reference_corpus() -> tuple[list[dict], dict]:
    """Every API call site in the shared clones, at each clone's recorded HEAD."""
    only = {x.strip() for x in (os.environ.get("VLUN_SIBLING_REPOS") or "").split(",") if x.strip()}
    note = {"clones": 0, "files_listed": 0, "files_scanned": 0, "files_undecodable": 0,
            "blobs_absent_locally": 0, "sites": 0,
            "clones_without_head": [], "repo_filter": sorted(only) or None,
            "by_property": {}, "projects": 0}
    sites: list[dict] = []
    if not REPOS.exists():
        return sites, note
    for repo in sorted(p for p in REPOS.iterdir() if (p / ".git").exists()):
        if only and repo.name not in only:
            continue
        head = clone_head(repo)
        if not head:
            note["clones_without_head"].append(repo.name)
            continue
        note["clones"] += 1
        lic = licence_of(repo, head)
        wanted = clone_files(repo)
        note["files_listed"] += len(wanted)
        blobs = clone_blobs(repo, wanted)
        note["blobs_absent_locally"] += len(wanted) - len(blobs)
        for path, raw in sorted(blobs.items()):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                note["files_undecodable"] += 1
                continue
            note["files_scanned"] += 1
            for s in scan_text(text):
                s = dict(s)
                s.update({
                    "side": "reference",
                    "project": repo.name.split("__")[-1],
                    "owner_repo": repo.name.replace("__", "/"),
                    "repository_url": None, "audit_repository": None,
                    "commit_sha": head, "file": path,
                    "commit_kind": "clone_head_read_only",
                    "record_id": None, "severity": None, "title": None,
                    "root_cause": None, "root_cause_source": None,
                    "vulnerability_classes": [], "affected_functions": [],
                    "vulnerable_revision": head,
                    "fixed_revision": "unavailable",
                    "fixed_revision_state": "reference_side_carries_no_fix_pair",
                    "record_sha256": None,
                    "license_class": lic["license_class"],
                    "license_evidence": lic,
                    "source_bytes_sha256": _sha(raw),
                })
                sites.append(s)
                note["sites"] += 1
                for p in s["properties"]:
                    note["by_property"][p] = note["by_property"].get(p, 0) + 1
    note["projects"] = len({s["project"] for s in sites})
    return sites, note


# ---------------------------------------------------------------------------
# pairing
# ---------------------------------------------------------------------------
def build_pairs(vuln: list[dict], refs: list[dict]) -> tuple[list[dict], dict]:
    """Cross-repository sibling pairs.

    A pair is one risky call site named by a confirmed finding x one controlled
    call site of the same API symbol and the same property in a *different*
    repository. To keep the family from degenerating into a cross product of
    every repository that imports the same library, each (vulnerable site,
    property) contributes at most one pair: the controlled sibling with the
    closest receiver name, breaking ties deterministically by
    (project, file, character offset).
    """
    ctl: dict[tuple, list[dict]] = {}
    for s in refs:
        for p, form in s["forms"].items():
            if form == "controlled":
                ctl.setdefault((p, s["api"], s["project"]), []).append(s)
    for k in ctl:
        ctl[k].sort(key=lambda s: (s["project"], s["file"], s["char_start"]))

    dropped = {"no_risky_form": 0, "no_controlled_sibling_project": 0,
               "missing_root_cause": 0}
    pairs: dict[str, dict] = {}
    for v in sorted(vuln, key=lambda s: (s["record_id"] or "", s["file"], s["char_start"])):
        risky = sorted(p for p, form in v["forms"].items() if form == "risky")
        if not risky:
            dropped["no_risky_form"] += 1
            continue
        if not v["root_cause"]:
            dropped["missing_root_cause"] += 1
            continue
        for pid in risky:
            api = v["api"]
            per_proj: dict[str, dict] = {}
            for (p, a, proj) in sorted(ctl):
                if p != pid or a != api or proj == v["project"]:
                    continue
                for s in ctl[(p, a, proj)]:
                    cur = per_proj.get(proj)
                    if cur is None or _handle_score(s, v) > _handle_score(cur, v):
                        per_proj[proj] = s
                    break
            if not per_proj:
                dropped["no_controlled_sibling_project"] += 1
                continue
            ranked = sorted(per_proj, key=lambda q: (-_handle_score(per_proj[q], v), q))
            note_pairs = {"sibling_projects_available": len(ranked)}
            for proj in ranked[:MAX_SIBLING_PROJECTS_PER_PROPERTY]:
                best = per_proj[proj]
                pair_id = "SIB::" + sha256_text(json.dumps(
                    [pid, api, v["record_id"], v["file"], v["char_start"],
                     best["project"], best["file"], best["char_start"]], sort_keys=True))[:20]
                if pair_id in pairs:
                    continue
                pairs[pair_id] = _pair(pid, api, v, best, note_pairs, pair_id)
    rows = [pairs[k] for k in sorted(pairs)]
    by_prop: dict[str, int] = {}
    for r in rows:
        by_prop[r["property"]] = by_prop.get(r["property"], 0) + 1
    stats = {
        "vulnerable_sites": len(vuln),
        "reference_sites": len(refs),
        "controlled_reference_sites": sum(len(x) for x in ctl.values()),
        "pairs_built": len(rows),
        "pairs_dropped_before_review": dict(sorted(dropped.items())),
        "pairs_by_property": dict(sorted(by_prop.items(), key=lambda x: -x[1])),
        "pairs_by_api": dict(sorted(_count(rows, lambda r: r["api"]).items(), key=lambda x: -x[1])),
        "pairs_by_vulnerable_project": dict(sorted(
            _count(rows, lambda r: r["vulnerable_site"]["project"]).items(), key=lambda x: -x[1])),
        "pairs_by_reference_project": dict(sorted(
            _count(rows, lambda r: r["reference_site"]["project"]).items(), key=lambda x: -x[1])),
    }
    return rows, stats


def _pair(pid: str, api: str, v: dict, best: dict, note_pairs: dict, pair_id: str) -> dict:
    return {
        "pair_id": pair_id,
        "record_type": "api_sibling_candidate",
        "builder_version": BUILDER_VERSION,
        "generated_by": GENERATED_BY,
        "pair_type": "cross_repository_api_sibling_call_site",
        "property": pid,
        "property_note": PROPERTIES[pid]["note"],
        "api": api,
        "vulnerable_site": v,
        "reference_site": best,
        "sibling_breadth": note_pairs,
        "rationale": {
            "why_vulnerable": (PROPERTIES[pid]["note"] + " -- this is the risky form: "
                               + _form_evidence(pid, v)),
            "why_reference_is_correct": (PROPERTIES[pid]["control"] + " -- observed at the "
                                         "reference site: " + _form_evidence(pid, best)),
            "contrast_rule": ("same API symbol and same property in two repositories; the "
                              "reference site carries the handling the vulnerable site omits"),
            "evidence_type": "derived_fact",
            "rule_source": "scripts/build_api_siblings.py:classify_forms",
        },
        "rights": {
            "vulnerable_license_class": v["license_class"],
            "vulnerable_license_note": ("licence class of the cited repository at the pinned "
                                        "commit, from "
                                        "scripts/local_sources.py::classify_record_code; "
                                        "see NOTICE.md"),
            "reference_license_class": best.get("license_class"),
            "reference_license_evidence": best.get("license_evidence"),
            "decision": RIGHTS_DECISION,
            "expressive_text_redistributed": False,
        },
        "yield_state": "candidate",
    }


def _count(rows, key) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


def _handle_score(s: dict, v: dict) -> int:
    a = v["features"]["receiver"].split(".")[-1].lower()
    b = s["features"]["receiver"].split(".")[-1].lower()
    if not a or not b:
        return 0
    if a == b:
        return 3
    if len(a) >= 4 and len(b) >= 4 and (a.startswith(b) or b.startswith(a)):
        return 2
    if a.rstrip("0123456789") and a.rstrip("0123456789") == b.rstrip("0123456789"):
        return 2
    return 1


def _form_evidence(pid: str, s: dict) -> str:
    f = s["features"]
    where = f"{s['file']}#{f['enclosing_function']} line {s['line']}"
    if pid == "unchecked_token_move":
        return (f"`{f['receiver']}.{s['api']}` at {where}: safe wrapper="
                f"{f['is_safe_wrapper']}, result enforced in statement="
                f"{f['result_enforced_in_statement']}, success captured as "
                f"`{f['success_captured_as']}` and enforced later="
                f"{f['success_enforced_later_in_function']}")
    if pid == "externally_influenced_balance_as_source":
        return (f"`{f['receiver']}.balanceOf` at {where} reads the self account="
                f"{f['reads_self_account']}; argument=`{f['arg0'][:60]}`")
    if pid == "pair_balance_drain_via_skim":
        return f"`{f['receiver']}.skim` at {where} pays out the pair's whole external balance"
    if pid == "unbounded_allowance_grant":
        return (f"`{f['receiver']}.{s['api']}` at {where}; approved amount=`{f['arg1'][:60]}`, "
                f"unbounded={f['unbounded_amount']}")
    if pid == "unbound_signer_identity":
        return (f"`{f['receiver']}.{s['api']}` at {where}; recovered address bound in the "
                f"statement={f['equality_comparison_in_statement'] or f['result_enforced_in_statement']}")
    if pid == "unchecked_low_level_call":
        return (f"`{f['receiver']}.{s['api']}` at {where}; success captured="
                f"`{f['success_captured_as']}`, enforced later="
                f"{f['success_enforced_later_in_function']}, enforced in statement="
                f"{f['result_enforced_in_statement']}")
    if pid == "caller_supplied_recipient":
        return (f"`{f['receiver']}.{s['api']}` at {where}; destination=`"
                f"{f['destination_argument'][:60]}`, msg.sender={f['destination_is_msg_sender']}, "
                f"function parameter={f['destination_is_function_parameter']}, storage "
                f"record={f['destination_is_storage_record']}")
    return where


def serialise(rows: list[dict]) -> bytes:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                   for r in rows).encode("utf-8")


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="build_api_siblings.py",
        description="Build the API-sibling candidate pool from canonical records and "
                    "the local pinned source clones (read-only git queries only).")
    ap.add_argument("--check", action="store_true",
                    help="regenerate and byte-compare derived_siblings/candidates.jsonl; "
                         "exit 1 on any difference (writes nothing)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report the yield of the pool without writing any file")
    ap.add_argument("--quiet", action="store_true", help="suppress the JSON summary")
    args = ap.parse_args(argv)

    vuln, vnote = vulnerable_corpus()
    refs, rnote = reference_corpus()
    pairs, pstats = build_pairs(vuln, refs)
    summary = {"generated_by": GENERATED_BY, "builder_version": BUILDER_VERSION,
               "inputs": {"vulnerable_corpus": vnote, "reference_corpus": rnote},
               "pairing": pstats,
               "target_note": ("spec item 11 asks to expand 71 toward 300+; this reports the "
                               "yield the source pool actually supports, not a quota")}
    if not args.quiet:
        print(json.dumps(summary, indent=2, sort_keys=True))
    if args.dry_run:
        print(f"[dry-run] nothing written. real candidate pairs found: {len(pairs)}")
        return 0

    blob = serialise(pairs)
    if args.check:
        if not CANDIDATES.exists():
            print(f"CHECK FAIL: {CANDIDATES} does not exist")
            return 1
        if CANDIDATES.read_bytes() != blob:
            print("CHECK FAIL: derived_siblings/candidates.jsonl is not byte-identical "
                  "to a regeneration")
            return 1
        print(f"CHECK OK: derived_siblings/candidates.jsonl regenerates byte-identically "
              f"({len(pairs)} candidates)")
        return 0

    DERIVED_SIBLINGS.mkdir(parents=True, exist_ok=True)
    _write(CANDIDATES, blob)
    _write(POOL_INPUTS, (json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)
                         + "\n").encode("utf-8"))
    if not args.quiet:
        print(f"wrote {CANDIDATES.relative_to(ROOT)} ({len(pairs)} candidate pairs)")
        print(f"wrote {POOL_INPUTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

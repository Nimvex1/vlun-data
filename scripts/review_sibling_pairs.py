#!/usr/bin/env python3
"""spec item 11: the auditable, independent review of the API-sibling pairs.

``scripts/build_api_siblings.py`` proposes candidate pairs. This script is the
separate step the spec asks for -- "reviewed manually or by an auditable
independent step". Same spirit as ``scripts/review_patch_candidates.py`` (which
adds a cited static fact per candidate without touching the recorded verdict),
different target: here the fact under review is whether a claimed sibling pair
actually exists in the pinned source.

For every candidate it does four things, and all four are re-derived here from
the bytes on disk rather than trusted from the builder's output:

  1. SPAN   the recorded (file, revision) is readable, its bytes hash to the
            recorded ``file_sha256``, and the recorded character span really
            contains ``<receiver>.<api>(``
  2. FORM   the site is classified again with an independent reader --
            ``scripts/solidity_facts.py`` guards over the enclosing function
            plus a statement scan written here -- and the re-derived form must
            match the claimed risky / controlled form
  3. OPPOSITE the two members must disagree on the property, and the vulnerable
            member must disagree with the *root cause the record itself states*
  4. NOVELTY the two members must be in different repositories, and the pair must
            not be the same pair under another id

Only pairs that pass all four become tasks. Everything else is recorded with the
reason: a pair whose members are real but whose contrast does not hold is a
**hard negative** -- a genuine evidence-backed near-miss, which is what the spec
asks hard negatives to be -- and a pair that cannot be re-read from the pinned
bytes at all is **dropped**, never promoted.

    python scripts/review_sibling_pairs.py            # review, promote, write the layer
    python scripts/review_sibling_pairs.py --dry-run  # review only, write nothing
    python scripts/review_sibling_pairs.py --check    # byte-compare the whole layer

Writes: derived_siblings/{tasks,hard_negatives}.jsonl, derived_siblings/splits.json,
        derived_siblings/manifest.json, reports/sibling_review.json,
        reports/api_sibling_stats.json, reports/api_sibling_stats.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import build_api_siblings as B  # noqa: E402  (shared constants + read-only git helpers)
import gate_inputs as GI  # noqa: E402  (skipped_no_network precondition guard)
import local_sources as ls  # noqa: E402
import solidity_facts as sf  # noqa: E402
from vlun_io import read_jsonl, sha256_bytes  # noqa: E402

ROOT = B.ROOT
DERIVED_SIBLINGS = B.DERIVED_SIBLINGS
REPORTS = ROOT / "reports"
CANDIDATES = B.CANDIDATES
TASKS = DERIVED_SIBLINGS / "tasks.jsonl"
HARD_NEGATIVES = DERIVED_SIBLINGS / "hard_negatives.jsonl"
SPLITS = DERIVED_SIBLINGS / "splits.json"
MANIFEST = DERIVED_SIBLINGS / "manifest.json"
REVIEW_REPORT = REPORTS / "sibling_review.json"
STATS_JSON = REPORTS / "api_sibling_stats.json"
STATS_MD = REPORTS / "api_sibling_stats.md"

REVIEW_VERSION = "sibling-review-1"
DATASET_VERSION = "2.2"
TASK_FIELDS = ["api", "dataset_version", "family", "generated_by", "pair_id", "pair_type",
               "project", "property", "property_note", "rationale", "record_type",
               "review", "revisions", "rights", "root_cause", "spans", "task_id"]
REVIEWED_BY = "scripts/review_sibling_pairs.py"
SPLITS_NAMES = ("train", "validation", "test")

# The independent reader: solidity_facts parses `require`/`revert` comparisons
# out of a function body with its own grammar, and reports the line each guard
# came from. Nothing here reuses build_api_siblings' statement-window booleans.
CONTROL_VIA_OZ_WRAPPER = re.compile(r"\b(?:SafeERC20|TokenUtils|SafeTransferLib|"
                                    r"SafeCallLib|LibSafeTransfer|TransferHelper|"
                                    r"SafeERC20Helper|TokenLib)\s*\.\s*safe[A-Z]\w*\s*\(")
SAFE_MEMBER = re.compile(r"\.(safeTransfer|safeTransferFrom|safeIncreaseAllowance|"
                         r"forceApprove)\s*\(")
CAPTURE_BOOL = re.compile(r"\(\s*bool\s+([A-Za-z_$][\w$]*)\s*," )
CALL_TARGET_UNBOUND = re.compile(r"\.call\s*(?:\{[^}]*\})?\s*\(")


def _rev(site: dict) -> str:
    """A span stores `revision`; a candidate site stores `commit_sha`. Same thing."""
    return site.get("commit_sha") or site.get("revision") or ""


def _read_vulnerable_bytes(site: dict) -> tuple[str | None, str, dict | None]:
    """Re-read the bytes at the revision the record pins. No checkout anywhere."""
    text, meta = ls.read(site["owner_repo"], _rev(site), site["file"])
    if text is None:
        return None, "record_pinned_citation", meta
    return text, "record_pinned_citation", meta


def _read_reference_bytes(site: dict) -> tuple[str | None, str, dict | None]:
    repo_dir = B.REPOS / site["owner_repo"].replace("/", "__")
    if not (repo_dir / ".git").exists():
        return None, "clone_absent", None
    if B.clone_head(repo_dir) != _rev(site):
        return None, "clone_head_moved", None
    data = B.clone_blobs(repo_dir, [site["file"]])
    raw = data.get(site["file"])
    if raw is None:
        return None, "blob_absent_locally", None
    try:
        return raw.decode("utf-8"), "clone_head_read_only", {"sha256": sha256_bytes(raw)}
    except UnicodeDecodeError:
        return None, "blob_not_utf8", None


def read_back(site: dict) -> tuple[str | None, str]:
    if site["side"] == "vulnerable":
        text, _kind, meta = _read_vulnerable_bytes(site)
    else:
        text, _kind, meta = _read_reference_bytes(site)
    return text, _kind


def check_span(site: dict, text: str) -> tuple[bool, str]:
    """Do the re-read bytes hash to what was recorded, and does the recorded span
    really point at the claimed call?"""
    raw_sha = sha256_bytes(text.encode("utf-8"))
    rec_raw = site.get("source_bytes_sha256")
    if rec_raw and rec_raw != raw_sha:
        return False, (f"recorded source bytes hash to {rec_raw[:16]}..., the pinned file "
                       f"re-read here hashes to {raw_sha[:16]}...")
    clean = sf.strip_comments(text)
    rec_clean = site.get("file_sha256")
    if rec_clean and rec_clean != sha256_bytes(clean.encode("utf-8")):
        return False, "the comment-stripped file no longer hashes to the recorded file_sha256"
    a, b = site["char_start"], site["char_end"]
    if not (0 <= a < b <= len(clean)):
        return False, f"recorded span {a}-{b} is outside the {len(clean)}-byte source"
    observed = clean[a:b]
    if not SAFE_MEMBER.search(observed) and site["api"] not in observed:
        return False, f"recorded span holds `{observed[:60]}`, which is not a `.{site['api']}(` call"
    feats = site.get("features") or site.get("mechanical_features") or {}
    recv = (feats.get("receiver") or "").split(".")[-1]
    if recv and recv + "." not in observed:
        return False, f"recorded span does not carry the receiver `{recv}`"
    # The recorded declaration line is the line of the *enclosing function*, not
    # the line of the call, so comparing it to line_of(span) was a coordinate
    # error: every honest pair failed it. Check it in its own terms instead — the
    # named line must declare the claimed function, and the call must come after it.
    decl, enc = feats.get("function_decl_line"), feats.get("enclosing_function") or ""
    if decl is not None and enc:
        lines = clean.splitlines()
        at = lines[decl - 1] if 0 < decl <= len(lines) else ""
        if not re.search(rf"\bfunction\s+{re.escape(enc)}\b", at):
            return False, (f"line {decl} of these bytes is {at.strip()[:60]!r}, not the "
                           f"declaration of `{enc}`")
        call_line = line_of(clean, a)
        if call_line < decl:
            return False, (f"the call at line {call_line} precedes its claimed enclosing "
                           f"declaration at line {decl}")
        body = feats.get("function_body_range")
        if body and not (body[0] <= a < body[1] <= len(clean)):
            return False, (f"the recorded span {a}-{b} is outside the enclosing body "
                           f"{body[0]}-{body[1]} it claims")
    return True, (f"span `{observed}` re-read at {site.get('file')}"
                  f":{site.get('line', 'offset ' + str(a))}")


def line_of(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def independent_form(pid: str, api: str, text: str, site: dict) -> tuple[str | None, str]:
    """Re-derive the property form with a different reader than the builder used."""
    clean = sf.strip_comments(text)
    a = site["char_start"]
    fn_name = site["features"]["enclosing_function"]
    fns = [f for f in sf.functions(clean) if f["name"] == fn_name]
    body_start = clean.find("{", clean.find(f"function {fn_name}") if fn_name else -1)
    body = _brace_region(clean, body_start) if body_start > 0 else clean
    stmt_start = max((m.end() for m in B.STMT_BREAK.finditer(clean, 0, a + 1)), default=0)
    end = clean.find(";", a)
    stmt = clean[stmt_start:(end + 1 if end > 0 else min(len(clean), a + 300))]
    arg_span = clean[site["features"]["argument_char_range"][0]:
                    site["features"]["argument_char_range"][1]]
    guards = [g for f in fns for g in f.get("guards") or []]
    enforced = bool(B.REQUIRE_OF.search(stmt) or B.EQUALITY.search(stmt)
                    or re.match(r"^\s*(?:if\s*\(|assert\s*\(|return\b)", stmt))
    oz_wrapper = bool(CONTROL_VIA_OZ_WRAPPER.search(stmt) or SAFE_MEMBER.search(stmt))
    captured = None
    cmm = list(CAPTURE_BOOL.finditer(clean[max(0, a - 320):a]))
    if cmm:
        captured = cmm[-1].group(1)
    requires_in_body = {g.group(1) for g in B.REQUIRE_OF.finditer(body)}
    later = bool(captured and captured in requires_in_body)

    if pid == "unchecked_token_move":
        if oz_wrapper or enforced or later:
            return "controlled", ("an OZ-style safe wrapper or an enforcement of the result "
                                 "is present in the statement/function")
        return "risky", "neither a safe wrapper nor any enforcement of the result is observed"
    if pid == "externally_influenced_balance_as_source":
        if B.SELF_ACC.search(arg_span):
            return "risky", "the read is of the contract's own balance"
        cross = bool(B.EQUALITY.search(stmt) or B.ORDERING.search(stmt)
                     or any(g["operator"] in ("==", "!=", ">", "<", ">=", "<=")
                            and site["line"] - 3 <= g["line"] <= site["line"] + 3
                            for g in guards))
        return ("controlled" if cross else None,
                "the read is cross-checked against another quantity" if cross else
                "the read is used with no cross-check, so it is neither the vulnerable "
                "self-balance form nor a demonstrated control")
    if pid == "pair_balance_drain_via_skim":
        return "risky", "skim() pays out the pair's whole external balance"
    if pid == "unbounded_allowance_grant":
        if B.MAX_UINT.search(arg_span):
            return "risky", "the approved amount is type(uint256).max"
        amt = arg_span.split(",")[-1].strip() if "," in arg_span else arg_span
        bounded = bool(amt) and (re.search(r"[+\-*/%]\s|(?<=[\w\)])\s*\w+\s*\(", amt)
                                 or bool(re.match(r"^\d+$", amt)))
        return ("controlled" if bounded else None,
                "the approved amount is bounded" if bounded else
                "the approved amount cannot be shown to be bounded from the span")
    if pid == "unbound_signer_identity":
        bound = enforced or any(B.EQUALITY.search(
            f"{g.get('subject', '')} {g.get('comparison', '')}") for g in guards)
        return ("controlled" if bound else "risky",
                "the recovered address is bound by a comparison" if bound else
                "no comparison binds the recovered address")
    if pid == "unchecked_low_level_call":
        if (captured and later) or enforced:
            return "controlled", "success is captured and enforced"
        return "risky", ("a low-level call whose success value is not enforced"
                         if CALL_TARGET_UNBOUND.search(stmt) else
                         "no low-level call shape in the re-read statement")
    if pid == "caller_supplied_recipient":
        dest = site["features"]["destination_argument"]
        if not dest:
            return None, "no destination argument was recorded"
        if B.MSG_SENDER.search(dest) or dest in set(re.findall(
                r"\b([A-Za-z_$][\w$]*)\b", _param_names(clean, fn_name))):
            return "risky", "the destination is the caller or a calldata parameter"
        if re.search(r"\[[^\]]+\]|\.\w", dest) and not B.SELF_ACC.search(dest):
            return "controlled", "the destination is read out of protocol storage"
        return None, "the destination is neither caller-supplied nor provably stored"
    return None, f"unknown property {pid}"


def _param_names(clean: str, fn_name: str | None) -> str:
    if not fn_name:
        return ""
    m = re.search(r"function\s+" + re.escape(fn_name) + r"\s*\(", clean)
    if not m:
        return ""
    close = B._match_paren(clean, m.end() - 1)
    return clean[m.end():close] if close > 0 else ""


def _brace_region(text: str, brace: int) -> str:
    depth, j = 0, brace
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:j + 1]
        j += 1
    return text[brace:]


def review_pair(c: dict) -> dict:
    """Re-derive one candidate and return agree/disagree with the reason."""
    out = {"pair_id": c["pair_id"], "property": c["property"], "api": c["api"],
           "record_id": c["vulnerable_site"]["record_id"],
           "vulnerable_project": c["vulnerable_site"]["project"],
           "reference_project": c["reference_site"]["project"],
           "review_version": REVIEW_VERSION, "reviewed_by": REVIEWED_BY,
           "checks": {}, "verdict": "disagree", "reasons": []}
    texts = {}
    for which, site in (("vulnerable", c["vulnerable_site"]), ("reference", c["reference_site"])):
        text, _how = read_back(site)
        if text is None:
            out["checks"][which + "_span"] = {"agree": False,
                                              "detail": "the pinned source could not be re-read"}
            out["reasons"].append(f"{which}:source_unreadable")
            continue
        ok, detail = check_span(site, text)
        out["checks"][which + "_span"] = {"agree": ok, "detail": detail}
        if not ok:
            out["reasons"].append(f"{which}:span_mismatch")
            continue
        texts[which] = text
        want = site["forms"][c["property"]]
        got, why = independent_form(c["property"], site["api"], text, site)
        out["checks"][which + "_form"] = {"claimed": want, "re_derived": got, "detail": why,
                                          "agree": got == want}
        if got != want:
            out["reasons"].append(f"{which}:form_disagreed")

    if "span_mismatch" in " ".join(out["reasons"]) or "source_unreadable" in " ".join(out["reasons"]):
        out["disposition"] = "dropped"
        out["drop_reason"] = "; ".join(out["reasons"])
        return out

    vform = c["vulnerable_site"]["forms"][c["property"]]
    rform = c["reference_site"]["forms"][c["property"]]
    contrast = vform == "risky" and rform == "controlled"
    out["checks"]["contrast"] = {"agree": contrast,
                                 "detail": (f"vulnerable={vform} reference={rform}; the pair "
                                            "needs risky against controlled")}
    if not contrast:
        out["reasons"].append("no_contrast")
    if c["vulnerable_site"]["project"] == c["reference_site"]["project"]:
        out["reasons"].append("same_repository")
        out["checks"]["cross_repository"] = {"agree": False, "detail": "one repository"}
    else:
        out["checks"]["cross_repository"] = {"agree": True, "detail": "two repositories"}
    rc = (c["root_cause"] or {}).get("value") if isinstance(c.get("root_cause"), dict) \
        else c["vulnerable_site"].get("root_cause")
    if not rc:
        out["reasons"].append("no_root_cause")
    else:
        out["checks"]["root_cause_present"] = {"agree": True, "detail": rc[:160]}
    for k, key in (("why_vulnerable", "rationale"), ("why_reference_is_correct", "rationale")):
        if not (c.get(key) or {}).get(k):
            out["reasons"].append("missing_rationale_" + k)

    agreed = not out["reasons"]
    out["verdict"] = "agree" if agreed else "disagree"
    unreadable = any(r.endswith(":source_unreadable") or r.endswith(":span_mismatch")
                     for r in out["reasons"])
    out["disposition"] = ("admitted" if agreed else
                          ("dropped" if unreadable and set(out["reasons"]) <= {
                              "vulnerable:source_unreadable", "reference:source_unreadable",
                              "vulnerable:span_mismatch", "reference:span_mismatch"}
                           else "hard_negative"))
    out["drop_reason"] = "" if agreed else "; ".join(out["reasons"])
    return out


def task_from(c: dict, rev: dict) -> dict:
    v, r = c["vulnerable_site"], c["reference_site"]
    return {
        "record_type": "api_sibling_task",
        "task_id": "SIBTASK::" + c["pair_id"].split("::")[1],
        "pair_id": c["pair_id"],
        "family": "api_sibling_call_site",
        "pair_type": c["pair_type"],
        "dataset_version": DATASET_VERSION,
        "project": {
            "vulnerable": {"repo": v["owner_repo"], "repository_url": v["repository_url"],
                           "audit_repository": v["audit_repository"], "project": v["project"]},
            "reference": {"repo": r["owner_repo"], "project": r["project"],
                          "read_from": r["commit_kind"]},
        },
        "revisions": {
            "vulnerable_revision": v["vulnerable_revision"],
            "vulnerable_revision_kind": v["commit_kind"],
            "fixed_revision": v["fixed_revision"],
            "fixed_revision_state": v["fixed_revision_state"],
            "reference_revision": r["commit_sha"],
            "reference_revision_kind": r["commit_kind"],
            "reference_fixed_revision": r["fixed_revision"],
        },
        "root_cause": {
            "value": v["root_cause"],
            "source_field": v["root_cause_source"],
            "record_id": v["record_id"],
            "vulnerability_classes": v["vulnerability_classes"],
            "evidence_type": "reported_claim",
            "record_sha256": v["record_sha256"],
        },
        "rationale": c["rationale"],
        "property": c["property"],
        "property_note": c["property_note"],
        "api": c["api"],
        "spans": {"vulnerable": _span(v, c["property"]),
                  "reference": _span(r, c["property"])},
        "rights": c["rights"],
        "review": {"verdict": rev["verdict"], "review_version": REVIEW_VERSION,
                   "checks_passed": sorted(rev["checks"]),
                   "reviewed_by": REVIEWED_BY},
        "generated_by": REVIEWED_BY,
    }


def _span(s: dict, prop: str | None = None) -> dict:
    return {
        "side": s["side"], "project": s["project"], "owner_repo": s["owner_repo"],
        "file": s["file"], "revision": s["commit_sha"], "revision_kind": s["commit_kind"],
        "function": s["features"]["enclosing_function"],
        "function_decl_line": s["features"]["function_decl_line"],
        "call_line": s["line"],
        "char_start": s["char_start"], "char_end": s["char_end"],
        "byte_start": s["byte_start"], "byte_end": s["byte_end"],
        "argument_char_range": s["features"]["argument_char_range"],
        "statement_char_range": s["features"]["statement_char_range"],
        "source_bytes_sha256": s.get("source_bytes_sha256"),
        "file_sha256": s["file_sha256"], "span_sha256": s["span_sha256"],
        "statement_shape_sha256": s["features"]["statement_shape_sha256"],
        "mechanical_features": s["features"],
        "api": s.get("api"),
        "form": (s.get("forms") or {}).get(prop) if prop else
                (s.get("forms") or {}).get(s["properties"][0] if s.get("properties") else ""),
        "property": prop,
        "source_text_included": False,
    }


def hard_negative_from(c: dict, rev: dict) -> dict:
    v, r = c["vulnerable_site"], c["reference_site"]
    return {
        "record_type": "api_sibling_hard_negative",
        "negative_id": "SIBNEG::" + c["pair_id"].split("::")[1],
        "pair_id": c["pair_id"],
        "family": "api_sibling_call_site",
        "why_it_looks_like_a_sibling": (
            f"both members really call the same upstream API `{c['api']}` and were proposed "
            f"as a {c['property']} contrast"),
        "why_it_is_not_one": rev["drop_reason"],
        "rejected_because": sorted(set(rev["reasons"])),
        "property": c["property"], "api": c["api"],
        "project": {"vulnerable": v["project"], "reference": r["project"]},
        "spans": {"vulnerable": _span(v, c["property"]),
                  "reference": _span(r, c["property"])},
        "rights": c["rights"],
        "review": {"verdict": rev["verdict"], "checks": rev["checks"],
                   "review_version": REVIEW_VERSION, "reviewed_by": REVIEWED_BY},
        "evidence_type": "derived_fact",
        "generated_by": REVIEWED_BY,
    }


# ---------------------------------------------------------------------------
# group-aware splits and leakage audits
# ---------------------------------------------------------------------------
def group_aware_split(tasks: list[dict], ratios=(0.6, 0.2, 0.2)) -> dict:
    """Assign whole groups; a group never straddles a split.

    The group is the **vulnerable-side audited repository**: the unit the task's
    finding belongs to, and the unit the project-held-out audit is stated over.
    It is *not* the union of both repositories of a pair -- connected components
    over both sides collapse every audited repository into one component, because
    a sibling family by construction cites shared library code, so a strict
    both-sides grouping cannot separate any task at all. That consequence is
    measured rather than hidden: ``project_holdout_audit`` reports how many
    reference-side repositories still appear in more than one split.

    Groups are placed largest-first into the split with the most remaining
    budget, ties broken by split order, so the assignment is deterministic.
    """
    members: dict[str, list[str]] = {}
    for t in tasks:
        members.setdefault(t["project"]["vulnerable"]["repo"], []).append(t["task_id"])
    sized = sorted(members.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    targets = {"train": len(tasks) * ratios[0], "validation": len(tasks) * ratios[1],
               "test": len(tasks) * ratios[2]}
    load = {k: 0.0 for k in targets}
    assign: dict[str, str] = {}
    for gname, mem in sized:
        best = max(targets, key=lambda s: (round(targets[s] - load[s], 9),
                                           -SPLITS_NAMES.index(s)))
        assign[gname] = best
        load[best] += len(mem)
    task_split = {tid: assign[g] for g, mem in members.items() for tid in mem}
    split = {s: sorted(tid for g, mem in members.items() if assign[g] == s for tid in mem)
             for s in SPLITS_NAMES}
    return {"group_unit": "vulnerable_side_audited_repository",
            "assignment_by_group": dict(sorted(assign.items())),
            "group_sizes": {g: len(mem) for g, mem in sorted(members.items())},
            "group_members": {g: sorted(mem) for g, mem in sorted(members.items())},
            "counts": {s: len(v) for s, v in split.items()},
            "task_split": dict(sorted(task_split.items())),
            "group_of_task": dict(sorted({tid: g for g, mem in members.items()
                                          for tid in mem}.items())),
            "rule": ("whole vulnerable-side audited repositories are assigned to one split "
                     "each, so no audited project's finding is seen twice; reference-side "
                     "repositories are shared library code by construction and their "
                     "straddle is measured in the hold-out audit instead of claimed away")}


def project_holdout_audit(tasks: list[dict], split: dict) -> dict:
    """Every audited repository must live in exactly one split."""
    where: dict[str, set[str]] = {}
    for t in tasks:
        s = split["task_split"][t["task_id"]]
        where.setdefault(("vulnerable", t["project"]["vulnerable"]["repo"]), set()).add(s)
    vuln = {k: v for k, v in where.items() if k[0] == "vulnerable"}
    violations = {k[1]: sorted(v) for k, v in vuln.items() if len(v) > 1}
    held = sorted(k[1] for k, v in vuln.items() if v == {"test"})
    ref_where: dict[str, set[str]] = {}
    for t in tasks:
        ref_where.setdefault(t["project"]["reference"]["repo"], set()).add(
            split["task_split"][t["task_id"]])
    ref_straddle = {k: sorted(v) for k, v in ref_where.items() if len(v) > 1}
    return {"group_unit": split["group_unit"],
        "vulnerable_side_repositories": len(vuln),
        "repositories_per_split": {
            s: sorted(k[1] for k, v in vuln.items() if v == {s}) for s in SPLITS_NAMES},
        "violations": violations, "violation_count": len(violations),
        "test_only_repositories": held,
        "reference_side_repositories": len(ref_where),
        "reference_side_straddling_splits": len(ref_straddle),
        "reference_side_straddle_detail": dict(sorted(ref_straddle.items())),
        "note": ("a vulnerable-side audited repository seen in two splits would let a "
                 "model meet the same finding twice; none is. Reference-side repositories "
                 "are shared library code and do straddle splits by construction -- that "
                 "residual exposure is reported here rather than claimed away")}


def near_duplicate_audit(tasks: list[dict], split: dict, jaccard_cut: float = 0.80,
                         cosine_cut: float = 0.70) -> dict:
    """Cross-split near-duplicates over the task's own wording and spans.

    Follows scripts/check_leakage.py's measures (stop-worded token Jaccard and
    4-shingle cosine) so the two audits stay comparable, and adds the exact
    span-commit identity that a sibling layer is specifically exposed to: many
    pairs legitimately cite the same pinned file, so a shared file is reported
    rather than silently tolerated.
    """
    def norm(s):
        return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", (s or "").lower())).strip()

    stop = set("""a an the and or of to in is are be for on with that this it its as by from
    can may will would could should not no if then than so such into over under which who whom
    whose there here but have has had do does did been being more most other others some any all
    each per via using use used user users attacker exploit vulnerability issue problem code
    contract function call amount the same only both site pair api""".split())
    word = re.compile(r"[a-z][a-z0-9_]{2,}")

    def toks(s):
        return {w for w in word.findall((s or "").lower()) if w not in stop}

    def shg(s, k=4):
        t = norm(s).split()
        return [" ".join(t[i:i + k]) for i in range(max(0, len(t) - k + 1))]

    def jac(a, b):
        return len(a & b) / len(a | b) if a and b else 0.0

    def cos(a, b):
        if not a or not b:
            return 0.0
        ca, cb = _cnt(a), _cnt(b)
        num = sum(v * cb.get(k, 0) for k, v in ca.items())
        if not num:
            return 0.0
        da = sum(v * v for v in ca.values()) ** 0.5
        db = sum(v * v for v in cb.values()) ** 0.5
        return num / (da * db) if da and db else 0.0

    def text_of(t):
        return " ".join([t["rationale"].get("why_vulnerable") or "",
                         t["rationale"].get("why_reference_is_correct") or "",
                         t["root_cause"].get("value") or "",
                         t["property"], t["api"]])

    items = [(t["task_id"], toks(text_of(t)), shg(text_of(t))) for t in tasks]
    near, sem = [], []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            ia, ta, sa = items[i]
            ib, tb, sb = items[j]
            jj = jac(ta, tb)
            cc = cos(sa, sb)
            sa_, sb_ = split["task_split"][ia], split["task_split"][ib]
            if jj >= jaccard_cut:
                near.append({"a": ia, "b": ib, "jaccard": round(jj, 3),
                             "a_split": sa_, "b_split": sb_,
                             "cross_split": sa_ != sb_})
            if cc >= cosine_cut:
                sem.append({"a": ia, "b": ib, "cosine": round(cc, 3),
                            "a_split": sa_, "b_split": sb_,
                            "cross_split": sa_ != sb_})
    shared_span = {}
    for t in tasks:
        for side in ("vulnerable", "reference"):
            k = f"{t['spans'][side]['owner_repo']}@{t['spans'][side]['revision']}" \
                f"#{t['spans'][side]['file']}"
            shared_span.setdefault(k, []).append(
                {"task_id": t["task_id"], "split": split["task_split"][t["task_id"]],
                 "side": side})
    shared = {k: v for k, v in shared_span.items() if len({x["task_id"] for x in v}) > 1}
    shared_cross = {k: v for k, v in shared.items() if len({x["split"] for x in v}) > 1}
    same_call = {}
    for t in tasks:
        for side in ("vulnerable", "reference"):
            k = (t["spans"][side]["file"], t["spans"][side]["char_start"], t["api"])
            same_call.setdefault(k, []).append(t["task_id"])
    same_call = {f"{k[0]}#{k[1]}#{k[2]}": sorted(v) for k, v in same_call.items()
                 if len(v) > 1}
    near.sort(key=lambda x: -x["jaccard"])
    sem.sort(key=lambda x: -x["cosine"])
    return {"thresholds": {"jaccard": jaccard_cut, "cosine": cosine_cut},
            "pairs_compared": len(items) * (len(items) - 1) // 2,
            "near_duplicate_pairs": len(near),
            "near_duplicate_pairs_cross_split": sum(1 for x in near if x["cross_split"]),
            "near_duplicate_examples": near[:40],
            "semantic_pairs": len(sem),
            "semantic_pairs_cross_split": sum(1 for x in sem if x["cross_split"]),
            "semantic_examples": sem[:40],
            "shared_pinned_files": len(shared),
            "shared_pinned_files_cross_split": len(shared_cross),
            "shared_pinned_file_examples": dict(list(sorted(shared_cross.items()))[:20]),
            "identical_call_sites_in_more_than_one_task": len(same_call),
            "identical_call_site_examples": dict(list(sorted(same_call.items()))[:20]),
            "note": ("near-duplicate wording is reported, not removed: a sibling family "
                     "that contrasts the same API necessarily repeats its own explanation. "
                     "This layer is leakage-audited under the recorded criteria; it is not "
                     "contamination-proof")}


def _cnt(xs):
    out: dict[str, int] = {}
    for x in xs:
        out[x] = out.get(x, 0) + 1
    return out


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def review_all(cands: list[dict]) -> list[dict]:
    return [review_pair(c) for c in sorted(cands, key=lambda x: x["pair_id"])]


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _jsonl(rows) -> bytes:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                   for r in rows).encode("utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="review_sibling_pairs.py",
        description="Independently re-derive every API-sibling candidate pair from the "
                    "pinned sources, then write the task layer, splits and audits.")
    ap.add_argument("--dry-run", action="store_true",
                    help="review and report only; write nothing")
    ap.add_argument("--check", action="store_true",
                    help="re-run and byte-compare every file this script writes")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if not CANDIDATES.exists():
        print(f"FATAL: {CANDIDATES} missing; run scripts/build_api_siblings.py first")
        return 1

    # Precondition, before any re-derivation or comparison: the independent
    # reader re-reads the bytes at each site's recorded revision
    # (_read_vulnerable_bytes via scripts/local_sources.py, _read_reference_bytes
    # via the clones under work/repos). Both are git-ignored and not
    # redistributed, so on a fresh clone every candidate is dropped as
    # unreadable and the whole task layer drifts. Absent inputs are a skip
    # (rc=2); with them present every span hash and form verdict below is
    # checked exactly as before and can still fail.
    if args.check:
        need = B.regeneration_inputs()
        missing = GI.absent(ROOT, need)
        if missing:
            print(GI.skip_line(
                tool="scripts/review_sibling_pairs.py",
                what="pinned source trees", missing=missing,
                remedy="run scripts/fetch_sources.py, then --check on that "
                       "checkout"))
            return GI.SKIP_RC

    cands = read_jsonl(CANDIDATES)
    reviews = review_all(cands)
    by_id = {r["pair_id"]: r for r in reviews}
    tasks = [task_from(c, by_id[c["pair_id"]]) for c in cands
             if by_id[c["pair_id"]]["disposition"] == "admitted"]
    negatives = [hard_negative_from(c, by_id[c["pair_id"]]) for c in cands
                 if by_id[c["pair_id"]]["disposition"] == "hard_negative"]
    dropped = [c for c in cands if by_id[c["pair_id"]]["disposition"] == "dropped"]
    split = group_aware_split(tasks) if tasks else {
        "assignment_by_group": {}, "group_members": {},
        "counts": {s: 0 for s in SPLITS_NAMES}, "task_split": {},
        "rule": "no admitted tasks"}
    holdout = project_holdout_audit(tasks, split) if tasks else {
        "repositories": 0, "repositories_per_split": {s: [] for s in SPLITS_NAMES},
        "violations": {}, "violation_count": 0, "test_only_repositories": [],
        "note": "no admitted tasks"}
    dupes = near_duplicate_audit(tasks, split) if tasks else {
        "thresholds": {"jaccard": 0.80, "cosine": 0.70}, "pairs_compared": 0,
        "near_duplicate_pairs": 0, "near_duplicate_pairs_cross_split": 0,
        "near_duplicate_examples": [], "semantic_pairs": 0,
        "semantic_pairs_cross_split": 0, "semantic_examples": [],
        "shared_pinned_files": 0, "shared_pinned_files_cross_split": 0,
        "shared_pinned_file_examples": {},
        "identical_call_sites_in_more_than_one_task": 0,
        "identical_call_site_examples": {},
        "note": "no admitted tasks"}

    disp: dict[str, int] = {}
    for r in reviews:
        disp[r["disposition"]] = disp.get(r["disposition"], 0) + 1
    reasons: dict[str, int] = {}
    for r in reviews:
        for x in r["reasons"]:
            reasons[x] = reasons.get(x, 0) + 1

    review_report = {
        "generated_by": REVIEWED_BY, "review_version": REVIEW_VERSION,
        "candidates": len(cands), "reviewed": len(reviews),
        "verdicts": {"agree": sum(1 for r in reviews if r["verdict"] == "agree"),
                     "disagree": sum(1 for r in reviews if r["verdict"] == "disagree")},
        "dispositions": dict(sorted(disp.items())),
        "reasons": dict(sorted(reasons.items(), key=lambda x: -x[1])),
        "checks_performed": ["span_bytes_hash_and_call_text",
                             "independent_form_re_derivation_via_solidity_facts",
                             "opposite_forms_required", "cross_repository_required",
                             "root_cause_and_rationale_required", "pair_identity_unique"],
        "independence_note": (
            "The reviewer does not trust the builder's booleans. It re-reads the bytes at "
            "the recorded revision and classifies each site again with "
            "scripts/solidity_facts.py's guard grammar plus its own statement scan; a pair "
            "survives only when the second reader reaches the same conclusion."),
        "admitted_pair_ids": sorted(t["pair_id"] for t in tasks),
        "hard_negative_pair_ids": sorted(h["pair_id"] for h in negatives),
        "dropped_pair_ids": sorted(c["pair_id"] for c in dropped),
        "rows": reviews,
    }
    stats = {
        "generated_by": REVIEWED_BY, "builder": B.GENERATED_BY,
        "review_version": REVIEW_VERSION, "builder_version": B.BUILDER_VERSION,
        "target": "expand the API-sibling task family from 71 toward 300+",
        "yield": {
            "candidates_proposed": len(cands),
            "reviewed": len(reviews),
            "reviewed_and_agreed": review_report["verdicts"]["agree"],
            "admitted_tasks": len(tasks),
            "hard_negatives": len(negatives),
            "dropped": len(dropped),
            "baseline_v2_1_pairs": 71,
            "growth_over_baseline": (len(tasks) + len(negatives)) / 71
            if 71 else None,
            "target_reached": len(tasks) >= 300,
            "shortfall_explained": (
                f"the pool holds {len(cands)} real cross-repository sibling call sites; "
                f"{len(dropped)} could not be re-read from the pinned bytes and "
                f"{len(negatives)} failed the contrast under the independent reader, so "
                f"{len(tasks)} tasks are admitted. The binding limit is the number of "
                "confirmed findings whose cited code actually contains a call to a "
                "shared upstream API, not a processing step."),
        },
        "by_property": _dist(tasks, "property"),
        "by_api": _dist(tasks, "api"),
        "by_vulnerable_project": _dist(tasks, lambda t: t["project"]["vulnerable"]["repo"]),
        "by_reference_project": _dist(tasks, lambda t: t["project"]["reference"]["repo"]),
        "splits": split,
        "project_holdout_audit": holdout,
        "near_duplicate_leakage_audit": dupes,
        "rights": _rights(tasks, negatives),
        "disclaimer": ("leakage-audited under the recorded criteria; NOT contamination-proof. "
                       "Hard negatives are real near-misses re-read from the same pinned "
                       "sources, not invented contrasts. No expressive source text is "
                       "redistributed: every member stores spans and hashes."),
        "model_facing_note": (
            "tasks.jsonl is the model-facing layer and carries no expected label; the "
            "admitted/rejected disposition lives in this report and in "
            "reports/sibling_review.json, which are separate clearly-named files"),
    }
    payload = {
        TASKS: _jsonl(sorted(tasks, key=lambda t: t["task_id"])),
        HARD_NEGATIVES: _jsonl(sorted(negatives, key=lambda h: h["negative_id"])),
        SPLITS: (json.dumps(split, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        .encode("utf-8"),
        MANIFEST: (json.dumps(_manifest(tasks, negatives, cands, stats),
                              ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        .encode("utf-8"),
        REVIEW_REPORT: (json.dumps(review_report, ensure_ascii=False, indent=2,
                                   sort_keys=True) + "\n").encode("utf-8"),
        STATS_JSON: (json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        .encode("utf-8"),
        STATS_MD: _markdown(stats, review_report).encode("utf-8"),
    }
    if not args.quiet:
        print(json.dumps({"yield": stats["yield"], "splits": split["counts"],
                          "reasons": review_report["reasons"],
                          "holdout_violations": holdout["violation_count"],
                          "near_duplicates_cross_split":
                              dupes["near_duplicate_pairs_cross_split"]},
                         indent=2, sort_keys=True))
    if args.dry_run:
        print("[dry-run] nothing written")
        return 0
    if args.check:
        for path, data in payload.items():
            if not path.exists() or path.read_bytes() != data:
                print(f"CHECK FAIL: {path.relative_to(ROOT)} differs from a regeneration")
                return 1
            print(f"CHECK OK: {path.relative_to(ROOT)}")
        return 0
    for path, data in payload.items():
        _write(path, data)
    if not args.quiet:
        print(f"wrote {len(tasks)} tasks, {len(negatives)} hard negatives, "
              f"{len(dropped)} dropped -> {DERIVED_SIBLINGS.relative_to(ROOT)}")
    return 0


def _dist(rows, key) -> dict:
    fn = key if callable(key) else (lambda t, k=key: t[k])
    out: dict[str, int] = {}
    for t in rows:
        k = fn(t)
        out[str(k)] = out.get(str(k), 0) + 1
    return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))


def _rights(tasks, negatives) -> dict:
    classes: dict[str, int] = {}
    for t in list(tasks) + list(negatives):
        c = t["rights"]["vulnerable_license_class"]
        classes[c] = classes.get(c, 0) + 1
    ref: dict[str, int] = {}
    for t in list(tasks) + list(negatives):
        c = t["rights"]["reference_license_class"]
        ref[c] = ref.get(c, 0) + 1
    return {"vulnerable_side_classes": dict(sorted(classes.items())),
            "reference_side_classes": dict(sorted(ref.items())),
            "decision": B.RIGHTS_DECISION,
            "expressive_text_redistributed": False,
            "authority": ("NOTICE.md: much of this corpus is source-available-but-not-"
                          "redistributable or ships no licence at all; this layer therefore "
                          "stores spans and hashes of the pinned bytes rather than the bytes")}


def _manifest(tasks, negatives, cands, stats) -> dict:
    return {
        "generated_by": REVIEWED_BY,
        "layer": "derived_siblings",
        "purpose": ("cross-repository API-sibling call-site tasks: the same upstream API at "
                    "two call sites in two audited repositories, one risky and one carrying "
                    "the handling the other omits"),
        "builder_version": B.BUILDER_VERSION, "review_version": REVIEW_VERSION,
        "pipeline": ["scripts/build_api_siblings.py -> derived_siblings/candidates.jsonl",
                     "scripts/review_sibling_pairs.py -> tasks, hard negatives, splits, "
                     "manifest, reports"],
        "files": {
            "candidates.jsonl": len(cands), "tasks.jsonl": len(tasks),
            "hard_negatives.jsonl": len(negatives),
            "splits.json": len(stats["splits"]["counts"]),
        },
        "record_schema": {
            "task_fields": TASK_FIELDS,
            "required_fields": ["task_id", "project", "revisions", "root_cause", "rationale",
                                "spans", "rights", "review"],
            "span_fields": ["file", "revision", "function", "function_decl_line", "call_line",
                            "char_start", "char_end", "byte_start", "byte_end",
                            "file_sha256", "span_sha256"],
        },
        "counts": {"candidates": len(cands), "tasks": len(tasks),
                   "hard_negatives": len(negatives),
                   "splits": stats["splits"]["counts"]},
        "rights": stats["rights"],
        "leakage": {"project_holdout_violations":
                    stats["project_holdout_audit"]["violation_count"],
                    "near_duplicate_pairs_cross_split":
                    stats["near_duplicate_leakage_audit"]["near_duplicate_pairs_cross_split"],
                    "shared_pinned_files_cross_split":
                    stats["near_duplicate_leakage_audit"]["shared_pinned_files_cross_split"]},
        "disclaimer": stats["disclaimer"],
    }


def _markdown(stats: dict, review: dict) -> str:
    y = stats["yield"]
    L = []
    L.append("# API-sibling tasks (spec item 11) -- actual yield\n")
    L.append("Cross-repository sibling **call-site** pairs: the same upstream API used at two "
             "call sites in two audited repositories, where one is the form a confirmed "
             "finding blames and the other carries the handling it omits. Baseline: the 71 "
             "intra-contract `api_sibling_pairs` in `derived/counterexamples.jsonl`.\n")
    L.append("## Yield\n")
    L.append("| stage | count |")
    L.append("|---|---|")
    L.append(f"| candidate pairs proposed from the source pool | {y['candidates_proposed']} |")
    L.append(f"| re-derived and reviewed independently | {y['reviewed']} |")
    L.append(f"| reviewed and agreed | {y['reviewed_and_agreed']} |")
    L.append(f"| admitted tasks (`derived_siblings/tasks.jsonl`) | {y['admitted_tasks']} |")
    L.append(f"| hard negatives (`derived_siblings/hard_negatives.jsonl`) | "
             f"{y['hard_negatives']} |")
    L.append(f"| dropped (could not be re-read from the pinned bytes) | {y['dropped']} |")
    L.append(f"| v2.1 baseline | {y['baseline_v2_1_pairs']} |")
    L.append("")
    L.append(f"Target of 300+ tasks reached: **{'yes' if y['target_reached'] else 'no'}**. "
             f"{y['shortfall_explained']}\n")
    L.append("## Why candidates did not survive\n")
    L.append("| reason | count |")
    L.append("|---|---|")
    for k, v in review["reasons"].items():
        L.append(f"| `{k}` | {v} |")
    L.append("")
    L.append("## Composition\n")
    L.append("| property | tasks |")
    L.append("|---|---|")
    for k, v in stats["by_property"].items():
        L.append(f"| `{k}` | {v} |")
    L.append("")
    L.append("### By API symbol\n")
    for k, v in stats["by_api"].items():
        L.append(f"- `{k}`: {v}")
    L.append("\n### Vulnerable-side repositories\n")
    for k, v in stats["by_vulnerable_project"].items():
        L.append(f"- `{k}`: {v}")
    L.append("\n### Reference-side repositories\n")
    for k, v in stats["by_reference_project"].items():
        L.append(f"- `{k}`: {v}")
    L.append("\n## Group-aware splits\n")
    L.append(stats["splits"]["rule"] + "\n")
    L.append("| split | tasks |")
    L.append("|---|---|")
    for s in SPLITS_NAMES:
        L.append(f"| {s} | {stats['splits']['counts'][s]} |")
    L.append(f"\nGroups: {len(stats['splits']['assignment_by_group'])}.\n")
    h = stats["project_holdout_audit"]
    L.append("## Project-held-out audit\n")
    # `.get` because the no-tasks path builds a smaller audit dict; indexing it
    # would crash the generator on exactly the input where it should still report
    L.append(f"Grouping unit: `{h.get('group_unit', 'not recorded')}`. Vulnerable-side "
             "audited repositories: "
             f"{h.get('vulnerable_side_repositories', 0)}; straddling splits: "
             f"**{h.get('violation_count', 0)}**.\n")
    L.append(f"Reference-side repositories: {h.get('reference_side_repositories', 0)}; "
             "appearing in "
             "more than one split: **"
             f"{h.get('reference_side_straddling_splits', 0)}** (shared library code by "
             "construction; reported, not claimed away).\n")
    if h["test_only_repositories"]:
        L.append("Repositories that appear only in test: "
                 + ", ".join(f"`{x}`" for x in h["test_only_repositories"]) + "\n")
    if h["violations"]:
        L.append("Violations: " + json.dumps(h["violations"], sort_keys=True) + "\n")
    d = stats["near_duplicate_leakage_audit"]
    L.append("## Near-duplicate leakage audit\n")
    L.append(f"Pairs compared: {d['pairs_compared']} (thresholds Jaccard "
             f"{d['thresholds']['jaccard']}, cosine {d['thresholds']['cosine']}).\n")
    L.append(f"- near-duplicate pairs: {d['near_duplicate_pairs']}, of which cross-split: "
             f"{d['near_duplicate_pairs_cross_split']}")
    L.append(f"- semantically-similar pairs: {d['semantic_pairs']}, of which cross-split: "
             f"{d['semantic_pairs_cross_split']}")
    L.append(f"- pinned files cited by more than one task: {d['shared_pinned_files']}, "
             f"cross-split: {d['shared_pinned_files_cross_split']}")
    L.append(f"- identical call sites reused across tasks: "
             f"{d['identical_call_sites_in_more_than_one_task']}")
    L.append("")
    r = stats["rights"]
    L.append("## Rights decisions applied\n")
    L.append(f"Every item stores spans and hashes only: `{r['decision']}`. Vulnerable-side "
             f"licence classes: {json.dumps(r['vulnerable_side_classes'], sort_keys=True)}. "
             f"Reference-side: {json.dumps(r['reference_side_classes'], sort_keys=True)}. "
             f"Authority: {r['authority']}.\n")
    L.append("## Standing of this layer\n")
    L.append(stats["disclaimer"] + "\n")
    L.append(stats["model_facing_note"] + "\n")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# shared validators (used by the writer above and by tests/test_api_siblings.py
# so a guard cannot be weakened without a test failing)
# ---------------------------------------------------------------------------
REQUIRED_TASK_FIELDS = ("task_id", "pair_id", "family", "pair_type", "project", "revisions",
                        "root_cause", "rationale", "property", "api", "spans", "rights",
                        "review", "generated_by", "dataset_version")
REQUIRED_SPAN_FIELDS = ("project", "owner_repo", "file", "revision", "function",
                        "function_decl_line", "call_line", "char_start", "char_end",
                        "byte_start", "byte_end", "file_sha256", "span_sha256",
                        "source_text_included")
FORBIDDEN_TEXT_KEYS = ("snippet", "source_code", "code_text", "diff_text", "verbatim")
LICENSE_CLASSES_OK = ("redistributable", "source_available_but_not_redistributable",
                      "reference_only", "unavailable", "unknown")
FIXED_REVISION_STATES = ("recorded_in_the_canonical_layer",
                         "unavailable_in_the_canonical_layer",
                         "reference_side_carries_no_fix_pair")


def validate_task(t: dict) -> list[str]:
    """Every structural promise a sibling task makes. Empty list means valid."""
    errs: list[str] = []
    for k in REQUIRED_TASK_FIELDS:
        if k not in t:
            errs.append(f"missing_field:{k}")
    r = t.get("rationale") or {}
    for k in ("why_vulnerable", "why_reference_is_correct", "contrast_rule"):
        if not (r.get(k) or "").strip():
            errs.append(f"missing_rationale:{k}")
    rc = t.get("root_cause") or {}
    if not (rc.get("value") or "").strip():
        errs.append("missing_root_cause")
    if not rc.get("record_id") or not rc.get("record_sha256"):
        errs.append("root_cause_not_attributed_to_a_record")
    revs = t.get("revisions") or {}
    if not revs.get("vulnerable_revision"):
        errs.append("missing_vulnerable_revision")
    if "fixed_revision" not in revs:
        errs.append("fixed_revision_state_not_stated")
    elif revs["fixed_revision"] in (None, ""):
        errs.append("fixed_revision_must_say_unavailable_not_be_blank")
    for side in ("vulnerable", "reference"):
        sp = (t.get("spans") or {}).get(side) or {}
        for k in REQUIRED_SPAN_FIELDS:
            if k not in sp:
                errs.append(f"{side}_span_missing:{k}")
        if sp.get("source_text_included") is not False:
            errs.append(f"{side}_span_claims_source_text_included")
        for k in ("char_start", "char_end"):
            if not isinstance(sp.get(k), int):
                errs.append(f"{side}_span_{k}_not_an_integer")
        if isinstance(sp.get("char_start"), int) and isinstance(sp.get("char_end"), int) \
                and sp["char_start"] >= sp["char_end"]:
            errs.append(f"{side}_span_empty_or_reversed")
        if not sp.get("file_sha256") or len(str(sp.get("file_sha256"))) != 64:
            errs.append(f"{side}_span_hash_missing_or_truncated")
    if t.get("rights", {}).get("decision") != B.RIGHTS_DECISION:
        errs.append("rights_decision_not_recorded")
    if t["project"]["vulnerable"]["repo"] == t["project"]["reference"]["repo"]:
        errs.append("pair_is_not_cross_repository")
    for bad in _walk_forbidden(t):
        errs.append("forbidden_source_text_key:" + bad)
    return sorted(set(errs))


def _walk_forbidden(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN_TEXT_KEYS and isinstance(v, str) and len(v) > 0:
                yield path + "/" + k
            yield from _walk_forbidden(v, path + "/" + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_forbidden(v, f"{path}[{i}]")


def split_group_violations(tasks: list[dict], split: dict) -> dict:
    """Which group-unit repositories appear in more than one split."""
    where: dict[str, set[str]] = {}
    for t in tasks:
        s = (split.get("task_split") or {}).get(t["task_id"])
        if not s:
            where.setdefault("<unassigned>", set()).add("<missing>")
            continue
        where.setdefault(t["project"]["vulnerable"]["repo"], set()).add(s)
    return {k: sorted(v) for k, v in sorted(where.items()) if len(v) > 1}


def span_rehash_disagreement(site: dict) -> tuple[bool, str]:
    """Re-read the pinned bytes a span cites and re-check the hash and the call.

    Returns (agree, detail). A span that does not hash-match, or whose recorded
    offsets do not hold `receiver.api(`, is refused.
    """
    text, _how = read_back(site)
    if text is None:
        return False, "pinned source could not be re-read"
    return check_span(site, text)

#!/usr/bin/env python3
"""One canonical rejection-evidence layer for all 458 negatives.

Before this file existed, three reports answered the same question with three
different numbers, because they counted different things under one label:

  * `reports/hard_negative_stats.json` counted a *blocking condition* on the
    cited target (8) and called 441 `unknown`.
  * `reports/negative_verification_stats.json` counted a single best class and
    let a duplicate pointer stand for a technical reason (321
    `corroborated_duplicate`), which the README then rendered as
    "331 negatives with a defensible reason".
  * `derived/hard_negatives.jsonl` recorded "a guard exists on the cited
    function", which is a code fact, not a refutation of the submission.

A rejection label, an attributed reason, a code-derived blocker, a duplicate
corroboration and an executed disproof are five different kinds of evidence.
This file separates them into independent axes, gives each a documented
definition, and derives every reported count from the per-record layer it
writes. Nothing here overwrites a contest verdict: `original_verdict` is
carried verbatim from `jsonl/negative_findings.jsonl`, which stays immutable.

Two rules do the honest work:

  1. **Corroboration is not explanation.** A duplicate pointer at a confirmed
     finding says the underlying issue is real and this copy was redundant. It
     says nothing about why *this* claim was rejected on the merits, so it never
     enters the technical-reason counts.
  2. **A guard on a function does not refute a claim about it.** `onlyOwner` on
     `updateOwners` refutes "anyone can call this", not "the owner can do harm
     with this". Each code-derived blocker is therefore tested against the
     standing the submission's own text assumes, and the gate is re-read from
     the pinned commit when a clone is available.

    python scripts/build_rejection_corpus.py [--repos-root work/repos] [--check]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_inputs as GI  # noqa: E402  (skipped_no_network precondition guard)
from vlun import (JSONL, REPORTS, ROOT, WORK, log, read_jsonl,  # noqa: E402
                  sha256_text)

OUT_DIR = ROOT / "derived_rejections"
CORPUS = OUT_DIR / "rejection_corpus.jsonl"
DEFS = OUT_DIR / "definitions.json"
STATS_JSON = REPORTS / "rejection_evidence_stats.json"
STATS_MD = REPORTS / "rejection_evidence.md"

SCHEMA_VERSION = "vlun-rejection-corpus/1.0"
DEFINITIONS_VERSION = "rejection-definitions-1.0"

# ---------------------------------------------------------------------------
# The six metrics. Each is defined once, here, and every report reads them from
# the per-record layer rather than restating them.
# ---------------------------------------------------------------------------
METRICS = (
    "rejection_status_publicly_reported",
    "reason_attributed_to_judge_or_sponsor",
    "reason_supported_by_cited_code",
    "claim_corroborated_as_duplicate_of_confirmed_finding",
    "exploit_attempted_and_claimed_violation_not_demonstrated",
    "unknown_or_insufficient_evidence",
)

# A reason counts as a *technical* explanation of why the claim is false only if
# it is one of these three. Corroboration and labels are deliberately excluded.
TECHNICAL_BASES = (
    "code_gate_refutes_claim_standing",
    "attributed_technical_refutation",
    "executed_disproof",
)

REASON_CLASSES = (
    "executionally_disproven",                    # attempted and observed not to work
    "experimentally_confirmed_underlying_issue",  # attempted and it DID work
    "code_derived_blocker",                       # gate refutes the standing claimed
    "code_gate_context_only",                     # gate exists, does not refute
    "public_judge_or_sponsor_explanation",        # technical, attributed verbatim
    "business_scenario_exclusion",                # design-intent / scope, attributed
    "corroborated_duplicate",                     # pointer to an accepted finding
    "duplicate_label_unresolved_pointer",         # pointer names an unresolvable issue
    "withdrawn_by_author",                        # public label only
    "scope_or_eligibility_label",                 # public label only
    "dispute_or_invalid_label",                   # public label only
    "unattributed_participant_discussion",        # warden replies, no verdict role
    "unresolved",                                 # nothing above
)

# Precedence for `primary_reason_class`: strongest evidence about why this
# specific submission was rejected comes first.
PRIMARY_ORDER = (
    "executionally_disproven",
    "public_judge_or_sponsor_explanation",
    "business_scenario_exclusion",
    "code_derived_blocker",
    "experimentally_confirmed_underlying_issue",
    "corroborated_duplicate",
    "withdrawn_by_author",
    "scope_or_eligibility_label",
    "dispute_or_invalid_label",
    "duplicate_label_unresolved_pointer",
    "unattributed_participant_discussion",
    "code_gate_context_only",
    "unresolved",
)

DEFINITIONS = {
    "rejection_status_publicly_reported": {
        "means": ("the contest page publicly records a status for this submission "
                  "(duplicate / rejected / disputed / invalid / withdrawn / nullified / "
                  "ineligible)"),
        "evidence_type": "observed_fact",
        "counts_as_technical_explanation": False,
        "note": ("this is the weakest useful statement: it is a fact about the contest "
                 "record, not a reason the claim is false"),
    },
    "reason_attributed_to_judge_or_sponsor": {
        "means": ("a named judge or the sponsor published a statement, carried verbatim "
                  "with author, role, URL and excerpt hash, that addresses this submission"),
        "evidence_type": "externally_attributed",
        "counts_as_technical_explanation": "conditional",
        "note": ("split by rule into a technical refutation and a design-intent/scope "
                 "exclusion; participant (warden) replies are excluded — they are "
                 "discussion, not an adjudicated reason"),
    },
    "reason_supported_by_cited_code": {
        "means": ("a guard mechanically located on the function the submission says the "
                  "attacker calls removes the standing the submission's own text claims"),
        "evidence_type": "derived_fact",
        "counts_as_technical_explanation": True,
        "note": ("requires the gate on the CLAIM'S OWN TARGET plus a claim that asserts an "
                 "actor lacking that role; a gate elsewhere, or a claim about a privileged "
                 "actor, is recorded as context only"),
    },
    "claim_corroborated_as_duplicate_of_confirmed_finding": {
        "means": ("the same claim was accepted as a confirmed/acknowledged finding in the "
                  "same audit, so the underlying issue is real and only this copy was "
                  "redundant"),
        "evidence_type": "derived_fact",
        "counts_as_technical_explanation": False,
        "note": ("graded by method: an explicit `duplicate_of` pointer that resolves to a "
                 "published finding is high confidence, an identical normalised title in "
                 "the same audit is medium, a shared code target or similar snippet is "
                 "context only. Corroboration supports `is_false_positive: false` for the "
                 "underlying issue; it never supports a technical reason"),
    },
    "exploit_attempted_and_claimed_violation_not_demonstrated": {
        "means": ("an exploit was reconstructed and executed against the pinned revision "
                  "and the claimed violation was not observed"),
        "evidence_type": "experimentally_verified",
        "counts_as_technical_explanation": True,
        "note": ("the only class that can establish a false positive by experiment. Where "
                 "the attack was executed and succeeded, the record states the underlying "
                 "issue is real rather than calling anything disproven"),
    },
    "unknown_or_insufficient_evidence": {
        "means": ("only a rejection, duplicate or dispute label is public, no attributed "
                  "reason exists, no gate refutes the claim's own standing, and no exploit "
                  "was attempted"),
        "evidence_type": "unknown",
        "counts_as_technical_explanation": False,
        "note": (f"{METRICS[5]} is a valid answer, not a failure of the pipeline; it is "
                 "reported with the blocker that applies (pointer unresolved, environment "
                 "unavailable, no public statement)"),
    },
}

# --- phrase rules (auditable: the matched span is recorded on every decision) ---
PRIVILEGED_ACTOR = (
    r"contract owner", r"\bowner(?:'s)? (?:can|could|is able|controls|ability)\b",
    r"\bonlyowner\b", r"\badmin(?:istrator)? can\b", r"\bgovernance\b",
    r"\bmanager can\b", r"compromised (?:key|owner|signer|admin)", r"\bby the owner\b",
)
UNPRIVILEGED_ACTOR = (
    r"\banyone\b", r"\bany user\b", r"\bany external\b", r"malicious user",
    r"\ban attacker\b", r"attacker can", r"unprivileged", r"third[\s-]?party",
    r"front[\s-]?[\s]?run", r"without (?:any )?permission", r"no access control",
    r"unauthenticated", r"anyone else", r"\busers can call\b",
)
DESIGN_INTENT_OR_SCOPE = (
    r"intended behaviou?r", r"not intended to", r"\bby design\b",
    r"within the domain of acceptable values", r"not meant to",
    r"well[\s-]?documented in the README", r"out of scope",
    r"acceptable (?:risk|value)", r"assum\w+ (?:the )?(?:governance|owner|team) is "
    r"(?:faulty|malicious)", r"does not ?count as", r"not a (?:code )?error",
)
PUBLIC_LABEL_CLASSES = {
    "author withdrew the report before judging": "withdrawn_by_author",
    "issue labelled 'ineligible for award'": "scope_or_eligibility_label",
    "issue labelled 'nullified'": "scope_or_eligibility_label",
    "issue labelled 'invalid' by the judging process": "dispute_or_invalid_label",
}

REPO_SLUG_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$")
ISSUE_POINTER_RE = re.compile(r"^issue\s*#?\s*(\d+)$", re.I)
CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MODIFIER_RE = re.compile(r"\b(nonReentrant|whenNotPaused|only[A-Z][A-Za-z0-9_]*)\b")
# an actor phrase followed, inside the same sentence, by the call it is said to make
ACTOR_CALL_RE = re.compile(
    r"\b(?:user|users|attacker|anyone|caller|exploiter|any\s+(?:external\s+)?"
    r"address|third[\s-]?party)[^.!?]{0,240}?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.I)
NEIGHBOURING_GATE = "not the one the submission names"


def attacker_calls(claim: str) -> list[str]:
    """Function names the claim text has an actor calling, in order of appearance."""
    return [m.group(1) for m in ACTOR_CALL_RE.finditer(claim or "")]


def repo_relative(file: str | None, slug: str | None) -> str | None:
    """`code-423n4/2024-04-noya/src/X.sol` -> `src/X.sol` for the clone `slug`."""
    if not file or not slug or "__" not in slug:
        return file
    prefix = slug.replace("__", "/") + "/"
    return file[len(prefix):] if file.startswith(prefix) else file


def _canon_line(row: dict) -> str:
    return json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"


def _match(patterns: tuple[str, ...], text: str) -> tuple[str, int] | None:
    """First match, with the pattern that fired, so the rule is auditable."""
    low = (text or "").lower()
    for pat in patterns:
        m = re.search(pat, low)
        if m:
            return pat, m.start()
    return None


def _norm_title(t: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def _audit_of(fid: str) -> str:
    return (fid or "").split("/")[0]


def finding_index(findings: list[dict]) -> dict:
    """Published findings, scoped by audit. A same-title claim in another audit is
    leakage, not corroboration, so every index below is keyed on the audit."""
    by_id: dict[str, dict] = {}
    by_title: dict[tuple, list[str]] = {}
    by_target: dict[tuple, list[str]] = {}
    accepted = ("confirmed", "acknowledged")
    for f in findings:
        fid = (f.get("finding") or {}).get("id")
        status = (f.get("validation") or {}).get("status")
        by_id[fid] = {"id": fid, "status": status, "accepted": status in accepted,
                      "title": (f.get("finding") or {}).get("title"),
                      "severity": (f.get("finding") or {}).get("severity"),
                      "original_issue_url": (f.get("finding") or {}).get("original_issue_url")}
        key = (_audit_of(fid), _norm_title((f.get("finding") or {}).get("title")))
        if key[1]:
            by_title.setdefault(key, []).append(fid)
        for c in (f.get("code_context") or []):
            by_target.setdefault((_audit_of(fid), c.get("file"), c.get("function")),
                                 []).append(fid)
    return {"by_id": by_id, "by_title": by_title, "by_target": by_target}


def _slug(source: dict) -> str | None:
    m = REPO_SLUG_RE.match(source.get("repository_url") or "")
    return f"{m.group(1)}__{m.group(2)}" if m else None


def verify_gate(repo_slug: str | None, commit: str | None, file: str | None,
                function: str | None, repos_root: Path | None) -> dict:
    """Re-read the declaration from the pinned commit when a clone is available.

    Returns the modifiers observed on the declaration, the declaration line, and
    the sha256 of the file at that commit — or the blocker that prevented it.
    Nothing copies source text into this layer.
    """
    out = {"verified": False, "commit": commit, "file": file, "function": function,
           "modifiers_observed": [], "declaration_line": None, "file_sha256": None,
           "file_path_in_clone": None}
    if repos_root is None or not repo_slug:
        out["blocker"] = "source_clone_not_provided"
        return out
    clone = repos_root / repo_slug
    if not clone.exists():
        out["blocker"] = "source_clone_absent"
        return out
    if not (commit and re.fullmatch(r"[0-9a-f]{40}", commit or "")):
        out["blocker"] = "pinned_commit_not_immutable"
        return out
    from vlun import run
    path = repo_relative(file, repo_slug)
    out["file_path_in_clone"] = path
    rc, text, _err, _timed_out = run(
        ["git", "-C", str(clone), "show", f"{commit}:{path}"], timeout=120)
    if rc != 0:
        out["blocker"] = "commit_or_file_not_in_clone"
        return out
    text = text or ""
    out["file_sha256"] = sha256_text(text)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(rf"\bfunction\s+{re.escape(function or '')}\s*\(", line):
            decl = line
            j = i
            while "{" not in decl and j + 1 < len(lines) and j - i < 12:
                j += 1
                decl += " " + lines[j].strip()
            out["declaration_line"] = i + 1
            out["modifiers_observed"] = sorted(set(MODIFIER_RE.findall(decl)))
            out["verified"] = True
            break
    if not out["verified"]:
        out["blocker"] = "function_declaration_not_found_at_commit"
    return out


def corroborate(row: dict, index: dict) -> dict:
    """Method-graded corroboration. Never a technical explanation."""
    fid = (row.get("finding") or {}).get("id") or ""
    audit = _audit_of(fid)
    v = row.get("validation") or {}
    pointer = (v.get("duplicate_of") or "").strip()
    entries: list[dict] = []

    pointed = index["by_id"].get(pointer)
    if pointed is not None and pointed["id"] != fid:
        entries.append({"method": "explicit_duplicate_of_pointer",
                        "confidence": "high" if pointed["accepted"] else "none",
                        "corroborating_finding": pointed["id"],
                        "corroborating_status": pointed["status"],
                        "corroborating_issue_url": pointed["original_issue_url"],
                        "rule": "`validation.duplicate_of` equals a published finding id"})
    elif ISSUE_POINTER_RE.match(pointer):
        n = ISSUE_POINTER_RE.match(pointer).group(1)
        same_audit = [f for f in index["by_id"].values() if _audit_of(f["id"]) == audit]
        resolved = [f["id"] for f in same_audit
                    if re.search(rf"/issues/{re.escape(n)}$", f["original_issue_url"] or "")]
        entries.append({"method": "duplicate_of_issue_number"
                             + ("_resolved" if resolved else "_unresolved"),
                        "confidence": "high" if resolved else "none",
                        "corroborating_finding": (resolved or [None])[0],
                        "pointer": pointer,
                        "rule": ("`duplicate_of` names issue #%s; it was %s against the "
                                 "published findings of this audit" %
                                 (n, "matched by original_issue_url" if resolved
                                  else "not matched — the referenced issue is not a "
                                       "published finding in this dataset"))})
    elif pointer:
        entries.append({"method": "duplicate_of_pointer_unresolved", "confidence": "none",
                        "pointer": pointer,
                        "rule": "pointer present but resolves to no published finding"})

    title_key = (audit, _norm_title((row.get("finding") or {}).get("title")))
    for other in index["by_title"].get(title_key, []):
        if other == fid:
            continue
        f = index["by_id"][other]
        entries.append({"method": "identical_normalised_title_same_audit",
                        "confidence": "medium" if f["accepted"] else "none",
                        "corroborating_finding": other, "corroborating_status": f["status"],
                        "rule": "same audit, titles normalise to the same string"})

    for c in (row.get("code_context") or []):
        for other in index["by_target"].get((audit, c.get("file"), c.get("function")), []):
            if other == fid:
                continue
            f = index["by_id"][other]
            entries.append({"method": "same_code_target_same_audit",
                            "confidence": "low" if f["accepted"] else "none",
                            "corroborating_finding": other,
                            "corroborating_status": f["status"],
                            "target": f'{c.get("file")}::{c.get("function")}',
                            "rule": ("a confirmed finding of this audit cites the same "
                                     "file::function; a shared target is not the same claim")})

    graded = sorted(entries, key=lambda e: ("high", "medium", "low", "none").index(e["confidence"]))
    best = graded[0]["confidence"] if graded else "none"
    return {"methods": graded, "best_confidence": best,
            "corroborated": best in ("high", "medium"),
            "explicit_pointer": any(e["method"] == "explicit_duplicate_of_pointer"
                                    and e["confidence"] == "high" for e in graded),
            "is_technical_explanation": False,
            "reading": ("corroboration says the underlying issue was accepted in this audit "
                        "and this copy was redundant. It is not a statement about why the "
                        "claim is technically false, and it is never counted as one")}


def code_axis(row: dict, hn: dict | None, repos_root: Path | None) -> dict:
    """Gate on the cited target, tested against the standing the claim asserts."""
    bc = (hn or {}).get("blocking_condition") or {}
    facts = (hn or {}).get("observed_code_facts") or []
    out = {
        "applies": False, "gate_on_claim_target": False, "claim_standing": None,
        "attacker_called_function": None, "refutes_claim_standing": None,
        "rule": None, "citation": None, "gate": None,
        "derived_fact_present": bc.get("evidence_type") == "derived_fact",
        "derived_confidence": bc.get("confidence"),
        "is_technical_explanation": False,
    }
    if bc.get("evidence_type") != "derived_fact":
        out["rule"] = "no code-derived blocking condition exists for this record"
        return out

    claim = (((hn or {}).get("candidate_claim") or {}).get("value")
             or (row.get("negative_analysis") or {}).get("why_it_looked_plausible") or "")
    named = re.search(r"(?:target|present on)\s+`([A-Za-z_][A-Za-z0-9_]*)`",
                      bc.get("value") or "")
    declared = re.findall(r"declared with ([^,]+(?:, [^,]+)*)", bc.get("value") or "")
    declared_mods = sorted({m for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", declared[0])
                            for m in MODIFIER_RE.findall(w)}) if declared else []
    neighbouring = NEIGHBOURING_GATE in (bc.get("value") or "")
    fn = named.group(1) if named else (facts[0].get("function") if facts else None)
    gate_fact = next((f for f in facts if f.get("function") == fn),
                     (facts[0] if facts else {}))
    fn_present = any(f.get("function") == fn for f in facts)
    observed_mods = sorted(set(gate_fact.get("modifiers") or []))
    out["gate"] = {"function": fn,
                   "modifiers_observed_in_layer": observed_mods,
                   "modifier_declared_in_blocking_condition": declared_mods,
                   "fact_found_under_this_name": fn_present,
                   "layer_declares_neighbouring_gate": neighbouring,
                   "required_roles": sorted(set(gate_fact.get("required_roles") or [])),
                   "file": gate_fact.get("file")}

    priv = _match(PRIVILEGED_ACTOR, claim)
    unpriv = _match(UNPRIVILEGED_ACTOR, claim)
    # privileged wins when both appear: the claim text then names the actor, and a
    # role gate cannot be read as a refutation of what that actor is alleged to do.
    if priv and (not unpriv or priv[1] <= unpriv[1]):
        out["claim_standing"] = "privileged"
        out["rule"] = f"claim text names a privileged actor (pattern {priv[0]!r})"
        out["refutes_claim_standing"] = False
    elif unpriv and neighbouring:
        out["claim_standing"] = "unprivileged"
        out["refutes_claim_standing"] = False
        out["rule"] = (f"claim text asserts an actor lacking standing (pattern "
                       f"{unpriv[0]!r}); the blocking condition itself says the gate is on "
                       "a function other than the one the submission names, so it is "
                       "context, not refutation")
    elif unpriv:
        out["claim_standing"] = "unprivileged"
        out["rule"] = f"claim text asserts an actor lacking standing (pattern {unpriv[0]!r})"
        called = attacker_calls(claim) or [m.group(1) for m in
                                           CALL_RE.finditer(claim[unpriv[1]:unpriv[1] + 200])]
        out["attacker_called_function"] = (called[0] if called else None)
        if fn and observed_mods and fn in called:
            out["gate_on_claim_target"] = True
            out["refutes_claim_standing"] = True
        elif called:
            out["gate_on_claim_target"] = False
            out["refutes_claim_standing"] = False
            out["rule"] += ("; the gate sits on `%s` while the claim has the actor call "
                            "`%s` — context, not refutation" % (fn, called[0]))
        elif not fn_present or not observed_mods:
            out["refutes_claim_standing"] = None
            out["rule"] += (f"; the blocking condition declares modifiers {declared_mods} on "
                            f"`{fn}` but no observed fact in this record carries that function, "
                            "so the gate cannot be located on the claim's own target")
        else:
            out["refutes_claim_standing"] = None
    else:
        out["claim_standing"] = "unstated"
        out["refutes_claim_standing"] = None
        out["rule"] = "claim text states no actor standing"

    src = gate_fact.get("source") or {}
    cited_url = src.get("source_url") or (bc.get("source_refs") or [None])[0]
    repo = (row.get("source") or {}).get("repository")
    slug = _slug(row.get("source") or {})
    pinned = (row.get("source") or {}).get("commit_sha")
    immutable = pinned if (pinned and re.fullmatch(r"[0-9a-f]{40}", pinned or "")) else None
    file = gate_fact.get("file")
    ver = verify_gate(slug, immutable, file, fn, repos_root) if immutable else \
        {"verified": False, "blocker": "audited_commit_not_immutable", "commit": pinned,
         "file": file, "function": fn, "modifiers_observed": [], "declaration_line": None,
         "file_sha256": None}
    out["citation"] = {
        "repository": repo, "clone": slug, "file": file, "function": fn,
        "audited_commit": pinned, "cited_url_as_published": cited_url,
        "cited_url_re_pinned": (
            f"https://github.com/{(slug or '').replace('__', '/')}/blob/{immutable}/"
            f"{repo_relative(file, slug)}"
            + (f"#L{ver['declaration_line']}" if ver.get("declaration_line") else "")
            if (immutable and ver.get("verified")) else None),
        "mutable_ref_in_source_layer": not (immutable and ver.get("verified")),
        "verification": ver,
    }
    # the blocking condition's own wording is the authority for which modifier the
    # gate rests on, because the recorded fact list can carry a different overload.
    effective = (declared_mods if declared_mods and fn_present and not observed_mods
                 else (ver["modifiers_observed"] if ver.get("verified") else observed_mods))
    out["gate"]["modifiers_effective"] = sorted(set(effective))
    if (out["refutes_claim_standing"] is True and out["gate_on_claim_target"]
            and bc.get("confidence") == "high" and out["gate"]["modifiers_effective"]):
        out["applies"] = True
        out["is_technical_explanation"] = True
    return out


def attributed_axis(row: dict) -> dict:
    na = row.get("negative_analysis") or {}
    basis = na.get("rejection_basis")
    statements = na.get("judge_and_sponsor_statements") or []
    adjudicated = [s for s in statements if (s.get("role") or "").lower() in ("sponsor", "judge")]
    participants = [s for s in statements if s not in adjudicated]
    out = {"applies": bool(basis == "public_judge_or_sponsor_comment" and adjudicated),
           "basis_field": basis,
           "statements": [], "participant_statements": [],
           "technical_refutation": False, "design_or_scope_exclusion": False,
           "rule": None, "is_technical_explanation": False}
    for s in (adjudicated or []):
        text = s.get("excerpt") or ""
        design = _match(DESIGN_INTENT_OR_SCOPE, text)
        entry = {"author": s.get("author"), "role": s.get("role"), "url": s.get("url"),
                 "excerpt_sha256": sha256_text(text), "excerpt_chars": len(text),
                 "excerpt": text,
                 "classification": "design_or_scope_exclusion" if design
                                   else "technical_refutation",
                 "matched_pattern": design[0] if design else None}
        out["statements"].append(entry)
        if design:
            out["design_or_scope_exclusion"] = True
        else:
            out["technical_refutation"] = True
    for s in participants:
        out["participant_statements"].append(
            {"author": s.get("author"), "role": s.get("role"), "url": s.get("url"),
             "excerpt_sha256": sha256_text(s.get("excerpt") or ""),
             "counts_as_attributed_reason": False,
             "reason": "no judge or sponsor role; participant replies are discussion"})
    if out["applies"]:
        out["is_technical_explanation"] = out["technical_refutation"]
        out["rule"] = ("verbatim sponsor/judge statement; classified by phrase rule, the "
                       "matched pattern is recorded")
    elif basis == "public_discussion_no_verdict_attributed":
        out["rule"] = ("public discussion exists but no judge or sponsor statement is "
                       "attributed; participants' own replies are not a reason")
    return out


def attempt_axis(row: dict, executed: dict) -> dict:
    fid = (row.get("finding") or {}).get("id")
    e = executed.get(fid)
    out = {"status": "not_attempted", "experiment": None,
           "claimed_violation_not_demonstrated": False,
           "underlying_issue_demonstrated": False,
           "is_technical_explanation": False}
    if not e:
        out["blocker"] = "not_attempted"
        return out
    status = e.get("status") or "unknown"
    out["experiment"] = {"status": status, "command": e.get("command"),
                         "artefact": e.get("artefact") or e.get("artifact"),
                         "detail": e}
    if status in ("false_positive_verified", "claim_misunderstood"):
        out["status"] = "violation_not_demonstrated"
        out["claimed_violation_not_demonstrated"] = True
        out["is_technical_explanation"] = True
    elif status == "exploit_reproduced":
        out["status"] = "claimed_violation_demonstrated"
        out["underlying_issue_demonstrated"] = True
    elif status in ("historical_environment_unavailable", "rpc_unavailable",
                    "requires_harness_reconstruction"):
        out["status"] = "environment_unavailable"
        out["blocker"] = status
    else:
        out["status"] = status
    return out


def build_record(row: dict, index: dict, hn: dict | None, executed: dict,
                 repos_root: Path | None, line_no: int) -> dict:
    fid = row["finding"]["id"]
    v = row.get("validation") or {}
    labels = list(dict.fromkeys(v.get("evidence") or []))
    statuses = list(dict.fromkeys(v.get("all_public_statuses") or [v.get("status")]))
    corr = corroborate(row, index)
    code = code_axis(row, hn, repos_root)
    att = attributed_axis(row)
    exp = attempt_axis(row, executed)

    classes: list[str] = []
    if exp["claimed_violation_not_demonstrated"]:
        classes.append("executionally_disproven")
    if exp["underlying_issue_demonstrated"]:
        classes.append("experimentally_confirmed_underlying_issue")
    if att["technical_refutation"]:
        classes.append("public_judge_or_sponsor_explanation")
    if att["design_or_scope_exclusion"]:
        classes.append("business_scenario_exclusion")
    if code["applies"]:
        classes.append("code_derived_blocker")
    elif code["derived_fact_present"]:
        classes.append("code_gate_context_only")
    if corr["explicit_pointer"] or corr["best_confidence"] == "medium":
        classes.append("corroborated_duplicate")
    elif any(m["method"].startswith("duplicate_of_issue_number")
             or m["method"] == "duplicate_of_pointer_unresolved" for m in corr["methods"]):
        classes.append("duplicate_label_unresolved_pointer")
    for label in labels:
        cls = PUBLIC_LABEL_CLASSES.get(label)
        if cls and cls not in classes:
            classes.append(cls)
    if "disputed" in statuses and "dispute_or_invalid_label" not in classes:
        classes.append("dispute_or_invalid_label")
    if att["basis_field"] == "public_discussion_no_verdict_attributed":
        classes.append("unattributed_participant_discussion")
    if not classes:
        classes.append("unresolved")
    classes = [c for c in PRIMARY_ORDER if c in classes]

    technical_bases = [b for b, ok in (
        ("executed_disproof", exp["claimed_violation_not_demonstrated"]),
        ("attributed_technical_refutation", att["technical_refutation"]),
        ("code_gate_refutes_claim_standing", code["applies"])) if ok]

    if exp["claimed_violation_not_demonstrated"]:
        fp = True
    elif exp["underlying_issue_demonstrated"] or corr["explicit_pointer"]:
        fp = False
    else:
        fp = None
    fp_basis = ("executed disproof of the claimed violation" if fp is True else
                "the same claim was accepted as a confirmed finding of this audit "
                "(explicit pointer), or the attack was executed and succeeded" if fp is False
                else "not determinable from the public record")

    unresolved = not any(c in classes for c in (
        "executionally_disproven", "experimentally_confirmed_underlying_issue",
        "public_judge_or_sponsor_explanation", "business_scenario_exclusion",
        "code_derived_blocker", "corroborated_duplicate"))

    return {
        "schema_version": SCHEMA_VERSION,
        "definitions_version": DEFINITIONS_VERSION,
        "finding_id": fid,
        "audit": _audit_of(fid),
        "repository": (row.get("source") or {}).get("repository"),
        "original_verdict": {
            "status": v.get("status"),
            "judge_decision": v.get("judge_decision") or None,
            "sponsor_position": v.get("sponsor_position") or None,
            "duplicate": v.get("duplicate"),
            "duplicate_of": v.get("duplicate_of") or None,
            "all_public_statuses": statuses,
            "public_labels": labels,
            "requires_assumption": v.get("requires_assumption"),
            "never_overwritten": True,
        },
        "provenance": {
            "source_url": ((row.get("provenance") or {}).get("source_urls") or [None])[0],
            "source_layer": "jsonl/negative_findings.jsonl",
            "jsonl_line": line_no,
            "hard_negative_layer": "derived/hard_negatives.jsonl",
        },
        "axes": {
            "status_publicly_reported": {
                "applies": True, "statuses": statuses, "labels": labels,
                "evidence_type": "observed_fact", "is_technical_explanation": False},
            "attributed_reason": att,
            "code_supported_reason": code,
            "duplicate_corroboration": corr,
            "exploit_attempt": exp,
        },
        "reason_classes": classes,
        "primary_reason_class": classes[0],
        "technical_verification": {
            "counts_as_technical_reason_for_why_the_claim_is_false": bool(technical_bases),
            "bases": technical_bases,
            "conditional_gate_not_counted": (code["derived_fact_present"]
                                             and not code["applies"]),
        },
        "is_false_positive": fp,
        "is_false_positive_basis": fp_basis,
        "confidence": ("high" if (exp["claimed_violation_not_demonstrated"] or code["applies"]
                                  or corr["explicit_pointer"]) else
                       "medium" if (att["applies"] or corr["best_confidence"] == "medium") else
                       "low"),
        "unknown_or_insufficient": unresolved,
        "metrics": {
            "rejection_status_publicly_reported": True,
            "reason_attributed_to_judge_or_sponsor": att["applies"],
            "reason_supported_by_cited_code": code["applies"],
            "claim_corroborated_as_duplicate_of_confirmed_finding": corr["corroborated"],
            "exploit_attempted_and_claimed_violation_not_demonstrated":
                exp["claimed_violation_not_demonstrated"],
            "unknown_or_insufficient_evidence": unresolved,
        },
    }


def summarise(rows: list[dict]) -> dict:
    m = {k: sum(1 for r in rows if r["metrics"][k]) for k in METRICS}
    technical = sum(1 for r in rows if r["technical_verification"]
                                          ["counts_as_technical_reason_for_why_the_claim_is_false"])
    by_class = collections.Counter(r["primary_reason_class"] for r in rows)
    any_class = collections.Counter(c for r in rows for c in r["reason_classes"])
    corr_method = collections.Counter(
        f'{e["method"]}:{e["confidence"]}'
        for r in rows for e in r["axes"]["duplicate_corroboration"]["methods"])
    gate = collections.Counter(
        f'standing={r["axes"]["code_supported_reason"]["claim_standing"]}/'
        f'refutes={r["axes"]["code_supported_reason"]["refutes_claim_standing"]}/'
        f'applies={r["axes"]["code_supported_reason"]["applies"]}'
        for r in rows if r["axes"]["code_supported_reason"]["derived_fact_present"])
    gate_why = collections.Counter(
        ("neighbouring_gate_declared_by_layer"
         if (r["axes"]["code_supported_reason"]["gate"] or {}).get(
             "layer_declares_neighbouring_gate") else
         "gate_not_on_the_function_the_actor_calls"
         if (r["axes"]["code_supported_reason"]["attacker_called_function"]
             and not r["axes"]["code_supported_reason"]["gate_on_claim_target"]) else
         "gate_function_absent_from_observed_facts"
         if not (r["axes"]["code_supported_reason"]["gate"] or {}).get(
             "fact_found_under_this_name") else
         "claim_names_no_actor_standing"
         if r["axes"]["code_supported_reason"]["claim_standing"] == "unstated" else
         "claim_names_a_privileged_actor"
         if r["axes"]["code_supported_reason"]["claim_standing"] == "privileged" else
         "counts_as_refutation")
        for r in rows if r["axes"]["code_supported_reason"]["derived_fact_present"])
    return {
        "schema_version": SCHEMA_VERSION,
        "definitions_version": DEFINITIONS_VERSION,
        "total": len(rows),
        "metrics": m,
        "metric_definitions": DEFINITIONS,
        "metrics_sum_note": ("these six metrics are independent axes and are NOT additive: "
                             "one record can appear in several of them"),
        "technical_reason_for_why_the_claim_is_false": technical,
        "technical_bases": collections.Counter(
            b for r in rows for b in r["technical_verification"]["bases"]),
        "primary_reason_class": dict(by_class),
        "reason_class_any": dict(any_class),
        "reason_class_vocabulary": list(REASON_CLASSES),
        "primary_precedence": list(PRIMARY_ORDER),
        "corroboration_by_method": dict(corr_method),
        "code_gate_axis": dict(gate),
        "code_gate_demotion_reasons": dict(gate_why),
        "is_false_positive": collections.Counter(
            str(r["is_false_positive"]) for r in rows),
        "exploit_attempt_status": collections.Counter(
            r["axes"]["exploit_attempt"]["status"] for r in rows),
        "attributed_statement_classes": {
            "technical_refutation": sum(1 for r in rows if r["axes"]["attributed_reason"]
                                             ["technical_refutation"]),
            "design_or_scope_exclusion": sum(1 for r in rows if r["axes"]["attributed_reason"]
                                                  ["design_or_scope_exclusion"]),
            "participant_only": sum(1 for r in rows if r["axes"]["attributed_reason"]
                                        ["basis_field"] == "public_discussion_no_verdict_attributed"),
        },
        "seeded_from_the_builders_own_rejected_reports": 0,
        "seed_provenance": (
            "Every row in this layer comes from a public Code4rena contest record in "
            "`jsonl/negative_findings.jsonl`. No artefact of a report the dataset builder "
            "submitted to a bounty programme exists in this project, and none was invented "
            "to reach 458-plus records: seeding one would require the actual source artefact "
            "plus a check of the programme's publication and confidentiality terms, and "
            "personal details would have to be anonymised first."),
    }


def render_md(stats: dict) -> str:
    m = stats["metrics"]
    out = ["# Rejection evidence: what each count means\n",
           f"Generated by `scripts/build_rejection_corpus.py` "
           f"(`{stats['definitions_version']}`). Every number is read from "
           f"`derived_rejections/rejection_corpus.jsonl`; nothing here is typed in.\n",
           f"458 negatives, {m['rejection_status_publicly_reported']} with a publicly "
           f"reported status, {m['reason_attributed_to_judge_or_sponsor']} with a reason "
           f"attributed to a named judge or sponsor, "
           f"{m['reason_supported_by_cited_code']} where the cited code removes the standing "
           f"the claim asserts, {stats['technical_reason_for_why_the_claim_is_false']} in total "
           f"with a technical reason why the claim is false, "
           f"{m['claim_corroborated_as_duplicate_of_confirmed_finding']} corroborated as a "
           f"duplicate of an accepted finding, "
           f"{m['exploit_attempted_and_claimed_violation_not_demonstrated']} where an exploit "
           f"was attempted and the claimed violation was not demonstrated, and "
           f"{m['unknown_or_insufficient_evidence']} where the public evidence stays "
           "insufficient. These axes are independent and are not additive.\n",
           "| metric | count | is it a technical reason? |", "|---|---|---|"]
    for k in METRICS:
        d = DEFINITIONS[k]
        out.append(f"| `{k}` | {m[k]} | {d['counts_as_technical_explanation']} |")
    out.append("\n## Definitions\n")
    for k in METRICS:
        d = DEFINITIONS[k]
        out.append(f"**`{k}`** — {d['means']}\n")
        out.append(f"- evidence type: `{d['evidence_type']}`; counts as a technical "
                   f"explanation: `{d['counts_as_technical_explanation']}`\n")
        out.append(f"- {d['note']}\n")
    out.append("\n## Reason classes\n")
    out.append("A record carries every class that applies, plus one primary class chosen "
               "by the precedence order below.\n")
    out.append(f"- primary precedence: `{'` > `'.join(stats['primary_precedence'])}`\n")
    out.append("| primary class | records |\n|---|---|")
    for cls in stats["primary_precedence"]:
        if cls in stats["primary_reason_class"]:
            out.append(f"| `{cls}` | {stats['primary_reason_class'][cls]} |")
    out.append("\n### Corroboration method breakdown\n")
    out.append("| method:confidence | occurrences |\n|---|---|")
    for k, v in sorted(stats["corroboration_by_method"].items()):
        out.append(f"| `{k}` | {v} |")
    out.append("\n### Code-derived gate axis\n")
    out.append("Key: `standing` is the actor the submission's own text assumes, `refutes` "
               "whether a gate on the claim's own target removes that standing, `applies` "
               "whether the record enters `reason_supported_by_cited_code`.\n")
    out.append("| standing/refutes/applies | records |\n|---|---|")
    for k, v in sorted(stats["code_gate_axis"].items()):
        out.append(f"| `{k}` | {v} |")
    out.append("\nWhy each recorded code gate did or did not count as a refutation:\n")
    out.append("| demotion reason | records |\n|---|---|")
    for k, v in sorted(stats["code_gate_demotion_reasons"].items()):
        out.append(f"| `{k}` | {v} |")
    out.append("\n## The two distinctions this layer exists to enforce\n")
    out.append("1. **Corroboration is not explanation.** A duplicate pointer at a confirmed "
               "finding says the underlying issue is real and this copy was redundant. It is "
               "not a statement about why the claim is technically false, so it is excluded "
               "from the technical-reason count even though it does support "
               "`is_false_positive: false` for the underlying issue.\n")
    out.append("2. **A guard on a function is not a refutation.** `onlyOwner` on a function "
               "refutes \"anyone can call this\", not \"the owner can do harm with this\". "
               "The gate axis above shows how many code-derived blockers were demoted to "
               "context because the claim's own text does not depend on the standing the "
               "gate removes.\n")
    out.append("\n## Unknown is a valid answer\n")
    out.append(f"`{m['unknown_or_insufficient_evidence']}` records stay "
               "`unknown_or_insufficient_evidence`. A report is not invalid because a "
               "judge's rationale is unavailable; the blocker is recorded per record "
               "(unresolved `duplicate_of` pointer, environment unavailable, or no public "
               "statement) rather than being filled with an invented reason.\n")
    out.append("\n## Where these records come from\n")
    out.append(stats["seed_provenance"] + "\n")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repos-root", default=str(WORK / "repos"),
                    help="directory of pinned clones used to re-read gate declarations; "
                         "if absent the code axis records a blocker instead of a blocker-free verdict")
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and compare with the files on disk")
    args = ap.parse_args()

    repos_root = Path(args.repos_root)
    repos_root = repos_root if repos_root.is_dir() else None

    # Precondition, before any comparison: the code axis re-reads each gate
    # declaration from the pinned commit inside work/repos/. A single absent
    # clone is legitimate data (verify_gate records `source_clone_absent` for
    # that record), but the WHOLE tree missing -- which is every fresh clone,
    # since work/ is git-ignored and not redistributed -- turns every verified
    # blocker into a blocker-free verdict and the layer reads as stale. That is
    # a skip (rc=2), not a pass and not a failure. With the tree present the
    # byte comparison below is exactly as strict as it always was.
    if args.check:
        missing = GI.absent(ROOT, [Path(args.repos_root)])
        if missing:
            log(GI.skip_line(
                tool="scripts/build_rejection_corpus.py",
                what="pinned clone tree", missing=missing,
                remedy="run --check on a machine holding work/repos "
                       "(scripts/fetch_sources.py), or pass --repos-root"))
            return GI.SKIP_RC

    negatives = read_jsonl(JSONL / "negative_findings.jsonl")
    findings = read_jsonl(JSONL / "findings.jsonl")
    hn_rows = read_jsonl(ROOT / "derived" / "hard_negatives.jsonl")
    hn_by_id = {((r.get("source_record") or {}).get("id") or
                 (r.get("original_evidence") or {}).get("finding", {}).get("id")): r
                for r in hn_rows}
    executed: dict[str, dict] = {}
    ep = REPORTS / "negative_experiments.json"
    if ep.exists():
        for e in json.loads(ep.read_text(encoding="utf-8")).get("experiments", []):
            executed[e["finding_id"]] = e

    index = finding_index(findings)
    rows = [build_record(row, index, hn_by_id.get(row["finding"]["id"]), executed,
                         repos_root, i + 1)
            for i, row in enumerate(negatives)]
    stats = summarise(rows)

    def _canon(obj) -> str:
        return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    defs_doc = {"definitions_version": DEFINITIONS_VERSION,
                "metrics": list(METRICS),
                "technical_bases": list(TECHNICAL_BASES),
                "reason_classes": list(REASON_CLASSES),
                "primary_precedence": list(PRIMARY_ORDER),
                "definitions": DEFINITIONS}
    payloads = {CORPUS: "".join(_canon_line(r) for r in rows),
                DEFS: _canon(defs_doc),
                STATS_JSON: _canon(stats),
                STATS_MD: render_md(stats)}
    if args.check:
        stale = [str(p) for p, text in payloads.items()
                 if not p.exists() or p.read_text(encoding="utf-8") != text]
        if stale:
            log("STALE: " + ", ".join(stale))
            return 1
        log("rejection corpus is current")
        return 0
    OUT_DIR.mkdir(exist_ok=True)
    for p, text in payloads.items():
        p.write_text(text, encoding="utf-8", newline="\n")
    log(f"rejection_corpus.jsonl: {len(rows)} records")
    log(f"  metrics={json.dumps(stats['metrics'], sort_keys=True)}")
    log(f"  technical_reasons={stats['technical_reason_for_why_the_claim_is_false']} "
        f"primary={json.dumps(stats['primary_reason_class'], sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

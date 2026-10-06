#!/usr/bin/env python3
"""VLUN V3.1 normalization: evidence extraction over the V3.0 candidate layer.

Reads ``derived_v3/candidate_ledger.jsonl`` (V3.0, never rewritten) plus the
vendored sources in ``V3/clones/`` and produces an ADDITIVE normalization
layer: fragments with character spans, field overlays with evidence, an
admitted preview, patch candidates, experiment readiness, and the sec-29
unknown audit. Extracted full text stays in temp space (METADATA_ONLY).

Stable identities: ``source_id:report_stem:native_finding_id`` (+ ``~dupN``).

    python scripts/normalize_v3.py
    python scripts/normalize_v3.py --check   # compute, write nothing
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v31_extract as X  # noqa: E402
import vlun_v3 as V  # noqa: E402
from build_v3 import _load_existing_overlap as _v3_overlap_loader  # noqa: E402

U = V.UNKNOWN
NORM_VERSION = "3.1"
_EXIST_NAMES: set[str] = set()
_EXIST_TITLES: set[str] = set()
_EXIST_COMMITS: set[str] = set()
_GENERIC_TITLES = {"qa report", "gas report", "gas optimizations"}

# ---------------------------------------------------------------------------
# Severity normalisation. Direct vocabulary matches are explicit; auditor
# scales are positional mappings with the original preserved (derived).
# ---------------------------------------------------------------------------

VLUN_SEV = {"Critical", "High", "Medium", "Low", "Informational"}
ABDK_SCALE = {"Critical": "Critical", "Major": "High",
              "Moderate": "Medium", "Minor": "Low"}
ABDK_SCALE_METHOD = ("auditor-scale positional mapping (Critical > Major > "
                     "Moderate > Minor observed in ABDK summary tables); "
                     "original label preserved")
NETH_EXTRA = {"Info": "Informational", "Best Practices": "Informational"}
NETH_EXTRA_METHOD = ("auditor label denotes a non-severity note class; "
                     "mapped to Informational, original preserved")


def normalize_severity(reported: str, source_id: str) -> tuple[str, str, str]:
    """(normalized, confidence, method). Unknown stays unknown."""
    if not reported or reported == U:
        return U, U, "no severity reported"
    r = reported.strip()
    if r in VLUN_SEV:
        return r, "explicit", "exact vocabulary match on reported severity"
    low = r.lower()
    for v in VLUN_SEV:
        if low == v.lower():
            return v, "explicit", "case-insensitive vocabulary match"
    if source_id == "abdk-audits" and r in ABDK_SCALE:
        return ABDK_SCALE[r], "derived", ABDK_SCALE_METHOD
    if source_id == "nethermind-audits" and r in NETH_EXTRA:
        return NETH_EXTRA[r], "derived", NETH_EXTRA_METHOD
    if source_id == "cyba-audits" and r in ("S", "Suggestion"):
        return "Informational", "derived", (
            "Suggestion-grade auditor prefix; mapped to Informational, "
            "original preserved")
    if r.startswith("S-") and source_id == "cyba-audits":
        return "Informational", "derived", (
            "Suggestion-grade finding ID prefix; original preserved")
    return U, U, f"no defensible mapping for reported severity {r!r}"


# ---------------------------------------------------------------------------
# Taxonomy. Explicit auditor labels first; conservative multi-signal keyword
# rules second (derived, capped); unknown otherwise. Multi-label supported.
# ---------------------------------------------------------------------------

VLUN_CLASSES = [
    "Access Control", "Arithmetic", "Authentication", "Authorization",
    "Business Logic", "Denial of Service", "Economic Attack", "Front-running",
    "Initialization", "Oracle Manipulation", "Price Manipulation",
    "Reentrancy", "Signature Validation", "State Validation",
    "Time Manipulation", "Unchecked Low-Level Call", "Upgradeability",
    "Validation Bypass", "Input Validation", "Accounting Error",
    "Precision / Rounding", "Storage Collision", "Cross-chain / Bridge",
    "Message Validation", "Replay Attack", "Nonce Management",
    "Flash-loan Attack", "MEV", "Randomness", "Other", "Unknown",
]

# class -> (strong phrases, support keywords). Derived fires on 1 strong or
# >=2 distinct support hits. All matching is case-insensitive substring.
TAX_SIGNALS: dict[str, tuple[list[str], list[str]]] = {
    "Reentrancy": (["reentrancy", "reentrant", "re-enter", "reenter"],
                   ["external call", "callback", "checks-effects-interactions",
                    "state change after", "withdrawal pattern"]),
    "Access Control": (["access control", "unauthorized access",
                        "unprotected function", "missing access",
                        "onlyowner bypass", "unrestricted access"],
                       ["onlyowner", "privileged role", "authorization",
                        "permission check", "admin rights", "access control"]),
    "Arithmetic": (["integer overflow", "integer underflow", "phantom overflow",
                    "overflow/underflow", "overflow / underflow", "overflow",
                    "underflow"],
                   ["precision loss", "rounding",
                    "integer division", "muldiv", "truncat", "unsafe cast"]),
    "Precision / Rounding": (["precision loss", "rounding error"],
                             ["precision", "rounding", "decimal", "scale factor",
                              "dust amount"]),
    "Oracle Manipulation": (["oracle manipulation", "price oracle attack"],
                            ["oracle", "price feed", "twap", "spot price",
                             "price manipulation", "stale price"]),
    "Price Manipulation": (["price manipulation", "price oracle attack"],
                           ["price feed", "twap", "spot price", "oracle",
                            "price impact", "slippage"]),
    "Signature Validation": (["signature replay", "invalid signature",
                              "signature malleability"],
                             ["signature", "ecdsa", "replay", "nonce",
                              "permit", "eip-712", "malleab", "ecrecover"]),
    "Replay Attack": (["replay attack", "replay protection", "replayable"],
                      ["nonce", "already executed"]),
    "Cross-chain / Bridge": (["cross-chain", "crosschain", "bridge exploit",
                              "message verification"],
                             ["bridge", "relayer", "optimism",
                              "arbitrum", "message", "finaliz"]),
    "Denial of Service": (["denial of service", "dos attack", "dos on",
                           "denial-of-service"],
                           ["grief", "bricked", "stuck funds",
                            "unbounded loop", "gas griefing"]),
    "Initialization": (["uninitialized", "initialize callable",
                        "front-run init", "uninitialised"],
                       ["initialize", "initializer", "constructor",
                        "proxy admin", "implementation slot"]),
    "Upgradeability": (["storage collision", "delegatecall injection",
                        "upgradeable proxy", "delegatecall"],
                       ["upgrade", "proxy", "implementation",
                        "storage layout", "diamond"]),
    "Storage Collision": (["storage collision", "storage slot collision"],
                          ["storage slot", "slot collision"]),
    "Front-running": (["front-running", "frontrunning", "sandwich attack",
                       "front-run", "frontrun"],
                      ["sandwich", "mempool"]),
    "MEV": (["mev", "maximal extractable value", "sandwich attack"],
            ["sandwich", "validator extract"]),
    "Flash-loan Attack": (["flash loan attack", "flashloan attack",
                           "flash loan", "flashloan", "flash swap"],
                          []),
    "Randomness": (["weak randomness", "predictable random", "randomness"],
                   ["random", "entropy", "vrf", "block.timestamp",
                    "blockhash", "predictable"]),
    "Time Manipulation": (["timestamp dependence", "timestamp manipulation"],
                          ["timestamp", "deadline", "expiry", "block.number",
                           "time lock"]),
    "Unchecked Low-Level Call": (["unchecked low-level", "unchecked call",
                                  "returndata"],
                                 ["low-level call", "unchecked", "staticcall",
                                  "callcode", "return value ignored"]),
    "Accounting Error": (["accounting error", "share inflation",
                          "inflation attack", "donation attack"],
                         ["accounting", "share", "balance mismatch",
                          "total supply", "exchange rate"]),
    "State Validation": (["state validation", "invalid state transition",
                          "post-condition", "postcondition"],
                         ["state machine", "invariant violation", "transition",
                          "postcondition"]),
    "Input Validation": (["missing validation", "insufficient validation",
                          "input validation", "missing input validation",
                          "no validation", "lack of validation"],
                         ["validat", "sanitiz", "bounds check",
                          "zero address", "input"]),
    "Validation Bypass": (["validation bypass", "bypass check"],
                           ["bypass", "circumvent", "skip validation"]),
    "Message Validation": (["message validation", "invalid message"],
                            ["payload", "packet", "channel"]),
    "Nonce Management": (["nonce management", "nonce reuse"],
                         ["sequence number"]),
    "Business Logic": (["business logic", "business-logic flaw",
                        "logic error"],
                       ["economic", "incentive",
                        "mechanism design"]),
    "Economic Attack": (["economic attack", "economic exploit"],
                        ["economic", "profit", "arbitrage", "incentive"]),
}

# Auditor Category value -> VLUN class, used only when the auditor uses the
# exact label (explicit) or the documented near-label (derived + rule note).
AUDITOR_CATEGORY_MAP = {
    "business logic": ("Business Logic", "explicit"),
    "reentrancy": ("Reentrancy", "explicit"),
    "access control": ("Access Control", "explicit"),
    "arithmetic": ("Arithmetic", "explicit"),
    "overflow/underflow": ("Arithmetic", "derived"),
    "overflow / underflow": ("Arithmetic", "derived"),
    "price manipulation": ("Price Manipulation", "derived"),
    "oracle manipulation": ("Oracle Manipulation", "derived"),
    "denial of service": ("Denial of Service", "explicit"),
    "front-running": ("Front-running", "explicit"),
    "signature": ("Signature Validation", "derived"),
}


CYBA_LETTER_SEV = {"C": "Critical", "H": "High", "M": "Medium",
                   "L": "Low"}


def _header_severity(native_id: str, header_text: str,
                     source_id: str) -> tuple[str, str, str]:
    """Severity from auditor header conventions. (reported, conf, method)."""
    m = re.match(r"\[?(Critical|High|Medium|Moderate|Major|Minor|Low|"
                 r"Informational)\]?", header_text.strip(), re.I)
    if m:
        word = m.group(1)
        for v in ("Critical", "High", "Medium", "Low", "Informational",
                  "Major", "Moderate", "Minor"):
            if word.lower() == v.lower():
                return v, "explicit", (
                    "severity word carried in finding header")
    m = re.match(r"\[?([CHML])-(\d+)\]?", native_id.strip())
    if m and source_id == "cyba-audits":
        return (CYBA_LETTER_SEV[m.group(1)], "explicit",
                "auditor finding-ID severity prefix ([H]-NN convention)")
    m = re.search(r"<<status:(.*?)>>", header_text)
    status_hint = m.group(1).strip() if m else U
    return U, U, "no severity in header"


def _header_status(header_text: str) -> str:
    m = re.search(r"<<status:(.*?)>>", header_text)
    return m.group(1).strip()[:40] if m else U


def map_taxonomy(category_reported: str | None, title: str,
                 body_sample: str) -> tuple[list[str], str, str, list[str]]:
    """(classes, confidence, method, matched_terms). Unknown-safe."""
    if category_reported and category_reported != U:
        key = category_reported.strip().lower()
        if key in AUDITOR_CATEGORY_MAP:
            cls, conf = AUDITOR_CATEGORY_MAP[key]
            method = ("explicit auditor Category field "
                      f"{category_reported!r} mapped to {cls}")
            if conf == "explicit" and cls.lower() == key:
                method += " (exact vocabulary match)"
            return [cls], conf, method, [category_reported]
        for v in VLUN_CLASSES:
            if key == v.lower():
                return [v], "explicit", (
                    f"auditor Category field exactly names VLUN class {v}"), \
                    [category_reported]
    text = f"{title}\n{body_sample}".lower()
    fired: list[tuple[str, list[str]]] = []
    for cls, (strong, support) in TAX_SIGNALS.items():
        shits = sorted({p for p in strong if p in text})
        suphits = sorted({k for k in support if k in text})
        if shits or len(suphits) >= 2:
            fired.append((cls, shits + suphits))
    if not fired:
        return ["Unknown"], U, ("no explicit label and no multi-signal rule "
                                "fired; left unknown"), []
    fired.sort(key=lambda x: x[0])
    classes = [c for c, _ in fired]
    terms = sorted({t for _, ts in fired for t in ts})[:12]
    return classes, "derived", ("conservative multi-signal keyword rules "
                                "(1 strong phrase or >=2 support terms)"), terms


# ---------------------------------------------------------------------------
# Language / ecosystem resolver. Explicit evidence wins; Rust/Go alone never
# determine a chain (spec sec 9).
# ---------------------------------------------------------------------------

LANG_SIGNALS = [
    (r"\.clar\b", "clarity", "stacks"),
    (r"\bclarity\b", "clarity", "stacks"),
    (r"\bstacks\b", "clarity", "stacks"),
    (r"\.sw\b", "sway", "fuel"),
    (r"\bsway\b", "sway", "fuel"),
    (r"\bfuel\b(?! (tank|efficiency))", "sway", "fuel"),
    (r"\.cairo\b", "cairo", "starknet"),
    (r"\bstarknet\b", "cairo", "starknet"),
    (r"\.move\b", "move", None),
    (r"\bsui::", "move", "sui"),
    (r"\baptos::", "move", "aptos"),
    (r"\.vy\b|\bvyper\b", "vyper", "evm"),
    (r"\.sol\b|\bsolidity\b", "solidity", "evm"),
    (r"\bcosmwasm\b|\bcw-[a-z]", "rust", "cosmos"),
    (r"\bsubstrate\b|\bpallet\b|\bframe\b", "rust", "substrate"),
    (r"\banchor\b", "rust", "solana"),
    (r"\bsolana\b", "rust", "solana"),
    (r"\bsoroban\b|\bstellar\b", "rust", "stellar"),
    (r"\bibc-go\b|\bcosmos\b", None, "cosmos"),
    (r"\bton\b", None, "ton"),
]


def resolve_lang_eco(code_files: list[str], text_sample: str,
                     old_lang: str, old_eco: str,
                     old_lang_ev: str) -> tuple[str, str, str, str]:
    """(language, ecosystem, confidence, method). Never contradicts explicit
    README-table evidence; Rust/Go alone cannot name a chain."""
    if old_lang_ev.startswith("observed_fact"):
        return old_lang, old_eco, "explicit", (
            "carried from v3.0 README-table evidence; text scan found no "
            "contradiction rule firing")
    hay = " ".join(code_files) + "\n" + text_sample[:3000].lower()
    votes: dict[tuple[str, str | None], list[str]] = {}
    for pat, lang, eco in LANG_SIGNALS:
        if re.search(pat, hay, re.I):
            votes.setdefault((lang, eco), []).append(pat)
    if not votes:
        # Solidity/EVM default ONLY when the source context already says so.
        if old_lang in ("solidity",) or old_eco in ("evm",):
            return old_lang, old_eco, "derived", (
                "v3.0 contest/practice evidence retained; no new signal")
        return U, U, U, "no language/ecosystem signal in text or file refs"
    # Prefer votes with a chain attached; require >=2 distinct patterns for
    # derived confidence, else unknown (single mentions are cheap).
    chained = {k: v for k, v in votes.items() if k[1] is not None}
    pool = chained or votes
    best = sorted(pool.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))[0]
    (lang, eco), pats = best
    if len(pats) >= 2 or eco in ("stacks", "fuel", "starknet"):
        return (lang or U), (eco or U), "derived", (
            f"converging explicit signals: {sorted(set(pats))[:4]}")
    if lang in ("solidity", "vyper") and eco == "evm":
        return lang, eco, "derived", f"explicit file/marker signal: {pats[0]}"
    return U, U, U, ("single weak signal only "
                     f"({pats[0]}); Rust/Go alone cannot name a chain")


# ---------------------------------------------------------------------------
# Commit role classification (scope vs fix) from local context words.
# ---------------------------------------------------------------------------

SCOPE_WORDS = re.compile(
    r"(?i)\b(scope|audited|audit commit|review commit|reviewed|assessment|"
    r"target commit|in scope|commit hash|repo|repository|github\.com)\b")
FIX_WORDS = re.compile(
    r"(?i)\b(fix|fixed|remediat|mitigat|patch|resolved|resolution|"
    r"after the fix|post-fix|corrective)\b")


def classify_commit_context(segment: str, sha: str) -> tuple[str, str]:
    """(role, confidence-note). Role in {scope, fix, unknown}."""
    for m in re.finditer(re.escape(sha), segment):
        window = segment[max(0, m.start() - 300):m.end() + 300]
        fix = bool(FIX_WORDS.search(window))
        scope = bool(SCOPE_WORDS.search(window))
        if fix and not scope:
            return "fix", "fix-context words within 300 chars, no scope words"
        if scope and not fix:
            return "scope", "scope-context words within 300 chars, no fix words"
        if fix and scope:
            return "unknown", "mixed fix+scope context; role ambiguous"
    return "unknown", "no role context near cited SHA"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="compute, write nothing")
    ap.add_argument("--limit-sources", default=None,
                    help="comma-separated source_ids (debugging only)")
    args = ap.parse_args()
    only = set(args.limit_sources.split(",")) if args.limit_sources else None

    V.log("normalize_v3.py: V3.1 evidence extraction (deterministic)")
    missing = [spec["source_id"] for spec in V.SOURCES_V3
               if not (V.CLONES / spec["clone"]).exists()]
    if missing:
        V.log("FATAL: V3/clones is not populated (missing: "
              + ", ".join(missing) + "). Refusing to ship an empty "
              "normalization layer as green.")
        return 2
    ledger = V.read_jsonl(V.DERIVED_V3 / "candidate_ledger.jsonl")
    records = {r["finding_id"]: r for r in
               V.read_jsonl(V.DERIVED_V3 / "records.jsonl")}
    global _EXIST_NAMES, _EXIST_TITLES, _EXIST_COMMITS
    _EXIST_NAMES, _EXIST_TITLES, _EXIST_COMMITS = _v3_overlap_loader()
    if only:
        ledger = [c for c in ledger if c["source_id"] in only]

    fragments: list[dict] = []
    overlays: list[dict] = []
    conflicts: list[dict] = []
    patch_candidates: list[dict] = []
    readiness: list[dict] = []
    stats: dict = {
        "extraction_quality": collections.Counter(),
        "splitter_use": collections.Counter(),
        "fragment_decisions": collections.Counter(),
        "severity_confidence": collections.Counter(),
        "taxonomy_confidence": collections.Counter(),
        "langeco_confidence": collections.Counter(),
        "commit_roles": collections.Counter(),
        "unknown_reasons": collections.Counter(),
    }

    for n_cand, cand in enumerate(ledger):
        if (n_cand + 1) % 500 == 0:
            V.log(f"  ... {n_cand + 1}/{len(ledger)} candidates, "
                  f"{len(fragments)} fragments")
        sid = cand["source_id"]
        loc = cand.get("source_location", "")
        path = X.resolve_path(loc)
        is_pdf = path is not None and path.suffix.lower() == ".pdf"
        is_md = path is not None and path.suffix.lower() == ".md"

        # -- Pashov PDFs render the already-parsed MD reports: skip the PDF
        # when a same-stem MD twin exists (saves ~300 heavy extractions);
        # PDFs without an MD twin still go through the generic path below.
        if sid == "pashov-audits" and is_pdf and path is not None:
            twin = path.parent.parent / "md" / (path.stem + ".md")
            if twin.exists():
                stats["extraction_quality"]["pashov_pdf_skipped_md_covers"] += 1
                _readiness_for(cand, {}, readiness)
                continue

        # -- enrich-only rows (no new splits): pashov/sherlock/informal MD --
        if cand["decision"] in ("IMPORT", "IMPORT_AS_UNVERIFIED",
                                "IMPORT_AS_NEGATIVE") and is_md \
                and sid in ("pashov-audits", "sherlock-symmetrical",
                            "sherlock-optimism", "informal-audits"):
            enrich = X.enrich_markdown_row(cand)
            _apply_enrichment(cand, enrich, overlays, conflicts, stats)
            _readiness_for(cand, {}, readiness)
            continue

        # -- DeFiHackLabs: structural attack sequence (observed from code) --
        if sid == "defihacklabs" and path is not None:
            atk = X.extract_attack_sequence(path)
            if atk.get("available"):
                overlays.append(_ov(cand["candidate_id"], "attack_sequence",
                                    U, {"steps": atk["steps"][:50],
                                        "entrypoints": atk["entrypoints"],
                                        "fork_chain": atk["fork_chain"],
                                        "selectors_referenced":
                                            atk["selectors_referenced"]},
                                    "observed_fact",
                                    "structural parse of PoC source "
                                    "(calls in file order; no execution)",
                                    None, False))
                stats["extraction_quality"]["dhl_attack_sequence"] += 1
            _readiness_for(cand, {"poc": "executable-file"}, readiness)
            continue

        # -- smartbugs: already normalized taxonomy; pass through ------------
        if sid == "smartbugs-curated":
            _readiness_for(cand, {"taxonomy": "explicit-curated"}, readiness)
            continue

        # -- C4 raw/QA rows without bodies: nothing to normalize offline -----
        if sid.startswith("c4-") or sid.startswith("sherlock-") and \
                cand["source_location"].endswith(".json"):
            stats["extraction_quality"]["no_body_offline"] += 1
            _readiness_for(cand, {}, readiness)
            continue

        # -- report-pointer rows: split + extract ---------------------------
        if cand["decision"] != "RESEARCH_ONLY" or not (is_pdf or is_md):
            if cand["decision"] in V.ADMITTED_DECISIONS:
                _readiness_for(cand, {}, readiness)
            continue
        text, quality = X.get_text(cand)
        stats["extraction_quality"][
            f"text_{quality.get('method', 'absent')}"] += 1
        if not quality["available"] or len(text) < 500:
            stats["unknown_reasons"]["fragmentation:text_unavailable"] += 1
            _readiness_for(cand, {}, readiness)
            continue
        if quality.get("readability", 0) < 0.6 or \
                quality.get("word_hits", 0) < 5:
            fragments.append(_RJ(
                cand, text, quality,
                "extraction quality below threshold "
                f"(readability {quality.get('readability')}, "
                f"word_hits {quality.get('word_hits')})"))
            stats["fragment_decisions"]["rejected_poor_extraction"] += 1
            _readiness_for(cand, {}, readiness)
            continue
        frags, sinfo, work = X.split_findings(cand, text)
        stats["splitter_use"][sinfo["splitter"]] += 1
        if sinfo.get("despaced_copy"):
            stats["extraction_quality"]["despaced_reports"] += 1
        if not frags:
            fragments.append(_RJ(
                cand, text, quality,
                f"splitter {sinfo['splitter']} found no finding boundaries"))
            stats["fragment_decisions"]["rejected_no_boundary"] += 1
            _readiness_for(cand, {}, readiness)
            continue
        # Deduplicate same-native-ID repeats (TOC + body): keep the instance
        # with severity evidence, else the longest.
        by_native: dict[str, list[dict]] = collections.defaultdict(list)
        for f in frags:
            by_native[f["native_finding_id"]].append(f)
        admitted_here = 0
        for native_id, group in sorted(by_native.items()):
            if len(group) > 1:
                stats["fragment_decisions"]["duplicate_native_id"] += len(group) - 1
            scored = []
            for f in group:
                seg = work[f["char_start"]:f["char_end"]]
                fields = X.extract_fields(seg, f["char_start"], work, sid)
                scored.append((f, seg, fields))
            scored.sort(key=lambda t: (
                0 if "severity_reported" in t[2] else 1,
                -(t[0]["char_end"] - t[0]["char_start"])))
            winner, seg, fields = scored[0]
            for loser, _, _ in scored[1:]:
                fragments.append(_RJ(
                    cand, text, quality,
                    f"duplicate native ID {native_id}: TOC/body repeat of kept "
                    f"instance at {winner['char_start']}",
                    span=(loser["char_start"], loser["char_end"])))
                stats["fragment_decisions"]["rejected_duplicate"] += 1
            if _emit_fragment(cand, text, quality, winner, seg, fields,
                              fragments, overlays, conflicts,
                              patch_candidates, readiness, stats,
                              despaced=bool(sinfo.get("despaced_copy")),
                              splitter=sinfo.get("splitter", U)):
                admitted_here += 1
        # One candidate-level readiness row per report pointer.
        _readiness_for(cand, {"admitted_children": admitted_here},
                       readiness)
        # parent pointer stays RESEARCH_ONLY; children carry the admission.

    # Overlay uniqueness (first evidence wins): several fragments of one
    # parent can observe the same parent-level field; repeats are counted,
    # never duplicated.
    seen_ov: set[tuple[str, str]] = set()
    unique_overlays = []
    for ov in overlays:
        key = (ov["target_id"], ov["field"])
        if key in seen_ov:
            stats["extraction_quality"]["overlay_superseded"] = \
                stats["extraction_quality"].get("overlay_superseded", 0) + 1
            continue
        seen_ov.add(key)
        unique_overlays.append(ov)
    overlays = unique_overlays

    # -- cross-source corroboration (conservative) ---------------------------
    corroborations = _corroborate(fragments, ledger, stats)

    # -- patch candidates: revision pairs as claims, never verdicts ---------
    patch_candidates = _collect_patch_candidates(records, fragments)
    stats["extraction_quality"]["patch_candidates"] = len(patch_candidates)

    preview = _build_preview(records, overlays, fragments, stats)

    # -- per-source yield (admitted vs rejected fragments) ------------------
    admitted_by: dict[str, int] = collections.Counter(
        f["source_id"] for f in fragments
        if f.get("fragment_status") == "admitted")
    rejected_by: dict[str, int] = collections.Counter(
        f["source_id"] for f in fragments
        if f.get("fragment_status") != "admitted")

    # -- unknown audit -------------------------------------------------------
    unknowns = _unknown_audit(fragments, ledger)

    # -- coverage BEFORE (v3.0 ledger) -> AFTER (v3.1 preview) ---------------
    coverage = _coverage(ledger, preview, fragments, readiness,
                         patch_candidates)

    norm_manifest = {
        "normalization_version": NORM_VERSION,
        "dataset_version": V.DATASET_VERSION_V3,
        "generated_by": "scripts/normalize_v3.py",
        "fragment_count": len(fragments),
        "fragment_decisions": dict(stats["fragment_decisions"]),
        "overlay_count": len(overlays),
        "conflict_count": len(conflicts),
        "preview_count": len(preview),
        "corroboration_links": len(corroborations),
        "patch_candidates": len(patch_candidates),
        "splitter_use": dict(stats["splitter_use"]),
        "extraction_quality": dict(stats["extraction_quality"]),
        "severity_confidence": dict(stats["severity_confidence"]),
        "taxonomy_confidence": dict(stats["taxonomy_confidence"]),
        "langeco_confidence": dict(stats["langeco_confidence"]),
        "commit_roles": dict(stats["commit_roles"]),
        "coverage_before_after": coverage,
        "yield_by_source": {s: {"admitted": admitted_by.get(s, 0),
                                "rejected": rejected_by.get(s, 0)}
                            for s in sorted(set(admitted_by) | set(rejected_by))},
    }

    if args.check:
        V.log(f"check only: {len(fragments)} fragments, "
              f"{len(overlays)} overlays, {len(preview)} preview rows; "
              "wrote nothing")
        return 0

    D = V.DERIVED_V3
    V.write_jsonl(D / "normalization_fragments.jsonl", fragments)
    V.write_jsonl(D / "normalization_overlay.jsonl", overlays)
    V.write_jsonl(D / "normalized_records_preview.jsonl", preview)
    V.write_json(D / "normalization.json", norm_manifest)
    V.write_jsonl(D / "corroborations_v31.jsonl", corroborations)
    V.write_jsonl(D / "patch_candidates.json", patch_candidates)
    V.write_jsonl(D / "experiment_readiness.json", readiness)
    R = V.REPORTS_V3
    V.write_json(R / "normalization_report.json", norm_manifest)
    _write_normalization_md(R / "normalization_report.md", norm_manifest,
                            fragments)
    V.write_json(R / "normalization_unknowns.json", unknowns)
    _write_unknowns_md(R / "normalization_unknowns.md", unknowns)
    fails = [f for f in fragments if f.get("fragment_status")
             == "rejected_no_text"]
    V.write_json(R / "extraction_failures.json",
                 {"failures": fails, "count": len(fails)})
    _write_poc_report(R / "poc_extraction_report.json", fragments, ledger)
    _write_patch_report(R / "patch_verification_report.json",
                        patch_candidates)
    _write_queue(R / "experiment_readiness_queue.md", readiness)
    V.log(f"normalize_v3.py done: {len(fragments)} fragments, "
          f"{len(overlays)} overlays, {len(preview)} preview rows")
    return 0


def _ov(target_id: str, field: str, old, new, evidence_type: str,
        method: str, span, conflict: bool) -> dict:
    return {"target_id": target_id, "field": field, "old_value": old,
            "new_value": new, "evidence_type": evidence_type,
            "method": method, "source_span": span, "conflict": conflict,
            "normalization_version": NORM_VERSION}


_REJ_SEQ: dict[str, int] = {}


def _RJ(cand: dict, text: str, quality: dict, reason: str,
        span=None) -> dict:
    """Rejected-fragment constructor with per-parent unique sequence."""
    seq = _REJ_SEQ.get(cand["candidate_id"], 0)
    _REJ_SEQ[cand["candidate_id"]] = seq + 1
    return _rejected_fragment(cand, text, quality, reason, span, seq)


def _rejected_fragment(cand: dict, text: str, quality: dict, reason: str,
                       span=None, seq: int = 0) -> dict:
    stem = cand["source_location"].split("/")[-1].rsplit(".", 1)[0]
    parent = cand["source_location"].split("/")[-2] \
        if "/" in cand["source_location"] else ""
    frag_id = (f"{cand['source_id']}:{parent}/{stem}:unparsed-{seq}"
               if seq else f"{cand['source_id']}:{parent}/{stem}:unparsed")
    return {"fragment_id": frag_id,
            "parent_candidate_id": cand["candidate_id"],
            "source_id": cand["source_id"],
            "fragment_status": "rejected",
            "rejection_reason": reason,
            "source_span": {"char_start": span[0], "char_end": span[1]}
            if span else None,
            "extraction_quality": quality,
            "normalization_version": NORM_VERSION}


def _apply_enrichment(cand: dict, enrich: dict, overlays: list,
                      conflicts: list, stats: dict) -> None:
    cid = cand["candidate_id"]
    if "code_files" in enrich:
        old = cand.get("affected_file")
        if old in (U, None):
            overlays.append(_ov(cid, "affected_file_candidates", old,
                                enrich["code_files"]["value"],
                                "observed_fact",
                                enrich["code_files"]["method"], None, False))
        stats["extraction_quality"]["md_code_files"] += 1
    if "code_functions" in enrich:
        overlays.append(_ov(cid, "function_candidates",
                            cand.get("affected_function"),
                            enrich["code_functions"]["value"],
                            "observed_fact",
                            enrich["code_functions"]["method"], None, False))
    if "poc_section" in enrich:
        overlays.append(_ov(cid, "poc_section_observed", None,
                            enrich["poc_section"]["value"],
                            "observed_fact",
                            enrich["poc_section"]["method"], None, False))
        if enrich["poc_section"]["value"].get("has_code") and \
                cand.get("verification_level") == "L0":
            overlays.append(_ov(cid, "verification_level", "L0", "L1",
                                "observed_fact",
                                "PoC code observed in finding body "
                                "(published PoC, not executed)", None, False))


def _emit_fragment(cand: dict, text: str, quality: dict, winner: dict,
                   seg: str, fields: dict, fragments: list, overlays: list,
                   conflicts: list, patch_candidates: list, readiness: list,
                   stats: dict, despaced: bool = False,
                   splitter: str = U) -> None:
    sid = cand["source_id"]
    report = cand.get("source_report_id", U)
    loc_parts = cand["source_location"].split("/")
    stem = loc_parts[-1].rsplit(".", 1)[0]
    # Parent dir disambiguates same-stem reports (e.g. every Sigmaprime
    # review lives in review.pdf under a per-client directory).
    parent = loc_parts[-2] if len(loc_parts) > 1 else ""
    base_id = f"{sid}:{parent}/{stem}:{winner['native_finding_id']}"
    title = winner["header_text"][:200] or U
    title_ok, title_note = X.title_quality_ok(title)
    if not title_ok:
        fragments.append(_RJ(
            cand, text, quality,
            f"title-quality gate: {title_note} (word-salad segment, not a "
            f"finding title)",
            span=(winner["char_start"], winner["char_end"])))
        stats["fragment_decisions"]["rejected_bad_title"] += 1
        _overlay_observed(cand, fields, overlays, stats)
        return False

    sev_rep = fields.get("severity_reported", {}).get("value", U)
    sev_method_note = fields.get("severity_reported", {}).get("method", "")
    if sev_rep in (U, None):
        h_rep, h_conf, h_method = _header_severity(
            winner["native_finding_id"], winner["header_text"], sid)
        if h_rep != U:
            sev_rep = h_rep
            sev_method_note = h_method + " (header convention, original " \
                "prefix preserved in native_finding_id)"
    sev_norm, sev_conf, sev_method = normalize_severity(sev_rep, sid)
    if sev_method_note and sev_norm != U:
        sev_method = sev_method_note + " | " + sev_method
    stats["severity_confidence"][sev_conf or "unknown"] += 1
    if sev_norm == U:
        fragments.append(_RJ(
            cand, text, quality,
            f"no defensible severity (reported: {sev_rep!r}); fragment kept "
            f"for audit, not admitted",
            span=(winner["char_start"], winner["char_end"])))
        stats["fragment_decisions"]["rejected_no_severity"] += 1
        # Still record taxonomy/code evidence as observed overlays on parent.
        _overlay_observed(cand, fields, overlays, stats)
        return False

    cat_rep = fields.get("category_reported", {}).get("value")
    classes, tax_conf, tax_method, terms = map_taxonomy(
        cat_rep, title, seg[:3000])
    stats["taxonomy_confidence"][tax_conf or "unknown"] += 1

    code_files = fields.get("code_files", {}).get("value", [])
    ctx = fields.get("context_ref", {}).get("value", {})
    if ctx and ctx.get("file") not in code_files:
        # Explicit Context file outranks regex-harvested filenames.
        code_files = [ctx["file"]] + code_files
    line_refs = sorted(set(fields.get("line_refs", {}).get("value", [])
                            + (ctx.get("report_line_refs", [])
                               if ctx else [])))[:30]
    lang, eco, le_conf, le_method = resolve_lang_eco(
        code_files, seg, cand.get("language", U), cand.get("ecosystem", U),
        cand.get("language_evidence", ""))
    stats["langeco_confidence"][le_conf or "unknown"] += 1

    sha_roles = []
    for sha in fields.get("commit_shas", {}).get("value", []):
        role, note = classify_commit_context(seg, sha)
        stats["commit_roles"][role] += 1
        sha_roles.append({"sha": sha, "role": role, "role_note": note})

    poc = fields.get("poc_section", {}).get("value", {})
    level = "L1" if poc.get("has_code") else "L0"

    fix_rep = fields.get("fix_status_reported", {}).get("value", U)
    if fix_rep in (U, None):
        hs = _header_status(winner["header_text"])
        if hs != U:
            fix_rep = hs + " (finding-card convention)"

    frag = {
        "fragment_id": base_id,
        "parent_candidate_id": cand["candidate_id"],
        "source_id": sid,
        "fragment_status": "admitted",
        "splitter": splitter,
        "native_finding_id": winner["native_finding_id"],
        "title": title,
        "severity_reported": sev_rep,
        "severity_normalized": sev_norm,
        "severity_confidence": sev_conf,
        "severity_method": sev_method,
        "original_vulnerability_class": cat_rep or U,
        "normalized_vulnerability_classes": classes,
        "taxonomy_confidence": tax_conf,
        "taxonomy_method": tax_method,
        "taxonomy_terms": terms,
        "language": lang, "ecosystem": eco,
        "language_confidence": le_conf, "language_method": le_method,
        "affected_file_candidates": code_files[:12],
        "affected_function_reported": fields.get(
            "function_reported", {}).get("value", U),
        "target_reported": fields.get("target_reported", {}).get("value", U),
        "fix_status_reported": fix_rep,
        "line_refs": line_refs,
        "code_permalinks": fields.get("code_permalinks", {}).get("value", []),
        "abdk_listings": fields.get("abdk_listings", {}).get("value", []),
        "commit_shas": sha_roles,
        "poc_section": poc or {"present": False},
        "remediation_present": bool("remediation_section" in fields),
        "verification_level": level,
        "source_span": {"char_start": winner["char_start"],
                        "char_end": winner["char_end"],
                        "page_hint": winner["page_hint"],
                        "text_basis": "despaced_copy" if despaced
                        else "source_text",
                        "source_location": cand["source_location"],
                        "file_sha256": cand["provenance"]["file_sha256"],
                        "clone_head": cand["provenance"]["clone_head"]},
        "source_report_id": report,
        "project": cand.get("project", U),
        "report_date": cand.get("report_date", U),
        "license_status": cand.get("license_status", U),
        "extraction_quality": quality,
        "normalization_version": NORM_VERSION,
    }
    fragments.append(frag)
    stats["fragment_decisions"]["admitted"] += 1
    _readiness_for(cand, {"fragment": frag}, readiness,
                   fragment_id=base_id)
    return True


def _overlay_observed(cand: dict, fields: dict, overlays: list,
                      stats: dict) -> None:
    cid = cand["candidate_id"]
    if "code_files" in fields and cand.get("affected_file") in (U, None):
        overlays.append(_ov(cid, "affected_file_candidates", U,
                            fields["code_files"]["value"][:12],
                            "observed_fact",
                            fields["code_files"]["method"], None, False))
    if "poc_section" in fields:
        overlays.append(_ov(cid, "poc_section_observed", None,
                            fields["poc_section"]["value"], "observed_fact",
                            fields["poc_section"]["method"], None, False))


def _readiness_for(cand: dict, extra: dict, readiness: list,
                   fragment_id: str | None = None) -> None:
    """Tier A-D + blockers. No execution is claimed here."""
    sev = cand.get("severity_normalized", U)
    has_poc = cand.get("poc_available") or extra.get("poc") == \
        "executable-file" or (extra.get("fragment") or {}).get(
            "poc_section", {}).get("has_code")
    has_repo = cand.get("repository") not in (U, None)
    has_commit = bool(cand.get("vulnerable_commit") not in (U, None)
                      ) or bool((extra.get("fragment") or {}).get("commit_shas"))
    blockers: list[str] = []
    if not has_poc:
        blockers.append("no_poc_published")
    if not has_repo:
        blockers.append("repository_unknown")
    if not has_commit:
        blockers.append("revision_unknown")
    if cand.get("source_id") == "defihacklabs":
        blockers.append("needs_archive_rpc: fork PoC requires historical "
                        "chain state; VLUN_RPC_URL unset")
    if sev in ("High", "Critical") and has_poc and has_repo and has_commit:
        tier = "A"
    elif sev in ("High", "Critical") and (has_repo or has_commit):
        tier = "B"
    elif cand.get("tier", 4) in (0, 1):
        tier = "C"
    else:
        tier = "D"
    readiness.append({
        "finding_id": fragment_id or cand["candidate_id"],
        "parent_candidate_id": cand["candidate_id"],
        "source_id": cand["source_id"],
        "severity": sev,
        "tier": tier,
        "has_poc": bool(has_poc),
        "has_repository": has_repo,
        "has_revision": has_commit,
        "admitted_children": extra.get("admitted_children", 0),
        "blockers": blockers,
        "executed": False,
        "normalization_version": NORM_VERSION,
    })


def _collect_patch_candidates(records: dict, fragments: list) -> list:
    """Vulnerable+fixed revision pairs as patch CLAIMS (reported_claim).

    status is always not_testable here: no execution was performed, so no
    effectiveness verdict exists. L6 needs the same test on both revisions.
    """
    cands = []
    for fid, rec in sorted(records.items()):
        vc, fc = rec.get("vulnerable_commit"), rec.get("fixed_commit")
        if isinstance(vc, str) and isinstance(fc, str) \
                and re.fullmatch(r"[0-9a-f]{40}", vc) \
                and re.fullmatch(r"[0-9a-f]{40}", fc):
            cands.append({
                "finding_id": fid,
                "source_id": rec.get("source_id", U),
                "vulnerable_commit": vc,
                "vulnerable_commit_confidence":
                    rec.get("vulnerable_commit_confidence", U),
                "fixed_commit": fc,
                "fixed_commit_confidence":
                    rec.get("fixed_commit_confidence", U),
                "repository": rec.get("repository", U),
                "patch_status": "not_testable",
                "patch_status_reason": ("no execution performed in V3.1; "
                                        "effectiveness needs same-test runs "
                                        "on both revisions"),
                "fix_claim_evidence": "reported_claim",
                "normalization_version": NORM_VERSION})
    for frag in fragments:
        if frag.get("fragment_status") != "admitted":
            continue
        roles: dict[str, list] = collections.defaultdict(list)
        for s in frag.get("commit_shas", []):
            if re.fullmatch(r"[0-9a-f]{40}", s.get("sha", "")):
                roles[s.get("role", "unknown")].append(s["sha"])
        if roles.get("scope") and roles.get("fix"):
            cands.append({
                "finding_id": frag["fragment_id"],
                "source_id": frag["source_id"],
                "vulnerable_commit": sorted(roles["scope"])[0],
                "vulnerable_commit_confidence": "strong",
                "fixed_commit": sorted(roles["fix"])[0],
                "fixed_commit_confidence": "strong",
                "repository": U,
                "patch_status": "not_testable",
                "patch_status_reason": ("role-classified SHAs from report "
                                        "context; no execution performed"),
                "fix_claim_evidence": "reported_claim",
                "normalization_version": NORM_VERSION})
    cands.sort(key=lambda c: c["finding_id"])
    return cands


def _corroborate(fragments: list, ledger: list, stats: dict) -> list:
    """Conservative links: same repo + same file + same primary class."""
    index: dict[tuple, list[str]] = collections.defaultdict(list)
    for c in ledger:
        repo = (c.get("repository") or "").lower()
        if repo in (U, "", "unknown"):
            continue
        f = c.get("affected_file")
        files = [f] if isinstance(f, str) and f != U else []
        for ff in files:
            index[(repo, Path(ff).name.lower(),
                   c.get("normalized_vulnerability_class", U))].append(
                       c["candidate_id"])
    links = []
    seen = set()
    for frag in fragments:
        if frag.get("fragment_status") != "admitted":
            continue
        for span_file in (frag.get("affected_file_candidates") or [])[:4]:
            for perm in frag.get("code_permalinks") or []:
                key = (perm["repository"].lower(),
                       Path(span_file).name.lower(),
                       (frag["normalized_vulnerability_classes"] or [U])[0])
                for other in index.get(key, []):
                    pair = tuple(sorted([frag["fragment_id"], other]))
                    if pair[0] != pair[1] and pair not in seen:
                        seen.add(pair)
                        links.append({
                            "a": pair[0], "b": pair[1],
                            "basis": ["same repository", "same file",
                                      "same primary class"],
                            "relationship": "corroboration",
                            "normalization_version": NORM_VERSION})
    stats["extraction_quality"]["corroboration_links"] = len(links)
    return links


def _build_preview(records: dict, overlays: list, fragments: list,
                   stats: dict) -> list:
    preview = []
    by_target: dict[str, list[dict]] = collections.defaultdict(list)
    for ov in overlays:
        by_target[ov["target_id"]].append(ov)
    for fid, rec in sorted(records.items()):
        row = dict(rec)
        applied = []
        for ov in by_target.get(fid, []):
            if ov["conflict"]:
                continue
            _apply_overlay_value(row, ov)
            applied.append(ov["field"])
        if applied:
            row["v31_overlays_applied"] = sorted(applied)
        row["normalization_version"] = NORM_VERSION
        preview.append(row)
    for frag in fragments:
        if frag.get("fragment_status") != "admitted":
            continue
        preview.append(_fragment_to_record(frag))
    preview.sort(key=lambda r: r.get("finding_id", ""))
    stats["extraction_quality"]["preview_rows"] = len(preview)
    return preview


def _apply_overlay_value(row: dict, ov: dict) -> None:
    f = ov["field"]
    if f == "affected_file_candidates":
        row["affected_file"] = ";".join(ov["new_value"][:3]) \
            if ov["new_value"] else U
    elif f == "function_candidates":
        row["affected_function"] = ";".join(ov["new_value"][:3]) \
            if ov["new_value"] else U
    elif f == "attack_sequence":
        row["attack_sequence"] = ov["new_value"]
    elif f == "poc_section_observed":
        row["poc"] = {"available": bool(ov["new_value"].get("has_code")),
                      "evidence": "observed PoC section in source"}
        if ov["new_value"].get("has_code") and \
                row.get("verification_level") == "L0":
            row["verification_level"] = "L1"
    elif f == "verification_level":
        row["verification_level"] = ov["new_value"]
    elif f == "poc_section":
        pass


def _fragment_to_record(frag: dict) -> dict:
    sev = frag["severity_normalized"]
    overlap = []
    normt = V.norm_title(frag.get("title", ""))
    if normt and normt not in _GENERIC_TITLES and normt in _EXIST_TITLES:
        overlap.append("exact normalized-title overlap with existing VLUN record")
    for s in frag.get("commit_shas", []):
        if re.fullmatch(r"[0-9a-f]{40}", s.get("sha", "")) \
                and s["sha"] in _EXIST_COMMITS:
            overlap.append("exact commit overlap with existing VLUN record")
            break
    return {
        "record_type": "record_v31",
        "finding_id": frag["fragment_id"],
        "source_id": frag["source_id"],
        "source_report_id": frag["source_report_id"],
        "project": frag["project"], "protocol": frag["project"],
        "repository": U,
        "ecosystem": frag["ecosystem"], "language": frag["language"],
        "severity": sev, "severity_reported": frag["severity_reported"],
        "title": frag["title"], "original_title": frag["title"],
        "normalized_vulnerability_class":
            frag["normalized_vulnerability_classes"][0]
            if frag["normalized_vulnerability_classes"] else U,
        "normalized_vulnerability_classes":
            frag["normalized_vulnerability_classes"],
        "taxonomy_confidence": frag["taxonomy_confidence"],
        "original_vulnerability_class":
            frag["original_vulnerability_class"],
        "description": (f"{frag['title']} -- normalized fragment of "
                        f"{frag['parent_candidate_id']} "
                        f"({frag['source_span']['source_location']})."),
        "root_cause": U, "affected_contract": U, "affected_function":
            frag["affected_function_reported"],
        "affected_file": ";".join(
            frag["affected_file_candidates"][:3])
        if frag["affected_file_candidates"] else U,
        "affected_lines": frag["line_refs"] if frag["line_refs"] else None,
        "affected_lines_note": ("report line refs, not source lines, until "
                                "anchored to a revision"),
        "preconditions": U, "attack_sequence": U, "impact": U,
        "poc": {"available": bool(frag["poc_section"].get("has_code")),
                "evidence": "observed PoC section in source report"},
        "fix_description": U,
        "fix_status_reported": frag["fix_status_reported"],
        "vulnerable_commit": U, "vulnerable_commit_confidence": U,
        "fixed_commit": U, "fixed_commit_confidence": U,
        "commit_shas_observed": frag["commit_shas"],
        "reported_claim": True, "verified_fact": "unknown",
        "verification_level": frag["verification_level"],
        "verification_status": "UNVERIFIED",
        "report_date": frag["report_date"], "commit_date": U,
        "license": U, "license_status": frag["license_status"],
        "decision": "IMPORT_AS_UNVERIFIED",
        "negative_class": None, "duplicate_of": None, "vlun_overlap": overlap,
        "parent_candidate_id": frag["parent_candidate_id"],
        "benchmark_split": None,
        "provenance": {
            "clone_head": frag["source_span"]["clone_head"],
            "file_sha256": frag["source_span"]["file_sha256"],
            "source_location": frag["source_span"]["source_location"],
            "char_span": [frag["source_span"]["char_start"],
                          frag["source_span"]["char_end"]],
            "page_hint": frag["source_span"]["page_hint"],
            "mutable_reference": False,
        },
        "dataset_version": V.DATASET_VERSION_V3,
        "normalization_version": NORM_VERSION,
        "schema_version": V.SCHEMA_VERSION_V3,
    }


def _coverage(ledger: list, preview: list, fragments: list,
              readiness: list, patch_candidates: list) -> dict:
    """Evidence coverage BEFORE (v3.0 ledger) -> AFTER (v3.1 preview).

    Every numerator is counted from the artefacts, never estimated.
    """
    def known(rows: list, key: str) -> int:
        return sum(1 for r in rows if r.get(key) not in (U, None, [], {}))

    def exact40(rows: list, key: str) -> int:
        return sum(1 for r in rows
                   if isinstance(r.get(key), str)
                   and re.fullmatch(r"[0-9a-f]{40}", r[key]))

    adm = [f for f in fragments if f.get("fragment_status") == "admitted"]

    def class_known_preview() -> int:
        n = 0
        for r in preview:
            if r.get("record_type") == "record_v31":
                continue
            if r.get("normalized_vulnerability_class") not in (U, None):
                n += 1
        for f in adm:
            if (f.get("normalized_vulnerability_classes") or [U])[0] != U:
                n += 1
        return n

    def lang_known_preview() -> int:
        n = sum(1 for r in preview
                if r.get("record_type") != "record_v31"
                and r.get("language") not in (U, None))
        return n + sum(1 for f in adm if f.get("language") not in (U, None))

    def eco_known_preview() -> int:
        n = sum(1 for r in preview
                if r.get("record_type") != "record_v31"
                and r.get("ecosystem") not in (U, None))
        return n + sum(1 for f in adm if f.get("ecosystem") not in (U, None))

    def files_known_preview() -> int:
        n = sum(1 for r in preview
                if r.get("record_type") != "record_v31"
                and r.get("affected_file") not in (U, None))
        return n + sum(1 for f in adm
                       if f.get("affected_file_candidates"))

    def repo_known_preview() -> int:
        return sum(1 for r in preview
                   if r.get("repository") not in (U, None))

    def exact40_preview(key: str) -> int:
        return sum(1 for r in preview
                   if isinstance(r.get(key), str)
                   and re.fullmatch(r"[0-9a-f]{40}", r[key]))

    def sev_known_preview() -> int:
        n = 0
        for r in preview:
            if r.get("record_type") == "record_v31":
                if r.get("severity") not in (U, None):
                    n += 1
            elif r.get("severity_normalized") not in (U, None):
                n += 1
        return n

    before = {
        "rows": len(ledger),
        "severity_known": known(ledger, "severity_normalized"),
        "class_known": sum(
            1 for c in ledger
            if c.get("normalized_vulnerability_class") not in (U, None)),
        "language_known": sum(
            1 for c in ledger if c.get("language") not in (U, None)),
        "ecosystem_known": sum(
            1 for c in ledger if c.get("ecosystem") not in (U, None)),
        "repository_known": sum(
            1 for c in ledger if c.get("repository") not in (U, None)),
        "exact_vulnerable_commits": exact40(ledger, "vulnerable_commit"),
        "exact_fixed_commits": exact40(ledger, "fixed_commit"),
        "affected_files": known(ledger, "affected_file"),
        "published_pocs": sum(1 for c in ledger if c.get("poc_available")),
    }
    after = {
        "rows": len(preview),
        "severity_known": sev_known_preview(),
        "class_known": class_known_preview(),
        "language_known": lang_known_preview(),
        "ecosystem_known": eco_known_preview(),
        "repository_known": repo_known_preview(),
        "exact_vulnerable_commits": exact40_preview("vulnerable_commit"),
        "exact_fixed_commits": exact40_preview("fixed_commit"),
        "affected_files": files_known_preview(),
        "affected_functions": sum(
            1 for f in adm
            if f.get("affected_function_reported") not in (U, None)),
        "line_refs": sum(1 for f in adm if f.get("line_refs")),
        "published_pocs": sum(
            1 for r in preview
            if r.get("record_type") != "record_v31"
            and (r.get("poc") or {}).get("available")) + sum(
            1 for f in adm if f.get("poc_section", {}).get("present")),
        "executable_pocs": 0,
        "experiment_ready_tier_a": sum(
            1 for r in readiness if r.get("tier") == "A"),
        "executed_pocs": 0,
        "reproduced": 0,
        "l5": 0,
        "l6": 0,
        "patch_candidates": len(patch_candidates),
        "patches_verified": 0,
    }
    after["note"] = ("AFTER counts preview rows (v3.0 records with overlays "
                     "applied + admitted V3.1 children). Executed/reproduced/"
                     "L5/L6 stay 0: nothing was executed in V3.1.")
    return {"before_v30_ledger": before, "after_v31": after,
            "normalization_version": NORM_VERSION}


def _unknown_audit(fragments: list, ledger: list) -> dict:
    fields = ["severity_normalized", "normalized_vulnerability_classes",
              "language", "ecosystem", "affected_file_candidates",
              "affected_function_reported", "commit_shas",
              "poc_section", "fix_status_reported"]
    per_field: dict[str, dict] = {}
    for field in fields:
        missing = [f["fragment_id"] for f in fragments
                   if f.get("fragment_status") == "admitted"
                   and _is_missing(f.get(field))]
        by_source: dict[str, int] = collections.Counter(
            f["source_id"] for f in fragments
            if f.get("fragment_status") == "admitted"
            and _is_missing(f.get(field)))
        per_field[field] = {"unknown": len(missing),
                            "by_source": dict(by_source),
                            "resolving_evidence": _resolve_note(field)}
    # Ledger-level unknowns for context (v3.0 baseline, not rewritten).
    base: dict[str, int] = {}
    for field, key in (("severity", "severity_normalized"),
                       ("language", "language"),
                       ("ecosystem", "ecosystem")):
        base[field] = sum(1 for c in ledger if c.get(key) in (U, None))
    return {"fields": per_field, "v30_baseline": base,
            "normalization_version": NORM_VERSION}


def _is_missing(v) -> bool:
    if isinstance(v, dict):
        # poc_section {"present": False} is unknown, not evidence.
        if v.get("present") is False and len(v) <= 2:
            return True
        return False
    return v in (U, None, [], {}) or v == ["Unknown"]


def _resolve_note(field: str) -> str:
    return {
        "severity_normalized": "explicit Severity field in the finding segment",
        "normalized_vulnerability_classes": "explicit auditor Category/Type label",
        "language": "README platform column or explicit framework + file-extension convergence",
        "ecosystem": "explicit platform/repository evidence (Rust alone insufficient)",
        "affected_file_candidates": "code filename or blob permalink in the finding segment",
        "affected_function_reported": "explicit Function field or attributed signature",
        "commit_shas": "40-hex SHA in scope/fix context",
        "poc_section": "PoC/proof section with code in the finding segment",
        "fix_status_reported": "explicit Status field in the finding segment",
    }.get(field, "stronger source evidence")


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def _write_normalization_md(path: Path, manifest: dict,
                            fragments: list) -> None:
    admitted = [f for f in fragments
                if f.get("fragment_status") == "admitted"]
    L = ["# V3.1 normalization report", "",
         f"normalization_version {NORM_VERSION} (dataset "
         f"{V.DATASET_VERSION_V3}). V3.0 files untouched; this layer is "
         "fragments + overlays + preview.",
         "",
         "## Coverage (evidence, not scans)",
         ""]
    L.append(f"fragments admitted: {len(admitted)} / "
             f"{manifest['fragment_count']}")
    L.append(f"fragment decisions: {manifest['fragment_decisions']}")
    L.append(f"overlays: {manifest['overlay_count']} "
             f"(conflicts kept, old values win: {manifest['conflict_count']})")
    L.append(f"preview rows: {manifest['preview_count']}")
    L.append(f"patch candidates (all not_testable): "
             f"{manifest['patch_candidates']}")
    L.append("")
    L.append("## Confidence distributions")
    L.append(f"severity: {manifest['severity_confidence']}")
    L.append(f"taxonomy: {manifest['taxonomy_confidence']}")
    L.append(f"language/ecosystem: {manifest['langeco_confidence']}")
    L.append(f"commit roles: {manifest['commit_roles']}")
    L.append("")
    L.append("## Extraction quality")
    L.append(f"{manifest['extraction_quality']}")
    L.append("")
    L.append("## Splitter use")
    L.append(f"{manifest['splitter_use']}")
    L.append("")
    L.append("## Per-source yield (admitted / rejected fragments)")
    L.append("")
    L.append("Source | Admitted | Rejected")
    L.append("---|---|---")
    for src, y in sorted(manifest.get("yield_by_source", {}).items()):
        L.append(f"{src} | {y['admitted']} | {y['rejected']}")
    L.append("")
    L.append("## Coverage BEFORE (v3.0 ledger) -> AFTER (v3.1)")
    L.append("")
    L.append("Metric | Before | After")
    L.append("---|---|---")
    cov = manifest.get("coverage_before_after", {})
    before = cov.get("before_v30_ledger", {})
    after = cov.get("after_v31", {})
    for key in ("rows", "severity_known", "class_known", "language_known",
                "ecosystem_known", "repository_known",
                "exact_vulnerable_commits", "exact_fixed_commits",
                "affected_files", "affected_functions", "line_refs",
                "published_pocs", "executable_pocs", "experiment_ready_tier_a",
                "executed_pocs", "reproduced", "l5", "l6",
                "patch_candidates", "patches_verified"):
        L.append(f"{key} | {before.get(key, '-')} | {after.get(key, '-')}")
    L.append("")
    L.append(after.get("note", ""))
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def _write_unknowns_md(path: Path, unknowns: dict) -> None:
    L = ["# V3.1 unknown audit", "",
         "Every still-unknown field: how many, which sources, and what "
         "evidence would resolve it.",
         ""]
    for field, info in unknowns["fields"].items():
        L.append(f"## {field}: unknown = {info['unknown']}")
        L.append(f"by_source: {info['by_source']}")
        L.append(f"resolving evidence: {info['resolving_evidence']}")
        L.append("")
    L.append("## V3.0 baseline (context, not rewritten)")
    L.append(f"{unknowns['v30_baseline']}")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def _write_poc_report(path: Path, fragments: list, ledger: list) -> None:
    mentioned = sum(1 for f in fragments
                    if f.get("poc_section", {}).get("present"))
    with_code = sum(1 for f in fragments
                    if f.get("poc_section", {}).get("has_code"))
    supplied_ledger = sum(1 for c in ledger if c.get("poc_available"))
    path.write_text(json.dumps({
        "poc_mentioned_fragments": mentioned,
        "poc_with_code_fragments": with_code,
        "poc_available_v30_rows": supplied_ledger,
        "poc_executed": 0,
        "reproduced": 0,
        "note": "published PoC is not executed PoC; L2+ needs experiment "
                "artefacts (see experiment_readiness.json)",
        "normalization_version": NORM_VERSION,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_patch_report(path: Path, patch_candidates: list) -> None:
    path.write_text(json.dumps({
        "patch_candidates": len(patch_candidates),
        "verified_effective": 0,
        "reproduced_but_not_blocked": 0,
        "not_testable": len(patch_candidates),
        "inconclusive": 0,
        "note": "merged/described fixes are patch claims (reported_claim), "
                "never effectiveness verdicts; L6 needs same-test both "
                "revisions",
        "normalization_version": NORM_VERSION,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_queue(path: Path, readiness: list) -> None:
    tiers: dict[str, list] = collections.defaultdict(list)
    for r in readiness:
        tiers[r["tier"]].append(r)
    L = ["# V3 experiment queue (readiness-scored, v3.1)", "",
         "No execution claimed. Tier A first; every row names its blockers.",
         ""]
    for tier in ("A", "B", "C", "D"):
        rows = sorted(tiers.get(tier, []),
                      key=lambda r: r["finding_id"])[:40]
        L.append(f"## Tier {tier} ({len(tiers.get(tier, []))} rows, "
                 f"showing {len(rows)})")
        for r in rows:
            L.append(f"- {r['finding_id']} [{r['severity']}] "
                     f"poc={r['has_poc']} repo={r['has_repository']} "
                     f"rev={r['has_revision']} blockers={r['blockers']}")
        L.append("")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())

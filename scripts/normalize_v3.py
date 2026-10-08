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
import normalize_v3_lib as _lib  # noqa: E402
from normalize_v3_lib import (
    NORM_VERSION, U, V, X,
    _RJ, _apply_enrichment, _build_preview,
    _collect_patch_candidates, _corroborate, _coverage,
    _emit_fragment, _ov, _readiness_for, _unknown_audit,
    _write_normalization_md, _write_patch_report, _write_poc_report,
    _write_queue, _write_unknowns_md,
)


# ---------------------------------------------------------------------------
# Severity normalisation. Direct vocabulary matches are explicit; auditor
# scales are positional mappings with the original preserved (derived).
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# Taxonomy. Explicit auditor labels first; conservative multi-signal keyword
# rules second (derived, capped); unknown otherwise. Multi-label supported.
# ---------------------------------------------------------------------------


# class -> (strong phrases, support keywords). Derived fires on 1 strong or
# >=2 distinct support hits. All matching is case-insensitive substring.

# Auditor Category value -> VLUN class, used only when the auditor uses the
# exact label (explicit) or the documented near-label (derived + rule note).










# ---------------------------------------------------------------------------
# Language / ecosystem resolver. Explicit evidence wins; Rust/Go alone never
# determine a chain (spec sec 9).
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# Commit role classification (scope vs fix) from local context words.
# ---------------------------------------------------------------------------





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
    _lib._EXIST_NAMES, _lib._EXIST_TITLES, _lib._EXIST_COMMITS = \
        _v3_overlap_loader()
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




































# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------











if __name__ == "__main__":
    sys.exit(main())

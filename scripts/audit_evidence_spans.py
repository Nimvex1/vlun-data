#!/usr/bin/env python3
"""Evidence-span citation audit for the V3.1 preview layer (spec item 10).

Recomputes, from the preview records only, how many of the 12,504 V3.1 preview
rows carry:

  (a) a resolvable span          provenance.char_span = [start, end], ints,
                                 0 <= start < end
  (b) a page/line pointer        provenance.page_hint is set OR the row carries
                                 affected_lines (report line refs)
  (c) a verified source ref      provenance.file_sha256 present AND the pinned
                                 source file exists at provenance.source_location
                                 under the repo root AND re-hashing its bytes
                                 equals file_sha256 (the same "verified source
                                 ref" vocabulary scripts/validate_v31.py uses:
                                 file hash + pinned clone_head, no branch refs)
  (d) all three                  intersection of (a), (b), (c)

It also splits the resolvable spans by whether their referenced BYTES are
reproducible from the pinned source. V3 sources are METADATA_ONLY (NOTICE.md):
the pipeline stores offsets + hashes, never span text. For a span to be
`byte_verifiable` the byte range [start:end] of the pinned file must decode as
plain text; PDF char_spans index an extractor output (source_span.text_basis =
"despaced_copy"/"source_text") that is not the raw file bytes, so they are
recorded `byte_unavailable` rather than guessed. Missing/unverifiable spans are
`unavailable`, never invented.

Writes:
    reports/evidence_span_audit.json
    reports/evidence_span_audit.md

Usage:
    python scripts/audit_evidence_spans.py
    python scripts/audit_evidence_spans.py --check   # fail if committed report is stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import vlun_v3 as V  # noqa: E402  (paths + clone_head helper only; stdlib-backed)

PREVIEW = V.DERIVED_V3 / "normalized_records_preview.jsonl"
REPORTS = ROOT / "reports"
EXPECTED_ROWS = 12504
TEXT_FLOOR = 0.60  # >=60% printable chars => byte range is human-readable text


def canon_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                for r in rows),
        encoding="utf-8", newline="\n")


def canon_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True,
                               ensure_ascii=False) + "\n",
                    encoding="utf-8", newline="\n")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _valid_span(cs) -> bool:
    return (isinstance(cs, list) and len(cs) == 2
            and isinstance(cs[0], int) and isinstance(cs[1], int)
            and 0 <= cs[0] < cs[1])


def _mostly_text(b: bytes) -> bool:
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t ")
    return (printable / len(s)) >= TEXT_FLOOR


def load_preview() -> list[dict]:
    rows = []
    with open(PREVIEW, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="recompute and fail (exit 1) if the committed "
                         "reports/evidence_span_audit.json differs")
    args = ap.parse_args()

    rows = load_preview()
    file_hash_cache: dict[str, str] = {}

    def verified_source_ref(p: dict) -> tuple[bool, str]:
        """(is_verified, reason). Re-hash the pinned file once per location."""
        dig = p.get("file_sha256")
        loc = p.get("source_location")
        head = p.get("clone_head")
        if not (isinstance(dig, str) and dig):
            return False, "no_file_sha256"
        if not (isinstance(loc, str) and loc):
            return False, "no_source_location"
        if not (isinstance(head, str) and head):
            return False, "no_clone_head_pin"
        fpath = ROOT / loc
        if not fpath.is_file():
            return False, "pinned_source_absent"
        if loc not in file_hash_cache:
            with open(fpath, "rb") as fh:
                file_hash_cache[loc] = sha256_bytes(fh.read())
        if file_hash_cache[loc] != dig:
            return False, "file_sha256_mismatch"
        return True, "ok"

    a = b = c = ab = ac = bc = abc = 0
    only = {"span_only": 0, "ptr_only": 0, "srcref_only": 0,
            "span_ptr": 0, "span_ref": 0, "ptr_ref": 0,
            "none": 0}
    byte_verifiable = 0
    byte_unavailable = 0
    byte_avail_reasons: dict[str, int] = {}
    spans_by_loc: dict[str, list[list[int]]] = {}

    for r in rows:
        p = r.get("provenance") or {}
        has_span = _valid_span(p.get("char_span"))
        has_ptr = (p.get("page_hint") is not None
                   or r.get("affected_lines") is not None)
        ref_ok, _reason = verified_source_ref(p)
        a += has_span
        b += has_ptr
        c += ref_ok
        ab += has_span and has_ptr
        ac += has_span and ref_ok
        bc += has_ptr and ref_ok
        abc += has_span and has_ptr and ref_ok
        # key the overlap matrix
        key = (has_span, has_ptr, ref_ok)
        if key == (True, False, True):
            only["span_only"] += 1
        elif key == (False, True, True):
            only["ptr_only"] += 1
        elif key == (False, False, True):
            only["srcref_only"] += 1
        elif key == (True, True, False):
            only["span_ptr"] += 1
        elif key == (True, False, False):
            only["span_ref"] += 1
        elif key == (False, True, False):
            only["ptr_ref"] += 1
        elif key == (False, False, False):
            only["none"] += 1

        if has_span:
            loc = p.get("source_location") or ""
            spans_by_loc.setdefault(loc, []).append(list(p["char_span"]))

    # Byte-availability: read each pinned source at most once, evaluate every
    # resolvable span inside it, then free the bytes. This keeps memory bounded
    # even though PDF reports hold many spans each.
    for loc, span_list in spans_by_loc.items():
        fpath = ROOT / loc if loc else None
        if fpath is None or not fpath.is_file():
            for _ in span_list:
                byte_unavailable += 1
                byte_avail_reasons["span_without_pinned_file"] = \
                    byte_avail_reasons.get("span_without_pinned_file", 0) + 1
            continue
        raw = fpath.read_bytes()
        for cs in span_list:
            reproducible = False
            reason = "span_without_pinned_file"
            if cs[1] <= len(raw):
                reproducible = _mostly_text(raw[cs[0]:cs[1]])
                reason = ("extractor_relative_or_binary_bytes"
                          if not reproducible else "ok")
            else:
                reason = "span_beyond_file_length"
            if reproducible:
                byte_verifiable += 1
            else:
                byte_unavailable += 1
            byte_avail_reasons[reason] = byte_avail_reasons.get(reason, 0) + 1

    # rows that have NEITHER a resolvable span NOR a page/line pointer
    no_span_no_ptr = sum(
        1 for r in rows
        if not _valid_span((r.get("provenance") or {}).get("char_span"))
        and not ((r.get("provenance") or {}).get("page_hint") is not None
                 or r.get("affected_lines") is not None))

    result = {
        "generator": "scripts/audit_evidence_spans.py",
        "spec_item": "10 evidence-span citation scoring",
        "preview_layer": PREVIEW.relative_to(ROOT).as_posix(),
        "preview_rows": len(rows),
        "expected_preview_rows": EXPECTED_ROWS,
        "counts": {
            "a_resolvable_span": a,
            "b_page_or_line_pointer": b,
            "c_verified_source_ref": c,
            "d_all_three": abc,
        },
        "pairwise": {
            "a_and_b": ab, "a_and_c": ac, "b_and_c": bc,
        },
        "overlap_matrix": {
            "span_only": only["span_only"],
            "pointer_only": only["ptr_only"],
            "source_ref_only": only["srcref_only"],
            "span_and_pointer_no_ref": only["span_ptr"],
            "span_and_ref_no_pointer": only["span_ref"],
            "pointer_and_ref_no_span": only["ptr_ref"],
            "all_three": abc,
            "none_of_three": only["none"],
        },
        "span_byte_availability": {
            "resolvable_spans": a,
            "byte_verifiable": byte_verifiable,
            "byte_unavailable": byte_unavailable,
            "reasons": byte_avail_reasons,
            "note": "V3 sources are METADATA_ONLY (NOTICE.md). A resolvable "
                    "char_span over a PDF indexes an extractor output "
                    "(source_span.text_basis in despaced_copy|source_text), "
                    "not the raw pinned-file bytes; the referenced bytes "
                    "cannot be hash-reproduced from the PDF, so the span is "
                    "marked unavailable rather than guessed.",
        },
        "unavailable_spans_total": no_span_no_ptr,
        "definitions": {
            "resolvable_span": "provenance.char_span=[s,e], ints, 0<=s<e",
            "page_or_line_pointer":
                "provenance.page_hint is set OR affected_lines is set",
            "verified_source_ref":
                "file_sha256 present AND pinned source_location exists under "
                "repo root AND sha256(pinned bytes)==file_sha256 AND "
                "clone_head pin present (matches validate_v31 no-invention)",
        },
    }

    md = _markdown(result)

    if args.check:
        jp = REPORTS / "evidence_span_audit.json"
        mp = REPORTS / "evidence_span_audit.md"
        want_j = json.dumps(result, indent=2, sort_keys=True,
                            ensure_ascii=False) + "\n"
        ok = jp.exists() and mp.exists() \
            and jp.read_text(encoding="utf-8") == want_j \
            and mp.read_text(encoding="utf-8") == md
        if not ok:
            V.log("audit_evidence_spans.py --check FAILED: committed report "
                  "is stale or missing; re-run without --check")
            return 1
        V.log("audit_evidence_spans.py --check OK")
        return 0

    REPORTS.mkdir(parents=True, exist_ok=True)
    canon_json(REPORTS / "evidence_span_audit.json", result)
    (REPORTS / "evidence_span_audit.md").write_text(md, encoding="utf-8",
                                                    newline="\n")
    V.log(f"audit_evidence_spans.py: wrote reports/evidence_span_audit."
          f"{{json,md}}  rows={len(rows)} span={a} ptr={b} ref={c} "
          f"all3={abc} byte_verifiable={byte_verifiable}")
    return 0


def _markdown(res: dict) -> str:
    c = res["counts"]
    o = res["overlap_matrix"]
    ba = res["span_byte_availability"]
    lines = [
        "# Evidence-span citation audit (V3.1 preview)",
        "",
        f"Generated by `{res['generator']}` from `{res['preview_layer']}`. "
        f"Preview rows: **{res['preview_rows']:,}** "
        f"(expected {res['expected_preview_rows']:,}).",
        "",
        "## Coverage counts (recomputed from records)",
        "",
        "| Dimension | Rows |",
        "|---|---:|",
        f"| (a) resolvable span | {c['a_resolvable_span']:,} |",
        f"| (b) page/line pointer | {c['b_page_or_line_pointer']:,} |",
        f"| (c) verified source ref | {c['c_verified_source_ref']:,} |",
        f"| (d) all three | {c['d_all_three']:,} |",
        "",
        "## Overlap matrix",
        "",
        "| Bucket | Rows |",
        "|---|---:|",
        f"| span only | {o['span_only']:,} |",
        f"| pointer only | {o['pointer_only']:,} |",
        f"| source-ref only | {o['source_ref_only']:,} |",
        f"| span + pointer, no ref | {o['span_and_pointer_no_ref']:,} |",
        f"| span + ref, no pointer | {o['span_and_ref_no_pointer']:,} |",
        f"| pointer + ref, no span | {o['pointer_and_ref_no_span']:,} |",
        f"| all three | {o['all_three']:,} |",
        f"| none of the three | {o['none_of_three']:,} |",
        "",
        "## Span byte availability (verified vs unavailable)",
        "",
        f"- resolvable spans: {ba['resolvable_spans']:,}",
        f"- byte-reproducible from the pinned source (`verified`): "
        f"{ba['byte_verifiable']:,}",
        f"- not byte-reproducible (`unavailable`): {ba['byte_unavailable']:,}",
        f"- reasons: `{json.dumps(ba['reasons'], sort_keys=True)}`",
        "",
        "> " + ba["note"],
        "",
        f"Rows with neither a resolvable span nor a page/line pointer: "
        f"**{res['unavailable_spans_total']:,}**.",
        "",
        "## Definitions",
        "",
        "```json",
        json.dumps(res["definitions"], indent=2, sort_keys=True),
        "```",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())

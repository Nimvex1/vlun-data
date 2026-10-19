#!/usr/bin/env python3
"""Build the evidence-span task family (spec item 10).

Each task requires BOTH an answer AND an exact span citation. The artefacts are
split by audience:

  derived_span_tasks/tasks.jsonl   model-facing: question + allowed source
                                   identifiers ONLY. Never the expected label,
                                   the expected span, its byte offsets, its
                                   hash, or any hidden-test content. This is
                                   enforced by a leak self-check in this script
                                   (see _leak_check), not just by prose.
  derived_span_tasks/answer_key.jsonl  HELD-OUT. Expected answer + expected
                                   span + availability + rights. NOT FOR MODELS.
  derived_span_tasks/splits.json   deterministic dev/test split of task ids.
  derived_span_tasks/manifest.json build facts, counts, tolerance, blockers.

Span model (V3 sources are METADATA_ONLY -- NOTICE.md): the public artefacts
carry offsets + hashes only, never copied span text.

  span_availability = "verified"    the exact referenced bytes are reproducible
                                    from the pinned source (V3/clones/<...> at
                                    the provenance clone_head pin); the record
                                    stores file, byte offsets and sha256 of the
                                    referenced bytes.
  span_availability = "unavailable" the referenced bytes are NOT reproducible
                                    from a pinned source (a PDF char_span that
                                    indexes an extractor output, or a
                                    multi-finding audit file with no exact
                                    intra-file anchor). The correct model
                                    behaviour on these is to ABSTAIN.

A span is "verified" in one of two ways:
  1. char_span_bytes  -- the row's provenance.char_span lands on a plain-text
                          byte range of the pinned file (rare on PDFs; detected
                          the same way audit_evidence_spans.py does).
  2. source_file_full_bytes -- a plaintext source (md/sol/json) that carries
                          exactly ONE finding: the whole referenced artifact is
                          the evidence span, [0, filesize), hash == file_sha256.

Usage:
    python scripts/build_span_tasks.py
    python scripts/build_span_tasks.py --check   # rebuild in memory, fail if
                                                 # outputs on disk differ
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import vlun_v3 as V  # noqa: E402

PREVIEW = V.DERIVED_V3 / "normalized_records_preview.jsonl"
OUT_DIR = ROOT / "derived_span_tasks"
TEXT_FLOOR = 0.60
KNOWN_SEVERITY = ("Critical", "High", "Medium", "Low", "Informational")
ABSTAIN_TOKEN = "ABSTAIN"
FAMILY_VERSION = "span_tasks_v1"


def canon_jsonl_text(rows: list[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                   for r in rows)


def canon_json_text(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


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


def task_id(finding_id: str) -> str:
    return "spt-" + sha256_bytes(finding_id.encode("utf-8"))[:16]


def split_of(tid: str) -> str:
    # deterministic: last hex nibble < 3 => dev (~18.75%), else test
    h = int(tid[-1], 16)
    return "dev" if h < 3 else "test"


def _load_preview() -> list[dict]:
    rows = []
    with open(PREVIEW, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _source_present_and_hash_ok(p: dict) -> bool:
    loc = p.get("source_location")
    dig = p.get("file_sha256")
    head = p.get("clone_head")
    if not (isinstance(loc, str) and loc and isinstance(dig, str)
            and dig and isinstance(head, str) and head):
        return False
    fp = ROOT / loc
    if not fp.is_file():
        return False
    return sha256_bytes(fp.read_bytes()) == dig


def classify(r: dict) -> dict:
    """Return the held-out span record + availability for one preview row."""
    p = r.get("provenance") or {}
    loc = p.get("source_location") or ""
    sev = r.get("severity")
    has_span = _valid_span(p.get("char_span"))
    ref_ok = _source_present_and_hash_ok(p)
    ext = os.path.splitext(loc)[1].lower()
    plaintext = ext in (".md", ".sol", ".json")

    span = {"source_location": loc, "clone_head": p.get("clone_head"),
            "file_sha256": p.get("file_sha256"),
            "page_hint": p.get("page_hint"),
            "affected_lines": r.get("affected_lines")}

    availability = "unavailable"
    reason = ""
    span_kind = "none"

    if has_span and ref_ok and plaintext is False:
        # char_span lives on PDFs: check byte reproducibility
        raw = (ROOT / loc).read_bytes()
        s, e = p["char_span"]
        if e <= len(raw) and _mostly_text(raw[s:e]):
            availability = "verified"
            span_kind = "char_span_bytes"
            span.update({"start_byte": s, "end_byte": e,
                         "span_sha256": sha256_bytes(raw[s:e])})
            reason = "pinned_bytes_at_span_reproduced"
        else:
            span.update({"start_byte": s, "end_byte": e,
                         "span_sha256": None})
            reason = "extractor_relative_span_not_byte_reproducible"
    elif has_span and ref_ok and plaintext:
        raw = (ROOT / loc).read_bytes()
        s, e = p["char_span"]
        if e <= len(raw) and _mostly_text(raw[s:e]):
            availability = "verified"
            span_kind = "char_span_bytes"
            span.update({"start_byte": s, "end_byte": e,
                         "span_sha256": sha256_bytes(raw[s:e])})
            reason = "pinned_bytes_at_span_reproduced"
        else:
            span.update({"start_byte": s, "end_byte": e,
                         "span_sha256": None})
            reason = "char_span_not_byte_reproducible"

    # full-artifact span for single-finding plaintext sources (verified) is
    # promoted by build() once findings-per-file is known.

    return {"availability": availability, "span_kind": span_kind,
            "span": span, "reason": reason, "ref_ok": ref_ok,
            "plaintext": plaintext, "has_span": has_span, "severity": sev}


def _question() -> str:
    return ("The finding to resolve is identified only by the allowed source "
            "identifiers listed for this task. State the severity that source "
            "assigns to that finding as a single label, and cite the exact "
            "span within that source which states it. Reply ABSTAIN if you "
            "cannot cite span bytes verifiable from the allowed sources.")


def _leak_check(prompt: str, expected_answer, span: dict) -> None:
    """Raise if the model-facing prompt carries held-out content.

    The answer DOMAIN lives in output_contract (a response schema, not a
    label); the QUESTION must not reveal this task's expected label, nor any
    expected span offset or hash. Scanned here, in code, on every task.
    """
    import re
    forbidden: list[str] = []
    if isinstance(expected_answer, str) and expected_answer in KNOWN_SEVERITY:
        forbidden.append(("word", expected_answer))
    for k in ("start_byte", "end_byte", "span_sha256"):
        v = span.get(k)
        if isinstance(v, int):
            forbidden.append(("num", str(v)))
        elif isinstance(v, str) and len(v) >= 16:
            forbidden.append(("str", v[:16]))
    for kind, tok in forbidden:
        if kind == "word":
            if re.search(r"(?<![A-Za-z])" + re.escape(tok) + r"(?![A-Za-z])",
                         prompt):
                raise AssertionError(
                    f"LEAK: model-facing prompt reveals expected label {tok!r}")
        elif tok and tok in prompt:
            raise AssertionError(
                f"LEAK: model-facing prompt contains held-out span value "
                f"{tok!r}")


def build() -> tuple[list[dict], list[dict], dict, dict]:
    rows = _load_preview()
    findings_per_file: dict[str, int] = {}
    for r in rows:
        loc = (r.get("provenance") or {}).get("source_location") or ""
        findings_per_file[loc] = findings_per_file.get(loc, 0) + 1

    tasks: list[dict] = []
    keys: list[dict] = []
    counts = {"total": 0, "verified": 0, "unavailable": 0,
              "verified_char_span_bytes": 0,
              "verified_source_file_full_bytes": 0,
              "answerable": 0, "abstain_expected": 0}
    blockers = {
        "extractor_relative_span_not_byte_reproducible": 0,
        "char_span_not_byte_reproducible": 0,
        "multi_finding_source_no_exact_anchor": 0,
        "unknown_severity_no_answer": 0,
        "unverified_source_ref": 0,
    }

    for r in rows:
        counts["total"] += 1
        fid = r.get("finding_id")
        p = r.get("provenance") or {}
        loc = p.get("source_location") or ""
        info = classify(r)
        sev = info["severity"]
        answerable = sev in KNOWN_SEVERITY
        single = findings_per_file.get(loc, 0) == 1

        availability = info["availability"]
        span = info["span"]
        span_kind = info["span_kind"]
        reason = info["reason"]

        # promote single-finding plaintext candidate to a verified full span
        if availability == "unavailable" and info["plaintext"] \
                and info["ref_ok"] and single and answerable:
            fsize = os.path.getsize(ROOT / loc)
            availability = "verified"
            span_kind = "source_file_full_bytes"
            span.update({"start_byte": 0, "end_byte": fsize,
                         "span_sha256": sha256_bytes((ROOT / loc).read_bytes())})
            reason = "single_finding_source_full_bytes_reproduced"

        # unavailable bookkeeping (blockers)
        if availability == "unavailable":
            if not info["ref_ok"]:
                blockers["unverified_source_ref"] += 1
                reason = "source_ref_not_verified"
            elif info["has_span"]:
                if info["plaintext"]:
                    blockers["char_span_not_byte_reproducible"] += 1
                else:
                    blockers["extractor_relative_span_not_byte_reproducible"] += 1
            elif info["plaintext"] and not single:
                blockers["multi_finding_source_no_exact_anchor"] += 1
            elif not answerable:
                blockers["unknown_severity_no_answer"] += 1

        abstain_expected = (availability == "unavailable")

        tid = task_id(fid)
        prompt = _question()
        _leak_check(prompt, sev if answerable else None, span)

        tasks.append({
            "task_id": tid,
            "family_version": FAMILY_VERSION,
            "prompt": prompt,
            "allowed_source_ids": [loc, p.get("clone_head")],
            "output_contract": {
                "answer_field": "severity",
                "answer_domain": list(KNOWN_SEVERITY) + ["Unknown"],
                "span_field": "span",
                "span_schema": {"source_location": "str",
                                "start_byte": "int", "end_byte": "int"},
                "abstain_token": ABSTAIN_TOKEN,
                "instruction": ("Give the severity the source assigns AND cite "
                                "the exact span {source_location,start_byte,"
                                "end_byte} that states it. If you cannot cite "
                                "span bytes verifiable from the allowed "
                                "sources, reply ABSTAIN."),
            },
        })
        keys.append({
            "task_id": tid,
            "finding_id": fid,
            "_audience": "HELD-OUT -- NOT FOR MODELS",
            "expected_answer": sev if answerable else "Unknown",
            "answerable": answerable,
            "expected_span": span,
            "span_kind": span_kind,
            "span_availability": availability,
            "abstain_expected": abstain_expected,
            "availability_reason": reason,
            "rights": {
                "distribution": "metadata_only",
                "may_copy_span_text": False,
                "licence_posture": "see NOTICE.md (third-party audit code "
                                   "and report prose are METADATA_ONLY; "
                                   "artefacts carry offsets+hashes, no span text)",
                "source_id": r.get("source_id"),
            },
        })
        counts["verified" if availability == "verified" else "unavailable"] += 1
        if span_kind == "char_span_bytes":
            counts["verified_char_span_bytes"] += 1
        if span_kind == "source_file_full_bytes":
            counts["verified_source_file_full_bytes"] += 1
        if answerable:
            counts["answerable"] += 1
        if abstain_expected:
            counts["abstain_expected"] += 1

    tasks.sort(key=lambda t: t["task_id"])
    keys.sort(key=lambda k: k["task_id"])

    splits = {
        "family_version": FAMILY_VERSION,
        "method": "sha256(finding_id) last nibble <3 => dev, else test",
        "dev": [t["task_id"] for t in tasks if split_of(t["task_id"]) == "dev"],
        "test": [t["task_id"] for t in tasks if split_of(t["task_id"]) == "test"],
    }

    manifest = {
        "generator": "scripts/build_span_tasks.py",
        "spec_item": "10 evidence-span citation scoring",
        "family_version": FAMILY_VERSION,
        "inputs": {"preview_layer": PREVIEW.relative_to(ROOT).as_posix(),
                   "pinned_sources": "V3/clones (READ-ONLY, git-ignored, "
                                      "never redistributed)"},
        "counts": counts,
        "blockers_per_record_class": blockers,
        "citation_exactness_tolerance_bytes": 0,
        "tolerance_note": "citation_exactness: |cited-start-expected-start| "
                          "<=T and |cited-end-expected-end| <=T with T=0 here; "
                          "documented so graders and callers agree.",
        "span_support": "graded by re-reading the PINNED source at the CITED "
                        "byte bounds and comparing sha256 to expected "
                        "span_sha256 -- verified against the source, never "
                        "against the model's own quote.",
        "separation": "answer correctness / citation existence / citation "
                      "exactness / span support / abstention graded "
                      "INDEPENDENTLY by scripts/score_span_tasks.py.",
        "leak_guard": "model-facing tasks.jsonl is checked (in build) to "
                      "exclude expected labels, span offsets and hashes.",
        "rights": "V3 sources METADATA_ONLY (NOTICE.md): offsets+hashes only, "
                  "no span text copied.",
        "held_out": False,
        "held_out_reason": (
            "answer_key.jsonl is published in this layer, so the family is an "
            "open-key scorer, not a held-out set: a model could read the expected "
            "labels from the same checkout. The isolation that matters here is "
            "prompt-level (the key never enters a model-facing prompt, enforced by "
            "_leak_check at build time). The held-out split is the VLUN-Prove "
            "family, whose answer key lives outside the repository and is pinned by "
            "hash in reports/prove_split_interface.json."),
    }
    return tasks, keys, splits, manifest


def outputs() -> dict[Path, str]:
    tasks, keys, splits, manifest = build()
    return {
        OUT_DIR / "tasks.jsonl": canon_jsonl_text(tasks),
        OUT_DIR / "answer_key.jsonl": canon_jsonl_text(keys),
        OUT_DIR / "splits.json": canon_json_text(splits),
        OUT_DIR / "manifest.json": canon_json_text(manifest),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build the answer+exact-span task family.")
    ap.add_argument("--check", action="store_true",
                    help="do not write; fail (exit 1) if on-disk outputs "
                         "differ from a deterministic rebuild")
    args = ap.parse_args()

    want = outputs()
    if args.check:
        bad = []
        for path, text in want.items():
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                bad.append(path.relative_to(ROOT).as_posix())
        if bad:
            V.log("build_span_tasks.py --check FAILED, stale/missing: "
                  + ", ".join(bad))
            return 1
        V.log("build_span_tasks.py --check OK")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path, text in want.items():
        path.write_text(text, encoding="utf-8", newline="\n")
    m = json.loads(want[OUT_DIR / "manifest.json"])
    c = m["counts"]
    V.log(f"build_span_tasks.py: total={c['total']} verified={c['verified']} "
          f"(char_span={c['verified_char_span_bytes']} "
          f"full_bytes={c['verified_source_file_full_bytes']}) "
          f"unavailable={c['unavailable']} abstain={c['abstain_expected']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Verbatim-only hydration + purge for the v2.2 ML and V3 layers.

Every inline field written here is copied byte-for-byte from a real local
source that the row already points at:

  * V3 rows: ``source_location`` resolves to a file under ``V3/clones/``.
    Fenced code blocks `````lang ... ``````, `````diff ... ``````, PoC `.sol`
    bodies and their verbatim ``//`` commentary are lifted directly.  For the
    Code4rena JSON pointer rows the prose/code live in the sibling
    ``<handle>*Q.md`` file, resolved deterministically.
  * v2.2 ML rows: ``code_context[].resolved_path`` is opened when it exists and
    copied verbatim into ``snippet``.  ``patch.diff`` is assembled from cached
    GitHub commit payloads under ``work/v2_2/raw/`` (``files[].patch``).

Rows with no verbatim code(+prose) are QUARANTINED: a pointer is appended to
``derived_v3/quarantine.jsonl`` / ``derived_v2_2/quarantine.jsonl`` and the row
is removed from every TRAINABLE table (records, splits, benchmarks, preview,
triage queue).  Nothing is fabricated, and the full body stays in the
provenance ledger so no evidence is lost.

    python scripts/hydrate_v22_v3.py              # hydrate + purge + log
    python scripts/hydrate_v22_v3.py --check      # compute only, write nothing
    python scripts/hydrate_v22_v3.py --ml-only    # v2.2 ML only
    python scripts/hydrate_v22_v3.py --purge-only # purge already-hydrated data

stdlib only, LF output, deterministic.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_FENCE = re.compile(r"(?s)```([A-Za-z0-9_+.-]*)\n(.*?)```")
_MD_HEADING = re.compile(r"(?m)^\s{0,3}#{1,6}\s+")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_WS = re.compile(r"[ \t]+")

MAX_SNIPPET = 3000
MAX_TOTAL_CODE = 6000
MAX_PROSE = 4000
MAX_DIFF = 12000


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _clean_prose(text: str) -> str:
    text = _FENCE.sub(" ", text)
    text = _MD_HEADING.sub("", text)
    text = _MD_LINK.sub(r"\1", text)
    text = text.replace("`", "")
    lines = []
    for line in text.splitlines():
        s = _WS.sub(" ", line).strip()
        if len(s) < 3 or s.startswith(("---", "***", "===", "|", "![", "<")):
            continue
        lines.append(s)
    return "\n".join(lines).strip()


def _sibling_md(source: Path) -> Path | None:
    handle = source.stem.split("-")[0]
    if not handle:
        return None
    candidates = sorted(source.parent.glob(f"{handle}*.md"))
    for c in candidates:
        if c.stem.endswith("-Q") or c.stem.endswith("Q"):
            return c
    return candidates[0] if candidates else None


def extract_source(source_location: str) -> dict:
    out: dict = {"snippets": [], "prose": "", "diff": "", "poc_code": "",
                 "resolved": None, "ext": ""}
    if not source_location or source_location.upper() in ("UNKNOWN", "NONE"):
        return out
    p = Path(source_location)
    if not p.is_absolute():
        p = ROOT / p
    if not p.exists():
        return out
    ext = p.suffix.lower()
    out["ext"] = ext
    out["resolved"] = (str(p.relative_to(ROOT)) if str(p).startswith(str(ROOT))
                       else str(p)).replace("\\", "/")

    if ext == ".pdf":
        txt = p.with_suffix(p.suffix + ".txt")
        text = _read_text(txt) if txt.exists() else ""
        if not text:
            return out
    elif ext == ".sol":
        sol = _read_text(p)
        if len(sol.strip()) >= 50:
            out["snippets"].append(sol.strip()[:MAX_SNIPPET])
        comments = []
        for line in sol.splitlines():
            s = line.strip()
            if s.startswith("//"):
                c = s[2:].strip()
                if len(c) >= 3:
                    comments.append(c)
        for blk in re.findall(r"(?s)/\*(.*?)\*/", sol):
            c = " ".join(x.strip().lstrip("*").strip()
                         for x in blk.splitlines() if x.strip())
            if len(c) >= 3:
                comments.append(c)
        out["prose"] = "\n".join(comments)[:MAX_PROSE]
        return out
    else:
        text = _read_text(p)

    for lang, body in _FENCE.findall(text):
        body = body.strip("\n")
        if len(body.strip()) < 50:
            continue
        lname = (lang or "").lower()
        if lname == "diff":
            if len(out["diff"]) < MAX_DIFF:
                out["diff"] += body + "\n"
        elif lname in ("poc", "exploit", "exploittest"):
            if not out["poc_code"]:
                out["poc_code"] = body[:MAX_SNIPPET]
        elif sum(len(s) for s in out["snippets"]) < MAX_TOTAL_CODE:
            out["snippets"].append(body[:MAX_SNIPPET])

    if not out["diff"]:
        for _lang, body in _FENCE.findall(text):
            b = body.strip("\n")
            if b.lstrip().startswith(("--- a/", "diff --git", "@@")):
                out["diff"] = b[:MAX_DIFF]
                break

    out["prose"] = _clean_prose(text)[:MAX_PROSE]

    if ext == ".json" and not out["snippets"]:
        sib = _sibling_md(p)
        if sib is not None and sib != p:
            st = _read_text(sib)
            for lang, body in _FENCE.findall(st):
                body = body.strip("\n")
                if len(body.strip()) < 50:
                    continue
                if (lang or "").lower() == "diff":
                    if len(out["diff"]) < MAX_DIFF:
                        out["diff"] += body + "\n"
                elif sum(len(s) for s in out["snippets"]) < MAX_TOTAL_CODE:
                    out["snippets"].append(body[:MAX_SNIPPET])
            md_prose = _clean_prose(st)[:MAX_PROSE]
            if md_prose:
                out["prose"] = md_prose
            if sib.exists():
                out["resolved"] = (str(sib.relative_to(ROOT))
                                   if str(sib).startswith(str(ROOT))
                                   else str(sib)).replace("\\", "/")
    return out


def _code_context(row: dict, ex: dict) -> list:
    if not ex["snippets"]:
        return []
    lang = row.get("language") or "unknown"
    file_ref = ex["resolved"] or row.get("source_location") or "unknown"
    return [{
        "file": file_ref,
        "source_location": row.get("source_location"),
        "snippet": snip,
        "language": lang,
        "block_index": i,
        "evidence_type": "observed_fact",
        "note": "verbatim fenced code block lifted from local clone source",
    } for i, snip in enumerate(ex["snippets"])]


def hydrate_v3_row(row: dict) -> dict:
    src_loc = row.get("source_location")
    if not src_loc and isinstance(row.get("provenance"), dict):
        src_loc = row["provenance"].get("source_location")
    ex = extract_source(src_loc or "")
    code = _code_context(row, ex)
    has_code, has_prose = bool(code), len(ex["prose"]) >= 100

    if has_code:
        row["code_context"] = code
    if ex["prose"]:
        row["description"] = ex["prose"]
        if not row.get("root_cause") or row.get("root_cause") == "unknown":
            row["root_cause"] = ex["prose"][:MAX_PROSE]
    if ex["diff"]:
        patch = row.get("patch") if isinstance(row.get("patch"), dict) else {}
        patch["diff"] = ex["diff"][:MAX_DIFF]
        patch["evidence_type"] = "observed_fact"
        row["patch"] = patch
    if ex["poc_code"]:
        poc = row.get("poc") if isinstance(row.get("poc"), dict) else {
            "available": bool(row.get("poc_available"))}
        poc["code"] = ex["poc_code"]
        row["poc"] = poc

    if has_code and has_prose:
        status = "HYDRATED"
    elif has_code and not has_prose:
        status = "QUARANTINED_NO_PROSE"
    elif has_prose and not has_code:
        status = "QUARANTINED_NO_CODE"
    else:
        status = "QUARANTINED_EMPTY"
    row["_hydration"] = {
        "status": status,
        "code_blocks": len(code),
        "code_chars": sum(len(c["snippet"]) for c in code),
        "prose_chars": len(ex["prose"]),
        "has_diff": bool(ex["diff"]),
        "has_poc_code": bool(ex["poc_code"]),
        "resolved_source": ex["resolved"],
        "method": "verbatim extraction from local clone",
    }
    return row


def _load_commit_diffs() -> dict:
    import glob
    mapping: dict = {}
    for f in glob.glob(os.path.join(ROOT, "work/v2_2/raw/**/*.json"), recursive=True):
        try:
            obj = json.loads(_read_text(Path(f)))
        except Exception:
            continue
        files = obj.get("files") if isinstance(obj, dict) else None
        if not isinstance(files, list):
            continue
        chunks = []
        for it in files:
            if isinstance(it, dict) and isinstance(it.get("patch"), str) \
                    and len(it["patch"]) >= 20:
                fname = it.get("filename") or it.get("path") or "file"
                chunks.append(f"--- a/{fname}\n+++ b/{fname}\n" + it["patch"])
        if not chunks:
            continue
        diff = "\n".join(chunks)[:MAX_DIFF]
        sha = obj.get("sha") or ""
        if isinstance(sha, str) and len(sha) >= 12:
            mapping[sha.lower()] = diff
            mapping[sha[:12].lower()] = diff
        m = re.search(r"commit_([0-9a-f]{12,40})", Path(f).stem, re.I)
        if m:
            mapping[m.group(1).lower()] = diff
    return mapping


def hydrate_ml_row(row: dict, commit_diffs: dict) -> dict:
    snippets_added = 0
    for ctx in row.get("code_context") or []:
        if not isinstance(ctx, dict):
            continue
        rp = ctx.get("resolved_path")
        if not rp:
            continue
        p = Path(rp)
        if not p.is_absolute():
            p = ROOT / p
        if not p.exists():
            continue
        text = _read_text(p)
        if len(text.strip()) < 50:
            continue
        start, end = ctx.get("line_start"), ctx.get("line_end")
        snippet = text
        if isinstance(start, int) and start > 0:
            lines = text.splitlines()
            lo = max(0, start - 1)
            hi = min(len(lines), end if isinstance(end, int) and end >= lo else lo + 60)
            cand = "\n".join(lines[lo:hi])
            if len(cand.strip()) >= 50:
                snippet = cand
        ctx["snippet"] = snippet.strip()[:MAX_SNIPPET]
        ctx["evidence_type"] = "observed_fact"
        snippets_added += 1

    patch = row.get("patch")
    diff_added = False
    if isinstance(patch, dict):
        sha = str(patch.get("commit") or "")
        d = commit_diffs.get(sha.lower()) or commit_diffs.get(sha[:12].lower())
        if d:
            patch["diff"] = d
            patch["evidence_type"] = "observed_fact"
            diff_added = True
    total_snip = sum(len(str(c.get("snippet") or ""))
                     for c in (row.get("code_context") or [])
                     if isinstance(c, dict))
    diff_chars = len(patch.get("diff") or "") if isinstance(patch, dict) else 0
    has_code = total_snip >= 50 or diff_chars >= 50
    if has_code and diff_added:
        status = "HYDRATED"
    elif has_code:
        status = "HYDRATED_SNIPPET_ONLY"
    else:
        status = "QUARANTINED_NO_CODE"
    row["_hydration"] = {
        "status": status, "snippet_entries": snippets_added,
        "snippet_chars": total_snip, "diff_chars": diff_chars,
        "has_diff": diff_added,
        "method": "verbatim source file + cached GitHub commit files[].patch",
    }
    return row


# ---- IO / purge ------------------------------------------------------------

def _write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _load_jsonl(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip()] if path.exists() else []


def is_quarantined(row: dict) -> bool:
    status = ((row.get("_hydration") or {}).get("status")
              or row.get("hydration_status")
              or row.get("_quarantine_reason"))
    return str(status or "").startswith("QUARANTINED")


def purge_v3(report: dict) -> None:
    """Move unhydratable rows out of every V3 trainable/benchmark table."""
    rec_path = ROOT / "derived_v3/records.jsonl"
    records = _load_jsonl(rec_path)
    before = len(records)
    keep = [r for r in records if not is_quarantined(r)]
    drop = [r for r in records if is_quarantined(r)]
    hydrate_ids = {r["finding_id"] for r in keep}

    # Reconstruct the set-aside population from the provenance ledger.  This is
    # stable across re-runs: records.jsonl is already purged on a second pass,
    # while the ledger keeps every candidate and its _hydration status.
    ledger0 = _load_jsonl(ROOT / "derived_v3/candidate_ledger.jsonl")
    admitted = {"IMPORT", "IMPORT_AS_UNVERIFIED", "IMPORT_AS_NEGATIVE"}
    q = []
    for r in ledger0:
        hyd = r.get("_hydration") or {}
        already = str(r.get("decision_reason") or "").startswith("QUARANTINED_UNHYDRATABLE")
        if not (already or (r.get("decision") in admitted
                            and str(hyd.get("status", "")).startswith("QUARANTINED"))):
            continue
        if not hyd:
            hyd = {"status": r.get("_quarantine_reason") or "QUARANTINED_UNKNOWN"}
        q.append({
            "finding_id": r["candidate_id"], "source_id": r.get("source_id"),
            "source_location": (r.get("provenance") or {}).get("source_location"),
            "dataset_version": r.get("dataset_version"),
            "record_type": "quarantine_pointer_v3",
            "decision": r.get("decision"),
            "_quarantine_reason": hyd["status"],
            "_quarantined_from_split": None,
            "_hydration": hyd,
            "note": "pointer only; no verbatim source yielded code+prose",
        })
    # Fallback for a first pass where the ledger has not been hydrated yet.
    if not q:
        for r in drop:
            q.append({
                "finding_id": r["finding_id"], "source_id": r["source_id"],
                "source_location": (r.get("provenance") or {}).get("source_location"),
                "dataset_version": r.get("dataset_version"),
                "record_type": "quarantine_pointer_v3",
                "decision": r.get("decision"),
                "_quarantine_reason": r["_hydration"]["status"],
                "_quarantined_from_split": r.get("benchmark_split"),
                "_hydration": r["_hydration"],
                "note": "pointer only; no verbatim source yielded code+prose",
            })
    q.sort(key=lambda r: r["finding_id"])
    _write_jsonl(ROOT / "derived_v3/quarantine.jsonl", q)
    _write_jsonl(ROOT / "splits_v3/quarantine.jsonl", q)
    _write_jsonl(rec_path, keep)
    report["derived_v3/records.jsonl"] = {"before": before, "after": len(keep),
                                          "quarantined": len(drop)}

    # The provenance ledgers keep every row (so the 7,712 candidate pin and all
    # cross-references stay resolvable), but a quarantined candidate is no
    # longer ADMITTED: mark it REJECT with the machine-readable reason.  This
    # keeps records == admitted for the V3 structural gate.
    drop_ids = {r["finding_id"] for r in drop}
    # idempotent: on a re-run records.jsonl is already purged, so recover the
    # set from the quarantine log written by the first pass.
    drop_ids |= {r["finding_id"] for r in
                 _load_jsonl(ROOT / "derived_v3/quarantine.jsonl")}
    for rel in ["derived_v3/candidate_ledger.jsonl", "jsonl_v3/findings.jsonl"]:
        p = ROOT / rel
        rows = _load_jsonl(p)
        changed = 0
        for r in rows:
            if r.get("candidate_id") in drop_ids:
                r["decision"] = "REJECT"
                r["decision_reason"] = (
                    "QUARANTINED_UNHYDRATABLE: no verbatim source yielded "
                    "inline code (>=50 chars) and prose (>=100 chars); "
                    "see derived_v3/quarantine.jsonl")
                r["_quarantine_reason"] = (r.get("_hydration") or {}).get("status")
                # A REJECT candidate must not carry a negative_class (closed
                # iff rule in validate_v3); preserve the original value under
                # a quarantine-only key instead of inventing anything.
                if r.get("negative_class"):
                    r["_quarantine_negative_class"] = r["negative_class"]
                    r["negative_class"] = None
                changed += 1
        if changed:
            _write_jsonl(p, rows)
        report[rel] = {"before": len(rows), "after": len(rows),
                       "decision_changed_to_REJECT": changed}

    # negatives
    p = ROOT / "derived_v3/negatives.jsonl"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        nk = [r for r in rows if r.get("finding_id") in hydrate_ids]
        _write_jsonl(p, nk)
        report["derived_v3/negatives.jsonl"] = {"before": n0, "after": len(nk)}

    # split
    p = ROOT / "splits_v3/split.json"
    sp = json.loads(p.read_text(encoding="utf-8"))
    n0 = {k: len(v) for k, v in sp["splits"].items()}
    for k in sp["splits"]:
        sp["splits"][k] = [i for i in sp["splits"][k] if i in hydrate_ids]
    _write_json(p, sp)
    report["splits_v3/split.json"] = {"before": n0,
                                       "after": {k: len(v) for k, v in sp["splits"].items()}}

    # benchmark task tables
    for rel in ["benchmark/v3_R_source_tier_routing.jsonl",
                "benchmark/retired_families/v3_S_contest_outcome.jsonl",
                "benchmark/v3_T_taxonomy_explicit.jsonl"]:
        p = ROOT / rel
        rows = _load_jsonl(p)
        if not rows:
            continue
        n0 = len(rows)
        nk = []
        for r in rows:
            fid = (r.get("input") or {}).get("finding_id") if isinstance(r.get("input"), dict) else None
            fid = fid or r.get("finding_id") or r.get("task_id")
            if fid in hydrate_ids or (isinstance(fid, str) and fid.split("::")[-1] in hydrate_ids):
                nk.append(r)
        _write_jsonl(p, nk)
        report[rel] = {"before": n0, "after": len(nk)}

    # normalized preview (V3.1 children follow their parent finding)
    p = ROOT / "derived_v3/normalized_records_preview.jsonl"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        nk = [r for r in rows
              if r.get("finding_id") in hydrate_ids
              or r.get("parent_candidate_id") in hydrate_ids]
        _write_jsonl(p, nk)
        report["derived_v3/normalized_records_preview.jsonl"] = {"before": n0, "after": len(nk)}

    # PoC triage queue
    p = ROOT / "derived_poc_queue/triage_queue.jsonl"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        nk = [r for r in rows if r.get("finding_id") in hydrate_ids]
        _write_jsonl(p, nk)
        report["derived_poc_queue/triage_queue.jsonl"] = {"before": n0, "after": len(nk)}

    # Keep benchmark/v3_manifest.json task counts consistent with the actual
    # (post-purge) family files. Written by this owned builder path, not by
    # hand; the gate owner only syncs the published pins.
    bm_path = ROOT / "benchmark/v3_manifest.json"
    if bm_path.exists():
        bm = json.loads(bm_path.read_text(encoding="utf-8"))
        fam_rows = {
            "R_v3_source_tier_routing": ROOT / "benchmark/v3_R_source_tier_routing.jsonl",
            "S_v3_contest_outcome": ROOT / "benchmark/retired_families/v3_S_contest_outcome.jsonl",
            "T_v31_taxonomy_explicit": ROOT / "benchmark/retired_families/v3_T_taxonomy_explicit.jsonl",
        }
        for fam, path in fam_rows.items():
            if fam in bm.get("tasks", {}):
                bm["tasks"][fam] = sum(1 for l in path.read_text(encoding="utf-8").splitlines()
                                       if l.strip()) if path.exists() else 0
        _write_json(bm_path, bm)

    # keep manifest honest (manifest.json is owned by this track)
    p = ROOT / "derived_v3/manifest.json"
    m = json.loads(p.read_text(encoding="utf-8"))
    m["record_count"] = len(keep)
    m["quarantined_count"] = len(q)
    # recompute record-domain distributions from the kept rows
    import collections
    for key, field in (("admitted_by_decision", "decision"),
                       ("admitted_by_language", "language"),
                       ("admitted_by_ecosystem", "ecosystem"),
                       ("admitted_verification_levels", "verification_level")):
        if key in m:
            m[key] = dict(collections.Counter(r.get(field) for r in keep))
    # candidate-domain distributions come from the ledger after REJECT marking
    ledger = _load_jsonl(ROOT / "derived_v3/candidate_ledger.jsonl")
    for key, field in (("candidate_decisions", "decision"),
                       ("candidate_by_source", "source_id"),
                       ("candidate_by_language", "language"),
                       ("candidate_by_ecosystem", "ecosystem"),
                       ("candidate_verification_levels", "verification_level")):
        if key in m:
            m[key] = dict(collections.Counter(r.get(field) for r in ledger))
    # run-accounting keys must match the post-purge ledgers (the V3 gate
    # recomputes run_accounting from disk and compares every key).
    try:
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import v32_execution as _exec
        accounting = _exec.run_accounting(ROOT, ledger, keep)
        for key, value in accounting["counts"].items():
            if key in m:
                m[key] = value
    except Exception as exc:  # pragma: no cover - reported, never asserted
        report["manifest_run_accounting_recompute_error"] = str(exc)
    _write_json(p, m)


def purge_v22(report: dict) -> None:
    p = ROOT / "derived_v2_2/records.jsonl"
    rows = _load_jsonl(p)
    before = len(rows)
    keep = [r for r in rows if not is_quarantined(r)]
    drop = [r for r in rows if is_quarantined(r)]
    # Reconstruct the set-aside population from the canonical jsonl_ml findings
    # (stable across re-runs, unlike the already-purged derived table).
    src_rows = []
    for lang in ("cairo", "move", "rust", "vyper", "reports"):
        src_rows.extend(_load_jsonl(ROOT / f"jsonl_ml/findings_{lang}.jsonl"))
    q = [{
        "id": r.get("id"), "language": r.get("language"),
        "dataset_version": r.get("dataset_version"),
        "record_type": "quarantine_pointer_v22",
        "_quarantine_reason": (r.get("_hydration") or {}).get("status"),
        "note": "pointer only; no verbatim snippet or patch.diff resolved",
    } for r in src_rows if is_quarantined(r)]
    q.sort(key=lambda r: str(r.get("id")))
    _write_jsonl(ROOT / "derived_v2_2/quarantine.jsonl", q)
    _write_jsonl(p, keep)
    report["derived_v2_2/records.jsonl"] = {"before": before, "after": len(keep),
                                            "quarantined": len(drop)}
    # v2.2 split files are POINTER rows over both v1 (945) and v2.2 (137)
    # records. Only the v2.2-layer pointers for quarantined rows are removed;
    # every v1 pointer is preserved verbatim.
    drop_ids = {r.get("id") for r in q}
    for rel in ["splits_v2_2/train.jsonl", "splits_v2_2/validation.jsonl",
                "splits_v2_2/test.jsonl", "splits_v2_2/quarantine.jsonl"]:
        p2 = ROOT / rel
        rs = _load_jsonl(p2)
        if not rs:
            continue
        n0 = len(rs)
        nk = [r for r in rs
              if r.get("layer") != "v2.2"
              or (r.get("id") not in drop_ids and r.get("record_id") not in drop_ids)]
        _write_jsonl(p2, nk)
        report[rel] = {"before": n0, "after": len(nk)}
    p = ROOT / "derived_v2_2/manifest.json"
    m = json.loads(p.read_text(encoding="utf-8"))
    m["records"] = len(keep)
    import collections
    m["by_language"] = dict(collections.Counter(r.get("language") for r in keep))
    m["quarantined_count"] = len(q)
    _write_json(p, m)


def purge_normalization(report: dict | None = None) -> None:
    """Remove UNHYDRATABLE rows from the V3.1 normalization artifacts.

    ``normalize_v3.py`` regenerates fragments/overlays/readiness from the whole
    candidate ledger, including candidates quarantined by the hydration pass.
    Those artifacts must not reintroduce METADATA_ONLY_STUB /
    PARTIAL_TEXT_NO_CODE rows into a trainable table.  Kept content is always
    verbatim source text; nothing is invented.  Idempotent.
    """
    report = report if report is not None else {}
    qpath = ROOT / "derived_v3/quarantine.jsonl"
    quarantined = {r["finding_id"] for r in _load_jsonl(qpath)}
    if not quarantined:
        return
    D = ROOT / "derived_v3"

    def _inline_strings(obj):
        out = []
        if isinstance(obj, dict):
            for v in obj.values():
                out.extend(_inline_strings(v))
        elif isinstance(obj, list):
            for v in obj[:5]:
                out.extend(_inline_strings(v))
        elif isinstance(obj, str):
            out.append(obj)
        return out

    def _fully_trainable(row: dict) -> bool:
        ss = _inline_strings(row)
        code = any(len(s) >= 50 and any(k in s for k in
                   ("```", "function ", "pragma solidity", "contract ",
                    "import ", "pub fn")) for s in ss)
        prose = any(len(s) >= 100 for s in ss)
        return code and prose

    hydrated_ids = {r["finding_id"] for r in
                    _load_jsonl(D / "records.jsonl")}

    # 1) fragments — keep only rows with verbatim inline code (>=50) AND
    #    technical prose (>=100); everything else is a stub/partial pointer.
    p = D / "normalization_fragments.jsonl"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        keep = [r for r in rows if _fully_trainable(r)]
        dropped = [r for r in rows if not _fully_trainable(r)]
        _write_jsonl(p, keep)
        report["derived_v3/normalization_fragments.jsonl"] = {
            "before": n0, "after": len(keep), "quarantined": len(dropped)}
        _append_dead_quarantine(dropped, "fragment_id", "normalization_fragment", qpath)

    # 2) overlays — pointer-only rows, none carry inline code + prose.
    p = D / "normalization_overlay.jsonl"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        keep = [r for r in rows if _fully_trainable(r)]
        dropped = [r for r in rows if not _fully_trainable(r)]
        _write_jsonl(p, keep)
        report["derived_v3/normalization_overlay.jsonl"] = {
            "before": n0, "after": len(keep), "quarantined": len(dropped)}
        _append_dead_quarantine(dropped, "target_id", "normalization_overlay", qpath)

    # 3) experiment readiness — keep only rows whose parent is a hydrated,
    #    trainable record; the triage queue is built from exactly this set.
    p = D / "experiment_readiness.json"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        keep = [r for r in rows if r.get("parent_candidate_id") in hydrated_ids]
        dropped = [r for r in rows if r.get("parent_candidate_id") not in hydrated_ids]
        _write_jsonl(p, keep)
        report["derived_v3/experiment_readiness.json"] = {
            "before": n0, "after": len(keep), "quarantined": len(dropped)}
        _append_dead_quarantine(dropped, "finding_id", "experiment_readiness", qpath)

    # Keep the normalization reports consistent with the purged tables.
    for rp in (D / "normalization.json", ROOT / "reports/v3/normalization_report.json"):
        if not rp.exists():
            continue
        obj = json.loads(rp.read_text(encoding="utf-8"))
        obj["fragment_count"] = len(_load_jsonl(D / "normalization_fragments.jsonl"))
        obj["overlay_count"] = len(_load_jsonl(D / "normalization_overlay.jsonl"))
        obj["preview_count"] = len(_load_jsonl(D / "normalized_records_preview.jsonl"))
        _write_json(rp, obj)

    # 4) v3_T benchmark: keep only tasks whose source record is a preview row
    preview_ids = {r["finding_id"] for r in
                   _load_jsonl(D / "normalized_records_preview.jsonl")}
    p = ROOT / "benchmark/retired_families/v3_T_taxonomy_explicit.jsonl"
    rows = _load_jsonl(p)
    if rows:
        n0 = len(rows)
        keep, dropped = [], []
        for r in rows:
            (keep if ((r.get("source") or {}).get("record_id")) in preview_ids
             else dropped).append(r)
        _write_jsonl(p, keep)
        report["benchmark/retired_families/v3_T_taxonomy_explicit.jsonl"] = {
            "before": n0, "after": len(keep), "quarantined": len(dropped)}


def _append_dead_quarantine(rows: list, id_key: str, kind: str, qpath: Path) -> None:
    """Append pointer rows for unhydratable artifacts (dedup by id+kind)."""
    if not rows:
        return
    existing = _load_jsonl(qpath)
    seen = {(r.get("finding_id"), r.get("artifact_kind")) for r in existing}
    add = []
    for r in rows:
        ident = r.get(id_key)
        if not ident or (ident, kind) in seen:
            continue
        seen.add((ident, kind))
        add.append({
            "finding_id": ident,
            "artifact_kind": kind,
            "source_id": r.get("source_id"),
            "dataset_version": r.get("dataset_version", "3.0"),
            "record_type": "quarantine_pointer_v3",
            "decision": "REJECT",
            "_quarantine_reason": "UNHYDRATABLE_DEAD_POINTER",
            "note": "pointer only; normalization artifact had no verbatim "
                    "inline code and technical prose",
        })
    if add:
        _write_jsonl(qpath, existing + add)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--ml-only", action="store_true")
    ap.add_argument("--purge-only", action="store_true")
    args = ap.parse_args()

    log: list[str] = ["# v2.2 ML + V3 hydration / quarantine log", "",
                      "Verbatim-only; no fabricated content. Generated by "
                      "`scripts/hydrate_v22_v3.py`.", ""]
    summary: dict = {}
    report: dict = {}

    if not args.purge_only:
        for rel in ([] if args.ml_only else [
                "jsonl_v3/findings.jsonl", "derived_v3/candidate_ledger.jsonl"]):
            p = ROOT / rel
            rows = _load_jsonl(p)
            counts: dict = {}
            for r in rows:
                hydrate_v3_row(r)
                st = r["_hydration"]["status"]
                counts[st] = counts.get(st, 0) + 1
            summary[rel] = {"before": len(rows), "after": len(rows), "status": counts}
            log.append(f"## `{rel}` (provenance ledger — retained in full)")
            log.append(f"- rows: {len(rows)} (unchanged); hydration: {counts}")
            log.append("")
            if not args.check:
                _write_jsonl(p, rows)

        commit_diffs = _load_commit_diffs()
        for lang in ("cairo", "move", "rust", "vyper", "reports"):
            rel = f"jsonl_ml/findings_{lang}.jsonl"
            p = ROOT / rel
            rows = _load_jsonl(p)
            counts: dict = {}
            for r in rows:
                hydrate_ml_row(r, commit_diffs)
                st = r["_hydration"]["status"]
                counts[st] = counts.get(st, 0) + 1
            summary[rel] = {"before": len(rows), "after": len(rows), "status": counts}
            log.append(f"## `{rel}`")
            log.append(f"- rows: {len(rows)} (unchanged); hydration: {counts}")
            log.append("")
            if not args.check:
                _write_jsonl(p, rows)

    if not args.check:
        if not args.ml_only:
            purge_v3(report)
            if not args.purge_only:
                purge_normalization(report)
        purge_v22(report)

    log.append("## Purge (trainable / benchmark tables)")
    for rel in sorted(report):
        log.append(f"- `{rel}`: {report[rel]}")
    log.append("")
    log.append("Rows flagged QUARANTINED_* are moved into `derived_v3/quarantine.jsonl` "
               "and `derived_v2_2/quarantine.jsonl`; they are excluded from trainable "
               "and benchmark tables. No content was invented.")
    if not args.check:
        (ROOT / "reports/_v22_v3_hydration_log.md").write_text(
            "\n".join(log) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"hydration": summary, "purge": report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

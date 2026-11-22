#!/usr/bin/env python3
"""Remove non-FULLY_TRAINABLE rows from the Vbeta + V4 trainable tables.

A row is FULLY_TRAINABLE iff it carries inline code of at least 50 characters
AND technical prose of at least 100 characters, both copied verbatim during the
hydration pass (``scripts/hydrate_vbeta_v4.py``).  Every other row is moved to a
quarantine/rejected log with its original id, the reason
``UNHYDRATABLE_DEAD_POINTER`` and its full original payload so ledger accounting
can be reconstructed.  No content is fabricated.

Owned layers rewritten (all under Vbeta/ or the V4 staging/ledger trees):
  Vbeta/derived_vbeta/{records,negatives,candidate_ledger,duplicates}.jsonl
  Vbeta/benchmark_vbeta/vbeta_{U,V}_*.jsonl
  Vbeta/splits_vbeta/{split.json,quarantine.jsonl}
  Vbeta/derived_vbeta/{manifest.json,quarantine.jsonl}
  Vbeta/benchmark_vbeta/vbeta_manifest.json
  jsonl_v4/findings.jsonl
  derived_v4/{candidate_ledger,admitted_ledger,duplicate_ledger}.jsonl
  derived_v4/{manifest.json,quarantine.jsonl}  (+ the mirror V4/manifest.json)

Pure bookkeeping (rights.jsonl, receipts.jsonl, metadata/errors/protocol,
source registries, jsonl_vbeta/* staging) is deliberately left intact.

    python scripts/purge_untrainable_vbeta_v4.py            # apply
    python scripts/purge_untrainable_vbeta_v4.py --check    # report only

Stdlib only.  LF writes, sorted keys (matches the repository writers).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

CODE_MIN = 50
PROSE_MIN = 100
REASON = "UNHYDRATABLE_DEAD_POINTER"

VB_DERIVED = ROOT / "Vbeta" / "derived_vbeta"
VB_BENCH = ROOT / "Vbeta" / "benchmark_vbeta"
VB_SPLITS = ROOT / "Vbeta" / "splits_vbeta"
V4_FINDINGS = ROOT / "jsonl_v4" / "findings.jsonl"
V4_DERIVED = ROOT / "derived_v4"
V4_LAYER = ROOT / "V4"
CACHE = ROOT / "work" / "hydration_cache"


# ---------------------------------------------------------------------------
# trainability primitives
# ---------------------------------------------------------------------------
def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2)
                    + "\n", encoding="utf-8", newline="\n")


def _snippets(row: dict) -> list[str]:
    cc = row.get("code_context")
    if not isinstance(cc, list):
        return []
    out = []
    for c in cc:
        if isinstance(c, dict):
            out.append(str(c.get("snippet") or c.get("code") or ""))
        else:
            out.append(str(c))
    return out


def code_chars(row: dict) -> int:
    return max((len(s) for s in _snippets(row)), default=0)


def prose_chars(row: dict, fields=("description",)) -> int:
    return max((len(str(row.get(f) or "")) for f in fields), default=0)


def is_trainable(row: dict, prose_fields=("description",)) -> bool:
    return code_chars(row) >= CODE_MIN and prose_chars(row, prose_fields) >= PROSE_MIN


def write_quarantine(path: Path, new_rows: list[dict]) -> list[dict]:
    """Append-only quarantine log: re-running the purge never drops history."""
    existing = read_jsonl(path)
    seen = {(r.get("source_table"), r.get("id")) for r in existing}
    merged = list(existing)
    for r in new_rows:
        key = (r.get("source_table"), r.get("id"))
        if key not in seen:
            merged.append(r)
            seen.add(key)
    write_jsonl(path, merged)
    return merged


def quarantine_row(row: dict, source_table: str, row_id: str,
                   prose_fields=("description",)) -> dict:
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    return {
        "id": row_id,
        "record_id": row_id,
        "reason": REASON,
        "source_table": source_table,
        "code_chars": code_chars(row),
        "prose_chars": prose_chars(row, prose_fields),
        "hydration_status": ev.get("hydration_status"),
        "hydrated_by": row.get("hydrated_by"),
        "dataset_version": row.get("dataset_version"),
        "decision": row.get("decision"),
        "record": row,  # full original payload: enough to rebuild any ledger
    }


# ---------------------------------------------------------------------------
# Vbeta
# ---------------------------------------------------------------------------
def _cache_only_fetch(url: str) -> str | None:
    """Deterministic, offline fetch: only blobs cached by the hydration pass."""
    try:
        from hydrate_vbeta_v4 import CACHE as HYD_CACHE
        cache = HYD_CACHE
    except Exception:
        cache = CACHE
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + ".txt"
    p = cache / key
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None


def hydrate_vbeta_records(records: list[dict]) -> list[dict]:
    """Re-apply the verbatim GIT-blob hydration (idempotent, cache only)."""
    try:
        from hydrate_vbeta_v4 import hydrate_vbeta_record
    except ImportError as exc:  # pragma: no cover - scripts/ is on sys.path
        raise RuntimeError("hydrate_vbeta_v4.py must be importable") from exc
    out = []
    for r in records:
        nr, _stats = hydrate_vbeta_record(dict(r), fetcher=_cache_only_fetch)
        out.append(nr)
    return out


def purge_vbeta(hydrate: bool = False) -> dict:
    rpath = VB_DERIVED / "records.jsonl"
    records = read_jsonl(rpath)
    if hydrate:
        records = hydrate_vbeta_records(records)
        # build_vbeta.py emits benchmark tasks with an empty ``input.code``;
        # re-inline the verbatim snippet exactly as hydrate_vbeta_v4.py does so
        # the trainability test sees the same content as a hydrated rebuild.
        rec_by_id = {r["finding_id"]: r for r in records}
        for name in ("vbeta_U_language_routing.jsonl",
                     "vbeta_V_source_tier_routing.jsonl"):
            p = VB_BENCH / name
            bench_rows = read_jsonl(p)
            for t in bench_rows:
                rec = rec_by_id.get(t.get("finding_id"))
                ctx = (rec or {}).get("code_context") or []
                inp = t.get("input")
                if isinstance(inp, dict) and ctx:
                    inp["code"] = ctx[0]["snippet"][:1000]
                    inp["code_source"] = ctx[0].get("source_url", "")
            write_jsonl(p, bench_rows)
    keep_records = [r for r in records if is_trainable(r)]
    keep_ids = {r["finding_id"] for r in keep_records}

    stats: dict[str, object] = {}

    # ledger: keep only candidates linked to a retained record
    cl_path = VB_DERIVED / "candidate_ledger.jsonl"
    ledger = read_jsonl(cl_path)
    keep_ledger = [r for r in ledger if r.get("candidate_id") in keep_ids]
    purged_ledger = [r for r in ledger if r.get("candidate_id") not in keep_ids]

    # negatives: keep only retained finding ids
    neg_path = VB_DERIVED / "negatives.jsonl"
    negatives = read_jsonl(neg_path)
    keep_neg = [r for r in negatives if r.get("finding_id") in keep_ids]
    purged_neg = [r for r in negatives if r.get("finding_id") not in keep_ids]

    # duplicates + split quarantine: no CORROBORATION_ONLY rows survive the
    # candidate_ledger purge, so these reject-link tables must be emptied too.
    dup_path = VB_DERIVED / "duplicates.jsonl"
    duplicates = read_jsonl(dup_path)
    keep_dup = [r for r in duplicates if r.get("candidate_id") in keep_ids]
    purged_dup = [r for r in duplicates if r.get("candidate_id") not in keep_ids]

    sq_path = VB_SPLITS / "quarantine.jsonl"
    split_quar = read_jsonl(sq_path)
    keep_sq = [r for r in split_quar if r.get("candidate_id") in keep_ids]
    purged_sq = [r for r in split_quar if r.get("candidate_id") not in keep_ids]

    # benchmarks: keep only tasks whose finding is retained and whose inline
    # code is present (0 STUB/PARTIAL rows by construction).
    bench_tasks: dict[str, list[dict]] = {}
    bench_purged: dict[str, list[dict]] = {}
    for name in ("vbeta_U_language_routing.jsonl", "vbeta_V_source_tier_routing.jsonl"):
        rows = read_jsonl(VB_BENCH / name)
        kept, purged = [], []
        for t in rows:
            inp = t.get("input") if isinstance(t.get("input"), dict) else {}
            ok = (t.get("finding_id") in keep_ids
                  and len(str(inp.get("code") or "")) >= CODE_MIN
                  and t.get("answer_key_status") == "labeled")
            (kept if ok else purged).append(t)
        bench_tasks[name] = kept
        bench_purged[name] = purged

    # quarantine log: every purged row, reconstructable
    qlog: list[dict] = []
    for r in records:
        if r["finding_id"] not in keep_ids:
            qlog.append(quarantine_row(r, "Vbeta/derived_vbeta/records.jsonl",
                                       r["finding_id"]))
    for r in purged_ledger:
        qlog.append(quarantine_row(r, "Vbeta/derived_vbeta/candidate_ledger.jsonl",
                                   r["candidate_id"]))
    for r in purged_neg:
        qlog.append(quarantine_row(r, "Vbeta/derived_vbeta/negatives.jsonl",
                                   r["finding_id"]))
    for r in purged_dup:
        qlog.append(quarantine_row(r, "Vbeta/derived_vbeta/duplicates.jsonl",
                                   r["candidate_id"]))
    for r in purged_sq:
        qlog.append(quarantine_row(r, "Vbeta/splits_vbeta/quarantine.jsonl",
                                   r["candidate_id"]))
    for name, rows in bench_purged.items():
        for t in rows:
            qlog.append(quarantine_row(t, f"Vbeta/benchmark_vbeta/{name}",
                                       t.get("task_id") or t.get("finding_id")))

    # split: preserve the pinned source->split assignment; filter members only
    split_path = VB_SPLITS / "split.json"
    split = json.loads(split_path.read_text(encoding="utf-8"))
    split["splits"] = {
        sname: sorted(i for i in ids if i in keep_ids)
        for sname, ids in split.get("splits", {}).items()
    }

    # append-only quarantine log (computed before the manifest pins its size)
    qlen = len(write_quarantine(VB_DERIVED / "quarantine.jsonl", qlog))

    # manifest: recompute count domains from the retained files
    mpath = VB_DERIVED / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    _sources_doc = json.loads(
        (ROOT / "Vbeta" / "sources.json").read_text(encoding="utf-8"))
    _sources = _sources_doc.get("sources", _sources_doc) if isinstance(
        _sources_doc, dict) else _sources_doc
    manifest["source_count"] = len(_sources)
    manifest["candidate_count"] = len(keep_ledger)
    manifest["record_count"] = len(keep_records)
    manifest["candidate_by_source"] = dict(sorted(
        collections.Counter(r["source_id"] for r in keep_ledger).items()))
    manifest["candidate_decisions"] = dict(sorted(
        collections.Counter(r["decision"] for r in keep_ledger).items()))
    manifest["candidate_verification_levels"] = dict(sorted(
        collections.Counter(r["verification_level"] for r in keep_ledger).items()))
    manifest["admitted_by_language"] = dict(sorted(
        collections.Counter(r["language"] for r in keep_records).items()))
    manifest["admitted_by_ecosystem"] = dict(sorted(
        collections.Counter(r["ecosystem"] for r in keep_records).items()))
    manifest["trainable_min_code_chars"] = CODE_MIN
    manifest["trainable_min_prose_chars"] = PROSE_MIN
    manifest["quarantine_rows"] = qlen
    manifest["purge_reason"] = REASON

    # benchmark manifest task counts
    bmpath = VB_BENCH / "vbeta_manifest.json"
    bm = json.loads(bmpath.read_text(encoding="utf-8"))
    for name, rows in bench_tasks.items():
        key = ("vbeta_U_language_routing" if name.startswith("vbeta_U")
               else "vbeta_V_source_tier_routing")
        bm["tasks"][key] = len(rows)
    bm["notes"] = (
        "Benchmarks contain only FULLY_TRAINABLE rows (inline code >= "
        f"{CODE_MIN} chars AND technical prose >= {PROSE_MIN} chars). "
        "Non-trainable/dead-pointer rows were removed to "
        "Vbeta/derived_vbeta/quarantine.jsonl."
    )
    bm["purge_reason"] = REASON

    # write retained tables
    write_jsonl(rpath, keep_records)
    write_jsonl(cl_path, keep_ledger)
    write_jsonl(neg_path, keep_neg)
    write_jsonl(dup_path, keep_dup)
    write_jsonl(sq_path, keep_sq)
    for name, rows in bench_tasks.items():
        write_jsonl(VB_BENCH / name, rows)
    write_json(split_path, split)
    write_json(mpath, manifest)
    write_json(bmpath, bm)

    stats.update({
        "records": {"kept": len(keep_records), "purged": len(records) - len(keep_records)},
        "candidate_ledger": {"kept": len(keep_ledger), "purged": len(purged_ledger)},
        "negatives": {"kept": len(keep_neg), "purged": len(purged_neg)},
        "duplicates": {"kept": len(keep_dup), "purged": len(purged_dup)},
        "split_quarantine": {"kept": len(keep_sq), "purged": len(purged_sq)},
        "benchmark_U": {"kept": len(bench_tasks["vbeta_U_language_routing.jsonl"]),
                        "purged": len(bench_purged["vbeta_U_language_routing.jsonl"])},
        "benchmark_V": {"kept": len(bench_tasks["vbeta_V_source_tier_routing.jsonl"]),
                        "purged": len(bench_purged["vbeta_V_source_tier_routing.jsonl"])},
        "quarantine_rows": qlen,
        "manifest_counts": (manifest["candidate_count"], manifest["record_count"],
                             manifest["source_count"]),
    })
    return stats


# ---------------------------------------------------------------------------
# V4
# ---------------------------------------------------------------------------
def purge_v4() -> dict:
    prose_fields = ("description", "root_cause", "impact", "raw_body_excerpt")

    findings = read_jsonl(V4_FINDINGS)
    keep_findings = [r for r in findings if is_trainable(r, prose_fields)]
    keep_ids = {r["candidate_id"] for r in keep_findings}

    cl_path = V4_DERIVED / "candidate_ledger.jsonl"
    ledger = read_jsonl(cl_path)
    keep_ledger = [r for r in ledger if r.get("candidate_id") in keep_ids]
    purged_ledger = [r for r in ledger if r.get("candidate_id") not in keep_ids]

    al_path = V4_DERIVED / "admitted_ledger.jsonl"
    admitted = read_jsonl(al_path)
    keep_admitted = [r for r in admitted if r.get("candidate_id") in keep_ids]
    purged_admitted = [r for r in admitted if r.get("candidate_id") not in keep_ids]

    dl_path = V4_DERIVED / "duplicate_ledger.jsonl"
    duplicates = read_jsonl(dl_path)
    keep_duplicates = [r for r in duplicates if r.get("candidate_id") in keep_ids]
    purged_duplicates = [r for r in duplicates if r.get("candidate_id") not in keep_ids]

    qlog: list[dict] = []
    for r in findings:
        if r["candidate_id"] not in keep_ids:
            qlog.append(quarantine_row(r, "jsonl_v4/findings.jsonl",
                                       r["candidate_id"], prose_fields))
    for r in purged_ledger:
        qlog.append(quarantine_row(r, "derived_v4/candidate_ledger.jsonl",
                                   r["candidate_id"], prose_fields))
    for r in purged_admitted:
        qlog.append(quarantine_row(r, "derived_v4/admitted_ledger.jsonl",
                                   r["candidate_id"], prose_fields))
    for r in purged_duplicates:
        qlog.append(quarantine_row(r, "derived_v4/duplicate_ledger.jsonl",
                                   r["candidate_id"], prose_fields))

    # rebuild both V4 manifests through register_v4.build_manifest so the
    # offline --manifest-only rebuild reproduces them byte-for-byte.
    import register_v4 as R
    old_m = json.loads((V4_DERIVED / "manifest.json").read_text(encoding="utf-8"))
    staged = old_m["source_candidates_staged"]
    manifest = R.build_manifest(keep_findings, keep_admitted, [], keep_duplicates,
                                keep_ledger, staged)
    mtext = R.manifest_serialise(manifest)

    write_jsonl(V4_FINDINGS, keep_findings)
    write_jsonl(cl_path, keep_ledger)
    write_jsonl(al_path, keep_admitted)
    write_jsonl(dl_path, keep_duplicates)
    qlen = len(write_quarantine(V4_DERIVED / "quarantine.jsonl", qlog))
    for target in (V4_DERIVED / "manifest.json", V4_LAYER / "manifest.json"):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(mtext, encoding="utf-8", newline="\n")

    return {
        "findings": {"kept": len(keep_findings), "purged": len(findings) - len(keep_findings)},
        "candidate_ledger": {"kept": len(keep_ledger), "purged": len(purged_ledger)},
        "admitted_ledger": {"kept": len(keep_admitted), "purged": len(purged_admitted)},
        "duplicate_ledger": {"kept": len(keep_duplicates), "purged": len(purged_duplicates)},
        "quarantine_rows": qlen,
        "manifest_counts": (manifest["candidates"], manifest["admitted"],
                             manifest["duplicates"], manifest["quarantined"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    args = ap.parse_args()
    # --check is deliberately a live dry-run: it computes trainability without
    # writing, by copying the files into a temp mirror would be overkill. Report
    # the current on-disk trainability statistics instead.
    if args.check:
        recs = read_jsonl(VB_DERIVED / "records.jsonl")
        f4 = read_jsonl(V4_FINDINGS)
        print(json.dumps({
            "vbeta_records": {"rows": len(recs),
                              "trainable": sum(1 for r in recs if is_trainable(r))},
            "v4_findings": {"rows": len(f4),
                            "trainable": sum(1 for r in f4 if is_trainable(
                                r, ("description", "root_cause", "impact",
                                    "raw_body_excerpt")))},
            "reason": REASON,
            "note": "apply mode performs the purge and writes quarantine logs",
        }, indent=2, sort_keys=True))
        return 0

    stats = {"vbeta": purge_vbeta(hydrate=False), "v4": purge_v4()}
    print(json.dumps({"generated_by": "scripts/purge_untrainable_vbeta_v4.py",
                      "reason": REASON, "no_fabrication": True, "stats": stats},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

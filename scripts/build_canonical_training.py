#!/usr/bin/env python3
"""Canonical training views across layers (additive; sources stay read-only).

Raw JSONL layers disagree on field names and label casing (v3 title-cases
severity, v1 nests it under ``finding.severity``, vbeta splits observed vs
normalized), rows are deeply nested, and large harvest layers carry mostly
unverified rows. Training directly on the raw union therefore mixes label
vocabularies, supervision strengths and row shapes.

This script builds ONE flat, compact, chunked training surface instead:

  training/canonical/severity.<split>.part-NNN.jsonl
  training/canonical/language.<split>.part-NNN.jsonl
  training/canonical/detection.<split>.part-NNN.jsonl
  training/canonical/manifest.json

Fixes applied here (never by rewriting a source layer):

  * severity normalized to lowercase closed vocab
    (critical/high/medium/low/informational); anything else is excluded
    from the severity task, never coerced.
  * language normalized to lowercase; ``unknown`` excluded from the
    language task.
  * detection admits ONLY verified rows: v1 judged+confirmed findings as
    positives, v1 rejected/disputed and v2.2 negative-controls as
    negatives. Unverified harvest rows (v3/v4/vbeta IMPORT*) are never
    detection positives.
  * every row is flat with a budgeted ``input_text`` (<=2000 chars) plus a
    code *pointer* (file/commit/lines/url), never a nested blob.
  * per-row inverse-frequency ``weight`` per (task, split) counters class
    and language imbalance.
  * files are chunked at 5,000 rows so no single file is unwieldy; the
    manifest maps every chunk and counts every exclusion by reason.
  * existing official splits are reused (v1 splits_v2, v2.2 splits_v2_2,
    v3 benchmark_split, vbeta by-source assignment). V4 has no official
    split, so rows carry a deterministic canonical-training-only
    by-source assignment, clearly marked as such.

SPLIT SELECTION -- what the model is allowed to train on
----------------------------------------------------------
The split assignments above are the SAME assignments the benchmark families
are built from (``splits_v2``, ``splits_v2_2``, ``splits_v3`` and the vbeta
by-source map). Their validation and test partitions are therefore
*evaluation* partitions of the benchmark, and shipping them inside the
training corpus ships the evaluation answers with the inputs.

So the model-visible corpus ships the TRAIN partition only, and two further
rules apply:

  * a record that ANY benchmark family holds out is excluded, whatever the
    layer's own split label says -- the v3 layer's ``benchmark_split`` and
    the benchmark's ``splits_v3`` disagree for 878 records, so a row can sit
    in a ``train`` shard and still be a benchmark test row;
  * nothing is deleted. Every excluded row is written, with its provenance
    intact, to ``benchmark/independent/canonical_holdout/``, which is
    outside ``training/`` and therefore outside a corpus consumer's reach.
    That directory is excluded from the training corpus manifest.

    python scripts/build_canonical_training.py
    python scripts/build_canonical_training.py --check   # compute, write nothing
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "training" / "canonical"
# The held-out partitions are evaluation material, not training material.
# They live outside training/ so that a consumer globbing the training
# directory cannot reach them.
HELDOUT_OUT = ROOT / "benchmark" / "independent" / "canonical_holdout"

# The model-visible corpus ships the train partition only. See the module
# docstring: these are the evaluation partitions of the benchmark families.
MODEL_VISIBLE_SPLITS = ("train",)

# One definition of "protected evaluation record", shared with the leakage
# report and the gate, so a builder cannot exclude a record the gate still
# considers protected.
_leak_spec = importlib.util.spec_from_file_location(
    "_leak", ROOT / "scripts" / "build_eval_leakage_report.py")
_leak = importlib.util.module_from_spec(_leak_spec)
_leak_spec.loader.exec_module(_leak)


SEVERITY_VOCAB = ("critical", "high", "medium", "low", "informational")
_SEV_WORD = re.compile(
    r"\b(critical|high|medium|low|informational|info)\b", re.I)
TASKS = ("severity", "language", "detection")
SPLITS = ("train", "validation", "test")
CHUNK_ROWS = 5000
INPUT_BUDGET = 2000
SNIPPET_BUDGET = 800

# V4 has no official split; deterministic canonical-training-only
# by-source assignment (sorted source_ids round-robin). Documented in the
# manifest so it can never be mistaken for an official eval split.
V4_SPLIT_SEED = ("train", "validation", "test")


def norm_severity(raw) -> str | None:
    if raw is None:
        return None
    m = _SEV_WORD.search(str(raw))
    if not m:
        return None
    word = m.group(1).lower()
    return "informational" if word == "info" else word


def norm_language(raw) -> str | None:
    if raw is None:
        return None
    lang = str(raw).strip().lower()
    if not lang or lang in ("unknown", "none"):
        return None
    return lang


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def budget(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " [truncated]"


def build_input(title: str, body: str, code_file: str | None,
                line_start, line_end, snippet: str | None) -> str:
    parts = []
    if title:
        parts.append("TITLE: " + budget(title, 300))
    if body:
        parts.append("SUMMARY: " + budget(body, 900))
    if snippet:
        loc = code_file or "unknown file"
        if line_start is not None and line_end is not None:
            loc += f" (lines {line_start}-{line_end})"
        parts.append("CODE " + loc + ": " + budget(snippet, SNIPPET_BUDGET))
    return budget("\n\n".join(parts), INPUT_BUDGET)


def code_ref(file, commit, line_start, line_end, url) -> dict | None:
    if not any([file, commit, url]):
        return None
    return {"file": file, "commit_sha": commit,
            "line_start": line_start, "line_end": line_end, "url": url}


class Builder:
    def __init__(self):
        self.rows: list[dict] = []
        self.excluded: collections.Counter = collections.Counter()

    def add(self, task: str, split: str, layer: str, canonical_id: str,
            supervision: str, input_text: str, label,
            verification_level: str | None, provenance: dict,
            code: dict | None = None):
        if split not in SPLITS:
            self.excluded[f"{layer}:unknown_split"] += 1
            return
        if not input_text:
            self.excluded[f"{layer}:empty_input"] += 1
            return
        self.rows.append({
            "example_id": f"{layer}:{canonical_id}:{task}",
            "task": task,
            "split": split,
            "layer": layer,
            "canonical_id": canonical_id,
            "supervision": supervision,
            "input_text": input_text,
            "code_ref": code,
            "label": label,
            "verification_level": verification_level or "unknown",
            "weight": 1.0,
            "provenance": provenance,
        })

    def apply_weights(self):
        groups: dict[tuple, list[dict]] = collections.defaultdict(list)
        for r in self.rows:
            groups[(r["task"], r["split"])].append(r)
        for (task, split), members in groups.items():
            counts = collections.Counter(
                json.dumps(r["label"], sort_keys=True) for r in members)
            n, k = len(members), len(counts)
            for r in members:
                key = json.dumps(r["label"], sort_keys=True)
                r["weight"] = round(n / (k * counts[key]), 4)

    def chunks(self):
        """Chunk the rows per (task, split).

        The model-visible corpus and the held-out shards are chunked
        separately by `chunk_rows`, so this split-level view is only used
        to report what was built.
        """
        self.rows.sort(key=lambda r: (r["task"], r["split"],
                                      r["canonical_id"]))
        out: dict[tuple, list[list[dict]]] = {}
        for (task, split), members in _groupby(
                self.rows, lambda r: (r["task"], r["split"])).items():
            out[(task, split)] = [members[i:i + CHUNK_ROWS]
                                  for i in range(0, len(members), CHUNK_ROWS)]
        return out


def partition(rows: list[dict], protected: set[str]) -> tuple[list, list, list]:
    """Split the built rows into (model-visible, held-out, reasons).

    A row is held out of the model-visible corpus when its own split is not
    a model-visible split, OR when its record is one a benchmark family
    holds out -- the v3 layer's ``benchmark_split`` and the benchmark's
    ``splits_v3`` disagree, so a row can sit in a ``train`` shard and still
    be a benchmark test row.
    """
    visible, held, reasons = [], [], []
    for r in rows:
        rid = r.get("canonical_id")
        protected_row = rid in protected
        split_row = r.get("split") not in MODEL_VISIBLE_SPLITS
        if not protected_row and not split_row:
            visible.append(r)
            reasons.append("model_visible")
            continue
        held.append(r)
        if protected_row and split_row:
            reasons.append("held_out_split_and_protected_record")
        elif protected_row:
            reasons.append("protected_record")
        else:
            reasons.append("held_out_split")
    return visible, held, reasons


def _groupby(rows, key):
    groups: dict = collections.defaultdict(list)
    for r in rows:
        groups[key(r)].append(r)
    return dict(sorted(groups.items()))


# ---------------------------------------------------------------- v1 ----
def harvest_v1(b: Builder):
    split_of: dict[str, str] = {}
    for split in SPLITS:
        for r in read_jsonl(ROOT / "splits_v2" / f"{split}.jsonl"):
            fid = (r.get("finding") or {}).get("id") or r.get("id")
            if fid:
                split_of.setdefault(str(fid), split)
    for r in read_jsonl(ROOT / "derived" / "records.jsonl"):
        cid = str(r.get("id") or "")
        split = split_of.get(cid)
        f = r.get("finding") or {}
        status = f.get("status")
        record_class = f.get("record_class")
        # severity task: only closed-vocab severities (qa/unknown excluded)
        sev = norm_severity(f.get("severity"))
        if sev is not None:
            ctx = (r.get("code_context") or [{}])[0]
            b.add("severity", split, "v1", cid, "observed",
                  build_input(f.get("title"), "",
                              ctx.get("file"), ctx.get("line_start"),
                              ctx.get("line_end"), ctx.get("snippet")),
                  sev, None,
                  {"source_id": (r.get("source") or {}).get("organization"),
                   "record_ref": cid},
                  code_ref(ctx.get("file"), ctx.get("commit_sha"),
                           ctx.get("line_start"), ctx.get("line_end"),
                           ctx.get("source_url")))
        elif split in SPLITS:
            b.excluded["v1:severity_unknown"] += 1
        # detection task: verified positives and negatives only
        if record_class == "judged" and status == "confirmed":
            ctx = (r.get("code_context") or [{}])[0]
            b.add("detection", split, "v1", cid, "verified",
                  build_input(f.get("title"), "",
                              ctx.get("file"), ctx.get("line_start"),
                              ctx.get("line_end"), ctx.get("snippet")),
                  True, None,
                  {"source_id": (r.get("source") or {}).get("organization"),
                   "record_ref": cid},
                  code_ref(ctx.get("file"), ctx.get("commit_sha"),
                           ctx.get("line_start"), ctx.get("line_end"),
                           ctx.get("source_url")))
        elif status in ("rejected", "disputed"):
            b.add("detection", split, "v1", cid, "verified",
                  build_input(f.get("title"), "", None, None, None, None),
                  False, None,
                  {"source_id": (r.get("source") or {}).get("organization"),
                   "record_ref": cid})
        elif split in SPLITS:
            b.excluded["v1:detection_unqualified"] += 1


# --------------------------------------------------------------- v2.2 ----
def harvest_v22(b: Builder):
    split_of: dict[str, str] = {}
    for split in SPLITS:
        for r in read_jsonl(ROOT / "splits_v2_2" / f"{split}.jsonl"):
            if r.get("id"):
                split_of.setdefault(str(r["id"]), split)
    for r in read_jsonl(ROOT / "derived_v2_2" / "records.jsonl"):
        cid = str(r.get("id") or "")
        split = split_of.get(cid)
        f = r.get("finding") or {}
        sev = norm_severity(f.get("severity"))
        lang = norm_language(r.get("language"))
        ctx = (r.get("code_context_view") or [{}])[0] \
            if isinstance(r.get("code_context_view"), list) else {}
        summary = f.get("summary") or ""
        if sev is not None:
            b.add("severity", split, "v2.2", cid, "observed",
                  build_input(f.get("title"), summary, ctx.get("file"),
                              ctx.get("line_start"), ctx.get("line_end"),
                              ctx.get("snippet")),
                  sev, None,
                  {"source_id": None, "record_ref": cid},
                  code_ref(ctx.get("file"), ctx.get("commit_sha"),
                           ctx.get("line_start"), ctx.get("line_end"),
                           ctx.get("source_url")))
        elif split in SPLITS:
            b.excluded["v2.2:severity_unknown"] += 1
        if lang is not None:
            b.add("language", split, "v2.2", cid, "observed",
                  build_input(f.get("title"), summary, ctx.get("file"),
                              ctx.get("line_start"), ctx.get("line_end"),
                              ctx.get("snippet")),
                  lang, None,
                  {"source_id": None, "record_ref": cid},
                  code_ref(ctx.get("file"), ctx.get("commit_sha"),
                           ctx.get("line_start"), ctx.get("line_end"),
                           ctx.get("source_url")))
        elif split in SPLITS:
            b.excluded["v2.2:language_unknown"] += 1
        status = f.get("status")
        record_class = f.get("record_class")
        if status in ("confirmed", "experimentally_verified"):
            b.add("detection", split, "v2.2", cid, "verified",
                  build_input(f.get("title"), summary, ctx.get("file"),
                              ctx.get("line_start"), ctx.get("line_end"),
                              ctx.get("snippet")),
                  True, None,
                  {"source_id": None, "record_ref": cid},
                  code_ref(ctx.get("file"), ctx.get("commit_sha"),
                           ctx.get("line_start"), ctx.get("line_end"),
                           ctx.get("source_url")))
        elif record_class in ("negative_control", "out_of_scope",
                              "overstated_by_the_report"):
            b.add("detection", split, "v2.2", cid, "verified",
                  build_input(f.get("title"), summary, None, None, None,
                              None),
                  False, None,
                  {"source_id": None, "record_ref": cid})
        elif split in SPLITS:
            b.excluded["v2.2:detection_unqualified"] += 1


# ---------------------------------------------------------------- v3 ----
def harvest_v3(b: Builder):
    for r in read_jsonl(ROOT / "derived_v3" / "records.jsonl"):
        cid = str(r.get("finding_id") or "")
        split = r.get("benchmark_split")
        sev = norm_severity(r.get("severity"))
        lang = norm_language(r.get("language"))
        body = r.get("description") or ""
        inp = build_input(r.get("title"), body, r.get("affected_file"),
                          None, None, None)
        if sev is not None:
            b.add("severity", split, "v3.0", cid, "observed", inp, sev,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid},
                  code_ref(r.get("affected_file"), r.get("vulnerable_commit"),
                           None, None, None))
        elif split in SPLITS:
            b.excluded["v3.0:severity_unknown"] += 1
        if lang is not None:
            b.add("language", split, "v3.0", cid, "observed", inp, lang,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid},
                  code_ref(r.get("affected_file"), r.get("vulnerable_commit"),
                           None, None, None))
        elif split in SPLITS:
            b.excluded["v3.0:language_unknown"] += 1
        # IMPORT rows are unverified: never detection positives. Negatives
        # carry an explicit negative class.
        if r.get("decision") == "IMPORT_AS_NEGATIVE":
            b.add("detection", split, "v3.0", cid, "verified", inp, False,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid},
                  code_ref(r.get("affected_file"), r.get("vulnerable_commit"),
                           None, None, None))
        elif split in SPLITS:
            b.excluded["v3.0:detection_unqualified"] += 1


# ---------------------------------------------------------------- v4 ----
def harvest_v4(b: Builder):
    rows = read_jsonl(ROOT / "jsonl_v4" / "findings.jsonl")
    per_source: dict[str, int] = collections.Counter(
        str(r.get("source_id")) for r in rows)
    # Largest source trains (a test-heavy layer teaches nothing); ties
    # break alphabetically so the assignment stays deterministic.
    ordered = sorted(per_source, key=lambda s: (-per_source[s], s))
    assign = {sid: V4_SPLIT_SEED[i % 3] for i, sid in enumerate(ordered)}
    for r in rows:
        cid = str(r.get("candidate_id") or "")
        split = assign.get(str(r.get("source_id")))
        sev = norm_severity(r.get("severity_normalized")
                            or r.get("original_severity"))
        lang = norm_language(r.get("language"))
        body = r.get("raw_body_excerpt") or ""
        locs = r.get("affected_location") or []
        loc = locs[0] if locs else None
        inp = build_input(r.get("title") or r.get("finding_title"), body,
                          loc, None, None, r.get("affected_code_excerpt"))
        if sev is not None:
            b.add("severity", split, "v4", cid, "observed", inp, sev,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid},
                  code_ref(loc, None, None, None, r.get("source_pointer")))
        elif split in SPLITS:
            b.excluded["v4:severity_unknown"] += 1
        if lang is not None:
            b.add("language", split, "v4", cid, "observed", inp, lang,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid},
                  code_ref(loc, None, None, None, r.get("source_pointer")))
        elif split in SPLITS:
            b.excluded["v4:language_unknown"] += 1
        if split in SPLITS:
            # L0-only staging layer: no verified positives/negatives.
            b.excluded["v4:detection_unqualified"] += 1
    return assign


# -------------------------------------------------------------- vbeta ----
def harvest_vbeta(b: Builder):
    split_doc = json.loads(
        (ROOT / "Vbeta" / "splits_vbeta" / "split.json").read_text(
            encoding="utf-8"))
    assign = split_doc.get("assignment", {})
    for r in read_jsonl(ROOT / "Vbeta" / "derived_vbeta" / "records.jsonl"):
        cid = str(r.get("finding_id") or "")
        split = assign.get(str(r.get("source_id")))
        sev = norm_severity(r.get("severity_normalized"))
        lang = norm_language(r.get("language"))
        inp = build_input(r.get("title"), r.get("description") or "",
                          None, None, None, None)
        if sev is not None:
            b.add("severity", split, "vbeta", cid, "observed", inp, sev,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid})
        elif split in SPLITS:
            b.excluded["vbeta:severity_unknown"] += 1
        if lang is not None:
            b.add("language", split, "vbeta", cid, "observed", inp, lang,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid})
        elif split in SPLITS:
            b.excluded["vbeta:language_unknown"] += 1
        if r.get("decision") == "IMPORT_AS_NEGATIVE":
            b.add("detection", split, "vbeta", cid, "verified", inp, False,
                  r.get("verification_level"),
                  {"source_id": r.get("source_id"), "record_ref": cid})
        elif split in SPLITS:
            b.excluded["vbeta:detection_unqualified"] += 1


def write_chunked(chunks: dict, outdir: Path, rel_prefix: str) -> list[dict]:
    outdir.mkdir(parents=True, exist_ok=True)
    for old in sorted(outdir.glob("*.jsonl")):
        old.unlink()
    files = []
    for (task, split), parts in chunks.items():
        for i, part in enumerate(parts):
            name = f"{task}.{split}.part-{i:03d}.jsonl"
            path = outdir / name
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                for r in part:
                    fh.write(json.dumps(r, sort_keys=True) + "\n")
            h = hashlib.sha256(path.read_bytes()).hexdigest()
            files.append({"path": f"{rel_prefix}/{name}", "task": task,
                          "split": split, "part": i, "rows": len(part),
                          "sha256": h})
    return sorted(files, key=lambda f: f["path"])


def chunk_rows(rows: list[dict], split_name: str) -> dict:
    """Chunk a flat row list into {task: [parts]} for one output stream."""
    rows = sorted(rows, key=lambda r: (r["task"], r["canonical_id"]))
    out: dict[tuple, list[list[dict]]] = {}
    for (task, _), members in _groupby(
            rows, lambda r: (r["task"], r["split"])).items():
        out[(task, split_name)] = [members[i:i + CHUNK_ROWS]
                                   for i in range(0, len(members), CHUNK_ROWS)]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="compute everything, write nothing")
    args = ap.parse_args()

    b = Builder()
    harvest_v1(b)
    harvest_v22(b)
    harvest_v3(b)
    v4_assign = harvest_v4(b)
    harvest_vbeta(b)
    b.apply_weights()

    protected = _leak.protected_identifiers()
    visible, held, reasons = partition(b.rows, protected)
    reason_counts = collections.Counter(reasons)

    chunks = chunk_rows(visible, "train")
    held_chunks = chunk_rows(held, "heldout")

    counts: dict[str, dict] = {}
    for (task, split), parts in chunks.items():
        labels = collections.Counter()
        for part in parts:
            for r in part:
                labels[json.dumps(r["label"], sort_keys=True)] += 1
        counts.setdefault(task, {})[split] = {
            json.loads(k): v for k, v in sorted(labels.items())}
    total = sum(len(p) for parts in chunks.values() for p in parts)

    manifest = {
        "generated_by": "scripts/build_canonical_training.py",
        "dataset_version": "canonical-1.0",
        "tasks": list(TASKS),
        "severity_vocab": list(SEVERITY_VOCAB),
        "input_budget_chars": INPUT_BUDGET,
        "chunk_rows": CHUNK_ROWS,
        "split_policy": (
            "official splits reused (v1 splits_v2, v2.2 splits_v2_2, v3 "
            "benchmark_split, vbeta by-source assignment); V4 uses a "
            "deterministic canonical-training-only by-source assignment. "
            "THE MODEL-VISIBLE CORPUS SHIPS THE TRAIN PARTITION ONLY: the "
            "validation and test partitions of these same assignments are "
            "the evaluation partitions of the benchmark families, so "
            "shipping them inside the training corpus would ship the "
            "evaluation answers with the inputs."),
        "model_visible_splits": list(MODEL_VISIBLE_SPLITS),
        "protected_record_exclusion": {
            "rule": ("a record that ANY benchmark family holds out (split "
                     "test or validation) is excluded from the model-visible "
                     "corpus, whatever this layer's own split label says; "
                     "the v3 layer's benchmark_split and the benchmark's "
                     "splits_v3 disagree, so a row can sit in a train shard "
                     "and still be a benchmark test row"),
            "protected_identifiers": len(protected),
            "source": ("scripts/build_eval_leakage_report.py::"
                       "protected_identifiers"),
            "rows_excluded_for_this_reason": reason_counts[
                "protected_record"] + reason_counts[
                    "held_out_split_and_protected_record"],
        },
        "held_out_partitions": {
            "excluded_rows": len(held),
            "reasons": dict(sorted(reason_counts.items())),
            "written_to": "benchmark/independent/canonical_holdout/",
            "model_visible": False,
            "note": ("nothing is deleted: every excluded row is written "
                     "there with its provenance intact. The directory is "
                     "outside training/, so a consumer globbing the training "
                     "directory cannot reach it, and it is not listed in "
                     "this manifest"),
        },
        "v4_canonical_split_assignment": v4_assign,
        "filters": {
            "severity": "closed-vocab only; qa/unknown excluded, never coerced",
            "language": "known languages only; unknown excluded",
            "detection": ("verified only: v1 judged+confirmed positives, "
                          "v1 rejected/disputed and v2.2 negative-control "
                          "negatives, v3/vbeta IMPORT_AS_NEGATIVE negatives; "
                          "unverified harvest rows never positives"),
        },
        "example_count": total,
        "counts": counts,
        "exclusions": dict(sorted(b.excluded.items())),
    }

    held_counts: dict[str, dict] = {}
    for (task, _), parts in held_chunks.items():
        by_split = collections.Counter()
        for part in parts:
            for r in part:
                by_split[r["split"]] += 1
        held_counts[task] = dict(sorted(by_split.items()))

    if args.check:
        print(f"canonical-training: {total} model-visible examples, "
              f"{sum(len(p) for p in chunks.values())} chunks")
        for task in TASKS:
            for split in SPLITS:
                n = sum(len(p) for p in
                        chunks.get((task, split), []))
                print(f"  {task}.{split}: {n}")
        print(f"  exclusions: {sum(b.excluded.values())}")
        print(f"  held out of the model-visible corpus: {len(held)} "
              f"-> benchmark/independent/canonical_holdout/")
        print(f"  protected identifiers: {len(protected)}")
        return 0

    files = write_chunked(chunks, OUT, "training/canonical")
    manifest["files"] = files
    with open(OUT / "manifest.json", "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    held_files = write_chunked(held_chunks, HELDOUT_OUT,
                                "benchmark/independent/canonical_holdout")
    held_manifest = {
        "generated_by": "scripts/build_canonical_training.py",
        "MODEL_VISIBLE": False,
        "warning": (
            "NOT MODEL-VISIBLE. These rows are the held-out partitions of "
            "the benchmark families expressed in the canonical training "
            "schema. They carry the labels the benchmark is scored on. They "
            "live outside training/ so that a corpus consumer globbing the "
            "training directory cannot reach them, and they are NOT listed "
            "in training/canonical/manifest.json. Do not train on them."),
        "excluded_rows": len(held),
        "reasons": dict(sorted(reason_counts.items())),
        "counts_by_task_and_layer_split": held_counts,
        "protected_identifiers": len(protected),
        "source_of_truth": ("scripts/build_canonical_training.py; the same "
                            "split selection the model-visible corpus uses"),
        "files": held_files,
    }
    with open(HELDOUT_OUT / "manifest.json", "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(held_manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"wrote {OUT} ({total} examples, {len(files)} chunks)")
    print(f"wrote {HELDOUT_OUT} ({len(held)} held-out rows, "
          f"{len(held_files)} chunks; NOT model-visible)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

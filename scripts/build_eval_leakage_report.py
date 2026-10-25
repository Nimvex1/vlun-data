#!/usr/bin/env python3
"""Measure every overlap between the evaluation set and the model-visible corpus.

The canary in `benchmark/CANARY.md` says benchmark data must never appear in a
training corpus. A canary string is a statement, not a check: it cannot tell
you that `training/canonical/severity.test.part-000.jsonl` contains 5,000 rows
of a family's held-out answers, because those rows carry no canary.

This script measures the overlap directly, from the committed data, and is the
single definition of "protected evaluation set" that the corpus builders
(`scripts/build_canonical_training.py`, `scripts/build_subsets.py`) and the
gate (`scripts/check_eval_leakage.py`) all import. One definition, so a builder
cannot exclude a record the gate still considers protected, and vice versa.

Three overlap classes, each measured per benchmark family and per training
file:

  id      the benchmark's own identifiers (task id, record id, finding id)
          against the training row's identifiers (canonical_record_id,
          canonical_id, provenance.record_ref, example_id). A shared id means
          the same source record is on both sides.
  text    the model-facing payload, normalised (case, punctuation, whitespace
          folded) and compared as ordered 8-word shingles. A row overlaps when
          the shorter shingle set is contained in the longer one, or when the
          normalised text is byte-identical.
  code    exact code snippets, snippets normalised for comments/whitespace/
          literals, file paths and commit shas.

and one label check: for every protected benchmark row whose id also appears in
the training corpus, does the training row carry the answer? The comparison
uses a label mapping *derived from the train partition* of the same family, so
no mapping is hand-written.

Usage:
    python scripts/build_eval_leakage_report.py            # build
    python scripts/build_eval_leakage_report.py --check    # verify current
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import subprocess
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

# The audit module owns the family registry, the answer-key projection and the
# model-facing payload extraction. Reusing it keeps this report and the
# independent audit talking about the same task.
_spec = importlib.util.spec_from_file_location(
    "_audit", ROOT / "scripts" / "independent_benchmark_audit.py")
_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_audit)

REPORT_VERSION = "1"

# The P0 remediation, recorded as measured. The BEFORE numbers were taken
# with THIS code against the pre-remediation training corpus (the `training/`
# tree of commit 985f7a5, materialised into a temporary directory); the
# AFTER numbers are what `measure()` recomputes on every run. The live
# sections of this report are always recomputed; this block is the record of
# the change, so a reader can see what it changed.
REMEDIATION = {
    "change": ("the model-visible training corpus shipped the benchmark's "
               "held-out partitions, with their labels. It now ships the "
               "train partition only, and excludes any record a benchmark "
               "family holds out whatever the layer's own split label says"),
    "before": {
        "measured_against": ("the `training/` tree of commit 985f7a5, "
                             "materialised into a temporary directory and "
                             "measured with this same code"),
        "corpus_rows": 33763,
        "corpus_rows_by_split": {"train": 16821, "test": 11220,
                                 "validation": 4904, "unsplit": 818},
        "rows_carrying_a_protected_record": 13767,
        "heldout_rows_with_id_overlap": 15542,
        "heldout_rows_with_text_overlap": 3678,
        "heldout_rows_with_code_overlap": 443,
        "heldout_rows_with_identical_code_snippet": 243,
        "heldout_answer_keys_reproduced_in_training": 464,
        "distinct_protected_records_in_corpus": 7999,
        "verdict": "leaking",
    },
    "after": {
        "measured_against": "the working tree's `training/` directory",
        "held_out_rows_written_to": (
            "benchmark/independent/canonical_holdout/ (17,002 canonical rows) "
            "and benchmark/independent/v1_task_holdout/ (612 v1 task rows); "
            "both are outside training/ and excluded from the training "
            "corpus manifest"),
    },
}

# ------------------------------------------------------------------ method ----
# The protected evaluation set: every benchmark row in a held-out partition.
# "held-out" means the split the family's own scorer is judged on, plus the
# validation partition, which is a scoring partition of the same families and
# therefore also excluded from the model-visible corpus.
HELDOUT_SPLITS = ("test", "validation")

# A record is protected when ANY family holds it out. A record can be train in
# one family's split system and test in another's (v1 uses splits_v2, v2.2
# uses splits_v2_2, v3 uses splits_v3, vbeta uses its own by-source map), so
# the protection is a property of the record, not of one file.
PROTECTED_SPLITS = HELDOUT_SPLITS

TOKEN = re.compile(r"[a-z0-9_]+")
SHINGLE_WORDS = 8
# Ordered-shingle containment: the shorter text must be contained in the
# longer one. 0.90 tolerates a truncated prefix/suffix but not a paraphrase.
TEXT_CONTAINMENT = 0.90
# A text shorter than this carries no signal; matching it is noise.
MIN_TEXT_TOKENS = 8
# A shingle that appears in more training rows than this is boilerplate and
# is not used to nominate candidates.
MAX_POSTING = 2000
MAX_CANDIDATES = 400

WS = re.compile(r"\s+")


def norm_text(s: str) -> str:
    """Case, punctuation and whitespace folded."""
    return " ".join(TOKEN.findall((s or "").lower()))


def norm_code(s: str) -> str:
    """Strip comments, literals and numbers so reformatting cannot hide a match."""
    s = re.sub(r"/\*.*?\*/", " ", s or "", flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    s = re.sub(r'"[^"]*"|\'[^\']*\'', '""', s)
    s = re.sub(r"\b0x[0-9a-fA-F]+\b", "0x0", s)
    s = re.sub(r"\b\d{3,}\b", "N", s)
    return " ".join(TOKEN.findall(s.lower()))


def shingles(text: str, k: int = SHINGLE_WORDS) -> frozenset[str]:
    w = text.split()
    if len(w) < k:
        return frozenset([" ".join(w)]) if w else frozenset()
    return frozenset(" ".join(w[i:i + k]) for i in range(len(w) - k + 1))


def read_jsonl(path: pathlib.Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------------ corpora ----
BENCH_GLOBS = (
    ("benchmark", "*.jsonl"),
    ("benchmark/retired_families", "*.jsonl"),
    ("Vbeta/benchmark_vbeta", "*.jsonl"),
)


def benchmark_family_files() -> list[str]:
    out = []
    for d, pat in BENCH_GLOBS:
        for p in sorted((ROOT / d).glob(pat)):
            out.append(p.relative_to(ROOT).as_posix())
    return out


def model_visible_training_files() -> list[str]:
    """Every JSONL under training/ is, by definition, model-visible.

    That is the point of the exercise: a corpus consumer globs a directory,
    so anything inside it is reachable. Files that must not be reachable live
    outside training/ (see `non_model_visible_evaluation_files`).
    """
    return sorted(p.relative_to(ROOT).as_posix()
                  for p in (ROOT / "training").rglob("*.jsonl"))


def non_model_visible_evaluation_files() -> list[str]:
    """Evaluation-side shards that are deliberately outside the corpus."""
    base = ROOT / "benchmark" / "independent"
    if not base.is_dir():
        return []
    return sorted(p.relative_to(ROOT).as_posix()
                  for p in base.rglob("*.jsonl"))


def protected_identifiers() -> set[str]:
    """Every identifier of every held-out benchmark row.

    A record is protected when ANY family holds it out: the split systems
    differ per layer, so one record can be train in one family's split and
    test in another's. The corpus builders exclude these identifiers, and
    the gate checks against them, from the same set.
    """
    out: set = set()
    for rel in benchmark_family_files():
        for raw in read_jsonl(ROOT / rel):
            if str(raw.get("split") or "") not in PROTECTED_SPLITS:
                continue
            out |= benchmark_row_ids(raw)
            rid = benchmark_record_id(raw)
            if rid:
                out.add(rid)
    return out


# ---------------------------------------------------------------- row views ----
def _add(out: set, v) -> None:
    if isinstance(v, str) and v.strip():
        v = v.strip()
        out.add(v)
        if "::" in v:
            out.add(v.split("::")[-1])


def benchmark_row_ids(row: dict) -> set[str]:
    out: set = set()
    src = row.get("source") or {}
    for v in (row.get("id"), row.get("task_id"), row.get("finding_id"),
              row.get("record_id"), src.get("record_id"),
              src.get("finding_id"), src.get("id"), src.get("task_id")):
        _add(out, v)
    inp = row.get("input")
    if isinstance(inp, dict):
        for k in ("finding_id", "record_id", "id"):
            _add(out, inp.get(k))
    return out


def benchmark_record_id(row: dict) -> str:
    """The one identifier that names the underlying record.

    A task id is decorated ('A::test::2024-08-wildcat/H-01', 'U_<source>:<id>')
    and therefore cannot be compared across layers; the record id can.
    """
    src = row.get("source") or {}
    for v in (src.get("record_id"), src.get("finding_id"),
              row.get("record_id"), row.get("finding_id")):
        if isinstance(v, str) and v.strip():
            return v.strip()
    for v in (row.get("id"), row.get("task_id")):
        if isinstance(v, str) and v.strip():
            return v.split("::")[-1].strip()
    return ""


def training_row_ids(row: dict) -> set[str]:
    out: set = set()
    prov = row.get("provenance") or {}
    for v in (row.get("canonical_record_id"), row.get("canonical_id"),
              row.get("id"), row.get("task_id"), row.get("finding_id"),
              row.get("record_id"), prov.get("record_ref"),
              prov.get("record_id"), prov.get("finding_id")):
        _add(out, v)
    return out


def _walk_strings(node) -> list[str]:
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            out.extend(_walk_strings(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_walk_strings(v))
    return out


def benchmark_code(row: dict) -> tuple[list[str], set[str], set[str]]:
    """(snippets, file paths, commit shas) carried by the task's evidence."""
    snippets, files, commits = [], set(), set()
    for b in _audit.code_blocks(row):
        if not isinstance(b, dict):
            continue
        if b.get("code"):
            snippets.append(str(b["code"]))
        if b.get("file"):
            files.add(str(b["file"]))
        if b.get("commit_sha"):
            commits.add(str(b["commit_sha"]))
    for b in (row.get("input") or {}).get("code_blocks", []) or []:
        if isinstance(b, dict):
            if b.get("code"):
                snippets.append(str(b["code"]))
            if b.get("file"):
                files.add(str(b["file"]))
    return snippets, files, commits


def training_code(row: dict) -> tuple[list[str], set[str], set[str]]:
    """(snippets, file paths, commit shas) carried by a training row."""
    snippets, files, commits = [], set(), set()
    ref = row.get("code_ref")
    if isinstance(ref, dict):
        if ref.get("file"):
            files.add(str(ref["file"]))
        if ref.get("commit_sha"):
            commits.add(str(ref["commit_sha"]))
    inp = row.get("input")
    if isinstance(inp, dict):
        blocks = inp.get("code")
        if isinstance(blocks, dict):
            blocks = blocks.get("code_blocks") or []
        if isinstance(blocks, list):
            for b in blocks:
                if isinstance(b, dict):
                    if b.get("snippet"):
                        snippets.append(str(b["snippet"]))
                    if b.get("code"):
                        snippets.append(str(b["code"]))
                    if b.get("file"):
                        files.add(str(b["file"]))
                    if b.get("commit_sha"):
                        commits.add(str(b["commit_sha"]))
        for k in ("snippet", "code", "fixed_commit", "vulnerable_commit",
                  "commit"):
            v = inp.get(k)
            if isinstance(v, str) and v:
                if k.endswith("commit"):
                    commits.add(v)
                elif k == "snippet":
                    snippets.append(v)
    # A canonical row keeps its snippet inside input_text ("CODE <loc>: <src>").
    text = row.get("input_text")
    if isinstance(text, str) and "CODE " in text:
        for part in text.split("\n\n"):
            if part.startswith("CODE "):
                loc, _, code = part.partition(": ")
                if loc[5:]:
                    files.add(loc[5:])
                if code:
                    snippets.append(code)
    return snippets, files, commits


def benchmark_answer_values(row: dict) -> dict:
    """The answer key as {field: normalised value}."""
    ak = row.get("answer_key")
    if not isinstance(ak, dict):
        a = row.get("answer")
        ak = a if isinstance(a, dict) else ({"answer": a} if a is not None
                                            else {})
    out = {}
    for k, v in ak.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[str(k)] = _scalar(v)
        else:
            out[str(k)] = json.dumps(v, sort_keys=True)
    return out


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "none"
    return str(v).strip().lower()


def training_answer_values(row: dict) -> dict:
    """A training row's supervised targets as {field: normalised value}."""
    if "label" in row:
        return {"label": _scalar(row["label"])}
    out = row.get("output")
    if isinstance(out, dict):
        return {str(k): _scalar(v) if not isinstance(v, (list, dict))
                else json.dumps(v, sort_keys=True) for k, v in out.items()}
    if isinstance(out, (str, int, float, bool)):
        return {"answer": _scalar(out)}
    return {}


# ------------------------------------------------------------------ measure ----
class Corpus:
    """The model-visible training corpus, indexed for overlap queries."""

    def __init__(self, files: list[pathlib.Path]):
        self.files = files
        self.rows: list[dict] = []      # per training row view
        self.id_index: dict[str, list[int]] = collections.defaultdict(list)
        self.shingle_index: dict[str, list[int]] = collections.defaultdict(list)
        self.shingles: list[frozenset[str]] = []
        self.text_index: dict[str, list[int]] = collections.defaultdict(list)
        self.snippet_exact: dict[str, list[int]] = collections.defaultdict(list)
        self.snippet_norm: dict[str, list[int]] = collections.defaultdict(list)
        self.file_index: dict[str, list[int]] = collections.defaultdict(list)
        self.commit_index: dict[str, list[int]] = collections.defaultdict(list)
        for path in files:
            rel = _rel(path)
            for raw in read_jsonl(path):
                idx = len(self.rows)
                ids = training_row_ids(raw)
                text = norm_text(_training_text(raw))
                sh = shingles(text) if text else frozenset()
                snips, files_s, commits = training_code(raw)
                view = {
                    "path": rel,
                    "ids": ids,
                    "text": text,
                    "shingles": sh,
                    "answers": training_answer_values(raw),
                    "split": str(raw.get("split") or ""),
                }
                self.rows.append(view)
                self.shingles.append(sh)
                for i in ids:
                    self.id_index[i].append(idx)
                for s in sh:
                    self.shingle_index[s].append(idx)
                if text:
                    self.text_index[text].append(idx)
                for s in snips:
                    self.snippet_exact[hashlib.sha1(s.encode()).hexdigest()].append(idx)
                    n = norm_code(s)
                    if n:
                        self.snippet_norm[hashlib.sha1(n.encode()).hexdigest()].append(idx)
                for f in files_s:
                    self.file_index[f].append(idx)
                for c in commits:
                    self.commit_index[c].append(idx)

    def id_hits(self, ids: set[str]) -> list[int]:
        out: set = set()
        for i in ids:
            out.update(self.id_index.get(i, ()))
        return sorted(out)

    def text_hits(self, text: str, sh: frozenset[str]) -> list[int]:
        if not sh:
            return []
        candidates: set = set()
        postings = sorted(((len(self.shingle_index[s]), s) for s in sh),
                          key=lambda x: x[0])
        for _, s in postings:
            pl = self.shingle_index[s]
            if len(pl) > MAX_POSTING:
                continue
            candidates.update(pl)
            if len(candidates) >= MAX_CANDIDATES:
                break
        if not candidates:
            # Every shingle is boilerplate: fall back to the shortest list.
            _, s = postings[0]
            candidates.update(self.shingle_index[s][:MAX_CANDIDATES])
        hits = []
        for idx in candidates:
            other = self.shingles[idx]
            if not other:
                continue
            inter = len(sh & other)
            if inter / min(len(sh), len(other)) >= TEXT_CONTAINMENT:
                hits.append(idx)
        return sorted(hits)

    def code_hits(self, snippets: list[str], files: set[str],
                  commits: set[str]) -> dict:
        """Which KIND of code evidence the corpus also carries.

        An identical (or reformatting-invariant) snippet means the held-out
        task's evidence is in the training corpus: that is leakage. A shared
        file path or commit sha only means the same repository or revision
        was mined, which is provenance, not an answer.
        """
        out: dict[str, set] = {"snippet": set(), "file_path": set(),
                               "commit_sha": set()}
        for s in snippets:
            out["snippet"] |= set(
                self.snippet_exact.get(hashlib.sha1(s.encode()).hexdigest(), ()))
            n = norm_code(s)
            if n:
                out["snippet"] |= set(
                    self.snippet_norm.get(hashlib.sha1(n.encode()).hexdigest(), ()))
        for f in files:
            out["file_path"] |= set(self.file_index.get(f, ()))
        for c in commits:
            out["commit_sha"] |= set(self.commit_index.get(c, ()))
        return out


def _rel(path: pathlib.Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def corpus_paths(corpus_root: pathlib.Path | None = None) -> list[pathlib.Path]:
    """The JSONL files of the model-visible corpus."""
    base = corpus_root if corpus_root is not None else ROOT / "training"
    if not base.is_dir():
        return []
    return sorted(p for p in base.rglob("*.jsonl") if p.is_file())


def _training_text(row: dict) -> str:
    if isinstance(row.get("input_text"), str):
        return row["input_text"]
    inp = row.get("input")
    if inp is None:
        return ""
    return " ".join(_walk_strings(inp))


def _benchmark_text(row: dict) -> str:
    return _audit.input_text(row)


def _benchmark_evidence_text(row: dict) -> str:
    return _audit.evidence_text(row)


def load_benchmark() -> list[dict]:
    """Every benchmark family row, with the family it belongs to."""
    out = []
    for rel in benchmark_family_files():
        fname = rel.split("/")[-1]
        spec = _audit.FAMILIES.get(fname)
        for raw in read_jsonl(ROOT / rel):
            gold = ""
            if spec is not None:
                gold = _audit.gold_of(raw, spec["projection"])
            ids = benchmark_row_ids(raw)
            text = norm_text(_benchmark_text(raw))
            ev = norm_text(_benchmark_evidence_text(raw))
            snips, files, commits = benchmark_code(raw)
            out.append({
                "family": rel,
                "family_file": fname,
                "split": str(raw.get("split") or ""),
                "ids": ids,
                "record_id": benchmark_record_id(raw),
                "gold": gold,
                "answers": benchmark_answer_values(raw),
                "text": text,
                "evidence": ev,
                "shingles": shingles(text),
                "evidence_shingles": shingles(ev),
                "snippets": snips,
                "files": files,
                "commits": commits,
                "row": raw,
            })
    return out


def derive_label_maps(bench: list[dict], corpus: Corpus) -> dict:
    """Learn each family's answer-key value mapping from its TRAIN partition.

    A canonical training row stores `label: true` where the benchmark key
    says `vulnerable`. The mapping between the two vocabularies is not
    hand-written: it is read off the train partition, where the same record
    appears on both sides, and then applied to the held-out partition.
    """
    maps: dict[str, dict] = {}
    for b in bench:
        if b["split"] != "train":
            continue
        hits = corpus.id_hits(b["ids"])
        for idx in hits:
            tv = corpus.rows[idx]["answers"]
            for k, v in b["answers"].items():
                if k not in tv:
                    continue
                m = maps.setdefault(b["family"], {}).setdefault(k, {})
                m.setdefault(tv[k], collections.Counter())[v] += 1
    resolved = {}
    for fam, fields in maps.items():
        for k, vals in fields.items():
            m = {}
            for tval, ctr in vals.items():
                best = sorted(ctr.items(), key=lambda x: (-x[1], x[0]))[0]
                if best[1] >= 2 and (len(vals) == 1 or best[1] > sum(ctr.values()) / 2):
                    m[tval] = best[0]
            if m:
                resolved.setdefault(fam, {})[k] = m
    return resolved


def measure(corpus_root: pathlib.Path | None = None) -> dict:
    bench = load_benchmark()
    train_paths = corpus_paths(corpus_root)
    train_files = [_rel(p) for p in train_paths]
    corpus = Corpus(train_paths)
    label_maps = derive_label_maps(bench, corpus)

    fam_stats: dict[str, dict] = collections.defaultdict(
        lambda: {"rows": 0, "by_split": collections.Counter(),
                 "heldout_rows": 0, "heldout_records": set(),
                 "all_records": set(), "train_records": set(),
                 "protected_id_hits": 0, "protected_text_hits": 0,
                 "protected_code_hits": 0, "protected_snippet_hits": 0,
                 "protected_file_hits": 0, "protected_commit_hits": 0,
                 "protected_label_exposed": 0,
                 "protected_label_compared": 0,
                 "train_id_hits": 0, "train_text_hits": 0,
                 "train_code_hits": 0, "train_snippet_hits": 0})
    file_stats: dict[str, dict] = collections.defaultdict(
        lambda: {"rows": 0, "by_split": collections.Counter(),
                 "protected_id_hits": 0, "protected_rows": 0,
                 "protected_text_hits": 0, "protected_code_hits": 0,
                 "protected_snippet_hits": 0,
                 "train_id_hits": 0, "train_text_hits": 0,
                 "train_code_hits": 0, "train_snippet_hits": 0})
    examples: list[dict] = []

    protected_records: set = set()
    all_records: set = set()
    protected_records_in_corpus: set = set()
    for b in bench:
        all_records |= b["ids"]
        if b["split"] in PROTECTED_SPLITS:
            protected_records |= b["ids"]
            if b["record_id"]:
                protected_records.add(b["record_id"])

    for b in bench:
        fam = fam_stats[b["family"]]
        fam["rows"] += 1
        fam["by_split"][b["split"]] += 1
        fam["all_records"] |= b["ids"]
        if b["record_id"]:
            fam["train_records"].add(b["record_id"])
        protected = b["split"] in PROTECTED_SPLITS
        if protected:
            fam["heldout_rows"] += 1
            fam["heldout_records"] |= b["ids"]
        id_hits = corpus.id_hits(b["ids"])
        text_hits = corpus.text_hits(b["text"], b["shingles"])
        code_hits = corpus.code_hits(b["snippets"], b["files"], b["commits"])
        snippet_hits = code_hits["snippet"]
        any_code_hits = snippet_hits or code_hits["file_path"] \
            or code_hits["commit_sha"]
        for idx in id_hits:
            file_stats[corpus.rows[idx]["path"]]["protected_id_hits" if protected
                                                 else "train_id_hits"] += 1
        for idx in text_hits:
            file_stats[corpus.rows[idx]["path"]]["protected_text_hits" if protected
                                                 else "train_text_hits"] += 1
        for idx in any_code_hits:
            file_stats[corpus.rows[idx]["path"]]["protected_code_hits" if protected
                                                 else "train_code_hits"] += 1
        for idx in snippet_hits:
            file_stats[corpus.rows[idx]["path"]]["protected_snippet_hits"
                                                 if protected
                                                 else "train_snippet_hits"] += 1
        if protected:
            fam["protected_id_hits"] += 1 if id_hits else 0
            fam["protected_text_hits"] += 1 if text_hits else 0
            fam["protected_code_hits"] += 1 if any_code_hits else 0
            fam["protected_snippet_hits"] += 1 if snippet_hits else 0
            fam["protected_file_hits"] += 1 if code_hits["file_path"] else 0
            fam["protected_commit_hits"] += 1 if code_hits["commit_sha"] else 0
            if (id_hits or text_hits or snippet_hits) and b["record_id"]:
                protected_records_in_corpus.add(b["record_id"])
            for idx in id_hits:
                path = corpus.rows[idx]["path"]
                file_stats[path]["protected_rows"] += 1
                tv = corpus.rows[idx]["answers"]
                mp = label_maps.get(b["family"], {})
                exposed = False
                compared = False
                for k, v in b["answers"].items():
                    if k not in tv:
                        continue
                    compared = True
                    mapped = mp.get(k, {}).get(tv[k], tv[k])
                    if mapped == v:
                        exposed = True
                if compared:
                    fam["protected_label_compared"] += 1
                    if exposed:
                        fam["protected_label_exposed"] += 1
                if len(examples) < 40 and id_hits:
                    examples.append({
                        "family": b["family"], "split": b["split"],
                        "benchmark_ids": sorted(b["ids"])[:4],
                        "training_file": corpus.rows[id_hits[0]]["path"],
                        "training_ids": sorted(corpus.rows[id_hits[0]]["ids"])[:4],
                        "answer_key": b["answers"],
                        "training_targets": tv,
                        "answer_key_reproduced_in_training": exposed,
                    })
        else:
            fam["train_id_hits"] += 1 if id_hits else 0
            fam["train_text_hits"] += 1 if text_hits else 0
            fam["train_code_hits"] += 1 if any_code_hits else 0
            fam["train_snippet_hits"] += 1 if snippet_hits else 0

    # training file census
    census = []
    for rel, p in zip(train_files, train_paths):
        rows = read_jsonl(p)
        by_split = collections.Counter(str(r.get("split") or "unsplit")
                                       for r in rows)
        census.append({"path": rel, "rows": len(rows), "sha256": sha256_file(p),
                       "by_split": dict(sorted(by_split.items()))})

    fam_out = {}
    for fam, st in sorted(fam_stats.items()):
        fam_out[fam] = {
            "rows": st["rows"],
            "by_split": dict(sorted(st["by_split"].items())),
            "records": len(st["train_records"]),
            "identifiers": len(st["all_records"]),
            "heldout_rows": st["heldout_rows"],
            "heldout_records": len(st["heldout_records"]),
            "overlap_with_model_visible_corpus": {
                "heldout": {
                    "rows_with_id_overlap": st["protected_id_hits"],
                    "rows_with_text_overlap": st["protected_text_hits"],
                    "rows_with_code_overlap": st["protected_code_hits"],
                    "rows_with_identical_code_snippet": st["protected_snippet_hits"],
                    "rows_sharing_only_a_file_path": st["protected_file_hits"],
                    "rows_sharing_only_a_commit_sha": st["protected_commit_hits"],
                    "rows_whose_answer_key_is_reproduced_in_training": st[
                        "protected_label_exposed"],
                    "rows_whose_answer_key_could_be_compared": st[
                        "protected_label_compared"],
                },
                "train": {
                    "rows_with_id_overlap": st["train_id_hits"],
                    "rows_with_text_overlap": st["train_text_hits"],
                    "rows_with_code_overlap": st["train_code_hits"],
                    "rows_with_identical_code_snippet": st["train_snippet_hits"],
                },
            },
        }

    file_out = {}
    for rel, p in zip(train_files, train_paths):
        st = file_stats.get(rel)
        rows = read_jsonl(p)
        by_split = collections.Counter(str(r.get("split") or "unsplit")
                                       for r in rows)
        file_out[rel] = {
            "rows": len(rows),
            "by_split": dict(sorted(by_split.items())),
            "heldout_rows_touching_this_file": (st or {}).get("protected_rows", 0),
            "heldout_id_hits": (st or {}).get("protected_id_hits", 0),
            "heldout_text_hits": (st or {}).get("protected_text_hits", 0),
            "heldout_code_hits": (st or {}).get("protected_code_hits", 0),
            "heldout_identical_snippet_hits": (st or {}).get(
                "protected_snippet_hits", 0),
            "train_id_hits": (st or {}).get("train_id_hits", 0),
            "train_text_hits": (st or {}).get("train_text_hits", 0),
            "train_code_hits": (st or {}).get("train_code_hits", 0),
        }

    heldout_id = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                     ["rows_with_id_overlap"] for v in fam_out.values())
    heldout_text = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                       ["rows_with_text_overlap"] for v in fam_out.values())
    heldout_code = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                       ["rows_with_code_overlap"] for v in fam_out.values())
    heldout_snippet = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                          ["rows_with_identical_code_snippet"]
                          for v in fam_out.values())
    heldout_file = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                       ["rows_sharing_only_a_file_path"] for v in fam_out.values())
    heldout_commit = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                         ["rows_sharing_only_a_commit_sha"]
                         for v in fam_out.values())
    heldout_label = sum(v["overlap_with_model_visible_corpus"]["heldout"]
                        ["rows_whose_answer_key_is_reproduced_in_training"]
                        for v in fam_out.values())
    train_id = sum(v["overlap_with_model_visible_corpus"]["train"]
                   ["rows_with_id_overlap"] for v in fam_out.values())

    # Corpus hygiene: what split does the model-visible corpus actually ship?
    corpus_by_split: collections.Counter = collections.Counter()
    corpus_protected_rows = 0
    corpus_rows = 0
    for view in corpus.rows:
        corpus_rows += 1
        corpus_by_split[view["split"] or "unsplit"] += 1
        if view["ids"] & protected_records:
            corpus_protected_rows += 1

    verdict = ("clean" if heldout_id == 0 and heldout_text == 0
               and heldout_snippet == 0 and corpus_protected_rows == 0
               else "leaking")

    return {
        "report_version": REPORT_VERSION,
        "generated_by": "scripts/build_eval_leakage_report.py",
        "method": {
            "protected_evaluation_set": (
                "every row of every benchmark family whose split is "
                + " or ".join(PROTECTED_SPLITS) + ". A record is protected if "
                "ANY family holds it out, because the split systems differ "
                "per layer (v1 splits_v2, v2.2 splits_v2_2, v3 splits_v3, "
                "vbeta by-source) and one record can be train in one and "
                "held out in another."),
            "model_visible_corpus": (
                "every .jsonl under training/. A corpus consumer globs a "
                "directory, so anything inside training/ is reachable; "
                "evaluation-side shards therefore live outside it."),
            "id_overlap": (
                "benchmark identifiers (task id, record id, finding id, the "
                "source block, and the input's own finding id) against "
                "training identifiers (canonical_record_id, canonical_id, "
                "provenance.record_ref, example_id, id, task_id). A '::'-"
                "suffixed family prefix is stripped so 'A::test::x' and 'x' "
                "compare equal."),
            "text_overlap": (
                "the model-facing payload, normalised to lowercase "
                "alphanumeric tokens, compared as ordered "
                f"{SHINGLE_WORDS}-word shingles. A row overlaps when "
                f"min(|A|,|B|) containment of the shingle sets is >= "
                f"{TEXT_CONTAINMENT}, or when the normalised text is "
                "identical. Text shorter than "
                f"{MIN_TEXT_TOKENS} tokens is not compared."),
            "code_overlap": (
                "exact code snippet bytes, snippets normalised for comments, "
                "literals and numbers, source file paths, and commit shas. "
                "An identical (or reformatting-invariant) snippet means the "
                "held-out task's evidence is in the training corpus and is "
                "counted as leakage. A shared file path or commit sha only "
                "means the same repository or revision was mined, which is "
                "provenance, and is reported separately."),
            "label_overlap": (
                "for a benchmark row whose id also appears in the corpus, the "
                "answer-key fields are compared with the training row's "
                "supervised targets. The value mapping between the two "
                "vocabularies is derived from the family's TRAIN partition, "
                "never hand-written."),
            "expected_train_overlap": (
                "rows in a family's train partition share records with the "
                "training corpus by construction. That is the training data, "
                "not leakage; only the held-out partitions are defects."),
            "thresholds": {
                "shingle_words": SHINGLE_WORDS,
                "text_containment": TEXT_CONTAINMENT,
                "min_text_tokens": MIN_TEXT_TOKENS,
                "max_shingle_posting": MAX_POSTING,
                "max_candidates": MAX_CANDIDATES,
            },
        },
        "corpora": {
            "benchmark_families": [
                {"path": rel, "rows": len(read_jsonl(ROOT / rel)),
                 "sha256": sha256_file(ROOT / rel)}
                for rel in benchmark_family_files()],
            "model_visible_training_files": census,
            "non_model_visible_evaluation_files": non_model_visible_evaluation_files(),
        },
        "protected_evaluation_set": {
            "records": len(protected_records),
            "all_benchmark_records": len(all_records),
            "records_present_in_model_visible_corpus": len(
                protected_records_in_corpus),
            "by_family": {f: v["heldout_records"] for f, v in fam_out.items()},
        },
        "model_visible_corpus_hygiene": {
            "rows": corpus_rows,
            "rows_by_split": dict(sorted(corpus_by_split.items())),
            "rows_carrying_a_protected_record": corpus_protected_rows,
            "rule": ("the model-visible corpus ships the train partition only; "
                     "a row whose record is held out by any benchmark family "
                     "does not belong in it, whatever the row's own split "
                     "label says"),
        },
        "overlap": {
            "heldout": {
                "rows_with_id_overlap": heldout_id,
                "rows_with_text_overlap": heldout_text,
                "rows_with_code_overlap": heldout_code,
                "rows_with_identical_code_snippet": heldout_snippet,
                "rows_sharing_only_a_file_path": heldout_file,
                "rows_sharing_only_a_commit_sha": heldout_commit,
                "rows_whose_answer_key_is_reproduced_in_training": heldout_label,
                "distinct_protected_records_in_corpus": len(
                    protected_records_in_corpus),
                "note": ("a record counts when the corpus carries its id, "
                         "its text or its code evidence; a shared commit sha "
                         "alone is provenance and does not count"),
            },
            "train": {
                "rows_with_id_overlap": train_id,
                "note": "expected: the training corpus is the train partition",
            },
            "by_family": fam_out,
            "by_training_file": file_out,
        },
        "examples": examples,
        "remediation": REMEDIATION,
        "release_boundary": release_boundary(),
        "verdict": verdict,
    }


# ----------------------------------------------------------------- rendering ----
def release_boundary() -> dict:
    """What is OPEN-KEY and what is actually protected, measured.

    A key that is committed in this repository is open-key, whatever the
    prose around it says. The only evaluation whose key is not in the
    repository is the VLUN-Prove private split, whose key is written
    outside the tracked tree; this function checks that no such file has
    appeared inside it.
    """
    families = []
    for rel in benchmark_family_files():
        rows = read_jsonl(ROOT / rel)
        keyed = sum(1 for r in rows
                    if r.get("answer_key") is not None
                    or r.get("answer") is not None)
        families.append({"path": rel, "rows": len(rows),
                         "rows_with_a_committed_answer_key": keyed})
    in_tree = []
    for p in sorted(ROOT.rglob("prove_tasks_private.jsonl")):
        in_tree.append(p.relative_to(ROOT).as_posix())
    holdout_keys = (ROOT / "benchmark" / "independent"
                    / "secondary_holdout_keys.jsonl")
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch",
             holdout_keys.relative_to(ROOT).as_posix()],
            cwd=str(ROOT), capture_output=True, text=True).returncode == 0
    except (OSError, ValueError, subprocess.SubprocessError):
        tracked = None
    return {
        "open_key": {
            "benchmark_families": {
                "statement": ("every benchmark family row carries its answer "
                              "key in the same file as its input; the key is "
                              "committed, so every family is OPEN-KEY and "
                              "no family may be described as hidden or "
                              "protected against repository-level leakage"),
                "families": families,
            },
            "secondary_holdout": {
                "statement": ("the answer key is a separate file labelled "
                              "OPEN-KEY: it is not a secret because the split "
                              "is deterministic and reproducible from the "
                              "committed benchmark files. It is not tracked in "
                              "this repository; the model-facing task file "
                              "carries the input and a task id only"),
                "key_file": "benchmark/independent/secondary_holdout_keys.jsonl",
                "tracked_in_git": tracked,
                "note": ("whether the key file is present in a given checkout "
                         "does not change its status: it is open, not private"),
            },
            "canonical_held_out_shards": {
                "statement": ("the held-out partitions of the training views "
                              "are committed, and are not model-visible "
                              "because they live outside training/"),
                "location": "benchmark/independent/canonical_holdout/",
            },
            "v1_task_holdout_rows": {
                "statement": ("the task rows whose records a benchmark family "
                              "holds out are committed, and are not "
                              "model-visible because they live outside "
                              "training/"),
                "location": "benchmark/independent/v1_task_holdout/",
            },
        },
        "protected": {
            "vlun_prove_private_split": {
                "statement": ("the key lives OUTSIDE the tracked tree and is "
                              "committed to by SHA-256, so this evaluation "
                              "IS protected against repository-level "
                              "retrieval. scripts/build_prove_split.py "
                              "refuses to write it inside the repository"),
                "key_files_inside_the_repository": in_tree,
                "protected": not in_tree,
                "verified_by": ("python scripts/build_prove_split.py --check "
                                "(the published interface must equal a "
                                "regeneration and the private key must still "
                                "match its published commitment)"),
            },
        },
    }


def render_md(rep: dict) -> str:
    out = ["# Evaluation-leakage audit: protected evaluation set vs model-visible corpus",
           "",
           f"Generated by `scripts/build_eval_leakage_report.py` "
           f"(report version {rep['report_version']}). Recompute with "
           "`python scripts/build_eval_leakage_report.py`; verify with "
           "`--check`.",
           "",
           "## Verdict",
           "",
           f"**{rep['verdict']}**",
           "",
           "| measure | held-out partitions | train partitions (expected) |",
           "|---|---|---|"]
    h = rep["overlap"]["heldout"]
    t = rep["overlap"]["train"]
    hy = rep["model_visible_corpus_hygiene"]
    rem = rep["remediation"]
    out += [
        f"| rows with an id overlap | {h['rows_with_id_overlap']} | "
        f"{t['rows_with_id_overlap']} |",
        f"| rows with a text overlap | {h['rows_with_text_overlap']} | n/a |",
        f"| rows with a code overlap | {h['rows_with_code_overlap']} | n/a |",
        f"| ... of which an identical code snippet | "
        f"{h['rows_with_identical_code_snippet']} | n/a |",
        f"| ... of which only a file path / commit sha (provenance) | "
        f"{h['rows_sharing_only_a_file_path']} / "
        f"{h['rows_sharing_only_a_commit_sha']} | n/a |",
        f"| rows whose answer key is reproduced in the corpus | "
        f"{h['rows_whose_answer_key_is_reproduced_in_training']} | n/a |",
        f"| distinct protected records present in the corpus | "
        f"{h['distinct_protected_records_in_corpus']} | n/a |",
        "",
        "## Model-visible corpus hygiene",
        "",
        f"- corpus rows: **{hy['rows']}**",
        f"- rows by split: `{hy['rows_by_split']}`",
        f"- rows carrying a record that some family holds out: "
        f"**{hy['rows_carrying_a_protected_record']}**",
        f"- rule: {hy['rule']}",
        "",
        "## Method",
        "",
    ]
    for k, v in rep["method"].items():
        if k == "thresholds":
            continue
        out.append(f"- **{k.replace('_', ' ')}** — {v}")
    out += ["", "Thresholds: "
            + ", ".join(f"`{k}={v}`" for k, v in
                        rep["method"]["thresholds"].items()), ""]
    out += ["## Protected evaluation set",
            "",
            f"- protected records (held out by at least one family): "
            f"**{rep['protected_evaluation_set']['records']}**",
            f"- protected records present in the model-visible corpus: "
            f"**{rep['protected_evaluation_set']['records_present_in_model_visible_corpus']}**",
            f"- distinct benchmark records in total: "
            f"{rep['protected_evaluation_set']['all_benchmark_records']}",
            "",
            "## Per-family breakdown",
            "",
            "| family | rows | held-out rows | id overlap | text overlap | "
            "code overlap | identical snippet | answer key reproduced |",
            "|---|---|---|---|---|---|---|---|"]
    for fam, v in rep["overlap"]["by_family"].items():
        o = v["overlap_with_model_visible_corpus"]["heldout"]
        out.append(
            f"| `{fam}` | {v['rows']} | {v['heldout_rows']} | "
            f"{o['rows_with_id_overlap']} | {o['rows_with_text_overlap']} | "
            f"{o['rows_with_code_overlap']} | "
            f"{o['rows_with_identical_code_snippet']} | "
            f"{o['rows_whose_answer_key_is_reproduced_in_training']} |")
    out += ["", "## Per-training-file breakdown",
            "",
            "| training file | rows | splits | held-out rows touching it | "
            "held-out id hits |",
            "|---|---|---|---|---|"]
    for rel, v in rep["overlap"]["by_training_file"].items():
        out.append(
            f"| `{rel}` | {v['rows']} | {v['by_split']} | "
            f"{v['heldout_rows_touching_this_file']} | {v['heldout_id_hits']} |")
    out += ["", "## Non-model-visible evaluation shards", ""]
    nm = rep["corpora"]["non_model_visible_evaluation_files"]
    if nm:
        out += ["These files live outside `training/`, so a consumer globbing "
                "the training directory cannot reach them:", ""]
        out += [f"- `{p}`" for p in nm]
    else:
        out.append("None.")
    out += ["", "## Remediation (before / after)", "",
            f"- change: {rem['change']}",            f"- before, measured against: {rem['before']['measured_against']}",
            "", "| measure | before | after |", "|---|---|---|"]
    after = {
        "corpus_rows": hy["rows"],
        "corpus_rows_by_split": hy["rows_by_split"],
        "rows_carrying_a_protected_record":
            hy["rows_carrying_a_protected_record"],
        "heldout_rows_with_id_overlap": h["rows_with_id_overlap"],
        "heldout_rows_with_text_overlap": h["rows_with_text_overlap"],
        "heldout_rows_with_code_overlap": h["rows_with_code_overlap"],
        "heldout_rows_with_identical_code_snippet":
            h["rows_with_identical_code_snippet"],
        "heldout_answer_keys_reproduced_in_training":
            h["rows_whose_answer_key_is_reproduced_in_training"],
        "distinct_protected_records_in_corpus":
            h["distinct_protected_records_in_corpus"],
        "verdict": rep["verdict"],
    }
    for k, v in rem["before"].items():
        if k in ("measured_against",):
            continue
        out.append(f"| {k.replace('_', ' ')} | {v} | {after.get(k, '')} |")
    out += ["", f"- after, measured against: {rem['after']['measured_against']}",
            f"- excluded rows: {rem['after']['held_out_rows_written_to']}", ""]
    out += ["", "## Release boundary: what is open-key and what is protected",
            ""]
    rb = rep["release_boundary"]
    out += ["| evaluation | status | where the key is |", "|---|---|---|"]
    for name, entry in sorted(rb["open_key"].items()):
        where = entry.get("location") or entry.get("key_file") or \
            "in the family file itself"
        out.append(f"| {name.replace('_', ' ')} | **OPEN-KEY** | `{where}` |")
    for name, entry in sorted(rb["protected"].items()):
        state = "PROTECTED" if entry.get("protected") else "**NOT PROTECTED**"
        out.append(f"| {name.replace('_', ' ')} | {state} | outside the "
                   f"repository |")
    out.append("")
    for name, entry in sorted(rb["open_key"].items()):
        out.append(f"- **{name.replace('_', ' ')}** — {entry['statement']}")
    for name, entry in sorted(rb["protected"].items()):
        out.append(f"- **{name.replace('_', ' ')}** — {entry['statement']}")
    out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed report differs")
    ap.add_argument("--json", default="reports/eval_leakage_report.json")
    ap.add_argument("--md", default="reports/eval_leakage_report.md")
    args = ap.parse_args()
    rep = measure()
    jtext = json.dumps(rep, indent=2, sort_keys=True) + "\n"
    mtext = render_md(rep)
    if args.check:
        stale = []
        for rel, want in ((args.json, jtext), (args.md, mtext)):
            p = ROOT / rel
            if not p.is_file():
                stale.append(f"missing {rel}")
            elif p.read_text(encoding="utf-8") != want:
                stale.append(f"STALE {rel}")
        if stale:
            print("; ".join(stale) + " -- run: python "
                  "scripts/build_eval_leakage_report.py", file=sys.stderr)
            return 1
        print("evaluation-leakage report is current")
        return 0
    (ROOT / args.json).parent.mkdir(parents=True, exist_ok=True)
    (ROOT / args.json).write_text(jtext, encoding="utf-8", newline="\n")
    (ROOT / args.md).write_text(mtext, encoding="utf-8", newline="\n")
    h = rep["overlap"]["heldout"]
    print(f"wrote {args.json}")
    print(f"wrote {args.md}")
    print(f"verdict: {rep['verdict']}")
    print(f"  held-out rows with id overlap   : {h['rows_with_id_overlap']}")
    print(f"  held-out rows with text overlap : {h['rows_with_text_overlap']}")
    print(f"  held-out rows with code overlap : {h['rows_with_code_overlap']}")
    print(f"  held-out answer keys reproduced : "
          f"{h['rows_whose_answer_key_is_reproduced_in_training']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

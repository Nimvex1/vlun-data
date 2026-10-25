#!/usr/bin/env python3
"""Gate: no overlap between the protected evaluation set and the corpus.

The canary in `benchmark/CANARY.md` is a statement; this is a check. A canary
string cannot tell you that `training/canonical/severity.test.part-000.jsonl`
carries 5,000 rows of a family's held-out answers, because those rows carry no
canary. This gate measures the overlap directly, on three axes, and fails the
build when it finds any:

  1. ID        a protected evaluation record id appears in the model-visible
               training corpus;
  2. content   a protected evaluation task's text, or its code evidence,
               appears in the model-visible training corpus;
  3. label     the model-facing task payload of an evaluation set carries its
               own answer, or its key file does not declare that the key is
               committed (OPEN-KEY).

Plus two structural checks: the model-visible corpus must ship no held-out
partition, and the VLUN-Prove private answer key must not be inside the
tracked tree.

Exit codes: 0 pass, 1 fail, 2 skipped (an input a clean checkout cannot
have). A skip is reported as SKIPPED, never as a pass.

    python scripts/check_eval_leakage.py
    python scripts/check_eval_leakage.py --quiet
    python scripts/check_eval_leakage.py --corpus <dir>   # corpus to check
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "_leak", ROOT / "scripts" / "build_eval_leakage_report.py")
_leak = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_leak)

TASKS = ROOT / "benchmark" / "independent" / "secondary_holdout_tasks.jsonl"
KEYS = ROOT / "benchmark" / "independent" / "secondary_holdout_keys.jsonl"
HOLDOUT_MANIFEST = (ROOT / "benchmark" / "independent"
                     / "secondary_holdout_manifest.json")

# The private prove split is written OUTSIDE the repository by
# scripts/build_prove_split.py. These are the file names it uses.
PRIVATE_KEY_NAMES = ("prove_tasks_private.jsonl",)
PRIVATE_DIR_NAMES = ("vlun_prove",)

# A field the model-facing task row must never carry.
ANSWER_FIELD_NAMES = ("gold", "label", "answer", "answer_key", "expected",
                      "original_id", "original_split", "group", "split")

# A truthy claim that an evaluation key is not in the repository.
HIDDENNESS_CLAIM_KEYS = ("hidden", "protected", "secret", "private",
                         "not_accessible", "key_is_outside_repository")

# The only split a model-visible corpus row may carry.
MODEL_VISIBLE_SPLITS = ("train", "unsplit")


def log(msg: str) -> None:
    print(msg)


# ------------------------------------------------------------ pure checks ----
def answer_fields_in_task_row(row: dict) -> list[str]:
    """Answer material a model-facing task row must not carry.

    A model-facing task is the input plus a task id. Anything that names the
    answer -- the gold, the original record id, the group the record belongs
    to -- belongs in the key file, not in the task.
    """
    return [f for f in ANSWER_FIELD_NAMES if f in row]


def held_out_partition_violations(rows: list[dict]) -> list[str]:
    """Corpus rows whose own split is a held-out partition.

    The model-visible corpus ships the train partition. A validation or test
    partition of an evaluation family is evaluation material.
    """
    bad = []
    for i, r in enumerate(rows):
        split = str(r.get("split") or "")
        if split and split not in MODEL_VISIBLE_SPLITS:
            bad.append(f"row {i} carries split={split!r}")
    return bad


def protected_id_violations(rows: list[dict], protected: set[str]) -> list[str]:
    """Corpus rows that carry a record some benchmark family holds out."""
    bad = []
    for i, r in enumerate(rows):
        ids = _leak.training_row_ids(r)
        hit = ids & protected
        if hit:
            bad.append(f"row {i} carries a protected record: {sorted(hit)[:3]}")
    return bad


def key_status_violations(key_rows: list[dict], manifest: dict) -> list[str]:
    """The answer key must say, in so many words, that it is committed here."""
    bad = []
    for row in key_rows:
        if str(row.get("key_status", "")).lower() != "open_key":
            bad.append(
                f"key row {row.get('holdout_task_id')!r} does not declare "
                f"key_status=open_key")
    ak = manifest.get("answer_key") or {}
    if str(ak.get("key_status", "")).upper() != "OPEN_KEY":
        bad.append("the holdout manifest does not declare "
                   "answer_key.key_status = OPEN_KEY")
    # The manifest must describe the key file as it actually is. A key that is
    # committed and a key that is withheld are different facts, and the manifest
    # may not claim the wrong one: the key is withheld from the repository here,
    # and the holdout stays open-key because the key is regenerable from the
    # committed sources at the recorded seed.
    tracked = key_file_is_tracked()
    declared = ak.get("committed_in_repository")
    if tracked is True and declared is not True:
        bad.append("the holdout manifest does not declare "
                   "answer_key.committed_in_repository = true although the key "
                   "file is tracked")
    if tracked is False and declared is not False:
        bad.append("the holdout manifest declares the answer key committed but "
                   "the key file is not tracked by git")
    if declared is False and ak.get("tracked_in_git") is not False:
        bad.append("the holdout manifest declares an uncommitted key but still "
                   "claims answer_key.tracked_in_git")
    for name, value in _walk_claims(manifest):
        if name in HIDDENNESS_CLAIM_KEYS and value:
            bad.append(
                f"the holdout manifest claims {name!r} for an answer key that "
                f"is open: it is regenerable from the committed sources")
    return bad


def key_file_is_tracked() -> bool | None:
    """Is the holdout answer key tracked by git? None when git cannot say."""
    try:
        rel = KEYS.relative_to(ROOT).as_posix()
    except ValueError:
        return None
    try:
        out = subprocess.run(["git", "ls-files", "--error-unmatch", rel],
                             cwd=str(ROOT), capture_output=True, text=True)
    except (OSError, ValueError):
        return None
    if out.returncode == 0:
        return True
    if out.returncode == 1 or "did not match" in (out.stderr or ""):
        return False
    return None


def _walk_claims(node, path="$"):
    """Yield (leaf key, value) for every leaf in a JSON document."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_claims(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_claims(v, f"{path}[{i}]")
    else:
        yield path.split(".")[-1], node


# ------------------------------------------------------------ repo checks ----
def corpus_files(corpus_root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in corpus_root.rglob("*.jsonl") if p.is_file())


def check_protected_overlap(corpus_root: pathlib.Path) -> list[str]:
    """Checks 1 and 2: id, text and code-evidence overlap."""
    problems: list[str] = []
    rep = _leak.measure(corpus_root)
    h = rep["overlap"]["heldout"]
    if h["rows_with_id_overlap"]:
        problems.append(
            f"{h['rows_with_id_overlap']} protected evaluation row(s) share a "
            f"record id with the model-visible training corpus")
    if h["rows_with_text_overlap"]:
        problems.append(
            f"{h['rows_with_text_overlap']} protected evaluation row(s) share "
            f"their model-facing text with the model-visible training corpus")
    if h["rows_with_identical_code_snippet"]:
        problems.append(
            f"{h['rows_with_identical_code_snippet']} protected evaluation "
            f"row(s) share their code evidence with the model-visible "
            f"training corpus")
    if h["rows_whose_answer_key_is_reproduced_in_training"]:
        problems.append(
            f"{h['rows_whose_answer_key_is_reproduced_in_training']} protected "
            f"evaluation answer key(s) are reproduced in the model-visible "
            f"training corpus")
    for fam, v in rep["overlap"]["by_family"].items():
        o = v["overlap_with_model_visible_corpus"]["heldout"]
        if (o["rows_with_id_overlap"] or o["rows_with_text_overlap"]
                or o["rows_with_identical_code_snippet"]):
            problems.append(
                f"{fam}: id={o['rows_with_id_overlap']} "
                f"text={o['rows_with_text_overlap']} "
                f"snippet={o['rows_with_identical_code_snippet']}")
    return problems


def check_corpus_hygiene(corpus_root: pathlib.Path) -> list[str]:
    """The model-visible corpus ships the train partition only."""
    problems: list[str] = []
    protected = _leak.protected_identifiers()
    for path in corpus_files(corpus_root):
        rows = _leak.read_jsonl(path)
        rel = _rel(path)
        for bad in held_out_partition_violations(rows):
            problems.append(f"{rel} {bad}; the model-visible corpus ships the "
                            f"train partition only")
        for bad in protected_id_violations(rows, protected):
            problems.append(f"{rel} {bad}")
    return problems


def _rel(path: pathlib.Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def check_task_payload_and_key() -> list[str]:
    """Check 3: the task payload exposes no answer, and the key says it is open."""
    problems: list[str] = []
    if not TASKS.is_file():
        problems.append(f"missing {TASKS.relative_to(ROOT)}")
        return problems
    if not KEYS.is_file():
        problems.append(f"missing {KEYS.relative_to(ROOT)} (the answer key must "
                        f"exist as its own file, labelled OPEN-KEY)")
        return problems

    key_rows = [json.loads(line) for line
                in KEYS.read_text(encoding="utf-8").splitlines() if line.strip()]
    keys = {row.get("holdout_task_id"): row for row in key_rows}
    for line in TASKS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        tid = row.get("holdout_task_id")
        blob = json.dumps(row, ensure_ascii=False)
        if tid not in keys:
            problems.append(f"task {tid!r} has no row in the key file")
            continue
        for field in answer_fields_in_task_row(row):
            problems.append(
                f"model-facing task {tid!r} carries the answer field "
                f"{field!r}")
        # The withheld task id must not reappear in the payload. The
        # benchmark's OWN payload may still leak the answer for some
        # families (family K names the language in its evidence, families
        # R/U/V carry the source id): that is a benchmark defect, measured
        # by scripts/independent_benchmark_audit.py and reported by the
        # holdout manifest, not something this layer can fix.
        original = str(keys[tid].get("original_id") or "")
        if original and original in blob:
            problems.append(
                f"model-facing task {tid!r} leaks its withheld task id "
                f"{original!r} in its payload")
    if not HOLDOUT_MANIFEST.is_file():
        problems.append(f"missing {HOLDOUT_MANIFEST.relative_to(ROOT)}")
        return problems
    manifest = json.loads(HOLDOUT_MANIFEST.read_text(encoding="utf-8"))
    problems.extend(key_status_violations(key_rows, manifest))
    return problems


def tracked_paths() -> list[str]:
    """Tracked file names, read-only. Falls back to a filesystem walk."""
    try:
        p = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT),
                           capture_output=True, text=True, errors="replace",
                           timeout=120)
        if p.returncode == 0:
            return [x for x in p.stdout.split("\0") if x]
    except (OSError, subprocess.SubprocessError):
        pass
    out = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        if ".git" in p.parts or "work" in p.parts or "__pycache__" in p.parts:
            continue
        out.append(p.relative_to(ROOT).as_posix())
    return out


def check_private_key_absent() -> list[str]:
    """The VLUN-Prove private answer key must not be inside the tree."""
    problems: list[str] = []
    for rel in tracked_paths():
        name = rel.split("/")[-1]
        parts = rel.split("/")
        if name in PRIVATE_KEY_NAMES:
            problems.append(f"the private prove answer key is in the tree: {rel}")
        if any(p in PRIVATE_DIR_NAMES for p in parts):
            problems.append(f"a private prove directory is in the tree: {rel}")
    return problems


def check_canary_absent_from_corpus(corpus_root: pathlib.Path) -> list[str]:
    """The canary is a cheap extra signal, never the defence on its own."""
    problems: list[str] = []
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from schema_terms import BENCHMARK_CANARY  # noqa: E402
    except ImportError:
        return problems
    # The GUID lives in one place (scripts/schema_terms.py). It is derived
    # from the canary string, never re-typed here.
    m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                  BENCHMARK_CANARY)
    needles = [BENCHMARK_CANARY] + ([m.group(0)] if m else [])
    for path in corpus_files(corpus_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(n in text for n in needles):
            problems.append(f"{_rel(path)} carries the benchmark canary string")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true",
                    help="suppress per-check output (for run_gates.py)")
    ap.add_argument("--corpus", default=str(ROOT / "training"),
                    help="directory holding the model-visible corpus")
    args = ap.parse_args()
    corpus_root = pathlib.Path(args.corpus).resolve()

    families = _leak.benchmark_family_files()
    if not families:
        log("SKIPPED: no benchmark family files in this checkout; there is no "
            "protected evaluation set to check against")
        return 2
    if not corpus_root.is_dir():
        log(f"SKIPPED: no corpus at {corpus_root}; there is no model-visible "
            f"corpus to check")
        return 2

    checks = [
        ("protected-evaluation-overlap",
         lambda: check_protected_overlap(corpus_root)),
        ("model-visible-corpus-hygiene",
         lambda: check_corpus_hygiene(corpus_root)),
        ("task-payload-and-key-status", check_task_payload_and_key),
        ("private-answer-key-absent", check_private_key_absent),
        ("canary-absent-from-corpus",
         lambda: check_canary_absent_from_corpus(corpus_root)),
    ]
    failures: list[str] = []
    for name, fn in checks:
        try:
            problems = fn()
        except Exception as exc:                      # noqa: BLE001
            problems = [f"the check could not run: {type(exc).__name__}: {exc}"]
        if problems:
            failures.append(name)
            if not args.quiet:
                log(f"  [FAIL] {name}")
                for p in problems[:20]:
                    log(f"      {p}")
                if len(problems) > 20:
                    log(f"      ... {len(problems) - 20} more")
        elif not args.quiet:
            log(f"  [ok]   {name}")
    if failures:
        log(f"evaluation leakage: {len(failures)} check(s) failed: "
            + ", ".join(failures))
        return 1
    log("ok: no protected evaluation record, answer or payload is reachable "
        "from the model-visible corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

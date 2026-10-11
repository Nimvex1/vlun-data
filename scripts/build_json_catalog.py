#!/usr/bin/env python3
"""Categorized catalog of every JSON/JSONL file in the repository.

The corpus keeps ~260 JSON files across 25 directories because each layer
is frozen in place (moving a file breaks its provenance). This script does
not move anything: it builds one browsable map — category by category —
so a reader can answer "where does this kind of data live" in one place.

    python scripts/build_json_catalog.py            # write reports/json_catalog.*
    python scripts/build_json_catalog.py --check    # verify current, write nothing

Writes reports/json_catalog.json (machine-readable) and
reports/json_catalog.md (per-category tables). The catalog excludes its own
two outputs: hashing them would make --check fail on every run.
Machine-local trees (work/, V3/clones/, scrape caches, ai/) are out of
scope and recorded as excluded, never scanned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_io as _io  # noqa: E402  (canonical JSON writers)

ROOT = Path(__file__).resolve().parent.parent
CATALOG_JSON = ROOT / "reports" / "json_catalog.json"
CATALOG_MD = ROOT / "reports" / "json_catalog.md"

# Machine-local trees: git-ignored inputs, caches and scratch. Never scanned;
# listed here so --check output is explicit about the scope.
EXCLUDED_PREFIXES = (
    "work/", "V3/clones/", "node_modules/", "__pycache__/", ".git/",
    ".firecrawl/", "nextdata/", ".freebuff/", "brag-output/", "ai/",
)

# The catalog's own outputs. Hashing them would make --check fail forever:
# the entry is computed from the previous bytes, then the file is rewritten.
SELF_OUTPUTS = ("reports/json_catalog.json", "reports/json_catalog.md")

# Gate outputs whose committed bytes legitimately vary run-to-run. These are
# pinned nowhere: reports/v3/validation_v31.json embeds a worktree-dirt
# observation ("N dirty entries ..."), so its bytes differ between a dirty
# tree, a clean tree and CI by design. (Its verdict counts are stable and
# stay gated by validate_v31.py itself.) Listed here, not hashed.
VOLATILE_OUTPUTS = ("reports/v3/validation_v31.json",)

# (category, one-line meaning). Order is the markdown section order.
CATEGORIES = (
    ("source", "original evidence layers: one row per harvested pointer"),
    ("derived", "normalized records, ledgers, manifests, overlays"),
    ("splits", "train/validation/test pointers plus quarantine"),
    ("benchmark", "task files, family manifests and holdouts"),
    ("experiments", "per-run result.json / harness.json run artefacts"),
    ("reports", "validation, stats, quality and baseline reports"),
    ("schema", "machine-readable schemas generated from schema_terms.py"),
    ("datasets", "admission-filtered subsets with a published rule"),
    ("training", "task-oriented training files"),
    ("harvest", "Vbeta scrape working files: candidates, fetch receipts"),
    ("meta", "repo-level registries, snapshots, packaging and reviews"),
)

# category -> layer label shown in the tables.
_LAYERS = {
    "jsonl": "v1", "jsonl_ml": "v2.2", "jsonl_v3": "v3",
    "derived": "v1", "derived_v2_2": "v2.2", "derived_v3": "v3",
}


def categorize(rel: str) -> tuple[str, str]:
    """(category, layer) for a repo-relative posix path."""
    top = rel.split("/")[0]
    if top == "schema":
        return "schema", "multi"
    if top == "datasets":
        return "datasets", "multi"
    if top == "training":
        return "training", "multi"
    if top in ("benchmark",) or rel.startswith("Vbeta/benchmark_vbeta/"):
        return "benchmark", "multi"
    if top in ("experiments", "experiments_v2_2", "experiments_v3"):
        layer = {"experiments": "v1", "experiments_v2_2": "v2.2",
                 "experiments_v3": "v3"}[top]
        return "experiments", layer
    if top in ("jsonl", "jsonl_ml", "jsonl_v3"):
        return "source", _LAYERS[top]
    if rel.startswith("Vbeta/jsonl_vbeta/"):
        return "source", "vbeta"
    if top in ("derived", "derived_v2_2", "derived_v3"):
        return "derived", _LAYERS[top]
    if rel.startswith("Vbeta/derived_vbeta/"):
        return "derived", "vbeta"
    if top in ("splits_v2", "splits_v2_2", "splits_v3"):
        layer = {"splits_v2": "v1", "splits_v2_2": "v2.2",
                 "splits_v3": "v3"}[top]
        return "splits", layer
    if rel.startswith("Vbeta/splits_vbeta/"):
        return "splits", "vbeta"
    if top == "reports" or rel.startswith("Vbeta/reports_vbeta/"):
        return "reports", "multi"
    if top == "Vbeta" and (
            rel == "Vbeta/candidates.json"
            or rel.endswith("_candidates.json")
            or rel.startswith("Vbeta/fetched/")):
        return "harvest", "vbeta"
    return "meta", "meta"


def tracked_set() -> set[str]:
    try:
        proc = subprocess.run(["git", "ls-files"], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=120)
    except OSError:
        return set()
    if proc.returncode != 0:
        return set()
    return set(proc.stdout.splitlines())


def ignored_set() -> set[str]:
    """Paths git ignores (machine-local by declaration in .gitignore).

    These must never enter the catalog: their bytes vary by machine (e.g.
    reports/reproducibility_checks.json records this machine's PASS/SKIP
    split), so cataloguing them makes --check fail on every other machine.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--others", "-i", "--exclude-standard"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    except OSError:
        return set()
    if proc.returncode != 0:
        return set()
    return set(proc.stdout.splitlines())


def scan() -> list[str]:
    ignored = ignored_set()
    out = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in (".json", ".jsonl"):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in SELF_OUTPUTS:
            continue
        if rel in VOLATILE_OUTPUTS:
            continue
        if rel in ignored:
            continue
        if any(rel == pre[:-1] or rel.startswith(pre)
               for pre in EXCLUDED_PREFIXES):
            continue
        out.append(rel)
    return sorted(out)


def describe(rel: str) -> dict:
    raw = (ROOT / rel).read_bytes()
    entry: dict = {
        "path": rel,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if rel.endswith(".jsonl"):
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            entry["rows"] = None
            entry["parse"] = "undecodable"
            return entry
        entry["rows"] = sum(1 for line in text.splitlines() if line.strip())
        entry["parse"] = "ok"
        return entry
    try:
        obj = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        entry["parse"] = "error"
        return entry
    entry["parse"] = "ok"
    if isinstance(obj, dict):
        entry["kind"] = "object"
        entry["keys"] = sorted(obj.keys())
    elif isinstance(obj, list):
        entry["kind"] = "array"
        entry["length"] = len(obj)
    else:
        entry["kind"] = type(obj).__name__
    return entry


def build() -> dict:
    tracked = tracked_set()
    files = scan()
    entries = []
    for rel in files:
        category, layer = categorize(rel)
        entry = describe(rel)
        entry["category"] = category
        entry["layer"] = layer
        entry["tracked"] = rel in tracked
        # keep key order stable: identity first, content last
        entries.append({
            "path": entry["path"],
            "category": entry["category"],
            "layer": entry["layer"],
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
            "tracked": entry["tracked"],
            **{k: v for k, v in entry.items()
               if k not in ("path", "category", "layer", "bytes",
                            "sha256", "tracked")},
        })
    by_category: dict[str, int] = {}
    for entry in entries:
        by_category[entry["category"]] = by_category.get(entry["category"], 0) + 1
    return {
        "generated_by": "scripts/build_json_catalog.py",
        "scope_note": ("every .json/.jsonl under the repo root except the "
                       "catalog's own outputs, machine-local trees, "
                       "git-ignored files (their bytes vary by machine), and "
                       "volatile gate outputs (bytes vary run-to-run by "
                       "design); nothing is moved, this file is a map"),
        "excluded_prefixes": list(EXCLUDED_PREFIXES),
        "volatile_outputs": list(VOLATILE_OUTPUTS),
        "file_count": len(entries),
        "by_category": {name: by_category.get(name, 0)
                        for name, _ in CATEGORIES},
        "files": entries,
    }


def render_md(doc: dict) -> str:
    lines = ["# JSON catalog (category-wise map, nothing moved)",
             "",
             "Generated by `scripts/build_json_catalog.py` from a scan of the",
             "working tree. Every `.json`/`.jsonl` file lives where its layer",
             "froze it; this page only says where each kind lives. Machine-local",
             f"trees ({', '.join(doc['excluded_prefixes'])}) are out of scope.",
             "",
             "Volatile gate outputs (bytes vary run-to-run by design) are",
             f"also excluded: {', '.join(doc['volatile_outputs'])}.",
             "",
             f"{doc['file_count']} files across "
             f"{sum(1 for _ in CATEGORIES)} categories.",
             ""]
    by_cat: dict[str, list[dict]] = {}
    for entry in doc["files"]:
        by_cat.setdefault(entry["category"], []).append(entry)
    for name, meaning in CATEGORIES:
        rows = by_cat.get(name, [])
        lines += [f"## {name} ({len(rows)})", "", f"*{meaning}.*", ""]
        lines += ["| file | layer | bytes | rows / content | tracked |",
                  "|---|---|---|---|---|"]
        for entry in rows:
            if "rows" in entry:
                content = f"{entry['rows']} rows" if entry["rows"] is not None else "undecodable"
            elif entry.get("kind") == "object":
                keys = entry.get("keys", [])
                content = f"object, {len(keys)} keys"
            elif entry.get("kind") == "array":
                content = f"array[{entry.get('length', '?')}]"
            elif entry.get("parse") == "error":
                content = "unparseable"
            else:
                content = str(entry.get("kind", "?"))
            lines.append(f"| `{entry['path']}` | {entry['layer']} | "
                         f"{entry['bytes']:,} | {content} | "
                         f"{'yes' if entry['tracked'] else 'no'} |")
        lines += [""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the catalog is current, write nothing")
    args = ap.parse_args()
    doc = build()
    if args.check:
        problems = []
        if not CATALOG_JSON.is_file():
            problems.append("reports/json_catalog.json (missing)")
        else:
            try:
                on_disk = json.loads(CATALOG_JSON.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                on_disk = None
            if on_disk != doc:
                problems.append("reports/json_catalog.json (stale)")
                if isinstance(on_disk, dict):
                    old = {f["path"]: f for f in on_disk.get("files", [])
                           if isinstance(f, dict) and "path" in f}
                    new = {f["path"]: f for f in doc["files"]}
                    diffs = sorted(set(old) ^ set(new)
                                   | {p for p in set(old) & set(new)
                                      if old[p] != new[p]})[:8]
                    for p in diffs:
                        problems.append(f"  entry differs: {p}")
        want_md = render_md(doc)
        if not CATALOG_MD.is_file():
            problems.append("reports/json_catalog.md (missing)")
        elif CATALOG_MD.read_text(encoding="utf-8") != want_md:
            problems.append("reports/json_catalog.md (stale)")
        if problems:
            print("STALE " + ", ".join(problems)
                  + " — run: python scripts/build_json_catalog.py")
            return 1
        print(f"json catalog is current ({doc['file_count']} files)")
        return 0
    _io.write_json(CATALOG_JSON, doc)
    CATALOG_MD.write_text(render_md(doc), encoding="utf-8", newline="\n")
    print(f"wrote reports/json_catalog.json + .md ({doc['file_count']} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

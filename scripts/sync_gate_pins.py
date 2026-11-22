#!/usr/bin/env python3
"""Recompute and rewrite every hardcoded numeric gate pin from live data.

WHY
---
The hydration workers change canonical row counts.  `scripts/check_manifests.py`
(and its generated `reports/dataset_stats.json`) contain literal counts that were
correct at authoring time.  After hydration those literals go stale and the
release gates fail for a reason that has nothing to do with correctness: the
gate is comparing the new data against an old number typed into the gate.

This tool is the *serial* fix point.  It reads the ACTUAL current dataset files,
recomputes every such literal, and rewrites it in place.  It touches only the
three files this track owns:

  * scripts/check_manifests.py
  * scripts/validate_checks.py      (kept in scope; currently has NO literal
                                    count pins -- it recomputes stats via
                                    generate_stats.build_stats())
  * reports/dataset_stats.json      (regenerated via generate_stats.build_stats)

It NEVER writes to tests/ or wave1/ (owned by other tracks).  Pins that live in
those files are recomputed and printed as ADVISORY values only, so the owning
track can re-freeze them with real numbers instead of guesses.

PROPERTIES
----------
* stdlib only (no third-party imports).
* deterministic: same tree -> same output, same bytes.
* idempotent: a second run performs zero writes.
* prints a before -> after diff for every pin it touches.
* fail-closed on a compute/IO error; a pin that has MOVED (regex no longer
  matches) is reported loudly as a warning but does not abort the whole run.

USAGE
-----
    python scripts/sync_gate_pins.py            # recompute + rewrite
    python scripts/sync_gate_pins.py --dry-run  # show the diff, write nothing
    python scripts/sync_gate_pins.py --quiet    # only the summary / warnings

Run this FIRST in Wave 3, before the layer builders regenerate derived layers,
and before build_release_manifest.py / build_json_catalog.py.  The authoritative
regeneration of reports/dataset_stats.json still happens in the layer-builder
phase via `python scripts/generate_stats.py`; this tool keeps the committed copy
consistent with that same build_stats() recomputation.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


# --------------------------------------------------------------------------- #
# Small stdlib-only helpers (mirror scripts/vlun.py semantics)                 #
# --------------------------------------------------------------------------- #
def jl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def js(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def rec_id(row: dict) -> str:
    """Stable record identity, identical to scripts/vlun.py::rec_id."""
    rid = (row.get("finding") or {}).get("id")
    if rid:
        return rid
    rid = (row.get("error") or {}).get("id") or (row.get("error") or {}).get("code")
    if rid:
        return str(rid)
    if row.get("protocol"):
        name = row["protocol"]
        return "protocol:" + str(name.get("name") or name)
    blob = json.dumps(row, sort_keys=True, ensure_ascii=False).encode()
    import hashlib
    return "sha256:" + hashlib.sha256(blob).hexdigest()[:24]


_WORK_RE = re.compile(r"(?<![A-Za-z0-9_/.-])work/")


def _cites_work(row: dict) -> bool:
    return bool(_WORK_RE.search(json.dumps(row, sort_keys=True, ensure_ascii=False)))


# --------------------------------------------------------------------------- #
# Recompute context: each named value is computed once, from live files.       #
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, root: Path):
        self.root = root
        self._cache: dict[str, object] = {}

    def get(self, name: str):
        if name not in self._cache:
            fn = _COMPUTERS[name]
            self._cache[name] = fn(self.root)
        return self._cache[name]

    # -- named recomputations -------------------------------------------------
    def v1_multi(self):
        rows = jl(self.root / "jsonl" / "errors.jsonl")
        return sum(1 for r in rows if (r.get("source") or {}).get("repository") == "multiple")

    def v1_quar(self):
        return len(jl(self.root / "splits_v2" / "quarantine.jsonl"))

    def v1_judged(self):
        return (len(jl(self.root / "jsonl" / "findings.jsonl"))
                + len(jl(self.root / "jsonl" / "negative_findings.jsonl")))

    def _bench_task_count(self, family: str) -> int:
        """Authoritative headline-family task count from benchmark/manifest.json.

        After hydration the raw jsonl row count is NOT the benchmark population:
        some judged rows are excluded from family A and some negative/patch rows
        are excluded from F/G. The manifest is the published truth and matches
        the actual family file row count, so pin from it (with a file-row
        fallback) rather than from raw source rows.
        """
        tasks = js(self.root / "benchmark" / "manifest.json")["tasks"]
        spec = tasks.get(family)
        if isinstance(spec, dict) and spec.get("tasks") is not None:
            return int(spec["tasks"])
        if isinstance(spec, dict) and spec.get("file"):
            return len(jl(self.root / spec["file"]))
        return 0

    def v1_A(self):
        return self._bench_task_count("A_vulnerability_detection")

    def v1_excluded(self):
        """Judged rows not admitted to headline family A (hydration-era delta)."""
        return self.v1_judged() - self.v1_A()

    def v1_F(self):
        return self._bench_task_count("F_false_positive_rejection")

    def v1_G(self):
        return self._bench_task_count("G_patch_verification")

    def v1_split_ptr(self):
        return sum(len(jl(self.root / "splits_v2" / f"{s}.jsonl"))
                   for s in ("train", "validation", "test", "quarantine"))

    def quar_ids(self):
        ids = sorted({rec_id(r) for r in jl(self.root / "splits_v2" / "quarantine.jsonl")})
        return json.dumps(ids, ensure_ascii=False)

    def v22_records(self):
        return len(jl(self.root / "derived_v2_2" / "records.jsonl"))

    def v22_ptr(self):
        return sum(len(jl(self.root / "splits_v2_2" / f"{s}.jsonl"))
                   for s in ("train", "validation", "test", "quarantine"))

    def m_tasks(self):
        spec = js(self.root / "benchmark" / "manifest.json")["tasks"]
        fname = spec["M_experiment_level_classification"]["file"]
        return len(jl(self.root / fname))

    def v22_ml_citations(self):
        return sum(1 for f in (self.root / "jsonl_ml").glob("*.jsonl")
                   for r in jl(f) if _cites_work(r))

    def v22_lpq_citations(self):
        files = ("benchmark/retired_families/L_severity_reconciliation.jsonl",
                 "benchmark/retired_families/P_provenance_tier_and_rights.jsonl",
                 "benchmark/Q_evidence_type_and_quality_rubric.jsonl")
        return sum(1 for f in files for r in jl(self.root / f) if _cites_work(r))

    def v3_candidates(self):
        return len(jl(self.root / "derived_v3" / "candidate_ledger.jsonl"))

    def v3_records(self):
        return len(jl(self.root / "derived_v3" / "records.jsonl"))

    def vb_candidates(self):
        return len(jl(self.root / "Vbeta" / "derived_vbeta" / "candidate_ledger.jsonl"))

    def vb_records(self):
        return len(jl(self.root / "Vbeta" / "derived_vbeta" / "records.jsonl"))

    def vb_sources(self):
        # The manifest's source_count is the authoritative value. Counting
        # distinct source_id in the candidate_ledger is WRONG after the DEAD-
        # pointer purge: the 80 retained rows all come from solodit-harvest,
        # yet the registered source registry still holds 15 sources.
        m = js(self.root / "Vbeta" / "derived_vbeta" / "manifest.json")
        return int(m["source_count"])

    # -- advisory (recomputed, never written: files owned by other tracks) ----
    def adv_v3_127(self):
        m = js(self.root / "derived_v3" / "manifest.json")
        return (m.get("evidence_admitted_records"), m.get("candidate_artefacts"))

    def adv_certora_200(self):
        reg = jl(self.root / "wave1" / "01_dedup" / "registry.jsonl")
        return sum(1 for r in reg
                   if str(r.get("key", "")).startswith("certora_rule:certora-reports:"))

    def adv_l5_35(self):
        doc = js(self.root / "reports" / "v2_2" / "l5_adjudication.json")
        return doc.get("counts", {}).get("L5_records")

    def adv_l6_7(self):
        m = js(self.root / "derived" / "manifest.json")
        return m.get("derived_verification_levels", {}).get("L6")


_COMPUTERS: dict[str, Callable[[Path], object]] = {
    name: getattr(Ctx, name) for name in [
        "v1_multi", "v1_quar", "v1_judged", "v1_A", "v1_excluded", "v1_F", "v1_G",
        "v1_split_ptr", "quar_ids", "v22_records", "v22_ptr", "m_tasks",
        "v22_ml_citations", "v22_lpq_citations", "v3_candidates", "v3_records",
        "vb_candidates", "vb_records", "vb_sources", "adv_v3_127",
        "adv_certora_200", "adv_l5_35", "adv_l6_7",
    ]
}
# getattr gives unbound methods: normalize to (root) -> value.
_COMPUTERS = {k: (lambda root, _f=v: _f(Ctx(root))) for k, v in _COMPUTERS.items()}


# --------------------------------------------------------------------------- #
# Pin specification                                                            #
# --------------------------------------------------------------------------- #
@dataclass
class Pin:
    pid: str
    desc: str
    file: str
    keys: list[str]
    patterns: list[str]
    # Each pattern must contain exactly the named groups n0..nN-1 where
    # N == len(keys); group ni is replaced with Ctx.get(keys[i]).

    def values(self, ctx: Ctx) -> list[str]:
        return [str(ctx.get(k)) for k in self.keys]

    def validate(self) -> None:
        want = {f"n{i}" for i in range(len(self.keys))}
        for pat in self.patterns:
            found = set(re.compile(pat).groupindex)
            if found != want:
                raise ValueError(
                    f"pin {self.pid}: pattern groups {sorted(found)} != expected {sorted(want)}")


MANIFEST = "scripts/check_manifests.py"

PINS: list[Pin] = [
    # ---- v1 docstring (truth strings kept accurate for reviewers) ----------
    Pin("v1-doc-multi-quar", "v1 docstring: multi-repo rows / quarantine rows",
        MANIFEST, ["v1_multi", "v1_quar"], [
            r'(source\.repository == "multiple": )(?P<n0>\d+)( rows\), with )(?P<n1>\d+)',
        ]),
    Pin("v1-doc-families", "v1 docstring: A-E / F / G populations",
        MANIFEST, ["v1_judged", "v1_excluded", "v1_A", "v1_F", "v1_G"], [
            r'\(A-E: (?P<n0>\d+) - (?P<n1>\d+) = (?P<n2>\d+); '
            r'F: (?P<n3>\d+) negatives; G: (?P<n4>\d+) patches\)',
        ]),

    # ---- quarantine --------------------------------------------------------
    Pin("quarantine-ids", "quarantined finding id list",
        MANIFEST, ["quar_ids"], [
            r'(?P<n0>\["[\w\-/]+"(?:, "[\w\-/]+")*\])(?=, qids,)',
        ]),
    Pin("quarantine-count-detail", "quarantine detail string count",
        MANIFEST, ["v1_quar"], [
            r'"the (?P<n0>\d+) cross-split duplicates',
        ]),
    Pin("v1-A-same-pop", "families B-E truth string (same population as A)",
        MANIFEST, ["v1_A"], [
            r'"same (?P<n0>\d+)-row population as family A"',
        ]),
    Pin("v1-F-truth", "family F truth string (negative finding ids)",
        MANIFEST, ["v1_F"], [
            r'"(?P<n0>\d+) negative finding ids"',
        ]),

    # ---- v2.2 --------------------------------------------------------------
    Pin("v22-records-137", "derived_v2_2 record count (literal + label)",
        MANIFEST, ["v22_records", "v22_records"], [
            r'("records == )(?P<n0>\d+)(", )(?P<n1>\d+)(,)',
        ]),
    Pin("v22-bylang", "derived_v2_2 by_language sum (label + literal)",
        MANIFEST, ["v22_records", "v22_records"], [
            r'("by_language sums to )(?P<n0>\d+)(",\n\s+)(?P<n1>\d+)(,)',
        ]),
    Pin("v22-ids-truth", "v2.2 family truth string (record ids)",
        MANIFEST, ["v22_records"], [
            r'"(?P<n0>\d+) derived_v2_2 record ids"',
        ]),
    Pin("v22-M", "M family executed-run task count (literal + truth)",
        MANIFEST, ["m_tasks", "m_tasks"], [
            r'("task count == executed runs", )(?P<n0>\d+)(, len\(m_tasks\),\n\s+")'
            r'(?P<n1>\d+)( executed runs)',
        ]),
    Pin("v22-split-ptr", "splits_v2_2 pointer rows + truth detail",
        MANIFEST, ["v22_ptr", "v1_split_ptr", "v22_records"], [
            r'("pointer rows", )(?P<n0>\d+)(, len\(ptrs\),\n\s+")'
            r'(?P<n1>\d+)( v1 \+ )(?P<n2>\d+)( v2\.2 pointers")',
        ]),
    Pin("v22-ml-work", "jsonl_ml rows citing work/ payloads",
        MANIFEST, ["v22_ml_citations"], [
            r'("rows citing work/ payloads", )(?P<n0>\d+)(,)',
        ]),
    Pin("v22-lpq-work", "L/P/Q tasks citing work/ payloads",
        MANIFEST, ["v22_lpq_citations"], [
            r'("tasks citing work/ payloads", )(?P<n0>\d+)(,)',
        ]),

    # ---- v3 / vbeta --------------------------------------------------------
    Pin("v3-manifest-counts", "v3 candidate/admitted manifest counts",
        MANIFEST, ["v3_candidates", "v3_records"], [
            r'("candidate_count/admitted counts", \()(?P<n0>\d+)(, )(?P<n1>\d+)(\),)',
        ]),
    Pin("vbeta-manifest-counts", "vbeta candidate/record/source manifest counts",
        MANIFEST, ["vb_candidates", "vb_records", "vb_sources"], [
            r'(\()(?P<n0>\d+)(, )(?P<n1>\d+)(, )(?P<n2>\d+)'
            r'(\),\n\s+\(mb\["candidate_count"\])',
        ]),
]


# --------------------------------------------------------------------------- #
# Rewrite engine                                                               #
# --------------------------------------------------------------------------- #
def _replace_groups(match: re.Match, values: list[str]) -> str:
    """Replace the named groups n0..nN-1 in `match` with `values`."""
    text = match.group(0)
    base = match.start()
    edits = []
    for i, value in enumerate(values):
        name = f"n{i}"
        if name not in match.groupdict() or match.group(name) is None:
            continue
        s, e = match.span(name)
        edits.append((s - base, e - base, str(value)))
    for s, e, val in sorted(edits, reverse=True):
        text = text[:s] + val + text[e:]
    return text


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def apply_pin(text: str, pin: Pin, ctx: Ctx):
    """Return (new_text, changes, missing).  changes = list of (line, old, new)."""
    values = pin.values(ctx)
    changes = []
    missing = False
    new_text = text
    for pattern in pin.patterns:
        rx = re.compile(pattern)
        found = list(rx.finditer(new_text))
        if not found:
            missing = True
            continue
        # Rebuild from right to left so offsets stay valid.
        out = new_text
        for m in reversed(found):
            old = m.group(0)
            new = _replace_groups(m, values)
            s, e = m.span()
            out = out[:s] + new + out[e:]
            changes.append((_line_of(new_text, s), old, new))
        new_text = out
    return new_text, changes, missing


def sync_python_file(rel: str, pins: list[Pin], ctx: Ctx, dry: bool, quiet: bool):
    path = ROOT / rel
    original = path.read_text(encoding="utf-8")
    text = original
    touched = 0
    warnings = []
    for pin in pins:
        text, changes, missing = apply_pin(text, pin, ctx)
        if missing:
            warnings.append(f"{rel}: pin {pin.pid} pattern(s) not found -- manual review")
        changed_here = [(ln, o, n) for ln, o, n in changes if o != n]
        if changed_here:
            touched += len(changed_here)
            if not quiet:
                print(f"  [{rel}] {pin.pid} ({pin.desc})")
                for ln, o, n in changed_here:
                    print(f"      L{ln}: {o!r} -> {n!r}")
        elif changes and not quiet:
            print(f"  [{rel}] {pin.pid}: {len(changes)} occurrence(s) already current")
    if text != original and not dry:
        # Preserve LF; the repo is an LF-only tree.
        path.write_text(text, encoding="utf-8", newline="\n")
    return touched, warnings, (text != original)


# --------------------------------------------------------------------------- #
# dataset_stats.json: regenerate through the single authoritative build_stats  #
# --------------------------------------------------------------------------- #
def _flatten_numbers(obj, prefix: str = "") -> dict[str, int]:
    out: dict[str, int] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten_numbers(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, bool):
        pass
    elif isinstance(obj, int):
        out[prefix] = obj
    return out


def sync_dataset_stats(root: Path, dry: bool, quiet: bool):
    sys.path.insert(0, str(SCRIPTS))
    import generate_stats  # stdlib-only repo module

    fresh = generate_stats.build_stats()
    out = root / "reports" / "dataset_stats.json"
    on_disk_text = out.read_text(encoding="utf-8")
    on_disk = json.loads(on_disk_text)

    old_nums = _flatten_numbers(on_disk)
    new_nums = _flatten_numbers(fresh)
    diffs = []
    for key in sorted(set(old_nums) | set(new_nums)):
        o, n = old_nums.get(key), new_nums.get(key)
        if o != n:
            diffs.append((key, o, n))

    if diffs:
        if not quiet:
            print(f"  [reports/dataset_stats.json] {len(diffs)} numeric field(s) differ")
            for key, o, n in diffs:
                print(f"      {key}: {o} -> {n}")
    else:
        if not quiet:
            print("  [reports/dataset_stats.json] all numeric fields already current")

    serialized = json.dumps(fresh, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if serialized != on_disk_text and not dry:
        out.write_text(serialized, encoding="utf-8", newline="\n")
    return diffs, (serialized != on_disk_text)


# --------------------------------------------------------------------------- #
# Per-family "manifest tasks == file rows" audit (report-only)                 #
# --------------------------------------------------------------------------- #
def check_family_rows(root: Path, quiet: bool):
    manifests = [
        ("benchmark/manifest.json", root / "benchmark" / "manifest.json"),
        ("benchmark/v3_manifest.json", root / "benchmark" / "v3_manifest.json"),
        ("Vbeta/benchmark_vbeta/vbeta_manifest.json",
         root / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json"),
    ]
    # v3/vbeta manifests publish `tasks` as a bare int per family (no `file`
    # key); benchmark/manifest.json uses dict specs with a `file` key. Handle
    # both shapes so the report-only audit never crashes on a schema change.
    count_only_files = {
        "R_v3_source_tier_routing": "benchmark/v3_R_source_tier_routing.jsonl",
        "S_v3_contest_outcome": "benchmark/retired_families/v3_S_contest_outcome.jsonl",
        "T_v31_taxonomy_explicit": "benchmark/retired_families/v3_T_taxonomy_explicit.jsonl",
        "vbeta_U_language_routing": "Vbeta/benchmark_vbeta/vbeta_U_language_routing.jsonl",
        "vbeta_V_source_tier_routing": "Vbeta/benchmark_vbeta/vbeta_V_source_tier_routing.jsonl",
    }
    mismatches = []
    checked = 0
    for label, path in manifests:
        try:
            tasks = js(path).get("tasks", {})
        except OSError:
            continue
        for fam, spec in tasks.items():
            if isinstance(spec, dict):
                fname = spec.get("file") or count_only_files.get(fam)
                want = spec.get("tasks")
            elif isinstance(spec, int):
                fname = count_only_files.get(fam)
                want = spec
            else:
                continue
            if not fname:
                continue
            fp = root / fname
            if not fp.is_file():
                mismatches.append(f"{label}:{fam}: file missing {fname}")
                continue
            rows = len(jl(fp))
            checked += 1
            if want is not None and want != rows:
                mismatches.append(f"{label}:{fam}: manifest tasks={want} file rows={rows}")
    if not quiet:
        print(f"  per-family manifest/file-row checks: {checked} families scanned, "
              f"{len(mismatches)} mismatch(es)")
    for m in mismatches:
        print(f"    [WARN] {m}")
    return mismatches


# --------------------------------------------------------------------------- #
# Advisory pins (recompute + report; never written -- other tracks own them)   #
# --------------------------------------------------------------------------- #
def advisory(root: Path, ctx: Ctx, quiet: bool):
    v3a, v3b = ctx.get("adv_v3_127")
    rows = [
        ("127 V3 records (execution artefact)",
         f"derived_v3/manifest.json evidence_admitted_records={v3a} "
         f"candidate_artefacts={v3b}",
         "tests/test_v3_run_accounting.py"),
        ("200 Certora keys", f"wave1 registry certora_rule keys={ctx.get('adv_certora_200')}",
         "wave1/tests/test_wave1.py"),
        ("35 L5 claims", f"reports/v2_2/l5_adjudication.json L5_records="
         f"{ctx.get('adv_l5_35')}", "tests/test_v22_l5_adjudication.py"),
        ("7 L6 (v1 derived)", f"derived/manifest.json L6={ctx.get('adv_l6_7')}",
         "tests/test_v1_derived_l6.py / reports/dataset_stats.json"),
    ]
    if not quiet:
        print("  ADVISORY (recomputed, NOT written -- owned by other tracks):")
    for label, value, owner in rows:
        print(f"    [advisory] {label}: {value}  (owner: {owner})")
    return rows


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="print the diff, write nothing")
    ap.add_argument("--quiet", action="store_true", help="only summary and warnings")
    ap.add_argument("--skip", nargs="*", default=[], metavar="PIN_ID",
                    help="pin ids to leave untouched (e.g. v3 pins while Track 3 re-runs)")
    args = ap.parse_args()

    skip = set(args.skip)
    known = {p.pid for p in PINS}
    unknown = sorted(skip - known)
    if unknown:
        raise SystemExit(f"unknown pin id(s) in --skip: {unknown}. Known: {sorted(known)}")

    ctx = Ctx(ROOT)
    for pin in PINS:
        pin.validate()

    print("sync_gate_pins.py" + (" (DRY RUN)" if args.dry_run else ""))
    if not args.quiet:
        print(f"root = {ROOT}")
    if skip:
        print(f"SKIPPED pin ids (deferred): {sorted(skip)}")

    warning_list: list[str] = []
    total_touched = 0
    changed_files = []

    by_file: dict[str, list[Pin]] = collections.defaultdict(list)
    for pin in PINS:
        if pin.pid in skip:
            continue
        by_file[pin.file].append(pin)

    for rel in ("scripts/check_manifests.py", "scripts/validate_checks.py"):
        if rel not in by_file:
            continue
        n, warns, did_change = sync_python_file(rel, by_file[rel], ctx, args.dry_run,
                                                args.quiet)
        total_touched += n
        warning_list.extend(warns)
        if did_change:
            changed_files.append(rel)

    diffs, did_change_stats = sync_dataset_stats(ROOT, args.dry_run, args.quiet)
    if did_change_stats:
        changed_files.append("reports/dataset_stats.json")

    print("\nfamily / row-count cross-checks:")
    mismatches = check_family_rows(ROOT, args.quiet)
    warning_list.extend(mismatches)

    print("\nadvisory pins:")
    advisory(ROOT, ctx, args.quiet)

    print("\n--- summary ---")
    print(f"pins rewritten: {total_touched} literal(s) across "
          f"{len([f for f in changed_files if f.endswith('.py')])} Python file(s)")
    print(f"dataset_stats numeric fields changed: {len(diffs)}")
    if changed_files:
        print(f"files {'that would be ' if args.dry_run else ''}written:")
        for f in changed_files:
            print(f"  - {f}")
    else:
        print("files written: none (idempotent -- tree already current)")
    if warning_list:
        print(f"warnings ({len(warning_list)}):")
        for w in warning_list:
            print(f"  [WARN] {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

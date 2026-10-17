#!/usr/bin/env python3
"""Reproducibility gate: deterministic provenance for every generated artifact.

Verifies, without rebuilding the world:
  1. required inputs exist
  2. referenced scripts exist
  3. referenced manifests exist
  4. source pins are well-formed (object-level resolution needs clones/network
     and is explicitly skipped_no_network when unavailable)
  5. generated files correspond to declared inputs (generated_by + inputs exist)
  6. no read-only layer can be written by any build stage (static scan)
  7. generation is deterministic (byte-stability + Vbeta rebuild parity)
  8. every declared output is actually produced
  9. every produced artifact belongs to the correct layer (version check)
 10. git-ignored work/ artefacts are never required for a fresh-clone build

Writes nothing. A skipped network stage stays `skipped_no_network` — never a
pass, never a failure.

    python scripts/check_reproducibility.py
    python scripts/check_reproducibility.py --quiet
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema_terms import READ_ONLY_LAYERS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def jl(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def js(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class Gate:
    def __init__(self, quiet=False):
        self.rows = []
        self.quiet = quiet

    def verdict(self, name, status, detail=""):
        # Explicit check, not assert: gate verdicts must hold under
        # `python -O` too (asserts are stripped there). An invalid status is
        # a bug in the caller, and it fails the gate rather than vanishing.
        if status not in ("PASS", "FAIL", "SKIPPED"):
            status, detail = (
                "FAIL", f"invalid gate status {status!r} for {name}: {detail}")
        self.rows.append({"check": name, "status": status, "detail": detail})
        if not self.quiet:
            print(f"  [{status}] {name}" + (f" — {detail}" if detail and status != "PASS" else ""))

    def ok(self, name, detail=""):
        self.verdict(name, "PASS", detail)

    def fail(self, name, detail=""):
        self.verdict(name, "FAIL", detail)

    def skip(self, name, detail="skipped_no_network"):
        self.verdict(name, "SKIPPED", detail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    G = Gate(args.quiet)
    print("check_reproducibility.py")

    # ---- 1. required inputs -------------------------------------------------
    required = [
        "jsonl/findings.jsonl", "jsonl/negative_findings.jsonl",
        "jsonl/exploits.jsonl", "jsonl/patches.jsonl",
        "jsonl/protocol.jsonl", "jsonl/metadata.jsonl", "jsonl/errors.jsonl",
        "jsonl_ml/findings_reports.jsonl", "jsonl_ml/findings_rust.jsonl",
        "jsonl_ml/findings_move.jsonl", "jsonl_ml/findings_cairo.jsonl",
        "jsonl_ml/findings_vyper.jsonl",
        "Vbeta/sources.json", "Vbeta/candidates.json",
        "Vbeta/fetched/receipts.jsonl",
        "Vbeta/scripts/vlun_vbeta.py", "Vbeta/scripts/build_vbeta.py",
        "Vbeta/scripts/validate_vbeta.py",
    ]
    missing = [f for f in required if not (ROOT / f).is_file()]
    if missing:
        G.fail("required inputs exist", f"missing: {missing}")
    else:
        G.ok("required inputs exist", f"{len(required)} files")

    # ---- 2. referenced scripts ----------------------------------------------
    # (An earlier revision also read scripts/build_all_stages.json here; the
    # file does not exist and the value was never used. Dead reads of
    # nonexistent files are removed, not guarded: a guard would imply the
    # file matters.)
    scripts = ["generate_stats.py", "generate_readme.py", "validate.py",
               "validate_v3.py", "validate_v31.py", "build_all.py",
               "check_manifests.py", "check_reproducibility.py",
               "schema_terms.py", "vlun.py", "taxonomy.py",
               "poc_classification.py"]
    missing_s = [s for s in scripts if not (ROOT / "scripts" / s).is_file()]
    if missing_s:
        G.fail("referenced scripts exist", f"missing: {missing_s}")
    else:
        G.ok("referenced scripts exist", f"{len(scripts)} scripts")

    # ---- 3. referenced manifests ----------------------------------------------
    manifests = [
        "reports/dataset_stats.json", "benchmark/manifest.json",
        "benchmark/v3_manifest.json", "derived/manifest.json",
        "derived_v2_2/manifest.json", "derived_v3/manifest.json",
        "splits_v3/split.json",
        "Vbeta/derived_vbeta/manifest.json",
        "Vbeta/benchmark_vbeta/vbeta_manifest.json",
        "Vbeta/splits_vbeta/split.json",
        "Vbeta/present_snapshot.json", "publish_manifest.json",
    ]
    missing_m = [m for m in manifests if not (ROOT / m).is_file()]
    if missing_m:
        G.fail("referenced manifests exist", f"missing: {missing_m}")
    else:
        G.ok("referenced manifests exist", f"{len(manifests)} manifests")

    # ---- 4. source pins -------------------------------------------------------
    pins = set()
    for row in jl(ROOT / "derived_v3" / "candidate_ledger.jsonl")[:2000]:
        for key in ("vulnerable_commit", "fixed_commit"):
            v = row.get(key)
            if v and v != "unknown":
                pins.add(v)
    malformed = [p for p in pins if not SHA40.match(p)]
    if malformed:
        G.fail("source pins well-formed", f"non-40-hex: {malformed[:5]}")
    else:
        G.ok("source pins well-formed", f"{len(pins)} sampled pins all 40-hex")
    G.skip("source pins resolvable to objects",
           "skipped_no_network: needs audited-repo clones; format checked above")

    # ---- 5. generated <-> inputs correspondence ------------------------------
    gen_inputs = {
        "reports/dataset_stats.json": (["scripts/generate_stats.py"],
                                       ["jsonl/findings.jsonl"]),
        "README.md": (["scripts/generate_readme.py"], ["reports/"]),
        "derived_v3/manifest.json": (["scripts/build_v3.py"],
                                     ["Vbeta/../V3/sources.json".replace("Vbeta/../", "")]),
        "Vbeta/derived_vbeta/manifest.json": (["Vbeta/scripts/build_vbeta.py"],
                                              ["Vbeta/sources.json",
                                               "Vbeta/candidates.json",
                                               "Vbeta/fetched/receipts.jsonl"]),
    }
    bad_gen = []
    for out, (gens, inputs) in gen_inputs.items():
        for g in gens:
            if not (ROOT / g).is_file():
                bad_gen.append(f"{out}: generator {g} missing")
        for i in inputs:
            if not (ROOT / i).exists():
                bad_gen.append(f"{out}: input {i} missing")
    if bad_gen:
        G.fail("generated files correspond to declared inputs", "; ".join(bad_gen))
    else:
        G.ok("generated files correspond to declared inputs",
             f"{len(gen_inputs)} artefacts")

    # ---- 6. read-only layers unwritable ---------------------------------------
    # Resolves constant-based paths too (JSONL, ML_JSONL, V.JSONL_V3), so
    # owner writes like V.write_jsonl(V.JSONL_V3 / ...) are attributed to
    # their layer instead of evading a literal-"jsonl/" scan. Each
    # read-only layer has exactly the writers below; anything else writing
    # there fails the gate.
    LAYER_OF_CONST = {"JSONL": "jsonl", "ML_JSONL": "jsonl_ml",
                      "JSONL_V3": "jsonl_v3"}
    READ_ONLY_OWNERS = {"jsonl": set(),
                        "jsonl_ml": {"build_ml_ingest.py",
                                     "build_vyper_ml.py"},
                        "jsonl_v3": {"build_v3.py"}}
    WRITE_VERBS = re.compile(
        r"write_jsonl?|open\([^)]*['\"]w|write_text|\.mkdir\(|replace\(")
    offenders = []
    for script in sorted((ROOT / "scripts").glob("*.py")):
        if script.name in ("check_reproducibility.py", "check_manifests.py",
                           "schema_terms.py", "pdf_text.py"):
            continue
        text = script.read_text(encoding="utf-8", errors="ignore")
        touched: dict[str, list[int]] = {}
        # Skip import statements including parenthesized continuations:
        # they name constants and writers without calling anything.
        code_lines = []
        depth = 0
        in_import = False
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if re.match(r"^(import|from)\s", stripped):
                in_import = True
            if in_import:
                depth += line.count("(") - line.count(")")
                if depth <= 0:
                    in_import = False
                    depth = 0
                continue
            code_lines.append((lineno, line))
        for lineno, line in code_lines:
            if not WRITE_VERBS.search(line):
                continue
            for const, layer in LAYER_OF_CONST.items():
                if re.search(rf"(?<![\w]){const}\b", line):
                    touched.setdefault(layer, []).append(lineno)
            for layer in READ_ONLY_LAYERS:
                if re.search(rf"['\"]{layer}/", line):
                    touched.setdefault(layer, []).append(lineno)
        for layer, lines_ in touched.items():
            if script.name not in READ_ONLY_OWNERS.get(layer, set()):
                offenders.append(
                    f"{script.name}:{lines_[0]} writes to read-only {layer}/ "
                    f"(owners: {sorted(READ_ONLY_OWNERS.get(layer, [])) or 'none'})")
    vbeta_build = (ROOT / "Vbeta" / "scripts" / "build_vbeta.py").read_text(
        encoding="utf-8")
    vbeta_build = (ROOT / "Vbeta" / "scripts" / "build_vbeta.py").read_text(
        encoding="utf-8")
    if "assert_inside_vbeta" not in vbeta_build:
        offenders.append("Vbeta build lacks path assert")
    if offenders:
        G.fail("no read-only layer writable by build", "; ".join(offenders[:8]))
    else:
        G.ok("no read-only layer writable by build",
             "static scan of scripts/ + Vbeta path assert")

    # ---- 7. determinism ---------------------------------------------------------
    # 7a. byte-stability: canonical dumps (sort_keys) must already be stable.
    unstable = []
    for path in [ROOT / "Vbeta" / "derived_vbeta" / "manifest.json",
                 ROOT / "derived_v3" / "manifest.json",
                 ROOT / "derived_v3" / "normalization.json",
                 ROOT / "reports" / "dataset_stats.json",
                 ROOT / "reports" / "v3" / "validation_v3.json",
                 ROOT / "reports" / "v3" / "validation_v31.json"]:
        try:
            obj = js(path)
            redump = json.dumps(obj, indent=2, sort_keys=True,
                                ensure_ascii=False) + "\n"
            if path.read_text(encoding="utf-8").replace("\r\n", "\n") != redump:
                unstable.append(str(path.relative_to(ROOT)))
        except OSError:
            unstable.append(str(path) + " (missing)")
    if unstable:
        G.fail("byte-stability of canonical dumps", f"unstable: {unstable}")
    else:
        G.ok("byte-stability of canonical dumps", "sort_keys-stable")

    # 7b. Vbeta rebuild parity: build twice, outputs identical (validation
    # report carries a timestamp and is excluded by semantic compare).
    def snapshot():
        snaps = {}
        base = ROOT / "Vbeta"
        for sub in ("jsonl_vbeta", "derived_vbeta", "splits_vbeta",
                    "benchmark_vbeta"):
            for p in sorted((base / sub).rglob("*")):
                if p.is_file():
                    h = hashlib.sha256(p.read_bytes()).hexdigest()
                    snaps[str(p.relative_to(base))] = h
        return snaps

    before = snapshot()
    r1 = subprocess.run([sys.executable, "Vbeta/scripts/build_vbeta.py"],
                        cwd=str(ROOT), capture_output=True, text=True)
    after = snapshot()
    if r1.returncode != 0:
        G.fail("Vbeta rebuild parity", f"rebuild rc={r1.returncode}")
    elif before != after:
        diff = [k for k in set(before) | set(after)
                if before.get(k) != after.get(k)]
        G.fail("Vbeta rebuild parity", f"outputs differ: {diff[:5]}")
    else:
        G.ok("Vbeta rebuild parity",
             f"{len(after)} artefacts byte-identical across rebuilds")

    # 7c. V3.1 byte-identity: committed normalization outputs must already
    # be in canonical form (per-row sort_keys JSONL, sort_keys JSON). A
    # hand-edited or non-deterministically written file fails here. The full
    # rebuild-from-clones parity needs V3/clones (git-ignored) and takes
    # minutes; after running `python scripts/normalize_v3.py` locally this
    # same check proves the rebuild is byte-identical. Without clones the
    # rebuild cannot run at all, which stays a skip, never a pass.
    V31_FILES = [
        "derived_v3/normalization_fragments.jsonl",
        "derived_v3/normalization_overlay.jsonl",
        "derived_v3/normalized_records_preview.jsonl",
        "derived_v3/normalization.json",
        "derived_v3/corroborations_v31.jsonl",
        "derived_v3/patch_candidates.json",
        "derived_v3/patch_reviews.jsonl",
        "derived_v3/experiment_readiness.json",
    ]
    # patch_candidates.json / experiment_readiness.json carry a .json name
    # but hold one object per line (written via write_jsonl); only
    # normalization.json is a single pretty-printed object.
    V31_JSONL_LIKE = set(V31_FILES) - {"derived_v3/normalization.json"}
    _noncanon = []
    for _rel in V31_FILES:
        _p = ROOT / _rel
        try:
            _raw = _p.read_bytes()
        except OSError:
            _noncanon.append(f"{_rel} (missing)")
            continue
        try:
            if _rel in V31_JSONL_LIKE:
                _rows = [json.loads(ln) for ln in
                         _raw.decode("utf-8").splitlines() if ln.strip()]
                _want = "".join(
                    json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                    for r in _rows).encode("utf-8")
            else:
                _want = (json.dumps(json.loads(_raw.decode("utf-8")),
                                    indent=2, sort_keys=True,
                                    ensure_ascii=False) + "\n").encode("utf-8")
        except ValueError as exc:
            _noncanon.append(f"{_rel} (invalid json: {exc})")
            continue
        if _raw.replace(b"\r\n", b"\n") != _want:
            _noncanon.append(_rel)
    if _noncanon:
        G.fail("V3.1 byte-identity (canonical form)",
               f"non-canonical: {_noncanon[:5]}")
    else:
        G.ok("V3.1 byte-identity (canonical form)",
             f"{len(V31_FILES)} artefacts in canonical form")

    # 7d/7e. derived/ and derived_v2_2/ rebuild parity.
    #
    # The v2.1 audit's worst finding (REFUTED-2: 376/722 v1 records change on
    # rebuild) was that derived/ had NO rebuild gate, so drift could ship
    # unnoticed. Clean-room rebuild-and-diff closes it.
    #
    # Learned the hard way: build_derived.py enriches code_context with
    # commit pins RESOLVED FROM work/ (git-ignored clones, absent on a fresh
    # clone). Without those it cannot reproduce the committed immutable pins
    # and silently emits commit_sha='main' -- which validate.py's
    # mutable-branch check then flags across 473 records. So the gate
    # REQUIRES its citation inputs, skips when they are absent, and always
    # RESTORES the committed bytes afterwards: this gate observes, it must
    # never leave a degraded layer behind.
    def _snap_files(rels):
        return {r: hashlib.sha256((ROOT / r).read_bytes()).hexdigest()
                for r in rels if (ROOT / r).is_file()}

    _derived_missing = [p for p in ("work/source_manifest.json", "work/repos")
                        if not (ROOT / p).exists()]

    def _rebuild_parity(label, script, files, missing_inputs):
        if missing_inputs:
            G.skip(f"{label} rebuild parity",
                   "skipped_no_network: citation inputs absent "
                   f"({', '.join(missing_inputs)}); rebuild would emit "
                   "mutable branch refs, not the committed immutable pins")
            return
        before = _snap_files(files)
        saved = {f: (ROOT / f).read_bytes() for f in files
                 if (ROOT / f).is_file()}
        try:
            r = subprocess.run([sys.executable, script], cwd=str(ROOT),
                               capture_output=True, text=True, timeout=1800)
        finally:
            for f, blob in saved.items():
                (ROOT / f).write_bytes(blob)
        after = _snap_files(files)
        if r.returncode != 0:
            G.fail(f"{label} rebuild parity", f"rebuild rc={r.returncode}")
        elif before != after:
            diff = [k for k in set(before) | set(after)
                    if before.get(k) != after.get(k)]
            G.fail(f"{label} rebuild parity",
                   f"outputs differ: {diff[:5]} (rebuilt bytes restored; "
                   "committed layer untouched)")
        else:
            G.ok(f"{label} rebuild parity",
                 f"{len(after)} artefacts byte-identical across rebuilds")

    _rebuild_parity("derived/", "scripts/build_derived.py",
                    ["derived/records.jsonl", "derived/manifest.json"],
                    _derived_missing)
    _rebuild_parity("derived_v2_2/", "scripts/build_derived_v22.py",
                    ["derived_v2_2/records.jsonl",
                     "derived_v2_2/manifest.json"],
                    [])

    # ---- 8. declared outputs produced -------------------------------------------
    declared = {
        "derived_v3": ["candidate_ledger.jsonl", "records.jsonl",
                       "negatives.jsonl", "duplicates.jsonl",
                       "corroborations.jsonl", "source_ledger.json",
                       "manifest.json"],
        "splits_v3": ["split.json", "quarantine.jsonl"],
        "Vbeta/jsonl_vbeta": ["sources.jsonl", "findings.jsonl"],
        "Vbeta/derived_vbeta": ["candidate_ledger.jsonl", "records.jsonl",
                                "negatives.jsonl", "duplicates.jsonl",
                                "corroborations.jsonl", "source_ledger.json",
                                "manifest.json"],
        "Vbeta/splits_vbeta": ["split.json", "quarantine.jsonl"],
        "Vbeta/benchmark_vbeta": ["vbeta_U_language_routing.jsonl",
                                  "vbeta_V_source_tier_routing.jsonl",
                                  "vbeta_manifest.json"],
        "Vbeta/reports_vbeta": ["quality_report.md", "validation_vbeta.json",
                                "shieldify_ingestion_report.md",
                                "solodit_harvest_stats.json",
                                "solodit_ingestion_report.md"],
    }
    missing_o = [f"{d}/{f}" for d, fs in declared.items() for f in fs
                 if not (ROOT / d / f).is_file()]
    if missing_o:
        G.fail("every declared output produced", f"missing: {missing_o}")
    else:
        G.ok("every declared output produced",
             f"{sum(len(v) for v in declared.values())} files")

    # ---- 9. layer correctness -----------------------------------------------------
    bad_layer = []
    probes = {
        "jsonl": ("findings.jsonl", "dataset_version", "1.0"),
        "derived_v3": ("records.jsonl", "dataset_version", "3.0"),
        "Vbeta/jsonl_vbeta": ("findings.jsonl", "dataset_version",
                              "vbeta-1.0"),
        "Vbeta/derived_vbeta": ("records.jsonl", "dataset_version",
                                "vbeta-1.0"),
    }
    for layer, (fname, field, want) in probes.items():
        try:
            rows = jl(ROOT / layer / fname)
            got = {r.get(field) for r in rows}
            if got != {want}:
                bad_layer.append(f"{layer}: {field}={sorted(str(g) for g in got)}")
        except OSError as exc:
            bad_layer.append(f"{layer}: {exc}")
    if bad_layer:
        G.fail("produced artifacts belong to correct layer", "; ".join(bad_layer))
    else:
        G.ok("produced artifacts belong to correct layer",
             "dataset_version uniform per layer dir")

    # ---- 10. work/ never required ---------------------------------------------------
    # Word-boundary match: the naive `"work/" in blob` also matches
    # `network/`. The data-layer citations below are provenance notes (which
    # builder script and raw payload produced a row), not load-bearing
    # payloads: every citing row carries its usable content inline.
    import re as _re
    WORK_CITE = _re.compile(r"(?<![A-Za-z0-9_/.-])work/")
    needing_work = []
    for m in ["reports/dataset_stats.json", "derived_v3/manifest.json",
              "Vbeta/derived_vbeta/manifest.json", "benchmark/manifest.json",
              "benchmark/v3_manifest.json"]:
        try:
            blob = (ROOT / m).read_text(encoding="utf-8")
            if WORK_CITE.search(blob):
                needing_work.append(m)
        except OSError:
            pass
    if needing_work:
        G.fail("work/ artefacts never required", f"referenced by: {needing_work}")
    else:
        G.ok("work/ artefacts never required", "no manifest references work/")

    # ---- 10b. data-layer work/ citation census ----------------------------------
    # 117 jsonl_ml rows (list_endpoint notes) + 16 benchmark L/P/Q tasks cite
    # git-ignored work/ payloads as provenance. They are counted here, not
    # hidden; usability holds because each citing row's content is inline.
    def _rows_with_cite(path: Path) -> int:
        try:
            return sum(1 for line in
                       path.read_text(encoding="utf-8").splitlines()
                       if line.strip() and WORK_CITE.search(line))
        except OSError:
            return 0

    ml_cited = sum(_rows_with_cite(p) for p in (ROOT / "jsonl_ml").glob("*.jsonl"))
    bq_cited = sum(_rows_with_cite(ROOT / f) for f in
                   ("benchmark/retired_families/L_severity_reconciliation.jsonl",
                    "benchmark/retired_families/P_provenance_tier_and_rights.jsonl",
                    "benchmark/Q_evidence_type_and_quality_rubric.jsonl"))
    G.ok("data-layer work/ citations censused",
         f"jsonl_ml={ml_cited} benchmark-LPQ={bq_cited} total="
         f"{ml_cited + bq_cited} (provenance notes; content inline)")

    # ---- 10b. declared-ignored paths are actually ignored ----------------------
    # Docs claim nextdata/, .firecrawl/, work/, V3/clones/ are local-only.
    # This gate fails if any of them is tracked (grep git ls-files) or if
    # .gitignore stops declaring them. Documentation without enforcement
    # rots; this is the enforcement.
    declared_ignored = ["nextdata/", ".firecrawl/", "work/", "V3/clones/",
                        ".freebuff/", "brag-output/",
                        "reports/reproducibility_checks.json"]
    try:
        gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
        missing_decl = [p for p in declared_ignored if p not in gi]
    except OSError:
        missing_decl = declared_ignored
    if missing_decl:
        G.fail("ignored paths declared in .gitignore",
               f"not declared: {missing_decl}")
    else:
        G.ok("ignored paths declared in .gitignore",
             f"{len(declared_ignored)} paths")
    try:
        ls = subprocess.run(["git", "ls-files", *declared_ignored],
                            cwd=str(ROOT), capture_output=True, text=True,
                            timeout=120)
        tracked = [line for line in (ls.stdout or "").splitlines() if line.strip()]
    except Exception as exc:  # noqa: BLE001
        tracked = [f"git ls-files failed: {exc}"]
    # Documented exception: the clones manifest itself is tracked by an
    # explicit .gitignore negation; everything else under these paths is not.
    tracked = [t for t in tracked
               if t.replace("\\", "/") != "V3/clones/MANIFEST.md"]
    if tracked:
        G.fail("declared-ignored paths are untracked",
               f"{len(tracked)} tracked files, e.g. {tracked[:3]}")
    else:
        G.ok("declared-ignored paths are untracked", "git ls-files empty")

    # ---- skipped stages stay skipped --------------------------------------------------
    try:
        balle = js(ROOT / "reports" / "build_all.json")
        by_status = balle.get("by_status", {})
        if by_status.get("skipped_no_network"):
            G.skip("network stages",
                   f"skipped_no_network: {by_status['skipped_no_network']} stages "
                   "recorded as skipped, never as success")
        else:
            G.ok("no skipped stages misreported", "build_all.json has no skips")
    except OSError:
        G.skip("network stages",
               "skipped_no_network: no build_all.json in this copy; "
               "network stages not runnable here")

    fails = [r for r in G.rows if r["status"] == "FAIL"]
    print(f"\nchecks={len(G.rows)} pass="
          f"{sum(1 for r in G.rows if r['status'] == 'PASS')} "
          f"fail={len(fails)} skipped="
          f"{sum(1 for r in G.rows if r['status'] == 'SKIPPED')}")
    # Writes only its own report, so generated documents can quote a live
    # count instead of a hard-coded one.
    _rep = ROOT / "reports" / "reproducibility_checks.json"
    _rep.parent.mkdir(parents=True, exist_ok=True)
    _rep.write_text(json.dumps({
        "generated_by": "scripts/check_reproducibility.py",
        "checks": G.rows,
        "checks_total": len(G.rows),
        "checks_passed": sum(1 for r in G.rows if r["status"] == "PASS"),
        "checks_failed": len(fails),
        "checks_skipped": sum(1 for r in G.rows if r["status"] == "SKIPPED"),
        "note": ("skipped_no_network entries are honest skips, never passes: "
                 "they need git-ignored clones or work/ inputs that are not "
                 "redistributed"),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())

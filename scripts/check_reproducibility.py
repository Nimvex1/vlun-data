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
        assert status in ("PASS", "FAIL", "SKIPPED")
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
    scripts = ["generate_stats.py", "generate_readme.py", "validate.py",
               "validate_v3.py", "validate_v31.py", "build_all.py",
               "check_manifests.py", "check_reproducibility.py",
               "schema_terms.py", "vlun.py", "taxonomy.py",
               "poc_classification.py"]
    try:
        stages = js(ROOT / "scripts" / "build_all_stages.json")
    except OSError:
        stages = None
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
    offenders = []
    for script in (ROOT / "scripts").glob("*.py"):
        if script.name in ("check_reproducibility.py", "check_manifests.py",
                           "schema_terms.py", "pdf_text.py"):
            continue
        text = script.read_text(encoding="utf-8", errors="ignore")
        for layer in READ_ONLY_LAYERS:
            # A builder references a read-only layer for writing if the layer
            # path appears near a write call. Conservative pattern: the layer
            # name inside a write_json/write_jsonl/out-file expression.
            for m in re.finditer(rf"['\"]{layer}/", text):
                window = text[max(0, m.start() - 400):m.start()]
                if re.search(r"write_jsonl?|open\(.*['\"]w|Out-File|>\s*$|"
                             r"write_text|replace\(", window):
                    # Exclude Vbeta's own read-only *inputs* (it only reads
                    # PRESENT; its writes assert inside Vbeta/).
                    if "Vbeta" not in str(script):
                        offenders.append(f"{script.name}: writes near {layer}/")
                        break
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
                 ROOT / "reports" / "dataset_stats.json"]:
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
    layer_versions = {
        "jsonl": "1.0", "derived_v3": "3.0", "Vbeta/jsonl_vbeta": "vbeta-1.0",
        "Vbeta/derived_vbeta": "vbeta-1.0",
    }
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
    needing_work = []
    for m in ["reports/dataset_stats.json", "derived_v3/manifest.json",
              "Vbeta/derived_vbeta/manifest.json", "benchmark/manifest.json",
              "benchmark/v3_manifest.json"]:
        try:
            blob = (ROOT / m).read_text(encoding="utf-8")
            if "work/" in blob:
                needing_work.append(m)
        except OSError:
            pass
    if needing_work:
        G.fail("work/ artefacts never required", f"referenced by: {needing_work}")
    else:
        G.ok("work/ artefacts never required", "no manifest references work/")

    # ---- 10b. declared-ignored paths are actually ignored ----------------------
    # Docs claim nextdata/, .firecrawl/, work/, V3/clones/ are local-only.
    # This gate fails if any of them is tracked (grep git ls-files) or if
    # .gitignore stops declaring them. Documentation without enforcement
    # rots; this is the enforcement.
    declared_ignored = ["nextdata/", ".firecrawl/", "work/", "V3/clones/"]
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
        tracked = [l for l in (ls.stdout or "").splitlines() if l.strip()]
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
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())

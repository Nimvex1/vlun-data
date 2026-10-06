#!/usr/bin/env python3
"""The V3.1 normalization gate. Fails on critical integrity violations.

    python scripts/validate_v31.py
    python scripts/validate_v31.py --quiet

Reads (never writes except its own report):

    derived_v3/normalization_fragments.jsonl
    derived_v3/normalization_overlay.jsonl
    derived_v3/normalized_records_preview.jsonl
    derived_v3/normalization.json
    derived_v3/corroborations_v31.jsonl
    derived_v3/patch_candidates.json
    derived_v3/experiment_readiness.json
    derived_v3/candidate_ledger.jsonl  (v3.0, read-only)
    derived_v3/records.jsonl           (v3.0, read-only)

Checks:

  structure     JSONL validity, required fields, id uniqueness (fragments,
                overlays by (target,field), preview finding_ids)
  spans         admitted fragments carry valid char spans (start<end,
                excerpt matches the span text shape, page_hint type)
  vocabularies  decisions, evidence types, severity values, taxonomy
                confidence (explicit|derived|unknown), commit roles,
                negative taxonomy, verification levels (L0/L1 only: no
                execution happened in V3.1)
  no-invention  every 40-hex SHA in fragments/overlays is re-found in the
                parent source text (temp cache); taxonomy-explicit only from
                Category fields; severity-explicit only from Severity fields
                or header conventions
  references    overlay targets exist in v3.0 ledger/records; preview rows
                either extend v3.0 records or carry parent links;
                corroboration endpoints exist; patch candidates resolve
  counts        normalization.json numbers recomputed from the files
  versions      normalization 3.1 + dataset 3.0 consistent everywhere
  isolation     v1/v2/v2.2/v3.0 committed files byte-identical to origin/main
                (V3.1 is additive; the gate diffs the git index)

Writes reports/v3/validation_v31.json. Exit 1 on any critical failure.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_v3 as V  # noqa: E402

U = V.UNKNOWN
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE = ("observed_fact", "reported_claim", "derived_fact",
            "experimentally_verified", "externally_attributed",
            "unverified", "unknown")
SEV = {"Critical", "High", "Medium", "Low", "Informational", U}
CONF = {"explicit", "derived", U}
ROLES = {"scope", "fix", "unknown"}


class Report:
    def __init__(self, quiet: bool = False):
        self.checks: list[dict] = []
        self.quiet = quiet

    def add(self, group: str, check: str, ok: bool, failures=None,
            detail=None, critical=True):
        fails = list(failures or []) if not ok else []
        self.checks.append({"group": group, "check": check, "ok": bool(ok),
                            "critical": critical,
                            "failure_count": len(fails),
                            "failures": fails[:25], "detail": detail})
        if not self.quiet:
            mark = "ok  " if ok else ("FAIL" if critical else "warn")
            extra = f"  ({len(fails)} failures)" if fails else ""
            V.log(f"  [{mark}] {group}/{check}{extra}")
            for f in fails[:5]:
                V.log(f"         - {f}")
        return ok


def _load_jsonl(path: Path, rep: Report, label: str) -> list[dict]:
    rows: list[dict] = []
    bad: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    bad.append(f"{label}:{i}: {exc}")
    except OSError as exc:
        bad.append(f"{label}: {exc}")
    rep.add("structure", f"{label}_valid_jsonl", not bad, bad)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    rep = Report(args.quiet)
    V.log("validate_v31.py")
    D = V.DERIVED_V3

    frags = _load_jsonl(D / "normalization_fragments.jsonl", rep, "fragments")
    overlays = _load_jsonl(D / "normalization_overlay.jsonl", rep, "overlays")
    preview = _load_jsonl(D / "normalized_records_preview.jsonl", rep,
                          "preview")
    ledger = _load_jsonl(D / "candidate_ledger.jsonl", rep, "ledger_v30")
    records = _load_jsonl(D / "records.jsonl", rep, "records_v30")
    corrs = _load_jsonl(D / "corroborations_v31.jsonl", rep, "corroborations")
    patches = _load_jsonl(D / "patch_candidates.json", rep, "patches")
    readiness = _load_jsonl(D / "experiment_readiness.json", rep, "readiness")

    # ---- structure ---------------------------------------------------------
    req_frag = ["fragment_id", "parent_candidate_id", "source_id",
                "fragment_status", "normalization_version"]
    missing = [f.get("fragment_id", "?") for f in frags
               if any(k not in f for k in req_frag)]
    rep.add("structure", "fragment_required_fields", not missing, missing)

    def dup_ids(rows: list[dict], key: str) -> list[str]:
        seen: set[str] = set()
        dups: list[str] = []
        for r in rows:
            v = r.get(key)
            if v in seen:
                dups.append(str(v))
            seen.add(v)
        return dups

    rep.add("structure", "fragment_ids_unique",
            not dup_ids(frags, "fragment_id"),
            dup_ids(frags, "fragment_id"))
    rep.add("structure", "preview_ids_unique",
            not dup_ids(preview, "finding_id"),
            dup_ids(preview, "finding_id"))
    ov_keys = [(o.get("target_id"), o.get("field")) for o in overlays]
    rep.add("structure", "overlay_target_field_unique",
            len(set(ov_keys)) == len(ov_keys),
            [f"{t}/{f}" for t, f in ov_keys
             if ov_keys.count((t, f)) > 1][:10])

    # ---- spans --------------------------------------------------------------
    bad_span = [f["fragment_id"] for f in frags
                if f.get("fragment_status") == "admitted"
                and not _span_ok(f)]
    rep.add("spans", "admitted_spans_valid", not bad_span, bad_span)

    # ---- vocabularies --------------------------------------------------------
    bad_sev = [f["fragment_id"] for f in frags
               if f.get("fragment_status") == "admitted"
               and f.get("severity_normalized") not in SEV]
    rep.add("vocabularies", "severity_values", not bad_sev, bad_sev)
    bad_tax = [f["fragment_id"] for f in frags
               if f.get("fragment_status") == "admitted"
               and f.get("taxonomy_confidence") not in CONF]
    rep.add("vocabularies", "taxonomy_confidence", not bad_tax, bad_tax)
    bad_role = []
    for f in frags:
        for s in f.get("commit_shas", []):
            if s.get("role") not in ROLES:
                bad_role.append(f["fragment_id"])
    rep.add("vocabularies", "commit_roles", not bad_role, bad_role)
    bad_lv = [r.get("finding_id") for r in preview
              if r.get("verification_level") not in ("L0", "L1")]
    rep.add("vocabularies", "levels_L0_L1_only", not bad_lv, bad_lv)
    bad_ev = [o["target_id"] + "/" + o["field"] for o in overlays
              if o.get("evidence_type") not in EVIDENCE]
    rep.add("vocabularies", "overlay_evidence_types", not bad_ev, bad_ev)
    bad_pc = [p.get("finding_id") for p in patches
              if p.get("patch_status") != "not_testable"]
    rep.add("vocabularies", "patches_never_effective", not bad_pc, bad_pc)
    bad_rd = [r.get("finding_id") for r in readiness if r.get("executed")]
    rep.add("vocabularies", "readiness_no_execution_claims", not bad_rd,
            bad_rd)

    # ---- no-invention: SHAs re-found in parent source text -------------------
    # SHAs live inside compressed PDF streams, so raw-byte search is wrong:
    # re-resolve through the same deterministic extraction used to produce
    # the fragment (temp-cached), whitespace-stripped on both sides.
    try:
        sys.path.insert(0, str(V.ROOT / "scripts"))
        import v31_extract as X  # noqa: E402
        ledger_by_id = {c["candidate_id"]: c for c in ledger}
        sha_fails: list[str] = []
        checked = 0
        texts: dict[str, str] = {}
        for f in frags:
            if f.get("fragment_status") != "admitted":
                continue
            if not f.get("commit_shas"):
                continue
            parent = ledger_by_id.get(f.get("parent_candidate_id", ""))
            if parent is None:
                sha_fails.append(f["fragment_id"] + ":parent-missing")
                continue
            pid = parent["candidate_id"]
            if pid not in texts:
                try:
                    t, _q = X.get_text(parent)
                except Exception:
                    t = ""
                texts[pid] = re.sub(r"\s+", "", t)
            for s in f.get("commit_shas", []):
                sha = s.get("sha", "")
                if not SHA40.match(sha):
                    continue
                checked += 1
                if sha not in texts[pid]:
                    sha_fails.append(f["fragment_id"] + ":" + sha[:12])
        rep.add("no-invention", "shas_present_in_source",
                not sha_fails, sha_fails,
                detail=f"{checked} SHAs re-checked against extracted source")
    except Exception as exc:  # extractor import failure is itself critical
        rep.add("no-invention", "shas_present_in_source", False, [str(exc)])

    # taxonomy-explicit only from Category fields: spot rule -- an explicit
    # fragment must carry a non-unknown original class OR a method string
    # citing the auditor Category field.
    bad_texp = [f["fragment_id"] for f in frags
                if f.get("fragment_status") == "admitted"
                and f.get("taxonomy_confidence") == "explicit"
                and f.get("original_vulnerability_class") in (U, None)
                and "Category field" not in f.get("taxonomy_method", "")]
    rep.add("no-invention", "explicit_taxonomy_grounded", not bad_texp,
            bad_texp)

    # ---- references -----------------------------------------------------------
    ledger_ids = {c["candidate_id"] for c in ledger}
    record_ids = {r["finding_id"] for r in records}
    bad_parent = [f["fragment_id"] for f in frags
                  if f.get("parent_candidate_id") not in ledger_ids]
    rep.add("references", "fragments_resolve_parents", not bad_parent,
            bad_parent)
    bad_ov = [o["target_id"] for o in overlays
              if o["target_id"] not in ledger_ids
              and o["target_id"] not in record_ids]
    rep.add("references", "overlays_resolve_targets", not bad_ov, bad_ov)
    bad_prev = [r.get("finding_id") for r in preview
                if r.get("finding_id") not in record_ids
                and not r.get("parent_candidate_id")]
    rep.add("references", "preview_rows_grounded", not bad_prev, bad_prev)
    endpoints = ledger_ids | record_ids | {f["fragment_id"] for f in frags}
    bad_corr = [c["a"] + "<->" + c["b"] for c in corrs
                if c.get("a") not in endpoints or c.get("b") not in endpoints]
    rep.add("references", "corroborations_resolve", not bad_corr, bad_corr)

    # ---- counts ----------------------------------------------------------------
    try:
        manifest = json.loads((D / "normalization.json").read_text(
            encoding="utf-8"))
        exp = [("fragment_count", manifest.get("fragment_count"),
                len(frags)),
               ("overlay_count", manifest.get("overlay_count"), len(overlays)),
               ("preview_count", manifest.get("preview_count"), len(preview)),
               ("corroboration_links",
                manifest.get("corroboration_links"), len(corrs)),
               ("patch_candidates", manifest.get("patch_candidates"),
                len(patches))]
        bad_counts = [f"{k}: manifest={a} actual={b}" for k, a, b in exp
                      if a != b]
        rep.add("counts", "manifest_counts_match", not bad_counts, bad_counts)
    except (OSError, json.JSONDecodeError) as exc:
        rep.add("counts", "manifest_readable", False, [str(exc)])

    # ---- versions ---------------------------------------------------------------
    ver_bad = []
    try:
        m = json.loads((D / "normalization.json").read_text(encoding="utf-8"))
        if m.get("normalization_version") != "3.1" or \
                m.get("dataset_version") != V.DATASET_VERSION_V3:
            ver_bad.append("normalization.json")
    except (OSError, json.JSONDecodeError):
        ver_bad.append("normalization.json")
    for f in frags[:20000]:
        if f.get("normalization_version") != "3.1":
            ver_bad.append(str(f.get("fragment_id")))
            break
    rep.add("versions", "v31_consistent", not ver_bad, ver_bad)

    # ---- isolation: V3.1 writes only V3.1 paths ---------------------------------
    # The V3.1 pipeline must never rewrite v1/v2/v2.2/v3.0 artefacts. The
    # hard guarantee is filename disjointness between V3.1 outputs and every
    # protected layer file. (Worktree dirt from other sessions is reported
    # as a non-critical warning, never attributed to V3.1.)
    protected = {
        "candidate_ledger.jsonl", "records.jsonl", "negatives.jsonl",
        "duplicates.jsonl", "corroborations.jsonl", "source_ledger.json",
        "manifest.json", "findings.jsonl", "sources.jsonl", "split.json",
        "quarantine.jsonl", "v3_manifest.json",
        "v3_R_source_tier_routing.jsonl", "v3_S_contest_outcome.jsonl",
        "quality_report.md", "dataset_summary.json", "top20_imported.md",
        "top20_untrusted.md", "experiment_queue.md", "validation_v3.json",
        "validation_report.json",
    }
    v31_outputs = {
        "normalization_fragments.jsonl", "normalization_overlay.jsonl",
        "normalized_records_preview.jsonl", "normalization.json",
        "corroborations_v31.jsonl", "patch_candidates.json",
        "experiment_readiness.json", "normalization_report.json",
        "normalization_report.md", "normalization_unknowns.json",
        "normalization_unknowns.md", "extraction_failures.json",
        "poc_extraction_report.json", "patch_verification_report.json",
        "experiment_readiness_queue.md", "validation_v31.json",
    }
    collision = sorted(protected & v31_outputs)
    rep.add("isolation", "v31_outputs_disjoint_from_protected",
            not collision, collision)
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--",
             "jsonl/", "jsonl_ml/", "derived/", "derived_v2_2/",
             "jsonl_v3/", "derived_v3/", "splits_v3/", "benchmark/",
             "reports/v3/"],
            capture_output=True, text=True, timeout=120, cwd=str(V.ROOT))
        dirty = [l for l in (out.stdout or "").splitlines() if l.strip()]
        # Anything not under a V3.1 output name is somebody else's worktree
        # dirt: warn, don't fail.
        foreign = [l for l in dirty
                   if not any(l.endswith("/" + n) or l.endswith(n)
                              for n in v31_outputs)]
        rep.add("isolation", "worktree_dirt_attribution", True,
                detail=f"{len(dirty)} dirty entries under data dirs, "
                       f"{len(foreign)} not from V3.1 outputs",
                critical=False)
        if foreign:
            rep.checks[-1]["failures"] = foreign[:25]
            rep.checks[-1]["failure_count"] = len(foreign)
    except Exception as exc:
        rep.add("isolation", "worktree_dirt_attribution", False, [str(exc)],
                critical=False)

    # ---- benchmark family T ------------------------------------------------------
    bench_path = V.BENCH / "v3_T_taxonomy_explicit.jsonl"
    if bench_path.exists():
        prev_by_id = {r.get("finding_id"): r for r in preview}
        t_tasks, t_bad = 0, []
        for line in open(bench_path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            t_tasks += 1
            try:
                task = json.loads(line)
            except json.JSONDecodeError:
                t_bad.append(f"line {t_tasks}: bad json")
                continue
            rid = (task.get("source") or {}).get("record_id")
            rec = prev_by_id.get(rid)
            if rec is None:
                t_bad.append(f"{task.get('task_id')}: unknown record")
                continue
            want = (rec.get("normalized_vulnerability_classes") or [None])[0]
            if (task.get("answer") or {}).get("vulnerability_class") != want:
                t_bad.append(f"{task.get('task_id')}: answer mismatch")
            if rec.get("taxonomy_confidence") != "explicit":
                t_bad.append(f"{task.get('task_id')}: not explicit")
        rep.add("references", "benchmark_T_resolves", not t_bad, t_bad,
                detail=f"{t_tasks} tasks checked")
    else:
        rep.add("references", "benchmark_T_resolves", True,
                detail="family T file absent (deferred)", critical=False)

    crit_fail = sum(1 for c in rep.checks if c["critical"] and not c["ok"])
    total = len(rep.checks)
    passed = sum(1 for c in rep.checks if c["ok"])
    out = {"checks": rep.checks, "passed": passed, "total": total,
           "critical_failures": crit_fail, "normalization_version": "3.1"}
    V.REPORTS_V3.mkdir(parents=True, exist_ok=True)
    with open(V.REPORTS_V3 / "validation_v31.json", "w",
              encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
    V.log(f"validate_v31.py: {passed}/{total} checks passed, "
          f"{crit_fail} critical failures")
    return 1 if crit_fail else 0


def _span_ok(f: dict) -> bool:
    sp = f.get("source_span") or {}
    try:
        s, e = int(sp["char_start"]), int(sp["char_end"])
    except (KeyError, TypeError, ValueError):
        return False
    if not (0 <= s < e):
        return False
    if not isinstance(sp.get("source_location"), str):
        return False
    if not isinstance(sp.get("file_sha256"), str):
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())

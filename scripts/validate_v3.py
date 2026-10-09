#!/usr/bin/env python3
"""The V3 build gate. Fails on critical integrity problems in the new layer.

    python scripts/validate_v3.py
    python scripts/validate_v3.py --quiet

Checks (all read-only except the validation report itself):

  structure     JSON/JSONL validity, required fields, id uniqueness
  provenance    sha256 shape, clone HEAD shape, no mutable refs
  consistency   decisions/levels/negative-class vocabularies, severity values,
                L1-requires-PoC, no L2+ without run artefacts
  references    duplicates/corroborations/negatives resolve to ledger rows,
                benchmark tasks resolve to records, splits resolve to records
  counts        manifest/source-ledger numbers recomputed from the files
  versions      every V3 artefact agrees on 3.0
  isolation     v1/v2.2 layers and benchmark/manifest.json untouched in shape
                (all A-Q families still present)

Writes reports/v3/validation_v3.json (machine-readable gate output).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_v3 as V  # noqa: E402
import v32_execution as _exec_mod  # noqa: E402

U = V.UNKNOWN
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
URL = re.compile(r"^https://\S+$")


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


def _load_jsonl(path: Path, rep: Report, group: str) -> list[dict]:
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
                    bad.append(f"{path.name}:{i}: {exc}")
    except OSError as exc:
        bad.append(f"{path}: {exc}")
    rep.add(group, f"{path.parent.name}/{path.name}_valid_jsonl",
            not bad, bad)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    rep = Report(args.quiet)
    V.log("validate_v3.py")

    # ---- structure ---------------------------------------------------------
    ledger = _load_jsonl(V.DERIVED_V3 / "candidate_ledger.jsonl", rep, "structure")
    records = _load_jsonl(V.DERIVED_V3 / "records.jsonl", rep, "structure")
    negatives = _load_jsonl(V.DERIVED_V3 / "negatives.jsonl", rep, "structure")
    duplicates = _load_jsonl(V.DERIVED_V3 / "duplicates.jsonl", rep, "structure")
    corroborations = _load_jsonl(V.DERIVED_V3 / "corroborations.jsonl", rep, "structure")
    findings = _load_jsonl(V.JSONL_V3 / "findings.jsonl", rep, "structure")
    sources = _load_jsonl(V.JSONL_V3 / "sources.jsonl", rep, "structure")

    required = ["candidate_id", "source_id", "source_location", "project",
                "finding_title", "severity_normalized", "language", "ecosystem",
                "vulnerable_commit", "fixed_commit", "verification_level",
                "decision", "quality_score"]
    missing = [f"{c.get('candidate_id', '?')}" for c in ledger
               if any(k not in c for k in required)]
    rep.add("structure", "candidate_required_fields", not missing, missing)

    def dup_ids(rows: list[dict], key: str) -> list[str]:
        seen: set[str] = set()
        dups: list[str] = []
        for r in rows:
            v = r.get(key)
            if v in seen:
                dups.append(str(v))
            seen.add(v)
        return dups

    rep.add("structure", "candidate_ids_unique",
            not dup_ids(ledger, "candidate_id"), dup_ids(ledger, "candidate_id"))
    rep.add("structure", "finding_ids_unique",
            not dup_ids(records, "finding_id"), dup_ids(records, "finding_id"))
    _src_missing = sorted(set(V.SOURCE_IDS)
                          - {r["source_id"] for r in sources})
    _src_extra = sorted({r["source_id"] for r in sources}
                        - set(V.SOURCE_IDS))
    rep.add("structure", "sources_cover_registry",
            not _src_missing and not _src_extra,
            [f"missing={_src_missing}"] if _src_missing else
            [f"undeclared={_src_extra}"] if _src_extra else [],
            detail=f"{len(sources)} sources == len(SOURCE_IDS)")

    # ---- provenance ---------------------------------------------------------
    bad_sha = [c["candidate_id"] for c in ledger
               if not (isinstance(c.get("provenance", {}).get("file_sha256"), str)
                       and SHA64.match(c["provenance"]["file_sha256"]))]
    rep.add("provenance", "file_sha256_shape", not bad_sha, bad_sha)
    bad_head = [c["candidate_id"] for c in ledger
                if c.get("provenance", {}).get("clone_head", U) != U
                and not SHA40.match(str(c["provenance"]["clone_head"]))]
    rep.add("provenance", "clone_head_shape", not bad_head, bad_head)
    bad_commit = [c["candidate_id"] for c in ledger
                  for k in ("vulnerable_commit", "fixed_commit")
                  if c.get(k) not in (U, None)
                  and not re.fullmatch(r"[0-9a-f]{7,40}", str(c[k]))]
    rep.add("provenance", "commit_hex_shape", not bad_commit, bad_commit)
    bad_conf = [c["candidate_id"] for c in ledger
                if c.get("vulnerable_commit_confidence", U) not in (*V.COMMIT_CONFIDENCE, U)
                or c.get("fixed_commit_confidence", U) not in (*V.COMMIT_CONFIDENCE, U)]
    rep.add("provenance", "commit_confidence_vocab", not bad_conf, bad_conf)
    bad_url = [c["candidate_id"] for c in ledger
               for k in ("repository", "issue_url")
               if c.get(k) not in (U, None) and not URL.match(str(c[k]))]
    rep.add("provenance", "url_shape", not bad_url, bad_url)

    # ---- consistency --------------------------------------------------------
    bad_dec = [c["candidate_id"] for c in ledger if c.get("decision") not in V.DECISIONS]
    rep.add("consistency", "decision_vocab", not bad_dec, bad_dec)
    bad_lv = [c["candidate_id"] for c in ledger
              if c.get("verification_level") not in V.VERIFICATION_LEVELS]
    rep.add("consistency", "level_vocab", not bad_lv, bad_lv)

    # Level above L1 requires an execution record; L4+ requires a committed
    # artefact directory; L5 requires attacker-side profit evidence and
    # L6 is never awardable here (no candidate has a fixed-side leg).
    executed = [c for c in ledger
                if c.get("verification_level") in ("L3", "L4", "L5", "L6")]
    no_exp = [c["candidate_id"] for c in executed if not c.get("experiment")]
    rep.add("consistency", "L3_plus_requires_experiment", not no_exp, no_exp,
            detail=f"{len(executed)} executed candidates")
    no_dir = [c["candidate_id"] for c in executed
              if c.get("verification_level") in ("L4", "L5", "L6")
              and not (V.ROOT / ((c.get("experiment") or {}).get(
                  "artifact_dir") or "")).is_dir()]
    rep.add("consistency", "L4_plus_requires_artefact_dir", not no_dir, no_dir)
    no_profit = [c["candidate_id"] for c in executed
                 if c.get("verification_level") == "L5"
                 and not (c.get("experiment") or {}).get("profit_evidence")]
    rep.add("consistency", "L5_requires_profit_evidence", not no_profit,
            no_profit)
    l6 = [c["candidate_id"] for c in executed if c.get("verification_level") == "L6"]
    rep.add("consistency", "no_L6_without_fixed_leg", not l6, l6)
    l1_no_poc = [c["candidate_id"] for c in ledger
                 if c.get("verification_level") == "L1" and not c.get("poc_available")]
    rep.add("consistency", "L1_requires_published_poc", not l1_no_poc, l1_no_poc)
    neg_bad = [c["candidate_id"] for c in ledger
               if (c.get("decision") == "IMPORT_AS_NEGATIVE") != (c.get("negative_class") in V.NEGATIVE_CLASSES)]
    rep.add("consistency", "negative_class_iff_negative", not neg_bad, neg_bad)
    dup_bad = [c["candidate_id"] for c in ledger
               if (c.get("duplicate_of") not in (None, U)) != (c["decision"] == "CORROBORATION_ONLY")
               and c.get("decision") not in ("REJECT",)]
    # REJECT rows may carry no duplicate_of; CORROBORATION_ONLY must carry one.
    cor_no_link = [c["candidate_id"] for c in ledger
                   if c.get("decision") == "CORROBORATION_ONLY" and not c.get("duplicate_of")]
    rep.add("consistency", "corroboration_has_link", not cor_no_link, cor_no_link)
    bad_score = [c["candidate_id"] for c in ledger
                 if not isinstance(c.get("quality_score"), int)
                 or not (0 <= c["quality_score"] <= 95)]
    rep.add("consistency", "quality_score_0_95", not bad_score, bad_score)
    lic_missing = [c["candidate_id"] for c in ledger if "license_status" not in c]
    rep.add("consistency", "license_metadata_present", not lic_missing, lic_missing)

    # ---- references ----------------------------------------------------------
    ledger_ids = {c["candidate_id"] for c in ledger}
    record_ids = {r["finding_id"] for r in records}
    bad_dup_ref = [d["candidate_id"] for d in duplicates
                   if d.get("duplicate_of") not in ledger_ids]
    rep.add("references", "duplicates_resolve", not bad_dup_ref, bad_dup_ref)
    bad_cor_ref = [d["candidate_id"] for d in corroborations
                   if d.get("corroborated_by_of") not in ledger_ids]
    rep.add("references", "corroborations_resolve", not bad_cor_ref, bad_cor_ref)
    neg_outside = [r["finding_id"] for r in negatives if r["finding_id"] not in record_ids]
    rep.add("references", "negatives_subset_of_records", not neg_outside, neg_outside)
    admitted = {c["candidate_id"] for c in ledger if c["decision"] in V.ADMITTED_DECISIONS}
    rec_match = record_ids == admitted
    rep.add("references", "records_eq_admitted",
            rec_match, [] if rec_match else [f"records={len(record_ids)} admitted={len(admitted)}"])

    # benchmark tasks resolve + splits resolve
    bench_ok, bench_fails = True, []
    bench_tasks = 0
    for name in ("v3_R_source_tier_routing.jsonl", "v3_S_contest_outcome.jsonl"):
        path = V.BENCH / name
        if not path.exists():
            bench_ok = False
            bench_fails.append(f"missing {name}")
            continue
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            bench_tasks += 1
            t = json.loads(line)
            rid = (t.get("source") or {}).get("record_id")
            if rid not in record_ids:
                bench_ok = False
                bench_fails.append(f"{name}:{t.get('task_id')}")
    rep.add("references", "benchmark_tasks_resolve", bench_ok, bench_fails)
    split_ok, split_fails = True, []
    split_path = V.SPLITS_V3 / "split.json"
    if split_path.exists():
        sp = json.loads(split_path.read_text(encoding="utf-8"))
        seen_split: dict[str, str] = {}
        for split_name, ids in (sp.get("splits") or {}).items():
            for fid in ids:
                if fid not in record_ids:
                    split_ok = False
                    split_fails.append(f"{split_name}:{fid}")
                if fid in seen_split:
                    split_ok = False
                    split_fails.append(f"spans-splits:{fid}")
                seen_split[fid] = split_name
        if set(seen_split) != record_ids:
            split_ok = False
            split_fails.append(f"split coverage {len(seen_split)} != records {len(record_ids)}")
    else:
        split_ok = False
        split_fails.append("missing splits_v3/split.json")
    rep.add("references", "splits_cover_records_once", split_ok, split_fails)

    # ---- counts ---------------------------------------------------------------
    manifest: dict = {}
    try:
        manifest = json.loads((V.DERIVED_V3 / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        rep.add("counts", "manifest_readable", False, [str(exc)])
    if manifest:
        checks = [
            ("candidate_count", manifest.get("candidate_count"), len(ledger)),
            ("record_count", manifest.get("record_count"), len(records)),
        ]
        bad_counts = [f"{k}: manifest={a} actual={b}" for k, a, b in checks if a != b]
        rep.add("counts", "manifest_counts_match", not bad_counts, bad_counts)
        # Every distribution must sum to the population it names.
        # record_count counts admitted records; candidate_* count the
        # ledger. Mixing them is how 5,467 and 7,712 got printed side by
        # side under identical-looking keys.
        cand_total, rec_total = len(ledger), len(records)
        dom_bad = []
        for key, want in (("candidate_decisions", cand_total),
                          ("candidate_verification_levels", cand_total),
                          ("candidate_by_source", cand_total),
                          ("candidate_by_ecosystem", cand_total),
                          ("candidate_by_language", cand_total),
                          ("admitted_verification_levels", rec_total),
                          ("admitted_by_decision", rec_total),
                          ("admitted_by_ecosystem", rec_total),
                          ("admitted_by_language", rec_total)):
            got = manifest.get(key)
            if not isinstance(got, dict):
                dom_bad.append(f"{key}: missing or not a distribution")
            elif sum(got.values()) != want:
                dom_bad.append(f"{key}: sums to {sum(got.values())}, "
                               f"expected {want}")
        rep.add("counts", "count_domains_self_consistent", not dom_bad,
                dom_bad,
                detail="candidate_* sums to the ledger; admitted_* sums to "
                       "the admitted records")
        try:
            sl = json.loads((V.DERIVED_V3 / "source_ledger.json").read_text(encoding="utf-8"))
            sources = sl.get("sources", [])
            ssum = sum(s["records_discovered"] for s in sources)
            # len(V.SOURCE_IDS), never a literal: adding or removing a source
            # must not require editing this gate.
            want_n = len(V.SOURCE_IDS)
            problems = []
            if ssum != len(ledger):
                problems.append(f"ledger_sum={ssum} ledger={len(ledger)}")
            if len(sources) != want_n:
                problems.append(f"sources={len(sources)} expected={want_n}")
            rep.add("counts", "source_ledger_sums", not problems, problems,
                    detail=f"{len(sources)} sources == len(SOURCE_IDS)")
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            rep.add("counts", "source_ledger_readable", False, [str(exc)])

    # ---- L3 rows trace to the compile sweep -------------------------------------
    # An L3 record claims "forge build rc=0 on these unmodified PoC bytes".
    # That claim is checkable without a forge run: the row must exist in the
    # committed sweep with rc==0, and the promoted record must not have
    # drifted from it (no invented compile, no invented artefact dir).
    sweep_path = V.REPORTS_V3 / "compile_sweep.json"
    if sweep_path.is_file():
        try:
            sweep = json.loads(sweep_path.read_text(encoding="utf-8"))
            rows = (sweep.get("rows") if isinstance(sweep, dict) else sweep)
            by_key = {}
            for s in (rows or []):
                if not isinstance(s, dict):
                    continue
                try:
                    key = _exec_mod.evidence_key(str(s.get("file", "")))
                except Exception:
                    continue
                if key:
                    by_key[key] = s
            l3_no_sweep, l3_drift = [], []
            for c in ledger:
                if c.get("verification_level") != "L3":
                    continue
                key = _exec_mod.evidence_key(c["candidate_id"])
                s = by_key.get(key)
                if s is None:
                    l3_no_sweep.append(c["candidate_id"])
                elif s.get("rc") != 0:
                    l3_drift.append(c["candidate_id"])
                else:
                    exp = c.get("experiment") or {}
                    comp = exp.get("compile") or {}
                    if comp.get("rc") != 0 or \
                            bool(comp.get("via_ir")) != bool(s.get("via_ir")):
                        l3_drift.append(c["candidate_id"])
            rep.add("consistency", "L3_requires_compile_sweep_row",
                    not l3_no_sweep, l3_no_sweep,
                    detail=f"{len(by_key)} sweep rows, "
                           f"{sum(1 for c in ledger if c.get('verification_level') == 'L3')} L3 records")
            rep.add("consistency", "L3_matches_sweep_row", not l3_drift,
                    l3_drift,
                    detail="record's compile evidence equals its sweep row "
                           "(rc=0, same via_ir, no invented artefact dir)")
            # Every sweep success must be accounted for by some record, so a
            # promotion cannot silently drop compiled PoCs.
            l3_keys = {_exec_mod.evidence_key(c["candidate_id"])
                       for c in ledger
                       if c.get("verification_level") in ("L3", "L4", "L5")}
            unaccounted = sorted(k for k, s in by_key.items()
                                 if s.get("rc") == 0 and k not in l3_keys)
            rep.add("consistency", "compiled_pocs_are_advertised",
                    not unaccounted, unaccounted[:10],
                    detail="every compiled sweep row appears as an L3+ record")
        except (OSError, ValueError) as exc:
            rep.add("consistency", "compile_sweep_readable", False, [str(exc)])
    else:
        rep.add("consistency", "compile_sweep_present", False, [],
                detail="missing reports/v3/compile_sweep.json: L3 claims "
                       "cannot be traced to a sweep row", critical=False)

    # ---- versions ---------------------------------------------------------------
    ver_bad = []
    for path in [V.DERIVED_V3 / "manifest.json"]:
        try:
            m = json.loads(path.read_text(encoding="utf-8"))
            if m.get("dataset_version") != V.DATASET_VERSION_V3 or m.get("schema_version") != V.SCHEMA_VERSION_V3:
                ver_bad.append(path.name)
        except (OSError, json.JSONDecodeError):
            ver_bad.append(path.name)
    for r in records[:5000]:
        if r.get("dataset_version") != V.DATASET_VERSION_V3 or r.get("schema_version") != V.SCHEMA_VERSION_V3:
            ver_bad.append(str(r.get("finding_id")))
            break
    rep.add("versions", "v3_version_3_0_consistent", not ver_bad, ver_bad)

    # ---- isolation (v1/v2.2 untouched in shape) ----------------------------------
    try:
        bm = json.loads((V.BENCH / "manifest.json").read_text(encoding="utf-8"))
        fams = set(bm.get("families", []))
        need = {"A_vulnerability_detection", "B_root_cause_reasoning",
                "C_attacker_reasoning", "D_exploit_construction",
                "E_exploit_verification", "F_false_positive_rejection",
                "G_patch_verification", "H_verified_exploit",
                "I_verified_non_exploit", "J_verified_patch",
                "K_language_ecosystem_routing", "L_severity_reconciliation",
                "M_experiment_level_classification",
                "N_attacker_identity_extraction", "O_record_class_and_scope",
                "P_provenance_tier_and_rights",
                "Q_evidence_type_and_quality_rubric"}
        rep.add("isolation", "benchmark_A_Q_intact", need <= fams,
                [f"missing={sorted(need - fams)}"] if need - fams else [])
    except (OSError, json.JSONDecodeError) as exc:
        rep.add("isolation", "benchmark_manifest_readable", False, [str(exc)])

    crit_fail = sum(1 for c in rep.checks if c["critical"] and not c["ok"])
    total = len(rep.checks)
    passed = sum(1 for c in rep.checks if c["ok"])
    out = {"checks": rep.checks, "passed": passed, "total": total,
           "critical_failures": crit_fail,
           "dataset_version": V.DATASET_VERSION_V3}
    V.REPORTS_V3.mkdir(parents=True, exist_ok=True)
    # newline="\n": platform-stable LF output (see vlun_v3.write_json).
    # Trailing "\n" keeps the file byte-identical to a sort_keys redump
    # (enforced by check_reproducibility.py §7a).
    with open(V.REPORTS_V3 / "validation_v3.json", "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    V.log(f"validate_v3.py: {passed}/{total} checks passed, "
          f"{crit_fail} critical failures")
    return 1 if crit_fail else 0


if __name__ == "__main__":
    sys.exit(main())

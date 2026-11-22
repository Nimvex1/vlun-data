"""validate_wave1.py — the eight locked Wave-1 gates.

(a) single-writer path confinement
(b) zero canonical layer / PRESENT sentinel drift
(c) dedup_check.py --check: zero admitted collisions
(d) rights & METADATA_ONLY compliance (no full-prose leaks)
(e) benchmark readiness: scorable>=100, labels>=2, holdout>=30, train shortcut<0.9
(i) HARD: 100% of candidate/admitted/benchmark rows are FULLY_TRAINABLE
    (>=50 chars verbatim inline code AND >=100 chars verbatim prose).
    gate h also enforces task_id/split consistency (previously detection-only).

Writes only wave1/reports_wave1/validate_wave1.json. Exits 1 on any failure.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from _common import ROOT, WAVE1, guard_wave1, sha256_file, write_json
from hydration_lib import ALLOWED_INLINE_FIELDS, fully_trainable, trainable_stats

PRESENT_JSON = WAVE1 / "00_governance" / "PRESENT.md.json"
WRITE_CALLS = re.compile(
    r"\b(?:open\s*\([^)]*['\"](?:w|a|x)['\"]|write_text\s*\(|write_bytes\s*\(|"
    r"write_jsonl\s*\(|append_jsonl\s*\(|write_json\s*\(|mkdir\s*\()"
)
CANONICAL_PREFIXES = (
    "jsonl/", "jsonl_ml/", "jsonl_v3/", "jsonl_v4/", "derived", "Vbeta/", "V3/", "V4/",
    "benchmark/", "reports/", "scripts/", "docs/", "splits", "dataset", "training/",
    "README.md", "pyproject.toml", "publish_manifest.json", "RELEASE_MANIFEST.json",
)


def gate_a_single_writer() -> dict:
    """Static scan: no wave1 script may contain a write to a canonical path."""
    violations = []
    scripts = sorted((WAVE1 / "scripts").rglob("*.py"))
    for p in scripts:
        if p.name == "validate_wave1.py":
            continue
        text = p.read_text(encoding="utf-8")
        # strip comments/docstrings heuristically for fewer false positives
        for m in WRITE_CALLS.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line = text[line_start : text.find("\n", m.end()) if "\n" in text[m.end():] else len(text)]
            if any(tok in line for tok in CANONICAL_PREFIXES) and "wave1/" not in line:
                violations.append({"script": str(p.relative_to(WAVE1)), "line": line.strip()[:200]})
    return {
        "scripts_scanned": len(scripts),
        "violations": violations[:50],
        "verdict": "PASS" if not violations else "FAIL",
    }


def gate_b_present() -> dict:
    if not PRESENT_JSON.exists():
        return {"verdict": "FAIL", "error": "PRESENT.md.json missing"}
    data = json.loads(PRESENT_JSON.read_text(encoding="utf-8"))
    drift = []
    checked = 0
    for rel, expected in data.get("canonical_sha256", {}).items():
        p = ROOT / rel
        checked += 1
        if not p.exists():
            drift.append({"path": rel, "issue": "missing"})
            continue
        actual = sha256_file(p)
        if actual != expected:
            drift.append({"path": rel, "expected": expected, "actual": actual})
    # script hash drift is expected while adapters are edited; report only
    script_drift = []
    for rel, expected in data.get("wave1_script_sha256", {}).items():
        p = WAVE1 / rel
        if p.exists() and sha256_file(p) != expected:
            script_drift.append(rel)
    return {
        "canonical_files_checked": checked,
        "canonical_drift": drift,
        "wave1_script_drift": script_drift,
        "verdict": "PASS" if not drift else "FAIL",
    }


def gate_c_dedup(no_write: bool = False) -> dict:
    script = WAVE1 / "scripts" / "dedup_check.py"
    if not script.exists():
        return {"verdict": "FAIL", "error": "dedup_check.py missing"}
    cmd = [sys.executable, str(script), "--check"]
    if no_write:
        cmd.append("--no-write")
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    report_path = WAVE1 / "reports_wave1" / "dedup_check.json"
    detail = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip()[:1000],
        "collisions": detail.get("collisions"),
        "admitted_rows": detail.get("admitted_rows"),
        "verdict": "PASS" if proc.returncode == 0 else "FAIL",
    }


def gate_d_rights() -> dict:
    forbidden_fields = {
        "body", "issue_body", "comment_body", "raw_text", "prose", "report_text",
        "full_text", "comment", "description_long", "raw_body_excerpt",
    }
    leaks = []
    admitted = WAVE1 / "04_admitted"
    rows = 0
    if admitted.exists():
        for p in sorted(admitted.rglob("*.jsonl")):
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rows += 1
                try:
                    d = json.loads(line)
                except Exception:
                    leaks.append({"file": str(p), "reason": "invalid json"})
                    continue
                for k, v in d.items():
                    if k.lower() in forbidden_fields:
                        leaks.append({"file": str(p), "candidate_id": d.get("candidate_id"), "field": k})
                    # rights.jsonl now declares FULL_TRAINABLE_INLINE_EXTRACTION:
                    # verbatim code/prose is intentionally vendored.  The legacy
                    # 1000-char METADATA_ONLY guard applies only to non-inline
                    # fields; inline fields are bounded by gate_i instead.
                    if isinstance(v, str) and len(v) > 1000 and k not in ALLOWED_INLINE_FIELDS:
                        leaks.append({"file": str(p), "candidate_id": d.get("candidate_id"),
                                      "field": k, "reason": f"string length {len(v)}"})
    rights = []
    rp = WAVE1 / "00_governance" / "rights.jsonl"
    if rp.exists():
        rights = [json.loads(l) for l in rp.read_text(encoding="utf-8").splitlines() if l.strip()]
    return {
        "admitted_rows_scanned": rows,
        "rights_rows": len(rights),
        "prose_leaks": leaks[:50],
        "verdict": "PASS" if not leaks else "FAIL",
    }


def gate_e_benchmark() -> dict:
    families = {}
    bdir = WAVE1 / "benchmark_wave1"
    if not bdir.exists():
        return {"verdict": "FAIL", "error": "benchmark_wave1/ missing"}
    for p in sorted(bdir.glob("*.jsonl")):
        rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        scorable = [r for r in rows if r.get("answer") is not None and r.get("label") is not None]
        labels = {str(r.get("label")) for r in scorable}
        splits = Counter(str(r.get("split")) for r in scorable)
        test_n = splits.get("test", 0) + splits.get("holdout", 0)
        train_labels = defaultdict(Counter)
        for r in scorable:
            if str(r.get("split")) in ("train", "trainval"):
                train_labels[r.get("family", "all")][str(r.get("label"))] += 1
        shortcut = None
        if train_labels and test_n:
            # majority train label accuracy on held-out rows
            majority = None
            for c in train_labels.values():
                maj, _ = c.most_common(1)[0]
                majority = majority or maj
            if majority:
                correct = sum(1 for r in scorable
                              if str(r.get("split")) in ("test", "holdout") and str(r.get("label")) == majority)
                shortcut = round(correct / test_n, 4) if test_n else None
        ready = (
            len(scorable) >= 100
            and len(labels) >= 2
            and test_n >= 30
            and (shortcut is None or shortcut < 0.9)
        )
        families[p.stem] = {
            "rows": len(rows),
            "scorable": len(scorable),
            "observed_labels": sorted(labels),
            "test_rows": test_n,
            "train_only_shortcut": shortcut,
            "ready_for_primary": ready,
        }
    any_ready = any(f["ready_for_primary"] for f in families.values())
    return {
        "families": families,
        "primary_ready_count": sum(1 for f in families.values() if f["ready_for_primary"]),
        "verdict": "PASS" if any_ready else "PENDING",
    }


def gate_f_label_purity() -> dict:
    """Fail if any family carries labels outside its governed semantic domain."""
    contract_path = WAVE1 / "00_governance" / "label_domains.json"
    if not contract_path.exists():
        return {"verdict": "FAIL", "error": "label_domains.json missing"}
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    domains = contract["domains"]
    families = contract["families"]
    violations = []
    bdir = WAVE1 / "benchmark_wave1"
    for fam, spec in families.items():
        p = bdir / f"{fam}.jsonl"
        if not p.exists():
            continue
        allowed = set(domains.get(spec.get("domain") or "", []))
        other = set()
        for other_fam, other_spec in families.items():
            if other_fam != fam and other_spec.get("domain"):
                other |= set(domains.get(other_spec["domain"], []))
        for row in (json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()):
            lab = str(row.get("label") or "")
            if spec.get("not_scorable"):
                if row.get("answer") is not None or lab:
                    violations.append({"family": fam, "task_id": row.get("task_id"),
                                       "reason": "not_scorable family carries an answer/label"})
                continue
            if lab not in allowed:
                kind = "CROSS_DOMAIN_MIX" if lab in other else "UNKNOWN_LABEL"
                violations.append({"family": fam, "task_id": row.get("task_id"),
                                   "label": lab, "reason": kind})
    return {
        "families_checked": len(families),
        "violations": violations[:50],
        "verdict": "PASS" if not violations else "FAIL",
    }


def gate_g_j_execution() -> dict:
    """J_verified_patch may only contain executed two-revision L6 artefacts."""
    p = WAVE1 / "benchmark_wave1" / "J_verified_patch.jsonl"
    if not p.exists():
        return {"verdict": "FAIL", "error": "J_verified_patch.jsonl missing"}
    bad = []
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    sha40 = re.compile(r"^[0-9a-fA-F]{40}$")
    for row in rows:
        ex = row.get("execution") if isinstance(row.get("execution"), dict) else {}
        reasons = []
        if str(ex.get("level", "")).upper() != "L6":
            reasons.append("level != L6")
        if not sha40.match(str(ex.get("vulnerable_sha", ""))):
            reasons.append("no vulnerable_sha")
        # A genuine L6 needs a real upstream FIX COMMIT from repository history.
        # A git-blob SHA of harness-bundled patched sources is an overlay, not a
        # commit-pinned fixed revision (VLUN candidate_ledger rule).
        fixed_commit = ex.get("fixed_commit") or row.get("fixed_commit")
        if not sha40.match(str(fixed_commit or "")):
            reasons.append("no genuine upstream 40-hex fixed_commit")
        if fixed_commit == ex.get("vulnerable_sha"):
            reasons.append("fixed_commit equals vulnerable_sha")
        raw_fixed_sha = str(ex.get("fixed_sha") or row.get("fixed_sha") or "")
        if raw_fixed_sha.startswith("blob:") or "blob" in str(ex.get("fixed_commit_basis") or "").lower():
            reasons.append("blob/overlay hash is not a commit")
        provenance = str(ex.get("patch_provenance") or row.get("patch_provenance") or "").lower()
        if provenance in {"harness_source_overlay_blob", "synthetic_overlay", "overlay"} or "overlay" in provenance:
            reasons.append("overlay patch provenance is not an upstream fix")
        if ex.get("violation_reproduced") is not True:
            reasons.append("violation not reproduced")
        if ex.get("blocked_on_fixed") is not True:
            reasons.append("not blocked on fixed revision")
        if not str(ex.get("result_artefact", "")):
            reasons.append("no result artefact")
        if reasons:
            bad.append({"task_id": row.get("task_id"), "reasons": reasons})
    return {
        "rows": len(rows),
        "non_L6_rows": bad[:50],
        "verdict": "PASS" if not bad else "FAIL",
    }


def gate_h_group_disjoint() -> dict:
    """Every group_id (repo/contest/property family) must live in ONE split only."""
    bdir = WAVE1 / "benchmark_wave1"
    violations = []
    families = {}
    if not bdir.exists():
        return {"verdict": "FAIL", "error": "benchmark_wave1/ missing"}
    for p in sorted(bdir.glob("*.jsonl")):
        groups: dict[str, set[str]] = defaultdict(set)
        rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        missing = 0
        task_id_mismatches = 0
        for row in rows:
            gid = row.get("group_id")
            split = row.get("split")
            if not gid or not split:
                missing += 1
                continue
            groups[str(gid)].add(str(split))
            tid_parts = str(row.get("task_id") or "").split("::")
            if len(tid_parts) >= 3 and tid_parts[1] in ("train", "val", "test", "validation", "holdout"):
                if tid_parts[1] != str(split):
                    task_id_mismatches += 1
        overlap = {g: sorted(s) for g, s in groups.items() if len(s) > 1}
        families[p.stem] = {
            "rows": len(rows),
            "groups": len(groups),
            "splits": sorted({s for ss in groups.values() for s in ss}),
            "overlapping_groups": dict(list(overlap.items())[:20]),
            "missing_group_id": missing,
            "task_id_split_mismatches": task_id_mismatches,
        }
        if overlap or missing or task_id_mismatches:
            violations.append({
                "family": p.stem,
                "overlapping_groups": list(overlap.items())[:10],
                "missing_group_id": missing,
                "task_id_split_mismatches": task_id_mismatches,
            })
    return {
        "families": families,
        "violations": violations[:50],
        "verdict": "PASS" if not violations else "FAIL",
    }


def gate_i_fully_trainable() -> dict:
    """HARD GATE: every row in the candidate/admitted/benchmark tables must be
    FULLY_TRAINABLE -- >=50 chars of verbatim inline code and >=100 chars of
    verbatim prose.  Any short row is a stub that escaped hydration/quarantine.
    """
    roots = [
        ("03_candidates", WAVE1 / "03_candidates", "**/*.jsonl"),
        ("04_admitted", WAVE1 / "04_admitted", "**/*.jsonl"),
        ("benchmark_wave1", WAVE1 / "benchmark_wave1", "*.jsonl"),
    ]
    per_file = {}
    violations = []
    total = 0
    for group, base, pattern in roots:
        if not base.exists():
            violations.append({"group": group, "reason": f"{base.name}/ missing"})
            continue
        for p in sorted(base.glob(pattern)):
            rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
            short = []
            for r in rows:
                total += 1
                st = trainable_stats(r)
                if not st["fully_trainable"]:
                    short.append({
                        "id": r.get("task_id") or r.get("candidate_id"),
                        "code_chars": st["code_chars"],
                        "prose_chars": st["prose_chars"],
                    })
            per_file[str(p.relative_to(WAVE1))] = {"rows": len(rows), "short": len(short)}
            for s in short[:10]:
                violations.append({"file": str(p.relative_to(WAVE1)), **s})
    return {
        "rows_scanned": total,
        "files": per_file,
        "short_rows": len(violations),
        "violations": violations[:50],
        "verdict": "PASS" if not violations else "FAIL",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="run gates without rewriting reports (for gate-suite runs)")
    args = ap.parse_args()
    gates = {
        "a_single_writer": gate_a_single_writer(),
        "b_present_drift": gate_b_present(),
        "c_dedup": gate_c_dedup(no_write=args.check),
        "d_rights": gate_d_rights(),
        "e_benchmark": gate_e_benchmark(),
        "f_label_purity": gate_f_label_purity(),
        "g_j_execution": gate_g_j_execution(),
        "h_group_disjoint_splits": gate_h_group_disjoint(),
        "i_fully_trainable": gate_i_fully_trainable(),
    }
    hard = ["a_single_writer", "b_present_drift", "c_dedup", "d_rights",
            "f_label_purity", "g_j_execution", "h_group_disjoint_splits",
            "i_fully_trainable"]
    verdict = "PASS" if all(gates[g]["verdict"] == "PASS" for g in hard) else "FAIL"
    # No run wall-clock field: this report is committed and byte-hashed by the
    # JSON catalog, so a fresh utc_now() on every run would make it stale.
    # All functional content (gates, verdict, note) is deterministic.
    report = {
        "gates": gates,
        "verdict": verdict,
        "note": "gate e is PENDING until a family reaches PRIMARY thresholds; it is informational "
                "and does not fail the structural gates.",
    }
    if not args.check:
        write_json(guard_wave1(WAVE1 / "reports_wave1" / "validate_wave1.json"), report)
    for name, g in gates.items():
        print(f"[{name}] {g.get('verdict')}")
    print(f"[validate_wave1] overall structural verdict: {verdict}")
    if verdict != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

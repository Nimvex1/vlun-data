import argparse
import hashlib
import json
import subprocess
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]


def parse_args():
    ap = argparse.ArgumentParser(description="Register V4 cloned findings")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT,
                    help="repository root (default: inferred from script location)")
    return ap.parse_args()


def load_jsonl(p):
    p = Path(p)
    if not p.exists():
        return []
    out = []
    with open(p, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"malformed JSONL at {p}:{lineno}: {exc}") from exc
    return out


def norm(s):
    return "".join(ch for ch in str(s or "").lower() if ch.isalnum())


def title_of(r):
    return r.get("title") or r.get("finding_title") or ""


def repo_of(r):
    return r.get("affected_repository") or r.get("repository") or ""


def commit_of(r):
    return r.get("vulnerable_commit") or ""


def func_of(r):
    return r.get("affected_function") or ""


def code_text_of(r):
    for key in ("affected_code_excerpt", "affected_code", "code"):
        v = r.get(key)
        if v:
            return str(v)
    return ""


def sim(a, b):
    a = " ".join(str(a or "").lower().split())
    b = " ".join(str(b or "").lower().split())
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def git_head(repo):
    repo = Path(repo)
    head = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True, stderr=subprocess.DEVNULL).strip()
    if not head:
        raise RuntimeError(f"empty git HEAD for {repo}")
    return head


def find_root(root):
    return Path(root).resolve()


def main():
    args = parse_args()
    ROOT = find_root(args.root)
    OUT_JSONL4 = ROOT / "jsonl_v4"
    OUT_DER4 = ROOT / "derived_v4"
    OUT_V4 = ROOT / "V4"
    for d in (OUT_JSONL4, OUT_DER4, OUT_V4):
        d.mkdir(parents=True, exist_ok=True)

    findings = [json.loads(line) for line in open(
        ROOT / "work" / "cloned_conversion" / "v4" / "extracted_findings.jsonl",
        encoding="utf-8") if line.strip()]

    # Rights come from the recorded decision file, never from a placeholder. The
    # harvester leaves `license: "unknown"` on every row, which used to flow
    # straight into the published layer and hide the one term that matters most
    # (Oak's CC BY-ND No-Derivatives). A source with no decision on file stops the
    # build rather than shipping an unresolved status.
    licensing = json.loads((ROOT / "V4" / "licensing.json").read_text(encoding="utf-8"))
    licence_by_source = {s["source_id"]: s for s in licensing.get("sources") or []}
    unresolved = sorted({f.get("source_id") for f in findings} - set(licence_by_source))
    if unresolved:
        raise RuntimeError(
            f"V4/licensing.json has no decision for source(s) {unresolved}; a licence "
            "status may not be defaulted to unknown")
    for f in findings:
        src = licence_by_source[f["source_id"]]
        f["license"] = src["license_status"]
        f["license_status"] = src["license_status"]
        f["derivatives_allowed"] = src["derivatives_allowed"]
        f["redistribution_right"] = src["redistribution_right"]
        f["legal_clearance"] = src["legal_clearance"]
        f["data_handling_policy"] = src["data_handling_policy"]
        f["rights_decision"] = {"version": licensing["version"],
                                "basis": "V4/licensing.json#" + f["source_id"],
                                "decided": licensing["generated"],
                                "not_a_legal_clearance": True}

    # existing records
    existing = []
    for r in load_jsonl(ROOT / "jsonl" / "findings.jsonl"):
        existing.append(r)
    for p in sorted((ROOT / "jsonl_ml").glob("findings_*.jsonl")):
        for r in load_jsonl(p):
            existing.append(r)
    for r in load_jsonl(ROOT / "jsonl_v3" / "findings.jsonl"):
        existing.append(r)
    for r in load_jsonl(ROOT / "Vbeta" / "jsonl_vbeta" / "findings.jsonl"):
        existing.append(r)

    by_repo = {}
    by_commit = {}
    for r in existing:
        key_repo = (repo_of(r) or "").lower()
        key_commit = commit_of(r) or ""
        if key_repo and key_repo not in ("unknown", ""):
            by_repo.setdefault(key_repo, []).append(r)
        if key_commit and key_commit not in ("unknown", None, ""):
            by_commit.setdefault(key_commit, []).append(r)

    staged_path = ROOT / "work" / "cloned_conversion" / "staged_report_candidates.jsonl"
    staged = []
    if staged_path.exists():
        staged = [json.loads(line) for line in open(
            staged_path, encoding="utf-8") if line.strip()]

    # pinned source commits
    pins = {}
    for pin_path in (ROOT / "V4" / "sources.json",
                     ROOT / "jsonl_v4" / "sources.jsonl"):
        try:
            if pin_path.suffix == ".json":
                rows = json.loads(pin_path.read_text(encoding="utf-8"))
                if isinstance(rows, list):
                    for row in rows:
                        if isinstance(row, dict) and row.get("source_id"):
                            pins[row["source_id"]] = row.get(
                                "source_repository_commit")
            else:
                for row in load_jsonl(pin_path):
                    if row.get("source_id"):
                        pins[row["source_id"]] = row.get(
                            "source_repository_commit")
        except (OSError, json.JSONDecodeError):
            continue
        if pins:
            break

    seen_dup_keys = set()
    seen_dup_ids = {}
    admitted = []
    quarantined = []
    duplicates = []
    candidate_ledger = []
    for f in findings:
        rid = f.get("candidate_id")
        if not f.get("title") or not f.get("original_severity"):
            rec = dict(f)
            rec["decision"] = "QUARANTINED"
            rec["quarantine_reason"] = "missing_core_fields"
            quarantined.append(rec)
            candidate_ledger.append({
                "candidate_id": rid, "decision": "QUARANTINED",
                "reason": "missing_core_fields", "source_id": f["source_id"]})
            continue

        repo = (repo_of(f) or f.get("affected_repository") or "").lower()
        commit = f.get("vulnerable_commit")

        cand_ids = set()
        for r in by_repo.get(repo, []):
            cand_ids.add(id(r))
        if commit and commit not in ("unknown", None):
            for r in by_commit.get(commit, []):
                cand_ids.add(id(r))
        cand_list = [r for r in existing if id(r) in cand_ids] if cand_ids else []

        # within-extracted duplicate: exact same title within the same report
        dup_key = (f.get("source_id"), f.get("report_path"),
                    norm(f.get("title") or f.get("finding_title")))
        within_dup = dup_key in seen_dup_keys

        best_score = 0.0
        best_ref = None
        for r in cand_list:
            s = 0.0
            if (r.get("source_url") or r.get("source_location")) == f.get("source_url"):
                s += 0.4
            if repo and repo == (repo_of(r) or "").lower():
                s += 0.2
            if commit and commit not in ("unknown", None) and commit == (commit_of(r) or ""):
                s += 0.3
            if func_of(f) and func_of(f) == func_of(r):
                s += 0.1
            ts = sim(title_of(r), f.get("title"))
            if ts >= 0.92:
                s += 0.4
            elif ts >= 0.8:
                s += 0.2
            # code identity uses the actual excerpt, not metadata
            ex_r = code_text_of(r)
            ex_f = code_text_of(f)
            if ex_r and ex_f:
                codehash_r = hashlib.sha256(ex_r.encode()).hexdigest()
                codehash_f = hashlib.sha256(ex_f.encode()).hexdigest()
                if codehash_r == codehash_f:
                    s += 0.4
            if ts < 0.8 and s > 0.7:
                s = 0.7
            if s > best_score:
                best_score = s
                best_ref = r

        seen_dup_keys.add(dup_key)
        if dup_key not in seen_dup_ids:
            seen_dup_ids[dup_key] = rid

        if within_dup:
            rec = dict(f)
            rec["decision"] = "DUPLICATE"
            rec["duplicate_of"] = seen_dup_ids.get(dup_key, rid + "-earlier")
            rec["quarantine_reason"] = None
            duplicates.append(rec)
            candidate_ledger.append({
                "candidate_id": rid, "decision": "DUPLICATE",
                "reason": "within_extracted", "source_id": f["source_id"]})
            continue
        if best_score >= 0.85:
            refid = None
            if isinstance(best_ref, dict):
                refid = best_ref.get("candidate_id")
                if not refid:
                    refid = best_ref.get("source_location")
            if not refid:
                refid = str(best_ref)
            rec = dict(f)
            rec["decision"] = "DUPLICATE"
            rec["duplicate_of"] = refid
            duplicates.append(rec)
            candidate_ledger.append({
                "candidate_id": rid, "decision": "DUPLICATE",
                "reason": "existing_match", "score": best_score,
                "source_id": f["source_id"]})
            continue
        if best_score >= 0.55:
            rec = dict(f)
            rec["decision"] = "QUARANTINED"
            rec["quarantine_reason"] = "conflicting_duplicate"
            quarantined.append(rec)
            candidate_ledger.append({
                "candidate_id": rid, "decision": "QUARANTINED",
                "reason": "conflicting_duplicate", "score": best_score,
                "source_id": f["source_id"]})
            continue
        rec = dict(f)
        rec["decision"] = "ADMITTED"
        rec["admitted"] = True
        admitted.append(rec)
        candidate_ledger.append({
            "candidate_id": rid, "decision": "ADMITTED",
            "source_id": f["source_id"]})

    def write_jsonl(path, rows):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")

    write_jsonl(OUT_JSONL4 / "findings.jsonl", admitted)

    # source commit verification
    source_defs = [
        ("halborn_public_reports", "Halborn Security Public Reports",
         ROOT / "work" / "new_sources" / "halborn_reports",
         "https://github.com/HalbornSecurity/PublicReports"),
        ("oak_security_audit_reports", "Oak Security audit reports",
         ROOT / "work" / "new_sources" / "oak_audit_reports",
         "https://github.com/oak-security/audit-reports"),
        ("coinfabrik_audit_reports", "CoinFabrik audit reports",
         ROOT / "work" / "new_sources" / "coinfabrik_reports",
         "https://github.com/CoinFabrik/coinfabrik-audit-reports"),
    ]
    sources_rows = []
    for sid, sname, repo, source_url in source_defs:
        if not repo.exists():
            raise RuntimeError(f"source repository missing: {repo}")
        head = git_head(repo)
        expected = pins.get(sid)
        if expected and head != expected:
            raise RuntimeError(
                f"pinned source commit mismatch for {sid}: "
                f"expected {expected}, got {head}")
        if not expected:
            raise RuntimeError(f"no pinned source commit for {sid}")
        sources_rows.append({
            "source_id": sid,
            "source_name": sname,
            "source_url": source_url,
            "source_type": "professional_audit_firm",
            "source_repository_commit": head,
            "license_status": licence_by_source[sid]["license_status"],
            "rights_decision": {"version": licensing["version"],
                                "basis": "V4/licensing.json#" + sid,
                                "decided": licensing["generated"]},
            "record_type": "source_v4",
            "dataset_version": "4.0",
        })
    write_jsonl(OUT_JSONL4 / "sources.jsonl", sources_rows)

    write_jsonl(OUT_DER4 / "candidate_ledger.jsonl", candidate_ledger)
    write_jsonl(OUT_DER4 / "admitted_ledger.jsonl", admitted)
    write_jsonl(OUT_DER4 / "quarantined_ledger.jsonl", quarantined)
    write_jsonl(OUT_DER4 / "duplicate_ledger.jsonl", duplicates)

    source_counts = Counter(f.get("source_id") for f in findings)
    manifest = {
        "dataset_version": "4.0",
        "layer": "V4",
        "generated_by": "scripts/register_v4.py",
        "source_candidates_staged": len(staged),
        "extracted_findings": len(findings),
        "admitted": len(admitted),
        "quarantined": len(quarantined),
        "duplicates": len(duplicates),
        "candidate_ledger": len(candidate_ledger),
        "reports_by_source": {k: source_counts[k] for k in sorted(source_counts)},
        "verification_levels": {"L0": len(findings)},
        "languages": dict(Counter(f.get("language") for f in findings)),
        "vulnerability_classes": dict(
            Counter(f.get("normalized_vulnerability_class", "unknown")
                    for f in findings)),
        "missing_provenance": sum(
            1 for f in findings
            if not f.get("affected_repository") or not f.get("vulnerable_commit")),
        "licensing_risks": [
            "halborn_public_reports: no LICENSE file found",
            "coinfabrik_audit_reports: no LICENSE file found",
            "oak_security_audit_reports: CC BY-ND 4.0",
        ],
    }
    manifest_text = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    (OUT_DER4 / "manifest.json").write_text(
        manifest_text, encoding="utf-8", newline="\n")
    (OUT_V4 / "manifest.json").write_text(
        manifest_text, encoding="utf-8", newline="\n")
    (OUT_V4 / "sources.json").write_text(
        json.dumps(sources_rows, sort_keys=True, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    print("counts", len(findings), len(admitted), len(quarantined), len(duplicates))


if __name__ == "__main__":
    main()
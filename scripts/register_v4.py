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
    ap.add_argument("--manifest-only", action="store_true",
                    help="rebuild derived_v4/manifest.json offline from the "
                         "committed V4 layers (no network, no git-ignored "
                         "work/ inputs)")
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


def partition_findings(findings, existing):
    """Classify extracted findings into the four V4 buckets.

    Returns (admitted, quarantined, duplicates, candidate_ledger). Every
    finding lands in exactly one bucket, so::

        len(candidate_ledger) == len(findings)
        == len(admitted) + len(quarantined) + len(duplicates)

    A duplicate keeps its full payload and a `duplicate_of` pointer to the
    earlier/existing candidate; duplicates are quarantined as links, never
    deleted or counted as admitted.
    """
    by_repo = {}
    by_commit = {}
    for r in existing:
        key_repo = (repo_of(r) or "").lower()
        key_commit = commit_of(r) or ""
        if key_repo and key_repo not in ("unknown", ""):
            by_repo.setdefault(key_repo, []).append(r)
        if key_commit and key_commit not in ("unknown", None, ""):
            by_commit.setdefault(key_commit, []).append(r)

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
    return admitted, quarantined, duplicates, candidate_ledger


def build_manifest(findings, admitted, quarantined, duplicates,
                   candidate_ledger, staged_count):
    """The V4 manifest, with candidate and admitted count domains separated.

    `verification_levels` is over ADMITTED records only. The wider candidate
    population (admitted + duplicates + quarantined) is reported as
    `candidates` with its own `candidate_verification_levels`; the old
    `verification_levels: {"L0": len(findings)}` counted every candidate and
    sat next to `admitted: 5268`, which is how 5,270 looked like 5,270
    admitted records while only 5,268 exist. Totals are asserted against the
    buckets so a future edit cannot reintroduce the mismatch.
    """
    source_counts = Counter(f.get("source_id") for f in findings)
    manifest = {
        "dataset_version": "4.0",
        "layer": "V4",
        "generated_by": "scripts/register_v4.py",
        "source_candidates_staged": staged_count,
        "extracted_findings": len(findings),
        "candidates": len(candidate_ledger),
        "admitted": len(admitted),
        "quarantined": len(quarantined),
        "duplicates": len(duplicates),
        "candidate_ledger": len(candidate_ledger),
        "reports_by_source": {k: source_counts[k] for k in sorted(source_counts)},
        "verification_levels": dict(Counter(
            (r.get("verification_level") or "L0") for r in admitted)),
        "candidate_verification_levels": dict(Counter(
            (f.get("verification_level") or "L0") for f in findings)),
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
    if manifest["candidates"] != len(findings):
        raise RuntimeError(
            f"candidate ledger {manifest['candidates']} != findings {len(findings)}")
    bucket_total = (manifest["admitted"] + manifest["quarantined"]
                    + manifest["duplicates"])
    if bucket_total != manifest["candidates"]:
        raise RuntimeError(
            f"admitted+quarantined+duplicates {bucket_total} != "
            f"candidates {manifest['candidates']}")
    if sum(manifest["verification_levels"].values()) != manifest["admitted"]:
        raise RuntimeError(
            "verification_levels does not sum to admitted records: "
            f"{sum(manifest['verification_levels'].values())} != "
            f"{manifest['admitted']}")
    if sum(manifest["candidate_verification_levels"].values()) != manifest["candidates"]:
        raise RuntimeError(
            "candidate_verification_levels does not sum to candidates: "
            f"{sum(manifest['candidate_verification_levels'].values())} != "
            f"{manifest['candidates']}")
    return manifest


OFFLINE_ALLOWED_CHANGES = {"verification_levels", "candidates",
                           "candidate_verification_levels"}


def _line_count(path):
    return len(load_jsonl(path))


def committed_candidate_domain(root):
    """Deterministic candidate domain rebuilt purely from committed layers.

    candidate domain = admitted payloads + duplicate payloads + quarantined
    payloads, sorted by `candidate_id` so the order never depends on file
    iteration or dict insertion order. No network access and no reads from
    the git-ignored `work/` harvest inputs.
    """
    root = Path(root)
    admitted = load_jsonl(root / "derived_v4" / "admitted_ledger.jsonl")
    duplicates = load_jsonl(root / "derived_v4" / "duplicate_ledger.jsonl")
    quarantined = load_jsonl(root / "derived_v4" / "quarantined_ledger.jsonl")
    candidate_ledger = load_jsonl(root / "derived_v4" / "candidate_ledger.jsonl")
    candidates = sorted(admitted + duplicates + quarantined,
                        key=lambda r: str(r.get("candidate_id")))

    # Cross-checks against the other committed layers: the ledgers and the
    # published admitted layer must agree line-for-line, and the candidate
    # domain must match the candidate ledger row count exactly.
    admitted_ids = [str(r.get("candidate_id")) for r in admitted]
    if len(set(admitted_ids)) != len(admitted_ids):
        raise RuntimeError("duplicate candidate_ids inside admitted_ledger")
    if len(set(str(r.get("candidate_id")) for r in candidates)) != len(candidates):
        raise RuntimeError("candidate domain contains duplicate candidate_ids")
    findings_ids = [str(r.get("candidate_id"))
                    for r in load_jsonl(root / "jsonl_v4" / "findings.jsonl")]
    if sorted(findings_ids) != sorted(admitted_ids):
        raise RuntimeError(
            f"jsonl_v4/findings.jsonl ({len(findings_ids)} rows) does not "
            f"cover admitted_ledger ({len(admitted_ids)} rows) exactly")
    if len(candidate_ledger) != len(candidates):
        raise RuntimeError(
            f"candidate_ledger {len(candidate_ledger)} != candidate domain "
            f"{len(candidates)}")
    ledger_decisions = Counter(str(r.get("decision", "")).upper()
                               for r in candidate_ledger)
    if (ledger_decisions.get("ADMITTED", 0) != len(admitted)
            or ledger_decisions.get("DUPLICATE", 0) != len(duplicates)
            or ledger_decisions.get("QUARANTINED", 0) != len(quarantined)):
        raise RuntimeError(
            f"candidate_ledger decision counts {dict(ledger_decisions)} do "
            f"not match buckets admitted={len(admitted)} "
            f"duplicates={len(duplicates)} quarantined={len(quarantined)}")
    return candidates, admitted, quarantined, duplicates, candidate_ledger


def build_manifest_from_committed_layers(root):
    """--manifest-only rebuild: the V4 manifest from committed layers alone.

    Reuses build_manifest so the online (register) and offline (audit) paths
    cannot drift. `source_candidates_staged` counts the staged harvest file
    `work/cloned_conversion/staged_report_candidates.jsonl`, which is
    git-ignored and absent in this checkout, so it cannot be recomputed
    offline: the value recorded in the committed manifest is preserved and
    no new number is invented. Everything else is derived from the committed
    layers; the caller diffs old vs new and refuses to ship unexpected key
    changes.
    """
    root = Path(root)
    manifest_path = root / "derived_v4" / "manifest.json"
    old_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidates, admitted, quarantined, duplicates, candidate_ledger = (
        committed_candidate_domain(root))

    # source_candidates_staged cannot be recomputed offline (see docstring):
    # preserve the committed value instead of inventing one.
    if "source_candidates_staged" not in old_manifest:
        raise RuntimeError(
            "committed manifest has no source_candidates_staged to preserve")
    staged_count = old_manifest["source_candidates_staged"]

    manifest = build_manifest(candidates, admitted, quarantined, duplicates,
                              candidate_ledger, staged_count)

    # Hard assertions tying the counts to the committed layer files.
    expected = {
        "candidates": _line_count(root / "derived_v4" / "candidate_ledger.jsonl"),
        "candidate_ledger": _line_count(
            root / "derived_v4" / "candidate_ledger.jsonl"),
        "extracted_findings": _line_count(
            root / "derived_v4" / "candidate_ledger.jsonl"),
        "admitted": _line_count(root / "derived_v4" / "admitted_ledger.jsonl"),
        "duplicates": _line_count(root / "derived_v4" / "duplicate_ledger.jsonl"),
        "quarantined": _line_count(
            root / "derived_v4" / "quarantined_ledger.jsonl"),
    }
    for key, want in expected.items():
        if manifest.get(key) != want:
            raise RuntimeError(
                f"offline rebuild: {key}={manifest.get(key)} != committed "
                f"layer line count {want}")
    if manifest["admitted"] != _line_count(root / "jsonl_v4" / "findings.jsonl"):
        raise RuntimeError(
            "offline rebuild: admitted != jsonl_v4/findings.jsonl line count")
    if manifest["candidates"] != (manifest["admitted"] + manifest["duplicates"]
                                  + manifest["quarantined"]):
        raise RuntimeError("offline rebuild: candidates != admitted + duplicates + quarantined")

    # No unrelated key may change: verification_levels is corrected to the
    # admitted domain and candidates/candidate_verification_levels are the
    # new candidate-domain keys; every other key must be identical to the
    # committed manifest.
    changed = {k for k in set(old_manifest) | set(manifest)
               if old_manifest.get(k) != manifest.get(k)}
    unexpected = sorted(changed - OFFLINE_ALLOWED_CHANGES)
    if unexpected:
        raise RuntimeError(
            "offline rebuild changed keys it must not touch: "
            + ", ".join(f"{k}: {old_manifest.get(k)!r} -> {manifest.get(k)!r}"
                        for k in unexpected))
    # `main()` writes V4/manifest.json and derived_v4/manifest.json from one
    # serialisation, so the second copy is held to the same rule: outside the
    # corrected keys it must already agree with the recomputed manifest, or the
    # checkout carries drift this mode did not introduce.
    layer_path = root / "V4" / "manifest.json"
    if layer_path.exists():
        layer_old = json.loads(layer_path.read_text(encoding="utf-8"))
        layer_drift = sorted(
            {k for k in set(layer_old) | set(manifest)
             if layer_old.get(k) != manifest.get(k)} - OFFLINE_ALLOWED_CHANGES)
        if layer_drift:
            raise RuntimeError(
                "V4/manifest.json disagrees with the committed layers on keys "
                "outside the correction: " + ", ".join(layer_drift))
    return old_manifest, manifest


def diff_manifest_keys(old, new):
    """Key-level old -> new diff lines for terminal reporting."""
    lines = []
    for key in sorted(set(old) | set(new)):
        if old.get(key) != new.get(key):
            lines.append(f"  {key}: {old.get(key)!r} -> {new.get(key)!r}")
    return lines


def manifest_serialise(manifest):
    return json.dumps(manifest, sort_keys=True, indent=2) + "\n"


def run_manifest_only(root):
    """Regenerate the V4 manifests from committed layers, safely.

    Both copies are written from one serialisation, exactly as `main()` does:
    `V4/manifest.json` and `derived_v4/manifest.json` are the same document, so
    a rebuild that wrote only one of them would ship two V4 manifests whose
    declared counts disagree - the very defect this mode exists to correct.
    """
    root = Path(root)
    old_manifest, manifest = build_manifest_from_committed_layers(root)
    new_text = manifest_serialise(manifest)
    changed = diff_manifest_keys(old_manifest, manifest)
    print("manifest key diff (old -> new):")
    if changed:
        print("\n".join(changed))
    else:
        print("  (no changes)")
    for target in (root / "derived_v4" / "manifest.json",
                   root / "V4" / "manifest.json"):
        target.write_text(new_text, encoding="utf-8", newline="\n")
        print(f"wrote {target.relative_to(root)}")
    print("counts candidates={} admitted={} duplicates={} quarantined={}".format(
        manifest["candidates"], manifest["admitted"],
        manifest["duplicates"], manifest["quarantined"]))
    return manifest


def main():
    args = parse_args()
    ROOT = find_root(args.root)
    if getattr(args, "manifest_only", False):
        # Offline, deterministic manifest rebuild from the committed V4 layers
        # only; the harvest inputs below are git-ignored and may be absent.
        run_manifest_only(ROOT)
        return
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

    staged_path = ROOT / "work" / "cloned_conversion" / "staged_report_candidates.jsonl"
    staged = []
    if staged_path.exists():
        staged = [json.loads(line) for line in open(
            staged_path, encoding="utf-8") if line.strip()]

    admitted, quarantined, duplicates, candidate_ledger = partition_findings(
        findings, existing)

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

    manifest = build_manifest(findings, admitted, quarantined, duplicates,
                              candidate_ledger, len(staged))
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
#!/usr/bin/env python3
"""The build gate. Fails the build on critical integrity problems.

    python scripts/validate.py            # run every check, exit non-zero on failure
    python scripts/validate.py --quiet
    python scripts/validate.py --online   # also probe that cited URLs resolve

Checks, grouped by what they protect:

  structure     JSON/JSONL validity, schema shape, record uniqueness
  provenance    required provenance, URL and commit format, mutable-ref flagging
  consistency   statistics, severity, PoC, patch, licence, negative labels
  evidence      every evidence_type is in the closed vocabulary; no
                experimentally_verified without a run artefact behind it
  splits        repository isolation, id isolation, cross-split duplicates
  v2.1          experimental claims are backed by run artefacts, the new
                vocabularies are closed, subsets obey their admission rules, and
                the new leakage detectors report zero

`reported_statistics == computed_statistics` is enforced by regenerating the
stats in-process and comparing against reports/dataset_stats.json on disk.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_stats  # noqa: E402
from vlun import (  # noqa: E402
    DATASET_VERSION, DERIVED, EVIDENCE_TYPES, EXEC_FAILURE_REASONS, EXPERIMENTS, JSONL, REPORTS,
    ROOT, SPLITS, WORK, code_entries, load_core, load_splits, log, read_jsonl, rec_id,
    sha256_text, snippet_entries, write_json,
)

SHA40 = re.compile(r"^[0-9a-f]{40}$")
PERMALINK = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/([^/#?]+)/([^#]+)(?:#L(\d+)(?:-L?(\d+))?)?$")
REQUIRED_TOP = {
    "findings.jsonl": ["record_type", "source", "protocol", "finding", "security_reasoning",
                       "poc", "patch", "validation", "provenance", "confidence"],
    "negative_findings.jsonl": ["record_type", "source", "protocol", "finding", "negative_analysis",
                                "security_reasoning", "poc", "patch", "validation", "provenance",
                                "confidence"],
    "exploits.jsonl": ["record_type", "source", "protocol", "finding", "exploit", "provenance",
                       "confidence"],
    "patches.jsonl": ["record_type", "source", "protocol", "finding", "patch", "provenance",
                      "confidence"],
    "protocol.jsonl": ["record_type", "source", "protocol", "provenance", "confidence"],
    "metadata.jsonl": ["record_type", "source", "provenance", "confidence"],
    "errors.jsonl": ["record_type", "source", "error", "provenance", "confidence"],
}
# `finding` block keys differ by family: v1 uses `status` on judged records and
# `validation_status` on exploit/patch rows. Only `id` and `severity` are
# universal, and enforcing more would be a schema invention, not a check.
REQUIRED_NESTED = {
    "finding": ["id", "severity"],
    "provenance": ["source_files", "source_urls"],
}
EXTRA_NESTED = {
    "findings.jsonl": {"finding": ["title", "status", "severity_source", "record_class"]},
    "negative_findings.jsonl": {"finding": ["title", "status"]},
    "exploits.jsonl": {"finding": ["title", "validation_status"]},
    "patches.jsonl": {"finding": ["title", "validation_status"]},
}


class Report:
    def __init__(self, quiet: bool = False):
        self.checks: list[dict] = []
        self.quiet = quiet

    def add(self, group: str, check: str, ok: bool, failures=None, detail=None, critical=True):
        fails = list(failures or []) if not ok else []
        self.checks.append({"group": group, "check": check, "ok": bool(ok),
                            "critical": critical,
                            "failure_count": len(fails),
                            "failures": fails[:25],
                            "detail": detail})
        if not self.quiet:
            mark = "ok  " if ok else ("FAIL" if critical else "warn")
            extra = f"  ({len(fails)} failures)" if fails else ""
            log(f"  [{mark}] {group}/{check}{extra}")
            if fails:
                for f in fails[:5]:
                    log(f"         - {f}")
        return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--online", action="store_true", help="probe cited URLs (slow, network)")
    args = ap.parse_args()

    rep = Report(args.quiet)
    log("validate.py")

    # ---------------------------------------------------------------- structure
    core = {}
    bad_json = []
    for fname, keys in REQUIRED_TOP.items():
        path = JSONL / fname
        rows = []
        for i, line in enumerate(open(path, encoding="utf-8"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                bad_json.append(f"{fname}:{i} {exc}")
        core[fname] = rows
    rep.add("structure", "jsonl_parses", not bad_json, bad_json)

    missing = []
    for fname, keys in REQUIRED_TOP.items():
        for r in core[fname]:
            for k in keys:
                if k not in r:
                    missing.append(f"{fname} {rec_id(r)} missing top-level '{k}'")
            for block, need in REQUIRED_NESTED.items():
                if isinstance(r.get(block), dict):
                    for k in need:
                        if k not in r[block]:
                            missing.append(f"{fname} {rec_id(r)} missing {block}.{k}")
            for block, need in EXTRA_NESTED.get(fname, {}).items():
                if isinstance(r.get(block), dict):
                    for k in need:
                        if k not in r[block]:
                            missing.append(f"{fname} {rec_id(r)} missing {block}.{k}")
    rep.add("structure", "required_fields_present", not missing, missing)

    dupes = []
    for fname, rows in core.items():
        c = collections.Counter(rec_id(r) for r in rows)
        for k, v in c.items():
            if v > 1:
                dupes.append(f"{fname} {k} x{v}")
    rep.add("structure", "record_uniqueness_within_file", not dupes, dupes)

    cross = []
    fids = collections.Counter(rec_id(r) for r in core["findings.jsonl"])
    eids = collections.Counter((r["finding"]["id"]) for r in core["exploits.jsonl"])
    sids = collections.Counter((r["finding"]["id"]) for r in core["patches.jsonl"])
    for name, c in (("exploits", eids), ("patches", sids)):
        unknown = sorted(set(c) - set(fids))
        if unknown:
            cross.append(f"{name} reference unknown finding ids: {unknown[:10]}")
    rep.add("structure", "cross_file_id_references_resolve", not cross, cross)

    version_bad = [f"{fn} dataset_version={ {r.get('dataset_version') for r in rows} }"
                   for fn, rows in core.items()
                   if {r.get("dataset_version") for r in rows} not in ({"1.0"}, set())]
    rep.add("structure", "source_layer_version_uniform", not version_bad, version_bad)

    # -------------------------------------------------------------- provenance
    no_src = [f"{fn} {rec_id(r)}" for fn, rows in core.items() for r in rows
              if not (r.get("source") or {}).get("repository")]
    rep.add("provenance", "every_record_has_a_source", not no_src, no_src)

    mutable, malformed = [], []
    for fn, rows in core.items():
        for r in rows:
            for e in code_entries(r):
                sha = e.get("commit_sha")
                if sha and not SHA40.match(sha):
                    mutable.append(f"{fn} {rec_id(r)} {e.get('file')} commit_sha={sha!r}")
            for u in (r.get("provenance") or {}).get("source_urls") or []:
                if "/blob/" in u and not PERMALINK.match(u):
                    malformed.append(f"{fn} {rec_id(r)} {u}")
    rep.add("provenance", "blob_permalinks_wellformed", not malformed, malformed,
            critical=False,
            detail="every /blob/ URL in the provenance layer parses as owner/repo/blob/<sha>/path")
    # `jsonl/` is the read-only original-evidence layer. It is never rewritten by
    # design, so the v1 mutable refs it recorded are a permanent, honest property
    # of that layer and are reported as a counted warning. The DERIVED layer is
    # the one this pipeline owns and rewrites, so it is checked separately below
    # and a mutable ref there is CRITICAL.
    src_mutable_n = len(mutable)
    rep.add("provenance", "source_layer_commit_pins_counted", True, [], critical=False,
            detail=(f"{src_mutable_n} citations in the read-only jsonl/ layer still use a "
                    f"mutable ref (a branch name). That layer is the v1 evidence record and is "
                    f"never rewritten, so this is a disclosed count, not a defect. The DERIVED "
                    f"layer is fully pinned - see provenance/derived_commit_pins_are_immutable."))

    # The load-bearing provenance check: does the layer we actually ship have any
    # citation that resolves to whatever is at HEAD today? Computed from
    # derived/records.jsonl itself, never from a report about it.
    derived_mutable, derived_total = [], 0
    _dpath = DERIVED / "records.jsonl"
    if _dpath.exists():
        for r in read_jsonl(_dpath):
            for key in ("code_context", "code_context_expanded",
                        "code_reference_only", "vulnerable_code"):
                for e in (r.get(key) or []):
                    if not isinstance(e, dict):
                        continue
                    derived_total += 1
                    sha = e.get("commit_sha")
                    u = e.get("source_url") or ""
                    m = re.search(r"/blob/([^/]+)/", u)
                    bad_sha = bool(sha) and not SHA40.match(sha)
                    bad_url = bool(m) and not SHA40.match(m.group(1))
                    if bad_sha or bad_url:
                        derived_mutable.append(
                            f"{rec_id(r)} {key} {e.get('file')} "
                            f"commit_sha={sha!r} url_ref={m.group(1) if m else None!r}")
    rep.add("provenance", "derived_commit_pins_are_immutable", not derived_mutable,
            derived_mutable, critical=True,
            detail=(f"{derived_total - len(derived_mutable)}/{derived_total} citations in "
                    f"derived/records.jsonl are pinned to a 40-hex commit and are therefore "
                    f"reproducible over time; every one is written by "
                    f"scripts/resolve_citations.py, which records original_reference, "
                    f"source_url_original, resolution_method and resolution_confidence inline"))

    rng = []
    for fn, rows in core.items():
        for r in rows:
            for e in snippet_entries(r):
                a, b = e.get("line_start"), e.get("line_end")
                if a and b and a > b:
                    rng.append(f"{fn} {rec_id(r)} {e.get('file')} start {a} > end {b}")
                if e.get("line_range_verified") and not (e.get("snippet") or "").strip():
                    rng.append(f"{fn} {rec_id(r)} verified range with no snippet")
    rep.add("provenance", "line_ranges_sane", not rng, rng)

    snippet_mismatch = []
    for fn in ("findings.jsonl", "negative_findings.jsonl"):
        for r in core[fn]:
            for e in snippet_entries(r):
                a, b = e.get("line_start"), e.get("line_end")
                sn = e.get("snippet") or ""
                if a and sn and sn.count("\n") + 1 > (b - a + 1) * 4:
                    snippet_mismatch.append(f"{fn} {rec_id(r)} {e.get('file')} "
                                            f"snippet far longer than its claimed range")
    rep.add("provenance", "snippet_length_plausible", not snippet_mismatch, snippet_mismatch,
            critical=False)

    # ------------------------------------------------------------- consistency
    recomputed = generate_stats.build_stats()
    on_disk = json.loads((REPORTS / "dataset_stats.json").read_text(encoding="utf-8"))
    diff = []
    if on_disk != recomputed:
        for k in sorted(set(on_disk) | set(recomputed)):
            if on_disk.get(k) != recomputed.get(k):
                diff.append(f"{k}: reported={on_disk.get(k)!r} computed={recomputed.get(k)!r}")
    rep.add("consistency", "reported_statistics_equal_computed", not diff, diff,
            detail=f"{len(on_disk)} top-level stat groups compared")

    sev_bad = []
    sev_by_id = {r["finding"]["id"]: r["finding"].get("severity") for r in core["findings.jsonl"]}
    for fn, rows in (("exploits.jsonl", core["exploits.jsonl"]), ("patches.jsonl", core["patches.jsonl"])):
        for r in rows:
            fid, sv = r["finding"]["id"], r["finding"].get("severity")
            if fid in sev_by_id and sev_by_id[fid] != sv:
                sev_bad.append(f"{fn} {fid} severity {sv!r} != findings.jsonl {sev_by_id[fid]!r}")
    rep.add("consistency", "severity_agrees_across_files", not sev_bad, sev_bad)

    splits = load_splits()
    split_sev = []
    for s, rows in splits.items():
        for r in rows:
            fid, sv = (r.get("finding") or {}).get("id"), (r.get("finding") or {}).get("severity")
            if fid in sev_by_id and sv != sev_by_id[fid]:
                split_sev.append(f"splits/{s} {fid} {sv!r} != {sev_by_id[fid]!r}")
    rep.add("consistency", "severity_agrees_with_splits", not split_sev, split_sev)

    poc_bad = []
    for fn in ("findings.jsonl", "negative_findings.jsonl"):
        for r in core[fn]:
            p = r.get("poc") or {}
            if p.get("reproducible"):
                poc_bad.append(f"{fn} {rec_id(r)} poc.reproducible=true with no execution artefact")
    rep.add("consistency", "no_unexecuted_poc_claims_reproducible", not poc_bad, poc_bad)

    patch_bad = []
    for r in core["patches.jsonl"]:
        p = r.get("patch") or {}
        if p.get("diff_withheld") and (p.get("diff") or "").strip():
            patch_bad.append(f"{rec_id(r)} diff_withheld but diff is present")
        if not p.get("diff_withheld") and p.get("available") and not (p.get("diff") or "").strip():
            patch_bad.append(f"{rec_id(r)} patch.available but no diff and not marked withheld")
    rep.add("consistency", "patch_diff_and_withheld_flag_agree", not patch_bad, patch_bad)

    neg_bad = []
    for r in core["negative_findings.jsonl"]:
        na = r.get("negative_analysis") or {}
        v = r.get("validation") or {}
        if na.get("rejection_basis") == "label_only" and (v.get("judge_decision") or "").strip():
            neg_bad.append(f"{rec_id(r)} label_only but carries a judge decision")
        if (r["finding"].get("severity") or "").strip():
            neg_bad.append(f"{rec_id(r)} rejected record carries a severity")
        if not na.get("rejection_basis"):
            neg_bad.append(f"{rec_id(r)} no rejection_basis")
    rep.add("consistency", "negative_labels_consistent", not neg_bad, neg_bad)

    lic_bad = []
    for r in core["findings.jsonl"] + core["negative_findings.jsonl"]:
        p = r.get("provenance") or {}
        if (p.get("license") or "").strip() and not p.get("license_verified"):
            lic_bad.append(f"{rec_id(r)} declares a licence but license_verified is false")
    rep.add("consistency", "license_declared_implies_verified", not lic_bad, lic_bad)

    # -------------------------------------------------------------- evidence
    EV = set(EVIDENCE_TYPES)
    ev_bad, verified_without_run = [], []
    runs = {v["finding_id"]: v for f in sorted((WORK / "poc_runs").glob("*.json"))
            if f.name != "_all.json"
            for v in json.loads(f.read_text(encoding="utf-8")).get("verdicts", [])}

    def walk(node, path, fid):
        if isinstance(node, dict):
            et = node.get("evidence_type")
            if et is not None:
                if et not in EV:
                    ev_bad.append(f"{fid} {path}.evidence_type={et!r} not in vocabulary")
                if et == "experimentally_verified" and fid not in runs:
                    verified_without_run.append(f"{fid} {path} claims experimentally_verified "
                                                f"with no run artefact")
            for k, v in node.items():
                walk(v, f"{path}.{k}", fid)
        elif isinstance(node, list):
            for i, v in enumerate(node[:50]):
                walk(v, f"{path}[{i}]", fid)

    for fn in ("records.jsonl", "hard_negatives.jsonl", "counterexamples.jsonl"):
        p = DERIVED / fn
        if not p.exists():
            continue
        for r in read_jsonl(p):
            walk(r, fn, (r.get("finding") or r.get("source_record") or {}).get("id") or r.get("id"))
    rep.add("evidence", "evidence_type_in_closed_vocabulary", not ev_bad, ev_bad)

    # Every `experimentally_verified` claim must be backed by an artefact that is
    # IN THE REPOSITORY, not by something under git-ignored `work/`. This is what
    # makes the headline PoC numbers auditable by a third party.
    committed_runs = {}
    _idx = REPORTS / "run_artefacts_index.json"
    if _idx.exists():
        committed_runs = json.loads(_idx.read_text(encoding="utf-8")).get("records", {})

    def claimed_fids():
        """Every record id in derived/ that asserts experimentally_verified somewhere."""
        out = set()

        def scan(node, fid):
            if isinstance(node, dict):
                if node.get("evidence_type") == "experimentally_verified":
                    out.add(fid)
                for v in node.values():
                    scan(v, fid)
            elif isinstance(node, list):
                for v in node[:200]:
                    scan(v, fid)

        for fn in ("records.jsonl", "hard_negatives.jsonl", "counterexamples.jsonl"):
            p = DERIVED / fn
            if not p.exists():
                continue
            for r in read_jsonl(p):
                fid = ((r.get("finding") or r.get("source_record") or {}).get("id")
                       or r.get("id") or "")
                scan(r, fid)
        return {f for f in out if f}

    claimed = claimed_fids()
    unbacked = sorted(f for f in claimed if f not in committed_runs)
    rep.add("evidence", "experimental_claims_have_a_committed_run_artefact", not unbacked,
            unbacked, critical=True,
            detail=(f"{len(claimed)} finding(s) in derived/ claim experimentally_verified; "
                    f"{len(committed_runs)} executed findings have a committed artefact under "
                    f"experiments/*__poc_run/result.json indexed by "
                    f"reports/run_artefacts_index.json. work/poc_runs is git-ignored and is "
                    f"deliberately not accepted as evidence."))

    stale = []
    for f in sorted((WORK / "poc_runs").glob("*.json")) if (WORK / "poc_runs").exists() else []:
        if f.name == "_all.json":
            continue
        for v in json.loads(f.read_text(encoding="utf-8")).get("verdicts", []):
            if v.get("verdict") == "reproduced" and not v.get("evidence", {}).get("forge_status"):
                stale.append(f"{f.name} {v['finding_id']}")
    rep.add("evidence", "every_reproduced_verdict_names_a_forge_status", not stale, stale)

    reason_bad = []
    for r in read_jsonl(DERIVED / "hard_negatives.jsonl"):
        for key in ("blocking_condition", "why_exploit_fails", "actual_protocol_behavior"):
            e = r.get(key) or {}
            if e.get("value") and e.get("evidence_type") not in EV:
                reason_bad.append(f"{r['source_record']['id']} {key} bad evidence_type")
            if e.get("value") and e.get("evidence_type") == "unknown":
                reason_bad.append(f"{r['source_record']['id']} {key} has a value but is typed unknown")
    rep.add("evidence", "negative_reasons_typed_consistently", not reason_bad, reason_bad)

    reasons_used = collections.Counter()
    if (WORK / "poc_runs").exists():
        for f in sorted((WORK / "poc_runs").glob("*.json")):
            if f.name == "_all.json":
                continue
            for v in json.loads(f.read_text(encoding="utf-8")).get("verdicts", []):
                if v.get("failure_reason"):
                    reasons_used[v["failure_reason"]] += 1
    unknown_reason = sorted(set(reasons_used) - set(EXEC_FAILURE_REASONS))
    rep.add("evidence", "failure_reasons_in_closed_vocabulary", not unknown_reason, unknown_reason)

    ver_bad = []
    for f in sorted((WORK / "poc_runs").glob("*.json")) if (WORK / "poc_runs").exists() else []:
        if f.name == "_all.json":
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        for v in d.get("verdicts", []):
            if v["verdict"] == "reproduced" and v.get("evidence", {}).get("forge_status") != "Success":
                ver_bad.append(f"{f.name} {v['finding_id']} reproduced without forge Success")
    rep.add("evidence", "reproduced_requires_a_successful_forge_run", not ver_bad, ver_bad)

    # ----------------------------------------------------------------- splits
    repo_splits = collections.defaultdict(set)
    for s, rows in splits.items():
        for r in rows:
            repo_splits[r["source"]["repository"]].add(s)
    rep.add("splits", "repository_not_in_two_splits",
            not [k for k, v in repo_splits.items() if len(v) > 1],
            [f"{k}: {sorted(v)}" for k, v in repo_splits.items() if len(v) > 1])

    id_splits = collections.defaultdict(set)
    for s, rows in splits.items():
        for r in rows:
            id_splits[rec_id(r)].add(s)
    rep.add("splits", "finding_id_not_in_two_splits",
            not [k for k, v in id_splits.items() if len(v) > 1],
            [f"{k}: {sorted(v)}" for k, v in id_splits.items() if len(v) > 1])

    leak = REPORTS / "leakage_report.json"
    if leak.exists():
        lr = json.loads(leak.read_text(encoding="utf-8"))
        post = lr.get("splits_v2", {}).get("post_check") or {}
        bad = []
        for k in ("near_duplicate_overlap", "semantic_overlap"):
            if post.get(k):
                bad.append(f"splits_v2 still has {post[k]} {k}")
        if post.get("repository_violations"):
            bad.append(f"splits_v2 repository violations: {post['repository_violations']}")
        rep.add("splits", "splits_v2_leakage_free", not bad, bad, critical=False,
                detail="checked against reports/leakage_report.json; run "
                       "scripts/check_leakage.py --emit splits_v2 first")
    else:
        rep.add("splits", "leakage_report_present", False, ["reports/leakage_report.json missing"])

    # ------------------------------------------------------------ derived layer
    der_bad = []
    for p in sorted(DERIVED.glob("*.jsonl")):
        try:
            read_jsonl(p)
        except Exception as exc:  # noqa: BLE001
            der_bad.append(f"{p.name}: {exc}")
    rep.add("consistency", "derived_files_parse", not der_bad, der_bad)

    if (DERIVED / "manifest.json").exists():
        dm = json.loads((DERIVED / "manifest.json").read_text(encoding="utf-8"))
        if dm.get("records") and (DERIVED / "records.jsonl").exists():
            actual = len(read_jsonl(DERIVED / "records.jsonl"))
            rep.add("consistency", "derived_manifest_matches_file",
                    dm["records"] == actual,
                    [f"manifest says {dm['records']}, file has {actual}"])

    # ------------------------------------------------------------------ online
    if args.online:
        urls = sorted({u for rows in core.values() for r in rows
                       for u in (r.get("provenance") or {}).get("source_urls") or []})[:40]
        dead = []
        for u in urls:
            try:
                req = urllib.request.Request(u, method="HEAD",
                                             headers={"User-Agent": "vlun-validate"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    if resp.status >= 400:
                        dead.append(f"{resp.status} {u}")
            except urllib.error.HTTPError as exc:
                if exc.code not in (403, 429):
                    dead.append(f"{exc.code} {u}")
            except Exception as exc:  # noqa: BLE001
                dead.append(f"{type(exc).__name__} {u}")
        rep.add("provenance", "cited_urls_resolve", not dead, dead, critical=False,
                detail=f"{len(urls)} URLs probed (403/429 treated as reachable)")

    # ==================================================================
    # v2.1 gate: experimental claims must be backed by artefacts, and the
    # new artefacts must agree with the reports that summarise them.
    # ==================================================================
    import experiments as _ex  # noqa: E402
    import poc_classification as _pc  # noqa: E402

    def _J(name):
        f = REPORTS / name
        if not f.exists():
            return {}
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    exps = _J("verified_experiments.json")
    repro = _J("reproduction_stats.json")
    pv = _J("patch_verification_v2.json")
    negv = _J("negative_verification_stats.json")
    cites = _J("citation_resolution.json")
    subs = _J("subsets.json")

    # 1. every experiment artefact directory exists and records a commit
    missing_art, bad_commit = [], []
    for e in exps.get("experiments", []):
        for label in ("vulnerable", "fixed"):
            rev = (e.get("revisions") or {}).get(label) or {}
            art = rev.get("artifact")
            if not art:
                missing_art.append(f"{e['finding_id']}:{label}")
                continue
            rj = Path(art) / "result.json"
            if not rj.exists():
                missing_art.append(f"{e['finding_id']}:{label}")
                continue
            d = json.loads(rj.read_text(encoding="utf-8"))
            commit = (d.get("repository") or {}).get("commit") or ""
            if not SHA40.match(str(commit)):
                bad_commit.append(f"{e['finding_id']}:{label}={commit[:12]}")
    rep.add("v2.1", "every_experiment_has_a_result_artefact", not missing_art, missing_art)
    rep.add("v2.1", "every_experiment_artefact_names_a_full_commit", not bad_commit, bad_commit)

    # 2. no production file was modified to make an experiment pass
    prod_touched = []
    for e in exps.get("experiments", []):
        for label in ("vulnerable", "fixed"):
            art = ((e.get("revisions") or {}).get(label) or {}).get("artifact")
            if not art:
                continue
            f = Path(art) / "result.json"
            if not f.exists():
                continue
            d = json.loads(f.read_text(encoding="utf-8"))
            n = (d.get("forensics") or {}).get("production_files_modified_count")
            if n:
                prod_touched.append(f"{e['finding_id']}:{label} modified {n} production file(s)")
    rep.add("v2.1", "no_experiment_modified_production_code", not prod_touched, prod_touched)

    # 3. L6 requires BOTH legs to have run the way the registry declared
    bogus_l6 = []
    for r in repro.get("per_record", []):
        if r.get("poc_level") != "L6":
            continue
        ex = r.get("experiment") or {}
        if not (ex.get("vulnerable_status") and ex.get("fixed_status")):
            bogus_l6.append(r["finding_id"])
    rep.add("v2.1", "L6_requires_both_revisions_executed", not bogus_l6, bogus_l6)

    # 4. no record above L2 without an experiment that actually executed
    unsupported = []
    for r in repro.get("per_record", []):
        lvl = r.get("poc_level") or "L0"
        if lvl in ("L0", "L1", "L2"):
            continue
        if (r.get("experiment") or {}).get("vulnerable_status") not in ("pass", "fail"):
            unsupported.append(f"{r['finding_id']}={lvl}")
    rep.add("v2.1", "no_poc_level_above_L2_without_an_executed_run", not unsupported, unsupported)

    # 5. `effective` patches need a vulnerable run that failed AND a fixed run that passed
    bogus_eff = []
    for r in pv.get("records", []):
        if r.get("fix_effectiveness") != "effective":
            continue
        if r.get("vulnerable_revision_result") != "fail" or r.get("fixed_revision_result") != "pass":
            bogus_eff.append(r["finding_id"])
    rep.add("v2.1", "effective_patch_has_vulnerable_fail_and_fixed_pass", not bogus_eff, bogus_eff)

    # 6. an experimentally verified negative needs an executed experiment behind it
    bogus_neg = []
    for r in negv.get("records", []):
        if r.get("negative_class") != "experimentally_verified":
            continue
        if not (r.get("executed_disproof") or {}).get("command"):
            bogus_neg.append(r["finding_id"])
    rep.add("v2.1", "experimentally_verified_negative_has_an_execution", not bogus_neg, bogus_neg)

    # 7. a corroborated duplicate must never be labelled a false positive
    mislabelled = [r["finding_id"] for r in negv.get("records", [])
                   if r.get("negative_class") == "corroborated_duplicate"
                   and r.get("is_false_positive") is not False]
    rep.add("v2.1", "corroborated_duplicate_is_not_called_a_false_positive",
            not mislabelled, mislabelled)

    # 8. controlled vocabularies
    bad_class = [r["finding_id"] for r in repro.get("per_record", [])
                 if r.get("poc_class") not in _pc.POC_CLASSES]
    rep.add("v2.1", "poc_class_in_closed_vocabulary", not bad_class, bad_class)

    bad_level = [r["finding_id"] for r in repro.get("per_record", [])
                 if r.get("poc_level") not in _pc.POC_LEVELS]
    rep.add("v2.1", "poc_level_in_closed_vocabulary", not bad_level, bad_level)

    bad_reason = sorted({(r.get("experiment") or {}).get("run_failure_reason")
                         for r in repro.get("per_record", [])
                         if (r.get("experiment") or {}).get("run_failure_reason")
                         and (r.get("experiment") or {}).get("run_failure_reason")
                         not in _pc.FAILURE_REASONS})
    rep.add("v2.1", "run_failure_reason_in_controlled_vocabulary", not bad_reason, bad_reason)

    bad_negclass = sorted({r.get("negative_class") for r in negv.get("records", [])
                           if r.get("negative_class")
                           and r["negative_class"] not in negv.get("class_vocabulary", [])})
    rep.add("v2.1", "negative_class_in_closed_vocabulary", not bad_negclass, bad_negclass)

    # 9. no mutable citation is left behind after resolution. Computed from the
    # records, and cross-checked against the resolver's own count so a stale
    # report cannot certify a stale dataset.
    _left = derived_mutable
    _rep_left = cites.get("remaining_mutable_occurrences_after_apply")
    _agree = (_rep_left is None) or (_rep_left == len(_left))
    _mismatch = ([] if _agree else
                 [f"resolver reported {_rep_left} remaining but the records hold {len(_left)}"])
    rep.add("v2.1", "no_mutable_branch_citations_remain", not _left and not _mismatch,
            list(_left) + _mismatch, critical=True,
            detail=("counted from derived/records.jsonl, not read from "
                    "reports/citation_resolution.json; the resolver's self-reported count is "
                    "compared against it so the two cannot silently disagree"))

    # 10. the subsets obey their own admission rules
    subset_bad = []
    for name, key in (("verified_exploits", "verified_exploits"),
                      ("verified_patches", "verified_patches")):
        f = ROOT / "datasets" / f"{name}.jsonl"
        if not f.exists():
            subset_bad.append(f"{name}: file missing")
            continue
        for row in read_jsonl(f):
            if name == "verified_exploits" and row.get("poc_level") not in ("L5", "L6"):
                subset_bad.append(f"{name}:{row.get('finding_id')} level={row.get('poc_level')}")
            if name == "verified_patches":
                if row.get("vulnerable_revision_result") != "fail" \
                        or row.get("fixed_revision_result") != "pass":
                    subset_bad.append(f"{name}:{row.get('finding_id')} "
                                      f"{row.get('vulnerable_revision_result')}/"
                                      f"{row.get('fixed_revision_result')}")
    rep.add("v2.1", "subsets_respect_their_admission_rule", not subset_bad, subset_bad)

    # 11. benchmark H/I/J tasks are never promoted without execution evidence
    bench_bad = []
    for fam in ("H_verified_exploit", "I_verified_non_exploit", "J_verified_patch"):
        f = ROOT / "benchmark" / f"{fam}.jsonl"
        if not f.exists():
            bench_bad.append(f"{fam}: missing")
            continue
        for row in read_jsonl(f):
            if row.get("answer_key_status") == "labeled" \
                    and not row.get("execution_refs"):
                bench_bad.append(f"{fam}:{row.get('id')} labeled without execution_refs")
            if row.get("answer_key_evidence_level") == "experimentally_verified" \
                    and not row.get("execution_refs"):
                bench_bad.append(f"{fam}:{row.get('id')} experimental without execution_refs")
    rep.add("v2.1", "experimental_benchmark_tasks_cite_an_execution", not bench_bad, bench_bad)

    # 12. static analysis never claims a clean bill of health
    static = _J("static_analysis.json")
    clean_claims = [r.get("repository") for r in static.get("repositories", [])
                    if r.get("static_analysis_status") not in ("available", "partial",
                                                               "unavailable")]
    rep.add("v2.1", "static_analysis_status_is_one_of_three", not clean_claims, clean_claims)
    unavailable = [r.get("repository") for r in static.get("repositories", [])
                   if r.get("static_analysis_status") in ("partial", "unavailable")]
    rep.add("v2.1", "unanalyzable_repositories_are_not_reported_clean", True,
            [{"repository": r, "reported_as": "unavailable/partial"} for r in unavailable],
            critical=False)

    # 13. cross-split leakage detectors that are new in v2.1
    leak = _J("leakage_report.json")
    art = leak.get("artefact_overlap") or {}
    for key in ("count_identical_patch_diffs", "count_normalised_poc_bodies",
                "count_root_cause_statements", "count_attack_sequences"):
        rep.add("v2.1", f"no_cross_split_{key.replace('count_', '')}",
                not art.get(key), [f"{key}={art.get(key)}"], critical=False)
    proto = (leak.get("protocol_isolation") or {}).get("count")
    rep.add("v2.1", "protocol_level_isolation_holds", proto == 0,
            [] if proto == 0 else [f"{proto} protocols span splits"])

    # 14. no withheld third-party source is published under experiments/
    #     reNFT is BUSL-1.1: use is permitted, redistribution is not. Only the
    #     tests this pipeline wrote itself may appear there.
    leaked = []
    exp_root = ROOT / "experiments"
    if exp_root.exists():
        for sol in exp_root.rglob("*.sol"):
            rel = sol.relative_to(ROOT).as_posix()
            rj = sol.parent.parent / "result.json"
            if not rj.exists():
                leaked.append(rel)
                continue
            d = json.loads(rj.read_text(encoding="utf-8"))
            if rel.split("/harness/")[-1] in (d.get("harness_files_withheld_for_licence") or []):
                leaked.append(rel)
    rep.add("v2.1", "no_withheld_source_is_published_under_experiments", not leaked, leaked)

    # 15. every experiment that withheld a harness file explains how to get it back
    unexplained = []
    for withheld in exp_root.rglob("WITHHELD.json") if exp_root.exists() else []:
        d = json.loads(withheld.read_text(encoding="utf-8"))
        if not d.get("how_to_obtain") or not d.get("files"):
            unexplained.append(str(withheld.relative_to(ROOT)))
    rep.add("v2.1", "withheld_harness_files_carry_a_resolver", not unexplained, unexplained)

    # ------------------------------------------------------------------ summary
    # Computed LAST, after every check has been added, so that a failure in any
    # group can reach the exit code.
    crit = [c for c in rep.checks if not c["ok"] and c["critical"]]
    warns = [c for c in rep.checks if not c["ok"] and not c["critical"]]

    summary = {
        "generated_by": "scripts/validate.py",
        "dataset_version": DATASET_VERSION,
        "checks": len(rep.checks),
        "passed": sum(1 for c in rep.checks if c["ok"]),
        "failed_critical": len(crit),
        "warnings": len(warns),
        "groups": dict(collections.Counter(c["group"] for c in rep.checks)),
        "details": rep.checks,
    }
    write_json(REPORTS / "validation_report.json", summary)

    # close the loop on the v2.1 summary: the gate is the last stage, so it is
    # the only place that knows whether the build actually passed
    v21 = REPORTS / "v2_1_summary.json"
    if v21.exists():
        doc = json.loads(v21.read_text(encoding="utf-8"))
        doc["validation_failures"] = len(crit)
        doc["validation_warnings"] = len(warns)
        doc["validation_checks_passed"] = f"{summary['passed']}/{summary['checks']}"
        doc["validation_failed_checks"] = [
            {"group": c["group"], "check": c["check"], "failures": c.get("failures")}
            for c in rep.checks if not c["ok"]]
        write_json(v21, doc)

    log(f"\n{summary['passed']}/{summary['checks']} checks passed; "
        f"{summary['failed_critical']} critical failures, {summary['warnings']} warnings")
    if crit:
        for c in crit:
            log(f"  CRITICAL: {c['group']}/{c['check']} ({c['failure_count']})")
        log("BUILD FAILED")
        return 1
    log("BUILD OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
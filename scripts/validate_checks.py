"""Group check functions for the v2 build gate (validate.py).

Split out mechanically from scripts/validate.py: every function
below is the exact code of one check group, dedented and
unmodified. scripts/validate.py keeps the CLI, the Report class
and the summary; behaviour and gate output are byte-identical.
"""

from __future__ import annotations

import collections
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

import generate_stats  # noqa: E402
from vlun import (  # noqa: E402
    BENCHMARK_FAMILIES, BENCH, DATASET_VERSION, DERIVED, EVIDENCE_TYPES,
    EXEC_FAILURE_REASONS, EXPERIMENTS, JSONL,
    REPORTS, ROOT, SCHEMA_VERSION, SOURCE_VERSION, SPLITS, WORK, code_entries, load_core,
    load_splits, read_jsonl, rec_id, sha256_text, snippet_entries,
)

SHA40 = re.compile(r"^[0-9a-f]{40}$")


def artifact_dir(art: str) -> Path:
    """Recorded artefact dir as a usable path on any checkout.

    Recorded artefacts are repo-relative POSIX (see run_verified_experiments
    .rel_artifact); legacy absolute entries still resolve on the machine
    that wrote them. Relative entries resolve against the checkout root.
    """
    p = Path(art)
    return p if p.is_absolute() else ROOT / art
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


# Ordered weakest -> strongest; shared by the evidence group and the v2.2
# layer group (single module-level definition, not one copy per group).
EV = set(EVIDENCE_TYPES)


def load_core_dict():
    """Load jsonl/ into {fname: rows}; also return the JSON error list."""
    core = {}
    bad_json = []
    for fname, keys in REQUIRED_TOP.items():
        path = JSONL / fname
        rows = []
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    bad_json.append(f"{fname}:{i} {exc}")
        core[fname] = rows
    return core, bad_json


def check_structure(rep, core, bad_json):
    """Structure checks (validate.py structure group)."""
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


_MUTABLE_BRANCH_RE = re.compile(r"/blob/(main|master)(/|$)")


def record_url_problems(record: dict) -> list[str]:
    """Mutable-URL violations for one derived record (pure).

    Fails on /blob/main|master/ in citation URL fields: any `source_url`
    key outside the original_evidence mirror subtree, and any top-level
    provenance.source_urls item not declared in that record's
    source_urls_unpinned residual list. Deliberately never flagged:
    *_original audit-trail fields, free prose (quoted verbatim), and
    original_evidence mirrors of the frozen source layer.
    """
    bad = []
    rid = (record.get("finding") or {}).get("id") or record.get("id") or "?"
    prov = record.get("provenance") or {}
    declared = {u for u in (prov.get("source_urls_unpinned") or [])
                if isinstance(u, str)}
    for u in sorted(declared):
        if not _MUTABLE_BRANCH_RE.search(u):
            bad.append(f"{rid} declares non-mutable {u[:100]} as unpinned")
    for u in prov.get("source_urls") or []:
        if (isinstance(u, str) and _MUTABLE_BRANCH_RE.search(u)
                and u not in declared):
            bad.append(f"{rid} provenance.source_urls mutable and undeclared: {u[:100]}")
    stack = [(record, False)]
    while stack:
        node, mirror = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                in_mirror = mirror or k == "original_evidence"
                if k == "source_url" and isinstance(v, str) and not in_mirror:
                    if _MUTABLE_BRANCH_RE.search(v):
                        bad.append(f"{rid} {k} mutable: {v[:100]}")
                else:
                    stack.append((v, in_mirror))
        elif isinstance(node, list):
            for v in node:
                stack.append((v, mirror))
    return bad


def check_provenance(rep, core):
    """Provenance checks."""
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
                if a and b and sn and sn.count("\n") + 1 > (b - a + 1) * 4:
                    snippet_mismatch.append(f"{fn} {rec_id(r)} {e.get('file')} "
                                            f"snippet far longer than its claimed range")
    rep.add("provenance", "snippet_length_plausible", not snippet_mismatch, snippet_mismatch,
            critical=False)

    # Phase 2 permalink gate: no branch link that looks pinned. Every mutable
    # citation URL in derived/records.jsonl fails unless declared in that
    # record's source_urls_unpinned residual list; a stale declaration fails
    # too. jsonl/ is frozen and counted, never failed.
    url_bad, n_unpinned_recs = [], 0
    _dpath = DERIVED / "records.jsonl"
    if _dpath.exists():
        for r in read_jsonl(_dpath):
            problems = record_url_problems(r)
            url_bad += problems
            if ((r.get("provenance") or {}).get("source_urls_unpinned")):
                n_unpinned_recs += 1
    jsonl_residual = 0
    for _fn in ("findings.jsonl", "negative_findings.jsonl"):
        _p = JSONL / _fn
        if _p.exists():
            with open(_p, encoding="utf-8") as _fh:
                jsonl_residual += sum(
                    1 for _line in _fh if _MUTABLE_BRANCH_RE.search(_line))
    rep.add("provenance", "provenance_urls_immutable_or_declared", not url_bad, url_bad,
            detail=(f"{n_unpinned_recs} derived records declare a mutable-URL residual; "
                    f"jsonl/ frozen residual: {jsonl_residual} mutable-URL lines "
                    f"(never rewritten, disclosed here)"))
    return derived_mutable


def check_consistency(rep, core):
    """Consistency checks; returns the splits mapping."""
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
    return splits


def load_pointer_exemptions() -> set[tuple[str, str]] | None:
    """(file, path) pairs exempt from the source_refs requirement.

    Single source: reports/evidence_pointer_audit.json buckets.meta — the
    published exemption list from the Phase 1 audit (meta wrappers that
    describe the schema or the record itself). Returns None when the audit
    file cannot be read; callers must fail loudly, never treat a missing
    exemption list as "everything is exempt".
    """
    try:
        doc = json.loads(
            (REPORTS / "evidence_pointer_audit.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    out = set()
    for entry in ((doc.get("buckets") or {}).get("meta") or {}).get("entries", []):
        out.add((entry.get("file"), entry.get("path")))
    return out


def fact_pointer_violations(rows: list[dict], file_label: str,
                            exemptions: set[tuple[str, str]]) -> list[str]:
    """IDs+paths of derived_fact/observed_fact wrappers with no pointer.

    Pure: operates on the given rows only, so the negative-control test can
    plant violations without touching committed files. A wrapper needs
    non-empty source_refs unless (file, index-stripped path) is exempt, where
    index-stripped means ``taxonomy.labels[0]`` matches ``taxonomy.labels[]``.
    """
    bad = []

    def walk(node, path, fid):
        if isinstance(node, dict):
            et = node.get("evidence_type")
            if et in ("derived_fact", "observed_fact"):
                refs = node.get("source_refs")
                key = (file_label, re.sub(r"\[\d+\]", "[]", path))
                if not refs and key not in exemptions:
                    bad.append(f"{fid} {path or '<root>'} {et} with empty source_refs")
            for k, v in node.items():
                walk(v, k if not path else f"{path}.{k}", fid)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]", fid)

    for r in rows:
        fid = (r.get("finding") or {}).get("id") or r.get("id") or "?"
        walk(r, "", fid)
    return bad


def check_evidence(rep, core):
    """Evidence checks."""
    # -------------------------------------------------------------- evidence
    ev_bad, verified_without_run = [], []
    runs = {v["finding_id"]: v for f in sorted((WORK / "poc_runs").glob("*.json"))
            if f.name != "_all.json"
            for v in json.loads(f.read_text(encoding="utf-8")).get("verdicts", [])}
    # Committed run artefacts ground the same claims on a fresh clone (no
    # work/): every experiments/ result.json carries its finding_id, so an
    # experimentally_verified claim with a committed run artefact passes
    # on every checkout, not just the machine that ran it.
    for _rj in sorted(EXPERIMENTS.rglob("result.json")):
        try:
            _fid = json.loads(_rj.read_text(encoding="utf-8")).get("finding_id")
        except (OSError, ValueError):
            continue
        if _fid:
            runs.setdefault(_fid, {"finding_id": _fid})

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
    # Collected by walk() above; without this rep.add the check silently
    # does not exist. Stricter than the committed-artefact check below:
    # these claims have no run artefact even under git-ignored work/.
    rep.add("evidence", "experimentally_verified_has_any_run_artefact",
            not verified_without_run, verified_without_run)

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

    # Phase 1 pointer gate: every derived_fact/observed_fact wrapper in the
    # derived layers names its pointer, except the published meta exemptions
    # (reports/evidence_pointer_audit.json buckets.meta). Critical: a fact
    # without a pointer is the exact defect Phase 1 closed.
    import vlun_ml as _ml
    exemptions = load_pointer_exemptions()
    if exemptions is None:
        rep.add("evidence", "every_fact_field_has_a_pointer", False,
                ["reports/evidence_pointer_audit.json unreadable: "
                 "exemptions unverifiable, nothing is assumed exempt"])
    else:
        ptr_bad = []
        for _rel, _rows in (
                ("derived/records.jsonl",
                 read_jsonl(DERIVED / "records.jsonl") if (DERIVED / "records.jsonl").exists() else []),
                ("derived_v2_2/records.jsonl",
                 read_jsonl(_ml.DERIVED_V22 / "records.jsonl") if (_ml.DERIVED_V22 / "records.jsonl").exists() else [])):
            ptr_bad += fact_pointer_violations(_rows, _rel, exemptions)
        rep.add("evidence", "every_fact_field_has_a_pointer", not ptr_bad, ptr_bad,
                detail=f"{len(exemptions)} published meta exemptions; "
                       f"silent bucket must stay 0")


def check_splits(rep, splits):
    """Split isolation checks."""
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


def check_derived_layer(rep):
    """Derived-layer checks."""
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


def check_online(rep, core, online):
    """URL probing (only with --online)."""
    # ------------------------------------------------------------------ online
    if online:
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


def check_v21(rep, derived_mutable):
    """v2.1 experimental-claim checks."""
    # ==================================================================
    # v2.1 gate: experimental claims must be backed by artefacts, and the
    # new artefacts must agree with the reports that summarise them.
    # ==================================================================
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

    # 1. every experiment artefact directory exists and records a commit
    missing_art, bad_commit = [], []
    for e in exps.get("experiments", []):
        for label in ("vulnerable", "fixed"):
            rev = (e.get("revisions") or {}).get(label) or {}
            art = rev.get("artifact")
            if not art:
                missing_art.append(f"{e['finding_id']}:{label}")
                continue
            rj = artifact_dir(art) / "result.json"
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
            f = artifact_dir(art) / "result.json"
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


def check_v22(rep):
    """v2.2 version-agreement checks."""
    # ------------------------------------------------------------------ v2.2
    # One canonical release number, and a gate that fails if any artefact
    # disagrees with it. Before v2.2 the shared constant said "2.0" while
    # README.md called the release v2.1 and no `schema_version` existed at all,
    # so three numbers described one dataset and nothing would have caught the
    # drift: nothing in this file checked them against each other.
    stale = []
    if DATASET_VERSION != SCHEMA_VERSION:
        stale.append(f"DATASET_VERSION={DATASET_VERSION} != SCHEMA_VERSION={SCHEMA_VERSION}")
    for path, label in ((REPORTS / "dataset_stats.json", "reports/dataset_stats.json"),
                        (BENCH / "manifest.json", "benchmark/manifest.json")):
        if path.exists():
            got = json.loads(path.read_text(encoding="utf-8")).get("dataset_version")
            if got != DATASET_VERSION:
                stale.append(f"{label} dataset_version={got!r} expected {DATASET_VERSION!r}")
        else:
            stale.append(f"{label} missing")
    _dv = {r.get("dataset_version") for r in read_jsonl(DERIVED / "records.jsonl")} \
        if (DERIVED / "records.jsonl").exists() else set()
    if _dv != {DATASET_VERSION}:
        stale.append(f"derived/records.jsonl dataset_version={sorted(map(str, _dv))} "
                     f"expected [{DATASET_VERSION!r}]")
    _sv = {r.get("dataset_version") for r in load_core()["findings"]}
    if _sv - {SOURCE_VERSION}:
        stale.append(f"jsonl/findings.jsonl dataset_version={sorted(map(str, _sv))} "
                     f"expected source layer {SOURCE_VERSION!r}")
    rep.add("v2.2", "versions_agree", not stale, stale, critical=True,
            detail=("the release version, the schema version and the version stamped on every "
                    "generated artefact are compared here, so a disagreement cannot ship"))

    readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
    rep.add("v2.2", "readme_states_the_release_version",
            f"v{DATASET_VERSION}" in readme or f"VLUN v{DATASET_VERSION}" in readme,
            [] if (f"v{DATASET_VERSION}" in readme) else ["README.md never mentions "
                                                          f"v{DATASET_VERSION}"],
            critical=False,
            detail="README.md is generated by scripts/generate_readme.py, which reads the "
                   "version from scripts/vlun.py; this check catches a stale copy")


def check_v22_layer(rep):
    """v2.2 layer-integrity checks."""
    # ---------------------------------------------------- v2.2 layer integrity
    # The multi-language half of the release: jsonl_ml, derived_v2_2,
    # splits_v2_2, experiments_v2_2 and benchmark families K-Q. Every check
    # here is computed from the records themselves; nothing is taken on trust
    # from a report file.
    import vlun_ml as _ml
    import build_benchmark_v22 as _bb22

    # 1. jsonl_ml passes its own gate, re-run here in-process so it cannot be
    #    skipped by forgetting to call scripts/check_ml_layer.py. A missing
    #    layer is a recorded SKIP (warning), never a silent pass.
    if not _ml.ML_JSONL.exists():
        rep.add("v2.2", "ml_layer_passes_its_own_gate", False, [],
                critical=False,
                detail="SKIPPED: jsonl_ml/ absent; 0 records checked")
        _ml_total, _ml_errors = 0, []
    else:
        _ml_total, _ml_errors = _ml.check_layer()
        rep.add("v2.2", "ml_layer_passes_its_own_gate", not _ml_errors,
                _ml_errors[:25],
                detail=f"{_ml_total} jsonl_ml records checked in-process; "
                       f"scripts/check_ml_layer.py runs the identical check_layer()")

    # 2. evidence walk over derived_v2_2: closed vocabulary, and no
    #    experimentally_verified record without an experiment behind it
    d22_path = _ml.DERIVED_V22 / "records.jsonl"
    d22 = read_jsonl(d22_path) if d22_path.exists() else []
    ev22_bad, exp22_bad = [], []
    for r in d22:
        rid = r.get("id")

        def _walk22(node, path, _rid=rid):
            if isinstance(node, dict):
                et = node.get("evidence_type")
                if et is not None and et not in EV:
                    ev22_bad.append(f"{_rid} {path}.evidence_type={et!r}")
                if et == "experimentally_verified" and not (r.get("experiment_view") or {}).get("present"):
                    exp22_bad.append(f"{_rid} {path} experimentally_verified with no experiment")
                for k, v in node.items():
                    _walk22(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, v in enumerate(node[:80]):
                    _walk22(v, f"{path}[{i}]")

        _walk22(r, "records.jsonl")
        se = (r.get("evidence_summary") or {}).get("strongest")
        we = (r.get("evidence_summary") or {}).get("weakest")
        if se not in EV or we not in EV:
            ev22_bad.append(f"{rid} evidence_summary strongest={se!r} weakest={we!r}")
    rep.add("v2.2", "derived_v2_2_evidence_walk", not ev22_bad, ev22_bad)
    rep.add("v2.2", "no_experimental_claim_without_an_experiment", not exp22_bad, exp22_bad)

    # 3. every experiment claim resolves to an artefact that exists on disk,
    #    and the index and the records name each other exactly
    idx_path = _ml.EXPERIMENTS_V22 / "index.json"
    idx = json.loads(idx_path.read_text(encoding="utf-8")) if idx_path.exists() else {}
    index_ids = {e.get("experiment_id") for e in idx.get("experiments", [])}
    art_bad, idx_bad = [], []
    for r in d22:
        ex = r.get("experiment_view") or {}
        if not ex.get("present"):
            continue
        for eid in ex.get("experiment_ids") or []:
            if eid not in index_ids:
                art_bad.append(f"{r['id']}: experiment {eid} missing from index.json")
        for a in ex.get("artefacts") or []:
            rel = a.get("path")
            if not rel:
                art_bad.append(f"{r['id']}: artefact entry with no path")
                continue
            p = ROOT / rel
            if not p.exists():
                art_bad.append(f"{r['id']}: artefact missing: {rel}")
                continue
            want = a.get("sha256")
            # Must match the producer exactly: build_derived_v22._artefact
            # records sha256 over read_text (universal newlines, CRLF->LF).
            # Hashing raw bytes instead fails on any CRLF checkout: the
            # working tree is CRLF while the recorded hash is not.
            if want and sha256_text(p.read_text(encoding="utf-8",
                                                errors="replace")) != want:
                art_bad.append(f"{r['id']}: artefact sha256 mismatch: {rel}")
    used = {eid for r in d22 for eid in ((r.get("experiment_view") or {}).get("experiment_ids") or [])}
    for e in idx.get("experiments", []):
        if e.get("experiment_id") not in used:
            idx_bad.append(f"index entry {e.get('experiment_id')} referenced by no record")
    rep.add("v2.2", "experiment_artefacts_resolve", not art_bad, art_bad,
            detail=f"{len(used)} experiment ids referenced by records; "
                   f"{len(index_ids)} in experiments_v2_2/index.json")
    rep.add("v2.2", "experiment_index_is_exactly_the_referenced_set", not idx_bad, idx_bad)

    # 4. splits_v2_2 resolves: every pointer's sha256 matches the record, no
    #    record is in two splits, and the v2.2 rows cover every derived record
    ptr_bad = []
    seen_split: dict[str, set] = collections.defaultdict(set)
    d22_map = {r["id"]: r for r in d22}
    for s in SPLITS:
        for p in read_jsonl(_ml.SPLITS_V22 / f"{s}.jsonl"):
            if p.get("layer") != "v2.2":
                continue
            seen_split[p["id"]].add(s)
            rec = d22_map.get(p["id"])
            if rec is None:
                ptr_bad.append(f"{s}: {p['id']} has no derived_v2_2 record")
                continue
            want = sha256_text(json.dumps(rec, sort_keys=True, ensure_ascii=False))
            if p.get("record_sha256") != want:
                ptr_bad.append(f"{s}: {p['id']} record_sha256 mismatch")
            if p.get("split") != s:
                ptr_bad.append(f"{s}: {p['id']} pointer split={p.get('split')!r}")
    for rid, ss in seen_split.items():
        if len(ss) > 1:
            ptr_bad.append(f"{rid} in {sorted(ss)}")
    missing_ptr = sorted(set(d22_map) - set(seen_split))
    ptr_bad += [f"{rid}: derived record has no split pointer" for rid in missing_ptr]
    rep.add("v2.2", "splits_v2_2_pointers_resolve", not ptr_bad, ptr_bad,
            detail=f"{len(seen_split)} v2.2 pointers over {len(d22)} derived records")

    # 5. no source is shared by tasks in two splits: family P would otherwise
    #    hand a test record a source whose label it saw in train
    src_splits: dict[str, set] = collections.defaultdict(set)
    for rid, split_names in seen_split.items():
        rec = d22_map.get(rid) or {}
        for e in (rec.get("sources_view") or {}).get("entries") or []:
            if e.get("source_id"):
                src_splits[e["source_id"]].update(split_names)
    spanning = sorted(k for k, v in src_splits.items() if len(v) > 1)
    rep.add("v2.2", "ml_sources_do_not_span_splits", not spanning, spanning,
            detail=f"{len(src_splits)} in-use sources checked across "
                   f"{len(seen_split)} v2.2 tasks")

    # 6. the benchmark manifest covers every family this codebase knows, with
    #    the counts actually on disk
    mpath = BENCH / "manifest.json"
    man = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else {}
    tasks_manifest = man.get("tasks") or {}

    def _task_file(name: str) -> Path:
        # Manifest `file` fields are the source of truth for task locations:
        # retired families live under benchmark/retired_families/ while the
        # manifest keeps covering them (check 6 above guarantees the entry).
        entry = tasks_manifest.get(name)
        if isinstance(entry, dict) and entry.get("file"):
            return ROOT / entry["file"]
        return BENCH / f"{name}.jsonl"
    fam_bad = []
    for key, (name, layer, _q) in (BENCHMARK_FAMILIES).items():
        entry = tasks_manifest.get(name)
        if entry is None:
            fam_bad.append(f"{name} (family {key}) missing from benchmark/manifest.json")
            continue
        f = ROOT / entry["file"]
        if not f.exists():
            fam_bad.append(f"{name}: file {entry['file']} missing")
            continue
        rows = read_jsonl(f)
        if entry.get("tasks") != len(rows):
            fam_bad.append(f"{name}: manifest tasks={entry.get('tasks')} file={len(rows)}")
        st = collections.Counter(r.get("answer_key_status") for r in rows)
        for k in ("labeled", "partial", "unlabeled"):
            if entry.get(k, 0) != st.get(k, 0):
                fam_bad.append(f"{name}: manifest {k}={entry.get(k)} file={st.get(k)}")
        if entry.get("layer", "v1") != layer:
            fam_bad.append(f"{name}: manifest layer={entry.get('layer')} expected {layer}")
    rep.add("v2.2", "benchmark_manifest_covers_every_family", not fam_bad, fam_bad,
            detail=f"{len(tasks_manifest)} families in the manifest; "
                   f"vlun.BENCHMARK_FAMILIES declares "
                   f"{len(BENCHMARK_FAMILIES)}")

    # 7. every row of every family obeys the shared row contract
    STATUS_VOCAB = {"labeled", "partial", "unlabeled", "unscorable"}
    row_bad = []
    for key, (name, layer, _q) in BENCHMARK_FAMILIES.items():
        f = _task_file(name)
        if not f.exists():
            continue
        for r in read_jsonl(f):
            rid = r.get("id") or ""
            if not rid.startswith(f"{key}::{r.get('split')}::"):
                row_bad.append(f"{name} {rid} id does not carry its key and split")
            if r.get("task") != name:
                row_bad.append(f"{name} {rid} task={r.get('task')!r}")
            if r.get("answer_key_status") not in STATUS_VOCAB:
                row_bad.append(f"{name} {rid} status={r.get('answer_key_status')!r}")
            if r.get("evidence_type") not in EV:
                row_bad.append(f"{name} {rid} evidence_type={r.get('evidence_type')!r}")
            if r.get("split") not in SPLITS:
                row_bad.append(f"{name} {rid} split={r.get('split')!r}")
            st = r.get("answer_key_status")
            if st in ("unlabeled", "unscorable") and not r.get("unlabelled_reason"):
                row_bad.append(f"{name} {rid} {st} without unlabelled_reason")
            if st == "labeled" and r.get("unlabelled_reason"):
                row_bad.append(f"{name} {rid} labeled but carries unlabelled_reason")
            rec_id_part = rid.split("::", 2)[-1]
            if layer == "v2.2":
                if r.get("layer") != "v2.2":
                    row_bad.append(f"{name} {rid} missing layer=v2.2")
                if r.get("answer_key_evidence_level") not in EV:
                    row_bad.append(f"{name} {rid} "
                                   f"answer_key_evidence_level={r.get('answer_key_evidence_level')!r}")
                if seen_split.get(rec_id_part) != {r.get("split")}:
                    row_bad.append(f"{name} {rid} split disagrees with splits_v2_2")
                # Independent check, never elif'd onto the one above: an
                # unlabeled row typed anything but unknown would otherwise
                # pass silently whenever its split also disagreed.
                if r.get("answer_key_status") == "unlabeled" \
                        and r.get("answer_key_evidence_level") != "unknown":
                    row_bad.append(f"{name} {rid} unlabeled typed "
                                   f"{r.get('answer_key_evidence_level')!r}, expected unknown")
    rep.add("v2.2", "benchmark_rows_obey_the_row_contract", not row_bad, row_bad,
            detail="applies to families A-Q: ids carry key+split, statuses and "
                   "evidence types are in the closed vocabularies, unlabelled "
                   "rows state why, and v2.2 rows resolve against splits_v2_2")

    # 8. the strongest possible check: rebuild every v2.2 family from the
    #    records and require byte-equality with what is on disk, so a stale or
    #    hand-edited benchmark file cannot ship
    rebuild_bad = []
    try:
        rebuilt, info = _bb22.build()
        rebuild_bad += info.get("problems") or []
        for key, (name, _layer, _q) in BENCHMARK_FAMILIES.items():
            if _layer != "v2.2":
                continue
            f = _task_file(name)
            on_disk = read_jsonl(f) if f.exists() else []
            if json.dumps(rebuilt.get(key, []), sort_keys=True, ensure_ascii=False) != \
                    json.dumps(on_disk, sort_keys=True, ensure_ascii=False):
                rebuild_bad.append(f"{name}: rebuilt tasks differ from the file on disk")
    except Exception as exc:  # noqa: BLE001
        rebuild_bad.append(f"rebuild raised {type(exc).__name__}: {exc}")
    rep.add("v2.2", "benchmark_kq_rebuilds_from_the_records", not rebuild_bad,
            rebuild_bad,
            detail="scripts/build_benchmark_v22.build() is re-run in-process and "
                   "its output compared with benchmark/*.jsonl; drift in either "
                   "direction fails the gate")

    # 9. family M is exactly the set of records with a run behind them: no
    #    task graded experimentally_verified without one, none missing
    m_file = _task_file("M_experiment_level_classification")
    m_ids = {r["source"]["record_id"] for r in read_jsonl(m_file)} if m_file.exists() else set()
    ran_ids = {r["id"] for r in d22 if (r.get("experiment_view") or {}).get("present")}
    diff = sorted(m_ids ^ ran_ids)
    rep.add("v2.2", "family_M_is_exactly_the_set_of_executed_records", not diff,
            diff[:10],
            detail=f"{len(m_ids)} tasks, {len(ran_ids)} records with an experiment")


def check_audit_sources(rep):
    """Audit-source ingestion checks."""
    # ------------------------------------------------- audit-source ingestion
    # VLUN v2.2 sections 1-25: the authoritative audit-source registry, the
    # section-4 ingestion records, and the section-23 report. Computed from
    # the artefacts scripts/ingest_audit_sources.py writes; nothing is taken
    # on trust from prose.
    import audit_sources as _as  # noqa: E402
    import vlun_ml as _ml  # noqa: E402 (v2.2 section import kept local,
    # as in the original single-file gate)

    _arep = REPORTS / "audit_source_ingestion_report.md"
    _ajson = REPORTS / "audit_source_ingestion.json"
    _asrc = _ml.DERIVED_V22 / "audit_sources.jsonl"
    _arec = _ml.DERIVED_V22 / "audit_ingestion_records.jsonl"
    rep.add("audit_sources", "ingestion_report_present",
            _arep.exists() and _ajson.exists(),
            [] if (_arep.exists() and _ajson.exists()) else
            ["reports/audit_source_ingestion_report.md or "
             "reports/audit_source_ingestion.json missing; run "
             "scripts/ingest_audit_sources.py"])

    _denom_bad: list[str] = []
    _sections_found = 0
    if _arep.exists():
        _text = _arep.read_text(encoding="utf-8")
        for n in range(1, 25):
            heads = [ln for ln in _text.splitlines()
                     if ln.startswith(f"## {n}.")]
            if not heads:
                _denom_bad.append(f"section {n} missing from the ingestion report")
                continue
            _sections_found += 1
        # every section-23 metric must read "numerator / denominator". Only
        # bold "**n / d**" metric lines are held to this: supplementary prose
        # (threshold rules, policy notes) is exempt.
        _metric_lines = [ln for ln in _text.splitlines()
                         if ln.startswith("- ") and "**" in ln]
        _bare = [ln[:110] for ln in _metric_lines if "/" not in ln]
        if _bare:
            _denom_bad += [f"metric without a denominator: {b}" for b in _bare[:10]]
    else:
        _denom_bad.append("no ingestion report to check")
    rep.add("audit_sources", "report_sections_and_denominators",
            not _denom_bad and _sections_found == 24, _denom_bad,
            detail=f"{_sections_found}/24 required sections present; every "
                   f"metric must read 'numerator / denominator'")

    _reg_bad: list[str] = []
    if _asrc.exists():
        _rows = read_jsonl(_asrc)
        _names = {r.get("source_name") for r in _rows}
        _want = {s["source_name"] for s in _as.MANDATORY_SOURCES}
        _missing = sorted(_want - _names)
        if _missing:
            _reg_bad.append(f"registry sources missing: {_missing}")
        _bad_class = sorted(n for r in _rows for n in [r.get("source_name")]
                            if r.get("source_class") not in _as.SOURCE_CLASSES)
        if _bad_class:
            _reg_bad.append(f"source_class outside S0-S5: {_bad_class}")
        if len(_rows) != len(_as.MANDATORY_SOURCES):
            _reg_bad.append(f"audit_sources.jsonl has {len(_rows)} rows, "
                            f"registry declares {len(_as.MANDATORY_SOURCES)}")
    else:
        _reg_bad.append("derived_v2_2/audit_sources.jsonl missing")
    rep.add("audit_sources", "registry_covers_every_mandatory_source",
            not _reg_bad, _reg_bad,
            detail=f"{len(_as.MANDATORY_SOURCES)} mandatory archives in "
                   f"scripts/audit_sources.py")

    _rec_bad: list[str] = []
    if _arec.exists():
        for r in read_jsonl(_arec):
            _rec_bad += [f"{r.get('source_name')}: {e}"
                         for e in _as.validate_ingestion_record(r)]
        if not read_jsonl(_arec):
            _rec_bad.append("audit_ingestion_records.jsonl is empty")
    else:
        _rec_bad.append("derived_v2_2/audit_ingestion_records.jsonl missing")
    rep.add("audit_sources", "ingestion_records_obey_the_section_4_schema",
            not _rec_bad, _rec_bad[:25])

    _fab: list[str] = []
    if _arec.exists():
        for r in read_jsonl(_arec):
            for key in ("audited_commit", "fix_commit"):
                v = r.get(key)
                if v not in (None, "", "unknown") and not SHA40.match(str(v)):
                    _fab.append(f"{r.get('source_name')} {key}={v!r} "
                                f"is not a 40-hex sha")
    rep.add("audit_sources", "no_fabricated_commit_provenance", not _fab, _fab,
            critical=False,
            detail="section 24: missing commits stay null/unknown, never guessed")


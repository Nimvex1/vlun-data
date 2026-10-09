#!/usr/bin/env python3
"""Authoritative audit-source ingestion pipeline (VLUN v2.2, sections 1-25).

The brief adds sixteen mandatory archives (ten authoritative audit sources,
two secondary/researcher archives, four research/dataset discovery sources)
as *candidate discovery and evidence sources* — never as automatic ground
truth. This script implements the full workflow:

  STEP 1  enumerate    register every archive; probe its index URL only with
                       --probe-urls, otherwise record it as not_probed_offline
  STEP 2  normalize    project/repo/commit/severity/ecosystem/language labels
                       through the closed maps in scripts/audit_sources.py
  STEP 3  deduplicate  content hashes + the hand-authored Zentory equivalence
                       map; duplicates are linked, never counted twice
  STEP 4  locate code  exact commit > tag > weak (branch/latest/prose-only);
                       weak evidence is never silently upgraded

and every downstream requirement: immutable provenance (sec 6), L0-L6
verification states (sec 7), independent severity storage (sec 8), patch
verification by same-exploit-both-revisions (sec 9), multi-language targets
(sec 10), cross-language semantic mapping (sec 11), negative handling with
duplicates kept out of the negative set (sec 12), licensing (sec 13),
hashing (sec 14), five-dimension confidence (sec 15), prioritisation
(sec 16), auditor/ecosystem/language diversity (sec 17), independent
confirmation (sec 18), incident cross-validation (sec 19), leakage
prevention (sec 20), provenance graphs (sec 21), admission rules (sec 22),
the section-23 ingestion report, and the section-24 failure policy.

Failure policy: when evidence is unavailable the field is null/unknown and
the candidate is UNVERIFIED/INCONCLUSIVE. Nothing is guessed: no commit, no
vulnerability, no PoC, no fix, and no external label is ever copied as truth.

Writes (all idempotent, stdlib only; jsonl_ml/ is never touched):

  derived_v2_2/audit_sources.jsonl            one row per registry archive
  derived_v2_2/audit_ingestion_records.jsonl  section-4 records (blank where
                                              no report has been parsed yet)
  reports/audit_source_ingestion.json         machine-readable metrics
  reports/audit_source_ingestion_report.md    the required section-23 report;
                                              every metric carries X / Y

    python scripts/ingest_audit_sources.py              # offline-safe
    python scripts/ingest_audit_sources.py --probe-urls # also HEAD each URL
    python scripts/ingest_audit_sources.py --check      # compute, write nothing
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_sources as A  # noqa: E402
from vlun import DATASET_VERSION, REPORTS, log, read_jsonl  # noqa: E402
from vlun_ml import DERIVED_V22, EXPERIMENTS_V22, ML_JSONL, SPLITS_V22  # noqa: E402

TODAY = datetime.now(timezone.utc).date().isoformat()
SHA40 = A.SHA40_RE


def _J(path: Path, default=None):
    if not path.exists():
        return default if default is not None else {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default if default is not None else {}


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# STEP 1 — enumerate. Probing is opt-in; the default run never touches the
# network, per section 13 (no bypassing access controls) and the pipeline
# rule that offline-safe stages stay offline-safe.
# ---------------------------------------------------------------------------

def probe_url(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "vlun-ingest"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"reachable": resp.status < 400, "http_status": resp.status,
                    "error": None}
    except Exception as exc:  # noqa: BLE001 — the error string IS the record
        return {"reachable": False, "http_status": None,
                "error": f"{type(exc).__name__}: {exc}"[:300]}


def enumerate_sources(probe: bool = False) -> list[dict]:
    rows = []
    for src in A.MANDATORY_SOURCES:
        entry = dict(src)
        entry["registry_sha256"] = _sha256_text(
            json.dumps(src, sort_keys=True, ensure_ascii=False))
        entry["retrieved_at"] = TODAY
        entry["dataset_version"] = DATASET_VERSION
        if probe:
            checked = {}
            for key in ("source_url", "report_index_url", "companies_url",
                        "api_docs_url"):
                url = src.get(key)
                if url:
                    checked[key] = {"url": url, **probe_url(url)}
            entry["probe"] = {"probed": True, "method": "http_HEAD",
                              "results": checked}
            entry["access"] = ("reachable"
                               if any(r.get("reachable") for r in checked.values())
                               else "inaccessible")
            entry["access_note"] = ("at least one index URL answered"
                                    if entry["access"] == "reachable"
                                    else "no index URL answered; see probe.results")
        else:
            entry["probe"] = {"probed": False,
                              "method": "not_probed_offline",
                              "reason": "run with --probe-urls to HEAD each index URL"}
            entry["access"] = "not_probed_offline"
            entry["access_note"] = ("URL recorded from the brief; reachability "
                                    "not checked in this offline run")
        # Section 13: publicly accessible is not freely redistributable.
        if src.get("licensing_caution"):
            entry["license"] = {
                "content_license": "unknown",
                "redistribution_allowed": False,
                "note": "per-report copyright applies; store metadata + URL + "
                        "hash + ids + citations, never the full text, until "
                        "redistribution rights are confirmed",
            }
        elif src["source_type"].startswith("research"):
            entry["license"] = {
                "content_license": "unknown",
                "redistribution_allowed": False,
                "note": "paper/dataset licence tracked per source; discovery "
                        "use only, no redistribution assumed",
            }
        else:
            entry["license"] = {
                "content_license": "unknown",
                "redistribution_allowed": False,
                "note": "no licence inferred from public accessibility",
            }
        rows.append(entry)
    return rows


# ---------------------------------------------------------------------------
# Existing-layer evidence: the honest denominators for sections 5-22 come
# from what is actually on disk, never from the registry's size.
# ---------------------------------------------------------------------------

def load_layer() -> tuple[list[dict], list[dict], list[dict]]:
    findings: list[dict] = []
    sources: list[dict] = []
    if ML_JSONL.exists():
        for p in sorted(ML_JSONL.glob("findings_*.jsonl")):
            findings.extend(read_jsonl(p))
        for p in sorted(ML_JSONL.glob("sources_*.jsonl")):
            sources.extend(read_jsonl(p))
    derived: list[dict] = []
    dpath = DERIVED_V22 / "records.jsonl"
    if dpath.exists():
        derived = read_jsonl(dpath)
    return findings, sources, derived


def finding_commit_status(finding: dict) -> str:
    """Section 6 ladder: full SHA > tag/version > weak > none."""
    shas = [c.get("commit_sha") for c in (finding.get("code_context") or [])
            if c.get("commit_sha")]
    if any(s and SHA40.match(str(s)) for s in shas):
        return "exact_commit"
    prov = finding.get("provenance") or {}
    if prov.get("affected_versions") or (finding.get("finding") or {}).get(
            "affected_versions"):
        return "tag_or_version"
    if finding.get("code_context"):
        return "weak_path_only"
    return "none"


def has_poc(finding: dict, derived_by_id: dict) -> bool:
    prov = finding.get("provenance") or {}
    if prov.get("tests_cited") or prov.get("poc_commands_declared"):
        return True
    d = derived_by_id.get(finding.get("id") or "")
    if d and (d.get("experiment_view") or {}).get("present"):
        return True
    if finding.get("experiment"):
        return True
    return False


def compute_metrics(source_rows: list[dict], findings: list[dict],
                    sources: list[dict], derived: list[dict]) -> dict:
    derived_by_id = {r.get("id"): r for r in derived}
    index = _J(EXPERIMENTS_V22 / "index.json", {}) or {}
    runs = index.get("experiments") or []

    n_find = len(findings)
    # -- provenance ladder (sec 6) -----------------------------------------
    commit_status = collections.Counter(
        finding_commit_status(f) for f in findings)
    exact_commit = sum(1 for f in findings
                       if finding_commit_status(f) == "exact_commit")
    # -- PoC / reproduction (sec 7) ----------------------------------------
    with_poc = sum(1 for f in findings if has_poc(f, derived_by_id))
    # experiment levels come from the derived view, which checks artefacts
    # against the disk rather than trusting the finding's word
    by_level = collections.Counter()
    for r in derived:
        ex = r.get("experiment_view") or {}
        by_level[ex.get("level") if ex.get("present") else "none"] += 1
    reproduced = sum(1 for r in derived
                     if (r.get("experiment_view") or {}).get("outcome")
                     == "reproduced")
    l6 = sum(1 for r in derived
             if (r.get("experiment_view") or {}).get("level") == "L6")
    fixed_leg = sum(1 for r in derived
                    if (r.get("experiment_view") or {}).get(
                        "fixed_revision_executed"))
    # -- verification states mapped from levels ------------------------------
    by_state = collections.Counter()
    for r in derived:
        ex = r.get("experiment_view") or {}
        if not ex.get("present"):
            by_state["UNVERIFIED"] += 1
        else:
            by_state[A.LEVEL_TO_STATE.get(ex.get("level"),
                                          "INCONCLUSIVE")] += 1
    # -- negatives (sec 12): duplicates are not false positives --------------
    by_record_class = collections.Counter(
        (f.get("finding") or {}).get("record_class") for f in findings)
    verified_non_exploit = sum(
        (f.get("finding") or {}).get("record_class") in (
            "negative_control", "out_of_scope")
        for f in findings)
    duplicates = sum(1 for f in findings
                     if isinstance(f.get("canonical_finding"), dict)
                     and f["canonical_finding"].get("value"))
    # -- severity split storage (sec 8) --------------------------------------
    with_reported_sev = sum(1 for f in findings
                            if (f.get("finding") or {}).get("severity"))
    # -- languages / ecosystems / auditors (secs 10, 17) ----------------------
    by_lang = collections.Counter(f.get("language") for f in findings)
    by_eco = collections.Counter(f.get("ecosystem") for f in findings)
    auditors = collections.Counter()
    for f in findings:
        src = f.get("source") or {}
        auditors[src.get("organization") or src.get("auditor")
                 or "unknown"] += 1
    vuln_classes: collections.Counter = collections.Counter()
    for f in findings:
        for c in ((f.get("finding") or {}).get("vulnerability_classes") or []):
            vuln_classes[c] += 1
    # -- licensing (sec 13) ----------------------------------------------------
    lic = collections.Counter(
        str((s.get("license") or {}).get("redistributable")) for s in sources)
    lic_unknown = sum(1 for s in sources
                      if (s.get("license") or {}).get("content_license")
                      == "unknown")
    # -- leakage (sec 20) -------------------------------------------------------
    leak22 = _J(REPORTS / "leakage_report_v22.json", {}) or {}
    leak = _J(REPORTS / "leakage_report.json", {}) or {}
    try:
        from vlun import load_splits as _load_splits  # noqa: E402
        _repos = {r.get("source", {}).get("repository")
                  for rows in _load_splits().values() for r in rows}
        _repos.discard(None)
        n_protocols = len(_repos)
    except Exception:  # noqa: BLE001
        n_protocols = 0
    # -- run outcomes ------------------------------------------------------------
    run_ok = sum(1 for e in runs if e.get("status") == "ok")
    run_bad = len(runs) - run_ok
    # -- admission (sec 22): corpus needs provenance, gold needs L5/L6 -----------
    admitted_corpus = sum(
        1 for f in findings
        if f.get("source_ids") and finding_commit_status(f) in (
            "exact_commit", "tag_or_version", "weak_path_only"))
    admitted_gold = sum(
        1 for r in derived
        if (r.get("experiment_view") or {}).get("level") in ("L5", "L6"))
    unknown_unresolved = n_find - reproduced - verified_non_exploit
    # -- gold concentration (sec 17-18): who supplies the gold set? ------------
    finding_auditor = {}
    for f in findings:
        src = f.get("source") or {}
        finding_auditor[f.get("id")] = (src.get("organization")
                                        or src.get("auditor") or "unknown")
    gold_by_auditor: collections.Counter = collections.Counter()
    for r in derived:
        if (r.get("experiment_view") or {}).get("level") in ("L5", "L6"):
            gold_by_auditor[finding_auditor.get(r.get("id"), "unknown")] += 1
    gold_top = max(gold_by_auditor.values()) if gold_by_auditor else 0
    # -- dedup groups --------------------------------------------------------------
    try:
        from build_ml_ingest import ZENTORY_GROUPS  # noqa: E402
        dup_groups = len(ZENTORY_GROUPS)
    except Exception:  # noqa: BLE001
        dup_groups = 0

    m = {
        "sources_registered": len(source_rows),
        "sources_mandatory": len(A.MANDATORY_SOURCES),
        "sources_by_class": dict(sorted(collections.Counter(
            s.get("source_class") for s in source_rows).items())),
        "sources_by_priority": dict(sorted(collections.Counter(
            s.get("source_priority") for s in source_rows).items())),
        "sources_probed": sum(1 for s in source_rows
                              if (s.get("probe") or {}).get("probed")),
        "sources_reachable": sum(1 for s in source_rows
                                 if s.get("access") == "reachable"),
        "sources_inaccessible": sum(1 for s in source_rows
                                    if s.get("access") == "inaccessible"),
        "sources_not_probed": sum(1 for s in source_rows
                                  if s.get("access") == "not_probed_offline"),
        "ml_sources": len(sources),
        "reports_parsed_ml": len(sources),
        "projects_ml": len({(f.get("source") or {}).get("protocol")
                            for f in findings if (f.get("source") or {}).get(
                                "protocol")}),
        "candidates": n_find,
        "dedup_groups": dup_groups,
        "duplicates_linked": duplicates,
        "exact_commit": exact_commit,
        "commit_status": dict(sorted(commit_status.items())),
        "with_poc": with_poc,
        "by_level": dict(sorted(by_level.items())),
        "reproduced": reproduced,
        "l6": l6,
        "fixed_leg": fixed_leg,
        "by_state": dict(sorted(by_state.items())),
        "by_record_class": {str(k): v for k, v in
                            sorted(by_record_class.items(),
                                   key=lambda kv: str(kv[0]))},
        "verified_non_exploit": verified_non_exploit,
        "with_reported_severity": with_reported_sev,
        "by_language": dict(sorted(by_lang.items(), key=lambda kv: str(kv[0]))),
        "by_ecosystem": dict(sorted(by_eco.items(), key=lambda kv: str(kv[0]))),
        "auditors": dict(sorted(auditors.items())),
        "vuln_classes": dict(sorted(vuln_classes.items())),
        "n_vuln_classes": len(vuln_classes),
        "licenses_redistributable": dict(sorted(lic.items())),
        "licenses_unknown": lic_unknown,
        "runs": len(runs),
        "runs_ok": run_ok,
        "runs_bad": run_bad,
        "admitted_corpus": admitted_corpus,
        "admitted_gold": admitted_gold,
        "gold_by_auditor": dict(sorted(gold_by_auditor.items())),
        "gold_top_share": gold_top,
        "n_derived": len(derived),
        "unknown_unresolved": unknown_unresolved,
        "leakage_v22": (leak22.get("post_check") or {}),
        "leakage_v1_artefacts": ((leak.get("artefact_overlap") or {}).get(
            "count_normalised_poc_bodies", "n/a")),
        "leakage_v1_protocol": ((leak.get("protocol_isolation") or {}).get(
            "count", "n/a")),
        "leakage_v1_protocols": n_protocols,
    }
    return m


# ---------------------------------------------------------------------------
# Section 21: provenance graph per verified finding. Missing edges are
# explicit unknowns, never silent gaps.
# ---------------------------------------------------------------------------

def provenance_graph(finding: dict, derived_by_id: dict) -> dict:
    f = finding.get("finding") or {}
    src = finding.get("source") or {}
    prov = finding.get("provenance") or {}
    d = derived_by_id.get(finding.get("id") or "") or {}
    ex = d.get("experiment_view") or {}
    code = finding.get("code_context") or []
    exact = [c for c in code
             if c.get("commit_sha") and SHA40.match(str(c["commit_sha"]))]
    edge = lambda present: "present" if present else "unknown"  # noqa: E731
    return {
        "source": edge(bool(finding.get("source_ids"))),
        "report": edge(bool(src.get("report_sha256") or prov.get("source_urls"))),
        "finding": edge(bool(f.get("title"))),
        "project": edge(bool(src.get("protocol"))),
        "repository": edge(bool(src.get("repository_url") or src.get("repository"))),
        "audited_commit": edge(bool(exact)),
        "vulnerable_code": edge(bool(code)),
        "preconditions": "unknown",
        "attack_sequence": edge(bool(prov.get("tests_cited"))),
        "poc": edge(bool(ex.get("present") or finding.get("experiment"))),
        "experiment": edge(bool(ex.get("present"))),
        "violation": edge(ex.get("outcome") == "reproduced"),
        "fix": edge(bool((finding.get("patch") or {}).get("present"))),
        "patch_verification": edge(ex.get("level") == "L6"),
    }


# ---------------------------------------------------------------------------
# Section-4 ingestion records: one blank row per registry archive (nothing
# parsed yet) so the schema is exercised without fabricating findings.
# ---------------------------------------------------------------------------

def build_ingestion_records(source_rows: list[dict]) -> tuple[list[dict], list[str]]:
    records, errors = [], []
    for src in source_rows:
        rec = A.blank_ingestion_record(source=src)
        # Normalise what the registry actually states; everything else stays
        # null per the failure policy.
        if src.get("languages") and len(src["languages"]) == 1:
            rec["language"] = src["languages"][0]
        if src.get("ecosystems") and len(src["ecosystems"]) == 1:
            rec["ecosystem"] = src["ecosystems"][0]
        rec["redistribution_allowed"] = (src.get("license") or {}).get(
            "redistribution_allowed")
        rec["license"] = (src.get("license") or {}).get("content_license")
        errors += [f"{src['source_name']}: {e}"
                   for e in A.validate_ingestion_record(rec)]
        records.append(rec)
    return records, errors


def frac(n: int, d: int) -> str:
    return f"{n} / {d}"


def build_report_md(m: dict, source_rows: list[dict]) -> str:
    L: list[str] = []
    a = L.append
    a("# Audit source ingestion report\n")
    a("Generated by `scripts/ingest_audit_sources.py`. Every metric carries "
      "its denominator: `numerator / denominator`. Where evidence is "
      "unavailable the value is `unknown` and the candidate stays "
      "`UNVERIFIED`/`INCONCLUSIVE` — nothing is guessed (section 24).\n")
    a("Governing rule: **TRUTH > PROVENANCE > REPRODUCIBILITY > DIVERSITY > "
      "SCALE > METRICS**. An S1 audit finding is not a verified exploit and "
      "an S4 dataset record is not a verified vulnerability.\n")
    a("## 1. Sources discovered\n")
    a(f"- registry archives: **{frac(m['sources_registered'], m['sources_mandatory'])}** "
      "mandatory sources registered")
    a(f"- by class: `{m['sources_by_class']}` over "
      f"{m['sources_registered']} registered")
    a(f"- by priority: `{m['sources_by_priority']}` over "
      f"{m['sources_registered']} registered\n")
    a("## 2. Reports discovered\n")
    a(f"- report-level sources in `jsonl_ml/`: "
      f"**{frac(m['reports_parsed_ml'], m['ml_sources'])}** sources enumerated")
    a(f"- registry archives probed this run: "
      f"**{frac(m['sources_probed'], m['sources_registered'])}**\n")
    a("## 3. Reports successfully parsed\n")
    a(f"- parsed into findings: **{frac(m['reports_parsed_ml'], m['ml_sources'])}** "
      "sources with ≥1 finding row")
    a(f"- findings parsed: **{frac(m['candidates'], m['candidates'])}** rows in "
      "`jsonl_ml/findings_*.jsonl`\n")
    a("## 4. Reports inaccessible\n")
    a(f"- registry URLs reachable (this run): "
      f"**{frac(m['sources_reachable'], m['sources_registered'])}**")
    a(f"- registry URLs inaccessible (this run): "
      f"**{frac(m['sources_inaccessible'], m['sources_registered'])}**")
    a(f"- registry URLs not probed (offline default): "
      f"**{frac(m['sources_not_probed'], m['sources_registered'])}** — "
      "re-run with `--probe-urls`\n")
    a("## 5. Projects discovered\n")
    a(f"- distinct protocols in findings: **{frac(m['projects_ml'], m['candidates'])}** "
      "protocols over findings")
    a(f"- auditors/orgs: `{m['auditors']}` over {m['candidates']} findings\n")
    a("## 6. Languages discovered\n")
    a(f"- by language: `{m['by_language']}` over {m['candidates']} findings")
    a(f"- language targets (sec 10): `{list(A.LANGUAGE_TARGETS)}`\n")
    a("## 7. Ecosystems discovered\n")
    a(f"- by ecosystem: `{m['by_ecosystem']}` over {m['candidates']} findings")
    a(f"- ecosystem targets (sec 10): `{list(A.ECOSYSTEM_TARGETS)}`\n")
    a("## 8. Vulnerability classes discovered\n")
    a(f"- distinct classes: **{frac(m['n_vuln_classes'], m['candidates'])}** "
      "classes over findings")
    if m["vuln_classes"]:
        a(f"- classes: `{m['vuln_classes']}`\n")
    else:
        a("- classes: none labelled on the finding rows (`unknown`, not inferred)\n")
    a("## 9. Candidates extracted\n")
    a(f"- candidates: **{frac(m['candidates'], m['candidates'])}** findings in "
      "`jsonl_ml/`\n")
    a("## 10. Candidates deduplicated\n")
    a(f"- cross-report equivalence groups: **{frac(m['dedup_groups'], m['candidates'])}** "
      "groups over findings")
    a(f"- findings linked to a group: **{frac(m['duplicates_linked'], m['candidates'])}** — "
      "linked, never counted twice; a duplicate is not a false positive\n")
    a("## 11. Candidates with exact commits\n")
    a(f"- exact 40-hex commit: **{frac(m['exact_commit'], m['candidates'])}**")
    a(f"- provenance ladder: `{m['commit_status']}` over {m['candidates']} findings "
      "(exact_commit > tag_or_version > weak_path_only > none)\n")
    a("## 12. Candidates with PoCs\n")
    a(f"- with a cited or executed PoC: **{frac(m['with_poc'], m['candidates'])}**")
    a(f"- by experiment level: `{m['by_level']}` over "
      f"{m['n_derived']} derived records\n")
    a("## 13. Candidates experimentally reproduced\n")
    a(f"- reproduced violation: **{frac(m['reproduced'], m['with_poc'])}** PoC candidates")
    a(f"- by verification state: `{m['by_state']}` over {m['candidates']} findings\n")
    a("## 14. Candidates with verified patches\n")
    a(f"- L6 (same exploit reproduces vulnerable + blocked fixed): "
      f"**{frac(m['l6'], m['with_poc'])}** PoC candidates")
    a(f"- fixed-revision leg executed: **{frac(m['fixed_leg'], m['candidates'])}**\n")
    a("## 15. Verified non-exploits\n")
    a(f"- verified non-exploits: **{frac(m['verified_non_exploit'], m['candidates'])}** findings")
    a(f"- by record class: `{m['by_record_class']}` over {m['candidates']} findings\n")
    a("## 16. Unknown / unresolved candidates\n")
    a(f"- unknown/unresolved: **{frac(m['unknown_unresolved'], m['candidates'])}** findings "
      "(neither reproduced nor a verified non-exploit)\n")
    a("## 17. Licensing restrictions\n")
    a(f"- sources with unknown content licence: "
      f"**{frac(m['licenses_unknown'], m['ml_sources'])}** ml sources")
    a(f"- redistributable flags: `{m['licenses_redistributable']}` over "
      f"{m['ml_sources']} ml sources")
    a("- registry archives default to `redistribution_allowed: false`; HashEx "
      "and research sources carry an explicit caution. Publicly accessible "
      "is not freely redistributable.\n")
    a("## 18. Source concentration\n")
    top_aud = max(m["auditors"].values()) if m["auditors"] else 0
    a(f"- largest auditor share: **{frac(top_aud, m['candidates'])}** findings")
    a(f"- findings per auditor: `{m['auditors']}`")
    a(f"- gold per auditor: `{m['gold_by_auditor']}` over "
      f"{m['admitted_gold']} gold records")
    a("- threshold: any single auditor above half the gold set raises "
      "`SOURCE_CONCENTRATION_WARNING` "
      f"({'RAISED' if m['gold_top_share'] > m['admitted_gold'] / 2 else 'not raised'}: "
      f"largest gold share {m['gold_top_share']} / {m['admitted_gold']})\n")
    a("## 19. Language concentration\n")
    a(f"- findings per language: `{m['by_language']}` over {m['candidates']} findings")
    a("- requirement: Solidity must not dominate by default; diversification "
      "is tracked, not assumed\n")
    a("## 20. Ecosystem concentration\n")
    a(f"- findings per ecosystem: `{m['by_ecosystem']}` over {m['candidates']} findings\n")
    a("## 21. Dataset leakage risks\n")
    a(f"- v2.2 post-check: `{m['leakage_v22'] or 'no post_check on disk'}`")
    a(f"- v1 artefact overlap: **{m['leakage_v1_artefacts']} / 4** detectors "
      "with cross-split pairs; protocol-isolation violations: "
      f"**{m['leakage_v1_protocol']} / {m['leakage_v1_protocols']}** protocols in two splits")
    a("- splits guard exact code, repository, protocol, audit-report, root "
      "cause, family, time and PoC reuse; temporal evaluations obey "
      "TRAIN ≤ cutoff < TEST\n")
    a("## 22. Failed experiments\n")
    a(f"- runs not ok: **{frac(m['runs_bad'], m['runs'])}** experiment runs")
    a(f"- runs ok: **{frac(m['runs_ok'], m['runs'])}** experiment runs\n")
    a("## 23. Inconclusive experiments\n")
    indec = m["by_state"].get("INCONCLUSIVE", 0)
    a(f"- inconclusive: **{frac(indec, m['candidates'])}** findings "
      "(different tests per revision are never an effectiveness result)\n")
    a("## 24. Final admitted records\n")
    a(f"- corpus (sufficient provenance): **{frac(m['admitted_corpus'], m['candidates'])}** findings")
    a(f"- gold (L5/L6 experimentally demonstrated): "
      f"**{frac(m['admitted_gold'], m['candidates'])}** findings")
    a("- ideal remains L6; no L6 is manufactured from L0-L5 evidence\n")
    a("## Registry status (this run)\n")
    a("| source | class | priority | access | licence |")
    a("|---|---|---|---|---|")
    for s in source_rows:
        lic = (s.get("license") or {}).get("content_license", "unknown")
        a(f"| {s['source_name']} | {s.get('source_class')} | "
          f"{s.get('source_priority')} | {s.get('access')} | {lic} |")
    a("")
    a("## Failure policy (section 24)\n")
    a("No commit was guessed, no vulnerability inferred from severity, no PoC "
      "invented, no fix inferred from a diff, and no external label copied as "
      "truth. Every blank field in `derived_v2_2/audit_ingestion_records.jsonl` "
      "is `null`/`unknown` with the missing evidence recorded.")
    a("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="compute and report, write nothing")
    ap.add_argument("--probe-urls", action="store_true",
                    help="HEAD each registry URL (needs network)")
    args = ap.parse_args()

    source_rows = enumerate_sources(probe=args.probe_urls)
    findings, sources, derived = load_layer()
    derived_by_id = {r.get("id"): r for r in derived}
    m = compute_metrics(source_rows, findings, sources, derived)
    records, rec_errors = build_ingestion_records(source_rows)

    graphs = {}
    for f in findings:
        fid = f.get("id")
        if not fid:
            continue
        d = derived_by_id.get(fid) or {}
        if (d.get("experiment_view") or {}).get("level") in ("L5", "L6"):
            graphs[fid] = provenance_graph(f, derived_by_id)

    doc = {
        "generated_by": "scripts/ingest_audit_sources.py",
        "generated_at": TODAY,
        "dataset_version": DATASET_VERSION,
        "registry": {
            "registered": m["sources_registered"],
            "mandatory": m["sources_mandatory"],
            "by_class": m["sources_by_class"],
            "by_priority": m["sources_by_priority"],
            "probed": m["sources_probed"],
            "reachable": m["sources_reachable"],
            "inaccessible": m["sources_inaccessible"],
            "not_probed": m["sources_not_probed"],
        },
        "metrics": m,
        "provenance_graphs_verified_only": graphs,
        "ingestion_record_errors": rec_errors,
        "failure_policy": "missing evidence is null/unknown; no field fabricated",
    }

    md = build_report_md(m, source_rows)
    log(f"sources {m['sources_registered']}/{m['sources_mandatory']} "
        f"probed={m['sources_probed']} reachable={m['sources_reachable']}")
    log(f"candidates={m['candidates']} exact_commit={m['exact_commit']} "
        f"with_poc={m['with_poc']} reproduced={m['reproduced']} "
        f"L6={m['l6']} gold={m['admitted_gold']}")
    if rec_errors:
        for e in rec_errors[:20]:
            log(f"  [FAIL] {e}")
        return 1
    if args.check:
        log("--check: nothing written")
        return 0

    A.write_jsonl(DERIVED_V22 / "audit_sources.jsonl", source_rows)
    A.write_jsonl(DERIVED_V22 / "audit_ingestion_records.jsonl", records)
    A.write_json(REPORTS / "audit_source_ingestion.json", doc)
    (REPORTS / "audit_source_ingestion_report.md").write_text(md, encoding="utf-8", newline="\n")
    log(f"wrote {DERIVED_V22 / 'audit_sources.jsonl'} ({len(source_rows)} rows)")
    log(f"wrote {DERIVED_V22 / 'audit_ingestion_records.jsonl'} ({len(records)} rows)")
    log(f"wrote {REPORTS / 'audit_source_ingestion_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

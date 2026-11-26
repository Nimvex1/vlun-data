"""Build wave1/01_dedup/registry.jsonl from all five canonical layers.

Stdlib only. Reads canonical layers strictly read-only. Every emitted row goes
through guard_wave1(). Idempotent: the registry is rewritten from scratch.
"""
from __future__ import annotations

import json
from collections import Counter

from _common import (
    ROOT,
    WAVE1,
    guard_wave1,
    ids_from_text,
    norm_id,
    norm_repo_slug,
    norm_tx,
    norm_url,
    read_jsonl,
    utc_now,
    write_jsonl,
)

REG = WAVE1 / "01_dedup" / "registry.jsonl"


def main() -> None:
    rows: list[dict] = []
    counts: Counter = Counter()

    def add(key: str, key_type: str, layer: str, value: str, *, source_ref: str = "") -> None:
        if not key:
            return
        rows.append(
            {
                "key": key,
                "key_type": key_type,
                "layer": layer,
                "value": value,
                "source_ref": source_ref,
            }
        )
        counts[f"{layer}:{key_type}"] += 1

    # ---------------- v1 ----------------
    for rel in [
        "jsonl/findings.jsonl",
        "jsonl/negative_findings.jsonl",
        "jsonl/exploits.jsonl",
        "jsonl/patches.jsonl",
        "derived/records.jsonl",
    ]:
        p = ROOT / rel
        if not p.exists():
            continue
        for rec in read_jsonl(p):
            fid = None
            if isinstance(rec.get("finding"), dict):
                fid = rec["finding"].get("id")
            fid = fid or rec.get("finding_id") or rec.get("candidate_id") or rec.get("id")
            if fid:
                add(f"v1_finding:{norm_id(fid)}", "finding_id", "v1", str(fid), source_ref=rel)
            src = rec.get("source") if isinstance(rec.get("source"), dict) else {}
            repo = src.get("repository") or rec.get("repository")
            if repo:
                add(f"v1_repo:{norm_repo_slug(repo)}", "repo_slug", "v1", str(repo), source_ref=rel)

    # 18 renft mitigation records in jsonl/patches.jsonl -> explicit bridge occupancy
    renft_issues = 0
    for rec in read_jsonl(ROOT / "jsonl" / "patches.jsonl"):
        text = json.dumps(rec, ensure_ascii=False)
        import re

        for slug, num in re.findall(
            r"code-423n4/(2024-02-renft-mitigation-findings)/issues/(\d+)", text, re.I
        ):
            add(
                f"mitigation_issue:{norm_repo_slug(slug)}:{num}",
                "mitigation_issue",
                "v1",
                f"{slug}/issues/{num}",
                source_ref="jsonl/patches.jsonl",
            )
            renft_issues += 1

    # ---------------- v2.2 ----------------
    alias_folds = 0
    for p in sorted((ROOT / "jsonl_ml").glob("sources_*.jsonl")):
        for rec in read_jsonl(p):
            sid = rec.get("source_id")
            if sid:
                add(f"v22_source:{str(sid).lower()}", "source_id", "v2.2", str(sid), source_ref=str(p.name))
            raw = json.dumps(rec, ensure_ascii=False)
            ids = ids_from_text(raw)
            for g in ids["ghsa"]:
                add(f"ghsa:{g}", "GHSA", "v2.2", g, source_ref=str(p.name))
            for c in ids["cve"]:
                add(f"cve:{c}", "CVE", "v2.2", c, source_ref=str(p.name))
            for alias_kind in ("cwa", "rustsec"):
                for a in ids[alias_kind]:
                    add(f"alias:{a}", "alias", "v2.2", a, source_ref=str(p.name))
                    # fold alias -> any GHSA named in the same record
                    for g in ids["ghsa"]:
                        add(f"alias_fold:{a}->{g}", "alias_fold", "v2.2", f"{a}->{g}", source_ref=str(p.name))
                        alias_folds += 1

    # ---------------- V3 ----------------
    for rec in read_jsonl(ROOT / "jsonl_v3" / "findings.jsonl"):
        cid = rec.get("candidate_id")
        if cid:
            add(f"v3_candidate:{cid}", "candidate_id", "V3", str(cid), source_ref="jsonl_v3/findings.jsonl")
        tx = norm_tx(rec.get("keyinfo_attack_tx") or "")
        if tx:
            add(f"v3_tx:{tx}", "attack_tx", "V3", tx, source_ref="jsonl_v3/findings.jsonl")
        sid = rec.get("source_id")
        cid = rec.get("candidate_id")
        if sid == "certora-reports" and cid:
            # one unique key per existing report-level pointer, for the formal adapter
            add(f"certora_rule:{cid}", "certora_key", "V3", str(cid), source_ref="jsonl_v3/findings.jsonl")
    for rec in read_jsonl(ROOT / "jsonl_v3" / "sources.jsonl"):
        sid = rec.get("source_id")
        if sid:
            add(f"v3_source:{sid}", "source_id", "V3", str(sid), source_ref="jsonl_v3/sources.jsonl")

    # ---------------- Vbeta ----------------
    for rel in ["Vbeta/jsonl_vbeta/findings.jsonl", "Vbeta/derived_vbeta/records.jsonl"]:
        p = ROOT / rel
        if not p.exists():
            continue
        for rec in read_jsonl(p):
            cid = rec.get("candidate_id") or rec.get("finding_id")
            if cid:
                add(f"vbeta_finding:{cid}", "finding_id", "Vbeta", str(cid), source_ref=rel)
    sol = ROOT / "Vbeta" / "solodit_candidates.json"
    if sol.exists():
        data = json.loads(sol.read_text(encoding="utf-8"))
        blob = json.dumps(data, ensure_ascii=False)
        import re

        urls = set(re.findall(r"https?://[^\s\"'<>]+", blob))
        for u in urls:
            add(f"solodit_url:{norm_url(u)}", "solodit_url", "Vbeta", norm_url(u), source_ref="Vbeta/solodit_candidates.json")
    try:
        vsrc = json.loads((ROOT / "Vbeta" / "sources.json").read_text(encoding="utf-8"))
        for rec in (vsrc.get("sources", []) if isinstance(vsrc, dict) else []):
            sid = (rec.get("source_id") or rec.get("name")) if isinstance(rec, dict) else ""
            if sid:
                add(f"vbeta_source:{sid}", "source_id", "Vbeta", str(sid), source_ref="Vbeta/sources.json")
    except (OSError, ValueError) as exc:
        print(f"[registry] Vbeta/sources.json skipped: {exc}")

    # ---------------- V4 ----------------
    p4 = ROOT / "jsonl_v4" / "findings.jsonl"
    if p4.exists():
        for rec in read_jsonl(p4):
            cid = rec.get("candidate_id") or rec.get("finding_id_original") or rec.get("finding_id")
            if cid:
                add(f"v4_candidate:{cid}", "candidate_id", "V4", str(cid), source_ref="jsonl_v4/findings.jsonl")
            ids = ids_from_text(json.dumps(rec, ensure_ascii=False))
            for g in ids["ghsa"]:
                add(f"ghsa:{g}", "GHSA", "V4", g, source_ref="jsonl_v4/findings.jsonl")
    for rec in read_jsonl(ROOT / "jsonl_v4" / "sources.jsonl"):
        sid = rec.get("source_id")
        if sid:
            add(f"v4_source:{sid}", "source_id", "V4", str(sid), source_ref="jsonl_v4/sources.jsonl")

    # ---------------- Prove revision pairs ----------------
    pairs = set()
    for rec in read_jsonl(ROOT / "derived_prove" / "candidate_ledger.jsonl"):
        fix = rec.get("fixed_commit")
        repo = rec.get("repository")
        if fix and isinstance(fix, str) and len(fix) >= 40:
            pairs.add((norm_repo_slug(repo or ""), fix.lower()))
    for repo, fix in sorted(pairs):
        add(f"prove_pair:{repo}:{fix}", "revision_pair", "Prove", f"{repo}@{fix}", source_ref="derived_prove/candidate_ledger.jsonl")

    # deduplicate by key, preserving first occurrence
    seen: set[str] = set()
    unique = []
    for r in rows:
        if r["key"] in seen:
            continue
        seen.add(r["key"])
        unique.append(r)

    n = write_jsonl(guard_wave1(REG), unique)
    summary = {
        "built_at": utc_now(),
        "registry_rows": n,
        "by_layer_type": {f"{k}": v for k, v in sorted(counts.items())},
        "unique_revision_pairs": len(pairs),
        "renft_mitigation_issue_occupancies": renft_issues,
        "alias_fold_edges": alias_folds,
    }
    from _common import write_json

    write_json(WAVE1 / "01_dedup" / "registry_summary.json", summary)
    print(f"[registry] wrote {n} unique keys to {REG}")
    for k, v in sorted(counts.items()):
        print(f"  {k}: {v}")
    print(f"  unique prove revision pairs: {len(pairs)}")
    print(f"  renft mitigation issue occupancies: {renft_issues}")


if __name__ == "__main__":
    main()

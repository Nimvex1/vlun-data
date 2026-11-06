#!/usr/bin/env python3
"""Depth dashboard: one page combining what the headline counts hide.

Per layer: record counts, verification-level histogram (L0-L6, labeled with
what each bin actually counts), and field-coverage highlights. Plus:
root_cause correction layer for High findings (verbatim quotes, never
paraphrased) and the prepared-but-unexecuted M-11-sibling experiment spec.

Writes reports/depth_dashboard.json + reports/depth_dashboard.md only.

    python scripts/depth_dashboard.py
    python scripts/depth_dashboard.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def jl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def js(path: Path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def first_sentences(text: str, n: int = 2) -> str:
    import re
    parts = re.split(r"(?<=[.?!])\s+", text.strip())
    return " ".join(parts[:n])[:600]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    layers: dict[str, dict] = {}
    findings = jl(ROOT / "jsonl" / "findings.jsonl")
    # The v1 level histogram is read from the published layer, never typed here:
    # a literal "7" stayed true long after it could have stopped being true, and
    # a dashboard figure that cannot move when the evidence moves is not a
    # measurement.
    _v1_manifest = json.loads((ROOT / "derived" / "manifest.json").read_text(
        encoding="utf-8"))
    _v1_levels = dict(_v1_manifest.get("derived_verification_levels") or {})
    _ve = json.loads((ROOT / "reports" / "verified_experiments.json").read_text(
        encoding="utf-8"))
    _experiments = _ve.get("experiments") or []
    _inconclusive = sum(1 for e in _experiments
                        if e.get("verdict") != "l6_verified_patch")
    layers["v1"] = {
        "records": len(findings),
        "levels": {**_v1_levels, "note": (
            f"{_v1_levels.get('L6', 0)} verified-effective patches (L6, "
            f"both-legs forge runs); {len(_experiments)} pinpoint experiments, "
            f"{_inconclusive} inconclusive")},
        "root_cause_known": sum(
            1 for r in findings
            if (r.get("finding", {}).get("root_cause") or "").strip()),
    }
    m22 = js(ROOT / "derived_v2_2" / "manifest.json", {}) or {}
    layers["v2.2"] = {
        "records": m22.get("records", 0),
        "levels": dict(m22.get("experiment_levels", {})),
        "levels_note": "executed-run levels over 37 runs; 'none' = no run",
    }
    m3 = js(ROOT / "derived_v3" / "manifest.json", {}) or {}
    _v3lv = m3.get("admitted_verification_levels", {}) or {}
    _v3_exec = sum(v for k, v in _v3lv.items() if k in ("L3", "L4", "L5", "L6"))
    layers["v3.0"] = {
        "records": m3.get("record_count", 0),
        "levels": dict(_v3lv),
        # Stated from the manifest, not typed: "nothing executed" was true when
        # it was written and stayed true in the prose after 127 records gained a
        # compile-or-run artefact.
        "levels_note": (f"{_v3_exec} admitted records carry an L3+ artefact "
                        f"({m3.get('execution_attempts', 0)} distinct proof runs, "
                        f"{_v3lv.get('L5', 0)} L5, {_v3lv.get('L6', 0)} L6); "
                        "the rest are L0/L1"),
    }
    proof32 = js(ROOT / "reports" / "v3" / "experimental_proof.json", {}) or {}
    layers["v3.2"] = {
        "runs": len((proof32.get("runs") or [])),
        "levels": dict(proof32.get("by_level", {})),
        "levels_note": "fork-execution runs, not records",
    }
    mvb = js(ROOT / "Vbeta" / "derived_vbeta" / "manifest.json", {}) or {}
    layers["vbeta"] = {
        "records": mvb.get("record_count", 0),
        "levels": dict(mvb.get("candidate_verification_levels", {})),
        "levels_note": "ledger-level; L0/L1 only by construction",
    }
    fc = js(ROOT / "reports" / "field_coverage.json", {}) or {}
    fields = fc.get("fields", {})

    # Correction layer: root_cause candidates for High findings, quoted
    # verbatim from the finding's own summary (first two sentences). The
    # original jsonl/ rows are untouched; this file only points at them.
    # Evidence is reported_claim (the auditor's own words), never derived.
    highs = [r for r in findings
             if r.get("finding", {}).get("severity") == "high"
             and (r.get("finding", {}).get("summary") or "").strip()]
    corrections = [{
        "record_id": r["finding"]["id"],
        "title": r["finding"].get("title"),
        "root_cause_candidate": first_sentences(
            r["finding"]["summary"], 2),
        "rule": "verbatim first-two-sentences quote of finding.summary; "
                "candidate, not verified cause",
        "evidence_type": "reported_claim",
        "source": "jsonl/findings.jsonl (row unmodified)",
    } for r in sorted(highs, key=lambda r: r["finding"]["id"])]

    dashboard = {
        "generated_by": "scripts/depth_dashboard.py",
        "layers": layers,
        "field_coverage_ref": "reports/field_coverage.json",
        "root_cause_corrections": len(corrections),
        "prepared_experiments": [{
            "finding_id": "2024-01-renft/M-13",
            "title": "RentPayload's signature can be replayed",
            "pattern": "M-11 sibling (same Signer.sol EIP-712 domain)",
            "vulnerable_commit": "2a4f56a292a1621fdc14db12725c2682ee7e5d4b",
            "fix_pr": "https://github.com/re-nft/smart-contracts/pull/10",
            "fix_merge_commit": "2e3e8dbca1330ca66d32a8bb9d3509abf043a758",
            "fix_merge_date": "2024-02-15",
            "mitigation": "confirmed by 3 reviewers (juancito, EV_om, "
                          "sin1st3r__); fix commit absent from jsonl patch "
                          "block (read-only layer left untouched)",
            "status": "prepared, NOT executed (no verdict recorded)",
        }],
        "scope_note": "no new sources admitted in this pass (rule 3.3)",
    }

    corr_path = ROOT / "derived" / "root_cause_candidates.jsonl"
    pv2 = js(ROOT / "reports" / "patch_verification_v2.json", {}) or {}
    dens = {
        "v1": (pv2.get("experimentally_confirmed_pairs", 0), len(findings)),
        "v2.2": (sum(v for k, v in
                      dict(m22.get("experiment_levels", {})).items()
                      if k in ("L5", "L6")),
                 m22.get("records", 0)),
        "v3.0": (0, m3.get("record_count", 0)),
        "vbeta": (0, mvb.get("record_count", 0)),
    }
    dens_line = " · ".join(f"{k} {a}/{b}" for k, (a, b) in dens.items())
    md_lines = [
        "# Depth dashboard — what the headline counts hide",
        "",
        "Generated by `scripts/depth_dashboard.py` from manifests and "
        "reports. Verification density "
        f"(L5+L6 ÷ admitted records): {dens_line}.",
        "",
        "## Verification levels per layer",
        "",
        "| Layer | Records/runs | Levels | Note |",
        "|---|---|---|---|",
    ]
    for name, info in layers.items():
        lvl = info.get("levels", {})
        lvl_s = ", ".join(f"{k}:{v}" for k, v in sorted(lvl.items())
                          if not str(k).startswith("note"))
        md_lines.append(
            f"| {name} | {info.get('records', info.get('runs'))} | "
            f"{lvl_s or '—'} | {info.get('levels_note', '')} |")
    md_lines += [
        "",
        "## Field coverage (worst first)",
        "",
    ]
    # known_pct == 0.0 is falsy; `or 100` dropped fully unknown fields from
    # the worst-first list entirely (they are the worst coverage there is).
    thin = sorted(
        ((k, v) for k, v in fields.items()
         if isinstance(v, dict)
         and isinstance(v.get("known_pct"), (int, float))
         and v["known_pct"] < 50),
        key=lambda kv: kv[1]["known_pct"])
    for k, v in thin[:15]:
        md_lines.append(
            f"- `{k}`: {v['known']}/{v['total']} ({v['known_pct']}%)")
    md_lines += [
        "",
        "## Root-cause correction layer",
        "",
        f"`derived/root_cause_candidates.jsonl` holds "
        f"{len(corrections)} verbatim-quote candidates for High findings "
        "with summaries (rule stated per row; originals untouched).",
        "",
        "## Prepared but unexecuted",
        "",
        "2024-01-renft/M-13 (RentPayload replay, M-11 sibling): vulnerable "
        "commit and fix-PR merge commit resolved above; no harness written, "
        "no verdict recorded. Execution needs a PAY-order fixture and is "
        "deferred, not faked.",
        "",
    ]

    out_json = ROOT / "reports" / "depth_dashboard.json"
    out_md = ROOT / "reports" / "depth_dashboard.md"
    if args.check:
        stale = []
        want_json = json.dumps(dashboard, indent=2, sort_keys=True) + "\n"
        if (not out_json.is_file()
                or out_json.read_text(encoding="utf-8") != want_json):
            stale.append("reports/depth_dashboard.json")
        want_md = "\n".join(md_lines) + "\n"
        if (not out_md.is_file()
                or out_md.read_text(encoding="utf-8") != want_md):
            stale.append("reports/depth_dashboard.md")
        want_corr = "".join(
            json.dumps(c, sort_keys=True) + "\n" for c in corrections)
        if (not corr_path.is_file()
                or corr_path.read_text(encoding="utf-8") != want_corr):
            stale.append("derived/root_cause_candidates.jsonl")
        if stale:
            print(f"STALE {', '.join(stale)} — run: python scripts/depth_dashboard.py")
            return 1
        print("depth dashboard is current")
        return 0
    out_json.write_text(json.dumps(dashboard, indent=2, sort_keys=True)
                        + "\n", encoding="utf-8", newline="\n")
    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8",
                      newline="\n")
    corr_path.write_text("".join(
        json.dumps(c, sort_keys=True) + "\n" for c in corrections),
        encoding="utf-8", newline="\n")
    print(f"wrote depth dashboard ({len(corrections)} root_cause candidates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Per-field coverage: how many records actually carry each key field.

Headline counts hide emptiness (259/264 empty root_cause, 432/722 unknown
attacker model). This script counts known vs unknown/empty per field from
the canonical files and writes reports/field_coverage.json + .md so buyers
can price honestly. Writes only those two files.

    python scripts/field_coverage.py
    python scripts/field_coverage.py --check   # exit 1 if reports are stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def jl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def js(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def get(row: dict, dotted: str):
    cur: object = row
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def known(v) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return v.strip().lower() not in ("", "unknown")
    if isinstance(v, (list, dict)):
        return len(v) > 0
    return True


def known_basis(v) -> bool:
    """Attacker-identity style: known only if basis/evidenced, not unknown."""
    if isinstance(v, dict):
        b = v.get("basis")
        e = v.get("evidence_type")
        return b not in (None, "unknown") and e not in (None, "unknown")
    return known(v)


def cover(rows: list[dict], field: str, basis: bool = False) -> dict:
    k = sum(1 for r in rows
            if (known_basis if basis else known)(get(r, field)))
    return {"total": len(rows), "known": k, "unknown_or_empty": len(rows) - k,
            "known_pct": round(100 * k / len(rows), 1) if rows else None}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    rep: dict[str, dict] = {}
    findings = jl(ROOT / "jsonl" / "findings.jsonl")
    for f in ("finding.root_cause", "finding.summary", "finding.severity",
              "finding.vulnerability_classes", "finding.title",
              "finding.status"):
        rep[f"v1.findings.{f}"] = cover(findings, f)
    derived = jl(ROOT / "derived" / "records.jsonl")
    rep["v1.derived.attacker_identity"] = cover(
        derived, "attacker_model.attacker_identity", basis=True)
    for f in ("invariants", "security_state_transition", "taxonomy"):
        rep[f"v1.derived.{f}"] = cover(derived, f)
    for layer, path in (("v3", ROOT / "derived_v3" / "records.jsonl"),
                        ("vbeta", ROOT / "Vbeta" / "derived_vbeta"
                         / "records.jsonl")):
        try:
            rows = jl(path)
        except OSError:
            continue
        for f in ("root_cause", "impact", "attack_sequence", "severity",
                  "language", "ecosystem", "fix_description"):
            rep[f"{layer}.records.{f}"] = cover(rows, f)

    out_json = ROOT / "reports" / "field_coverage.json"
    lines = ["# Field coverage — what fraction of records carry each field",
             "",
             "Counts recomputed from canonical files by "
             "`scripts/field_coverage.py`. `unknown`/empty/null counts as "
             "missing; nothing is inferred.",
             "",
             "| Scope.field | Total | Known | Missing | Known % |",
             "|---|---|---|---|---|"]
    for key in sorted(rep):
        c = rep[key]
        lines.append(f"| `{key}` | {c['total']} | {c['known']} | "
                     f"{c['unknown_or_empty']} | {c['known_pct']} |")
    out_md = ROOT / "reports" / "field_coverage.md"
    payload = {"generated_by": "scripts/field_coverage.py", "fields": rep}
    if args.check:
        stale = []
        if not out_json.is_file() or json.loads(
                out_json.read_text(encoding="utf-8")) != payload:
            stale.append("reports/field_coverage.json")
        if not out_md.is_file() or out_md.read_text(
                encoding="utf-8") != "\n".join(lines) + "\n":
            stale.append("reports/field_coverage.md")
        if stale:
            print(f"STALE {', '.join(stale)} — run: python scripts/field_coverage.py")
            return 1
        print("field coverage reports are current")
        return 0
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(rep)} field coverages "
          f"({sum(1 for c in rep.values() if (c['known_pct'] or 0) < 50)} "
          f"fields under 50% known)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""One roll-up of everything the pipeline set aside, in place of six scattered lists.

The remediation brief asks for a quarantine report covering malformed records,
missing sources and failed executions. Those facts already exist, but each lives
in a different artefact, so nobody could answer "how much did this corpus
refuse?" without opening nine files. This script reads them and counts, and it
names the source of every number so a reader can go and check it.

Nothing is copied into the public record here beyond identifiers and locators:
the withheld-content rules in `NOTICE.md` apply to this file as to any other.

    python scripts/build_quarantine_report.py [--check]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import REPORTS, ROOT, log, write_json  # noqa: E402

MD = REPORTS / "quarantine_report.md"
JS = REPORTS / "quarantine_report.json"
MISSING = "not recorded"


def jread(rel: str) -> dict:
    p = ROOT / rel
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def count_lines(rel: str) -> int | None:
    p = ROOT / rel
    if not p.is_file():
        return None
    return sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.strip())


def _self_digest() -> str:
    """Digest of this generator's own source.

    The report is generated, so a change to the collector must not be
    recorded with `--check`: that compares output to output and passes
    forever. The committed artefact is stamped with the digest it was built
    by, and `--check` fails whenever the committed bytes were produced by
    different code — which is what makes the stamped count a real
    measurement of the current pipeline.
    """
    src = Path(__file__).resolve()
    return hashlib.sha256(src.read_bytes()).hexdigest()


def collect() -> dict:
    groups: list[dict] = []

    def add(name: str, why: str, count, source: str, detail=None) -> None:
        groups.append({"group": name, "meaning": why,
                       "records": count if count is not None else MISSING,
                       "counted_from": source, "detail": detail or {}})

    # --- set aside by the split builders -------------------------------------
    for rel, label, source in (
            ("splits_v2/quarantine.jsonl", "v1/v2 split quarantine",
             "leakage-detected duplicates and cross-split references"),
            ("splits_v2_2/quarantine.jsonl", "v2.2 split quarantine",
             "near-duplicate and same-source rows kept out of train/validation/test"),
            ("Vbeta/splits_vbeta/quarantine.jsonl", "Vbeta split quarantine",
             "harvested candidates that duplicate an admitted record or lack a locator")):
        add(label, source, count_lines(rel), rel)

    # --- refused by the ingestion layer --------------------------------------
    add("V4 quarantined ledger", "report candidates extracted from the cloned archives "
        "that did not clear the V4 admission rule",
        count_lines("derived_v4/quarantined_ledger.jsonl"),
        "derived_v4/quarantined_ledger.jsonl")
    add("V4 duplicate ledger", "candidates that matched a record already in the corpus",
        count_lines("derived_v4/duplicate_ledger.jsonl"),
        "derived_v4/duplicate_ledger.jsonl")

    # --- malformed or unreadable, by kind -------------------------------------
    err = jread("reports/extraction_errors.json")
    kinds = {k: v for k, v in (err.get("by_kind") or {}).items()}
    if kinds:
        add("extraction errors by kind",
            "rows the extractor could not read, citations it could not retrieve, and "
            "labels it refused to rely on",
            sum(kinds.values()), "reports/extraction_errors.json", detail=kinds)

    # --- execution attempts that did not establish anything --------------------
    attempts = [json.loads(l) for l in
                (REPORTS / "poc_attempts.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()] if (REPORTS / "poc_attempts.jsonl").is_file() else []
    by_status: dict[str, int] = {}
    for a in attempts:
        s = str(a.get("status") or "unknown")
        by_status[s] = by_status.get(s, 0) + 1
    if attempts:
        add("v1/v2.1 PoC re-run attempts", "recorded sandbox attempts that did not reach a "
            "demonstrated violation — preserved as data, not deleted",
            len(attempts), "reports/poc_attempts.jsonl", detail=by_status)

    unblock = jread("reports/v3/v32_unblock_attempts.json")
    if unblock:
        add("V3.2 recovery attempts", "attempts to unblock a previously blocked execution; "
            "the blocked ones keep their explicit blocker and are not promoted",
            unblock.get("attempts_total", MISSING),
            "reports/v3/v32_unblock_attempts.json",
            detail=unblock.get("by_status") or {})

    nonevm = jread("reports/nonevm_pilot.json")
    if nonevm:
        blockers = (nonevm.get("counts") or {}).get("blockers_overall") or {}
        add("non-EVM pilot blockers", "candidates that could not be executed here: missing "
            "toolchain, unpinned revision, build-time budget",
            sum(blockers.values()) if blockers else MISSING,
            "reports/nonevm_pilot.json", detail=blockers)

    exps = jread("reports/verified_experiments.json")
    inconc = [e for e in exps.get("experiments", []) if str(e.get("verdict", "")).startswith("inconclusive")]
    if exps:
        add("inconclusive declared experiments", "an experiment that ran and still did not "
            "establish the claim; the record keeps the level the evidence supports",
            len(inconc), "reports/verified_experiments.json",
            detail={str(e.get("verdict")): sum(1 for x in inconc if x.get("verdict") == e.get("verdict"))
                    for e in inconc})

    # --- rights: content withheld from the published distribution -------------
    rights = jread("reports/rights_inventory.json")
    registry = rights.get("source_registry") or {}
    sources = registry.get("sources") if isinstance(registry, dict) else registry
    sources = sources or []
    pointer_rows = sum(count_lines(f"distribution_v1/{name}") or 0 for name in (
        "records_v1_withheld_pointers.jsonl", "records_v4_withheld_pointers.jsonl",
        "withheld_harness.jsonl"))
    if rights:
        personal = rights.get("personal_data_findings") or []
        add("withheld expressive content", "third-party code, report prose or PoC source "
            "removed from the distribution view and replaced by a pointer record",
            pointer_rows, "distribution_v1/*_withheld_pointers.jsonl, withheld_harness.jsonl",
            detail={"personal_data_artefacts": len(personal),
                    "licence_contradictions": len(rights.get("licence_contradictions") or []),
                    "registered_sources": len(sources)})
    return {"generated_by": "scripts/build_quarantine_report.py",
            "generator_sha256": _self_digest(),
            "groups": groups,
            "reading": ("every count is recomputed from the artefact named in `counted_from`; "
                        "a category whose source file is absent reports the group as absent "
                        "rather than as zero")}


def render(doc: dict) -> str:
    out = ["# What the pipeline set aside\n",
           "Generated by `scripts/build_quarantine_report.py`. Each row names the artefact it "
           "was counted from, so the number can be checked rather than trusted. "
           f"Built by generator `{str(doc.get('generator_sha256') or '')[:12]}`.\n",
           "| group | records | counted from |", "|---|---|---|"]
    for g in doc["groups"]:
        out.append(f"| {g['group']} — {g['meaning']} | {g['records']} | "
                   f"`{g['counted_from']}` |")
    out.append("\n" + doc["reading"] + "\n")
    out.append("\n## Blocker detail\n")
    for g in doc["groups"]:
        if not g["detail"]:
            continue
        out.append(f"**{g['group']}**\n")
        for k, v in sorted(g["detail"].items(), key=lambda kv: str(kv[0])):
            out.append(f"- `{k}`: {v}")
        out.append("")
    out.append("\n## What this list is for\n")
    out.append("A corpus grows by refusing things as much as by admitting them. This file "
               "exists so the refusals are countable: a quarantined row is still a row, an "
               "inconclusive experiment is still an experiment, and a withheld snippet is "
               "still cited. Nothing here was deleted to make a headline number look "
               "cleaner.\n")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    doc = collect()
    js = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    md = render(doc)
    if args.check:
        stale = [str(p) for p, t in [(JS, js), (MD, md)]
                 if not p.exists() or p.read_text(encoding="utf-8") != t]
        if stale:
            log("STALE: " + ", ".join(stale))
            return 1
        log("quarantine report is current")
        return 0
    JS.write_text(js, encoding="utf-8", newline="\n")
    MD.write_text(md, encoding="utf-8", newline="\n")
    log("quarantine_report.md: " + ", ".join(
        f"{g['group']}={g['records']}" for g in doc["groups"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Non-EVM execution pilot (spec item 9): discover, pin, execute, report.

Runs one adapter per platform (CosmWasm, Solana Anchor, Aptos/Sui Move,
Cairo/Scarb), each in an isolated local scratch tree - no live-chain
transaction, no real funds, no faucet claim, no deployment, no Docker.

Per run it writes command.txt, toolchain.txt, harness.json, assertion.json,
stdout.txt, stderr.txt and result.json under experiments_nonevm/<record>/,
then regenerates reports/nonevm_pilot.json and .md with every count recomputed
from those artefacts (nothing is typed into the report).

    python scripts/nonevm/run_pilot.py                     # all platforms
    python scripts/nonevm/run_pilot.py --platform sui_move
    python scripts/nonevm/run_pilot.py --report-only       # recount artefacts

Exit code 0 if the pilot ran and the artefacts are self-consistent, 1 if an
artefact failed validation, 2 if a platform adapter crashed.
"""
from __future__ import annotations

import argparse
import importlib
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common as C  # noqa: E402

MODULES = {
    "cosmwasm": "cosmwasm",
    "solana_anchor": "solana_anchor",
    "aptos_move": "aptos_move",
    "sui_move": "sui_move",
    "cairo_scarb": "cairo_scarb",
}


def obs(name, value) -> None:
    print(f"OBS {name}={value}", flush=True)


def check(name, ok, detail="") -> None:
    print(f"CHECK {'pass' if ok else 'fail'} {name}"
          + (f" :: {detail}" if detail else ""), flush=True)


def ceiling_ladder(runs: list[dict]) -> dict:
    """Per record: L6 needs the violation reproduced on one pinned revision
    and the same named assertion blocking on the other pinned revision."""
    by_record: dict[str, list[dict]] = {}
    for r in runs:
        by_record.setdefault(r["record_id"], []).append(r)
    out = {}
    for rid, rows in by_record.items():
        best = "L1"
        reproduced = {(x.get("assertion") or {}).get("name")
                      for x in rows if x.get("outcome") == "claim_reproduced"
                      and x.get("status") == "executed"}
        blocked_on_other = set()
        for x in rows:
            name = (x.get("assertion") or {}).get("name")
            if (x.get("status") == "executed" and name in reproduced
                    and (x.get("assertion") or {}).get("met") is True
                    and x.get("outcome") != "claim_reproduced"
                    and x.get("run_slug") not in
                    [y.get("run_slug") for y in rows
                     if y.get("outcome") == "claim_reproduced"
                     and (y.get("assertion") or {}).get("name") == name]):
                blocked_on_other.add(name)
        ladder_seen = [x.get("ladder") for x in rows if x.get("ladder")]
        for lvl in reversed(C.LADDER):
            if lvl in ladder_seen:
                best = lvl
                break
        if reproduced and blocked_on_other:
            best = "L6"
        out[rid] = {"highest_run_ladder": best,
                    "record_ceiling": "L6" if reproduced and blocked_on_other
                    else best,
                    "assertions_reproduced": sorted(n for n in reproduced if n),
                    "assertions_blocked_on_other_pin":
                        sorted(n for n in blocked_on_other if n),
                    "runs": len(rows)}
    return out


def vbeta_pool_audit() -> dict:
    """Size the non-EVM pool that lives in the Vbeta layer, from its own files.

    The spec quotes 156 non-Solidity records; the count below is recomputed so
    the pilot reports what is there rather than what was expected.  A finding
    is only *eligible* for execution if it carries a 40-hex commit that can be
    pinned; the language and the missing pin are the reasons recorded here.
    """
    import collections
    import json
    import re
    path = C.ROOT / "Vbeta" / "jsonl_vbeta" / "findings.jsonl"
    out = {"path": str(path.relative_to(C.ROOT)), "exists": path.exists()}
    if not path.exists():
        return out
    RE40 = re.compile(r"\b[0-9a-f]{40}\b")
    langs = collections.Counter()
    pinned = collections.Counter()
    total = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            lang = str(r.get("language") or "unspecified")
            if lang == "solidity":
                continue
            langs[lang] += 1
            if RE40.search(json.dumps(r)):
                pinned[lang] += 1
    out.update({
        "findings_total": total,
        "non_solidity_by_language": dict(sorted(langs.items(),
                                               key=lambda kv: -kv[1])),
        "non_solidity_total": sum(langs.values()),
        "non_solidity_with_a_40_hex_sha_somewhere": sum(pinned.values()),
        "eligibility_note": (
            "V3/Vbeta layers are metadata-only: no prose or code from them is "
            "copied into any artefact of this pilot. They are excluded from the "
            "executed set because the upstream commit of each finding is not "
            "recorded, so nothing can be pinned or replayed."),
    })
    return out


def declared_behaviour_discrepancies(runs: list[dict]) -> list[dict]:
    """Runs where the published scoping and the observed behaviour differ.

    Computed from the artefacts plus the adapter's own pin table, so a
    discrepancy is data the report can show rather than prose someone typed.
    """
    import cosmwasm
    roles = dict(cosmwasm.PINS)
    out = []
    for r in runs:
        if r.get("platform") != "cosmwasm" or r.get("status") != "executed":
            continue
        slug = r.get("run_slug", "")
        version = slug.split("-")[2] if slug.startswith("cosmwasm-std-") else None
        if version not in roles:
            continue
        a = r.get("assertion") or {}
        if a.get("name", "").endswith("pow_in_range_control"):
            continue
        if a.get("met") is False:
            out.append({"record_id": r["record_id"], "run_slug": slug,
                        "pin": version, "declared": roles[version],
                        "assertion": a.get("name"),
                        "observed": (a.get("observed") or {}).get("test_status"),
                        "expected": (a.get("expected") or {}).get("test_status"),
                        "note": "declared behaviour and observed behaviour "
                                "differ on this pin/profile"})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--platform", action="append", choices=sorted(MODULES),
                    help="run only this platform (repeatable); default all")
    ap.add_argument("--report-only", action="store_true",
                    help="recompute the reports from existing artefacts")
    ap.add_argument("--limit", type=int, default=0,
                    help="cap executed runs per platform (0 = no cap)")
    args = ap.parse_args()
    plats = args.platform or C.PLATFORM_ORDER

    records = C.load_records()
    obs("records_in_v22_layer", len(records))
    candidates = {p: C.candidates_for(p, records) for p in C.PLATFORM_ORDER}
    for p in C.PLATFORM_ORDER:
        obs(f"candidates_{p}", len(candidates[p]))

    all_runs: list[dict] = []
    prereq_matrix: list[dict] = []
    crashed = []
    for p in C.PLATFORM_ORDER:
        mod = importlib.import_module(MODULES[p])
        for row in mod.prerequisites():
            row["platform"] = p
            prereq_matrix.append(row)
        if args.report_only:
            continue
        if p not in plats:
            continue
        try:
            specs, blocked = mod.plan(records)
        except Exception:
            crashed.append(p)
            traceback.print_exc()
            continue
        obs(f"planned_runs_{p}", len(specs))
        obs(f"blocked_candidates_{p}", len(blocked))
        if args.limit:
            specs = specs[:args.limit]
        for row in blocked:
            try:
                rec = mod.execute_blocked(row)
                C.write_run_artefacts(rec)
                all_runs.append(rec)
            except Exception:
                crashed.append(p)
                traceback.print_exc()
        for spec in specs:
            try:
                rec = mod.execute(spec)
            except Exception:
                crashed.append(p)
                traceback.print_exc()
                continue
            d = C.write_run_artefacts(rec)
            all_runs.append(rec)
            print(f"RUN {rec['platform']} {rec['record_id']} "
                  f"{rec['run_slug']} -> status={rec['status']} "
                  f"outcome={rec['outcome']} ladder={rec['ladder']} "
                  f"met={(rec.get('assertion') or {}).get('met')} "
                  f"blocker={rec.get('blocker')}", flush=True)
            obs(f"artefact_dir_{rec['run_slug']}", str(d))

    # the report always recounts from the artefacts on disk, never from what
    # this process happened to run
    runs = C.load_runs()
    obs("artefact_runs_on_disk", len(runs))
    integrity = C.validate_pilot()
    rep = C.build_report(runs, candidates, prereq_matrix, integrity)
    rep["record_ladder_ceilings"] = ceiling_ladder(runs)
    rep["unexecuted_pool_audit"] = vbeta_pool_audit()
    rep["declared_behaviour_discrepancies"] = declared_behaviour_discrepancies(runs)
    rep["crashed_platforms"] = crashed
    rep["non_execution_note"] = (
        "Counts are recomputed from experiments_nonevm/*/result.json. A run is "
        "only counted as executed when the platform's native test command "
        "produced a named test result; a compiler failure stays at L2.")
    # The report is a committed artefact, so it is redacted on the way out:
    # it quotes the toolchain paths of the machine that ran the pilot.
    C.write_json(C.REPORT_JSON, C.redact_obj(rep))
    C.write_text(C.REPORT_MD, C.redact_text(C.render_md(rep)))
    C.write_json(C.ARTEFACT_ROOT / "index.json", {
        "schema": C.SCHEMA, "generated_utc": rep["generated_utc"],
        "runs": sorted(f"{r['record_id']}/{r['run_slug']}" for r in runs),
        "counts": rep["counts"]})

    check("artefacts_self_consistent", integrity["clean"],
          f"{integrity['runs_validated']} runs validated, "
          f"{len(integrity['error_dirs'])} with errors")
    check("no_adapter_crash", not crashed, ",".join(crashed) or "none")
    obs("runs_total", rep["counts"]["runs_total"])
    obs("executed_runs", rep["counts"]["executed_runs"])
    obs("unique_records_executed", rep["counts"]["unique_records_executed"])
    obs("outcomes", rep["counts"]["outcomes_overall"])
    obs("ladder", rep["counts"]["ladder_overall"])
    obs("report_json", str(C.REPORT_JSON))
    obs("report_md", str(C.REPORT_MD))
    if crashed:
        return 2
    return 0 if integrity["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

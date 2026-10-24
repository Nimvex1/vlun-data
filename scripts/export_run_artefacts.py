#!/usr/bin/env python3
"""Export the executed-PoC run records out of git-ignored `work/` and into `experiments/`.

Why this exists
---------------
`work/` is git-ignored because it holds retrieved source from repositories that
declare no licence. But the *verdicts* produced by running those PoCs are the
dataset's headline experimental claim ("5 of 155 PoCs demonstrate the claimed
impact"), and until now they existed only inside `work/poc_runs/`, so no third
party could check them. This script commits the run record - repository, audited
commit, exact command, forge status, test name, gas, decoded failure reason - and
nothing else.

What is deliberately NOT committed
----------------------------------
The PoC bodies themselves are not committed. `verify_pocs.py` restores the audited
test tree after each run (`test_tree_restored`), so the materialised bodies are not
recoverable, and for `repo_native_test` rows the body would be unlicensed upstream
source in any case. Each artefact therefore points at where the body lived
(path + commit) instead of redistributing it. `body_committed: false` is stated
explicitly in every result.json so no consumer mistakes this for a complete,
independently re-runnable PoC.

    python scripts/export_run_artefacts.py
    python scripts/export_run_artefacts.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact_machine_paths import redact_obj  # noqa: E402  (one redaction convention, repo-wide)
from vlun import EXPERIMENTS, REPORTS, WORK, log, write_json  # noqa: E402

EXECUTED = {"reproduced", "not_reproduced", "inconclusive"}

# How to read each verdict. Kept here, next to the artefacts, so a consumer does
# not have to infer the semantics.
POLARITY = {
    "reproduced": (
        "The materialised PoC asserts the FINDING's claimed outcome. forge reported "
        "Success, so the claimed outcome was observed at the audited commit."
    ),
    "not_reproduced": (
        "The materialised PoC asserts the FINDING's claimed outcome. forge reported "
        "Failure, so the claimed outcome was NOT observed at the audited commit."
    ),
    "inconclusive": (
        "The PoC could not be brought to a verdict in this environment. The run "
        "failure reason records the specific cause; no claim is made either way."
    ),
}

# How the PoC body came to exist. A repo_native_test is the audit author's own
# test run unmodified - it is evidence that the report's claim reproduces, but it
# is NOT an exploit this dataset constructed.
POC_TYPE_NOTE = {
    "report_quoted_poc": (
        "PoC body reconstructed from the code quoted in the public Code4rena report "
        "and written into the audited repository's test tree for the run."
    ),
    "repo_native_test": (
        "The audit author's own test, run unmodified from the audited repository. "
        "This reproduces the reporter's claim; it is not an exploit constructed by "
        "this dataset."
    ),
    "not_a_runnable_test": "The report quotes prose or a snippet, not a runnable test.",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--poc-runs", default=str(WORK / "poc_runs"))
    ap.add_argument("--out", default=str(EXPERIMENTS))
    ap.add_argument("--index", default=str(REPORTS / "run_artefacts_index.json"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src = Path(args.poc_runs)
    if not src.exists():
        log(f"no {src}; run scripts/verify_pocs.py first")
        return 0

    out_root = Path(args.out)
    index: dict[str, dict] = {}
    written = 0

    for f in sorted(src.glob("*.json")):
        if f.name == "_all.json":
            continue
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        repo = doc.get("repo") or f.stem.replace("__", "/")
        head = doc.get("head_commit")
        for v in doc.get("verdicts", []):
            verdict = v.get("verdict")
            if verdict not in EXECUTED:
                continue
            fid = v.get("finding_id")
            if not fid:
                continue
            slug = fid.replace("/", "__")
            d = out_root / f"{slug}__poc_run"
            ev = v.get("evidence") or {}
            native = v.get("poc_native_location") or None
            result = {
                "finding_id": fid,
                "verdict": verdict,
                "verdict_meaning": POLARITY.get(verdict, ""),
                "poc_type": v.get("poc_type"),
                "poc_type_note": POC_TYPE_NOTE.get(v.get("poc_type"), ""),
                "finding_severity": v.get("finding_severity"),
                "repository": repo,
                "audited_commit": head,
                "forge_status": ev.get("forge_status"),
                "test_name": ev.get("test_name"),
                "gas_used": ev.get("gas_used"),
                "observed_reason": ev.get("reason") or None,
                "observed_impact_assertion": v.get("poc_observed_impact") or None,
                "claimed_impact_assertion": v.get("poc_claimed_impact") or None,
                "poc_placement": v.get("poc_placement"),
                "poc_materialised_file": v.get("poc_materialised_file"),
                "poc_native_location": native,
                "failure_reason": v.get("failure_reason"),
                "body_committed": False,
                "body_note": (
                    "The PoC body is not redistributed. verify_pocs.py restores the "
                    "audited test tree after each run, so the materialised body is not "
                    "recoverable; for repo_native_test rows it is unlicensed upstream "
                    "source. Reconstruct it from poc_materialised_file / "
                    "poc_native_location at audited_commit, or from the code quoted in "
                    "the public report."
                ),
                "has_fixed_revision_leg": False,
                "fixed_revision_note": (
                    "This is a single-revision run at the audited commit. It is NOT one "
                    "of the pinpoint vulnerable-vs-fixed experiments in "
                    "experiments/<finding>__*/{vulnerable,fixed}/ and does not "
                    "establish that a patch was effective."
                ),
                "evidence_semantics": "experimentally_verified",
                "generated_by": "scripts/export_run_artefacts.py",
            }
            index[fid] = {
                "verdict": verdict,
                "artefact": f"experiments/{d.name}/result.json",
                "repository": repo,
                "poc_type": v.get("poc_type"),
                "body_committed": False,
            }
            if args.dry_run:
                log(f"  would write {d / 'result.json'}  ({verdict})")
                written += 1
                continue
            d.mkdir(parents=True, exist_ok=True)
            # The exported record copies free text out of the machine-local
            # run log (a forge reason, a materialised file's location). It is
            # redacted on the way in, so a committed artefact never carries
            # the operator's home directory.
            write_json(d / "result.json", redact_obj(result))
            (d / "PROVENANCE.md").write_text(
                redact_obj(
                    f"# {fid} — single-revision PoC run\n\n"
                    f"- verdict: `{verdict}` — {POLARITY.get(verdict, '')}\n"
                    f"- forge status: `{ev.get('forge_status')}`\n"
                    f"- test: `{ev.get('test_name')}`\n"
                    f"- repository: `{repo}` at commit `{head}`\n"
                    f"- PoC type: `{v.get('poc_type')}` — "
                    f"{POC_TYPE_NOTE.get(v.get('poc_type'), '')}\n"
                    f"- body committed: **no** — {result['body_note']}\n"
                    f"- fixed-revision leg: **no** — {result['fixed_revision_note']}\n\n"
                    f"Full record: [`result.json`](result.json)\n"),
                encoding="utf-8", newline="\n")
            written += 1

    summary = {
        "generated_by": "scripts/export_run_artefacts.py",
        "source": "work/poc_runs/*.json (git-ignored); this index is the committed copy",
        "artefacts_written": written,
        "bodies_committed": 0,
        "records": index,
    }
    if not args.dry_run:
        write_json(Path(args.index), summary)
        log(f"wrote {args.index} ({len(index)} executed findings)")
    log(f"run artefacts written: {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
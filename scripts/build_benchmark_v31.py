#!/usr/bin/env python3
"""V3.1 benchmark family T: explicit-confidence taxonomy classification.

Source: derived_v3/normalized_records_preview.jsonl child rows whose
normalized class carries EXPLICIT confidence (auditor Category field naming
a VLUN class). Rows whose title+target already name the class are EXCLUDED
(answer leakage); the residual filename-leak risk is documented, not hidden.

Task: given {title, target component, severity}, predict the normalized
vulnerability class. Answer keys rebuild mechanically from the preview.

    python scripts/build_benchmark_v31.py
    python scripts/build_benchmark_v31.py --check

Writes benchmark/v3_T_taxonomy_explicit.jsonl and extends
benchmark/v3_manifest.json (deterministic read-modify-write).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_v3 as V  # noqa: E402
from build_v3 import SPLIT_OF  # noqa: E402
from vlun import RETIRED_FAMILIES  # noqa: E402

U = V.UNKNOWN


def _class_tokens(cls: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[A-Za-z]{4,}", cls)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="compute, write nothing")
    args = ap.parse_args()

    preview = V.read_jsonl(V.DERIVED_V3 / "normalized_records_preview.jsonl")
    tasks = []
    skipped_leak = 0
    for r in preview:
        if r.get("record_type") != "record_v31":
            continue
        if r.get("taxonomy_confidence") != "explicit":
            continue
        classes = r.get("normalized_vulnerability_classes") or []
        if len(classes) != 1 or classes[0] in (U, "Unknown"):
            continue
        cls = classes[0]
        leaked = _class_tokens(cls) & set(
            re.findall(r"[A-Za-z]{4,}",
                       f"{r.get('title', '')} {r.get('affected_contract', '')}"))
        target = r.get("affected_file", U)
        if target not in (U, None):
            leaked |= _class_tokens(cls) & set(
                re.findall(r"[A-Za-z]{4,}", str(target)))
        if leaked:
            skipped_leak += 1
            continue
        split = SPLIT_OF.get(r.get("source_id", ""), U)
        tasks.append({
            "task_id": f"T_v31_taxonomy::{r['finding_id']}",
            "family": "T_v31_taxonomy_explicit",
            "input": {"title": r.get("title", U),
                      "target": target,
                      "severity": r.get("severity", U)},
            "answer": {"vulnerability_class": cls},
            "answer_key_status": "labeled",
            "answer_basis": "explicit auditor Category field "
                            "(see preview taxonomy_method)",
            "source": {"record_id": r["finding_id"],
                       "source_id": r.get("source_id", U)},
            "split": split,
        })
    tasks.sort(key=lambda t: t["task_id"])
    V.log(f"build_benchmark_v31.py: {len(tasks)} tasks "
          f"({skipped_leak} title-leakers excluded)")
    if args.check:
        return 0
    if "v3_T_taxonomy_explicit.jsonl" in RETIRED_FAMILIES:
        # T stays frozen under benchmark/retired_families/; the manifest
        # keeps its count and families entry (carried, not recomputed).
        V.log("build_benchmark_v31.py: T_v31_taxonomy_explicit retired, "
              "rows not rebuilt")
    else:
        V.write_jsonl(V.BENCH / "v3_T_taxonomy_explicit.jsonl", tasks)
    man_path = V.BENCH / "v3_manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    if "T_v31_taxonomy_explicit" not in man["families"]:
        man["families"].append("T_v31_taxonomy_explicit")
    if "v3_T_taxonomy_explicit.jsonl" not in RETIRED_FAMILIES:
        man["tasks"]["T_v31_taxonomy_explicit"] = len(tasks)
    elif "T_v31_taxonomy_explicit" not in man.get("tasks", {}):
        # A retired family is carried, not rebuilt, but its row count still
        # has to be carried into the manifest: the gate checks the frozen file
        # against this count and a missing key is a failure, not a skip.
        frozen = V.BENCH / "retired_families" / "v3_T_taxonomy_explicit.jsonl"
        man["tasks"]["T_v31_taxonomy_explicit"] = sum(
            1 for line in frozen.read_text(encoding="utf-8").splitlines()
            if line.strip())
    # Idempotent provenance: strip any previously appended suffixes before
    # re-adding once, so reruns never duplicate text.
    gen = man.get("generated_by", "")
    gen = gen.replace(" + scripts/build_benchmark_v31.py", "")
    man["generated_by"] = gen + " + scripts/build_benchmark_v31.py"
    base_notes = man.get("notes", "")
    base_notes = base_notes.split(" Family T admits only")[0]
    man["notes"] = base_notes + (
        " Family T admits only explicit-confidence taxonomy rows whose "
        "title+target do not already name the answer class "
        f"({skipped_leak} leakers excluded this run).")
    V.write_json(man_path, man)
    return 0


if __name__ == "__main__":
    sys.exit(main())

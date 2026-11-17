#!/usr/bin/env python3
"""Generate schema/*.schema.json FROM scripts/schema_terms.py.

The vocabulary stays single-sourced: every enum in every schema file is
copied from schema_terms.py at generation time, so a vocabulary change
without regeneration fails the agreement check in check_manifests.py.
Structure (required fields) is declared here per layer — that is the spec
author's job, not the data's.

    python scripts/build_schemas.py
    python scripts/build_schemas.py --check   # exit 1 if schemas are stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import schema_terms as T  # noqa: E402

SCHEMA_DIR = ROOT / "schema"
DRAFT = "https://json-schema.org/draft/2020-12/schema"


def finding_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": "vlun-findings-1.0",
        "title": "VLUN v1 finding row (jsonl/)",
        "type": "object",
        "required": ["record_type", "source", "protocol", "finding",
                     "provenance"],
        "properties": {
            "record_type": {"type": "string"},
            "dataset_version": {"type": "string"},
            "source": {"type": "object"},
            "protocol": {"type": ["object", "string"]},
            "finding": {
                "type": "object",
                "required": ["id", "severity"],
                "properties": {
                    "id": {"type": "string"},
                    "severity": {"type": "string"},
                },
            },
            "provenance": {"type": "object"},
        },
    }


def derived_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": "vlun-derived-2.2",
        "title": "VLUN derived record (derived/, derived_v2_2/)",
        "type": "object",
        "required": ["id", "finding", "dataset_version"],
        "properties": {
            "id": {"type": "string"},
            "finding": {"type": "object"},
            "verification_level": {"enum": list(T.VERIFICATION_LEVELS)},
            "experiment": {"type": ["object", "null"]},
            "violation_evidence": {
                "type": ["object", "null"],
                "required": ["impact_type", "actor", "property", "expected",
                             "observed", "source", "execution"],
                "properties": {
                    "impact_type": {"enum": list(T.VIOLATION_IMPACTS)},
                    "actor": {"type": "string"},
                    "property": {"type": "string"},
                    "expected": {"type": "string"},
                    "observed": {"type": "string"},
                    "source": {"type": "string"},
                    "execution": {"type": "object"},
                },
            },
            "taxonomy": {"type": ["object", "string", "null"]},
        },
    }


def benchmark_task_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": "vlun-benchmark-task-1.0",
        "title": "VLUN benchmark task (any family)",
        "type": "object",
        "required": ["input"],
        "properties": {
            "id": {"type": "string"},
            "task_id": {"type": "string"},
            "task": {"type": "string"},
            "input": {"type": "object"},
            "split": {"enum": list(T.SPLITS) + ["quarantine", "unknown"]},
            "answer_key_status": {"enum": ["labeled", "partial",
                                           "unlabeled", "unscorable"]},
            "source": {"type": "object"},
        },
        "anyOf": [{"required": ["id"]}, {"required": ["task_id"]}],
    }


def experiment_result_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": "vlun-experiment-result-1.0",
        "title": "VLUN experiment result (experiments/*/result.json)",
        "type": "object",
        "required": ["experiment_id", "finding_id", "command"],
        "properties": {
            "experiment_id": {"type": "string"},
            "finding_id": {"type": "string"},
            "command": {"type": "string"},
            "declared_expected_status": {
                "type": "string",
                "enum": ["pass", "fail"],
            },
        },
    }


def evidence_vocabulary() -> dict:
    # The closed vocabularies, verbatim from schema_terms (single source).
    return {
        "$schema": DRAFT,
        "$id": "vlun-evidence-vocabulary-1.0",
        "title": "VLUN closed vocabularies (mirrors scripts/schema_terms.py)",
        "evidence_types": list(T.EVIDENCE_TYPES),
        "verification_levels": list(T.VERIFICATION_LEVELS),
        "admission_decisions": list(T.DECISIONS),
        "admitted_decisions": list(T.ADMITTED_DECISIONS),
        "negative_classes": list(T.NEGATIVE_CLASSES),
        "splits": list(T.SPLITS),
        "layers": list(T.LAYERS),
        "patch_fields": list(T.PATCH_FIELDS),
        "count_domains": list(T.COUNT_DOMAINS),
        "violation_impacts": list(T.VIOLATION_IMPACTS),
    }


SCHEMAS = {
    "findings.schema.json": finding_schema,
    "derived.schema.json": derived_schema,
    "benchmark-task.schema.json": benchmark_task_schema,
    "experiment-result.schema.json": experiment_result_schema,
    "evidence-vocabulary.json": evidence_vocabulary,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    built = {name: fn() for name, fn in SCHEMAS.items()}
    if args.check:
        stale = []
        for name, obj in built.items():
            p = SCHEMA_DIR / name
            want = json.dumps(obj, indent=2, sort_keys=True) + "\n"
            if (not p.is_file()
                    or p.read_text(encoding="utf-8") != want):
                stale.append(f"schema/{name}")
        if stale:
            print(f"STALE {', '.join(stale)} — run: python scripts/build_schemas.py")
            return 1
        print("schema/ is current")
        return 0
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    for name, obj in built.items():
        (SCHEMA_DIR / name).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(built)} schemas to schema/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

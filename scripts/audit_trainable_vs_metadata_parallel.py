#!/usr/bin/env python3
"""Parallel equivalent of scripts/audit_trainable_vs_metadata.py.

This script produces the SAME audit outputs as the single-threaded script by
reusing that script's detection functions verbatim (imported as ``audit``).
Only the per-file scan is parallelised with a ProcessPoolExecutor; aggregation,
rendering and output formatting mirror the original main() exactly.

No dataset file (.jsonl or dataset .json) is ever modified.

Python standard library only.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import sys
from pathlib import Path

# Make the sibling audit module importable in both the parent and the
# Windows "spawn" child processes used by ProcessPoolExecutor.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import audit_trainable_vs_metadata as audit  # noqa: E402

# Sample raw lines are truncated for IPC; the hydration plan prints only
# raw[:1800], so this is byte-equivalent for every rendered sample.
_SAMPLE_RAW_LIMIT = 4000


def _process_one(args):
    """Process exactly one JSONL file; see audit_trainable_vs_metadata.main().

    Args is ``(rel_path, abs_path, local_clone_names_list)``.  The body below
    reproduces lines 631-719 of the original main() verbatim in behaviour.
    """
    rel_path, abs_path, local_clone_names_list = args
    local_clone_names = set(local_clone_names_list)
    path = Path(abs_path)
    layer = audit.assign_layer(rel_path)
    buckets = {name: 0 for name in audit.BUCKET_NAMES}
    coverage_counts = {
        "pct_code": 0, "pct_diff": 0, "pct_poc": 0,
        "pct_prose": 0, "pct_spec": 0, "pct_metadata_flagged": 0,
    }
    file_hydration = {name: 0 for name in audit.HYDRATION_NAMES}
    global_hydration_local = {name: 0 for name in audit.HYDRATION_NAMES}
    invalid = 0
    valid_rows = 0
    sample = None
    sample_preference = 99

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except (ValueError, TypeError):
                invalid += 1
                continue
            if not isinstance(row, dict):
                invalid += 1
                continue

            info = audit.analyze_row(row, local_clone_names)
            valid_rows += 1
            b = info["bucket"]
            buckets[b] += 1
            flags = info["flags"]
            if flags["code"]:
                coverage_counts["pct_code"] += 1
            if flags["diff"]:
                coverage_counts["pct_diff"] += 1
            if flags["poc"]:
                coverage_counts["pct_poc"] += 1
            if flags["prose"]:
                coverage_counts["pct_prose"] += 1
            if flags["spec"]:
                coverage_counts["pct_spec"] += 1
            if info["flagged"]:
                coverage_counts["pct_metadata_flagged"] += 1

            global_hydration_local[info["hydration"]] += 1
            if b in ("METADATA_ONLY_STUB", "PARTIAL_TEXT_NO_CODE"):
                file_hydration[info["hydration"]] += 1
                pref = 0 if b == "METADATA_ONLY_STUB" else 1
                if pref < sample_preference:
                    sample_preference = pref
                    sample = {
                        "raw": line[:_SAMPLE_RAW_LIMIT],
                        "flags": flags,
                        "flagged": info["flagged"],
                        "hydration": info["hydration"],
                        "pointers": info["pointers"],
                    }

    has_stubs = buckets["METADATA_ONLY_STUB"] > 0 or buckets["PARTIAL_TEXT_NO_CODE"] > 0
    display = audit.hydration_display(file_hydration) if has_stubs else "NONE"
    dominant = "NONE"
    if has_stubs:
        dominant_counts = sorted(
            [(k, n) for k, n in file_hydration.items() if n > 0],
            key=lambda item: (-item[1], audit.HYDRATION_PRIORITY[item[0]]),
        )
        dominant = dominant_counts[0][0]

    coverage_pct = {key: audit.pct(value, valid_rows) for key, value in coverage_counts.items()}
    file_row = {
        "path": rel_path,
        "layer": layer,
        "table_role": audit.classify_table_role(rel_path),
        "total_rows": valid_rows,
        "invalid_lines": invalid,
        "buckets": buckets,
        "coverage_pct": coverage_pct,
        "hydration_source": {
            "counts": file_hydration,
            "dominant": dominant,
            "display": display,
        },
        "has_stubs": has_stubs,
    }
    return (
        file_row, sample, valid_rows, invalid, buckets,
        coverage_counts, file_hydration, global_hydration_local,
    )


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    json_path = reports / "metadata_vs_trainable_audit.json"
    plan_path = reports / "metadata_stub_hydration_plan.md"
    md_path = reports / "metadata_vs_trainable_audit.md"

    files, excluded, excluded_count = audit.discover_jsonl(root)

    # Names of local clone directories that exist under work/sources/ and V3/clones/.
    local_clone_names = set()
    for base in (root / "work" / "sources", root / "V3" / "clones"):
        try:
            for child in base.iterdir():
                if child.is_dir():
                    local_clone_names.add(child.name.lower())
        except OSError:
            pass

    clone_list = sorted(local_clone_names)
    tasks = [
        (path.relative_to(root).as_posix(), str(path), clone_list)
        for path in files
    ]

    # Windows note: ProcessPoolExecutor uses spawn.  _process_one and its
    # imports are module-level and picklable; passing a sorted list for the
    # clone names and rebuilding a set in the worker avoids set-pickle issues.
    # main() is only invoked under __main__ below, so spawned children never
    # create their own pool.
    with concurrent.futures.ProcessPoolExecutor(max_workers=14) as executor:
        # executor.map preserves the sorted discover_jsonl() order.
        results = list(executor.map(_process_one, tasks))

    file_rows = []
    stub_rows_by_file = {}
    total_rows = 0
    total_invalid = 0
    global_buckets = {name: 0 for name in audit.BUCKET_NAMES}
    global_hydration = {name: 0 for name in audit.HYDRATION_NAMES}
    stub_files = []
    by_layer = {}

    # Aggregate in the same order as the original sequential main() loop.
    for (file_row, sample, valid_rows, invalid, buckets,
         coverage_counts, _file_hydration, global_hydration_local) in results:
        file_rows.append(file_row)
        rel = file_row["path"]
        if sample is not None:
            stub_rows_by_file[rel] = sample
        has_stubs = file_row["has_stubs"]
        if has_stubs:
            stub_files.append(rel)

        total_rows += valid_rows
        total_invalid += invalid
        for name in audit.BUCKET_NAMES:
            global_buckets[name] += buckets[name]
        for name in audit.HYDRATION_NAMES:
            global_hydration[name] += global_hydration_local[name]

        layer = file_row["layer"]
        layer_stat = by_layer.setdefault(layer, {
            "files": 0, "rows": 0,
            "buckets": {name: 0 for name in audit.BUCKET_NAMES},
            "coverage_pct_avg": {key: 0.0 for key in coverage_counts},
            "_cov_sum": {key: 0.0 for key in coverage_counts},
            "stub_files": [],
        })
        layer_stat["files"] += 1
        layer_stat["rows"] += valid_rows
        for name in audit.BUCKET_NAMES:
            layer_stat["buckets"][name] += buckets[name]
        for key in coverage_counts:
            layer_stat["_cov_sum"][key] += file_row["coverage_pct"][key]
        if has_stubs:
            layer_stat["stub_files"].append(rel)

    for layer_stat in by_layer.values():
        n = layer_stat["files"] or 1
        for key in layer_stat["coverage_pct_avg"]:
            layer_stat["coverage_pct_avg"][key] = round(layer_stat["_cov_sum"][key] / n, 1)
        del layer_stat["_cov_sum"]

    json_data = {
        "schema_version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        # Phase 4 fix: keep the generated report machine-independent (the
        # no-machine-paths gate must stay at zero leaks). The field is purely
        # informational; "." is portable and needs no verifier change.
        "repo_root": ".",
        "scan": {
            "excluded_dirs": excluded,
            "excluded_jsonl_files": excluded_count,
            "total_jsonl_files": len(file_rows),
            "total_rows": total_rows,
            "invalid_lines": total_invalid,
        },
        "definitions": {
            "buckets": {
                "METADATA_ONLY_STUB": "Explicit METADATA_ONLY/POINTER_ONLY flag, or no inline code, diff, PoC, prose >=100 chars and no formal spec.",
                "FULLY_TRAINABLE": "Inline code >=50 chars AND inline technical prose >=100 chars, with no explicit metadata flag.",
                "PARTIAL_TEXT_NO_CODE": "Has inline prose >=100 chars, PoC or formal spec text, but no inline target source code or unified diff.",
                "invalid": "Non-dict or unparseable JSON lines; counted separately and never bucketed.",
            },
            "hydration": {
                "HYDRATABLE_FROM_LOCAL_WORK": "A work/sources/ or local clone-dir path pointer exists (priority 1).",
                "HYDRATABLE_FROM_GIT_OR_GITHUB": "A GitHub URL/repo/commit/PR/issue, GHSA, CVE or 40-hex SHA pointer exists (priority 2).",
                "UNHYDRATABLE_DEAD_POINTER": "Only PDF/advisory/placeholder pointers or no pointer at all.",
                "file_summary_scope": "Per-file counts cover stub+partial rows only; the global summary covers all bucketed rows.",
            },
            "thresholds": {
                "inline_code_min_chars": 50,
                "inline_diff_min_chars": 50,
                "inline_poc_min_chars": 50,
                "inline_prose_min_chars": 100,
                "inline_formal_spec_min_chars": 50,
                "prose_min_letter_space_ratio": 0.5,
                "prose_min_alpha_words": 12,
                "known_code_container_min_code_markers": 1,
                "unknown_key_min_code_markers": 2,
            },
            "notes": [
                "Detection walks every string value recursively; known field paths are additionally recognised.",
                "code_reference_only pointer objects have no snippet and are never counted as inline code.",
                "invariants[].invariant natural-language text is only counted as a formal spec when CVL markers are present.",
                "METADATA_ONLY/POINTER_ONLY must be an exact value (or in a known flag field); the words inside input_text are not flags.",
            ],
            "table_roles": {
                "trainable_or_benchmark": "Dataset, derived task table, split or benchmark task. Must have 0 METADATA_ONLY_STUB rows (enforced by verify_audit.py).",
                "governance_or_quarantine_ledger": "Provenance, rights, quarantine, dedup, audit or normalization bookkeeping. Stub rows retained for audit trail and dedup accounting.",
                "test_fixture": "Synthetic files under tests/fixtures/**, never training data.",
            },
        },
        "summary": {
            "files": len(file_rows),
            "rows": total_rows,
            "buckets": global_buckets,
            "hydration": global_hydration,
            "invalid_lines": total_invalid,
            "table_roles": {
                role: {
                    "files": sum(1 for f in file_rows if f.get("table_role") == role),
                    "METADATA_ONLY_STUB": sum(
                        f["buckets"]["METADATA_ONLY_STUB"] for f in file_rows
                        if f.get("table_role") == role),
                }
                for role in audit.TABLE_ROLES
            },
        },
        "by_layer": dict(sorted(by_layer.items())),
        "files": file_rows,
        "stub_files": stub_files,
    }

    with json_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(json_data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    table = audit.markdown_table(file_rows)
    with md_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Trainable vs metadata audit - console table\n\n")
        handle.write("Generated by `scripts/audit_trainable_vs_metadata.py`.\n\n")
        handle.write(table + "\n")

    with plan_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(audit.build_hydration_plan(json_data, stub_rows_by_file, root) + "\n")

    print(table)
    print()
    print(f"Scanned {len(file_rows)} jsonl files ({excluded_count} excluded under "
          f"{', '.join(excluded)}); {total_rows} rows; {total_invalid} invalid lines; "
          f"{len(stub_files)} files contain stub/partial rows.")
    print("Buckets: " + ", ".join(f"{k}={global_buckets[k]}" for k in audit.BUCKET_NAMES))
    return 0


if __name__ == "__main__":
    sys.exit(main())

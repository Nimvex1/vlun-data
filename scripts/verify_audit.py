#!/usr/bin/env python3
"""Independent verification of the metadata-vs-trainable audit.

This script is deliberately schema-driven: it reads ``reports/metadata_vs_trainable_audit.json``
and validates internal consistency plus re-derivation of facts directly from the repository.
It does NOT hardcode the expected counts as assertions -- those appear only as informational
"expected vs actual" notes at the end of the report.

It only reads dataset files.  The single file it writes is
``reports/audit_verification.txt`` (the full PASS/FAIL log).

Run:  python scripts/verify_audit.py
Exit: 0 if every check passes, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_JSON = REPO_ROOT / "reports" / "metadata_vs_trainable_audit.json"
HYDRATION_PLAN = REPO_ROOT / "reports" / "metadata_stub_hydration_plan.md"
LOG_PATH = REPO_ROOT / "reports" / "audit_verification.txt"


def _display_path(path: Path) -> str:
    """Repo-relative POSIX path for logs (never a machine-specific path)."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name

# Mirror the scanner's exclusion set (any *directory component* equal to these).
EXCLUDED_DIRS = frozenset({"work", ".git"})

BUCKET_KEYS = frozenset(
    {"FULLY_TRAINABLE", "PARTIAL_TEXT_NO_CODE", "METADATA_ONLY_STUB"}
)
DOMINANT_VALUES = frozenset(
    {
        "HYDRATABLE_FROM_LOCAL_WORK",
        "HYDRATABLE_FROM_GIT_OR_GITHUB",
        "UNHYDRATABLE_DEAD_POINTER",
        "NONE",
    }
)

# Keys that may document the number of invalid/unparseable lines in a file entry.
INVALID_LINE_KEYS = (
    "invalid_lines",
    "invalid_json_lines",
    "invalid_line_count",
    "malformed_lines",
    "bad_lines",
    "parse_errors",
    "invalid_records",
)

# Field aliases used to locate per-file metadata (the audit schema may vary slightly).
LAYER_KEYS = ("layer", "layer_name", "source_layer", "group", "category")
STUB_KEYS = ("has_stubs", "has_stub", "stub", "is_stub")

SPOT_CHECK_COUNT = 5
SPOT_CHECK_SEED = 20261120  # fixed seed -> reproducible spot-check selection

# Informational only -- NOT asserted.  Key = canonical layer label, values = aliases,
# expected file count and expected row count from repository exploration.
EXPECTED_LAYERS = (
    ("v1", ("v1", "V1", "v1.0"), 9, 1877),
    ("v2.2", ("v2.2", "v2_2", "V2.2", "2.2"), 10, 249),
    ("V3", ("V3", "v3", "v3.0"), 2, 7730),
    ("Vbeta", ("Vbeta", "vbeta", "V_BETA", "beta"), 11, 34370),
    ("wave1", ("wave1", "WAVE1", "wave-1"), 25, 39950),
    ("benchmark", ("benchmark", "benchmark_singular"), 34, 24078),
    ("datasets(excl negatives)", ("datasets", "datasets_excl_negatives"), 3, 314),
    ("taxonomy", ("taxonomy",), 2, 449),
    ("derived_prove", ("derived_prove", "derived-prove"), 1, 210),
)


# ---------------------------------------------------------------------------
# Result collector
# ---------------------------------------------------------------------------


class Results:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, str]] = []  # (status, check, message)
        self.discrepancies: list[str] = []

    def _add(self, status: str, check: str, message: str = "") -> None:
        self.records.append((status, check, message))

    def passed(self, check: str, message: str = "") -> None:
        self._add("PASS", check, message)

    def failed(self, check: str, message: str = "") -> None:
        self._add("FAIL", check, message)
        self.discrepancies.append(f"{check}: {message}" if message else check)

    def info(self, check: str, message: str = "") -> None:
        self._add("INFO", check, message)

    @property
    def checks_run(self) -> int:
        return sum(1 for s, _, _ in self.records if s in ("PASS", "FAIL"))

    @property
    def passed_count(self) -> int:
        return sum(1 for s, _, _ in self.records if s == "PASS")

    @property
    def failed_count(self) -> int:
        return sum(1 for s, _, _ in self.records if s == "FAIL")

    def write_log(self) -> None:
        # Phase 4 fix: the separator used to be written as a bare `"=" * 78`
        # after adjacent string literals. Implicit literal concatenation binds
        # before `*`, so the WHOLE header block was repeated 78 times and the
        # separator collapsed to a single "=". Parenthesise the repetition.
        # Paths are rendered repo-relative so the generated log carries no
        # machine-specific path (no-machine-paths gate stays at zero leaks).
        header = (
            "INDEPENDENT AUDIT VERIFICATION LOG\n"
            f"Repository : <repo>\n"
            f"Audit JSON : {_display_path(AUDIT_JSON)}\n"
            f"Hydration  : {_display_path(HYDRATION_PLAN)}\n"
        ) + "=" * 78
        lines = [header]
        for status, check, message in self.records:
            line = f"[{status}] {check}"
            if message:
                line += f" -- {message}"
            lines.append(line)
        lines.append("=" * 78)
        lines.append(
            f"SUMMARY: checks run={self.checks_run}  passed={self.passed_count}  "
            f"failed={self.failed_count}"
        )
        if self.discrepancies:
            lines.append("DISCREPANCIES:")
            for d in self.discrepancies:
                lines.append(f"  - {d}")
        else:
            lines.append("DISCREPANCIES: none")
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def norm_path(value: object) -> str:
    """Normalise a path to forward slashes with no leading './'."""
    text = str(value).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def iter_kv(obj: object):
    """Yield every (key, value) pair anywhere in a nested dict/list structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from iter_kv(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_kv(v)


def iter_dicts(obj: object):
    """Yield every dict anywhere in a nested dict/list structure."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from iter_dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_dicts(v)


def is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def read_nonempty_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return [line for line in text.splitlines() if line.strip()]


def first_present(entry: dict, keys: tuple[str, ...], default=None):
    for key in keys:
        if key in entry:
            return entry[key]
    return default


def documented_invalid_lines(entry: dict) -> tuple[int, str | None]:
    """Return (count, key-name) for documented invalid lines, or (0, None)."""
    for key in INVALID_LINE_KEYS:
        value = entry.get(key)
        if is_number(value) and int(value) >= 0:
            return int(value), key
    return 0, None


def discover_jsonl() -> list[str]:
    """Repo-wide rglob with the scanner's exclusions, as sorted relative paths."""
    found: list[str] = []
    for path in REPO_ROOT.rglob("*.jsonl"):
        rel = path.relative_to(REPO_ROOT)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        found.append(rel.as_posix())
    return sorted(found)


# ---------------------------------------------------------------------------
# Check 1 -- repo-wide path set
# ---------------------------------------------------------------------------


def check_path_set(res: Results, audit: dict, files: list[dict]) -> set[str]:
    discovered = set(discover_jsonl())
    audited: set[str] = set()
    for entry in files:
        if isinstance(entry, dict) and "path" in entry:
            audited.add(norm_path(entry["path"]))

    missing = sorted(discovered - audited)
    extra = sorted(audited - discovered)
    res.passed(
        "1. repo-wide jsonl path set",
        f"discovered={len(discovered)} audited={len(audited)}",
    )
    if missing:
        res.failed(
            "1a. paths missing from audit",
            f"{len(missing)} file(s): " + ", ".join(missing[:20]),
        )
    else:
        res.passed("1a. paths missing from audit", "none")
    if extra:
        res.failed(
            "1b. paths extra in audit",
            f"{len(extra)} file(s): " + ", ".join(extra[:20]),
        )
    else:
        res.passed("1b. paths extra in audit", "none")
    res.info(
        "1c. exclusions",
        "excluded any path with a directory component in "
        + ", ".join(sorted(EXCLUDED_DIRS)),
    )
    return discovered


# ---------------------------------------------------------------------------
# Check 2 -- exact row counts
# ---------------------------------------------------------------------------


def check_row_counts(res: Results, files: list[dict], path_to_entry: dict) -> None:
    for index, entry in enumerate(files):
        rel = norm_path(entry.get("path", f"<entry {index}>"))
        declared = entry.get("total_rows")
        invalid, invalid_key = documented_invalid_lines(entry)
        counted = len(read_nonempty_lines(REPO_ROOT / rel))
        if not is_number(declared):
            res.failed(f"2. row count [{rel}]", f"total_rows is not a number: {declared!r}")
            continue
        declared_int = int(declared)
        if counted == declared_int:
            msg = f"counted={counted} total_rows={declared_int}"
            if invalid:
                msg += f" (invalid_lines={invalid} via '{invalid_key}' tracked separately)"
            res.passed(f"2. row count [{rel}]", msg)
        elif invalid and counted - declared_int == invalid:
            res.passed(
                f"2. row count [{rel}]",
                f"counted={counted} total_rows={declared_int} invalid_lines={invalid} "
                f"(via '{invalid_key}'); difference fully explained by invalid lines",
            )
        elif invalid and abs(counted - declared_int) <= invalid:
            res.passed(
                f"2. row count [{rel}]",
                f"counted={counted} total_rows={declared_int} invalid_lines={invalid} "
                f"(via '{invalid_key}'); difference within documented tolerance",
            )
        else:
            res.failed(
                f"2. row count [{rel}]",
                f"counted(non-empty lines)={counted} but total_rows={declared_int} "
                f"(delta={counted - declared_int}; invalid_lines={invalid})",
            )


# ---------------------------------------------------------------------------
# Check 3 -- bucket keys and sums
# ---------------------------------------------------------------------------


def check_buckets(res: Results, files: list[dict]) -> None:
    for index, entry in enumerate(files):
        rel = norm_path(entry.get("path", f"<entry {index}>"))
        buckets = entry.get("buckets")
        if not isinstance(buckets, dict):
            res.failed(f"3. buckets [{rel}]", f"buckets is not an object: {type(buckets).__name__}")
            continue
        keys = set(buckets.keys())
        if keys != BUCKET_KEYS:
            res.failed(
                f"3a. bucket keys [{rel}]",
                f"expected exactly {sorted(BUCKET_KEYS)}, got {sorted(keys)}",
            )
            continue
        res.passed(f"3a. bucket keys [{rel}]", "exactly the 3 required keys")

        bad_values = {
            k: v
            for k, v in buckets.items()
            if not (is_number(v) and int(v) >= 0 and float(v).is_integer())
        }
        if bad_values:
            res.failed(f"3b. bucket values [{rel}]", f"non-integer/negative values: {bad_values}")
            continue
        res.passed(f"3b. bucket values [{rel}]", "all non-negative integers")

        total = entry.get("total_rows")
        invalid, invalid_key = documented_invalid_lines(entry)
        if not is_number(total):
            res.failed(f"3c. bucket sum [{rel}]", "total_rows is not a number")
            continue
        total_int = int(total)
        bucket_sum = sum(int(v) for v in buckets.values())
        formulas = [f"sum(buckets) == total_rows ({total_int})"]
        if bucket_sum == total_int:
            res.passed(
                f"3c. bucket sum [{rel}]",
                f"sum(buckets)={bucket_sum}; formula used: " + formulas[0],
            )
            continue
        if invalid:
            adjusted = total_int - invalid
            formulas.append(
                f"sum(buckets) == total_rows - invalid_lines "
                f"({total_int} - {invalid} = {adjusted}, via '{invalid_key}')"
            )
            if bucket_sum == adjusted:
                res.passed(
                    f"3c. bucket sum [{rel}]",
                    f"sum(buckets)={bucket_sum}; formula used: " + formulas[-1],
                )
                continue
        res.failed(
            f"3c. bucket sum [{rel}]",
            f"sum(buckets)={bucket_sum} matches neither formula: " + " | ".join(formulas),
        )


# ---------------------------------------------------------------------------
# Check 4 -- coverage_pct and pct_metadata_flagged
# ---------------------------------------------------------------------------


def check_percentages(res: Results, audit: dict) -> None:
    # coverage_pct is an OBJECT of sub-percentages (pct_code, pct_diff, pct_poc,
    # pct_prose, pct_spec, pct_metadata_flagged) -- not a single scalar.  Check 4b
    # separately validates pct_metadata_flagged; here we validate every numeric
    # sub-value of every coverage_pct object is a percentage in [0.0, 100.0].
    coverage_dicts = [
        v for k, v in iter_kv(audit)
        if k == "coverage_pct" and isinstance(v, dict)
    ]
    coverage_scalars = [
        v for k, v in iter_kv(audit)
        if k == "coverage_pct" and is_number(v)
    ]
    coverage_values = [
        (sub_key, sub_val)
        for cd in coverage_dicts
        for sub_key, sub_val in cd.items()
        if is_number(sub_val)
    ]
    coverage_values.extend(("coverage_pct", v) for v in coverage_scalars)
    if not coverage_values:
        res.failed("4a. coverage_pct present", "no coverage_pct values found in audit JSON")
    else:
        bad = [
            (k, v)
            for k, v in coverage_values
            if not (-1e-9 <= float(v) <= 100.0 + 1e-9)
        ]
        if bad:
            res.failed(
                "4a. coverage_pct range",
                f"{len(bad)} value(s) outside [0.0, 100.0]: {bad[:10]}",
            )
        else:
            res.passed(
                "4a. coverage_pct range",
                f"all {len(coverage_values)} numeric sub-percentage value(s) across "
                f"{len(coverage_dicts)} coverage_pct object(s) "
                f"(+{len(coverage_scalars)} scalar) are numbers in [0.0, 100.0]",
            )

    flagged = [(k, v) for k, v in iter_kv(audit) if k == "pct_metadata_flagged"]
    if not flagged:
        res.failed("4b. pct_metadata_flagged present", "no pct_metadata_flagged value found")
    else:
        bad = [(k, v) for k, v in flagged if not (is_number(v) and float(v) <= 100.0 + 1e-9)]
        if bad:
            res.failed("4b. pct_metadata_flagged <= 100", f"violations: {bad[:10]}")
        else:
            res.passed(
                "4b. pct_metadata_flagged <= 100",
                f"all {len(flagged)} value(s) <= 100: " + ", ".join(str(v) for _, v in flagged),
            )
        negatives = [(k, v) for k, v in flagged if is_number(v) and float(v) < 0]
        if negatives:
            res.info("4c. pct_metadata_flagged negatives", f"negative values: {negatives[:10]}")
        else:
            res.passed("4c. pct_metadata_flagged non-negative", "none negative")


# ---------------------------------------------------------------------------
# Check 5 -- hydration_source
# ---------------------------------------------------------------------------


def check_hydration_source(res: Results, audit: dict) -> None:
    sources = [
        obj.get("hydration_source")
        for obj in iter_dicts(audit)
        if isinstance(obj.get("hydration_source"), dict)
    ]
    if not sources:
        res.failed("5. hydration_source present", "no hydration_source object found")
        return
    res.passed("5. hydration_source present", f"found {len(sources)} object(s)")
    for index, src in enumerate(sources):
        dominant = src.get("dominant")
        if dominant not in DOMINANT_VALUES:
            res.failed(
                f"5a. hydration_source[{index}].dominant",
                f"invalid value {dominant!r}; allowed={sorted(DOMINANT_VALUES)}",
            )
        else:
            res.passed(f"5a. hydration_source[{index}].dominant", str(dominant))
        offenders: list[str] = []
        for key, value in src.items():
            if key == "dominant":
                continue
            if isinstance(value, bool):
                offenders.append(f"{key}={value!r} (bool is not a count)")
            elif isinstance(value, int):
                if value < 0:
                    offenders.append(f"{key}={value} (negative count)")
            elif isinstance(value, float):
                res.info(
                    f"5b. hydration_source[{index}].{key}",
                    f"non-integer numeric value {value!r} (not treated as a count)",
                )
        if offenders:
            res.failed(
                f"5b. hydration_source[{index}] counts",
                "; ".join(offenders),
            )
        else:
            res.passed(
                f"5b. hydration_source[{index}] counts",
                "all integer counts are non-negative",
            )


# ---------------------------------------------------------------------------
# Check 6 -- summary
# ---------------------------------------------------------------------------


def check_summary(res: Results, audit: dict, files: list[dict]) -> None:
    summary = audit.get("summary")
    if not isinstance(summary, dict):
        res.failed("6. summary present", f"summary is not an object: {type(summary).__name__}")
        return
    res.passed("6. summary present", "object")

    rows_sum = 0
    all_numeric = True
    for entry in files:
        value = entry.get("total_rows")
        if is_number(value):
            rows_sum += int(value)
        else:
            all_numeric = False
    declared_rows = summary.get("rows")
    if not all_numeric or not is_number(declared_rows):
        res.failed(
            "6a. summary.rows",
            f"non-numeric total_rows or summary.rows (summary.rows={declared_rows!r})",
        )
    elif int(declared_rows) == rows_sum:
        res.passed("6a. summary.rows", f"rows={int(declared_rows)} == sum(total_rows)")
    else:
        res.failed(
            "6a. summary.rows",
            f"summary.rows={int(declared_rows)} but sum(total_rows)={rows_sum}",
        )

    declared_files = summary.get("files")
    if not is_number(declared_files):
        res.failed("6b. summary.files", f"summary.files is not a number: {declared_files!r}")
    elif int(declared_files) == len(files):
        res.passed("6b. summary.files", f"files={int(declared_files)} == len(files)")
    else:
        res.failed(
            "6b. summary.files",
            f"summary.files={int(declared_files)} but len(files)={len(files)}",
        )


# ---------------------------------------------------------------------------
# Check 7 -- by_layer and stub_files
# ---------------------------------------------------------------------------


def check_layers_and_stubs(res: Results, audit: dict, files: list[dict]) -> set[str]:
    by_layer = audit.get("by_layer")
    if not isinstance(by_layer, dict):
        res.failed("7a. by_layer present", f"by_layer is not an object: {type(by_layer).__name__}")
    else:
        res.passed("7a. by_layer present", f"{len(by_layer)} layer key(s)")

    file_layers: set[str] = set()
    unlabelled = 0
    for entry in files:
        layer = first_present(entry, LAYER_KEYS)
        if layer is None:
            unlabelled += 1
        else:
            file_layers.add(str(layer))
    if unlabelled:
        res.info("7b. unlabelled files", f"{unlabelled} file entr(y/ies) have no layer label")
    if isinstance(by_layer, dict):
        missing_layers = sorted(file_layers - set(by_layer.keys()))
        if missing_layers:
            res.failed(
                "7b. by_layer coverage",
                f"layers in files[] missing from by_layer: {missing_layers}",
            )
        else:
            res.passed(
                "7b. by_layer coverage",
                f"all {len(file_layers)} labelled layer(s) present in by_layer",
            )
        extra_layers = sorted(set(by_layer.keys()) - file_layers)
        if extra_layers:
            res.info("7c. extra by_layer keys", f"not labelled in files[]: {extra_layers}")

    stub_from_files: set[str] = set()
    for entry in files:
        if first_present(entry, STUB_KEYS, False):
            rel = entry.get("path")
            if rel is not None:
                stub_from_files.add(norm_path(rel))

    declared_raw = audit.get("stub_files", [])
    if isinstance(declared_raw, (list, tuple, set)):
        stub_declared = {norm_path(p) for p in declared_raw}
    else:
        res.failed("7d. stub_files type", f"stub_files is not a list: {type(declared_raw).__name__}")
        stub_declared = set()
    if stub_declared == stub_from_files:
        res.passed(
            "7d. stub_files == has_stubs paths",
            f"both sets contain {len(stub_from_files)} path(s)",
        )
    else:
        only_declared = sorted(stub_declared - stub_from_files)
        only_files = sorted(stub_from_files - stub_declared)
        res.failed(
            "7d. stub_files == has_stubs paths",
            f"only in stub_files={only_declared[:20]}; only has_stubs=true={only_files[:20]}",
        )
    return stub_from_files


# ---------------------------------------------------------------------------
# Check 8 -- hydration plan headers
# ---------------------------------------------------------------------------


def find_plan_section(text: str, path: str) -> str | None:
    target = norm_path(path)
    lines = text.splitlines()
    starts: list[int] = []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("#") and norm_path(stripped).find(target) != -1:
            starts.append(i)
    if not starts:
        return None
    start = starts[0]
    match = re.match(r"\s*(#+)", lines[start])
    level = len(match.group(1)) if match else 1
    end = len(lines)
    for i in range(start + 1, len(lines)):
        match2 = re.match(r"\s*(#+)", lines[i])
        if match2 and len(match2.group(1)) <= level:
            end = i
            break
    return "\n".join(lines[start:end])


def check_hydration_plan(res: Results, stub_files: set[str]) -> str:
    if not HYDRATION_PLAN.is_file():
        res.failed("8. hydration plan exists", f"missing: {_display_path(HYDRATION_PLAN)}")
        return ""
    text = HYDRATION_PLAN.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        res.failed("8. hydration plan non-empty", "file is empty")
        return ""
    res.passed(
        "8. hydration plan exists/non-empty",
        f"{len(text)} characters, {len(text.splitlines())} lines",
    )

    missing: list[str] = []
    for path in sorted(stub_files):
        if find_plan_section(text, path) is None:
            missing.append(path)
    if missing:
        res.failed(
            "8a. plan section headers",
            f"{len(missing)} stub path(s) without a section header: "
            + ", ".join(missing[:20]),
        )
    else:
        res.passed(
            "8a. plan section headers",
            f"section header found for all {len(stub_files)} stub path(s)",
        )
    return text


# ---------------------------------------------------------------------------
# Check 9 -- spot-check sample records
# ---------------------------------------------------------------------------


def find_json_objects(text: str) -> list[tuple[str, dict]]:
    """Find balanced {...} substrings that parse to JSON objects."""
    results: list[tuple[str, dict]] = []
    n = len(text)
    i = 0
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_string = False
        escaped = False
        j = i
        while j < n:
            char = text[j]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[i : j + 1]
                        try:
                            obj = json.loads(candidate)
                            if isinstance(obj, dict):
                                results.append((candidate, obj))
                        except (ValueError, TypeError):
                            pass
                        break
            j += 1
        i = j + 1
    return results


def is_placeholder(value: object) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if stripped in {"...", "…", "<...>", "[truncated]", "[...]", ""}:
        return True
    return bool(stripped) and set(stripped) <= set(".… ")


def verify_sample_in_source(sample_raw: str, sample_obj: dict | None, source: Path):
    """Return (matched: bool, strategy: str) for a sample against a source file."""
    parsed_source: list[tuple[str, object]] = []
    for line in read_nonempty_lines(source):
        stripped = line.strip()
        try:
            obj = json.loads(stripped)
        except (ValueError, TypeError):
            obj = None
        parsed_source.append((stripped, obj))

    raw = sample_raw.strip()

    if sample_obj is not None:
        for line, _ in parsed_source:
            if line == raw:
                return True, "exact raw-string match"
        for _, obj in parsed_source:
            if isinstance(obj, dict) and obj == sample_obj:
                return True, "exact parsed-object match"
        # Subset match, ignoring explicit placeholder values in the sample.
        for _, obj in parsed_source:
            if not isinstance(obj, dict):
                continue
            ok = True
            for key, value in sample_obj.items():
                if is_placeholder(value):
                    continue
                if key not in obj or obj[key] != value:
                    ok = False
                    break
            if ok:
                return True, "subset of a real source record (placeholders ignored)"

    # Truncated-prefix match: the sample text is a prefix of a real, parseable line.
    prefix = raw.rstrip(" \t...,…")
    if prefix.startswith("{"):
        for line, obj in parsed_source:
            if line.startswith(prefix) and isinstance(obj, dict):
                return True, "truncated prefix of a real source line"

    return False, "no matching source record"


def check_spot_checks(res: Results, plan_text: str, stub_files: set[str], files: list[dict]) -> None:
    if not stub_files:
        res.info("9. spot checks", "no stub files to sample; skipped")
        return
    if not plan_text:
        res.failed("9. spot checks", "hydration plan text unavailable")
        return

    path_to_entry = {norm_path(e.get("path", "")): e for e in files if isinstance(e, dict)}
    count = min(SPOT_CHECK_COUNT, len(stub_files))
    rng = random.Random(SPOT_CHECK_SEED)
    chosen = sorted(rng.sample(sorted(stub_files), count))
    res.info(
        "9. selection",
        f"{count} stub file(s) sampled with seed={SPOT_CHECK_SEED}: " + ", ".join(chosen),
    )

    for rel in chosen:
        section = find_plan_section(plan_text, rel)
        if section is None:
            # Already reported in check 8; avoid a duplicate FAIL but do not claim a pass.
            res.info(f"9. sample [{rel}]", "no section (see check 8); not re-checked")
            continue
        candidates = find_json_objects(section)
        matched = False
        strategy = ""
        for raw, obj in candidates:
            ok, how = verify_sample_in_source(raw, obj, REPO_ROOT / rel)
            if ok:
                matched = True
                strategy = how
                break
        if matched:
            res.passed(
                f"9. sample [{rel}]",
                f"sample is a real JSON object present in source ({strategy})",
            )
            continue

        # Fallback: try a truncated sample line that has no balanced closing brace.
        truncated_ok = False
        truncated_how = ""
        for line in section.splitlines():
            candidate = line.strip().strip("`").lstrip(">").strip()
            if not candidate.startswith("{"):
                continue
            prefix = candidate.rstrip(" \t...,…")
            if not prefix.startswith("{"):
                continue
            for source_line, obj in [
                (s.strip(), _try_json(s.strip())) for s in read_nonempty_lines(REPO_ROOT / rel)
            ]:
                if source_line.startswith(prefix) and isinstance(obj, dict):
                    truncated_ok = True
                    truncated_how = "truncated sample prefix of a real source line"
                    break
            if truncated_ok:
                break
        if truncated_ok:
            res.passed(f"9. sample [{rel}]", truncated_how)
        elif not candidates:
            res.failed(f"9. sample [{rel}]", "no JSON object sample found in plan section")
        else:
            res.failed(
                f"9. sample [{rel}]",
                f"{len(candidates)} JSON object(s) found in plan, none appears in source file",
            )


def _try_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Informational expected-vs-actual notes (never asserted)
# ---------------------------------------------------------------------------


def emit_expected_notes(res: Results, files: list[dict]) -> None:
    actual_files: dict[str, int] = {}
    actual_rows: dict[str, int] = {}
    assert_rows_all_numeric = True
    for entry in files:
        layer = first_present(entry, LAYER_KEYS)
        if layer is None:
            continue
        key = str(layer)
        actual_files[key] = actual_files.get(key, 0) + 1
        value = entry.get("total_rows")
        if is_number(value):
            actual_rows[key] = actual_rows.get(key, 0) + int(value)
        else:
            assert_rows_all_numeric = False

    res.info(
        "INFO. baseline",
        "expected counts below are exploration notes only -- NOT used as assertions",
    )
    for label, aliases, exp_files, exp_rows in EXPECTED_LAYERS:
        matched_keys = [k for k in actual_files if k in aliases]
        if matched_keys:
            got_files = sum(actual_files[k] for k in matched_keys)
            got_rows = sum(actual_rows.get(k, 0) for k in matched_keys)
            note = (
                f"{label}: expected {exp_files} files/{exp_rows} rows; "
                f"actual {got_files} files/{got_rows} rows"
            )
            if (got_files, got_rows) == (exp_files, exp_rows):
                note += " (match)"
            else:
                note += " (DIFFERS -- informational only)"
            res.info("INFO. expected vs actual", note)
        else:
            res.info(
                "INFO. expected vs actual",
                f"{label}: expected {exp_files} files/{exp_rows} rows; "
                "actual (no matching layer label in files[])",
            )
    if not assert_rows_all_numeric:
        res.info("INFO. expected vs actual", "some total_rows were non-numeric; row notes partial")
    res.info(
        "INFO. baseline",
        "exploration also noted ~189 in-scope .jsonl files repo-wide and ~12,829 "
        "OTHER-EMPTY rows expected in METADATA_ONLY_STUB (informational only)",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    res = Results()

    if not AUDIT_JSON.is_file():
        res.failed("0. audit JSON exists", f"missing: {_display_path(AUDIT_JSON)}")
        res.info("0. next step", "run scripts/audit_trainable_vs_metadata.py first")
        res.write_log()
        _print_summary(res)
        return 1

    try:
        audit = json.loads(AUDIT_JSON.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        res.failed("0. audit JSON parse", f"{type(exc).__name__}: {exc}")
        res.write_log()
        _print_summary(res)
        return 1
    res.passed("0. audit JSON exists/parses", str(AUDIT_JSON.relative_to(REPO_ROOT)))

    files_raw = audit.get("files")
    if not isinstance(files_raw, list):
        res.failed("0. files[] present", f"files is not a list: {type(files_raw).__name__}")
        res.write_log()
        _print_summary(res)
        return 1
    files = [entry for entry in files_raw if isinstance(entry, dict)]
    if len(files) != len(files_raw):
        res.info(
            "0. files[] entries",
            f"{len(files_raw)} raw entries, {len(files)} dict entries (non-dicts skipped)",
        )
    res.passed("0. files[] present", f"{len(files)} file entries")

    try:
        check_path_set(res, audit, files)
        path_to_entry = {norm_path(e.get("path", "")): e for e in files}
        check_row_counts(res, files, path_to_entry)
        check_buckets(res, files)
        check_percentages(res, audit)
        check_hydration_source(res, audit)
        check_summary(res, audit, files)
        stub_files = check_layers_and_stubs(res, audit, files)
        plan_text = check_hydration_plan(res, stub_files)
        check_spot_checks(res, plan_text, stub_files, files)
        emit_expected_notes(res, files)
    except Exception as exc:  # keep a log even on an unexpected verifier error
        res.failed("VERIFIER ERROR", f"{type(exc).__name__}: {exc}")

    res.write_log()
    _print_summary(res)
    return 1 if res.failed_count else 0


def _print_summary(res: Results) -> None:
    print("=" * 70)
    print("AUDIT VERIFICATION SUMMARY")
    print("=" * 70)
    for status, check, message in res.records:
        if status in ("PASS", "FAIL"):
            line = f"[{status}] {check}"
            if message:
                line += f" -- {message}"
            print(line)
    print("-" * 70)
    print(
        f"checks run={res.checks_run}  passed={res.passed_count}  "
        f"failed={res.failed_count}"
    )
    if res.discrepancies:
        print("DISCREPANCIES:")
        for d in res.discrepancies:
            print(f"  - {d}")
    else:
        print("DISCREPANCIES: none")
    print(f"Full log: {_display_path(LOG_PATH)}")
    print("=" * 70)


if __name__ == "__main__":
    sys.exit(main())

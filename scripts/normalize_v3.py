#!/usr/bin/env python3
"""VLUN V3.1 deterministic normalization.

Reads derived_v3/candidate_ledger.jsonl and local V3/clones source files.
Produces a non-destructive normalization overlay, metadata-only finding
fragments, a normalized_records preview, and a coverage report.

The script never copies third-party report prose into outputs, never upgrades
verification above L1, never invents commits, and never promotes PDF fragments.
PDF extraction uses pdftotext when available.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLONES = ROOT / "V3" / "clones"
DERIVED = ROOT / "derived_v3"
REPORTS = ROOT / "reports" / "v3"
U = "unknown"

CLASS_RULES = (
    ("Reentrancy", (r"\breentranc(?:y|e|ies)\b", r"\bre-?entrant\b",
                    r"\breentrant\b", r"\bcallback\b.*\bwithdraw\b")),
    ("Unchecked Low-Level Call", (r"\bunchecked\s+(?:low[- ]level\s+)?call\b",
                                   r"\blow[- ]level\s+(?:call|interaction)\b",
                                   r"\bdelegatecall\b.*\bunchecked\b")),
    ("Arithmetic", (r"\boverflow\b", r"\bunderflow\b",
                     r"\bdivision\s+by\s+zero\b", r"\bprecision\s+(?:loss|error)\b",
                     r"\brounding\s+(?:error|loss|issue)\b")),
    ("Front-running", (r"\bfront[- ]running\b", r"\bfrontrun(?:ning)?\b",
                        r"\bsandwich\s+attack\b")),
    ("Access Control", (r"\baccess[- ]control\b", r"\bunauthori[sz](?:ed|ation)\b",
                        r"\bprivilege\s+escalation\b", r"\bonlyowner\b",
                        r"\bmissing\s+auth(?:entication|orization)\b")),
    ("Denial of Service", (r"\bdenial[- ]of[- ]service\b", r"\b(?:dos|ddos)\b",
                           r"\bgrief(?:ing)?\b", r"\bunbounded\s+loop\b")),
    ("Randomness", (r"\bweak\s+random(?:ness|\s+number)?\b",
                    r"\bpredictable\s+random\b", r"\binsecure\s+random(?:ness|\s+number)?\b")),
    ("Time Manipulation", (r"\btime\s+manipulation\b",
                           r"\btimestamp\s+(?:depend|manipulat)\b",
                           r"\bblock\.timestamp\b.*\b(?:attack|manipulat|depend)\b")),
    ("Short Address", (r"\bshort[- ]address\b",)),
)

FILE_RE = re.compile(r"\b([A-Za-z0-9_./-]+\.(?:sol|vy|rs|move|cairo|clar|sw|go))\b", re.I)
FN_RE = re.compile(r"\b(?:function|fn)\s+([A-Za-z_]\w*)\s*\(")
LINE_RES = (
    re.compile(r"\b[Ll]ines?\s+(\d{1,6})(?:\s*[-–]\s*(\d{1,6}))?\b"),
    re.compile(r"#L(\d+)(?:-L(\d+))?"),
    re.compile(r":(\d{1,6})(?:-(\d{1,6}))?\b"),
)
FRAG_RES = (
    (re.compile(r"^\s*\[?(C|H|M|L)-([0-9]+[A-Za-z]?)\]?\s*[:\-]\s*(.+)$", re.I), "severity_id"),
    (re.compile(r"^\s*(?:finding|issue)\s+([0-9]{1,4})\s*[:\-]\s*(.+)$", re.I), "numbered"),
)

def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]

def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    tmp.replace(path)

def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def clean(value):
    return value in (None, "", U)

def source_path(location):
    prefix = "V3/clones/"
    if not isinstance(location, str) or not location.startswith(prefix):
        return None
    path = CLONES / location[len(prefix):]
    return path if path.exists() and path.is_file() else None

def extract_text(path):
    try:
        if path.suffix.lower() == ".pdf":
            exe = shutil.which("pdftotext")
            if not exe:
                return None, "blocked_pdf_tool_missing", "pdftotext not found"
            proc = subprocess.run(
                [exe, "-layout", "-nopgbrk", "-enc", "UTF-8", str(path), "-"],
                capture_output=True, text=True, errors="ignore", timeout=90,
            )
            if proc.returncode:
                return None, "pdf_extract_failed", (proc.stderr or "")[:500]
            return proc.stdout, "ok", None
        return path.read_text(encoding="utf-8", errors="ignore"), "ok", None
    except subprocess.TimeoutExpired:
        return None, "pdf_extract_timeout", "pdftotext exceeded 90 seconds"
    except OSError as exc:
        return None, "extract_error", str(exc)[:500]

def infer_severity(title, text):
    patterns = (
        (r"\bC(?:ritical)?-\d+[A-Za-z]?\b", "Critical"),
        (r"\bH(?:igh)?-\d+[A-Za-z]?\b", "High"),
        (r"\bM(?:edium)?-\d+[A-Za-z]?\b", "Medium"),
        (r"\bL(?:ow)?-\d+[A-Za-z]?\b", "Low"),
    )
    for pattern, severity in patterns:
        if re.search(pattern, title, re.I):
            return severity, "structured title severity"
    match = re.search(
        r"(?im)^\s*(?:severity|risk)\s*[:\-]\s*(critical|high|medium|low|informational)\b",
        text[:20000],
    )
    return (match.group(1).title(), "explicit severity field") if match else (U, "no explicit severity evidence")

def infer_class(title, text):
    for scope, blob in (("title", title), ("finding_text", text[:18000])):
        hits = []
        for cls, patterns in CLASS_RULES:
            if any(re.search(pattern, blob, re.I) for pattern in patterns):
                hits.append(cls)
        hits = list(dict.fromkeys(hits))
        if len(hits) == 1:
            return hits[0], "deterministic lexical rule", hits
        if len(hits) > 1:
            return U, "ambiguous lexical evidence", hits
    return U, "no high-confidence class rule", []

def infer_lang_eco(title, text, current_lang, current_eco):
    hay = (title + "\n" + text[:12000]).lower()
    lang = current_lang if not clean(current_lang) else U
    eco = current_eco if not clean(current_eco) else U
    languages = {
        "solidity": (r"\bsolidity\b", r"\.sol\b"), "vyper": (r"\bvyper\b", r"\.vy\b"),
        "rust": (r"\brust\b", r"\.rs\b", r"\banchor\b"),
        "move": (r"\bmove\b", r"\bsui\b", r"\baptos\b"),
        "cairo": (r"\bcairo\b", r"\.cairo\b", r"\bstarknet\b"),
        "clarity": (r"\bclarity\b", r"\bstacks\b"),
        "sway": (r"\bsway\b", r"\bforc\b"), "go": (r"\bgolang\b", r"\.go\b"),
    }
    ecosystems = {
        "evm": (r"\bevm\b", r"\bethereum\b", r"\bsolidity\b"),
        "solana": (r"\bsolana\b", r"\banchor\b"), "sui": (r"\bsui\b",),
        "aptos": (r"\baptos\b",), "starknet": (r"\bstarknet\b",),
        "cosmos": (r"\bcosmos\b", r"\bcosmwasm\b", r"\bibc\b"),
        "substrate": (r"\bsubstrate\b", r"\bpolkadot\b"), "stacks": (r"\bstacks\b",),
        "ton": (r"\btoncoin\b",), "stellar": (r"\bstellar\b", r"\bsoroban\b"),
    }
    if lang == U:
        hits = [key for key, pats in languages.items() if any(re.search(p, hay) for p in pats)]
        if len(hits) == 1:
            lang = hits[0]
    if eco == U:
        hits = [key for key, pats in ecosystems.items() if any(re.search(p, hay) for p in pats)]
        if len(hits) == 1:
            eco = hits[0]
    return lang, eco

def infer_code_refs(text):
    files = list(dict.fromkeys(m.group(1).strip(".,;") for m in FILE_RE.finditer(text[:30000])))
    files = [x for x in files if not x.startswith("http")][:3]
    functions = [m.group(1) for m in FN_RE.finditer(text[:30000])]
    functions = list(dict.fromkeys(functions))
    spans = []
    for regex in LINE_RES:
        for match in regex.finditer(text[:30000]):
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if 0 < start <= end <= 1000000:
                spans.append((start, end))
    spans = list(dict.fromkeys(spans))
    return (
        files[0] if len(files) == 1 else U,
        functions[0] if len(functions) == 1 else U,
        list(spans[0]) if len(spans) == 1 else None,
    )

def poc_presence(text):
    if re.search(
        r"(?im)^\s*#{1,6}\s*(?:proof of concept|poc|exploit|steps to reproduce|reproduction|attack scenario)\b",
        text,
    ):
        return True, "explicit PoC/exploit/reproduction heading"
    if re.search(r"\bfunction\s+(?:testExploit|testPoC|testAttack)\s*\(", text):
        return True, "executable test entrypoint"
    return False, "no explicit PoC marker"

def extract_fragments(text):
    lines = text.splitlines()
    starts = []
    for index, line in enumerate(lines):
        stripped = line.strip("# \t")
        for regex, kind in FRAG_RES:
            match = regex.match(stripped)
            if not match:
                continue
            if kind == "severity_id":
                key = f"{match.group(1).upper()}-{match.group(2)}"
            else:
                key = f"finding-{match.group(1)}"
            starts.append((index, key, match.group(3).strip()))
            break
    output = []
    for number, (start, key, title) in enumerate(starts):
        end = starts[number + 1][0] if number + 1 < len(starts) else len(lines)
        chunk = "\n".join(lines[start:end])
        severity, severity_rule = infer_severity(title, chunk)
        cls, class_rule, class_signals = infer_class(title, chunk)
        file_, function, line_span = infer_code_refs(chunk)
        poc, poc_rule = poc_presence(chunk)
        output.append({
            "fragment_key": key,
            "title": title[:500],
            "severity": severity,
            "normalized_vulnerability_class": cls,
            "affected_file": file_,
            "affected_function": function,
            "affected_lines": line_span,
            "poc_available": poc,
            "evidence": {
                "severity_rule": severity_rule,
                "class_rule": class_rule,
                "class_signals": class_signals,
                "code_ref_extraction": "unique-pattern-only",
                "poc_rule": poc_rule,
                "source_span": {"start_line": start + 1, "end_line": end},
                "source_text_sha256": hashlib.sha256(chunk.encode("utf-8")).hexdigest(),
            },
        })
    return output

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="scan and print counts; write nothing")
    args = parser.parse_args()

    ledger = read_jsonl(DERIVED / "candidate_ledger.jsonl")
    records = read_jsonl(DERIVED / "records.jsonl")
    if not ledger:
        print("FATAL: derived_v3/candidate_ledger.jsonl is missing or empty")
        return 2

    overlays = []
    fragments = []
    statuses = collections.Counter()
    updates = collections.Counter()
    blocked = []

    for candidate in ledger:
        path = source_path(candidate.get("source_location"))
        overlay = {
            "candidate_id": candidate["candidate_id"],
            "source_id": candidate["source_id"],
            "source_location": candidate.get("source_location"),
            "normalizer_version": "3.1.0",
            "status": "no_source_file",
            "updates": {},
            "field_evidence": {},
        }
        if path is None:
            overlays.append(overlay)
            statuses[overlay["status"]] += 1
            continue

        text, status, detail = extract_text(path)
        overlay["status"] = status
        if detail:
            overlay["tool_detail"] = detail
        statuses[status] += 1
        if status != "ok":
            blocked.append({"candidate_id": candidate["candidate_id"], "status": status, "detail": detail})
            overlays.append(overlay)
            continue

        source_sha = sha256_file(path)

        def add(field, value, rule):
            if clean(candidate.get(field)) and not clean(value):
                overlay["updates"][field] = value
                overlay["field_evidence"][field] = {
                    "evidence_type": "observed_fact",
                    "rule": rule,
                    "source_file_sha256": source_sha,
                }
                updates[field] += 1

        severity, severity_rule = infer_severity(candidate.get("finding_title", U), text)
        add("severity_normalized", severity, severity_rule)

        cls, class_rule, class_signals = infer_class(candidate.get("finding_title", U), text)
        add("normalized_vulnerability_class", cls, class_rule)

        language, ecosystem = infer_lang_eco(
            candidate.get("finding_title", U), text,
            candidate.get("language", U), candidate.get("ecosystem", U),
        )
        add("language", language, "single unambiguous language marker")
        add("ecosystem", ecosystem, "single unambiguous ecosystem marker")

        affected_file, affected_function, affected_lines = infer_code_refs(text)
        add("affected_file", affected_file, "unique source-code path")
        if clean(candidate.get("affected_lines")) and affected_lines:
            overlay["updates"]["affected_lines"] = affected_lines
            overlay["field_evidence"]["affected_lines"] = {
                "evidence_type": "observed_fact",
                "rule": "unique line-range pattern",
                "source_file_sha256": source_sha,
            }
            updates["affected_lines"] += 1
        if clean(candidate.get("affected_function")) and not clean(affected_function):
            overlay["updates"]["affected_function"] = affected_function
            overlay["field_evidence"]["affected_function"] = {
                "evidence_type": "observed_fact",
                "rule": "unique function signature pattern",
                "source_file_sha256": source_sha,
            }
            updates["affected_function"] += 1

        if not bool(candidate.get("poc_available")):
            poc, poc_rule = poc_presence(text)
            if poc:
                overlay["updates"]["poc_available"] = True
                overlay["field_evidence"]["poc_available"] = {
                    "evidence_type": "observed_fact",
                    "rule": poc_rule,
                    "source_file_sha256": source_sha,
                }
                updates["poc_available"] += 1

        found = extract_fragments(text)
        overlay["fragment_count"] = len(found)
        title_norm = re.sub(r"\s+", " ", str(candidate.get("finding_title", ""))).strip().lower()
        matches = [f for f in found if re.sub(r"\s+", " ", f["title"]).strip().lower() == title_norm]
        if len(matches) == 1:
            overlay["matched_fragment_key"] = matches[0]["fragment_key"]

        for fragment in found:
            fragments.append({
                "candidate_id": candidate["candidate_id"],
                "source_id": candidate["source_id"],
                "source_location": candidate["source_location"],
                "source_file_sha256": source_sha,
                "fragment": fragment,
            })
        overlays.append(overlay)

    preview = []
    overlay_by_id = {row["candidate_id"]: row for row in overlays}
    for record in records:
        row = dict(record)
        overlay = overlay_by_id.get(record["finding_id"], {})
        for field, value in overlay.get("updates", {}).items():
            if field == "severity_normalized":
                if clean(row.get("severity")):
                    row["severity"] = value
            elif field == "poc_available":
                row.setdefault("poc", {})["available"] = True
            elif field == "affected_file":
                if clean(row.get("affected_file")):
                    row["affected_file"] = value
            elif field == "affected_lines":
                if clean(row.get("affected_lines")):
                    row["affected_lines"] = value
            elif field == "affected_function":
                if clean(row.get("affected_function")):
                    row["affected_function"] = value
            elif clean(row.get(field)):
                row[field] = value
        if overlay.get("updates"):
            row["normalization_v3_1"] = {
                "version": "3.1.0",
                "overlay_sha256": hashlib.sha256(
                    json.dumps(overlay, sort_keys=True).encode()
                ).hexdigest(),
                "field_evidence": overlay.get("field_evidence", {}),
            }
        preview.append(row)

    report = {
        "dataset_version": "3.1-normalization",
        "normalizer_version": "3.1.0",
        "candidates_scanned": len(ledger),
        "records_previewed": len(preview),
        "source_status": dict(statuses),
        "safe_updates_available": dict(updates),
        "finding_fragments_discovered": len(fragments),
        "candidates_with_fragments": len({row["candidate_id"] for row in fragments}),
        "blocked_or_failed": len(blocked),
        "guardrails": [
            "unknown remains unknown when evidence is ambiguous",
            "existing V3 top-level vulnerability taxonomy is unchanged",
            "source report prose is never copied into outputs",
            "L2-L6 are never assigned",
            "commit fields are never changed",
            "fragments are metadata-only and are not auto-admitted",
        ],
        "blocked": blocked[:200],
    }

    if args.check:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    write_jsonl(DERIVED / "normalization_overlay.jsonl", overlays)
    write_jsonl(DERIVED / "normalization_fragments.jsonl", fragments)
    write_jsonl(
        DERIVED / "normalized_records_preview.jsonl",
        sorted(preview, key=lambda row: row["finding_id"]),
    )
    write_json(REPORTS / "normalization_report.json", report)
    (REPORTS / "normalization_report.md").write_text(
        "# V3.1 normalization report\n\n"
        f"- candidates scanned: **{len(ledger)}**\n"
        f"- existing records previewed: **{len(preview)}**\n"
        f"- safe field updates available: {dict(updates)}\n"
        f"- finding fragments discovered: **{len(fragments)}**\n"
        f"- candidates with fragments: **{len({row['candidate_id'] for row in fragments})}**\n"
        f"- blocked/failed source extractions: **{len(blocked)}**\n\n"
        "The preview is non-destructive. Review the overlay and fragments before "
        "changing canonical V3 records. No third-party report prose is stored.\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

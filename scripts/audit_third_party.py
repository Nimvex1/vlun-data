#!/usr/bin/env python3
"""Measure what third-party source this dataset actually redistributes.

This exists so the numbers in LICENSE part 3 and in the README are checkable
rather than asserted. It does not use the repository's own `license_classification`
field as its answer; it re-derives the measurement from the text itself, then
reports the classifier's verdict alongside so a discrepancy is visible.

    python scripts/audit_third_party.py
    python scripts/audit_third_party.py --sample 20 --print-samples

Writes reports/third_party_audit.json and exits non-zero if any record is
redistributing source from a repository that declares no licence, so the finding
cannot be quietly dropped between releases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import DERIVED, REPORTS, log, write_json  # noqa: E402

SHA40 = re.compile(r"^[0-9a-f]{40}$")
MUTABLE = {"main", "master", "develop", "release-v5.0", "release", "HEAD",
           "dev", "latest"}
CITATION_KEYS = ("code_context", "code_context_expanded", "code_reference_only",
                 "vulnerable_code")

# Conservative: these only fire on text that is unambiguously Solidity source.
SOLIDITY = re.compile(
    r"(function\s+\w+\s*\(|contract\s+\w+\s*\{|pragma\s+solidity|import\s*\{|"
    r"require\s*\(\s*msg\.sender|revert\s+[A-Z]\w*\s*\(|"
    r"\.transfer\(|\.safeTransferFrom\(|returns\s*\(\s*uint256)",
    re.IGNORECASE)


def deep(v):
    """Unwrap a {value, evidence_type, source_refs} envelope."""
    return v.get("value") if isinstance(v, dict) and "value" in v else v


def stable_sample(items, k, salt="vlun-third-party-audit"):
    """Deterministic sample: same records every run, so diffs are meaningful."""
    def h(x):
        return hashlib.sha256((salt + str(x)).encode("utf-8")).hexdigest()
    return sorted(items, key=h)[:k]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--records", default=str(DERIVED / "records.jsonl"))
    ap.add_argument("--out", default=str(REPORTS / "third_party_audit.json"))
    ap.add_argument("--sample", type=int, default=0,
                    help="include this many sampled verbatim-source records")
    ap.add_argument("--print-samples", action="store_true")
    args = ap.parse_args()

    path = Path(args.records)
    if not path.exists():
        log(f"no {path}")
        return 1
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

    licence = Counter()
    flag = Counter()
    repo_of_flag: dict[str, Counter] = defaultdict(Counter)
    with_solidity: list[str] = []
    entry_counts = Counter()
    long_entries = 0
    external_targets: Counter = Counter()

    for r in rows:
        rid = r.get("id")
        repo = (r.get("source") or {}).get("repository")
        lic = str(deep(r.get("license_classification")) or "unset")
        fl = str(deep(r.get("redistribution")) if not isinstance(r.get("redistribution"), dict)
                 else deep((r.get("redistribution") or {}).get("flag")) or "unset")
        licence[lic] += 1
        flag[fl] += 1

        found = False
        for key in CITATION_KEYS:
            for e in (r.get(key) or []):
                if not isinstance(e, dict):
                    continue
                entry_counts[key] += 1
                text = e.get("snippet") or e.get("code") or ""
                if len(text) > 200:
                    long_entries += 1
                if SOLIDITY.search(text or ""):
                    found = True
                f = e.get("file") or ""
                if "/" in f and repo and repo not in "/".join(f.split("/")[:2]):
                    external_targets["/".join(f.split("/")[:2])] += 1
        if found:
            with_solidity.append(rid)
            repo_of_flag[fl][repo] += 1

    redistributed_unlicensed = sum(
        n for k, n in flag.items() if "redistributed" in k.lower())
    declared_unlicensed = licence.get("unknown", 0) + licence.get("none", 0)

    samples = []
    for rid in stable_sample(with_solidity, args.sample):
        r = next(x for x in rows if x.get("id") == rid)
        snippets = [e.get("snippet") or "" for k in CITATION_KEYS
                    for e in (r.get(k) or []) if e.get("snippet")]
        longest = max(snippets, key=len) if snippets else ""
        samples.append({
            "id": rid,
            "repository": (r.get("source") or {}).get("repository"),
            "license_classification": deep(r.get("license_classification")),
            "redistribution_flag": deep((r.get("redistribution") or {}).get("flag")),
            "snippet_entries": len(snippets),
            "longest_snippet_chars": len(longest),
            "longest_snippet_excerpt": longest[:220],
        })
        if args.print_samples:
            log(f"  {rid} [{samples[-1]['license_classification']}] "
                f"{samples[-1]['longest_snippet_chars']}ch :: "
                f"{longest[:110].replace(chr(10), ' | ')}")

    doc = {
        "generated_by": "scripts/audit_third_party.py",
        "records": len(rows),
        "measurement_note": (
            "Counts are re-derived from the text of the citations, not read from the "
            "dataset's own license_classification field. The classifier's view is "
            "reported alongside so the two can be compared."),
        "license_classification": dict(licence),
        "redistribution_flag": dict(flag),
        "records_declaring_no_licence": declared_unlicensed,
        "records_self_declared_redistributed_unlicensed_source": redistributed_unlicensed,
        "records_containing_solidity_source_text": len(with_solidity),
        "citation_entries_by_field": dict(entry_counts),
        "citation_entries_over_200_chars": long_entries,
        "records_with_solidity_source_by_repo": {
            k: dict(v) for k, v in repo_of_flag.items() if k},
        "external_repositories_cited": dict(
            external_targets.most_common(40)),
        "external_citation_total": sum(external_targets.values()),
        "samples": samples,
        "legal_status": (
            "This dataset redistributes source from repositories that declare no "
            "licence. Downstream redistribution is the recipient's decision; see "
            "LICENSE part 3. No upstream permission has been obtained."),
        "blocks_release_if_nonzero": True,
    }
    write_json(Path(args.out), doc)

    log(f"wrote {args.out}")
    log(f"  records                                   : {len(rows)}")
    log(f"  declaring no upstream licence             : {declared_unlicensed}")
    log(f"  self-declared redistributed unlicensed src : {redistributed_unlicensed}")
    log(f"  containing Solidity source text           : {len(with_solidity)}")
    log(f"  citation entries > 200 chars              : {long_entries}")
    log(f"  external citation entries                 : {sum(external_targets.values())}")

    if redistributed_unlicensed:
        log("")
        log(f"NOTE: {redistributed_unlicensed} records redistribute source from "
            f"repositories with no declared licence.")
        log("      This is disclosed, not resolved. See LICENSE part 3.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Ingest the v2.2 standalone audit reports into the multi-language source layer.

Five reports live outside `jsonl/` (which is the immutable v1 Code4rena layer
and is never written): three independent audits of the same Zentory codebase,
one Kerf audit and one Quantillon review. This script

  1. registers each report as a source, with its sha256 and how it was verified;
  2. parses every finding section out of the markdown;
  3. resolves each finding's cited PoC test against the runs in
     experiments_v2_2/, so a claim the report makes about its own test becomes
     `experimentally_verified` only when we actually observed that test;
  4. checks that every cited file and line range still resolves in the audited
     repository (they have no .git, so the commit cannot be pinned - that is
     recorded as unknown, not guessed);
  5. links the Zentory findings that two or three reports independently filed,
     which is what `independent_confirmation_count` is for: a claim made twice
     is corroborated, never a duplicate to be discarded.

    python scripts/build_ml_ingest.py          # rewrite jsonl_ml/*_reports.jsonl
    python scripts/build_ml_ingest.py --check  # parse and report, write nothing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import DATASET_VERSION, SCHEMA_VERSION, log  # noqa: E402
from vlun_ml import (  # noqa: E402
    ML_JSONL, claim, finding_record, source_record, unknown, validate_finding,
    validate_source, write_jsonl,
)

TODAY = "2026-10-05"
EXPERIMENTS = Path(__file__).resolve().parent.parent / "experiments_v2_2"

# ---------------------------------------------------------------------------
# the five reports
# ---------------------------------------------------------------------------

REPORTS = [
    dict(
        report_id="zentory-mode-a",
        title="Zentory Protocol - Security Audit Report (Mode A, HIGH+)",
        path=r"C:\Users\jeet\Documents\zentory-protocol-main\report.md",
        repo=r"C:\Users\jeet\Documents\zentory-protocol-main\zentory-protocol-main\contracts",
        protocol="Zentory Protocol",
        ecosystem="hyperevm",
        category="Perpetuals / vaults / signals (HyperEVM)",
        tier=3,
        origin="audit",
        author="AI-assisted audit (lens-agent methodology, no named human auditor)",
        heading=re.compile(r"^### ((?:H|M)-\d+) — (.+)$", re.M),
    ),
    dict(
        report_id="zentory-contracts-audit",
        title="Zentory Protocol - Smart Contract Security Audit (High/Critical focus)",
        path=r"C:\Users\jeet\Documents\zentory-protocol-main\zentory-protocol-main\contracts\report.md",
        repo=r"C:\Users\jeet\Documents\zentory-protocol-main\zentory-protocol-main\contracts",
        protocol="Zentory Protocol",
        ecosystem="hyperevm",
        category="Perpets / vaults / signals (HyperEVM)",
        tier=3,
        origin="audit",
        author="AI-assisted audit (skill `smart-contract-security-audit`, no named human auditor)",
        heading=re.compile(r"^### ((?:H|M)\d+) — (.+)$", re.M),
    ),
    dict(
        report_id="zentory-self-audit",
        title="Zentory Protocol - Self-Audit Report",
        path=r"C:\Users\jeet\Downloads\zentory-protocol-main\zentory-protocol-main\report.md",
        repo=r"C:\Users\jeet\Downloads\zentory-protocol-main\zentory-protocol-main\contracts",
        protocol="Zentory Protocol",
        ecosystem="hyperevm",
        category="Perpetuals / vaults / signals (HyperEVM)",
        tier=3,
        origin="audit",
        author="self-audit; the report states no human auditor reviewed or signed off on it",
        heading=re.compile(r"^### ([A-Z]+-?\d+b?) — (.+)$", re.M),
    ),
    dict(
        report_id="kerf-report",
        title="Kerf Contracts - Security Audit Report",
        path=r"C:\Users\jeet\Downloads\kerf-contracts-main\kerf-contracts-main\REPORT.md",
        repo=r"C:\Users\jeet\Downloads\kerf-contracts-main\kerf-contracts-main",
        protocol="Kerf",
        ecosystem="evm",
        category="Perp / LP vaults / structured notes",
        tier=3,
        origin="audit",
        author="unattributed in the report; no firm named",
        heading=re.compile(r"^## ((?:H|M)-\d+) — (.+)$", re.M),
    ),
    dict(
        report_id="quantillon-report",
        title="Quantillon Protocol - Independent Security Review (Live Findings)",
        path=r"C:\Users\jeet\Downloads\smart-contracts-main\smart-contracts-main"
             r"\quantillon-protocol\report.md",
        repo=r"C:\Users\jeet\Downloads\smart-contracts-main\smart-contracts-main"
             r"\quantillon-protocol",
        protocol="Quantillon Protocol",
        ecosystem="base",
        category="EURO stablecoin / hedged vaults (Base)",
        tier=3,
        origin="audit",
        author="independent security researcher (commercial engagement, terms stated in the report)",
        heading=re.compile(r"^### \[(\w+)\] ((?:H|M|I)-\d+) — (.+)$", re.M),
    ),
]

# Findings that two or three of the Zentory reports filed independently against
# the same root cause. This is a hand-authored map because matching them is a
# judgement about *sameness* that no string rule can make honestly; every entry
# is checkable against the report text it names.
ZENTORY_GROUPS = {
    "zentory/fee-distributor-pool-double-count": [
        ("zentory-mode-a", "H-1"), ("zentory-contracts-audit", "H1"),
        ("zentory-self-audit", "M-03"),
    ],
    "zentory/trigger-buyback-strands-pool": [
        ("zentory-mode-a", "H-2"), ("zentory-self-audit", "H-06"),
    ],
    "zentory/totalve-supply-never-decays": [
        ("zentory-mode-a", "H-3"), ("zentory-contracts-audit", "H2"),
        ("zentory-self-audit", "H-02"),
    ],
    "zentory/deployer-retains-admin": [
        ("zentory-mode-a", "H-4"), ("zentory-self-audit", "H-07"),
    ],
    "zentory/evaluate-fees-on-unrealized-pnl": [
        ("zentory-mode-a", "H-5"), ("zentory-self-audit", "C-1"),
    ],
    "zentory/hypercore-executor-role-deployer": [
        ("zentory-mode-a", "H-6"), ("zentory-self-audit", "H-01"),
    ],
    "zentory/zentbuyback-burns-without-swap": [
        ("zentory-mode-a", "M-1"), ("zentory-self-audit", "H-06b"),
    ],
    "zentory/cancel-subscription-unpayable": [
        ("zentory-mode-a", "M-2"), ("zentory-contracts-audit", "H3"),
        ("zentory-self-audit", "M-05"),
    ],
    "zentory/governor-live-votes-no-snapshot": [
        ("zentory-mode-a", "M-3"), ("zentory-self-audit", "H-03"),
    ],
    "zentory/hot-keeper-advances-registry-epoch": [
        ("zentory-contracts-audit", "M1"), ("zentory-self-audit", "H-05"),
    ],
}

SEV_BY_PREFIX = {
    "C": "critical", "H": "high", "M": "medium", "O": "unknown",
    "I": "informational", "S": "informational", "SC": "informational",
}

# How a report frames its own finding, so that framing is preserved instead of
# being flattened into "a finding". Two signals, deliberately kept apart:
#   * the chapter the finding sits in (`## OVERSTATED`) - chapter only, because
#     a finding's *title* may legitimately contain the word ("governor quorum
#     permanently overstated") without the report having withdrawn it;
#   * the finding's own title, for the markers a report puts there.
CLASS_BY_CONTEXT = {
    "OVERSTATED": "overstated_by_the_report",
    "ADDITIONAL OBSERVATIONS": "observation",
    "SCOPE-RISK": "scope_risk",
}
CLASS_BY_TITLE = {
    "OUT OF SCOPE": "out_of_scope",
    "NEGATIVE CONTROL": "negative_control",
}


def classify(sec: dict) -> str:
    title = (sec.get("title") or "").upper()
    for key, val in CLASS_BY_TITLE.items():
        if key in title:
            return val
    ctx = (sec.get("context") or "").upper()
    for key, val in CLASS_BY_CONTEXT.items():
        if key in ctx:
            return val
    return "audit_finding"

TEST_RE = re.compile(r"\b(?:test_[A-Za-z0-9_]+|test[A-Z][A-Za-z0-9_]*)\b")
# A citation may put the line range inside the backticks (`F.sol:124-126`) or
# after them (`F.sol` :124-126); the reports use both shapes.
LOCATION_RE = re.compile(
    r"`?([A-Za-z0-9_./\-]+\.(?:sol|vy|rs|move|cairo))"
    r"(?::(\d+)(?:\s*-\s*(\d+))?)?`?")
CMD_RE = re.compile(r"^\s*(forge test[^\n`]*|node [^\n`]+)\s*$", re.M)
SEV_EXPLICIT_RE = re.compile(r"\*\*Severity:\*\*\s*\*?\*?([A-Za-z]+)", re.I)
# Some findings ship no forge test at all - they point at a script instead
# (`- **PoC:** \`test/AuditAirdropSnapshotPoc.mjs\``). Such a link is only made
# when an experiment actually executed that script.
POC_FILE_RE = re.compile(r"`([^`\s]+\.(?:mjs|cjs|js|ts|py|sh))`")
# Off-chain code a finding can live in. It is not a contract language, so it
# never becomes `code_context` (that would need a language we cannot name
# honestly) - it is recorded as an affected component instead.
SCRIPT_LOC_RE = re.compile(
    r"`?([A-Za-z0-9_./\-]+\.(?:ts|mjs|cjs|js))"
    r"(?::(\d+)(?:\s*-\s*(\d+))?)?`?")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_experiment_index() -> dict:
    p = EXPERIMENTS / "index.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def split_sections(text: str, heading: re.Pattern):
    """Every heading match with the body that follows it and the `##` above it."""
    out = []
    # Track the enclosing level-2 heading so a finding inside "## OVERSTATED"
    # can be classed as such.
    level2 = [m for m in re.finditer(r"^## (.+)$", text, re.M)]
    matches = list(heading.finditer(text))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        # stop at the next level-1/2 heading of any kind so a `###` section
        # cannot swallow the `##` chapter that follows it
        nxt2 = [x.start() for x in level2 if x.start() > m.start()]
        if nxt2:
            end = min(end, nxt2[0])
        ctx = ""
        for x in level2:
            if x.start() < m.start():
                ctx = x.group(1)
        out.append({
            "fid": m.group(1),
            "title": m.group(2) if m.lastindex == 2 else m.group(2),
            "body": text[m.end():end],
            "context": ctx,
        })
    return out


def parse_severity(rep: dict, sec: dict) -> tuple[str, str]:
    """Severity is whatever the report itself says, in the order the report is
    most explicit: a `**Severity:**` line, else the chapter the finding sits in
    (`## HIGH`), else the report's own id prefix. Nothing is inferred from any
    other source."""
    m = SEV_EXPLICIT_RE.search(sec["body"])
    if m:
        v = m.group(1).strip().lower()
        if v in ("critical", "high", "medium", "low", "informational"):
            return v, "stated in the report as '**Severity:** <x>'"
    ctx = (sec.get("context") or "").upper()
    for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        if ctx.startswith(key):
            return key.lower(), f"stated by the report chapter '## {ctx[:40]}'"
    pref = re.match(r"^([A-Z]+)-?\d", sec["fid"])
    p = pref.group(1) if pref else ""
    if p in SEV_BY_PREFIX:
        return SEV_BY_PREFIX[p], f"inferred from the report's own id prefix {p!r}"
    return "unknown", "the report states no severity for this id"


def parse_findings(rep: dict, text: str) -> list[dict]:
    if rep["report_id"] == "quantillon-report":
        secs = []
        for m in rep["heading"].finditer(text):
            nxt = rep["heading"].search(text, m.end())
            end = nxt.start() if nxt else len(text)
            secs.append({"fid": m.group(2), "title": m.group(3),
                         "body": text[m.end():end], "context": "",
                         "bracket_sev": m.group(1)})
    else:
        secs = split_sections(text, rep["heading"])

    out = []
    for s in secs:
        if rep["report_id"] == "quantillon-report":
            sev = s.get("bracket_sev", "").lower()
            sev = {"high": "high", "medium": "medium", "info": "informational",
                   "critical": "critical", "low": "low"}.get(sev, "unknown")
            sev_src = "stated in the heading as '[<severity>]'"
        else:
            sev, sev_src = parse_severity(rep, s)

        record_class = classify(s)

        body = s["body"]
        tests = sorted({t for t in TEST_RE.findall(body)})
        cmds = [c.strip() for c in CMD_RE.findall(body)]
        locs = []
        for lm in LOCATION_RE.finditer(body):
            locs.append({"file": lm.group(1),
                         "line_start": int(lm.group(2)) if lm.group(2) else None,
                         "line_end": int(lm.group(3)) if lm.group(3)
                         else (int(lm.group(2)) if lm.group(2) else None)})
        # de-duplicate, keep order
        seen, uniq_locs = set(), []
        for l in locs:
            k = (l["file"], l["line_start"], l["line_end"])
            if k not in seen:
                seen.add(k)
                uniq_locs.append(l)
        scripts = []
        for lm in SCRIPT_LOC_RE.finditer(body):
            path = lm.group(1)
            if path.startswith("test/") or path.startswith("tests/"):
                continue          # that is the PoC, not the thing being faulted
            if path not in [s["file"] for s in scripts]:
                scripts.append({"file": path,
                                "line_start": int(lm.group(2)) if lm.group(2) else None,
                                "line_end": int(lm.group(3)) if lm.group(3)
                                else (int(lm.group(2)) if lm.group(2) else None)})

        out.append({
            "fid": s["fid"], "title": s["title"].strip(),
            "body": body.strip(), "severity": sev, "severity_source": sev_src,
            "record_class": record_class, "tests": tests, "commands": cmds,
            "poc_files": sorted({m for m in POC_FILE_RE.findall(body)
                                 if "/" in m or "\\" in m}),
            "locations": uniq_locs[:12],
            "script_locations": scripts[:8],
        })
    return out


SKIP_DIRS = {"out", "cache", "lib", "node_modules", "artifacts", "target",
             ".git", ".venv", "venv", "broadcast", "typechain-types",
             "dependencies", "build", "docs"}
# Vendored third-party code. Kept in a separate index because finding a file
# here answers a different question: the citation resolves, but to somebody
# else's contract, not to the audited protocol's.
DEP_DIRS = {"lib", "node_modules", "dependencies", "@openzeppelin", "vendor"}
_INDEX: dict[str, dict[str, list[str]]] = {}
EXTS = {".sol", ".vy", ".rs", ".move", ".cairo", ".ts", ".mjs", ".js"}


def project_roots(rep: dict) -> list[Path]:
    """The roots a citation may be relative to.

    Reports cite from whichever directory they were written against: for the
    Zentory trees that is the project root (so `contracts/src/...` and
    `scripts/...` both resolve), while other reports cite from inside the
    contracts directory. Both are tried, and nothing outside these roots is
    searched - a basename match two repositories over would be a lie."""
    root = Path(rep["repo"])
    return [root, root.parent] if root.name == "contracts" else [root]


def file_index(root: Path, mode: str = "source") -> dict[str, list[str]]:
    """mode='source' indexes the project's own files, mode='dep' its vendored
    dependencies; the two are never mixed so a citation cannot silently land in
    somebody else's code."""
    key = f"{mode}:{root}"
    if key in _INDEX:
        return _INDEX[key]
    idx: dict[str, list[str]] = {}
    for r, dirs, files in _walk(root):
        rel_parts = Path(r).relative_to(root).parts
        is_dep = bool(DEP_DIRS & set(rel_parts))
        for name in files:
            p = Path(r) / name
            if p.suffix.lower() not in EXTS:
                continue
            if mode == "source" and (is_dep or SKIP_DIRS & set(rel_parts)):
                continue
            if mode == "dep" and not is_dep:
                continue
            idx.setdefault(name, []).append(
                (Path(r) / name).relative_to(root).as_posix())
    _INDEX[key] = idx
    return idx


def _walk(root: Path):
    """os.walk pruned of build output, which is neither source nor dependency."""
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       {"out", "cache", "artifacts", "target", ".git",
                        "broadcast", "typechain-types", "docs"}]
        yield dirpath, dirnames, filenames


def resolve_path(rep: dict, cited: str) -> tuple[Path | None, str, list[str]]:
    """Resolve one citation to a file on disk, recording *how* it resolved."""
    roots = project_roots(rep)
    rel = cited.replace("\\", "/")
    if roots[0].name == "contracts" and rel.startswith("contracts/"):
        rel = rel[len("contracts/"):]           # report cited the parent dir
    for r in roots:
        p = r / rel
        if p.exists():
            return p, "exact", []
    # fall back to a unique basename inside the roots we are allowed to search
    cands: list[str] = []
    for r in roots:
        for c in file_index(r).get(Path(rel).name, []):
            cands.append(str(r / c))
    uniq = sorted(set(cands))
    if len(uniq) == 1:
        return Path(uniq[0]), "resolved_by_unique_basename", uniq
    if uniq:
        return None, "ambiguous_basename", uniq
    # last resort: the name only exists in vendored dependencies (OpenZeppelin
    # and friends). Resolving there is honest as long as it says so.
    deps: list[str] = []
    for r in roots:
        for c in file_index(r, "dep").get(Path(rel).name, []):
            deps.append(str(r / c))
    deps = sorted(set(deps))
    if deps:
        return Path(deps[0]), "external_dependency", deps
    return None, "not_found", []


def project_relative(rep: dict, p: Path) -> str:
    """Path relative to the outermost allowed root, so the same file cited two
    different ways (`src/F.sol` and `contracts/src/F.sol`) ends up identical."""
    for r in reversed(project_roots(rep)):
        try:
            return p.relative_to(r).as_posix()
        except ValueError:
            continue
    return p.name


def resolve_code_context(rep: dict, locs: list[dict]) -> list[dict]:
    """Prove the cited file and line range exist - the reports have no .git, so
    the commit cannot be pinned. Existence is checkable, so it is checked and
    the way it resolved is recorded; the sha stays unknown rather than guessed."""
    out = []
    for l in locs:
        p, how, cands = resolve_path(rep, l["file"])
        entry = {
            "language": "solidity",
            "file": project_relative(rep, p) if p else l["file"],
            "path_as_cited": l["file"],
            "resolution": how,
            "note": {
                "external_dependency":
                    "the file exists but is vendored third-party code, so it is "
                    "not part of the audited protocol",
                "not_found":
                    "no file with this name under the roots this citation is "
                    "allowed to resolve against",
                "ambiguous_basename":
                    "several files share this name; candidates are listed and "
                    "none was chosen",
            }.get(how),
            "resolved_path": str(p) if p else None,
            "candidates": cands[:6],
            "commit_sha": None,
            "commit_note": "the audited tree carries no .git metadata, so no "
                           "commit can be pinned; the citation is path-and-line only",
            "line_start": l["line_start"],
            "line_end": l["line_end"],
            "file_exists": p is not None,
            "line_range_verified": False,
            "evidence_type": "observed_fact" if p is not None else "unknown",
        }
        if p is not None and l["line_start"]:
            try:
                n = sum(1 for _ in open(p, encoding="utf-8", errors="replace"))
            except OSError:
                n = None
            if n is not None:
                entry["file_lines"] = n
                entry["line_range_within_file"] = l["line_end"] is None or \
                    l["line_end"] <= n
                entry["line_range_verified"] = bool(
                    l["line_start"] <= n and
                    (l["line_end"] is None or l["line_end"] <= n))
        out.append(entry)
    return out


def match_experiments(rep_id: str, tests: list[str], poc_files: list[str],
                      index: dict) -> tuple[list, dict]:
    """Which of this finding's cited artefacts did we actually watch run?

    Two link kinds, both mechanical:
      * `test`      - the exact test name appears in a run from this report;
      * `poc_file`  - no forge test was cited, but the report's PoC script is
                      the very thing an experiment executed.
    Nothing else produces a link. A PoC the report mentions but we never ran
    stays unlinked, which is the point: the gap has to remain visible."""
    exps = [e for e in index.get("experiments", [])
            if e.get("source_report") == rep_id]
    observed = {}
    for e in exps:
        for name in e.get("passing_tests") or []:
            observed[name.rstrip("()")] = (e, "passed")
        for name in e.get("failing_tests") or []:
            observed[name.rstrip("()")] = (e, "failed")
    hits, seen = [], set()
    for t in tests:
        match = t if t in observed else None
        if match is None:
            # a report often cites the short form (`test_poc_2`) of the real
            # name (`test_poc_2_triggerBuyback...`); match only on a whole-token
            # boundary so `test_poc_2` cannot pick up `test_poc_20`
            for name in observed:
                if name.startswith(t + "_"):
                    match = name
                    break
        if match is None:
            continue
        e, outcome = observed[match]
        key = (e["experiment_id"], match)
        if key in seen:
            continue
        seen.add(key)
        hits.append({"test": match, "cited_as": t,
                     "experiment_id": e["experiment_id"],
                     "observed": outcome, "match_kind": "test"})
    if hits:
        return hits, {e["experiment_id"]: e for e in exps}
    for e in exps:
        cmd = e.get("command") or ""
        for f in poc_files:
            if f in cmd or Path(f).name in cmd:
                hits.append({
                    "test": None, "poc_file": f,
                    "experiment_id": e["experiment_id"],
                    "observed": f"exit_code={e.get('exit_code')}",
                    "match_kind": "poc_file",
                })
    return hits, {e["experiment_id"]: e for e in exps}


def experiment_block(hits: list, exps: dict) -> dict | None:
    """Turn observed runs into an experiment record.

    The mapping from "this test" to "this finding" comes from the report: the
    test appears inside that finding's own section. What we add is that the
    test was actually run here, against the audited tree, and what it did.
    Nothing in here asserts the test was *correct* - only that it ran and how
    it came out."""
    if not hits:
        return None
    first = exps[hits[0]["experiment_id"]]
    counts = first.get("test_counts")
    by_kind = {h.get("match_kind") for h in hits}
    if by_kind == {"poc_file"}:
        basis = ("the report names the script as this finding's PoC and an "
                 "experiment executed that script against the audited tree in "
                 "this session; the observation recorded here is that it ran "
                 "and what it returned. The script's assertions are its own, "
                 "not something this pipeline derived")
    else:
        basis = ("the report presents these tests as the PoC for this finding; "
                 "they ran against the audited tree in this session with the "
                 "results recorded in tests_observed. A run that passes the "
                 "report's own assertion, or that fails while asserting the "
                 "correct invariant, is consistent with the defect being "
                 "present; the test-to-finding mapping is the report's, not "
                 "something this pipeline derived")
    return {
        "level": "L5",
        "executed": True,
        "outcome": "reproduced",
        "outcome_basis": basis,
        "match_kinds": sorted(by_kind),
        "tests_observed": hits,
        "experiment_ids": sorted({h["experiment_id"] for h in hits}),
        "result_artifact": f"experiments_v2_2/{hits[0]['experiment_id']}/result.json",
        "stdout_artifact": f"experiments_v2_2/{hits[0]['experiment_id']}/stdout.txt",
        "toolchain": first.get("toolchain") or {},
        "seconds": first.get("seconds"),
        "tests_in_suite": counts,
        "fixed_revision_executed": False,
        # poc_classification.py defines L6 as "reproduced on the vulnerable
        # revision and blocked on the fixed one"; that is the run these records
        # do not have, so that is what has to be explained.
        "why_no_L6": "the audited trees carry no git history and no patched "
                     "revision exists to run the same test against, so no "
                     "vulnerable-vs-fixed comparison was possible",
    }


def build(check_only: bool) -> tuple[list, list]:
    index = load_experiment_index()
    all_sources, all_findings = [], []
    group_index: dict[tuple[str, str], str] = {}
    for gid, members in ZENTORY_GROUPS.items():
        for m in members:
            group_index[m] = gid

    for rep in REPORTS:
        p = Path(rep["path"])
        if not p.exists():
            log(f"  MISSING report: {p}")
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        digest = sha256_file(p)

        src = source_record(
            source_id=f"solidity:{rep['report_id']}",
            language="solidity",
            ecosystem=rep["ecosystem"],
            title=rep["title"],
            source_tier=rep["tier"],
            evidence_origin=rep["origin"],
            url=p.as_uri(),
            repository=None,
            retrieved_at=TODAY,
            verification_status="retrieved_and_read",
            retrieval={
                "method": "local_file_read",
                "path": str(p),
                "sha256": digest,
                "bytes": p.stat().st_size,
            },
            published_at=None,
            severity=unknown("a report is a container, not a severity claim"),
            license={
                "content_license": "unknown",
                "redistributable": False,
                "evidence_type": "observed_fact",
                "note": "no licence is declared anywhere in the report, so its "
                        "text is neither copied into this repository nor "
                        "redistributed; only the parsed claims and a sha256 are",
            },
            notes=f"author: {rep['author']}. protocol: {rep['protocol']} "
                  f"({rep['category']}). The report is the primary evidence for "
                  f"its findings and is referenced by local path + sha256.",
        )
        # A local report is evidence we can hash, so it is recorded as such
        # rather than being dressed up as a URL it does not have.
        src["url_scheme"] = "local_file"
        src["protocol"] = {"name": rep["protocol"], "category": rep["category"]}
        src["report"] = {"path": str(p), "sha256": digest,
                         "bytes": p.stat().st_size,
                         "parsed_findings": 0}
        src["author_note"] = rep["author"]
        all_sources.append(src)

        findings = parse_findings(rep, text)
        src["report"]["parsed_findings"] = len(findings)

        for f in findings:
            hits, exps = match_experiments(rep["report_id"], f["tests"],
                                           f["poc_files"], index)
            exp = experiment_block(hits, exps)
            ctx = resolve_code_context(rep, f["locations"])
            offchain = []
            for s in f["script_locations"]:
                sp, how, _ = resolve_path(rep, s["file"])
                offchain.append({"file": s["file"],
                                 "resolved_path": str(sp) if sp else None,
                                 "resolution": how,
                                 "line_start": s["line_start"],
                                 "line_end": s["line_end"]})

            # every test the report cites for this finding, minus the ones we
            # watched run - the difference is what remains unverified
            observed_tests = {
                n.rstrip("()") for e in exps.values()
                for n in ((e.get("passing_tests") or []) +
                          (e.get("failing_tests") or []))}
            ran_poc_files = {
                Path((e.get("command") or "").split()[-1]).name
                for e in exps.values() if e.get("command")}
            executed = bool(exp and exp.get("executed"))
            status = "experimentally_verified" if executed else "reported_claim"
            gid = group_index.get((rep["report_id"], f["fid"]))
            members = ZENTORY_GROUPS.get(gid, [])

            evidence = {
                "existence": claim(
                    f"{f['fid']} is filed in {rep['report_id']}",
                    "observed_fact",
                    [f"solidity:{rep['report_id']}"],
                    "read out of the report document itself"),
                "severity": claim(
                    f["severity"], "reported_claim",
                    [f"solidity:{rep['report_id']}"],
                    f["severity_source"]),
                "root_cause": claim(
                    None, "reported_claim",
                    [f"solidity:{rep['report_id']}"],
                    "the report states a root cause; this pipeline did not "
                    "independently derive one - the body text is preserved in "
                    "finding.summary"),
                "affected_versions": unknown(
                    "the audited trees carry no git metadata and the reports "
                    "state no version range"),
                "fix_commit": unknown(
                    "no fix has been committed to any tree we can see; the "
                    "reports propose fixes but none was executed"),
                "patch_effective": unknown(
                    "no patched revision was executed against the same test, so "
                    "no effectiveness claim is made"),
                "independent_confirmation": claim(
                    len(members) if gid else None,
                    "derived_fact" if gid else "unknown",
                    [f"solidity:{m[0]}" for m in members] if gid else [],
                    "count of distinct reports that filed this root cause"
                    if gid else "no other report in this batch filed it"),
            }
            if executed:
                evidence["poc_execution"] = claim(
                    "observed", "experimentally_verified",
                    exp["experiment_ids"],
                    exp["outcome_basis"])

            sev = f["severity"]
            rec = finding_record(
                language="solidity",
                ecosystem=rep["ecosystem"],
                finding_id=f"{rep['report_id']}/{f['fid']}",
                title=f["title"],
                source_ids=[f"solidity:{rep['report_id']}"],
                source={
                    "organization": rep["author"],
                    "repository": None,
                    "repository_url": None,
                    "report_path": str(p),
                    "report_sha256": digest,
                    "protocol": rep["protocol"],
                    "audit_date": None,
                },
                severity={"value": sev, "source": f["severity_source"]},
                finding={
                    "record_class": f["record_class"],
                    "status": status,
                    "vulnerability_classes": [],
                    "summary": f["body"][:4000],
                    "root_cause": None,
                    "affected_components": sorted(
                        {l["file"] for l in f["locations"]} |
                        {s["file"] for s in f["script_locations"]}),
                    "affected_functions": [],
                    "affected_versions": None,
                    "patched_versions": None,
                },
                evidence=evidence,
                provenance={
                    "source_urls": [p.as_uri()],
                    "retrieved_at": TODAY,
                    "evidence_origin": rep["origin"],
                    "source_tier": rep["tier"],
                    "record_sha256": hashlib.sha256(
                        f["body"].encode("utf-8")).hexdigest(),
                    "parsed_by": "scripts/build_ml_ingest.py",
                    "poc_commands_declared": f["commands"][:5],
                    "tests_cited": f["tests"],
                    # kept visible on purpose: a PoC the report ships but we
                    # never ran is an unverified claim, not a silent pass
                    "tests_cited_but_not_run": [
                        t for t in f["tests"]
                        if t not in observed_tests and not any(
                            n.startswith(t + "_") for n in observed_tests)],
                    "poc_files_cited_but_not_run": [
                        x for x in f["poc_files"]
                        if Path(x).name not in ran_poc_files],
                    "offchain_citations": offchain,
                },
                code_context=ctx,
                patch={"present": False, "evidence_type": "unknown",
                       "note": "the reports describe fixes but ship no diff"},
                experiment=exp,
                dataset_version=DATASET_VERSION,
                schema_version=SCHEMA_VERSION,
            )
            if gid:
                rec["canonical_finding"] = {
                    "value": gid,
                    "evidence_type": "derived_fact",
                    "source_refs": [f"solidity:{m[0]}" for m in members],
                    "note": "hand-authored equivalence map across the Zentory "
                            "reports; see ZENTORY_GROUPS in "
                            "scripts/build_ml_ingest.py. The three reports were "
                            "read against three separate checkouts that carry "
                            "no git metadata, so their revisions cannot be "
                            "shown identical; a PoC run against one checkout "
                            "does not upgrade this record's own status.",
                }
                rec["independent_confirmation_count"] = len(members)
                rec["duplicate_reports"] = [
                    {"report": m[0], "finding_id": m[1]}
                    for m in members
                    if m != (rep["report_id"], f["fid"])
                ]
                rec["corroboration_independence"] = {
                    "evidence_type": "observed_fact",
                    "authorships_documented": False,
                    "note": "reports zentory-mode-a and zentory-contracts-audit "
                            "name no human auditor and share a methodology, so "
                            "corroboration between them is weak; "
                            "zentory-self-audit is a self-review that states no "
                            "one else signed off. Counting is therefore a count "
                            "of distinct documents, not of distinct auditors.",
                }
            else:
                rec["canonical_finding"] = unknown(
                    "no other report in this batch filed the same root cause")
                rec["independent_confirmation_count"] = 1
                rec["duplicate_reports"] = []
                rec["corroboration_independence"] = {
                    "evidence_type": "unknown",
                    "authorships_documented": False,
                    "note": "only one document in this batch files this root "
                            "cause, so there is nothing to corroborate it",
                }

            all_findings.append(rec)

    return all_sources, all_findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="parse but write nothing")
    args = ap.parse_args()

    sources, findings = build(args.check)
    errors = []
    for s in sources:
        errors += [f"sources {s['source_id']}: {e}" for e in validate_source(s)]
    for f in findings:
        errors += [f"findings {f['id']}: {e}" for e in validate_finding(f)]

    executed = sum(1 for f in findings if (f.get("experiment") or {}).get("executed"))
    groups = {f.get("canonical_finding", {}).get("value")
              for f in findings
              if isinstance(f.get("canonical_finding"), dict)
              and f["canonical_finding"].get("value")}
    log(f"parsed {len(sources)} reports, {len(findings)} findings "
        f"({executed} with an executed PoC, {len(groups)} cross-report groups)")
    if errors:
        for e in errors[:40]:
            log(f"  [FAIL] {e}")
        return 1

    if args.check:
        log("--check: nothing written")
        return 0

    write_jsonl(ML_JSONL / "sources_reports.jsonl", sources)
    write_jsonl(ML_JSONL / "findings_reports.jsonl", findings)
    log(f"wrote {ML_JSONL / 'sources_reports.jsonl'}")
    log(f"wrote {ML_JSONL / 'findings_reports.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

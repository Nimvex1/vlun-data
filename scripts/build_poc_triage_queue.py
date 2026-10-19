#!/usr/bin/env python3
"""Build the PoC triage queue for the v1/v2.1 evidence layer.

Spec item 6 ("Execution Density"): the corpus identifies 155 exploit records but
only nine pinpoint experiments exist in the v1/v2.1 evidence layer. Before any
re-run is meaningful, every candidate has to be triaged against ONE standard:
what would have to be true for this record's claimed impact to be demonstrated.

This script does not run anything. It reads the evidence layers, the local
read-only clones under `work/repos/`, and the patch layer, and emits one row per
candidate saying what is available, what is missing, and whether the current
evidence standard can be met by an attempt at all.

Layers are never merged into one number:

    v1_v2_1   jsonl/exploits.jsonl                      (the 155 exploit records)
    v3_1      derived_v3/experiment_readiness.json      (newly acquired candidates)
    ml_v2_2   jsonl_ml/findings_*.jsonl + scripts/run_ml_pocs.py declared PoCs
    vbeta     Vbeta/jsonl_vbeta/findings.jsonl          (L0/L1 pointers by design)

Rows for the v1/v2.1 layer carry every field the runner needs to attempt them.
Rows for the other layers are carried so the eligible pool is visible, and they
are counted separately in the report.

Blocker vocabulary (closed, machine readable):

    source_unavailable              the audited tree at the pinned revision is not
                                    obtainable from this checkout
    toolchain_missing              the framework the PoC needs is not installed here
    rpc_unavailable                 the PoC forks historical chain state and no
                                    read-only archive endpoint is configured
    fixture_missing                 a file the PoC imports is absent at the revision
    harness_reconstruction_required the quoted artefact is a fragment that needs the
                                    reporter's fixture rebuilt before it can compile
    licence_gated                   the only way to host the PoC bytes would be
                                    redistributing code whose licence forbids it
    not_exploit                     the record is not an exploit-consequence claim
                                    (QA/gas/informational shape), so no impact test
                                    exists to reproduce

    python scripts/build_poc_triage_queue.py
    python scripts/build_poc_triage_queue.py --check    # regenerate + byte-compare
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import poc_classification as pc  # noqa: E402
from vlun import JSONL, REPORTS, ROOT, WORK, owner_repo  # noqa: E402
from vlun_io import read_jsonl, write_json, write_jsonl  # noqa: E402

QUEUE_DIR = ROOT / "derived_poc_queue"
CLONES = WORK / "repos"
OUT_JSONL = QUEUE_DIR / "triage_queue.jsonl"
OUT_JSON = REPORTS / "poc_triage_queue.json"
OUT_MD = REPORTS / "poc_triage_queue.md"

LAYER_V1 = "v1_v2_1"
LAYER_V3 = "v3_1"
LAYER_ML = "ml_v2_2"

BLOCKERS = (
    "source_unavailable",
    "toolchain_missing",
    "rpc_unavailable",
    "fixture_missing",
    "harness_reconstruction_required",
    "licence_gated",
    "not_exploit",
)

NON_REDISTRIBUTABLE = ("Business Source License 1.1", "Commons Clause",
                       "CC BY-ND", "cc-by-nd")

CONTRACT_DECL = re.compile(r"\bcontract\s+[A-Za-z_$][\w$]*\b")
TEST_FN = re.compile(r"(?m)^\s*(?:function|public\s+function)\s+(test[A-Za-z0-9_]*)\s*\(")
ASSERT_LINE = re.compile(r"\b(assert[A-Za-z0-9_]*|require|vm\.expectRevert|"
                         r"vm\.expectRevertSelector|expectRevert)\s*\(([^;]{0,300})")
FORK_DECL = re.compile(r"create(?:Select)?Fork\(\s*\"([^\"]+)\"")
IMPORT_STMT = re.compile(r"""import\s+(?:[^;]*?from\s+)?["']([^"']+)["']\s*;""")
NBA = re.compile("\u00a0")       # the quoted PoCs are NBSP-indented from the report HTML
LVL_RANK = {f"L{i}": i for i in range(7)}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def clean(text: str) -> str:
    return NBA.sub(" ", text or "").replace("\r\n", "\n")


# ---------------------------------------------------------------------------
# local clone reconnaissance (read-only: never a write inside work/repos)
# ---------------------------------------------------------------------------
def clone_dir(owner_repo: str) -> Path:
    return CLONES / owner_repo.replace("/", "__")


def top_level(d: Path) -> set[str]:
    try:
        return {p.name for p in d.iterdir()}
    except OSError:
        return set()


def read_text(p: Path, limit: int = 200_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def repo_facts(owner_repo: str) -> dict:
    """What the local tree at the pinned revision actually provides."""
    d = clone_dir(owner_repo)
    names = top_level(d)
    if not names:
        return {"clone_present": False, "head": None, "foundry_config": False,
                "hardhat_config": False, "remappings": False, "lockfile": False,
                "lib_dirs": [], "node_modules": False, "test_dirs": [],
                "head_matches_pinned": False, "solc_declared": None,
                "source_roots": []}
    head = None
    try:
        import subprocess
        r = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=120)
        head = (r.stdout or "").strip() or None
    except Exception:  # noqa: BLE001 - reconnaissance must never break the queue
        head = None
    ft = d / "foundry.toml"
    solc = None
    test_dirs: list[str] = []
    src_roots: list[str] = []
    if ft.exists():
        m = re.search(r"solc(?:_version)?\s*=\s*['\"]?([0-9]+\.[0-9]+\.[0-9]+)",
                      read_text(ft), re.M)
        solc = m.group(1) if m else None
        for key, bucket in (("test", test_dirs), ("src", src_roots)):
            mm = re.search(rf"^\s*{key}\s*=\s*['\"]([^'\"]+)['\"]", read_text(ft), re.M)
            if mm:
                bucket.append(mm.group(1))
    for cand in ("contracts", "src", "testFoundry", "test", "tests"):
        if cand in names and cand not in src_roots + test_dirs:
            (test_dirs if cand.startswith("test") else src_roots).append(cand)
    return {
        "clone_present": True,
        "head": head,
        "head_matches_pinned": None,          # filled per record once known
        "foundry_config": ft.exists(),
        "hardhat_config": any(n.startswith("hardhat.config") for n in names),
        "remappings": ("remappings.txt" in names
                       or (ft.exists() and "remappings" in read_text(ft))),
        "lockfile": any(n in names for n in ("package-lock.json", "yarn.lock",
                                              "pnpm-lock.yaml")),
        "lib_dirs": sorted((d / "lib").glob("*")) and sorted(
            p.name for p in (d / "lib").glob("*") if p.is_dir()) or [],
        "node_modules": "node_modules" in names,
        "test_dirs": sorted(set(test_dirs)),
        "source_roots": sorted(set(src_roots)),
        "solc_declared": solc,
    }


# ---------------------------------------------------------------------------
# per-record extraction
# ---------------------------------------------------------------------------
def assertion_of(code: str, record: dict) -> dict:
    """The concrete statement the PoC makes, plus the impact it is supposed to test."""
    body = clean(code)
    hits = []
    for m in ASSERT_LINE.finditer(body):
        cond = re.sub(r"\s+", " ", m.group(0))[:300]
        if cond not in hits:
            hits.append(cond)
    exp = record.get("exploit") or {}
    impact = exp.get("expected_impact") or ""
    if not impact:
        seq = exp.get("attack_sequence") or []
        impact = "; ".join(f"{s.get('actor', '')}: {s.get('action', '')}".strip(": ")
                           for s in seq if isinstance(s, dict))
    return {
        "assertions_present": bool(hits),
        "assertion_count": len(hits),
        "assertions": hits[:6],
        "assertion_kind": ("state_change_equality" if any("Eq" in h for h in hits)
                           else "revert_expectation" if any("evert" in h for h in hits)
                           else "boolean_assert" if hits
                           else "no_assertion_in_quoted_poc"),
        "claimed_impact": re.sub(r"\s+", " ", str(impact))[:600],
    }


def unresolved_imports(code: str, root: Path, test_dirs: list[str]) -> list[str]:
    """Relative imports in the quoted PoC that do not exist in the pinned tree."""
    out = []
    body = clean(code)
    for imp in IMPORT_STMT.findall(body):
        if imp.startswith(("forge-std", "@", "lib/", "node_modules")):
            continue
        if not (imp.startswith("./") or imp.startswith("../") or "/" in imp):
            continue
        rel = imp.lstrip("./")
        for base in test_dirs + [""]:
            p = (root / base / rel) if base else (root / rel)
            if p.is_file():
                break
            # the PoC is written from inside the test dir
            p2 = root / rel
            if p2.is_file():
                break
        else:
            out.append(imp)
    return sorted(set(out))


def patch_reference(finding_id: str, patches: dict) -> dict:
    p = patches.get(finding_id) or {}
    pl = p.get("patch") or {}
    return {
        "patch_record_present": bool(p),
        "patch_available": pl.get("available"),
        "fixed_commit": pl.get("fixed_commit"),
        "fixed_commit_note": re.sub(r"\s+", " ", str(pl.get("fixed_commit_note") or ""))[:300],
        "prs": pl.get("prs") or [],
    }


def triage_v1(record: dict, facts_by_repo: dict, patches: dict,
              rpc_configured: bool) -> dict:
    src = record.get("source") or {}
    exp = record.get("exploit") or {}
    gh_owner_repo = owner_repo(src) or f"{src.get('organization', '')}/{src.get('repository', '')}"
    repo = src.get("repository", "")
    pinned = src.get("commit_sha") or ""
    code = clean(exp.get("code") or "")
    setup = clean(exp.get("setup") or "")
    cls = pc.classify(exp)
    level = pc.level_for(cls)["level"]

    facts = facts_by_repo.setdefault(repo, repo_facts(gh_owner_repo))
    facts = dict(facts)
    facts["head_matches_pinned"] = (facts["head"] == pinned) if pinned else None

    fns = TEST_FN.findall(code)
    has_contract = bool(CONTRACT_DECL.search(code))
    fork_aliases = sorted(set(FORK_DECL.findall(code)) | set(
        FORK_DECL.findall(setup)))
    imports = unresolved_imports(code, clone_dir(gh_owner_repo), facts["test_dirs"])
    framework = ("hardhat" if (exp.get("code_language") == "typescript"
                               or (not facts["foundry_config"]
                                   and facts["hardhat_config"]))
                 else "foundry" if facts["foundry_config"] else "unknown")
    if exp.get("framework"):
        framework = str(exp["framework"]).lower() or framework

    licence = str((record.get("provenance") or {}).get("license") or "")
    restrictive = any(k.lower() in licence.lower() for k in NON_REDISTRIBUTABLE)

    blockers: list[str] = []
    if record["finding"].get("severity") == "qa":
        blockers.append("not_exploit")
    if not facts["clone_present"]:
        blockers.append("source_unavailable")
    elif facts["head"] and pinned and facts["head"] != pinned:
        blockers.append("source_unavailable")
    if imports:
        blockers.append("fixture_missing")
    if not has_contract and fns:
        blockers.append("harness_reconstruction_required")
    if not fns:
        blockers.append("harness_reconstruction_required")
    if fork_aliases and not rpc_configured:
        blockers.append("rpc_unavailable")
    if framework == "hardhat" and not facts["node_modules"]:
        blockers.append("toolchain_missing")
    if framework == "unknown":
        blockers.append("toolchain_missing")
    # de-duplicate while keeping first-seen order, then sort for determinism
    seen: list[str] = []
    for b in blockers:
        if b not in seen:
            seen.append(b)
    blockers = sorted(seen)

    eligible = not blockers
    # An attempt is still worth recording when the only obstacle is the
    # reconstruction itself: the runner materialises the quoted bytes and lets
    # the compiler decide. Those are "attemptable", not "eligible to prove L5".
    attemptable = eligible or (
        set(blockers) <= {"harness_reconstruction_required", "fixture_missing"}
        and facts["clone_present"] and bool(fns))

    permalinks = sorted({v.get("commit_sha") for v in (record.get("vulnerable_code") or [])
                         if isinstance(v, dict) and v.get("commit_sha")})
    urls = [u for u in (record.get("provenance") or {}).get("source_urls", []) if u]
    return {
        "candidate_layer": LAYER_V1,
        "finding_id": record["finding"]["id"],
        "repository": gh_owner_repo,
        "repository_url": src.get("repository_url"),
        "pinned_vulnerable_commit": pinned,
        "additional_permalink_commits": permalinks,
        "poc_source_pointer": {
            "kind": "dataset_quoted_record",
            "path": f"jsonl/exploits.jsonl#finding.id={record['finding']['id']}",
            "upstream_url": urls[0] if urls else None,
            "quoted_code_sha256": sha256_text(code) if code else None,
            "quoted_code_bytes": len(code.encode("utf-8")),
            "quoted_test_name": exp.get("test_name") or None,
            "declared_test_file": exp.get("test_file") or None,
        },
        "claimed_impact": assertion_of(code, record)["claimed_impact"],
        "assertion": assertion_of(code, record),
        "required_toolchain": {
            "framework": framework,
            "forge_required": framework == "foundry",
            "node_required": framework == "hardhat",
            "solidity_versions": (record.get("protocol") or {}).get("solidity_versions") or [],
            "solc_declared_in_config": facts["solc_declared"],
            "fork_aliases_required": fork_aliases,
        },
        "dependency_configuration": {
            "clone_present": facts["clone_present"],
            "clone_head": facts["head"],
            "head_matches_pinned_commit": facts["head_matches_pinned"],
            "foundry_toml": facts["foundry_config"],
            "remappings_available": facts["remappings"],
            "lockfile_available": facts["lockfile"],
            "lib_directories": facts["lib_dirs"],
            "node_modules_present": facts["node_modules"],
            "unresolved_relative_imports": imports,
            "declared_dependency_count": len(
                (record.get("protocol") or {}).get("dependencies") or []),
        },
        "patch_reference": patch_reference(record["finding"]["id"], patches),
        "licence": {
            "declared": licence or None,
            "restrictive_for_redistribution": restrictive,
            "note": ("restrictive licences gate publishing the bytes, not running "
                     "them locally; runs happen in a scratch copy under work/"),
        },
        "poc_class": cls["poc_class"],
        "poc_class_rationale": cls["rationale"],
        "evidence_level_before_this_campaign": level,
        "eligibility": "eligible" if eligible else "not_eligible",
        "attemptable_under_current_standard": bool(attemptable),
        "blocker_classes": blockers,
        "blocker_class": blockers[0] if blockers else None,
    }


def triage_v3(row: dict) -> dict:
    blockers = []
    b = set(row.get("blockers") or [])
    if {"repository_unknown", "revision_unknown", "no_poc_published"} & b:
        blockers.append("source_unavailable")
    if any(x.startswith("needs_archive_rpc") for x in b):
        blockers.append("rpc_unavailable")
    return {
        "candidate_layer": LAYER_V3,
        "finding_id": row.get("finding_id"),
        "repository": row.get("source_id"),
        "repository_url": None,
        "pinned_vulnerable_commit": None,
        "additional_permalink_commits": [],
        "poc_source_pointer": {
            "kind": "v3_readiness_row",
            "path": "derived_v3/experiment_readiness.json",
            "upstream_url": None,
            "quoted_code_sha256": None,
            "quoted_code_bytes": 0,
            "quoted_test_name": None,
            "declared_test_file": None,
        },
        "claimed_impact": None,
        "assertion": {"assertions_present": False, "assertion_count": 0,
                      "assertions": [], "assertion_kind": "unknown_from_layer",
                      "claimed_impact": None},
        "required_toolchain": {"framework": "unknown", "forge_required": False,
                                "node_required": False, "solidity_versions": [],
                                "solc_declared_in_config": None,
                                "fork_aliases_required": []},
        "dependency_configuration": {
            "clone_present": False, "clone_head": None,
            "head_matches_pinned_commit": None, "foundry_toml": False,
            "remappings_available": False, "lockfile_available": False,
            "lib_directories": [], "node_modules_present": False,
            "unresolved_relative_imports": [], "declared_dependency_count": 0},
        "patch_reference": {"patch_record_present": False, "patch_available": None,
                             "fixed_commit": None, "fixed_commit_note": None,
                             "prs": []},
        "licence": {"declared": None, "restrictive_for_redistribution": False,
                     "note": "inherited from the v3 layer; not re-checked here"},
        "poc_class": "v3_readiness",
        "poc_class_rationale": f"tier={row.get('tier')} has_poc={row.get('has_poc')}",
        "evidence_level_before_this_campaign": "L0",
        "eligibility": "eligible" if not blockers else "not_eligible",
        "attemptable_under_current_standard": bool(row.get("executed")),
        "blocker_classes": sorted(set(blockers)),
        "blocker_class": sorted(set(blockers))[0] if blockers else None,
    }


def build(rpc_env: str | None) -> tuple[list[dict], dict]:
    rpc_configured = bool(rpc_env)
    exploits = read_jsonl(JSONL / "exploits.jsonl")
    patches = {}
    for p in read_jsonl(JSONL / "patches.jsonl"):
        fid = (p.get("finding") or {}).get("id")
        if fid:
            patches.setdefault(fid, p)

    rows = [triage_v1(r, {}, patches, rpc_configured) for r in exploits]
    rows.sort(key=lambda r: r["finding_id"])

    # additional layers, reported separately and never merged into the 155
    v3_rows: list[dict] = []
    v3_poc_bearing = 0
    v3_total = 0
    rf = ROOT / "derived_v3" / "experiment_readiness.json"
    if rf.exists():
        for line in rf.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            v3_total += 1
            if row.get("has_poc"):
                v3_poc_bearing += 1
                v3_rows.append(triage_v3(row))
    v3_rows.sort(key=lambda r: str(r["finding_id"]))

    ml_files = sorted((ROOT / "jsonl_ml").glob("findings_*.jsonl"))
    ml_records = sum(len(read_jsonl(p)) for p in ml_files)

    vbeta_rows = read_jsonl(ROOT / "Vbeta" / "jsonl_vbeta" / "findings.jsonl") \
        if (ROOT / "Vbeta" / "jsonl_vbeta" / "findings.jsonl").exists() else []

    stats = {
        "generated_by": "scripts/build_poc_triage_queue.py",
        "layers": {
            LAYER_V1: {
                "source": "jsonl/exploits.jsonl",
                "candidates": len(exploits),
                "eligible": sum(1 for r in rows if r["eligibility"] == "eligible"),
                "not_eligible": sum(1 for r in rows if r["eligibility"] != "eligible"),
                "attemptable": sum(1 for r in rows
                                    if r["attemptable_under_current_standard"]),
                "blocker_counts": blocker_counts(rows),
                "poc_class_counts": dict(sorted(
                    (lambda c: c.items())(
                        __import__("collections").Counter(
                            r["poc_class"] for r in rows)))),
                "with_assertion_in_quoted_poc": sum(
                    1 for r in rows if r["assertion"]["assertions_present"]),
                "with_patch_reference": sum(
                    1 for r in rows if r["patch_reference"]["fixed_commit"]),
                "repositories": dict(sorted(
                    __import__("collections").Counter(
                        r["repository"] for r in rows).items())),
            },
            LAYER_V3: {
                "source": "derived_v3/experiment_readiness.json",
                "rows_read": v3_total,
                "poc_bearing_candidates": v3_poc_bearing,
                "queued": len(v3_rows),
                "eligible": sum(1 for r in v3_rows if r["eligibility"] == "eligible"),
                "blocker_counts": blocker_counts(v3_rows),
            },
            LAYER_ML: {
                "source": "jsonl_ml/findings_*.jsonl",
                "records": ml_records,
                "additional_exploit_poc_candidates": 0,
                "note": ("the ml layer carries finding records with a separate "
                          "experiment runner (scripts/run_ml_pocs.py); it adds no "
                          "exploit-PoC candidate rows to this queue"),
            },
            "vbeta": {
                "source": "Vbeta/jsonl_vbeta/findings.jsonl",
                "records": len(vbeta_rows),
                "additional_exploit_poc_candidates": 0,
                "note": "Vbeta is L0/L1 pointer-level by construction: no PoC bytes",
            },
        },
        "blocker_vocabulary": list(BLOCKERS),
        "standard": ("L3 requires a compiler run we performed; L4 requires that "
                     "run to execute; L5 additionally requires the record's own "
                     "assertion to be identified and to hold. Executing is not "
                     "reproducing."),
    }
    return rows + v3_rows, stats


def blocker_counts(rows: list[dict]) -> dict:
    c: dict[str, int] = {}
    for r in rows:
        for b in (r["blocker_classes"] or (["none"] if r["eligibility"] == "eligible"
                                             else ["unclassified"])):
            c[b] = c.get(b, 0) + 1
    return dict(sorted(c.items()))


# ---------------------------------------------------------------------------
# validation (shared with tests/test_poc_triage.py)
# ---------------------------------------------------------------------------
def validate_queue_rows(rows: list[dict], *, expected_v1: int | None = None) -> list[str]:
    """Structural rules the queue must satisfy. Returns one string per breach.

    These are the rules that keep a triage queue honest: a row cannot be called
    eligible while carrying a blocker, a blocker must be from the closed
    vocabulary, the PoC must be referenced by pointer (never by copied bytes),
    and the queue must cover the exploit layer exactly once per finding.
    """
    errs: list[str] = []
    v1 = [r for r in rows if r.get("candidate_layer") == LAYER_V1]
    if expected_v1 is not None and len(v1) != expected_v1:
        errs.append(f"v1/v2.1 layer has {len(v1)} rows, expected {expected_v1} "
                    f"exploit records")
    seen: set[tuple[str, str]] = set()
    for r in rows:
        fid = r.get("finding_id")
        layer = r.get("candidate_layer")
        if not fid or not layer:
            errs.append("row without finding_id/candidate_layer")
            continue
        if (layer, fid) in seen:
            errs.append(f"duplicate row for {layer}/{fid}")
        seen.add((layer, fid))
        bc = r.get("blocker_class")
        bcs = r.get("blocker_classes") or []
        if bc is not None and bc not in BLOCKERS:
            errs.append(f"{fid}: blocker_class {bc!r} outside the closed vocabulary")
        for b in bcs:
            if b not in BLOCKERS:
                errs.append(f"{fid}: blocker_classes entry {b!r} is not a known class")
        if r.get("eligibility") == "eligible" and bcs:
            errs.append(f"{fid}: marked eligible while carrying blockers {bcs}")
        if r.get("eligibility") == "not_eligible" and not bcs:
            errs.append(f"{fid}: marked not_eligible with no blocker class")
        if layer == LAYER_V1:
            if not r.get("pinned_vulnerable_commit"):
                errs.append(f"{fid}: no pinned vulnerable revision")
            ptr = r.get("poc_source_pointer") or {}
            if "code" in ptr or "quoted_code" in ptr:
                errs.append(f"{fid}: queue must point at the PoC, not copy it")
            if not (ptr.get("path") or ptr.get("upstream_url")):
                errs.append(f"{fid}: PoC source pointer is empty")
            if "assertion" not in r or not isinstance(r.get("assertion"), dict):
                errs.append(f"{fid}: assertion record missing")
    return errs


def markdown(stats: dict, rows: list[dict]) -> str:
    v1 = [r for r in rows if r["candidate_layer"] == LAYER_V1]
    L = ["# PoC triage queue", "",
         "Generated by `scripts/build_poc_triage_queue.py`. Counts are recomputed "
         "from the records; none of them is typed by hand.", ""]
    lay = stats["layers"]
    L += ["## Candidates by layer (never merged)", "",
          "| layer | candidates | eligible | not eligible | attemptable |",
          "|---|---|---|---|---|"]
    for name in (LAYER_V1, LAYER_V3):
        d = lay[name]
        n = d.get("candidates", d.get("poc_bearing_candidates"))
        att = d.get("attemptable", "-")
        L.append(f"| `{name}` | {n} | {d['eligible']} | {d['not_eligible'] if 'not_eligible' in d else d.get('queued', 0) - d['eligible']} | {att} |")
    L += [f"| `{LAYER_ML}` | {lay[LAYER_ML]['records']} records, "
          f"{lay[LAYER_ML]['additional_exploit_poc_candidates']} additional PoC candidates | 0 | 0 | 0 |",
          f"| `vbeta` | {lay['vbeta']['records']} records, "
          f"{lay['vbeta']['additional_exploit_poc_candidates']} additional PoC candidates | 0 | 0 | 0 |", ""]
    L += [f"The v1/v2.1 queue is the {lay[LAYER_V1]['candidates']} exploit records of "
          "`jsonl/exploits.jsonl`. The v3.1 layer is reported separately: it is a "
          "different evidence layer and its rows cannot be counted as v1/v2.1 "
          "experiments.", ""]
    L += ["## Blocker classes (v1/v2.1)", "",
          "| blocker | records |", "|---|---|"]
    for k, v in lay[LAYER_V1]["blocker_counts"].items():
        L.append(f"| `{k}` | {v} |")
    L += ["", "## Blocker classes (v3.1, separately)", "",
          "| blocker | candidates |", "|---|---|"]
    for k, v in lay[LAYER_V3]["blocker_counts"].items():
        L.append(f"| `{k}` | {v} |")
    L += ["", "## PoC class distribution (v1/v2.1)", "",
          "| poc_class | records |", "|---|---|"]
    for k, v in lay[LAYER_V1]["poc_class_counts"].items():
        L.append(f"| `{k}` | {v} |")
    L += ["",
          f"Records whose quoted PoC contains at least one concrete assertion: "
          f"{lay[LAYER_V1]['with_assertion_in_quoted_poc']}.",
          f"Records with a referenced fixed commit: "
          f"{lay[LAYER_V1]['with_patch_reference']}.", ""]
    L += ["## Attempt pool, ranked", "",
          "| finding | repository | poc_class | blockers |", "|---|---|---|---|"]
    pool = sorted([r for r in v1 if r["attemptable_under_current_standard"]],
                  key=lambda r: (r["blocker_classes"] != [], r["finding_id"]))
    for r in pool:
        L.append(f"| `{r['finding_id']}` | {r['repository']} | `{r['poc_class']}` | "
                 f"{', '.join(r['blocker_classes']) or 'none'} |")
    L += ["", "## Per-record fields", "",
          "Each row of `derived_poc_queue/triage_queue.jsonl` carries: stable finding "
          "id, repository and pinned vulnerable revision, a PoC *pointer* (dataset path "
          "plus upstream URL and the sha256 of the quoted bytes - the PoC code itself is "
          "not copied into this queue), the required toolchain, what dependency "
          "configuration is available locally, the patch reference, the assertion the "
          "PoC makes, the eligibility verdict and the blocker classes.", ""]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the PoC triage queue.")
    ap.add_argument("--check", action="store_true",
                    help="regenerate into a temp buffer and byte-compare the "
                         "committed outputs; write nothing")
    ap.add_argument("--rpc", default=os.environ.get("VLUN_RPC_URL"),
                    help="read-only archive RPC to assume (default $VLUN_RPC_URL)")
    args = ap.parse_args()

    rows, stats = build(args.rpc)
    errs = validate_queue_rows(rows, expected_v1=len(read_jsonl(JSONL / "exploits.jsonl")))
    if errs:
        for e in errs[:20]:
            print(f"QUEUE INVALID: {e}")
        print(f"{len(errs)} structural breach(es)")
        return 1
    stats["totals"] = {
        "queued_rows": len(rows),
        "v1_v2_1_candidates": stats["layers"][LAYER_V1]["candidates"],
        "v1_v2_1_eligible": stats["layers"][LAYER_V1]["eligible"],
        "v1_v2_1_attemptable": stats["layers"][LAYER_V1]["attemptable"],
        "v3_1_poc_bearing_candidates": stats["layers"][LAYER_V3]["poc_bearing_candidates"],
        "rpc_configured": bool(args.rpc),
    }
    md = markdown(stats, rows)

    if args.check:
        ok = True
        for path, payload in ((OUT_JSONL, None), (OUT_JSON, stats), (OUT_MD, md)):
            if not path.exists():
                print(f"MISSING {path.relative_to(ROOT)}")
                ok = False
                continue
            if payload is None:
                want = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                               for r in sorted(rows, key=lambda x: (
                                   x["candidate_layer"], str(x["finding_id"]))))
                have = OUT_JSONL.read_text(encoding="utf-8")
            else:
                if path.suffix == ".json":
                    want = json.dumps(payload, indent=2, sort_keys=True,
                                      ensure_ascii=False) + "\n"
                else:
                    want = payload
                have = path.read_text(encoding="utf-8")
            if want != have:
                print(f"DRIFT  {path.relative_to(ROOT)}")
                ok = False
            else:
                print(f"OK     {path.relative_to(ROOT)}")
        print("check:", "byte-identical" if ok else "drift detected")
        return 0 if ok else 1

    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_JSONL, sorted(rows, key=lambda x: (x["candidate_layer"],
                                                        str(x["finding_id"]))))
    write_json(OUT_JSON, stats)
    OUT_MD.write_text(md, encoding="utf-8", newline="\n")
    t = stats["totals"]
    print(f"queued {t['queued_rows']} rows: v1/v2.1 {t['v1_v2_1_candidates']} "
          f"({t['v1_v2_1_eligible']} eligible, {t['v1_v2_1_attemptable']} attemptable) "
          f"+ v3.1 {t['v3_1_poc_bearing_candidates']} PoC-bearing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

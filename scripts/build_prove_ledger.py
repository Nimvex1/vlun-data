#!/usr/bin/env python3
"""Merge and police the VLUN-Prove candidate ledger.

Prove grows by execution, so the ledger is the control that keeps the published
pool honest. Every candidate row must state one stage, and a row may only claim
`qualified` when it carries the eight admission-gate fields the interface claims
on its behalf. Blocked and rejected rows are kept with their blocker: a failed
attempt is evidence, not something to delete.

Inputs are the discovery ledgers (`work/prove_candidates/*.jsonl`) plus the
recorded two-revision evidence already in this tree. Outputs land in
`derived_prove/` and `reports/`; nothing here mutates `jsonl/`, `jsonl_ml/` or
`jsonl_v3/`.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from vlun import REPORTS, log, read_jsonl, write_json, write_jsonl  # noqa: E402

CANDIDATE_DIR = ROOT / "work" / "prove_candidates"
OUT_DIR = ROOT / "derived_prove"
LEDGER = OUT_DIR / "candidate_ledger.jsonl"
STATS_JSON = REPORTS / "prove_candidate_ledger.json"
STATS_MD = REPORTS / "prove_candidate_ledger.md"

SCHEMA_VERSION = "vlun-prove-candidate-ledger/1.0"

STAGES = ("candidate", "revision_pair_resolved", "harness_available",
          "vulnerable_run_passed_gate", "fixed_run_passed_gate", "qualified",
          "blocked", "rejected_with_reason")

# The order a candidate advances through. A stage may never skip a predecessor.
LADDER = ["candidate", "revision_pair_resolved", "harness_available",
          "vulnerable_run_passed_gate", "fixed_run_passed_gate", "qualified"]

# What a row must carry before it is allowed to say `qualified`. Each of these is
# one clause of the admission gate, checked rather than asserted in prose.
QUALIFICATION_FIELDS = {
    "repository": "source provenance: an immutable repository URL",
    "vulnerable_commit": "the pinned vulnerable revision",
    "fixed_commit": "the pinned fixing revision",
    "test_sha256": "one identical test file, hashed, on both sides",
    "vulnerable_artifact": "recorded vulnerable-side run",
    "fixed_artifact": "recorded fixed-side run",
    "toolchain": "compiler and runner versions used for both runs",
    "stage_decision": "the grader's own stage reached, not a process exit code",
}

RIGHTS_STATUSES = ("cleared_for_redistribution", "withheld_pending_permission",
                   "unclassified")

FRAMEWORKS = ("foundry", "hardhat", "foundry+hardhat", "cairo", "scarb", "sui-move",
              "truffle", "other", "unknown")


def licence_map() -> tuple[dict[str, tuple[str, str]], str]:
    """repository -> (licence_code, where it was read), from evidence already on disk.

    Only exact repository matches are applied. A repository nobody has classified is NOT
    defaulted to a licence: `apply_rights` marks the row `withheld_pending_permission`,
    which keeps its artefacts local and says so.
    """
    path = CANDIDATE_DIR / "web_ledger.jsonl"
    mapping: dict[str, tuple[str, str]] = {}
    if not path.exists():
        return mapping, "work/prove_candidates/web_ledger.jsonl (absent)"
    for row in _load(path):
        repo = str(row.get("repository") or "").strip().rstrip("/").lower()
        licence = row.get("licence_code")
        if repo and licence:
            mapping.setdefault(repo, (str(licence).strip(), path.name))
    return mapping, path.name


def apply_rights(rows: list[dict]) -> dict:
    """Admission clause 8: a qualified row must carry a rights position it did not invent."""
    licences, source = licence_map()
    counts = collections.Counter()
    for row in rows:
        if row.get("licence_code"):
            counts[str(row["licence_code"]).split(" (")[0]] += 1
            continue
        repo = str(row.get("repository") or "").strip().rstrip("/").lower()
        if repo in licences:
            code, where = licences[repo]
            row["licence_code"] = code
            row["rights_reference"] = f"work/prove_candidates/{where}"
            row["rights_status"] = "cleared_for_redistribution" if code.startswith("MIT") \
                else "withheld_pending_permission"
            counts[code.split(" (")[0]] += 1
            continue
        row.setdefault("rights_status", "unclassified")
        row.setdefault("rights_reference", source)
        if row.get("candidate_stage") == "qualified":
            # A verified run with no licence evidence on disk may not redistribute its
            # harness: the artefacts stay local and the row says so instead of quietly
            # implying a licence nobody recorded.
            row["rights_status"] = "withheld_pending_permission"
            row["rights_note"] = ("no licence classification on disk for this repository: "
                                  "harness bytes stay in the local artefact tree and are not "
                                  "redistributed until the licence is established")
    return dict(counts)


_ALIASES = {
    "unknown (no readable diff)": "unknown",
    "hardhat+foundry": "foundry+hardhat",
    "sui": "sui-move",
    "move": "sui-move",
    "sui-move": "sui-move",
    "cairo-scarb": "cairo",
    "cairo": "cairo",
    "scarb": "scarb",
}


def framework_key(value) -> str | None:
    """Fold a discovery ledger's framework note into the counted vocabulary.

    Discovery rows carry what the repository said ("sui-move (sui 1.48.2 and
    1.6.3 recorded)"), but diversity is counted by framework, so the version text
    cannot become the group key. The original string is preserved alongside.
    """
    if value in (None, ""):
        return "unknown"
    text = str(value).strip().lower()
    if text in FRAMEWORKS:
        return text
    if text in _ALIASES:
        return _ALIASES[text]
    head = text.split(" ")[0].split("(")[0].strip()
    if head in _ALIASES:
        return _ALIASES[head]
    if head in FRAMEWORKS:
        return head
    for name in ("foundry", "hardhat", "cairo", "scarb", "truffle"):
        if name in text:
            return name
    if "move" in text:
        return "sui-move"
    return "other"


def _load(path: Path) -> list[dict]:
    return read_jsonl(path) if path.exists() else []


def _toolchain(artifact: str | None) -> str | None:
    """The recorded toolchain for a run, read from the artefact the recorder wrote.

    Some layers store `toolchain.txt`; the v1 experiment layer records the toolchain
    inside `result.json` as `environment_requirements` plus the exact `command`, so
    both are accepted and neither is invented.
    """
    if not artifact:
        return None
    directory = ROOT / artifact
    path = directory / "toolchain.txt"
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if text:
            return text[:400]
    result = directory / "result.json"
    if result.exists():
        try:
            record = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        captured = {"environment_requirements": record.get("environment_requirements"),
                    "command": record.get("command")}
        if any(captured.values()):
            return json.dumps(captured, sort_keys=True)[:600]
    return None


def interface_repositories() -> dict[str, str]:
    """finding id -> the clone URL the published interface records for it.

    `patch_verification_v2` names the audit (`2024-01-renft`) while a run ledger names
    the URL, so the two spellings would count as two codebases. Repository diversity is
    the number this pool is judged on, so the URL is authoritative where it is known.
    """
    path = REPORTS / "prove_split_interface.json"
    if not path.exists():
        return {}
    try:
        interface = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {t["finding_id"]: t.get("repository") for t in interface.get("tasks") or []
            if t.get("finding_id") and t.get("repository")}


def seed_from_recorded_evidence() -> list[dict]:
    """Every two-revision pair this tree has already executed becomes a ledger row.

    A run only reaches `qualified` when the harness digest is identical on both
    sides, the vulnerable side failed with a recorded reason and the fixed side
    passed. Different harness bytes on the two sides is the documented failure mode
    of this pool, so it downgrades the row to `candidate` instead of crediting it.
    """
    rows: list[dict] = []
    urls = interface_repositories()
    verification = {}
    pv = REPORTS / "patch_verification_v2.json"
    if pv.exists():
        verification = {r["finding_id"]: r
                        for r in json.loads(pv.read_text(encoding="utf-8")).get("records", [])}
    experiments = []
    ve = REPORTS / "verified_experiments.json"
    if ve.exists():
        experiments = json.loads(ve.read_text(encoding="utf-8")).get("experiments", [])

    for experiment in experiments:
        fid = experiment.get("finding_id")
        record = verification.get(fid, {})
        revisions = experiment.get("revisions") or {}
        vulnerable = revisions.get("vulnerable") or {}
        fixed = revisions.get("fixed") or {}
        identical_harness = bool(vulnerable.get("harness_digest")) and \
            vulnerable.get("harness_digest") == fixed.get("harness_digest")
        row = {
            "candidate_id": f"recorded::{fid}",
            "finding_id": fid,
            "repository": urls.get(fid) or record.get("repository") or "unknown",
            "vulnerable_commit": vulnerable.get("commit"),
            "fixed_commit": fixed.get("commit"),
            "framework": "foundry",
            "test_sha256": vulnerable.get("harness_digest"),
            "test_sha256_fixed_side": fixed.get("harness_digest"),
            "test_name": experiment.get("match_test"),
            "vulnerable_artifact": vulnerable.get("artifact"),
            "fixed_artifact": fixed.get("artifact"),
            "toolchain": _toolchain(vulnerable.get("artifact")),
            "stage_decision": record.get("two_revision_evidence"),
            "vulnerable_revision_result": record.get("vulnerable_revision_result"),
            "fixed_revision_result": record.get("fixed_revision_result"),
            "per_test_status_vulnerable": vulnerable.get("per_test_status"),
            "origin": "recorded_vlun_evidence",
            "source_documents": ["reports/verified_experiments.json",
                                 "reports/patch_verification_v2.json"],
        }
        if not identical_harness:
            row["candidate_stage"] = "candidate"
            row["blocker"] = ("the two sides ran different harness bytes "
                              f"({str(vulnerable.get('harness_digest'))[:8]} vs "
                              f"{str(fixed.get('harness_digest'))[:8]}): not an identical-test "
                              "verification")
        elif (record.get("fix_effectiveness") == "effective"
              and vulnerable.get("status") == "fail" and fixed.get("status") == "pass"):
            row["candidate_stage"] = "qualified"
        else:
            row["candidate_stage"] = "blocked"
            row["blocker"] = ("fix_effectiveness="
                              f"{record.get('fix_effectiveness')}, vulnerable side "
                              f"{vulnerable.get('status')}, fixed side {fixed.get('status')}")
        rows.append(row)

    # Patch records with no experiment row are still candidates worth tracking.
    for fid, record in verification.items():
        if any(r["finding_id"] == fid for r in rows):
            continue
        rows.append({
            "candidate_id": f"patch::{fid}",
            "finding_id": fid,
            "repository": urls.get(fid) or record.get("repository"),
            "vulnerable_commit": record.get("vulnerable_commit"),
            "fixed_commit": record.get("fixed_commit"),
            "framework": "unknown",
            "test_name": record.get("regression_test"),
            "stage_decision": record.get("two_revision_evidence"),
            "origin": "recorded_vlun_evidence",
            "source_documents": ["reports/patch_verification_v2.json"],
            "candidate_stage": "blocked",
            "blocker": f"fix_effectiveness={record.get('fix_effectiveness')}: "
                       "no executed two-revision run is recorded for this finding",
        })
    return rows


# A ledger row ships in the repository, so it must not carry the absolute path of
# the machine that produced it. A local artefact path is rewritten to its
# repo-relative form; nothing else about the row changes.

def _relativize(value):
    if isinstance(value, str):
        text = value.replace("\\", "/")
        prefix = str(ROOT).replace("\\", "/")
        if text[:len(prefix)].lower() == prefix.lower():
            text = text[len(prefix):].lstrip("/")
        return text.replace("\\", "/")
    if isinstance(value, list):
        return [_relativize(item) for item in value]
    if isinstance(value, dict):
        return {k: _relativize(v) for k, v in value.items()}
    return value


def normalize(row: dict, origin: str) -> dict:
    row = _relativize(row)
    out = {k: v for k, v in row.items() if v not in (None, "", [], {})}
    out.setdefault("candidate_stage", "candidate")
    out["origin"] = out.get("origin") or origin
    # Discovery ledgers record blockers as a list of exact reasons; the merged row
    # carries both, so the `blocked requires a blocker` rule stays enforceable without
    # inventing anything the source row did not say.
    if not out.get("blocker") and out.get("blockers"):
        out["blocker"] = "; ".join(str(b) for b in out["blockers"])
    if out.get("framework") is not None:
        recorded = str(out["framework"])
        folded = framework_key(recorded)
        if folded != recorded:
            out["framework_recorded"] = recorded
        out["framework"] = folded
    return out


def load_input_ledgers() -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    loaded: list[str] = []
    for path in sorted(list(CANDIDATE_DIR.glob("*ledger*.jsonl"))
                       + list(CANDIDATE_DIR.glob("*runs*.jsonl"))):
        batch = _load(path)
        for row in batch:
            rows.append(normalize(row, path.name))
        loaded.append(f"{path.name}:{len(batch)}")
    return rows, loaded


# Stage strength, used only when two sources describe the same candidate: an executed
# verification supersedes an inventory lead, never the other way round. Blocked and
# rejected rows keep their own rank so a later, weaker file cannot erase a failure.
STAGE_RANK = {"candidate": 0, "revision_pair_resolved": 1, "harness_available": 2,
              "vulnerable_run_passed_gate": 3, "fixed_run_passed_gate": 4,
              "qualified": 5, "blocked": -1, "rejected_with_reason": -2}


def merge_rows(recorded: list[dict], discovered: list[dict]) -> dict[str, dict]:
    by_id: dict[str, dict] = {}
    for row in recorded + discovered:
        cid = row["candidate_id"]
        existing = by_id.get(cid)
        if existing is None:
            by_id[cid] = row
            continue
        incoming = STAGE_RANK.get(row.get("candidate_stage"), 0)
        current = STAGE_RANK.get(existing.get("candidate_stage"), 0)
        if incoming <= current:
            # Keep the weaker row's history, but never its stronger-looking fields.
            if row.get("blocker"):
                existing.setdefault("earlier_blocker", row["blocker"])
            existing["source_documents"] = sorted(set(
                (existing.get("source_documents") or [])
                + (row.get("source_documents") or [])
                + [existing.get("origin"), row.get("origin")]))
            continue
        row["source_documents"] = sorted(set(
            (existing.get("source_documents") or [])
            + (row.get("source_documents") or [])
            + [existing.get("origin"), row.get("origin")]))
        if existing.get("blocker"):
            row["superseded_blocker"] = existing["blocker"]
        by_id[cid] = row
    return by_id


def validate(rows: list[dict]) -> list[str]:
    errors = []
    seen: set[str] = set()
    for row in rows:
        cid = row.get("candidate_id")
        if not cid:
            errors.append(f"row without candidate_id: {json.dumps(row)[:120]}")
            continue
        if cid in seen:
            errors.append(f"duplicate candidate_id {cid}")
        seen.add(cid)
        stage = row.get("candidate_stage")
        if stage not in STAGES:
            errors.append(f"{cid}: stage {stage!r} is not in {STAGES}")
            continue
        framework = row.get("framework")
        if framework is not None and framework not in FRAMEWORKS:
            # A version string is not a framework. Diversity is counted by framework,
            # so `hardhat+foundry` or `sui-move (sui 1.48.2...)` would silently split a
            # repository group in two.
            errors.append(f"{cid}: framework {framework!r} is not in {FRAMEWORKS}")
        if row.get("commits_present_offline") is True and row.get("candidate_stage") in (
                "qualified", "vulnerable_run_passed_gate", "fixed_run_passed_gate"):
            if not (row.get("vulnerable_commit") and row.get("fixed_commit")):
                errors.append(f"{cid}: claims offline revisions yet names neither commit")
        if stage in ("blocked", "rejected_with_reason") and not row.get("blocker"):
            errors.append(f"{cid}: {stage} requires a recorded blocker")
        if stage == "qualified":
            missing = [field for field in QUALIFICATION_FIELDS if not row.get(field)]
            if missing:
                errors.append(
                    f"{cid}: claims qualified without "
                    + ", ".join(f"{m} ({QUALIFICATION_FIELDS[m]})" for m in missing))
            # The final invariant, checked rather than asserted in prose: one test,
            # byte-identical, exposed the violation on the vulnerable revision and
            # passed on the fixed revision.
            if row.get("test_sha256") and row.get("test_sha256_fixed_side") and \
                    row["test_sha256"] != row["test_sha256_fixed_side"]:
                errors.append(
                    f"{cid}: qualified but the test bytes differ between the two sides "
                    f"({row['test_sha256'][:12]} vs {row['test_sha256_fixed_side'][:12]})")
            if str(row.get("stage_decision")) not in (
                    "patch_verified", "effective", "VERIFIED_TWO_REVISION"):
                errors.append(f"{cid}: qualified with stage_decision="
                              f"{row.get('stage_decision')!r}")
            rights_ok = (bool(row.get("licence_code") and row.get("rights_reference"))
                         or row.get("rights_status") == "withheld_pending_permission")
            if not rights_ok:
                errors.append(
                    f"{cid}: qualified without a rights position (needs licence_code + "
                    "rights_reference, or rights_status=withheld_pending_permission)")
            index = LADDER.index("qualified")
            for reached in LADDER[1:index]:
                if row.get(f"gate_{reached}") is False:
                    errors.append(f"{cid}: qualified but {reached} was recorded as failed")
    return errors


def summarise(rows: list[dict], errors: list[str], loaded: list[str]) -> dict:
    by_stage = collections.Counter(r.get("candidate_stage") for r in rows)
    repos = collections.Counter(r.get("repository") for r in rows if r.get("repository"))
    qualified_repos = collections.Counter(
        r.get("repository") for r in rows if r.get("candidate_stage") == "qualified")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "scripts/build_prove_ledger.py",
        "stage_vocabulary": list(STAGES),
        "qualification_requirements": QUALIFICATION_FIELDS,
        "input_ledgers": loaded,
        "counts": {
            "candidate_rows": len(rows),
            "by_stage": dict(by_stage),
            "distinct_repositories": len(repos),
            "distinct_repositories_with_a_qualified_task": len(qualified_repos),
            "by_framework": dict(collections.Counter(
                r.get("framework") or "unknown" for r in rows)),
            "by_origin": dict(collections.Counter(r.get("origin", "?") for r in rows)),
        },
        "invariants_violated": errors,
        "pool_target": 50,
        "target_met": by_stage.get("qualified", 0) >= 50,
        "shortfall": max(0, 50 - by_stage.get("qualified", 0)),
        "note": ("a qualified row is one whose identical test exposed the violation on the "
                 "pinned vulnerable revision and passed on the pinned fixed revision; "
                 "candidates, runs and tasks are counted apart"),
    }


def render_markdown(stats: dict, rows: list[dict]) -> str:
    counts = stats["counts"]
    inputs = ", ".join(stats["input_ledgers"]) or "no input ledgers"
    lines = [
        "# VLUN-Prove candidate ledger",
        "",
        f"Generated by `scripts/build_prove_ledger.py` from {inputs}.",
        "",
        f"- candidate rows: {counts['candidate_rows']}",
        f"- by stage: {counts['by_stage']}",
        f"- distinct repositories: {counts['distinct_repositories']} "
        f"({counts['distinct_repositories_with_a_qualified_task']} carrying a qualified task)",
        f"- by framework: {counts['by_framework']}",
        f"- by licence: {counts.get('by_licence', {})}; qualified rows' rights position: "
        f"{counts.get('rights_status_of_qualified', {})} (a BUSL-1.1 or unclassified repo "
        "keeps its harness local: provenance is retained, nothing is redistributed)",
        f"- pool target: {stats['pool_target']} qualified, target met: {stats['target_met']}, "
        f"shortfall: {stats['shortfall']}",
        "",
        "## What a qualified row must carry",
        "",
    ]
    for field, meaning in stats["qualification_requirements"].items():
        lines.append(f"- `{field}` - {meaning}")
    lines += ["", "## Blocked and rejected candidates", ""]
    blockers = collections.Counter(
        (r.get("repository") or "?", r.get("blocker") or "?")
        for r in rows if r.get("candidate_stage") in ("blocked", "rejected_with_reason"))
    if not blockers:
        lines.append("_none recorded_")
    for (repo, blocker), n in sorted(blockers.items(), key=lambda kv: (-kv[1], kv[0]))[:40]:
        lines.append(f"- {n} x `{repo}`: {blocker}")
    lines += ["", "## Invariants", ""]
    lines += ([f"- VIOLATED: {e}" for e in stats["invariants_violated"]] or ["- all checks pass"])
    lines += ["", stats["note"], ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    recorded = seed_from_recorded_evidence()
    discovered, loaded = load_input_ledgers()
    by_id = merge_rows(recorded, discovered)
    rows = sorted(by_id.values(), key=lambda r: r["candidate_id"])
    licence_counts = apply_rights(rows)
    errors = validate(rows)
    stats = summarise(rows, errors, loaded)
    stats["counts"]["by_licence"] = licence_counts
    stats["counts"]["rights_status_of_qualified"] = dict(collections.Counter(
        r.get("rights_status") or "unclassified" for r in rows
        if r.get("candidate_stage") == "qualified"))

    if args.check:
        current = _load(LEDGER) if LEDGER.exists() else []
        if json.loads(json.dumps(rows)) != current:
            log("STALE: derived_prove/candidate_ledger.jsonl -- run: "
                "python scripts/build_prove_ledger.py")
            return 1
        if json.loads(STATS_JSON.read_text(encoding="utf-8")) != stats:
            log(f"STALE: {STATS_JSON}")
            return 1
        log(f"ok: {len(rows)} ledger rows, {len(errors)} invariant violation(s)")
        return 1 if errors else 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(LEDGER, rows)
    write_json(STATS_JSON, stats)
    STATS_MD.write_text(render_markdown(stats, rows), encoding="utf-8", newline="\n")
    if not args.quiet:
        log(f"wrote {len(rows)} ledger rows; stages={stats['counts']['by_stage']}; "
            f"violations={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

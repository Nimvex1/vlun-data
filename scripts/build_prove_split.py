#!/usr/bin/env python3
"""VLUN-Prove: a two-revision proof task, and the split that stays out of the repo.

A prove task asks a model to write the test that demonstrates a finding's impact.
The grader then runs *that same test* against the vulnerable revision, where the
violation must appear, and against the fixed revision, where it must be blocked.
Stage by stage:

    generated -> compiles -> executes -> impact_reproduced -> patch_verified

Two rules make the ladder mean something. A compile or dependency failure stops
the run at the stage it reached — it is never re-labelled as a failed proof. And
`impact_reproduced` requires the *expected assertion* to be the thing that broke:
a test that fails for an unrelated reason (wrong interface, missing fixture, a
gas issue) does not count, even when forge exits non-zero.

Everything the grader needs in order to judge — the fixed revision, the harness
sources, the expected assertion signature — is the answer key, so it is written
to a private location OUTSIDE the repository and never to a path inside it. The
repo publishes the task prompts, the scoring interface, and a SHA-256 commitment
to each private file, so a reader can verify the key did not change after a run
without being able to read it.

Nothing here claims contamination-proof: the split is leakage-audited under the
criteria recorded in `reports/prove_split_interface.json`, and the pool is what
the executed two-revision evidence supports today — not a target number.

    python scripts/build_prove_split.py --home /path/outside/the/repo [--check]
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
from vlun import REPORTS, ROOT, log, write_json  # noqa: E402

SCHEMA = "vlun-prove/1.0"
INTERFACE_JSON = REPORTS / "prove_split_interface.json"
INTERFACE_MD = REPORTS / "prove_split_interface.md"
PRIVATE_DIRNAME = "vlun_prove"
CUTOFF = "2026-10-19"          # evidence available in this tree as of this date
STAGES = ("generated", "compiles", "executes", "impact_reproduced", "patch_verified")
FORBIDDEN_IN_PUBLIC = ("fixed_commit", "expected_assertion", "harness_source",
                       "per_test_status", "expectation")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artefact_text(path: Path) -> str:
    """Run logs are written by different tools; the hardhat capture is UTF-16LE."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in raw[:200]:
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def private_home(home: Path) -> Path:
    resolved = home.resolve()
    root = ROOT.resolve()
    if resolved == root or root in resolved.parents:
        raise SystemExit(
            f"refusing to write the answer key inside the repository: {resolved}\n"
            "the private split must live outside the tracked tree (e.g. "
            "C:/Users/jeet/vlun-private)")
    return resolved / PRIVATE_DIRNAME


def public_leak_check(interface: dict) -> list[str]:
    """No answer-key material may reach the model-facing task list.

    The guard looks at `tasks` (what a model is handed), not at the interface's
    own metadata — the metadata is where the isolation contract *names* the
    fields it withholds, and naming them is not the same as leaking them.
    """
    blob = json.dumps(interface.get("tasks", []), ensure_ascii=False).lower()
    bad = [f"answer-key field {k!r} appears in the model-facing task list"
           for k in FORBIDDEN_IN_PUBLIC if k in blob]
    for task in interface.get("tasks", []):
        for key in ("fixed", "fixed_commit", "harness", "expected_assertion",
                    "per_test_status", "expectation"):
            if key in task:
                bad.append(f"{task.get('task_id')}: task field {key!r} is answer-key material")
    allowed = {t["vulnerable_commit"].lower() for t in interface.get("tasks", [])}
    bad += [f"unexpected 40-hex revision {s[:10]} in the model-facing file"
            for s in set(re.findall(r"\b[0-9a-f]{40}\b", blob)) - allowed]
    return bad


def load_evidence() -> dict:
    ver = json.loads((REPORTS / "verified_experiments.json").read_text(encoding="utf-8"))
    by_id = {e["finding_id"]: e for e in ver.get("experiments", [])
             if e.get("verdict") == "l6_verified_patch"}
    lop = ROOT / "experiments_v3" / "1inch-lop-m01" / "record.json"
    two_side = dict(by_id)
    if lop.exists():
        rec = json.loads(lop.read_text(encoding="utf-8"))
        two_side[rec["finding_id"]] = {
            "finding_id": rec["finding_id"], "framework": "hardhat",
            "record": rec,
            "revisions": {"vulnerable": {"commit": rec["revisions"]["vulnerable"]},
                          "fixed": {"commit": rec["revisions"]["fixed"]}},
            "match_test": None, "artifact": "experiments_v3/1inch-lop-m01",
            "verdict": "l6_verified_patch"}
    return two_side


def registry_index() -> tuple[dict, dict, str | None]:
    """The declared two-revision registry, keyed by finding id.

    Returns (entries, repo specs, blocker). Building it reads test bytes out of
    the pinned local clone, so an absent clone is recorded rather than guessed.
    """
    try:
        import run_verified_experiments as rve  # noqa: E402
        return ({e["finding_id"]: e for e in rve.build_registry()}, rve.REPOS, None)
    except (SystemExit, OSError, RuntimeError, KeyError) as exc:
        return {}, {}, f"registry_unavailable: {type(exc).__name__}: {str(exc)[:120]}"


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def mocha_failures(log_text: str) -> list[str]:
    """Failing mocha titles from a hardhat run log.

    Mocha numbers each failure and puts the suite on the numbered line, the test
    title on the following line, and the error beneath that — so the title is
    taken from the continuation line when there is one.
    """
    text = _strip_ansi(log_text).replace("\x00", "")
    lines = text.splitlines()
    titles: list[str] = []
    for i, line in enumerate(lines):
        m = re.match(r"\s*\d+\)\s+(\S.*)$", line)
        if not m:
            continue
        nxt = next((lines[j] for j in range(i + 1, min(i + 4, len(lines)))
                    if lines[j].strip()), "")
        title = nxt.strip().rstrip(":") if nxt.strip().endswith(":") else m.group(1).strip()
        if title and title not in titles:
            titles.append(title)
    return titles


def assertion_signature(exp: dict) -> dict:
    """What the grader must see break on the vulnerable revision."""
    if exp.get("framework") == "hardhat":
        rec = exp.get("record") or {}
        sig = {"failing_tests": [], "signals": [], "evidence_integrity": [],
               "must_not_be": ["compile_error", "no_tests_ran", "setup_revert"],
               "security_property": rec.get("scenario") or "",
               "expected_failure_summary": ((rec.get("results") or {}).get("vulnerable") or
                                            {}).get("failure"),
               "runner": "hardhat", "runner_implemented_in_grader": False}
        sig["artifact"] = exp.get("artifact")
        for name in ("adapted_test", "vulnerable_log", "fixed_log"):
            entry = (rec.get("files") or {}).get(name) or {}
            p = ROOT / (entry.get("path") or "")
            if not entry.get("path") or not p.exists():
                sig.setdefault("evidence_integrity", []).append(
                    f"{name}: artefact {entry.get('path')!r} not present")
                continue
            actual = sha256_file(p)
            if entry.get("sha256") and entry["sha256"] != actual:
                sig.setdefault("evidence_integrity", []).append(
                    f"{name}: recorded sha256 {entry['sha256'][:12]} != bytes {actual[:12]}")
            sig[f"{name}_sha256"] = actual
            if name == "vulnerable_log":
                titles = mocha_failures(artefact_text(p))
                sig["failing_tests"] = titles
                sig["signals"] = [{"test": t, "forge_reason": None,
                                   "assertion_messages": []} for t in titles]
        return sig
    v = (exp.get("revisions") or {}).get("vulnerable") or {}
    rr = recorded_run(v)
    fails = sorted(t for t, s in (rr.get("per_test_status") or {}).items()
                   if s == "Failure")
    # the report's own observed_failure list spells tests with a trailing `()`;
    # the replayed JSON does not. Both spellings are kept so the grader's expected
    # names line up with whatever a submission's run reports.
    names = sorted({n for t in fails for n in (t, t + "()")})
    sig = {"failing_tests": names,
           "signals": [s for s in rr.get("signals") or [] if s.get("test") in fails],
           "must_not_be": ["compile_error", "no_tests_ran", "setup_revert"],
           "security_property": exp.get("security_property") or "",
           "runner": "foundry",
           "signals_source": rr.get("signals_source"),
           "signals_blocker": rr.get("signals_blocker")}
    return sig


def harness_manifest(spec: dict | None, label: str, commit: str) -> dict:
    """Name and hash the reference test bytes without copying them anywhere.

    The registry holds the actual sources (some of them upstream test code under
    BUSL-1.1), so the answer key records what was run and how to obtain it, not a
    second copy of it.
    """
    rev = ((spec or {}).get("revisions") or {}).get(label) or {}
    harness = rev.get("harness") or {}
    authored = set(rev.get("authored_harness") or [])
    return {
        "repo_key": rev.get("repo_key"),
        "match_path": rev.get("match_path"),
        "expected_status": rev.get("expected_status"),
        "expectation": rev.get("expectation"),
        "files": {name: {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                         "bytes": len(text.encode("utf-8")),
                         "authored_by_this_project": name in authored,
                         "retrieval": (f"scripts/run_verified_experiments.build_registry()"
                                       f" -> {label}.harness[{name!r}]"
                                       if name not in authored else
                                       f"git show {commit} (overlay) + the registry entry")}
                  for name, text in sorted(harness.items())},
    }


def recorded_run(rev: dict) -> dict:
    """The run evidence this project already recorded, in the grader's own shape.

    The summarised report often lost the forge failure reason, so the preserved
    stdout is replayed through the grader's own parser first: the ladder is then
    judged on the same bytes a real submission would be judged on. Where the log
    cannot be parsed, that is recorded as a blocker instead of quietly falling
    back to a thinner signal.
    """
    import prove_grader as G  # noqa: E402
    status = rev.get("per_test_status") or {}
    reason = rev.get("run_failure_reason")
    broken_build = reason in ("compile_error", "dependency_missing", "toolchain_missing")
    out = {"build_rc": 1 if broken_build else 0,
           "dependency_ok": not broken_build,
           "build_failure_reason": reason if broken_build else None,
           "ran_tests": bool(status),
           "per_test_status": status,
           "test_exit_code": rev.get("exit_code"),
           "signals": [{"test": o.get("test"), "forge_reason": o.get("forge_reason"),
                        "assertion_messages": o.get("assertion_messages") or []}
                       for o in (rev.get("observed_failure") or [])],
           "signals_source": "reports/verified_experiments.json summary"}
    log_path = ROOT / (rev.get("artifact") or "") / "stdout.txt"
    if not rev.get("artifact") or not log_path.exists():
        out["signals_blocker"] = "recorded_stdout_absent"
        return out
    text = artefact_text(log_path)
    replay = G.parse_forge_output(text)
    if not replay[0]:
        out["signals_blocker"] = "recorded_stdout_not_parseable"
        return out
    replay_status, replay_signals = replay
    merged: dict[str, dict] = {s.get("test"): dict(s) for s in out["signals"]}
    summary_had_reason = any(s.get("forge_reason") or s.get("assertion_messages")
                             for s in out["signals"])
    for s in replay_signals:
        cur = merged.setdefault(s.get("test"), {"test": s.get("test"),
                                                "forge_reason": None,
                                                "assertion_messages": []})
        cur["forge_reason"] = cur.get("forge_reason") or s.get("forge_reason")
        if s.get("assertion_messages"):
            cur["assertion_messages"] = s["assertion_messages"]
    out.update({"per_test_status": replay_status, "ran_tests": bool(replay_status),
                "signals": [merged[k] for k in sorted(merged)],
                "signals_source": (f"{out['signals_source']} + replayed from "
                                   f"{rev['artifact']}/stdout.txt"),
                "reason_recovered_from_stdout": (
                    not summary_had_reason
                    and any(s.get("forge_reason") or s.get("assertion_messages")
                            for s in replay_signals)),
                "stdout_sha256": sha256_file(log_path)})
    return out


def grader_self_check(evidence: dict) -> dict:
    """Run the published stage rules over the project's own recorded runs.

    This validates the grader's logic, not any model: the submission is the test
    that was actually executed on both revisions when the evidence was made. A
    task that stops short of `patch_verified` here is not a broken task — it says
    the recorded run does not carry the evidence the grader requires.
    """
    import prove_grader as G  # noqa: E402
    reached: dict[str, int] = {}
    recovered: list[bool] = []
    per_task = []
    for fid in sorted(evidence):
        exp = evidence[fid]
        if exp.get("framework") not in (None, "foundry"):
            continue
        revs = exp.get("revisions") or {}
        if not ((revs.get("vulnerable") or {}).get("per_test_status")):
            continue
        vuln_run = recorded_run(revs.get("vulnerable") or {})
        verdict = G.stage_ladder(
            {"files": {"submitted.t.sol": "// recorded reference test"}},
            vuln_run, recorded_run(revs.get("fixed") or {}),
            assertion_signature(exp))
        reached[verdict["stage_reached"]] = reached.get(verdict["stage_reached"], 0) + 1
        recovered.append(bool(vuln_run.get("reason_recovered_from_stdout")))
        per_task.append({"finding_id": fid, "stage_reached": verdict["stage_reached"],
                         "signals_source": vuln_run.get("signals_source"),
                         "signals_blocker": vuln_run.get("signals_blocker"),
                         "reasons": verdict.get("reasons", {})})
    return {"validates": "the grader's stage rules against this project's own recorded runs",
            "is_not_a_model_result": True,
            "tasks_self_checked": len(per_task),
            "stage_reached_distribution": reached,
            "reasons_recovered_by_replaying_stdout": sum(
                1 for r in recovered if r),
            "per_task": per_task}


def build(home: Path) -> tuple[dict, dict]:
    evidence = load_evidence()
    self_check = grader_self_check(evidence)
    detail = self_check.pop("per_task")
    reg, repos, reg_blocker = registry_index()
    tasks, private = [], []
    for fid in sorted(evidence):
        exp = evidence[fid]
        revs = exp.get("revisions") or {}
        v_commit = (revs.get("vulnerable") or {}).get("commit")
        f_commit = (revs.get("fixed") or {}).get("commit")
        if not (v_commit and f_commit):
            continue
        spec = reg.get(fid) or {}
        repo_key = ((spec.get("revisions") or {}).get("vulnerable") or {}).get("repo_key")
        vuln_spec = repos.get(repo_key or "")
        repo_url = getattr(vuln_spec, "url", None)
        framework = exp.get("framework") or getattr(vuln_spec, "framework", None) or "foundry"
        tid = f"prove-{fid.replace('/', '__')}"
        checked = {d["finding_id"]: d["stage_reached"] for d in detail}
        tasks.append({
            "task_id": tid, "finding_id": fid, "framework": framework,
            "repository": repo_url or exp.get("artifact"),
            "self_check_stage_reached": checked.get(fid),
            "vulnerable_commit": v_commit,
            "prompt": (
                "Write a test that demonstrates the impact of this finding against the pinned "
                f"revision `{v_commit}` of the named repository. The test must (a) compile with "
                "the repository's own toolchain, (b) execute, and (c) fail because the claimed "
                "invariant is violated — not because of a setup, interface or gas problem. "
                "Submit the test file(s); the grader runs them unchanged against the same "
                "revision and against a second revision that is not disclosed."),
            "submission_contract": {"files": ["*.t.sol"] if framework == "foundry" else ["*.js"],
                                    "overlay_root": "test/vlun_poc/" if framework == "foundry"
                                    else "test/",
                                    "max_bytes": 200_000},
            "stages": list(STAGES),
            "gradable_by_the_published_grader": framework == "foundry",
            "artifact_reference": exp.get("artifact"),
        })
        sig = assertion_signature(exp)
        sig["security_property"] = (spec.get("security_property")
                                    or sig.get("security_property") or "")
        private.append({
            "task_id": tid, "finding_id": fid, "framework": framework,
            "vulnerable_commit": v_commit, "fixed_commit": f_commit,
            "match_test": exp.get("match_test") or spec.get("match_test"),
            "expected_assertion": sig,
            "expected_fixed_status": "pass",
            "harness": {"registry_declared": bool(spec)},
            "harness": {label: harness_manifest(spec, label,
                                                (revs.get(label) or {}).get("commit"))
                        for label in ("vulnerable", "fixed")},
            "evidence_artifact": exp.get("artifact"),
        })
    interface = {
        "schema_version": SCHEMA,
        "generated_by": "scripts/build_prove_split.py",
        "stages": list(STAGES),
        "stage_rules": {
            "generated": "the submission contains at least one non-empty test file",
            "compiles": "the toolchain build succeeded; a compile or dependency failure "
                        "stops the run at this stage and never counts as a failed proof",
            "executes": "forge (or hardhat) ran at least one test from the submission",
            "impact_reproduced": "on the vulnerable revision the expected test failed with "
                                 "the expected assertion signature, not an unrelated error",
            "patch_verified": "the same test file, unmodified, passed on the second revision",
        },
        "grader_reads_the_assertion_not_the_exit_code": True,
        "grader_runner_coverage": {
            "foundry": "implemented in scripts/prove_grader.py (forge build + forge test)",
            "hardhat": "NOT implemented — the task is recorded, its two-side evidence is "
                       "cited, and the grader refuses to credit a stage it cannot run",
        },
        "isolation": {
            "model_sees": ["task_id", "finding_id", "repository", "vulnerable_commit",
                           "prompt", "submission_contract"],
            "model_must_not_see": ["fixed_commit", "expected_assertion", "harness sources",
                                   "per-test verdicts", "any answer key or hidden test"],
            "answer_key_location": "outside the repository; see commitment hashes below",
        },
        "pool": {
            "tasks_with_two_revisions_executed": len(tasks),
            "by_framework": _count(tasks, "framework"),
            "by_repository": _count(tasks, "repository"),
            "target_claimed": 200,
            "target_met": len(tasks) >= 200,
            "why_smaller": (
                "the pool is bounded by the two-revision evidence that exists in this tree: "
                "seven executed vulnerable/fixed pairs in the v1 layer plus one hardhat "
                "two-side run in the V3.2 layer. Every additional task needs a pinned fixed "
                "revision and a test that was actually run on both sides, so the private "
                "split is recorded at its real size rather than padded to 200."),
        },
        "dates": {"evidence_cutoff_utc": CUTOFF,
                  "note": ("no generation timestamp is recorded: this file must be "
                           "byte-reproducible, and the build time is the commit time")},
        "leakage_audit": {
            "criteria": ["no fixed revision appears in any model-facing file",
                         "no harness source or expected assertion appears in a public file",
                         "tasks sharing one repository are reported as a single group so a "
                         "split cannot be called project-held-out"],
            "project_diversity": _count(tasks, "repository"),
            "not_contamination_proof": True,
            "statement": ("this split is leakage-audited under the criteria above; it is not "
                          "and must not be described as contamination-proof"),
        },
        "tasks": tasks,
        "registry_blocker": reg_blocker,
        "notes": [
            ("the reason a recorded test failed now comes from the `forge --json` entry "
             "(scripts/experiments.py:per_test_reason); the recorder used to read only the "
             "human `[FAIL: …]` line, which does not exist under `--json`, so every recorded "
             "run stored `reason: null`. Already-recorded artefacts are evidence and are not "
             "rewritten — the self-check above recovers the reason by replaying the preserved "
             "stdout through the grader's own parser, and future runs record it directly."),
            (f"{self_check['reasons_recovered_by_replaying_stdout']} of "
             f"{self_check['tasks_self_checked']} recorded runs had their failure reason "
             "recovered from the artefact bytes rather than the summary."),
        ],
        "grader_self_check": self_check,
        "private_commitment": {},
    }
    problems = public_leak_check(interface)
    if problems:
        raise SystemExit("public interface carries answer-key material: "
                         + "; ".join(problems))
    return interface, {"schema_version": SCHEMA, "tasks": private,
                       "grader_self_check_detail": detail}


def _count(rows: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        out[str(r.get(key))] = out.get(str(r.get(key)), 0) + 1
    return dict(sorted(out.items()))


def write_private(home: Path, bundle: dict) -> dict:
    d = private_home(home)
    d.mkdir(parents=True, exist_ok=True)
    key = d / "prove_tasks_private.jsonl"
    key.write_text("".join(json.dumps(t, ensure_ascii=False, sort_keys=True) + "\n"
                           for t in bundle["tasks"]), encoding="utf-8", newline="\n")
    detail = d / "grader_self_check.json"
    detail.write_text(json.dumps(bundle.get("grader_self_check_detail", []),
                                 ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8", newline="\n")
    commitment = {
        "schema_version": SCHEMA,
        "location": "outside the repository (path deliberately not published)",
        "files": {p.name: {"sha256": sha256_file(p),
                           "records": (len(bundle["tasks"]) if p == key else
                                       len(bundle.get("grader_self_check_detail", []))),
                           "bytes": p.stat().st_size}
                  for p in (key, detail)},
        "note": ("publish this commitment before a run so that a later comparison shows "
                 "whether the answer key moved; the key itself stays out of the repo"),
    }
    write_json(d / "COMMITMENT.json", commitment)
    return commitment


def render_md(interface: dict) -> str:
    p = interface["pool"]
    out = ["# VLUN-Prove: scoring interface and private held-out split\n",
           f"Generated by `scripts/build_prove_split.py` (`{interface['schema_version']}`). "
           "The answer key lives outside this repository; the commitment below pins its "
           "bytes by hash.\n",
           "## The stage ladder\n",
           "| stage | credited when |", "|---|---|"]
    for s in interface["stages"]:
        out.append(f"| `{s}` | {interface['stage_rules'][s]} |")
    out.append(f"\nThe grader reads the assertion, not the exit code: "
               f"`grader_reads_the_assertion_not_the_exit_code` = "
               f"{interface['grader_reads_the_assertion_not_the_exit_code']}.\n")
    out.append("## Pool as it actually stands\n")
    out.append(f"- tasks with both revisions executed: **{p['tasks_with_two_revisions_executed']}**")
    out.append(f"- by framework: `{p['by_framework']}`")
    out.append(f"- by repository (one group each): `{p['by_repository']}`")
    out.append(f"- stretch target {p['target_claimed']} met: **{p['target_met']}**")
    out.append(f"- why smaller: {p['why_smaller']}\n")
    out.append("## Isolation\n")
    out.append(f"- the model sees: `{interface['isolation']['model_sees']}`")
    out.append(f"- the model must not see: `{interface['isolation']['model_must_not_see']}`\n")
    out.append("## Leakage audit\n")
    for c in interface["leakage_audit"]["criteria"]:
        out.append(f"- {c}")
    out.append(f"- {interface['leakage_audit']['statement']}\n")
    out.append("## Grader self-check\n")
    sc = interface["grader_self_check"]
    out.append(f"{sc['validates']}. It is **not** a model result. "
               f"{sc['tasks_self_checked']} recorded two-revision runs were replayed through "
               f"`prove_grader.stage_ladder()`; stages reached: "
               f"`{sc['stage_reached_distribution']}`.\n")
    out.append("A task that stops short of `patch_verified` here is not a broken task: it "
               "says the run this project recorded does not carry the evidence the grader "
               "requires (per-task reasons are in the private bundle, because they name the "
               "expected test).\n")
    out.append("## Runner coverage\n")
    for k, v in interface["grader_runner_coverage"].items():
        out.append(f"- `{k}`: {v}")
    out.append("\n## Commitment to the private key\n")
    out.append("```json\n" + json.dumps(interface["private_commitment"], indent=2,
                                        sort_keys=True) + "\n```\n")
    out.append("\n## Notes\n")
    for note in interface.get("notes", []):
        out.append(f"- {note}")
    out.append("\n## Tasks (model-facing)\n")
    for t in interface["tasks"]:
        out.append(f"- `{t['task_id']}` — {t['finding_id']} on "
                   f"{t['repository']} at `{t['vulnerable_commit'][:10]}` "
                   f"({t['framework']})")
    return "\n".join(out) + "\n"


def verified_private_commitment(home: Path) -> dict:
    """Read the existing commitment and re-hash the files it pins (read-only).

    `--check` must not rewrite the answer key: a gate that regenerates the thing
    it is verifying proves nothing.
    """
    d = private_home(home)
    committed = d / "COMMITMENT.json"
    if not committed.exists():
        raise SystemExit(f"no commitment at {committed}; run without --check first")
    doc = json.loads(committed.read_text(encoding="utf-8"))
    drift = []
    for name, meta in (doc.get("files") or {}).items():
        p = d / name
        if not p.exists():
            drift.append(f"{name}: pinned file is gone")
        elif sha256_file(p) != meta.get("sha256"):
            drift.append(f"{name}: bytes changed since the commitment was published")
    if drift:
        raise SystemExit("private split drifted: " + "; ".join(drift))
    return doc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--home", default=os.environ.get("VLUN_PRIVATE_HOME")
                    or str(Path.home() / "vlun-private"),
                    help="private location for the answer key; must be outside this repo "
                         "(or set VLUN_PRIVATE_HOME)")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not Path(args.home).exists() and args.check:
        # Exit 2 is the runner's SKIPPED code: the private split is machine-local,
        # so a machine without it skips rather than fails.
        log(f"SKIPPED: no private split at {args.home}; run without --check to create it")
        return 2

    interface, bundle = build(Path(args.home))
    if args.check:
        interface["private_commitment"] = verified_private_commitment(Path(args.home))
    else:
        interface["private_commitment"] = write_private(Path(args.home), bundle)
    md = render_md(interface)
    js = json.dumps(interface, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        stale = [str(f) for f, t in [(INTERFACE_JSON, js), (INTERFACE_MD, md)]
                 if not f.exists() or f.read_text(encoding="utf-8") != t]
        if stale:
            log("STALE: " + ", ".join(stale))
            return 1
        log(f"prove interface is current ({len(interface['tasks'])} tasks)")
        return 0
    INTERFACE_JSON.write_text(js, encoding="utf-8", newline="\n")
    INTERFACE_MD.write_text(md, encoding="utf-8", newline="\n")
    log(f"prove_split_interface.json: {len(interface['tasks'])} tasks, "
        f"pool target 200 met: {interface['pool']['target_met']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

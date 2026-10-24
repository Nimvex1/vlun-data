#!/usr/bin/env python3
"""Fail the build when a committed artefact carries a machine-local path.

A repository that ships an absolute user-profile path is not portable and not
anonymous: the artefact is tied to the one checkout that produced it, and it
publishes the operator's account name and directory layout to every reader of
the dataset. This gate is the repo-wide guard against that, and it is the
counterpart of `scripts/inventory_rights.py:assert_environment_independent`,
which stops the rights builder from *writing* such a path in the first place.

    python scripts/check_no_machine_paths.py            # human-readable scan
    python scripts/check_no_machine_paths.py --quiet    # one summary line
    python scripts/check_no_machine_paths.py --strict   # also fail on the
                                                        # tracked pending items
    python scripts/check_no_machine_paths.py --write-report
                                                        # reports/machine_path_scan.json

Exit code 0 = pass, 1 = fail.

Design rules:

  * The scanner never reads the *current* machine's home directory. It
    detects paths by SHAPE (a drive letter followed by a user-profile
    directory, a POSIX home directory, a root directory, a temp directory),
    so it fails the same way for every operator and for every CI runner. A
    gate that only knew about `os.path.expanduser("~")` would pass on the
    machine that produced the artefact and fail everywhere else - the exact
    defect this gate exists to catch.
  * Paths are matched after undoing JSON string escaping (a doubled
    backslash becomes a single one), so a path stored inside a JSON string
    is found exactly like the same path stored in a plain text file.
  * The allowlist is narrow: every entry is one (glob, pattern) pair with a
    written reason. `GENUINE` entries are paths that are not the operator's
    at all (a path quoted from an upstream audit report, a redaction
    placeholder, a command example in a document). `PENDING` entries are real
    operator-machine paths that a file owned by another agent still carries;
    they are counted and printed on every run and they fail the build under
    --strict (the list is currently empty - no such file is outstanding).
    `read_only_source_layer_unresolved` is a third state: a real
    operator-machine path inside a pinned source layer, which this scanner
    cannot fix and does not pretend is clean.
  * This file is itself scanned, so it spells no machine path literally. The
    two upstream patterns are assembled from two halves for that reason; a
    comment marks them.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------

# Every pattern is matched against a line whose JSON escaping has been undone
# (a doubled backslash becomes a single one). The lookbehind keeps the
# `https://` form out: its trailing `s:/` is preceded by a word character, so
# the drive-letter pattern does not match it.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # X:\\Users\\<name> and X:\\Documents and Settings\\<name>
    ("windows_user_profile",
     re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]+(?:Users|Documents and Settings)"
                r"[\\/]+[A-Za-z0-9._-]+")),
    # /home/<name> and /Users/<name>
    ("posix_home",
     re.compile(r"(?<![A-Za-z0-9])/(?:home|Users)/[A-Za-z0-9._-]+")),
    # /root/<name>
    ("posix_root",
     re.compile(r"(?<![A-Za-z0-9])/root/[A-Za-z0-9._-]+")),
    # /tmp/<name>/ (a directory, not a bare file name)
    ("posix_tmp",
     re.compile(r"(?<![A-Za-z0-9])/tmp/[A-Za-z0-9._-]+/")),
)

# The redaction placeholder the repository already uses: a committed path
# whose account name was replaced by a fixed token. It names no account, so
# it is not a leak.
REDACTION_TOKEN = "REDACTED"

# The component that names the account, per pattern kind: it is the only part
# of a hit that is machine specific, so the report can show the shape of the
# path without repeating the account name. The index counts path components
# of the match, so a leading separator makes the first component empty.
_NAME_COMPONENT = 2

# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------

# Machine-local trees: git-ignored inputs and agent tooling. They are not
# committed artefacts, they are not scanned, and they are listed here so the
# scope of the gate is explicit rather than implied.
EXCLUDED_PREFIXES = (
    "work/", "V3/clones/", "node_modules/", "__pycache__/", ".git/",
    ".firecrawl/", "nextdata/", ".freebuff/", "brag-output/", "ai/",
    "graphify-out/", ".opencode/", ".claude/", ".swarm/", ".mypy_cache/",
    ".pytest_cache/", ".ruff_cache/", ".idea/", ".vscode/",
)

# The generated trees. A file that is not tracked is only scanned when it
# lives under one of these: a generated report that has not been committed
# yet must still be checked, while an untracked scratch file at the root of
# somebody's working tree is not an artefact of this repository.
GENERATED_ROOTS = (
    "reports/", "derived/", "derived_v2_2/", "derived_v3/", "derived_siblings/",
    "derived_span_tasks/", "derived_rejections/", "derived_poc_queue/",
    "splits_v2/", "splits_v2_2/", "splits_v3/", "jsonl_ml/", "jsonl_v3/",
    "jsonl_v4/", "benchmark/", "experiments/", "experiments_v2_2/",
    "experiments_v3/", "experiments_nonevm/", "experiments_v1_reruns/",
    "distribution_v1/", "datasets/", "training/", "schema/", "Vbeta/",
)

# The report this scanner writes. It describes matches, it does not contain
# them: the account name is replaced by a placeholder before it is written,
# so the ledger itself is free of machine paths and needs no exemption.
SELF_OUTPUT = "reports/machine_path_scan.json"

# The gate itself and the redaction script it is paired with. They are
# scanned whether or not they are tracked, because they spell the path shapes
# the gate looks for.
ALWAYS_SCANNED = (
    "scripts/check_no_machine_paths.py",
    "scripts/redact_machine_paths.py",
)

# ---------------------------------------------------------------------------
# allowlist
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Allow:
    """One allowlist entry: a glob, a path shape and the reason it is allowed.

    `path_glob` is matched against the repository-relative posix path.
    `pattern` is a regular expression matched against the matched text (the
    account name is still in place).
    `match_sha256` pins the exact matched text when the entry covers one
    specific leak: the entry then stops matching as soon as a different
    path appears, so a new machine path in the same file is an operator leak
    again instead of riding along under an old entry.
    """

    path_glob: str
    pattern: str
    category: str          # GENUINE | PENDING | read_only_source_layer_unresolved
    reason: str
    owner: str = ""        # for PENDING: who owns the file
    required_change: str = ""
    match_sha256: str = ""

    def matches(self, rel: str, match: str) -> bool:
        if not fnmatch.fnmatch(rel, self.path_glob):
            return False
        if self.match_sha256:
            digest = hashlib.sha256(match.encode("utf-8")).hexdigest()
            if digest != self.match_sha256:
                return False
        return re.search(self.pattern, match) is not None


# The two upstream patterns are assembled from two halves because this file
# is scanned by this scanner: written out in one piece, the allowlist itself
# would contain the very path shapes it is meant to describe.
_UPSTREAM_CAIRO_RE = r"^/home/(?:projects|NM-0051-GYROSCOPE|nethermind-audits|venv-3\.9)"
_UPSTREAM_REPO_RE = r"^/" + r"root/contracts"
_DOC_TMP_RE = r"^/" + r"tmp/fresh"

# GENUINE: the path is not the operator's machine at all.
ALLOWLIST: tuple[Allow, ...] = (
    Allow(
        path_glob="*",
        pattern=r"(?:^|[\\/])REDACTED(?:[\\/]|$)",
        category="GENUINE",
        reason="redaction placeholder: the account name of a local report was "
               "replaced by the fixed token REDACTED before the file was "
               "committed (see `git log -S 'Users/REDACTED'`). It names no "
               "account and no machine.",
    ),
    Allow(
        path_glob="derived_v3/normalization_overlay.jsonl",
        pattern=_UPSTREAM_CAIRO_RE,
        category="GENUINE",
        reason="upstream quote: these are file paths that appear inside a "
               "third-party audit report (Cairo/Aave, Gyroscope, nethermind "
               "royco-boosts) and are preserved verbatim as evidence of what "
               "the upstream text said. They are not paths on any machine that "
               "built this repository.",
    ),
    Allow(
        path_glob="Vbeta/*",
        pattern=_UPSTREAM_REPO_RE,
        category="GENUINE",
        reason="upstream quote: the segment is part of a GitHub URL of the "
               "sherlock-audit 2024-02-perennial-v2-3 repository, i.e. a path "
               "inside the audited repository, not a local path.",
    ),
    Allow(
        path_glob="improve.md",
        pattern=_DOC_TMP_RE,
        category="GENUINE",
        reason="documented command example: the document instructs the "
               "reader to clone into a temporary directory; it is not a path "
               "on the machine that wrote the document.",
    ),
)

# PENDING: a real operator-machine path that a file owned by another agent
# still carries. Each entry names the owner and the change that clears it.
# They are counted and printed on every run; --strict turns them into a
# failure so the outstanding work cannot be forgotten.
#
# The tuple is currently EMPTY: the one entry it used to hold named a report
# whose generator now writes a repository-relative path, so the leak is gone.
# A stale entry would claim outstanding work that does not exist and would
# give a file a permanent pass, so it is removed instead of kept.
PENDING: tuple[Allow, ...] = ()

# ---------------------------------------------------------------------------
# the read-only source layers
# ---------------------------------------------------------------------------

# The layers this repository treats as a pinned source of record. Their bytes
# ARE the layer: a reader has to be able to check a row against exactly what
# was produced, so a path inside one of them is REPORTED, never rewritten.
#
# Why the scanner does not redact them:
#
#   A path in `jsonl_ml/` is not a formatting problem, it is a stale layer.
#   The layer was produced by a generator that recorded the operator's local
#   clone path. Changing those bytes in place would make the layer no longer
#   the thing its own generator produced, and its digests would no longer
#   describe what was produced - which is the one property a pinned source
#   layer exists to have. The fix is a REBUILD of the layer with a
#   repository-relative resolved path, not an edit of the committed bytes.
#
# What a human has to do:
#
#   `scripts/build_ml_ingest.py` now records the path as cited (and the
#   local report path with the account component replaced by the
#   repository's redaction token), and `scripts/run_ml_pocs.py` no longer
#   defaults to a home directory. Rebuilding `jsonl_ml/` through those
#   generators on a machine that has the audited trees therefore produces a
#   layer with no machine path in it; commit that rebuild and the entries
#   below become stale, which the gate reports until they are removed.
#
# The entries pin the exact matched text by digest, so a NEW machine path in
# these layers is an ordinary operator leak again and fails the build.
READ_ONLY_SOURCE_LAYERS = (
    "jsonl/",
    "jsonl_ml/",
    "jsonl_v3/",
)

# The category name. These hits are real machine paths that are still in the
# repository: they are named, counted and reported, never counted as clean.
READ_ONLY_CATEGORY = "read_only_source_layer_unresolved"

READ_ONLY: tuple[Allow, ...] = (
    Allow(
        path_glob="jsonl_ml/*",
        pattern=r".",
        category=READ_ONLY_CATEGORY,
        match_sha256=("3870ca2e9bb605f2bc1cbdb75af66b90036b72da18784a7123"
                      "681316dace625b"),
        reason="unresolved leak in a read-only source layer: the ML-layer rows "
               "embed the operator's absolute report path, interpreter path "
               "or command line, and the layer is a pinned source of record "
               "whose bytes may not be rewritten in place. It is reported "
               "here, per file, instead of being silently ignored.",
        owner="owner of jsonl_ml/ (a read-only source layer)",
        required_change="rebuild jsonl_ml/ from the upstream commit with a "
                        "repository-relative resolved path "
                        "(scripts/build_ml_ingest.py records the path as "
                        "cited), then commit the rebuilt layer and remove "
                        "this entry.",
    ),
)

# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    file: str
    line: int
    column: int
    kind: str
    match: str
    category: str
    reason: str
    owner: str = ""
    required_change: str = ""

    @property
    def leak(self) -> bool:
        return self.category == "OPERATOR_LEAK"

    @property
    def unresolved_source_layer(self) -> bool:
        return self.category == READ_ONLY_CATEGORY

    def to_json(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            # The account name is replaced before the match is written out,
            # so the ledger never contains a machine path itself. The digest
            # pins the exact text that was found.
            "match": redact_name(self.match, self.kind),
            "match_sha256": hashlib.sha256(self.match.encode("utf-8")).hexdigest(),
            "category": self.category,
            "reason": self.reason,
            "owner": self.owner,
            "required_change": self.required_change,
        }


def redact_name(match: str, kind: str) -> str:
    """Replace the account-name component of a matched path with a token."""
    sep = "\\" if "\\" in match else "/"
    parts = match.split(sep)
    if len(parts) <= _NAME_COMPONENT:
        return match
    parts[_NAME_COMPONENT] = "<user>"
    return sep.join(parts)


def classify(rel: str, kind: str, match: str) -> tuple[str, str, str, str]:
    """Return (category, reason, owner, required_change) for one match."""
    for allow in list(ALLOWLIST) + list(PENDING) + list(READ_ONLY):
        if allow.matches(rel, match):
            return (allow.category, allow.reason, allow.owner,
                    allow.required_change)
    return ("OPERATOR_LEAK",
            "absolute path of a machine-local account directory: it ties the "
            "artefact to the checkout that produced it and publishes the "
            "account name",
            "", "")


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------


def _git(*args: str) -> list[str]:
    try:
        proc = subprocess.run(["git", *args], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=300,
                              errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [x for x in proc.stdout.split("\0") if x]


def excluded(rel: str) -> bool:
    return any(rel == pre[:-1] or rel.startswith(pre) for pre in EXCLUDED_PREFIXES)


def candidate_files() -> list[str]:
    """Every file the gate looks at: tracked files plus untracked files that
    are not git-ignored (a freshly generated report is not tracked yet)."""
    seen: set[str] = set()
    for rel in _git("ls-files", "-z"):
        seen.add(rel)
    for rel in _git("ls-files", "--others", "--exclude-standard", "-z"):
        # An untracked file is only an artefact of this repository when it
        # sits under a generated tree; anything else is a scratch file.
        if any(rel.startswith(root) for root in GENERATED_ROOTS):
            seen.add(rel)
    # The gate's own two files are always scanned, tracked or not: they spell
    # the path shapes the gate looks for (in an allowlist and in a redaction
    # pattern), so they have to hold themselves to the rule from the moment
    # they exist, not from the moment they are committed.
    seen.update(ALWAYS_SCANNED)
    out = []
    for rel in sorted(seen):
        if rel == SELF_OUTPUT or excluded(rel):
            continue
        if (ROOT / rel).is_file():
            out.append(rel)
    return out


def scan_files(paths: list[str]) -> list[Finding]:
    """Scan the given repository-relative paths and classify every hit."""
    findings: list[Finding] = []
    for rel in paths:
        try:
            raw = (ROOT / rel).read_bytes()
        except OSError:
            continue
        text = raw.decode("utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            # Undo JSON string escaping so a path inside a JSON string is
            # found exactly like the same path in a plain text file.
            probe = line.replace("\\\\", "\\")
            found: list[tuple[str, int, int, str]] = []
            for kind, pattern in PATTERNS:
                for m in pattern.finditer(probe):
                    found.append((kind, m.start(), m.end(), m.group(0)))
            # One path can match two patterns (a drive-letter form also
            # contains the POSIX user-profile shape). Keep the longest match
            # per overlapping span so a path is counted once.
            found.sort(key=lambda x: (x[1], -(x[2] - x[1])))
            kept: list[tuple[str, int, int, str]] = []
            for kind, start, end, text in found:
                if any(start < k[2] and k[1] < end for k in kept):
                    continue
                kept.append((kind, start, end, text))
            for kind, start, _end, match in kept:
                category, reason, owner, change = classify(rel, kind, match)
                findings.append(Finding(
                    file=rel, line=lineno, column=start + 1,
                    kind=kind, match=match, category=category,
                    reason=reason, owner=owner, required_change=change))
    findings.sort(key=lambda f: (f.file, f.line, f.column, f.kind))
    return findings


def scan(paths: list[str] | None = None) -> list[Finding]:
    return scan_files(paths if paths is not None else candidate_files())


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def build_report(findings: list[Finding], files: list[str]) -> dict:
    by_category: dict[str, int] = {}
    by_file: dict[str, int] = {}
    unresolved_by_file: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        if f.leak:
            by_file[f.file] = by_file.get(f.file, 0) + 1
        if f.unresolved_source_layer:
            unresolved_by_file[f.file] = unresolved_by_file.get(f.file, 0) + 1
    return {
        "generated_by": "scripts/check_no_machine_paths.py",
        "scanned_files": len(files),
        "findings": len(findings),
        "by_category": dict(sorted(by_category.items())),
        "operator_leak_files": dict(sorted(by_file.items())),
        "pending_by_owner": sorted({
            f.owner for f in findings if f.category == "PENDING" and f.owner}),
        "read_only_source_layer_unresolved": {
            "category": READ_ONLY_CATEGORY,
            "layers": list(READ_ONLY_SOURCE_LAYERS),
            "total": sum(unresolved_by_file.values()),
            "by_file": dict(sorted(unresolved_by_file.items())),
            "why_not_auto_redacted": (
                "the bytes of a pinned source layer ARE the layer: changing "
                "them would break the property the layer exists to have, so "
                "the leak is reported here instead of being rewritten. A "
                "human rebuilds the layer from the upstream commit with a "
                "repository-relative resolved path."),
            "what_a_human_must_do": (
                "rebuild the layer through its generator "
                "(scripts/build_ml_ingest.py records the path as cited), "
                "commit the rebuilt layer, then remove the matching entry "
                "from READ_ONLY."),
        },
        "allowlist": [
            {"path_glob": a.path_glob, "category": a.category,
             "reason": a.reason, "owner": a.owner,
             "required_change": a.required_change}
            for a in list(ALLOWLIST) + list(PENDING) + list(READ_ONLY)
        ],
        "hits": [f.to_json() for f in findings],
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--quiet", action="store_true",
                    help="print one summary line only")
    ap.add_argument("--strict", action="store_true",
                    help="also fail on the tracked pending items")
    ap.add_argument("--write-report", action="store_true",
                    help="write reports/machine_path_scan.json")
    ap.add_argument("--json", action="store_true",
                    help="print the report as JSON on stdout")
    args = ap.parse_args(argv)

    files = candidate_files()
    findings = scan_files(files)
    leaks = [f for f in findings if f.leak]
    pending = [f for f in findings if f.category == "PENDING"]
    genuine = [f for f in findings if f.category == "GENUINE"]
    unresolved = [f for f in findings if f.unresolved_source_layer]
    unresolved_by_file: dict[str, int] = {}
    for f in unresolved:
        unresolved_by_file[f.file] = unresolved_by_file.get(f.file, 0) + 1

    if args.write_report:
        out = ROOT / SELF_OUTPUT
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(build_report(findings, files),
                                  ensure_ascii=False, indent=2,
                                  sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(build_report(findings, files), ensure_ascii=False,
                         indent=2, sort_keys=True))
    elif not args.quiet:
        print(f"scanned {len(files)} files")
        print(f"  operator leaks : {len(leaks)}")
        print(f"  pending        : {len(pending)}")
        print(f"  genuine        : {len(genuine)}")
        print(f"  {READ_ONLY_CATEGORY}: {len(unresolved)}")
        for f in leaks:
            print(f"  LEAK {f.file}:{f.line}: {f.kind} "
                  f"{redact_name(f.match, f.kind)!r}")
        for f in pending:
            print(f"  PENDING {f.file}:{f.line}: {f.kind} "
                  f"{redact_name(f.match, f.kind)!r} ({f.owner})")
        for rel in READ_ONLY_SOURCE_LAYERS:
            hits = sum(n for path, n in unresolved_by_file.items()
                       if path.startswith(rel))
            print(f"  {READ_ONLY_CATEGORY} {rel}: {hits} hit(s)")
        for rel, n in sorted(unresolved_by_file.items()):
            print(f"    {rel}: {n} hit(s) - {unresolved[0].required_change}")
    else:
        print(f"files={len(files)} leaks={len(leaks)} pending={len(pending)} "
              f"genuine={len(genuine)} "
              f"{READ_ONLY_CATEGORY}={len(unresolved)}")

    if leaks:
        return 1
    if args.strict and (pending or unresolved):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

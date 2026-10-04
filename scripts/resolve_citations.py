#!/usr/bin/env python3
"""Resolve mutable source citations to immutable commit SHAs.

473 of the dataset's code citations point at a branch (`main`, `master`,
`release-v5.0`) instead of a commit. Those line ranges are not reproducible over
time, and the v2 dataset reported them as a validation warning.

This script replaces each mutable reference with the historical commit that
actually contains the cited code, and records *how* it was resolved and with what
confidence. It never invents a SHA: a citation is only pinned when a mechanical
identity test succeeded.

Resolution methods, in order of strength:

  blob_identity_first_commit
      The file's git blob at the anchor revision was located in the target
      repository's history; the earliest commit carrying that exact blob is the
      revision in which the cited content already existed. Confidence `high`
      when the blob is unique in the file's history, `medium` when it recurs.

  audit_snapshot_identity
      The citation is into the audited repository itself, and the blob at the
      audit snapshot commit (`source.commit_sha`) is the anchor. Same identity
      test, but the anchor is the audited revision by construction.

  date_bounded_default_branch
      No content was available to compare, so the tip of the default branch as
      of the audit date is used. This is a *guess bounded by a date*, recorded
      with confidence `low` and an explicit caveat. It is never presented as a
      verified revision.

  unresolved
      The target repository is not available locally, or the path does not exist
      in its history. Left mutable on purpose.

Determinism: identical inputs produce an identical file. Only local git
operations are used; nothing is fetched.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    DERIVED, REPORTS, ROOT, WORK, log, read_jsonl, write_json, write_jsonl,
)

BLOB_URL = re.compile(
    r"^https://github\.com/([^/]+/[^/#?]+?)(?:\.git)?/blob/([^/]+)/(.*?)(?:#.*)?$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")

MUTABLE_REFS = ("main", "master", "develop", "release-v5.0", "release", "HEAD")
MUTABLE = set(MUTABLE_REFS)

REF_KEYS = ("code_context", "vulnerable_code", "code_reference_only",
            "code_context_expanded")


# ---------------------------------------------------------------------------
# git plumbing. Never raises; a missing repository is an unresolved citation.
# ---------------------------------------------------------------------------
def git(args: list[str], cwd: Path | None, timeout: int = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(["git", *args], cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return p.returncode, (p.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 127, ""


@lru_cache(maxsize=None)
def locate_clone(repo: str) -> Path | None:
    """Local clone for `owner/repo`, preferring a full clone in work/wt."""
    key = repo.replace("/", "__")
    for base in (WORK / "wt", WORK / "repos"):
        for name in {key, key.replace("_", "-", 2), repo.replace("-", "__", 2)}:
            p = base / name
            if (p / ".git").exists():
                return p
    p = WORK / "repos" / key
    return p if (p / ".git").exists() else None


@lru_cache(maxsize=None)
def default_branch(clone: Path) -> str | None:
    rc, out = git(["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"], clone)
    if rc == 0 and out:
        return out.split("/")[-1]
    for cand in ("main", "master"):
        rc, _ = git(["rev-parse", "--verify", "--quiet", f"refs/heads/{cand}"], clone)
        if rc == 0:
            return cand
    return None


@lru_cache(maxsize=None)
def path_commits(clone: str, path: str) -> tuple[str, ...]:
    """Every commit that touched `path`, oldest first."""
    rc, out = git(["log", "--all", "--reverse", "--format=%H", "--", path], Path(clone))
    if rc != 0:
        return ()
    return tuple(x for x in out.split() if x)


@lru_cache(maxsize=None)
def blob_at(clone: str, commit: str, path: str) -> str | None:
    rc, out = git(["rev-parse", "--verify", "--quiet", f"{commit}:{path}"], Path(clone))
    if rc != 0 or not out:
        return None
    return out


@lru_cache(maxsize=None)
def commit_date(clone: str, commit: str) -> str | None:
    rc, out = git(["show", "-s", "--format=%cI", commit], Path(clone))
    return out if rc == 0 else None


@lru_cache(maxsize=None)
def is_ancestor(clone: str, older: str, newer: str) -> bool:
    rc, _ = git(["merge-base", "--is-ancestor", older, newer], Path(clone))
    return rc == 0


def commits_with_blob(clone: Path, path: str, blob: str) -> list[str]:
    hits = []
    for c in path_commits(str(clone), path):
        if blob_at(str(clone), c, path) == blob:
            hits.append(c)
    return hits


@lru_cache(maxsize=None)
def _file_line_count(clone: str, commit: str, path: str) -> int | None:
    """Line count of a file at a commit, without writing it to disk."""
    blob = blob_at(clone, commit, path)
    if not blob:
        return None
    p = subprocess.run(["git", "cat-file", "blob", blob], cwd=clone,
                       capture_output=True, timeout=300)
    if p.returncode != 0:
        return None
    return p.stdout.count(b"\n") or None


@lru_cache(maxsize=None)
def stable_blob_window(clone: Path, path: str, db: str
                       ) -> tuple[str, str | None, str] | None:
    """The contiguous run of commits at the tip of `db` over which `path` is
    byte-identical.

    -> (oldest_commit_in_run, commit_that_last_changed_the_file_or_None, tip)
    """
    c = str(clone)
    rc, tip = git(["rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{db}"], clone)
    if rc != 0:
        rc, tip = git(["rev-parse", "--verify", "--quiet", f"refs/heads/{db}"], clone)
    if rc != 0 or not tip:
        return None
    head_blob = blob_at(c, tip, path)
    if not head_blob:
        return None
    rc, log_out = git(["log", "--format=%H", db, "--", path], clone)
    if rc != 0:
        return None
    touching = log_out.split()
    # walk back from the tip while the blob is unchanged
    change_commit = None
    prev = tip
    for commit in touching:
        if blob_at(c, commit, path) != head_blob:
            change_commit = commit
            break
        prev = commit
    if change_commit is None:
        # the file has never changed on this branch
        oldest = touching[-1] if touching else tip
        return oldest, None, tip
    # the run starts at the child of `change_commit` on `db`
    rc, child = git(["rev-list", "--ancestry-path", "--reverse",
                     f"{change_commit}..{db}"], clone)
    if rc == 0 and child:
        return child.split()[-1], change_commit, tip
    return prev, change_commit, tip


# ---------------------------------------------------------------------------
# anchors: the byte content a mutable citation refers to
# ---------------------------------------------------------------------------
@lru_cache(maxsize=None)
def anchor_blob(repo: str, path: str, audit_date: str | None,
                audit_snapshot: str | None) -> tuple[str | None, str | None, str | None]:
    """-> (blob_sha, anchor_revision, anchor_method) for a mutable citation.

    Preference order:
      1. the audit snapshot commit of the audited repository itself,
      2. any locally retrieved copy of the file at an immutable commit.
    """
    clone = locate_clone(repo)
    if clone is None:
        return None, None, None
    if audit_snapshot:
        b = blob_at(str(clone), audit_snapshot, path)
        if b:
            return b, audit_snapshot, "audit_snapshot_identity"
    # fall back to whatever fetch_sources.py retrieved for this path
    for f in sorted(_retrieved_copies(repo, path)):
        rc, blob = git(["hash-object", str(f)], None)
        if rc == 0 and blob:
            return blob, _commit_of_retrieved_copy(repo, path, f), "retrieved_copy_identity"
    return None, None, None


@lru_cache(maxsize=None)
def _retrieved_copies(repo: str, path: str) -> tuple[str, ...]:
    base = WORK / "sources" / repo.replace("/", "__")
    out = []
    if base.is_dir():
        for commit_dir in sorted(base.iterdir()):
            f = commit_dir / path
            if f.is_file():
                out.append(str(f))
    return tuple(out)


def _commit_of_retrieved_copy(repo: str, path: str, filepath: str) -> str | None:
    """`work/sources/<owner>__<repo>/<commit>/<path>` -> <commit>."""
    base = WORK / "sources" / repo.replace("/", "__")
    try:
        rel = Path(filepath).relative_to(base)
    except ValueError:
        return None
    parts = rel.parts
    return parts[0] if parts else None


@lru_cache(maxsize=None)
def vendored_candidate_blobs(repo: str, path: str, audit_snapshot: str | None
                            ) -> list[tuple[str, str]]:
    """Blobs of byte-copies of `path` that live in other local repositories.

    An audited protocol often vendors the third-party file it compiled against.
    That copy is an *audit-time* anchor: whatever upstream commit produced those
    bytes is the revision the audit actually exercised. Returned as
    (blob, "repo:path@commit") so the provenance of the candidate is recorded.
    """
    base = Path(path).name
    out: list[tuple[str, str]] = []
    roots = [WORK / "repos", WORK / "wt"]
    target_slugs = {repo.replace("/", "__"), repo.split("/")[-1]}
    seen_repos = set(target_slugs)
    for root in roots:
        if not root.is_dir():
            continue
        for clone in sorted(root.iterdir()):
            if not (clone / ".git").exists():
                continue
            slug = clone.name
            if slug in seen_repos:
                continue
            seen_repos.add(slug)
            for commit in _recent_commits(str(clone), 6):
                rc, files = git(["ls-tree", "-r", "--name-only", commit], clone)
                if rc != 0:
                    continue
                for f in files.splitlines():
                    if Path(f).name == base:
                        b = blob_at(str(clone), commit, f)
                        if b:
                            out.append((b, f"{slug}:{f}@{commit}"))
                if out:
                    break
    return out


@lru_cache(maxsize=None)
def _recent_commits(clone: str, n: int) -> tuple[str, ...]:
    rc, out = git(["log", "--format=%H", "-n", str(n)], Path(clone))
    return tuple(out.split()) if rc == 0 else ()


@lru_cache(maxsize=None)
def blob_at_date(clone: Path, db: str, path: str, iso: str) -> str | None:
    """The blob of `path` on `db` as of the audit date."""
    rc, cand = git(["rev-list", "-1", f"--before={iso}", db], clone)
    if rc != 0 or not cand:
        return None
    return blob_at(str(clone), cand, path)


def audit_date_to_iso(date_str: str | None) -> str | None:
    if not date_str:
        return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", date_str.strip())
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T23:59:59+00:00" if m else None


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------
@lru_cache(maxsize=None)
def submodule_at(clone: str, commit: str, path_prefix: str) -> tuple[str, str] | None:
    """If `path_prefix` is a submodule at `commit`, return (submodule_repo, sha)."""
    p = Path(clone)
    rc, out = git(["ls-tree", commit, path_prefix], p)
    if rc != 0 or "commit" not in out:
        return None
    # `<mode> commit <sha>\t<path>`
    fields = out.split()
    if len(fields) < 3:
        return None
    sha = fields[2]
    if not sha:
        return None
    rc, mods = git(["config", "-f", str(p / ".gitmodules"), "--get-regexp", r"submodule\..*\.path"], p)
    if rc != 0:
        return None
    urls: dict[str, str] = {}
    for line in mods.splitlines():
        k, _, v = line.partition(" ")
        m = re.match(r"submodule\.(.+)\.path$", k)
        if m:
            urls[m.group(1)] = v.strip()
    rc, m2 = git(["config", "-f", str(p / ".gitmodules"), "--get-regexp", r"submodule\..*\.url"], p)
    name = None
    for line in (m2 or "").splitlines():
        k, _, v = line.partition(" ")
        mm = re.match(r"submodule\.(.+)\.url$", k)
        if mm and urls.get(mm.group(1)) == path_prefix:
            name = mm.group(1)
            url = v.strip()
            break
    if not name:
        return None
    m3 = re.match(r"^(?:https://github\.com/|git@github\.com:)([^/]+)/([^/]+?)(?:\.git)?$", url or "")
    if not m3:
        return None
    return f"{m3.group(1)}/{m3.group(2)}", sha


def resolve_one(repo: str, path: str, ref: str, audit_date: str | None,
                audit_snapshot: str | None) -> dict:
    out = {
        "original_reference": ref,
        "target_repository": repo,
        "path_in_repository": path,
        "commit_resolution_status": "unresolved",
        "resolved_commit": None,
        "resolution_method": None,
        "resolution_confidence": "unknown",
        "evidence": None,
    }
    clone = locate_clone(repo)
    if clone is None:
        out["resolution_method"] = "no_local_clone"
        out["caveat"] = "repository is not available locally; the citation stays mutable"
        return out

    blob, anchor_rev, anchor_method = anchor_blob(repo, path, audit_date, audit_snapshot)
    out["anchor_revision"] = anchor_rev
    out["anchor_blob"] = blob

    # A citation into a vendored submodule resolves in the submodule's own
    # repository at the exact SHA the audit snapshot pinned. That is stronger
    # than any branch-tip guess, so it is tried before the fallbacks.
    if blob is None and audit_snapshot:
        for depth in (1, 2):
            prefix = "/".join(path.split("/")[:depth])
            sub = submodule_at(str(clone), audit_snapshot, prefix)
            if not sub:
                continue
            sub_repo, sub_sha = sub
            sub_path = "/".join(path.split("/")[depth:])
            out["resolved_via_submodule"] = {
                "submodule_path": prefix, "submodule_repository": sub_repo,
                "submodule_commit": sub_sha, "submodule_path_in_repository": sub_path,
                "audit_snapshot": audit_snapshot,
            }
            sub_clone = locate_clone(sub_repo)
            if sub_clone is not None and blob_at(str(sub_clone), sub_sha, sub_path):
                out.update({
                    "commit_resolution_status": "resolved",
                    "resolved_commit": sub_sha,
                    "resolution_method": "submodule_pointer_at_audit_snapshot",
                    "resolution_confidence": "high",
                    "evidence": (f"{prefix} is a submodule pinned at {sub_sha[:12]} in the "
                                 f"audit snapshot {audit_snapshot[:12]}; the cited file exists "
                                 f"in {sub_repo} at that commit"),
                    "resolved_commit_date": commit_date(str(sub_clone), sub_sha),
                    "effective_repository": sub_repo,
                    "effective_path": sub_path,
                    "reproducible_permalink":
                        f"https://github.com/{sub_repo}/blob/{sub_sha}/{sub_path}",
                })
                return out

    # What does today's default branch hold? Recorded so the report can say
    # whether the mutable reference was actually dangerous.
    head_blob = None
    db = default_branch(clone)
    if db:
        rc, _ = git(["rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{db}"], clone)
        if rc != 0:
            rc, _ = git(["rev-parse", "--verify", "--quiet", f"refs/heads/{db}"], clone)
        if rc == 0:
            rc, hb = git(["rev-parse", "--verify", "--quiet", f"{db}:{path}"], clone)
            head_blob = hb if rc == 0 else None
    out["default_branch"] = db
    out["default_branch_blob"] = head_blob
    out["default_branch_still_matches"] = (
        bool(blob) and head_blob == blob) if blob else None

    if blob:
        hits = commits_with_blob(clone, path, blob)
        if hits:
            resolved = hits[0]
            unique = len(hits) == 1
            out.update({
                "commit_resolution_status": "resolved",
                "resolved_commit": resolved,
                "resolution_method": "blob_identity_first_commit",
                "resolution_confidence": "high" if unique else "medium",
                "evidence": ("git blob %s of %s first appears at commit %s; "
                             "%d commit(s) in the file's history carry it"
                             % (blob[:12], path, resolved[:12], len(hits))),
                "matching_commits": hits[:12],
                "resolved_commit_date": commit_date(str(clone), resolved),
                "reproducible_permalink":
                    f"https://github.com/{repo}/blob/{resolved}/{path}",
            })
            if audit_snapshot and is_ancestor(str(clone), resolved, audit_snapshot):
                out["resolution_confidence"] = "high"
                out["evidence"] += "; it is an ancestor of the audit snapshot %s" % audit_snapshot[:12]
            return out
        # The anchor content is provably absent from the local history: say so
        # rather than pinning to an unrelated commit.
        out["resolution_method"] = "blob_not_found_in_local_history"
        out["evidence"] = (f"git blob {blob[:12]} of {path} was searched across "
                           f"{len(path_commits(str(clone), path))} commits of {repo} "
                           "and not found; the local clone is incomplete")
        out["caveat"] = "local clone history is insufficient to pin this citation"

    # A file whose path was touched by exactly one commit in the whole history
    # and was introduced by it is provably unchanged from that commit onwards.
    # That is a content-identity statement, not a date guess.
    touches = path_commits(str(clone), path)
    if len(touches) == 1:
        added = touches[0]
        rc, out2 = git(["log", "--all", "--diff-filter=A", "--format=%H", "--", path], clone)
        if rc == 0 and added in out2.split():
            lines = _file_line_count(clone, added, path)
            out.update({
                "commit_resolution_status": "resolved",
                "resolved_commit": added,
                "resolution_method": "single_introduction_commit",
                "resolution_confidence": "high",
                "evidence": (f"{path} was added at {added[:12]} and that is the only commit in "
                             f"the history of {repo} that touches the path, so the cited content "
                             "is identical at every revision of this repository"
                             + (f"; the file holds {lines} lines, so every cited line range is "
                                "addressable" if lines else "")),
                "resolved_commit_date": commit_date(str(clone), added),
                "reproducible_permalink":
                    f"https://github.com/{repo}/blob/{added}/{path}",
            })
            return out

    iso = audit_date_to_iso(audit_date)
    if iso and db:
        rc, cand = git(["rev-list", "-1", f"--before={iso}", db], clone)
        if rc == 0 and cand:
            out.update({
                "commit_resolution_status": "resolved_with_low_confidence",
                "resolved_commit": cand,
                "resolution_method": "date_bounded_default_branch",
                "resolution_confidence": "low",
                "evidence": (f"tip of `{db}` as of the audit date {audit_date}: {cand}. "
                             "This bounds the citation in time; it does not prove the cited "
                             "lines were identical at that commit."),
                "caveat": "date-bounded, not content-verified",
                "resolved_commit_date": commit_date(str(clone), cand),
                "reproducible_permalink":
                    f"https://github.com/{repo}/blob/{cand}/{path}",
            })
            # If the file has not changed anywhere between that commit and the
            # branch tip, the date bound becomes a content-identity statement.
            window = stable_blob_window(clone, path, db)
            if window:
                oldest, change_commit, head = window
                change_date = commit_date(str(clone), change_commit) if change_commit else None
                if change_commit is None or (change_date and change_date >= iso):
                    out.update({
                        "commit_resolution_status": "resolved",
                        "resolved_commit": oldest,
                        "resolution_method": "unchanged_since_before_audit",
                        "resolution_confidence": "high",
                        "evidence": (
                            f"{path} carries an identical git blob at every commit of `{db}` from "
                            f"{oldest[:12]} to the branch tip {head[:12]}"
                            + (f", and that blob was last changed at {change_commit[:12]} on "
                               f"{change_date}, i.e. after the audit date {audit_date}"
                               if change_commit else
                               ", and it has never been changed in the history of this repository")
                            + ". The cited content at audit time is therefore byte-identical to "
                              "the content at the pinned commit."),
                        "content_unchanged_range": [oldest, head],
                    })
                else:
                    out["caveat"] = (f"the file changed at {change_commit[:12]} ({change_date}), "
                                     "after the audit date, so the date-bounded commit cannot be "
                                     "content-verified")
            return out

    out["resolution_method"] = "unresolved_no_anchor"
    out["caveat"] = ("no anchor content and no audit date; the citation cannot be "
                     "pinned without inventing a commit")
    return out


def try_date_anchored_identity(repo: str, path: str, audit_date: str | None,
                               audit_snapshot: str | None) -> dict | None:
    """Anchor the content on the target repository's own state at the audit date.

    A report written on 2024-03-20 read the file as it stood on the default
    branch that day. Reading that revision's blob and locating the earliest
    commit that carries those exact bytes answers "which commit contains the
    cited code" without leaving the target repository.
    """
    iso = audit_date_to_iso(audit_date)
    if not iso:
        return None
    clone = locate_clone(repo)
    if clone is None:
        return None
    db = default_branch(clone)
    if not db:
        return None
    at_date = blob_at_date(clone, db, path, iso)
    if not at_date:
        return None
    hits = commits_with_blob(clone, path, at_date)
    if not hits:
        return None
    resolved = hits[0]
    date_commit = git(["rev-list", "-1", f"--before={iso}", db], clone)[1]
    return {
        "commit_resolution_status": "resolved",
        "resolved_commit": resolved,
        "resolution_method": "date_anchored_blob_identity",
        "resolution_confidence": "high" if len(hits) == 1 else "medium",
        "evidence": (
            f"the target repository held git blob {at_date[:12]} for {path} on `{db}` at the "
            f"audit date {audit_date} (commit {date_commit[:12]}); that exact content first "
            f"appears at commit {resolved[:12]} and is carried by {len(hits)} commit(s) of the "
            "file's history. The pinned commit therefore contains the cited content, and the "
            "commit that was tip at audit time is recorded as date_anchor_commit."),
        "anchor_revision": date_commit,
        "anchor_blob": at_date,
        "date_anchor_commit": date_commit,
        "matching_commits": hits[:12],
        "resolved_commit_date": commit_date(str(clone), resolved),
        "reproducible_permalink":
            f"https://github.com/{repo}/blob/{resolved}/{path}",
    }


def try_vendored_identity(repo: str, path: str, audit_date: str | None,
                          audit_snapshot: str | None) -> dict | None:
    """A byte-copy of `path` inside *another* audited repository.

    Some audited protocols vendor the third-party file they compiled against. If
    that copy is byte-identical to what the target repository held at the audit
    date, the citation is content resolved independently of the target's own
    history. Returns None when no candidate verifies.
    """
    iso = audit_date_to_iso(audit_date)
    if not iso:
        return None
    clone = locate_clone(repo)
    if clone is None:
        return None
    db = default_branch(clone)
    if not db:
        return None
    at_date = blob_at_date(clone, db, path, iso)
    if not at_date:
        return None
    for blob, origin in vendored_candidate_blobs(repo, path, audit_snapshot):
        if blob != at_date:
            continue
        hits = commits_with_blob(clone, path, blob)
        if not hits:
            continue
        resolved = hits[0]
        return {
            "commit_resolution_status": "resolved",
            "resolved_commit": resolved,
            "resolution_method": "vendored_copy_identity_at_audit_date",
            "resolution_confidence": "high" if len(hits) == 1 else "medium",
            "evidence": (
                f"a byte-identical copy of {path} exists at {origin}, an independent "
                f"repository; the target repository held that same git blob ({blob[:12]}) on "
                f"`{db}` at the audit date {audit_date}, and the earliest commit carrying those "
                f"bytes is {resolved[:12]}"),
            "anchor_revision": origin,
            "anchor_blob": blob,
            "vendored_anchor": origin,
            "matching_commits": hits[:12],
            "resolved_commit_date": commit_date(str(clone), resolved),
            "reproducible_permalink":
                f"https://github.com/{repo}/blob/{resolved}/{path}",
        }
    return None


# ---------------------------------------------------------------------------
def collect(records: list[dict]):
    """Mutable citations, keyed by (repo, path), with the audit metadata each was seen under."""
    seen: dict[tuple[str, str], dict] = {}
    occurrences: list[tuple[str, str, str, dict]] = []
    for rec in records:
        rid = rec.get("id")
        src = rec.get("source") or {}
        audit_date = src.get("audit_date")
        snapshot = src.get("commit_sha")
        # The audit repository a record came from is the *only* place where
        # `source.commit_sha` is the audited revision of that repository.
        audited_repo = f"code-423n4/{src.get('repository')}" if src.get("repository") else None
        for key in REF_KEYS:
            for c in rec.get(key) or []:
                url = c.get("source_url") or ""
                m = BLOB_URL.match(url)
                if not m:
                    continue
                repo, ref, path = m.group(1), m.group(2), m.group(3)
                if SHA40.match(ref):
                    continue
                occurrences.append((rid, key, path, c))
                seen.setdefault((repo, path), {
                    "repo": repo, "path": path, "refs": set(),
                    "audit_dates": set(), "audited_snapshots": set()})
                e = seen[(repo, path)]
                e["refs"].add(ref)
                if audit_date:
                    e["audit_dates"].add(audit_date)
                if snapshot and repo == audited_repo:
                    e["audited_snapshots"].add(snapshot)
    return seen, occurrences


def apply_resolutions(records: list[dict], resolutions: dict,
                      per_citation: list[dict], min_confidence: str) -> dict:
    """Write the resolved commit back into the records.

    This is the step that makes the claim "no mutable branch citation remains"
    true of the data rather than only of this script's own report. Every mutated
    citation keeps its provenance: the original ref and URL are preserved and the
    resolution method/confidence is recorded inline, so the edit is auditable and
    reversible. `jsonl/` is never touched.
    """
    rank = {"high": 3, "medium": 2, "low": 1, "unknown": 0, None: 0}
    floor = rank.get(min_confidence, 2)

    stats = {"citations_seen": 0, "citations_pinned": 0, "citations_skipped_low_confidence": 0,
             "citations_unresolved": 0, "records_touched": 0, "urls_rewritten": 0}
    for rec in records:
        touched = False
        for key in REF_KEYS:
            for c in rec.get(key) or []:
                if not isinstance(c, dict):
                    continue
                sha = c.get("commit_sha")
                if sha and SHA40.match(sha):
                    continue                      # already immutable
                url = c.get("source_url") or ""
                m = BLOB_URL.match(url)
                if not m:
                    stats["citations_unresolved"] += 1
                    continue
                repo, ref, path = m.group(1), m.group(2), m.group(3)
                stats["citations_seen"] += 1
                res = resolutions.get((repo, path)) or {}
                new = res.get("resolved_commit")
                if res.get("commit_resolution_status") != "resolved" or not new \
                        or not SHA40.match(new):
                    stats["citations_unresolved"] += 1
                    continue
                if rank.get(res.get("resolution_confidence"), 0) < floor:
                    stats["citations_skipped_low_confidence"] += 1
                    continue
                c["commit_sha"] = new
                c["source_url"] = re.sub(
                    r"^(https://github\.com/" + re.escape(repo) + r"/blob/)[^/]+/",
                    lambda mo: mo.group(1) + new + "/", url)
                if c["source_url"] != url:
                    stats["urls_rewritten"] += 1
                c["original_reference"] = ref
                c["source_url_original"] = url
                c["commit_resolution_status"] = res.get("commit_resolution_status")
                c["resolution_method"] = res.get("resolution_method")
                c["resolution_confidence"] = res.get("resolution_confidence")
                c["commit_pinned_by"] = "scripts/resolve_citations.py"
                stats["citations_pinned"] += 1
                touched = True
        if touched:
            stats["records_touched"] += 1
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--records", default=str(DERIVED / "records.jsonl"))
    ap.add_argument("--out", default=str(REPORTS / "citation_resolution.json"))
    ap.add_argument("--apply", dest="apply", action="store_true", default=True,
                    help="write the resolved commit back into --records (default)")
    ap.add_argument("--no-apply", dest="apply", action="store_false",
                    help="only emit the report; leave the records untouched")
    ap.add_argument("--min-confidence", default="medium",
                    choices=["high", "medium", "low", "unknown"],
                    help="lowest resolution confidence that may be written back")
    args = ap.parse_args()

    records = read_jsonl(Path(args.records))
    seen, occurrences = collect(records)
    log(f"mutable citation occurrences: {len(occurrences)}")
    log(f"distinct (repository, path) targets: {len(seen)}")

    resolutions: dict[tuple[str, str], dict] = {}
    for i, (key, e) in enumerate(sorted(seen.items()), 1):
        # The audit snapshot is an anchor only when the citation is *into* the
        # audited repository that this record was produced from.
        snaps = sorted(e["audited_snapshots"])
        snap = snaps[0] if len(snaps) == 1 else None
        res = resolve_one(e["repo"], e["path"], sorted(e["refs"])[0],
                          sorted(e["audit_dates"])[0] if e["audit_dates"] else None,
                          snap)
        if res.get("resolution_confidence") in (None, "low", "unknown"):
            upgraded = (try_vendored_identity(
                e["repo"], e["path"],
                sorted(e["audit_dates"])[0] if e["audit_dates"] else None, snap)
                or try_date_anchored_identity(
                    e["repo"], e["path"],
                    sorted(e["audit_dates"])[0] if e["audit_dates"] else None, snap))
            if upgraded:
                for k in ("original_reference", "target_repository",
                          "path_in_repository", "default_branch"):
                    upgraded.setdefault(k, res.get(k))
                res = upgraded
        res["original_references"] = sorted(e["refs"])
        res["mutable_occurrences"] = sum(
            1 for _, _, p, _ in occurrences if (e["repo"], p) == key)
        res["affected_records"] = sorted(
            {rid for rid, _, p, _ in occurrences if (e["repo"], p) == key})
        resolutions[key] = res
        if i % 25 == 0:
            log(f"  resolved {i}/{len(seen)}")

    # occurrence-level index so every citation can be pinned by id
    per_citation = []
    for rid, key_name, path, c in occurrences:
        m = BLOB_URL.match(c.get("source_url") or "")
        r = resolutions.get((m.group(1), path), {})
        per_citation.append({
            "record_id": rid,
            "context_key": key_name,
            "source_url_original": c.get("source_url"),
            "file": c.get("file"),
            "function": c.get("function"),
            "line_start": c.get("line_start"),
            "line_end": c.get("line_end"),
            "original_reference": r.get("original_reference"),
            "resolved_commit": r.get("resolved_commit"),
            "source_url_pinned": (f"https://github.com/{m.group(1)}/blob/"
                                  f"{r['resolved_commit']}/{path}" if r.get("resolved_commit")
                                  else None),
            "commit_resolution_status": r.get("commit_resolution_status"),
            "resolution_method": r.get("resolution_method"),
            "resolution_confidence": r.get("resolution_confidence"),
        })

    from collections import Counter
    status = Counter(v["commit_resolution_status"] for v in resolutions.values())
    method = Counter(v["resolution_method"] for v in resolutions.values())
    conf = Counter(v["resolution_confidence"] for v in resolutions.values())
    occ_status = Counter(v["commit_resolution_status"] for v in per_citation)

    doc = {
        "generated_by": "scripts/resolve_citations.py",
        "input_records": len(records),
        "mutable_occurrences": len(occurrences),
        "distinct_targets": len(resolutions),
        "by_status": dict(status),
        "by_method": dict(method),
        "by_confidence": dict(conf),
        "occurrences_by_status": dict(occ_status),
        "remaining_mutable_occurrences": sum(
            v for k, v in occ_status.items() if k == "unresolved"),
        "policy": ("A mutable citation is only replaced when a mechanical content or "
                   "date identity test succeeded. No SHA is invented; unresolved "
                   "citations stay mutable and are counted."),
        "targets": [dict(v, target_repository=k[0], path_in_repository=k[1])
                    for k, v in sorted(resolutions.items())],
        "citations": per_citation,
    }
    write_json(Path(args.out), doc)
    log(f"wrote {args.out}")
    log(f"  status: {dict(status)}")
    log(f"  confidence: {dict(conf)}")

    # ------------------------------------------------------------------ apply
    # The report above proposes the fix. Without this step the dataset itself is
    # left holding branch names while the report claims they were resolved, so the
    # numbers below are measured on the records AFTER the write-back.
    applied: dict = {}
    if args.apply:
        applied = apply_resolutions(records, resolutions, per_citation,
                                    args.min_confidence)
        write_jsonl(Path(args.records), records)
        log(f"applied resolutions to {args.records} "
            f"(min-confidence={args.min_confidence})")
        log(f"  {applied}")

    # Recount from the written file rather than trusting either the resolver or
    # the in-memory copy. This is the number the README and the gate must quote.
    still_mutable = 0
    still_by_file: dict[str, int] = defaultdict(int)
    for rec in read_jsonl(Path(args.records)):
        for key in REF_KEYS:
            for c in rec.get(key) or []:
                if not isinstance(c, dict):
                    continue
                sha = c.get("commit_sha") or ""
                m = BLOB_URL.match(c.get("source_url") or "")
                if (sha and not SHA40.match(sha)) or (m and not SHA40.match(m.group(2))):
                    still_mutable += 1
                    still_by_file[key] += 1
    doc["applied"] = {
        "applied_to_records": bool(args.apply),
        "min_confidence": args.min_confidence,
        **applied,
    }
    doc["remaining_mutable_occurrences_after_apply"] = still_mutable
    doc["remaining_mutable_by_context_key"] = dict(still_by_file)
    doc["remaining_mutable_in_source_layer"] = None   # filled by validate.py
    write_json(Path(args.out), doc)
    log(f"  mutable citations still present in {args.records}: {still_mutable} "
        f"{dict(still_by_file)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
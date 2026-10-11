#!/usr/bin/env python3
"""Retrieve audited sources at exactly the commits the dataset cites.

Two things are fetched, both pinned:

  work/repos/<name>/         a blobless git clone of the audited repository
  work/sources/<repo>/<sha>/<path>
                             the byte-exact content of every (commit, file)
                             pair that appears in code_context, vulnerable_code
                             or code_reference_only

plus the repository LICENSE at the pinned commit, which is what the
licence classification in derived/license_classification.json is based on.

Nothing here copies source into the dataset. Retrieved files stay under work/,
which is git-ignored. The dataset only records hashes and citations.

    python scripts/fetch_sources.py                 # everything
    python scripts/fetch_sources.py --repo 2024-04-noya
    python scripts/fetch_sources.py --checkouts     # also materialise the tree
    python scripts/fetch_sources.py --verify        # re-hash and report

Uses git's blobless clone so a 500 MB audit repo costs a few MB of pack, and
`git cat-file` fetches individual blobs on demand. Raw GitHub HTTP is used only
as a fallback, so an unauthenticated run still works (rate limited).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    REPORTS, WORK, code_entries, load_core, log, owner_repo as owner_repo_of, run,
    sha256_text, write_json,
)

CLONES = WORK / "repos"
SOURCES = WORK / "sources"
MANIFEST = WORK / "source_manifest.json"
ORG_DEFAULT = "code-423n4"
LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md",
                 "COPYING", "license", "LICENSE-APACHE")


def repo_name(owner_repo: str) -> str:
    return owner_repo.replace("/", "__")


def split_path(owner_repo: str, path: str) -> tuple[str, str]:
    """A cited `file` is a permalink path: `<org>/<repo>/<path-in-repo>`.

    It is not always the audited repository — reports cite third-party
    dependencies too (pendle-finance/pendle-core-v2-public, re-nft/smart-contracts).
    Split it so each blob is fetched from the repository that actually holds it.
    """
    parts = (path or "").split("/")
    if len(parts) > 2 and "/" in owner_repo:
        return f"{parts[0]}/{parts[1]}", "/".join(parts[2:])
    return owner_repo, path


def cited_pairs() -> dict[str, set[tuple[str, str]]]:
    """owner/repo -> {(commit_sha, path_within_repo)} over every code citation."""
    core = load_core()
    out: dict[str, set[tuple[str, str]]] = {}
    for rows in core.values():
        for row in rows:
            src = row.get("source") or {}
            repo_key = owner_repo_of(src)
            if not repo_key:
                continue
            for e in code_entries(row):
                sha, path = e.get("commit_sha"), e.get("file")
                if not (sha and path):
                    continue
                repo, rel_path = split_path(repo_key, path)
                out.setdefault(repo, set()).add((sha, rel_path))
    return out


def head_commits() -> dict[str, str]:
    """owner/repo -> the audit commit the dataset was built from."""
    core = load_core()
    out: dict[str, str] = {}
    for rows in core.values():
        for row in rows:
            src = row.get("source") or {}
            key = owner_repo_of(src)
            if not (key and src.get("commit_sha")):
                continue
            out.setdefault(key, src["commit_sha"])
    return out


def git_url(org: str, repo: str) -> str:
    return f"https://github.com/{org}/{repo}.git"


def ensure_clone(org: str, repo: str, name: str) -> Path:
    """Blobless clone. Existing clones are reused so re-runs are cheap."""
    dest = CLONES / name
    if (dest / ".git").exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    rc, out, err, _ = run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet",
                           git_url(org, repo), str(dest)], timeout=1800)
    if rc != 0:
        # Fall back to a plain clone; some servers reject partial clone filters.
        rc, out, err, _ = run(["git", "clone", "--no-checkout", "--quiet",
                               git_url(org, repo), str(dest)], timeout=3600)
    if rc != 0:
        raise RuntimeError(f"clone failed {org}/{repo}: rc={rc} {(err or out).strip()[:400]}")
    return dest


def cat_file(dest: Path, sha: str, path: str) -> tuple[str | None, str]:
    """(content, note). content is None when the blob cannot be resolved."""
    rc, out, err, _ = run(["git", "-C", str(dest), "cat-file", "-p", f"{sha}:{path}"], timeout=300)
    if rc == 0 and out is not None:
        return out, "git_cat_file"
    note = err.strip().splitlines()[0][:160] if err.strip() else f"rc={rc}"
    low = note.lower()
    if "does not exist" in low or "exists on disk" in low or "not our ref" in low or "path" in low:
        return None, "path_missing_at_commit"
    if "could not get object" in low or "not our ref" in low or "upload-pack" in low:
        return None, "commit_unreachable"
    if "authentication" in low or "terminal prompts" in low or "403" in low:
        return None, "clone_incomplete_or_auth_required"
    return None, "cat_file_failed:" + note


def fetch_license(dest: Path, repo: str, shas: list[str]) -> dict:
    """Find a LICENSE at any cited commit; record path, sha256 and first line."""
    for sha in shas:
        for name in LICENSE_NAMES:
            text, note = cat_file(dest, sha, name)
            if text and text.strip():
                head = text.strip().splitlines()[0][:200]
                return {"found": True, "path": name, "commit_sha": sha,
                        "sha256": sha256_text(text), "first_line": head,
                        "license_text_available_offline": True}
    return {"found": False, "path": None, "reason": "no LICENSE file at any cited commit"}


def fetch_repo(owner_repo: str, pairs: set[tuple[str, str]], do_checkout: bool,
               head: str | None, role: str) -> dict:
    org, name = owner_repo.split("/", 1)
    dest = CLONES / repo_name(owner_repo)
    base = {
        "repo": owner_repo, "name": name, "org": org, "role": role,
        "files_requested": len(pairs), "files_retrieved": 0, "files_missing": 0,
    }
    try:
        ensure_clone(org, name, repo_name(owner_repo))
    except Exception as exc:  # noqa: BLE001 - one dead repo must not kill the run
        return {**base, "status": "clone_failed", "detail": str(exc)[:400]}

    shas = sorted({s for s, _ in pairs})
    got, missing = [], []
    for sha in shas:
        for path in sorted(p for s, p in pairs if s == sha):
            text, note = cat_file(dest, sha, path)
            if text is None:
                missing.append({"commit_sha": sha, "file": f"{owner_repo}/{path}", "reason": note})
                continue
            out = SOURCES / repo_name(owner_repo) / sha / path
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            got.append({"commit_sha": sha, "file": f"{owner_repo}/{path}",
                        "path_in_repo": path,
                        "sha256": sha256_text(text),
                        "bytes": len(text.encode("utf-8")),
                        "lines": text.count("\n") + 1,
                        "local_path": str(out.relative_to(WORK)).replace("\\", "/")})

    lic = fetch_license(dest, name, shas or ([head] if head else []))
    if do_checkout and head:
        run(["git", "-C", str(dest), "checkout", "--quiet", head], timeout=3600)

    return {
        **base, "status": "ok",
        "head_commit": head,
        "commits_cited": len(shas),
        "files_retrieved": len(got),
        "files_missing": len(missing),
        "missing_detail": missing[:80],
        "retrieved": got,
        "license": lic,
        "bytes_retrieved": sum(g["bytes"] for g in got),
    }


def verify() -> dict:
    """Re-hash everything on disk against the manifest."""
    if not MANIFEST.exists():
        return {"ok": False, "detail": "no manifest; run scripts/fetch_sources.py first"}
    man = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bad, checked = [], 0
    for r in man["repos"]:
        if r.get("status") != "ok":
            continue
        for g in r["retrieved"]:
            p = WORK / g["local_path"]
            if not p.exists():
                bad.append({"path": g["local_path"], "problem": "missing_on_disk"})
                continue
            checked += 1
            h = sha256_text(p.read_text(encoding="utf-8"))
            if h != g["sha256"]:
                bad.append({"path": g["local_path"], "problem": "hash_mismatch"})
    return {"ok": not bad, "files_checked": checked, "failures": bad[:40]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", action="append", help="limit to one repository (repeatable)")
    ap.add_argument("--checkouts", action="store_true",
                    help="also `git checkout` the head commit so forge can build")
    ap.add_argument("--verify", action="store_true", help="only re-hash what is on disk")
    args = ap.parse_args()

    if args.verify:
        res = verify()
        write_json(REPORTS / "source_fetch_verification.json", res)
        log(f"verify: {res.get('files_checked', 0)} files, ok={res.get('ok')}, "
            f"failures={len(res.get('failures', []))}")
        return 0 if res.get("ok") else 1

    pairs = cited_pairs()
    heads = head_commits()
    audited = {f"{k.split('/', 1)[1]}" for k in heads}
    names = args.repo or sorted(pairs)
    results = []
    for owner_repo in names:
        if owner_repo not in pairs:
            log(f"skip {owner_repo}: not cited in the dataset")
            continue
        role = "audited_protocol" if owner_repo.split("/", 1)[1] in audited else "cited_dependency"
        log(f"fetching {owner_repo} ({len(pairs[owner_repo])} pinned files, {role}) ...")
        res = fetch_repo(owner_repo, pairs[owner_repo], args.checkouts, heads.get(owner_repo), role)
        results.append(res)
        log(f"  -> {res['status']}: {res.get('files_retrieved', 0)}/{res.get('files_requested', 0)} files, "
            f"license={'found' if res.get('license', {}).get('found') else 'absent'}")

    man = {
        "generated_by": "scripts/fetch_sources.py",
        "source_layer_version": "1.0",
        "total_files_requested": sum(r["files_requested"] for r in results),
        "total_files_retrieved": sum(r.get("files_retrieved", 0) for r in results),
        "total_files_missing": sum(r.get("files_missing", 0) for r in results),
        "repos": results,
    }
    write_json(MANIFEST, man)
    log(f"total {man['total_files_retrieved']}/{man['total_files_requested']} pinned files, "
        f"{man['total_files_missing']} unresolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
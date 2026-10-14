#!/usr/bin/env python3
"""Resolve a cited (commit, file) to bytes on disk, with a redistribution gate.

scripts/fetch_sources.py already pulled 321 of the 326 cited files. This module
is the only sanctioned way to read them, and it enforces the licence rule:

  redistributable            full text may leave the repository
  source_available_but_not_  structure may be analysed, but no source text and no
  redistributable            verbatim guard expressions may be recorded
  unknown / unavailable      no analysis is possible; say so

Derived facts about a file (which modifier guards a function, whether a guard
compares msg.sender) are statements about behaviour, not copies of the work, so
they are recorded for withheld files too. The *text* never is.
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solidity_facts as sf  # noqa: E402
from vlun import WORK, load_core  # noqa: E402

MANIFEST = WORK / "source_manifest.json"

# Licence decisions live in derived/license_classification.json when it exists;
# until then fall back to the record's own `code_reference_only_note`, which states
# why the v1 builder withheld the text.
BUSL_MARKERS = ("busl", "commons clause", "business source", "source-available")
PERMISSIVE_MARKERS = ("mit", "apache", "bsd", "isc", "mozilla", "gpl", "lgpl", "unlicense", "cc0")


@lru_cache(maxsize=1)
def _manifest() -> dict:
    if not MANIFEST.exists():
        return {}
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    idx = {}
    for r in m.get("repos", []):
        key = r["repo"].replace("/", "__")
        for g in r.get("retrieved", []):
            idx[(key, g["commit_sha"], g["path_in_repo"])] = g
    return idx


@lru_cache(maxsize=1)
def _license_by_repo() -> dict:
    out = {}
    if not MANIFEST.exists():
        return out
    for r in json.loads(MANIFEST.read_text(encoding="utf-8")).get("repos", []):
        lic = r.get("license") or {}
        head = (lic.get("first_line") or "").lower()
        text = json.dumps(lic).lower()
        if not lic.get("found"):
            out[r["repo"]] = "unknown"
        elif any(k in text for k in BUSL_MARKERS):
            out[r["repo"]] = "source_available_but_not_redistributable"
        elif any(k in text or k in head for k in PERMISSIVE_MARKERS):
            out[r["repo"]] = "redistributable"
        else:
            out[r["repo"]] = "source_available_but_not_redistributable"
    return out


def license_classification() -> dict:
    """Per-repository licence class, from the LICENSE at the pinned commit."""
    return dict(_license_by_repo())


def repo_key_for_cited_file(owner: str, file: str) -> str:
    parts = (file or "").split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) > 2 else owner


def _owner_of(row: dict) -> str | None:
    """owner/repo for a record, or None when the record carries no
    resolvable repository. Callers degrade to unknown/skip instead of
    raising KeyError on records the validator tolerates."""
    src = row.get("source") or {}
    repo = src.get("repository")
    if not repo:
        return None
    return f"{src.get('organization', 'code-423n4')}/{repo}"


def classify_record_code(row: dict) -> str:
    """Licence class for the code a record cites.

    Deliberately conservative. The class comes from the LICENSE file that exists
    at the cited commit, not from what the v1 builder chose to redistribute:

      redistributable                        a permissive LICENSE is present
      source_available_but_not_redistributable  BUSL / Commons Clause, or v1
                                                withheld it for that reason
      reference_only                        cited, withheld, reason not a licence
      unknown                               no LICENSE at any cited commit

    `unknown` is the correct answer for most audited repositories here, which
    ship no LICENSE at all — and that is itself a provenance fact worth keeping.
    """
    note = (row.get("code_reference_only_note") or "").lower()
    classes = set()
    _owner = _owner_of(row)
    if _owner is None:
        # No resolvable repository: nothing can be licence-checked, which is
        # itself the answer (unknown), not a crash. The validator tolerates
        # such records, so the analyser must too.
        return "unknown"
    for e in (list(row.get("code_context") or []) + list(row.get("vulnerable_code") or [])):
        key = repo_key_for_cited_file(
            f"{_owner}",
            e.get("file") or "")
        classes.add(_license_by_repo().get(key, "unknown"))
    for e in (row.get("code_reference_only") or []):
        key = repo_key_for_cited_file(
            f"{_owner}",
            e.get("file") or "")
        classes.add(_license_by_repo().get(key, "unknown"))
    if not classes:
        if any(k in note for k in BUSL_MARKERS):
            return "source_available_but_not_redistributable"
        return "reference_only" if note else "unknown"
    if "source_available_but_not_redistributable" in classes:
        return "source_available_but_not_redistributable"
    if classes == {"redistributable"}:
        return "redistributable"
    if "unknown" in classes:
        return "unknown"
    return "unknown"


def redistribution_flag(row: dict) -> dict:
    """Was source text copied into the dataset without a declared licence?

    This is a fact about the *published* dataset, not about the audit. It is
    reported rather than silently tolerated so a downstream redistributor can
    make their own decision.
    """
    cls = classify_record_code(row)
    text_present = bool(row.get("code_context") or row.get("vulnerable_code"))
    return {
        "license_class": cls,
        "source_text_in_dataset": text_present,
        "flag": ("source_redistributed_without_declared_license"
                 if text_present and cls == "unknown" else None),
        "note": ("the cited repository ships no LICENSE at the pinned commit; the text in this "
                 "record was redistributed by the v1 builder on the basis of the audit's own "
                 "terms, which are not recorded here"),
    }


def lookup(owner_repo: str, commit_sha: str, cited_file: str):
    """-> (local_path | None, meta | None)."""
    key = repo_key_for_cited_file(owner_repo, cited_file)
    parts = (cited_file or "").split("/")
    path_in_repo = "/".join(parts[2:]) if len(parts) > 2 else cited_file
    meta = _manifest().get((key.replace("/", "__"), commit_sha, path_in_repo))
    if not meta:
        return None, None
    return WORK / meta["local_path"], meta


def read(owner_repo: str, commit_sha: str, cited_file: str):
    p, meta = lookup(owner_repo, commit_sha, cited_file)
    if p is None or not p.exists():
        return None, meta
    try:
        return p.read_text(encoding="utf-8", errors="replace"), meta
    except OSError:
        return None, meta


def analyse_cited(owner_repo: str, entry: dict, allow_text: bool) -> dict:
    """Structural facts for one cited file.

    `allow_text` False means: facts only. No snippet, no verbatim guard
    comparison. The result is still useful for attacker modelling and for
    deciding whether a claim about this file is reachable.
    """
    sha, path = entry.get("commit_sha"), entry.get("file")
    text, meta = read(owner_repo, sha, path)
    base = {"file": path, "commit_sha": sha, "source_url": entry.get("source_url"),
            "retrieved_locally": text is not None,
            "sha256": (meta or {}).get("sha256"),
            "line_start": entry.get("line_start"), "line_end": entry.get("line_end"),
            "line_range_verified": bool(entry.get("line_range_verified")),
            "text_redistributed": bool(allow_text and text is not None)}
    if text is None:
        base.update(evidence_type="unknown", note="file not retrieved; no analysis possible",
                    contracts=[], functions=[], target_function=None, state_variables=[])
        return base

    window = text
    if entry.get("line_start") and entry.get("line_end"):
        # Widen to the enclosing contract so callers/callees are visible, but keep
        # the cited range as the authority.
        window = _enclosing(text, entry["line_start"], entry["line_end"])
    a = sf.analyse(window, entry.get("function"))
    res = dict(base)
    res.update({
        "evidence_type": "observed_fact",
        "source_refs": [entry.get("source_url")] if entry.get("source_url") else [],
        "contracts": a["contracts"][:6],
        "function_count": a["function_count"],
        "state_variables": a["state_variables"][:40],
        "contract_level_signals": a["contract_level_signals"],
        "target_function": a["target_function"],
        "functions": _trim_functions(a["functions"], allow_text),
    })
    if allow_text:
        res["documented_intent"] = entry.get("documented_intent") or None
    return res


def _enclosing(text: str, line_start: int, line_end: int) -> str:
    lines = text.splitlines(keepends=True)
    depth, start = 0, None
    for i, ln in enumerate(lines, 1):
        if "contract " in ln or "interface " in ln or "library " in ln:
            start = i
            depth = ln.count("{") - ln.count("}")
            continue
        if start is not None:
            depth += ln.count("{") - ln.count("}")
            if depth <= 0 and i > line_end:
                break
    if start is None:
        return "\n".join(lines[max(0, line_start - 20):line_end + 20])
    return "".join(lines[start - 1:min(len(lines), start + 4000)])


def _trim_functions(fns: list[dict], allow_text: bool) -> list[dict]:
    out = []
    for f in fns:
        g = {k: v for k, v in f.items() if k != "guards"}
        g["guards"] = [
            {k: (v if allow_text or k not in ("comparison",) else None) for k, v in gd.items()}
            for gd in f.get("guards", [])[:6]
        ]
        out.append(g)
    return out[:60]


def enrich_all(row: dict) -> list[dict]:
    """Analyse every cited file of a record, honouring the licence gate."""
    owner = _owner_of(row)
    if owner is None:
        return []
    cls = classify_record_code(row)
    allow = cls == "redistributable"
    entries = (list(row.get("code_context") or []) + list(row.get("vulnerable_code") or [])
               + list(row.get("code_reference_only") or []))
    seen, out = set(), []
    for e in entries:
        key = (e.get("commit_sha"), e.get("file"))
        if key in seen:
            continue
        seen.add(key)
        # A record that already redistributed the snippet keeps it; nothing to add.
        if e.get("snippet"):
            continue
        out.append(analyse_cited(owner, e, allow_text=allow))
    return out


def retrieved_coverage() -> dict:
    """How much of the cited code corpus is on disk right now."""
    core = load_core()
    need, have = set(), set()
    for rows in core.values():
        for row in rows:
            owner = _owner_of(row)
            if owner is None:
                continue
            for e in (list(row.get("code_context") or []) + list(row.get("vulnerable_code") or [])
                      + list(row.get("code_reference_only") or [])):
                if not (e.get("commit_sha") and e.get("file")):
                    continue
                key = repo_key_for_cited_file(owner, e["file"]).replace("/", "__")
                need.add((key, e["commit_sha"], "/".join(e["file"].split("/")[2:])
                          if len(e["file"].split("/")) > 2 else e["file"]))
    for k in _manifest():
        have.add(k)
    return {"cited_files": len(need), "retrieved": len(need & have),
            "missing": len(need - have),
            "missing_examples": [list(x) for x in sorted(need - have)[:15]]}
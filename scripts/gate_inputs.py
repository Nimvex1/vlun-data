#!/usr/bin/env python3
"""Shared precondition guard for the generated-artefact ``--check`` gates.

A ``--check`` gate proves that a committed artefact equals a regeneration of it.
Some regenerations must re-read bytes that live in a git-ignored tree --
``V3/clones/`` (the pinned audit reports), ``work/repos/`` and
``work/sources/`` (the pinned source clones) -- which a fresh ``actions/checkout``
clone cannot have. On such a checkout the comparison is not failed, it is
*impossible*, and the two wrong answers are both easy to fall into:

  * reporting it as a failure turns every clean checkout red for a reason that
    has nothing to do with the data;
  * reporting it as a pass is the "green build that verified nothing" this
    repository already refuses -- ``scripts/run_gates.py`` exits 1 when zero
    gates pass.

The contract comes from ``scripts/check_reproducibility.py`` (``Gate.skip``) and
is unchanged here: an unavailable input is recorded as ``skipped_no_network``
-- never a pass, never a failure. ``scripts/run_gates.py`` reads a gate process
exiting ``2`` (``SKIPPED_CODES``) as exactly that, and prints the tail of its
output next to the ``[SKIPPED]`` verdict.

Guards are deliberately NARROW. A caller enumerates the specific ignored inputs
its regeneration reads; if every one of them is on disk this module says nothing
and the caller runs its full byte comparison exactly as before, still able to
fail. Only an actual absence produces a skip, and the skip line names what is
missing plus what a maintainer who HAS the clones should run instead.

Usage (the established idiom, matching ``scripts/build_prove_split.py``):

    from gate_inputs import SKIP_RC, absent, skip_line

    missing = absent(ROOT, required_paths)
    if missing:
        V.log(skip_line(tool="scripts/foo.py",
                         what="pinned audit-report sources",
                         missing=missing, total=len(required_paths),
                         remedy="run on a checkout with V3/clones/"))
        return SKIP_RC

stdlib only; writes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

# The runner's SKIPPED code. Never 0 (that would be a pass), never 1 (that
# would be a failure) -- see scripts/run_gates.py SKIPPED_CODES.
SKIP_RC = 2

# Stable, greppable prefix. `skipped_no_network` is the vocabulary
# scripts/check_reproducibility.py and reports/reproducibility_checks.json
# already use; keep it verbatim so CI logs stay searchable.
MARKER = "SKIPPED skipped_no_network:"

# scripts/run_gates.py prints only the last two output lines of a gate, cut to
# 160 characters, so the skip line has to carry the whole reason inside that
# window. Longer detail belongs in the caller's own docstring, not here.
MAX_LINE = 155


def absent(root, paths) -> list[str]:
    """Repo-relative names of the inputs in ``paths`` that are NOT on disk.

    Order-preserving and de-duplicated, so the skip line names the same inputs
    on every run. ``str`` and ``Path`` both work; a relative input is resolved
    against ``root``, so callers may pass repo-relative names or absolute paths.
    """
    root = Path(root)
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        pp = Path(p)
        cand = pp if pp.is_absolute() else root / pp
        if cand.exists():
            continue
        try:
            name = cand.relative_to(root).as_posix()
        except ValueError:
            name = cand.as_posix()
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def referenced_paths(jsonl_path, *keys) -> list[str]:
    """Distinct non-empty values found at a nested key across JSONL rows.

    Used to enumerate the pinned files a regeneration re-reads: the span gates
    store them per row under ``provenance.source_location`` /
    ``expected_span.source_location``, so the input list comes from the committed
    artefact itself rather than from a guessed filename. Order-preserving,
    de-duplicated, silently empty when the JSONL is absent (the caller's own
    comparison reports that as a failure, not a skip).
    """
    out: list[str] = []
    seen: set[str] = set()
    p = Path(jsonl_path)
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            cur = json.loads(line)
        except ValueError:
            continue
        for k in keys:
            cur = cur.get(k) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, str) and cur and cur not in seen:
            seen.add(cur)
            out.append(cur)
    return out


def parents(paths, depth: int = 3) -> list[str]:
    """Collapse repo-relative input names to their first ``depth`` components.

    A regeneration may need thousands of pinned files, but the input that is
    actually absent is the tree that holds them. Naming ``V3/clones/abdk-audits``
    rather than its 400 files keeps the skip line inside the runner's tail
    window while still naming real missing inputs. Order-preserving, de-duplicated.
    """
    out: list[str] = []
    seen: set[str] = set()
    for name in paths:
        parts = PurePosixPath(name).parts
        cut = "/".join(parts[:depth])
        if cut and cut not in seen:
            seen.add(cut)
            out.append(cut)
    return out


def skip_line(*, tool: str, what: str, missing, total=None,
              remedy: str = "", max_names: int = 3) -> str:
    """Compose ONE machine-readable skip line naming the missing inputs.

    ``tool`` is the gate script's own repo-relative path (so the log identifies
    the emitter, not just the symptom), ``what`` names the input class, and
    ``remedy`` states what a maintainer with the ignored inputs must run
    instead. The remedy is load-bearing, so it is kept and example names are
    dropped until the line fits the runner's tail window; at least the count of
    missing inputs always survives.
    """
    missing = list(missing)
    n = len(missing)
    count = f"{n}" if total in (None, n) else f"{n} of {total}"
    stem = f"{MARKER} {tool}: {what} absent ({count})"
    tail = f" -- maintainer: {remedy}" if remedy else ""
    for k in range(max(max_names, 0), -1, -1):
        names = _names(missing, k)
        line = f"{stem}: {names}{tail}" if names else f"{stem}{tail}"
        if len(line) <= MAX_LINE:
            return line
    # Even the stem and remedy do not fit: keep the marker, the tool and the
    # count, which is what a log search for `skipped_no_network` needs.
    return f"{stem}{tail}"[:MAX_LINE]


def _names(missing, k: int) -> str:
    if k <= 0 or not missing:
        return ""
    shown = ", ".join(missing[:k])
    extra = len(missing) - k
    return f"{shown} (+{extra} more)" if extra > 0 else shown

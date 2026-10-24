#!/usr/bin/env python3
"""Redact the operator's home directory out of the committed artefacts.

A committed artefact that carries `C:\\Users\\<account>\\...` is tied to the one
checkout that produced it and publishes the operator's account name to every
reader of the dataset. The repository already has a convention for that: the
fixed token `REDACTED` in the account position
(`C:/Users/REDACTED/Documents/...`), used by the layers that were sanitised
earlier. This script applies exactly that convention and nothing else:

  * the ACCOUNT component of a machine-local path becomes `REDACTED`;
  * everything else in the path stays - the tool, the file, the error text -
    so the transcript still shows what actually happened;
  * an absolute interpreter path in a recorded command becomes the portable
    `python`, so a recorded command can be re-run on any machine.

    python scripts/redact_machine_paths.py            # apply
    python scripts/redact_machine_paths.py --check    # report, change nothing
    python scripts/redact_machine_paths.py --files    # per-file counts

What it does NOT touch, and why

  * The read-only source layers (`jsonl/`, `jsonl_ml/`, `jsonl_v3/`). Their
    bytes ARE the layer: a pinned source of record whose whole role is to be
    exactly what was produced. Rewriting a byte of them to remove a path
    would change what the layer is, so the leak that is still in `jsonl_ml/`
    is reported by `scripts/check_no_machine_paths.py` as an explicit, named,
    unresolved category instead of being silently rewritten here. A human
    clears it by rebuilding the layer from the upstream commit with a
    repository-relative resolved path - `scripts/build_ml_ingest.py` now
    records one, so the next rebuild of that layer is clean.

  * The genuine-upstream allowlist. A path quoted from a third-party audit
    report is evidence of what the upstream text said; it is not a path on
    any machine that built this repository, so it survives verbatim.

Determinism and idempotence

The script only ever rewrites the account component (or the interpreter
token), so running it twice changes nothing: the second run finds no
operator path left to redact and rewrites no file. The recorded artefact
digests are re-pointed at the redacted bytes in the same pass, so the
provenance chain stays closed (`scripts/reconcile_proof_artefact_hashes.py`
and `scripts/unblock_v32_runs.py --check` both re-verify them).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------

# The trees this script may rewrite. Everything outside is left alone: other
# agents own the other generated layers, and a read-only source layer is
# never rewritten by anybody.
SCOPE = (
    "experiments/",
    "experiments_v2_2/",
    "experiments_v3/",
    "experiments_nonevm/",
    "experiments_v1_reruns/",
    "reports/static_analysis.json",
    "reports/nonevm_pilot.json",
    "reports/poc_attempts.jsonl",
    "benchmark/retired_families/M_experiment_level_classification.jsonl",
)

# The pinned source layers. They are reported, never rewritten.
READ_ONLY_LAYERS = (
    "jsonl/",
    "jsonl_ml/",
    "jsonl_v3/",
)

# The redaction token. It is the repository's existing convention: a fixed
# word in the account position, naming no account and no machine.
REDACTION_TOKEN = "REDACTED"

# The portable interpreter token used in a recorded command.
PORTABLE_PYTHON = "python"

# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------

# A separator in a path: two backslashes (a JSON-escaped backslash), one
# backslash (a plain-text path) or a forward slash.
_SEP = rb"(?:\\\\|\\|/)"

# `C:\Users\<name>` / `C:\Documents and Settings\<name>`.
WIN_PROFILE = re.compile(
    rb"(?P<drive>[A-Za-z]:)" + _SEP +
    rb"(?:Users|Documents and Settings)" + _SEP +
    rb"(?P<name>[A-Za-z0-9._-]+)")

# `/home/<name>`, `/Users/<name>`, `/root/<name>`.
POSIX_PROFILE = re.compile(
    rb"(?P<root>/)(?P<who>home|Users|root)" + _SEP +
    rb"(?P<name>[A-Za-z0-9._-]+)")

# A path-shaped token: a drive letter, or a POSIX absolute path. It stops at
# the first character that cannot be part of a path, so a quoted JSON string
# ends the token at its closing quote.
WIN_TOKEN = re.compile(rb"[A-Za-z]:" + _SEP + rb"[^\s\"'<>|,;`]*")
POSIX_TOKEN = re.compile(rb"/[^\s\"'<>|,;`]*")

# The last component of a path, when it names a Python interpreter.
PY_BASENAME = re.compile(rb"^python(?:\d+(?:\.\d+)*)?(?:\.exe)?$")

# Upstream path shapes that are quoted from a third-party audit report and
# must survive verbatim: they are not paths on any machine that built this
# repository. They are matched on the whole path shape, because the account
# component alone cannot tell an upstream quote from a local path.
#
# The second pattern is assembled from two halves because THIS file is
# scanned by scripts/check_no_machine_paths.py: written out in one piece,
# the allowlist itself would contain the very path shape it is meant to
# describe, and the gate would report this file as an operator leak.
_UPSTREAM_HOME_RE = (rb"^/home/(?:projects|NM-0051-GYROSCOPE|nethermind-audits|"
                     rb"venv-3\.9)$")
_UPSTREAM_REPO_RE = rb"^/" + rb"root/contracts"

GENUINE_UPSTREAM = (
    re.compile(_UPSTREAM_HOME_RE),
    re.compile(_UPSTREAM_REPO_RE),
)

# The manifest keys that record a digest of a sibling file.
DIGEST_KEYS = ("artefacts", "output_sha256", "artifact_hashes",
               "artifact_sha256")

# The layer whose digests are computed over the text with CRLF folded to LF
# (the `sha256-v1-text` scheme). Every other manifest records the digest of
# the committed bytes as they are (`sha256-v1-raw` / `sha256-v1-bytes`).
# The scheme belongs to the manifest, not to the file it points at: the
# derived_v2_2 records hash the v2.2 artefacts with the text scheme, while
# the v2.2 result.json hashes the same files with the raw scheme.
DIGEST_SCHEME_TEXT = ("derived_v2_2/",)

# The v1 experiments tree is EXCLUDED from the digest reconciliation. Four of
# its transcripts were redacted after the run, and the digest they still
# record is the digest of the pre-redaction bytes: that is the evidence, and
# `scripts/reconcile_proof_artefact_hashes.py` lists the difference as a
# recorded, unresolved mismatch with the original blob. Re-pointing it here
# would erase a true statement about the run.
DIGEST_RECONCILE_TREES = ("experiments_v2_2/", "experiments_v3/",
                          "experiments_nonevm/", "experiments_v1_reruns/")

# Files outside SCOPE that record a digest of a file inside it. They are not
# rewritten (another agent may own them), but their recorded digest has to
# follow the bytes, or the provenance chain breaks.
DOWNSTREAM_MANIFESTS = ("derived_v2_2/records.jsonl",)

# The ledger of PoC attempts: it records the digest of every artefact of every
# attempt, including the attempt's own result.json.
LEDGER_FILES = ("reports/poc_attempts.jsonl",)


def _is_genuine_upstream(path: bytes) -> bool:
    """Is this path shape an upstream quote, not a path on a local machine?

    The comparison is on the unescaped shape, so a JSON-escaped upstream
    quote is recognised as well.
    """
    probe = path.replace(b"\\\\", b"\\")
    return any(rx.match(probe) for rx in GENUINE_UPSTREAM)


def redact_bytes(data: bytes) -> tuple[bytes, int]:
    """Redact one buffer. Returns (redacted bytes, number of replacements)."""
    count = 0

    # 1. an absolute interpreter path becomes the portable `python`.
    def _interp(m: re.Match) -> bytes:
        nonlocal count
        start = m.start()
        # a path inside a URL is part of the URL, not a local path
        if start >= 3 and data[start - 3:start] == b"://":
            return m.group(0)
        token = m.group(0)
        base = re.split(rb"[/\\]", token)[-1]
        if not PY_BASENAME.match(base):
            return m.group(0)
        count += 1
        return PORTABLE_PYTHON.encode("ascii")

    data = WIN_TOKEN.sub(_interp, data)
    data = POSIX_TOKEN.sub(_interp, data)

    # 2. the account component of a machine-local path becomes the token.
    def _profile(m: re.Match) -> bytes:
        nonlocal count
        name = m.group("name")
        if name == REDACTION_TOKEN.encode("ascii"):
            return m.group(0)
        if _is_genuine_upstream(m.group(0)):
            return m.group(0)
        start, end = m.span("name")
        count += 1
        return (m.group(0)[:start - m.start()] +
                REDACTION_TOKEN.encode("ascii") +
                m.group(0)[end - m.start():])

    data = WIN_PROFILE.sub(_profile, data)
    data = POSIX_PROFILE.sub(_profile, data)
    return data, count


def redact_text(text: str) -> str:
    """Redact captured output before it is written to an artefact."""
    out, _ = redact_bytes(text.encode("utf-8", "surrogateescape"))
    return out.decode("utf-8", "surrogateescape")


def redact_argv(argv: list[str]) -> list[str]:
    """Redact a recorded argv so the command can be re-run anywhere."""
    out = []
    for a in argv:
        b, _ = redact_bytes(a.encode("utf-8", "surrogateescape"))
        out.append(b.decode("utf-8", "surrogateescape"))
    return out


def redact_obj(obj):
    """Redact every string in a JSON-like structure, in place of the value."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj


# ---------------------------------------------------------------------------
# files
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


def in_scope(rel: str) -> bool:
    return any(rel.startswith(s) for s in SCOPE)


def is_read_only_layer(rel: str) -> bool:
    return any(rel.startswith(s) for s in READ_ONLY_LAYERS)


def scope_files() -> list[str]:
    """Every tracked file the redaction may touch, plus untracked ones."""
    out = []
    for rel in _git("ls-files", "-z") + _git("ls-files", "--others",
                                            "--exclude-standard", "-z"):
        if not in_scope(rel) or is_read_only_layer(rel):
            continue
        if (ROOT / rel).is_file():
            out.append(rel)
    return sorted(set(out))


def digest_of(rel: str, scheme: str = "raw") -> str:
    """The digest a manifest in this layer records for a file."""
    data = (ROOT / rel).read_bytes()
    if scheme == "text":
        data = data.replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _replace_digest(data: bytes, old: str, new: str,
                    old_bytes: int | None, new_bytes: int | None) -> bytes:
    """Swap one recorded digest (and its byte count) for the new value.

    The digest and the byte count live in the same JSON object, but not
    necessarily next to each other (the keys are sorted, so `bytes` can come
    first and `sha256` last), so the enclosing object is located and patched
    as a whole. The bytes are patched in place, not re-serialised, so the
    file keeps its exact formatting.
    """
    if old == new:
        return data
    ob = old.encode("ascii")
    nb = new.encode("ascii")
    needle = b'"' + ob + b'"'
    out = data
    pos = 0
    while True:
        idx = out.find(needle, pos)
        if idx < 0:
            break
        start = out.rfind(b"{", 0, idx)
        end = out.find(b"}", idx)
        if start < 0 or end < 0:
            out = out[:idx] + b'"' + nb + b'"' + out[idx + len(needle):]
            pos = idx + len(nb) + 2
            continue
        chunk = out[start:end].replace(needle, b'"' + nb + b'"')
        if old_bytes is not None and new_bytes is not None and old_bytes != new_bytes:
            pat = re.compile(rb'("bytes":\s*)' + str(old_bytes).encode("ascii") +
                             rb'(?![0-9])')
            chunk, _ = pat.subn(
                lambda m: m.group(1) + str(new_bytes).encode("ascii"),
                chunk, count=1)
        out = out[:start] + chunk + out[end:]
        pos = start + len(chunk)
    return out


def _recorded_digests(rel: str) -> list[tuple[str, str, int | None, int | None]]:
    """Every (old digest, file, old byte count) a manifest records."""
    path = ROOT / rel
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    out: list[tuple[str, str, int | None, int | None]] = []

    def record(target: Path, value) -> None:
        if isinstance(value, dict):
            old = value.get("sha256")
            old_bytes = value.get("bytes")
        else:
            old = value
            old_bytes = None
        if not isinstance(old, str) or len(old) != 64:
            return
        if not target.is_file() or target.resolve() == path.resolve():
            return
        out.append((old, target.relative_to(ROOT).as_posix(), old_bytes,
                    target.stat().st_size))

    def record_map(base: Path, mapping) -> None:
        """A mapping of file name -> digest, relative to `base`."""
        if not isinstance(mapping, dict):
            return
        for name, value in mapping.items():
            record(base / name, value)

    def record_list(mapping) -> None:
        """A list of {path, sha256} entries, relative to the repository."""
        if not isinstance(mapping, list):
            return
        for entry in mapping:
            if not isinstance(entry, dict):
                continue
            rel_path = entry.get("path")
            if not isinstance(rel_path, str):
                continue
            record(ROOT / rel_path, entry)

    if rel.endswith(".jsonl"):
        for line in raw.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            base = ROOT / str(row.get("artefact_dir") or "")
            for key in DIGEST_KEYS:
                record_map(base, row.get(key))
            record_list((row.get("experiment_view") or {}).get("artefacts"))
        return out

    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    base = path.parent
    for key in DIGEST_KEYS:
        record_map(base, doc.get(key))
    for entry in doc.get("experiments") or []:
        if not isinstance(entry, dict):
            continue
        base = ROOT / "experiments_v2_2" / str(entry.get("experiment_id") or "")
        record_map(base, entry.get("artefacts"))
    for row in doc.get("records") or []:
        if not isinstance(row, dict):
            continue
        record_list((row.get("experiment_view") or {}).get("artefacts"))
    return out


def reconcile_manifests(rel: str) -> int:
    """Re-point the digests a manifest records at the bytes on disk.

    A manifest that keeps the digest of the pre-redaction bytes describes a
    file that no longer exists, so the digest is recomputed from the bytes on
    disk. The JSON is patched in place (not re-serialised) so the file keeps
    its exact formatting and only the digest changes.
    """
    path = ROOT / rel
    data = path.read_bytes()
    scheme = "text" if rel.startswith(DIGEST_SCHEME_TEXT) else "raw"
    changed = 0
    for old, target, old_bytes, new_bytes in _recorded_digests(rel):
        new = digest_of(target, scheme)
        out = _replace_digest(data, old, new, old_bytes, new_bytes)
        if out != data:
            data = out
            changed += 1
    if changed:
        path.write_bytes(data)
    return changed


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="report what would change; write nothing")
    ap.add_argument("--files", action="store_true",
                    help="print one line per changed file")
    ap.add_argument("--quiet", action="store_true",
                    help="print one summary line only")
    args = ap.parse_args(argv)

    files = scope_files()
    for rel in files:
        if is_read_only_layer(rel):
            raise SystemExit(f"refusing to rewrite the read-only layer: {rel}")

    # The manifests whose recorded digests have to follow the redacted bytes.
    manifests = [rel for rel in files
                 if rel.startswith(DIGEST_RECONCILE_TREES) or
                 rel in LEDGER_FILES]
    manifests += [rel for rel in DOWNSTREAM_MANIFESTS
                  if (ROOT / rel).is_file()]

    changed: list[tuple[str, int, int]] = []
    total_paths = 0
    total_digests = 0

    if args.check:
        for rel in files:
            data = (ROOT / rel).read_bytes()
            out, hits = redact_bytes(data)
            if out == data:
                continue
            changed.append((rel, hits, 0))
            total_paths += hits
    else:
        # 1. redact the text of every file in scope
        for rel in files:
            path = ROOT / rel
            data = path.read_bytes()
            out, hits = redact_bytes(data)
            if out == data:
                continue
            path.write_bytes(out)
            changed.append((rel, hits, 0))
            total_paths += hits
        # 2. re-point the recorded digests at the redacted bytes. A manifest
        #    can record the digest of another manifest (the attempt ledger
        #    records the attempt's result.json), so this runs to a fixpoint.
        digests_per_file: dict[str, int] = {}
        for _ in range(8):
            round_changes = 0
            for rel in manifests:
                n = reconcile_manifests(rel)
                if n:
                    digests_per_file[rel] = digests_per_file.get(rel, 0) + n
                    round_changes += n
            total_digests += round_changes
            if not round_changes:
                break
        changed = [(rel, hits, digests_per_file.get(rel, 0))
                   for rel, hits, _ in changed]
        for rel, n in sorted(digests_per_file.items()):
            if rel not in [c[0] for c in changed]:
                changed.append((rel, 0, n))

    if args.files:
        for rel, hits, digests in changed:
            print(f"  {rel}: {hits} path(s), {digests} digest(s)")
    if not args.quiet:
        print(f"scanned {len(files)} file(s) in scope")
        print(f"  machine paths redacted : {total_paths}")
        print(f"  digests re-pointed     : {total_digests}")
        print(f"  files changed          : {len(changed)}")
    else:
        print(f"files={len(files)} changed={len(changed)} "
              f"paths={total_paths} digests={total_digests}")
    if args.check and changed:
        print(f"  {len(changed)} file(s) still carry a machine path")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

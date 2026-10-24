"""Verify every recorded artefact hash against the committed bytes.

Every layer that publishes run artefacts publishes a digest for them, and a
digest that does not match the shipped bytes is a broken provenance claim, not
a cosmetic issue. This script is the canonical check for all of them: it knows
which layer records which scheme, recomputes each digest from the committed
bytes, and fails on any mismatch that is not explicitly recorded as
unresolved.

The hashing schemes
--------------------
The repository grew two conventions before this file named them, so a digest
alone did not say how it had been computed. Both are recorded here, and every
newly computed digest carries ``hash_version`` so that a future reader never
has to guess:

  sha256-v2        the scheme going forward. The digest of the artefact's
                   committed bytes with every CRLF replaced by LF. It is
                   identical on an LF checkout and on a CRLF checkout, so the
                   gate cannot pass on one machine and fail on another.

  sha256-v1-text   historical. The digest of the artefact read as UTF-8 text
                   with universal newlines. For every artefact committed with
                   LF - which is all of them except the three verbatim tool
                   outputs under experiments_v3/1inch-lop-m01/ - this is the
                   same value as sha256-v2.

  sha256-v1-raw    historical. The digest of the bytes the tool actually
                   emitted, which on Windows means CRLF. The artefacts of
                   experiments_v2_2/ and experiments_nonevm/ were committed
                   before .gitattributes gave those trees the -text attribute
                   (added in c124c7e), so git normalised their CRLF bytes to LF
                   in the commit. The recorded digest therefore identifies the
                   committed content with every LF expanded back to CRLF, and
                   that is how it is verified here.

  sha256-v1-bytes  historical. The digest of the artefact's bytes exactly as
                   committed, with no newline handling at all. The
                   experiments_v3/ tree is committed with -text, so a checkout
                   reproduces those bytes verbatim.

Unresolved mismatches
---------------------
A recorded digest that cannot be reproduced from the committed bytes is not
silently rewritten. It is listed in UNRESOLVED_ARTEFACT_HASHES below, with
the recorded value, the value the committed bytes actually have, the reason
and - where one exists - the commit whose blob reproduces the original. The
check fails if a mismatch is not in that list, and it also fails if a listed
mismatch has stopped being a mismatch, so the list cannot rot.

Usage:
    python scripts/reconcile_proof_artefact_hashes.py          # rewrite v3 hashes
    python scripts/reconcile_proof_artefact_hashes.py --check  # fail if stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROOF = ROOT / "reports" / "v3" / "experimental_proof.json"

# The record files that inherit the proof's hashes. A record's
# `experiment.artifact_hashes` is a copy of the proof's, so it drifts the
# same way and must be reconciled from the same ground truth.
RECORD_FILES = [
    ROOT / "jsonl_v3" / "findings.jsonl",
    ROOT / "derived_v3" / "records.jsonl",
]

# ---------------------------------------------------------------------------
# the scheme
# ---------------------------------------------------------------------------
HASH_VERSION = "sha256-v2"
"""The version string a newly computed artefact digest carries."""

SCHEME_SUMMARY = {
    "sha256-v2": ("digest of the committed bytes with CRLF replaced by LF; "
                  "identical on an LF checkout and on a CRLF checkout"),
    "sha256-v1-text": ("digest of the artefact read as UTF-8 text with universal "
                       "newlines; equal to sha256-v2 for every artefact committed "
                       "with LF"),
    "sha256-v1-raw": ("digest of the bytes the tool emitted (CRLF on Windows); "
                      "the committed bytes carry the same content with LF, so the "
                      "value is reproduced by expanding every LF back to CRLF"),
    "sha256-v1-bytes": ("digest of the artefact's bytes exactly as committed, "
                        "with no newline handling; used by the experiments_v3/ tree, "
                        "which is committed with -text"),
}


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_normalised(data: bytes) -> str:
    """sha256-v2: the committed content, independent of the checkout's EOL policy."""
    return digest_bytes(data.replace(b"\r\n", b"\n"))


def digest_expanded(data: bytes) -> str:
    """sha256-v1-raw seen from an LF checkout: the emitted CRLF bytes."""
    return digest_bytes(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))


def digests_for(data: bytes) -> dict:
    return {
        "raw": digest_bytes(data),
        "normalised": digest_normalised(data),
        "expanded": digest_expanded(data),
    }


def matches(want: str, data: bytes, scheme: str) -> tuple[bool, str]:
    """Does `want` identify these bytes under `scheme`? -> (ok, which digest)."""
    d = digests_for(data)
    if scheme in ("sha256-v2", "sha256-v1-text"):
        return (want == d["normalised"], "normalised")
    if scheme == "sha256-v1-raw":
        # The emitted bytes are CRLF; the committed bytes may be LF (committed
        # before -text was in force) or CRLF (this checkout). Both are the
        # same content, so both are accepted.
        if want == d["raw"]:
            return True, "raw"
        if want == d["expanded"]:
            return True, "expanded"
        return False, ""
    if scheme == "sha256-v1-bytes":
        return (want == d["raw"], "raw")
    raise ValueError(f"unknown hash scheme {scheme!r}")


# ---------------------------------------------------------------------------
# the layers that publish artefact digests
# ---------------------------------------------------------------------------
# Each layer is (label, directory, result glob, key, scheme). `key` is the
# field in the result file that holds {artefact: digest}; the digest may be a
# plain string or a {"bytes":..., "sha256":...} object.
LAYERS = [
    ("v1 experiments", ROOT / "experiments", "*/*/result.json",
     "artifact_sha256", "sha256-v1-text"),
    ("v2.2 experiments", ROOT / "experiments_v2_2", "*/result.json",
     "artefacts", "sha256-v1-raw"),
    ("v2.2 index", ROOT / "experiments_v2_2", "index.json",
     "artefacts", "sha256-v1-raw"),
    ("nonevm experiments", ROOT / "experiments_nonevm", "*/*/result.json",
     "artefacts", "sha256-v1-raw"),
    ("v3 experiments", ROOT / "experiments_v3", "*/result.json",
     "artifact_hashes", "sha256-v1-bytes"),
]


def want_of(value) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("sha256")
    return None


# ---------------------------------------------------------------------------
# recorded, unresolved mismatches
# ---------------------------------------------------------------------------
# A recorded digest that cannot be reproduced from the committed bytes. The
# original value is never rewritten away; it is listed here with the reason.
UNRESOLVED_ARTEFACT_HASHES = [
    {
        "path": "experiments/2024-01-renft__H-03/vulnerable/stderr.txt",
        "recorded_sha256": "2adedc5f8aeee70cd0d0aec67089e8ac7854b9c52ffcae5fd042d41df4c7b05c",
        "committed_sha256": "2db60f784c9e53c73eea228832dbeb4b17e2953547093e1f7edb208054e6ecb8",
        "recorded_hash_version": "sha256-v1-text",
        "reason": ("the committed stderr.txt was redacted after the run (the local "
                   "path in the compiler message became C:/Users/REDACTED/...), so the "
                   "recorded digest no longer describes the committed bytes"),
        "original_reproducible_from": ("93af4b9:experiments/2024-01-renft__H-03/"
                                       "vulnerable/stderr.txt"),
        "note": ("the recorded digest is genuine: it is the digest of the "
                 "pre-redaction bytes, reproducible byte for byte from the blob "
                 "above. It cannot be reproduced from the bytes committed today."),
    },
    {
        "path": "experiments/2024-01-renft__H-04/vulnerable/stderr.txt",
        "recorded_sha256": "ca934e321fb6c32a1df6c90dddcdb4637ae494d3b2ee751e09661758e7844775",
        "committed_sha256": "05fcbeaee2e6e2ddb2663663d2a61e4a826047395a8b46ef0332e09b3d7b0e60",
        "recorded_hash_version": "sha256-v1-text",
        "reason": ("the committed stderr.txt was redacted after the run (the local "
                   "path in the compiler message became C:/Users/REDACTED/...), so the "
                   "recorded digest no longer describes the committed bytes"),
        "original_reproducible_from": ("93af4b9:experiments/2024-01-renft__H-04/"
                                       "vulnerable/stderr.txt"),
        "note": ("the recorded digest is genuine: it is the digest of the "
                 "pre-redaction bytes, reproducible byte for byte from the blob "
                 "above. It cannot be reproduced from the bytes committed today."),
    },
    {
        "path": "experiments/2024-01-renft__M-09/vulnerable/stderr.txt",
        "recorded_sha256": "ef7b55c879a552d9602ea950b8bfd7520ace96fab4adea912d2530d48f06b8b0",
        "committed_sha256": "6aebb40821548041d891f81cbc533fa3914f862ddc0c0541a07b4673564821cd",
        "recorded_hash_version": "sha256-v1-text",
        "reason": ("the committed stderr.txt was redacted after the run (the local "
                   "path in the compiler message became C:/Users/REDACTED/...), so the "
                   "recorded digest no longer describes the committed bytes"),
        "original_reproducible_from": ("93af4b9:experiments/2024-01-renft__M-09/"
                                       "vulnerable/stderr.txt"),
        "note": ("the recorded digest is genuine: it is the digest of the "
                 "pre-redaction bytes, reproducible byte for byte from the blob "
                 "above. It cannot be reproduced from the bytes committed today."),
    },
    {
        "path": "experiments/2024-01-renft__submission-621/attempted/stderr.txt",
        "recorded_sha256": "34ed04a954ff9d4d5deb9b6c9e1c53910b1e48fb9622c298289d8c8bfa5b74eb",
        "committed_sha256": "5c35535de4b098f2f9ad3265ddf74134d9aac53b8273836b45ada74e977436c2",
        "recorded_hash_version": "sha256-v1-text",
        "reason": ("the committed stderr.txt was redacted after the run (the local "
                   "path in the compiler message became C:/Users/REDACTED/...), so the "
                   "recorded digest no longer describes the committed bytes"),
        "original_reproducible_from": ("93af4b9:experiments/2024-01-renft__submission-621/"
                                       "attempted/stderr.txt"),
        "note": ("the recorded digest is genuine: it is the digest of the "
                 "pre-redaction bytes, reproducible byte for byte from the blob "
                 "above. It cannot be reproduced from the bytes committed today."),
    },
]

# Categories that are hash-claimed but are NOT verifiable against bytes in this
# repository. They are named here so that they are not silently ignored.
NON_VERIFIABLE_HASH_CATEGORIES = [
    {
        "category": "withheld harness files",
        "where": ("experiments/**/harness/WITHHELD.json and "
                  "distribution_v1/withheld_harness.jsonl"),
        "claim": ("a sha256 per withheld harness file, i.e. per verbatim copy of a "
                  "file from the audited (BUSL-1.1) repository"),
        "why_not_verifiable": ("the bytes are deliberately not published here, so "
                               "there is nothing in this repository to hash. Each "
                               "entry carries the upstream commit and path it can be "
                               "obtained from, and scripts/validate_checks.py checks "
                               "that every withheld file has such a resolver."),
        "checked_by": "scripts/validate_checks.py (withheld_harness_files_carry_a_resolver)",
    },
]


def unresolved_index() -> dict:
    return {e["path"]: e for e in UNRESOLVED_ARTEFACT_HASHES}


# ---------------------------------------------------------------------------
# the scan
# ---------------------------------------------------------------------------
def scan_layer(label, base, pattern, key, scheme):
    """-> (checked, mismatches, missing) for one layer."""
    checked, mismatches, missing = 0, [], []
    if not base.is_dir():
        return checked, mismatches, missing
    for res in sorted(base.glob(pattern)):
        doc = json.loads(res.read_text(encoding="utf-8"))
        if res.name == "index.json":
            entries = []
            for e in doc.get("experiments") or []:
                for n, v in (e.get(key) or {}).items():
                    entries.append((base / e["experiment_id"] / n, n, v))
        else:
            entries = [(res.parent / n, n, v)
                       for n, v in (doc.get(key) or {}).items()]
        for path, name, value in entries:
            want = want_of(value)
            if want is None:
                continue
            rel = path.relative_to(ROOT).as_posix() if path.is_absolute() else str(path)
            if not path.is_file():
                missing.append(f"{label}: {rel} MISSING")
                continue
            checked += 1
            ok, which = matches(want, path.read_bytes(), scheme)
            if not ok:
                mismatches.append({
                    "path": rel, "layer": label, "recorded_sha256": want,
                    "committed_sha256": digest_normalised(path.read_bytes()),
                    "scheme": scheme,
                })
    return checked, mismatches, missing


def scan_record_layers():
    """The record layers that copy the proof's or the v2.2 digests."""
    checked, mismatches, missing = 0, [], []
    for path in RECORD_FILES:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            exp = (json.loads(line).get("experiment") or {})
            d = exp.get("artifact_dir")
            for name, want in (exp.get("artifact_hashes") or {}).items():
                f = ROOT / d / name
                if not f.is_file():
                    missing.append(f"{path.name}: {d}/{name} MISSING")
                    continue
                checked += 1
                ok, _ = matches(want, f.read_bytes(), "sha256-v1-bytes")
                if not ok:
                    mismatches.append({
                        "path": f"{d}/{name}", "layer": path.name,
                        "recorded_sha256": want,
                        "committed_sha256": digest_normalised(f.read_bytes()),
                        "scheme": "sha256-v1-bytes",
                    })
    # derived_v2_2 records the v2.2 artefacts with the text scheme.
    d22 = ROOT / "derived_v2_2" / "records.jsonl"
    if d22.is_file():
        for line in d22.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            ev = (json.loads(line).get("experiment_view") or {})
            for a in ev.get("artefacts") or []:
                want = want_of(a)
                if not want:
                    continue
                f = ROOT / a["path"]
                if not f.is_file():
                    missing.append(f"derived_v2_2: {a['path']} MISSING")
                    continue
                checked += 1
                ok, _ = matches(want, f.read_bytes(), "sha256-v1-text")
                if not ok:
                    mismatches.append({
                        "path": a["path"], "layer": "derived_v2_2",
                        "recorded_sha256": want,
                        "committed_sha256": digest_normalised(f.read_bytes()),
                        "scheme": "sha256-v1-text",
                    })
    return checked, mismatches, missing


def scan_proof():
    """The v3 proof file itself."""
    checked, mismatches, missing = 0, [], []
    if not PROOF.is_file():
        return checked, mismatches, missing
    doc = json.loads(PROOF.read_text(encoding="utf-8"))
    for run in doc.get("runs", []):
        d = run.get("artifact_dir")
        for name, want in (run.get("artifact_hashes") or {}).items():
            f = ROOT / d / name
            if not f.is_file():
                missing.append(f"experimental_proof.json: {d}/{name} MISSING")
                continue
            checked += 1
            ok, _ = matches(want, f.read_bytes(), "sha256-v1-bytes")
            if not ok:
                mismatches.append({
                    "path": f"{d}/{name}", "layer": "experimental_proof.json",
                    "recorded_sha256": want,
                    "committed_sha256": digest_normalised(f.read_bytes()),
                    "scheme": "sha256-v1-bytes",
                })
    return checked, mismatches, missing


def scan_all():
    """Scan every layer that publishes artefact digests."""
    checked = 0
    mismatches, missing = [], []
    per_layer = []
    for label, base, pattern, key, scheme in LAYERS:
        c, m, x = scan_layer(label, base, pattern, key, scheme)
        checked += c
        mismatches += m
        missing += x
        per_layer.append({"layer": label, "scheme": scheme, "digests": c,
                           "mismatches": len(m)})
    c, m, x = scan_record_layers()
    checked += c
    mismatches += m
    missing += x
    per_layer.append({"layer": "v3 record files + derived_v2_2",
                      "scheme": "sha256-v1-bytes / sha256-v1-text",
                      "digests": c, "mismatches": len(m)})
    c, m, x = scan_proof()
    checked += c
    mismatches += m
    missing += x
    per_layer.append({"layer": "experimental_proof.json", "scheme": "sha256-v1-bytes",
                      "digests": c, "mismatches": len(m)})
    return checked, mismatches, missing, per_layer


# ---------------------------------------------------------------------------
# the original behaviour: reconciling the v3 proof and its copies
# ---------------------------------------------------------------------------
def disk_hashes(base: pathlib.Path, names) -> dict:
    out = {}
    for n in names:
        f = base / n
        if f.is_file():
            out[n] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def reconcile_records(strict: bool = True) -> list[str]:
    """Point every record's artefact hashes at the bytes on disk."""
    problems = []
    for path in RECORD_FILES:
        if not path.is_file():
            continue
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        dirty = False
        for r in rows:
            exp = r.get("experiment") or {}
            d = exp.get("artifact_dir")
            hashes = exp.get("artifact_hashes") or {}
            if not d or not hashes:
                continue
            base = ROOT / d
            truth = disk_hashes(base, hashes.keys())
            for name, want in hashes.items():
                got = truth.get(name)
                if got is None:
                    problems.append(f"{path.name}: {d}/{name} MISSING")
                elif got != want:
                    if strict:
                        problems.append(
                            f"{path.name}: {d}/{name} {want[:12]} != {got[:12]}")
                    else:
                        hashes[name] = got
                        dirty = True
        if dirty:
            path.write_text(
                "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                        for r in rows),
                encoding="utf-8", newline="\n")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--list-unresolved", action="store_true",
                    help="print the recorded unresolved mismatches and exit")
    args = ap.parse_args()
    if args.list_unresolved:
        print(json.dumps(UNRESOLVED_ARTEFACT_HASHES, indent=2))
        return 0
    if not PROOF.is_file():
        print(f"missing {PROOF}", file=sys.stderr)
        return 1

    checked, mismatches, missing, per_layer = scan_all()
    known = unresolved_index()
    unrecorded = []
    stale = []
    for m in mismatches:
        entry = known.get(m["path"])
        if entry is None:
            unrecorded.append(m)
        elif entry["recorded_sha256"] != m["recorded_sha256"] or \
                entry["committed_sha256"] != m["committed_sha256"]:
            unrecorded.append(m)
    seen = {m["path"] for m in mismatches}
    for path, entry in known.items():
        if path not in seen:
            stale.append(path)

    if args.check:
        problems = reconcile_records(strict=True)
        allp = [f"{m['layer']}: {m['path']} {m['recorded_sha256'][:12]} != "
                f"{m['committed_sha256'][:12]} (not recorded as unresolved)"
                for m in unrecorded]
        allp += [f"{m['layer']}: {m['path']} MISSING" for m in missing]
        allp += [f"{path}: listed as unresolved but the digest now matches"
                 for path in stale]
        allp += problems
        if allp:
            print(f"{len(allp)} artefact hash problem(s):\n  "
                  + "\n  ".join(allp[:20])
                  + "\n-- run: python scripts/reconcile_proof_artefact_hashes.py",
                  file=sys.stderr)
            return 1
        print(f"artefact hashes are current: {checked} digest(s) over "
              f"{len(per_layer)} layer(s), "
              f"{len(known)} recorded as unresolved")
        for layer in per_layer:
            print(f"  {layer['layer']:34s} {layer['scheme']:34s} "
                  f"{layer['digests']:4d} digest(s), "
                  f"{layer['mismatches']} unresolved")
        for cat in NON_VERIFIABLE_HASH_CATEGORIES:
            print(f"  [not hash-verifiable here] {cat['category']}: {cat['where']}")
        return 0

    stale_proof = []
    changed = 0
    doc = json.loads(PROOF.read_text(encoding="utf-8"))
    for run in doc.get("runs", []):
        d = run.get("artifact_dir")
        hashes = run.get("artifact_hashes") or {}
        if not d or not hashes:
            continue
        base = ROOT / d
        for name, want in sorted(hashes.items()):
            f = base / name
            if not f.is_file():
                stale_proof.append(f"{d}/{name}: MISSING")
                continue
            got = digest_bytes(f.read_bytes())
            if got != want:
                stale_proof.append(f"{d}/{name}: {want[:12]} != {got[:12]}")
                hashes[name] = got
                changed += 1
    rec_problems = reconcile_records(strict=False)
    if stale_proof:
        PROOF.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8", newline="\n")
        print(f"recomputed {changed} hash(es) across "
              f"{len(doc.get('runs', []))} proof runs -> {PROOF}")
    if rec_problems:
        print(f"reconciled {len(rec_problems)} record-level hash(es) in "
              + ", ".join(p.name for p in RECORD_FILES))
    if not stale_proof and not rec_problems:
        print("nothing stale; no files rewritten")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

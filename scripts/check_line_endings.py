"""Scan every tracked text file for CRLF and report offenders.

Windows text-mode writers emit CRLF, which .gitattributes (eol=lf) then
rewrites on checkout -- producing "LF will be replaced by CRLF" warnings and
breaking byte-identity gates. This finds the offenders so the fix lands on
the writer, not on a blanket renormalise.

Run:  python scripts/check_line_endings.py
Exit: 1 if any tracked text file contains CRLF (never renormalise silently).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {".jsonl", ".json", ".md", ".csv", ".py", ".sol", ".toml",
                 ".txt", ".yml", ".yaml", ".cff", ".cfg", ".ini"}
# Locally-scraped / vendored trees are git-ignored and never normalised.
EXCLUDED_PREFIXES = ("work/", "V3/clones/", "nextdata/", ".firecrawl/",
                     ".freebuff/", "brag-output/", ".git/", ".pytest_cache/")
# Verbatim execution evidence is stored byte-for-byte as the tool emitted it
# (.gitattributes marks it -text). Its line endings are part of the artefact
# and of its recorded sha256, so they are NOT normalised or flagged.
EVIDENCE_PREFIXES = ("experiments/", "experiments_v2_2/", "experiments_v3/")


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT),
                             capture_output=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"cannot list tracked files: {exc}", file=sys.stderr)
        return []
    return [f for f in out.stdout.decode("utf-8", "replace").split("\0") if f]


def _blob(rel: str) -> bytes | None:
    """The bytes git would store for `rel`, or None if unavailable.

    Read from the index (`git cat-file blob :path`) rather than the working
    tree: on a machine with core.autocrlf=true the checkout is CRLF even
    when the committed content is LF, and eol=lf means git normalises it
    back on commit. What matters is the byte stream that reaches the
    repository, and its sha256 gates depend on that one. Untracked files
    have no index entry, so they fall back to the working tree.
    """
    out = subprocess.run(["git", "cat-file", "blob", f":{rel}"],
                         cwd=str(ROOT), capture_output=True)
    if out.returncode == 0 and out.stdout:
        return out.stdout
    p = ROOT / rel
    try:
        return p.read_bytes()
    except OSError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    offenders: list[str] = []
    scanned = 0
    for rel in tracked_files():
        if rel.startswith(EXCLUDED_PREFIXES) or rel.startswith(EVIDENCE_PREFIXES):
            continue
        if Path(rel).suffix.lower() not in TEXT_SUFFIXES:
            continue
        if not (ROOT / rel).is_file():
            continue
        blob = _blob(rel)
        if blob is None:
            continue
        if b"\x00" in blob[:4096]:      # binary mislabelled by extension
            continue
        scanned += 1
        if b"\r\n" in blob:
            offenders.append(rel)

    if offenders:
        if not args.quiet:
            print(f"check_line_endings: {len(offenders)} file(s) would be "
                  f"committed with CRLF (of {scanned} scanned):")
            for rel in offenders[:40]:
                print(f"  {rel}")
            if len(offenders) > 40:
                print(f"  ... {len(offenders) - 40} more")
            print("\nFix the WRITER: pass newline=\"\\n\" to write_text/open, "
                  "or use vlun_v3.write_json/write_jsonl. Do not blanket-"
                  "normalise: that hides a writer that will reintroduce CRLF.")
        return 1
    if not args.quiet:
        print(f"check_line_endings: {scanned} tracked text files, all LF")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
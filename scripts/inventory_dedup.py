#!/usr/bin/env python3
"""Read-only inventory: exact-corpus dedup snapshot for the VLUN expansion plan.

Step 1 of the plan: scan ALL five existing layers (v1, v2.2, V3, Vbeta, V4)
and print

  * the exact list of the 18 V3 archives (jsonl_v3/sources.jsonl);
  * the exact list of the 112 v2.2 sources (union of source ids in
    jsonl_ml/sources_*.jsonl);
  * totals across all five layers: unique normalized URLs,
    (auditor_or_org, protocol_or_repo, normalized_title) keys, and sha256
    digests, plus a per-layer breakdown and sample keys.

Method notes (definitions used by this script):
  * Normalized URL: scheme + host lowercased, default ports dropped,
    trailing slashes and fragments stripped; the query string is kept.
    String values that start with a scheme are used as URLs verbatim
    (to preserve URLs embedded in spaced GitHub paths); URLs found
    mid-text are extracted with a regex that stops at quotes/brackets.
  * Title: whitespace collapsed, lowercased.
  * Digests: any 64-hex string found in record values is counted (mostly
    sha256 of reports/files; 40-hex git commit ids are not counted).
  * Keys are per-layer extracts of (auditor_or_org, protocol_or_repo,
    normalized_title); example keys are printed per layer.
  * rows = parsed JSON records + non-JSON data files (1 each); files =
    data files read.

Read-only: reads every file under the layer roots; writes nothing.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent.parent

LAYER_ROOTS = {
    "v1": ["jsonl", "derived"],
    "v2.2": ["jsonl_ml", "derived_v2_2"],
    "V3": ["jsonl_v3", "derived_v3"],
    "Vbeta": ["Vbeta", "nextdata", ".firecrawl"],
    "V4": ["jsonl_v4", "V4"],
}

URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]]+", re.IGNORECASE)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
WS_RE = re.compile(r"\s+")
SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# normalization helpers
# --------------------------------------------------------------------------- #


def normalize_url(url: str) -> str:
    """Normalize a URL for dedup keys (see module docstring)."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip().lower()
    scheme = p.scheme.lower()
    netloc = p.netloc.lower().rstrip(".")
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    if scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = p.path or ""
    while len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return urlunsplit((scheme, netloc, path, p.query, ""))


def norm_title(t: object) -> str:
    """Normalized title: whitespace collapsed, lowercased."""
    return WS_RE.sub(" ", str(t or "").strip()).lower()


# --------------------------------------------------------------------------- #
# generic recursive collectors (schema-free: works on any parsed record)
# --------------------------------------------------------------------------- #


def collect_urls_text(text: str) -> list[str]:
    """Extract scheme'd URLs from raw text (mid-text regex extraction)."""
    out = []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,;:")
        if u:
            out.append(u)
    return out


def collect_urls_record(rec: object) -> list[str]:
    """Collect URLs from a parsed record: field values that start with a
    scheme are taken verbatim (keeps GitHub URLs with spaced paths);
    everything else is regex-extracted."""
    out: list[str] = []

    def walk(x: object) -> None:
        if isinstance(x, str):
            s = x.strip()
            if SCHEME_RE.match(s):
                out.append(s.rstrip(".,;:"))
            else:
                out.extend(collect_urls_text(x))
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(rec)
    return out


def collect_digests_record(rec: object) -> set[str]:
    """Collect 64-hex strings from a parsed record."""
    out: set[str] = set()

    def walk(x: object) -> None:
        if isinstance(x, str):
            s = x.strip().lower()
            if HEX64_RE.match(s):
                out.add(s)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(rec)
    return out


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #


def parse_records(path: Path) -> list[dict]:
    """Yield parsed JSON records from a .jsonl/.json file (read-only).
    Unparseable lines/files are skipped silently."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        recs: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict):
                recs.append(r)
            elif isinstance(r, list):
                recs.extend(d for d in r if isinstance(d, dict))
        return recs
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict) and isinstance(data.get("sources"), list):
            return [d for d in data["sources"] if isinstance(d, dict)]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return [data] if isinstance(data, dict) else []
    return []


def iter_files(roots: list[str]):
    for root_rel in roots:
        root = ROOT / root_rel
        if not root.is_dir():
            print(f"  [warn] layer root missing: {root_rel}")
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                yield Path(dirpath) / name


# --------------------------------------------------------------------------- #
# per-layer key extractors
# --------------------------------------------------------------------------- #


def _d(x: object) -> dict:
    return x if isinstance(x, dict) else {}


def v1_key(r: dict):
    src = _d(r.get("source"))
    finding = _d(r.get("finding"))
    org = src.get("organization") or r.get("organization") or ""
    repo = src.get("repository") or r.get("repository") or ""
    title = finding.get("title") or r.get("title") or ""
    return (org or "", repo or "", norm_title(title))


def v22_key(r: dict):
    finding = _d(r.get("finding"))
    sources = (_d(r.get("sources_view")).get("entries") or [])
    first = _d(sources[0]) if sources else {}
    repo = first.get("repository") or ""
    org = (
        r.get("auditor")
        or _d(r.get("source")).get("organization")
        or (repo.split("/")[0] if repo else "")
        or (first.get("source_id") or "").split(":")[0]
    )
    title = finding.get("title") or r.get("title") or ""
    return (
        org or "",
        repo or (finding.get("id") or "").split(":")[0] or "",
        norm_title(title),
    )


def v3_key(r: dict):
    org = r.get("organization") or r.get("project") or ""
    repo = r.get("protocol") or r.get("repository") or ""
    title = r.get("title") or r.get("original_title") or r.get("finding_title") or ""
    return (org or "", repo or "", norm_title(title))


def vbeta_key(r: dict):
    org = r.get("attribution") or r.get("organization") or ""
    if not org:
        sid = r.get("source_id") or r.get("source_name") or ""
        if ":" in sid:
            org = sid.split(":")[0]
        elif sid:
            org = sid.split("-")[0]
    repo = r.get("source_location") or r.get("repository") or r.get("source_id") or ""
    title = r.get("finding_title") or r.get("title") or r.get("source_name") or ""
    return (org or "", repo or "", norm_title(title))


def v4_key(r: dict):
    org = r.get("source_name") or r.get("organization") or r.get("source_id") or ""
    repo = r.get("project") or r.get("top_level_category") or r.get("source_id") or ""
    title = r.get("finding_title") or r.get("title") or ""
    return (org or "", repo or "", norm_title(title))


KEY_EXTRACTORS = {
    "v1": v1_key,
    "v2.2": v22_key,
    "V3": v3_key,
    "Vbeta": vbeta_key,
    "V4": v4_key,
}


# --------------------------------------------------------------------------- #
# layer scan
# --------------------------------------------------------------------------- #


def scan_layer(name: str, roots: list[str], key_fn):
    urls: set[str] = set()
    digests: set[str] = set()
    keys: set[tuple] = set()
    key_counts: Counter = Counter()
    rows = 0
    files = 0

    for p in iter_files(roots):
        recs = parse_records(p)
        if recs:
            files += 1
            for rec in recs:
                rows += 1
                for u in collect_urls_record(rec):
                    nu = normalize_url(u)
                    if nu:
                        urls.add(nu)
                digests.update(collect_digests_record(rec))
                if key_fn is not None:
                    k = key_fn(rec)
                    keys.add(k)
                    key_counts[k] += 1
        else:
            # Non-JSON data file (e.g. .md pages in nextdata/): still count
            # URLs in the text.
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if text:
                for u in collect_urls_text(text):
                    nu = normalize_url(u)
                    if nu:
                        urls.add(nu)
                rows += 1
            files += 1

    return {
        "rows": rows,
        "files": files,
        "urls": urls,
        "keys": keys,
        "digests": digests,
        "examples": key_counts.most_common(5),
    }


# --------------------------------------------------------------------------- #
# canonical source lists
# --------------------------------------------------------------------------- #


def v3_archives() -> list[str]:
    out = []
    for rec in parse_records(ROOT / "jsonl_v3" / "sources.jsonl"):
        sid = rec.get("source_id")
        if sid:
            out.append(sid)
    return sorted(set(out))


def v22_sources() -> list[str]:
    out: set[str] = set()
    ml = ROOT / "jsonl_ml"
    for p in sorted(ml.glob("sources_*.jsonl")):
        for rec in parse_records(p):
            sid = rec.get("source_id")
            if sid:
                out.add(sid)
    return sorted(out)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main() -> int:
    line = "=" * 72
    print(line)
    print("VLUN existing-corpus dedup inventory (read-only)")
    print(line)

    print("\nV3 archives (18):")
    for sid in v3_archives():
        print(f"  - {sid}")

    sids = v22_sources()
    print(f"\nv2.2 sources ({len(sids)}):")
    for sid in sids:
        print(f"  - {sid}")

    totals = {}
    for name in LAYER_ROOTS:
        t = scan_layer(name, LAYER_ROOTS[name], KEY_EXTRACTORS[name])
        totals[name] = t
        print(f"\n[{name}] rows={t['rows']} files={t['files']}")
        print(f"  unique normalized URLs: {len(t['urls'])}")
        print(
            f"  (auditor_or_org, protocol_or_repo, normalized_title) keys: "
            f"{len(t['keys'])}"
        )
        print(f"  sha256 digests: {len(t['digests'])}")
        for k, c in t["examples"]:
            print(f"    key example ({c}x): {k!r}")

    print("\nTOTALS across all 5 layers (union):")
    all_urls: set[str] = set()
    all_keys: set[tuple] = set()
    all_digests: set[str] = set()
    all_rows = 0
    for name in LAYER_ROOTS:
        t = totals[name]
        all_urls |= t["urls"]
        all_keys |= t["keys"]
        all_digests |= t["digests"]
        all_rows += t["rows"]
    print(f"  rows: {all_rows}")
    print(f"  unique normalized URLs: {len(all_urls)}")
    print(
        f"  (auditor_or_org, protocol_or_repo, normalized_title) keys: "
        f"{len(all_keys)}"
    )
    print(f"  sha256 digests: {len(all_digests)}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

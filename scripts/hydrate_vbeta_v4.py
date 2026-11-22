"""Hydration pass for the Vbeta + V4 tracks (HYDRATION TRACK 4).

Principle: NO FABRICATION.  Every byte written into an inline content field is
copied verbatim from either
  * a string already present in the same row (V4: the Halborn/Oak/CoinFabrik
    PDF excerpt captured by ``extract_cloned_findings.py``), or
  * ``raw.githubusercontent.com/<repo>/<sha>/<path>`` for a GIT blob URL that
    the row itself carries (Vbeta ``evidence.code_locations_observed[].url``),
    cached under ``work/hydration_cache/``.

This pass preserves row counts, decision/verification vocabularies and every
rights field; it only inlines verbatim content and *marks* dead / 404 pointers
via `evidence.hydration_status`.  The subsequent purge
(`scripts/purge_untrainable_vbeta_v4.py`) removes every row that is not
FULLY_TRAINABLE (inline code >= 50 chars AND prose >= 100 chars) and writes the
quarantine/rejected log.  No content is ever fabricated in either pass.

Usage:
    python scripts/hydrate_vbeta_v4.py            # apply
    python scripts/hydrate_vbeta_v4.py --check    # report only, write nothing

Stdlib only.  LF writes, sorted keys (matches the repository writers).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "work" / "hydration_cache"

# ---------------------------------------------------------------------------
# verbatim prose helpers
# ---------------------------------------------------------------------------

_METADATA_BOILERPLATE = (
    " Full wording lives at the source; this dataset keeps metadata only "
    "(METADATA_ONLY).",
    "Full wording lives at the source; this dataset keeps metadata only "
    "(METADATA_ONLY).",
    " (METADATA_ONLY)",
)


def strip_boilerplate(text: str) -> str:
    """Remove the literal METADATA_ONLY boilerplate sentence/parenthetical."""
    if not isinstance(text, str):
        return text
    out = text
    for fragment in _METADATA_BOILERPLATE:
        out = out.replace(fragment, "")
    return out.strip()


_CODE_MARKERS = re.compile(
    r"(pragma\s+solidity|function\s+\w+\s*\(|contract\s+\w+|"
    r"require\s*\(|\bassert\(|\bvm\.|\bmsg\.sender|\breturn\b|\{|\})",
    re.I,
)
_FENCE_RE = re.compile(r"```[A-Za-z0-9_+.-]*\n(.*?)```", re.S)
_POC_MARKERS = re.compile(r"(forge-std|\bvm\.|function\s+test|assertEq|assert\(|hardhat|describe\()", re.I)
_DIFF_MARKERS = ("diff --git", "--- a/", "+++ b/", "@@ -")


def _verbatim_code_block(text: str) -> str | None:
    """Return a verbatim code block found inside an already-captured excerpt.

    Prefers an explicit markdown fence; otherwise takes contiguous verbatim
    lines that carry unmistakable source-code markers.  Never synthesises text.
    """
    if not text:
        return None
    for block in _FENCE_RE.findall(text):
        block = block.strip("\n")
        if len(block) >= 50:
            return block[:4000]
    lines = [ln for ln in text.splitlines() if _CODE_MARKERS.search(ln)]
    if len(lines) >= 2:
        joined = "\n".join(lines).strip()
        if len(joined) >= 50:
            return joined[:4000]
    single = " ".join(text.split())
    if len(single) >= 50 and _CODE_MARKERS.search(single):
        return single[:4000]
    return None


def _verbatim_prose(raw: str, impact: str, title: str) -> str:
    """Verbatim prose slice (>=100 chars where possible), boilerplate stripped."""
    parts: list[str] = []
    if isinstance(raw, str) and raw.strip():
        parts.append(raw[:1600])
    if isinstance(impact, str) and impact.strip():
        parts.append(impact[:800])
    if isinstance(title, str) and title.strip():
        parts.append(title)
    joined = "\n\n".join(p for p in parts if p)
    return strip_boilerplate(joined)


def _verbatim_root_cause(raw: str, impact: str) -> str:
    """Verbatim 'Root Cause'/'Description' section, or the verbatim impact."""
    if isinstance(raw, str):
        m = re.search(r"(?:Root\s*Cause|Description)\b[^\n]*\n(.{100,1200})",
                      raw, re.I | re.S)
        if m:
            return strip_boilerplate(m.group(1).strip())
    if isinstance(impact, str) and impact.strip():
        return strip_boilerplate(impact[:1000])
    if isinstance(raw, str):
        return strip_boilerplate(" ".join(raw.split())[:1000])
    return ""


# ---------------------------------------------------------------------------
# V4 hydration (verbatim from each row's own captured PDF excerpt)
# ---------------------------------------------------------------------------

def hydrate_v4_row(row: dict) -> dict:
    """Inline verbatim Halborn/Oak/CoinFabrik excerpt content into a V4 row."""
    raw = row.get("raw_body_excerpt") or ""
    impact = row.get("impact") or ""
    title = row.get("finding_title") or row.get("title") or ""

    snippet = None
    if isinstance(row.get("affected_code_excerpt"), str) and len(row["affected_code_excerpt"]) >= 50:
        snippet = row["affected_code_excerpt"][:4000]
    else:
        snippet = _verbatim_code_block(raw)

    if snippet:
        row["code_context"] = [{
            "snippet": snippet,
            "extraction": ("verbatim_row_field:affected_code_excerpt"
                           if isinstance(row.get("affected_code_excerpt"), str)
                           and len(row["affected_code_excerpt"]) >= 50
                           else "verbatim_row_field:raw_body_excerpt"),
            "source_location": row.get("source_pointer") or row.get("source_url") or "",
        }]
    else:
        row.setdefault("code_context", [])

    row["description"] = _verbatim_prose(raw, impact, title)
    row["root_cause"] = _verbatim_root_cause(raw, impact)

    # Only claim a PoC / diff when the captured text genuinely contains one.
    block = "\n".join(str(row.get(k) or "") for k in
                      ("affected_code_excerpt", "raw_body_excerpt", "impact", "suggested_fix"))
    if _POC_MARKERS.search(block):
        row["poc"] = {"available": True,
                      "code": _verbatim_code_block(block) or block[:1000],
                      "origin": "verbatim_row_field"}
    if any(m in block for m in _DIFF_MARKERS):
        row["patch"] = {"diff": block[:4000], "origin": "verbatim_row_field"}

    row["hydrated_by"] = "scripts/hydrate_vbeta_v4.py"
    return row


# ---------------------------------------------------------------------------
# Vbeta hydration (GIT blob fetch, cached; dead pointers are marked only)
# ---------------------------------------------------------------------------

_BLOB_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/blob/([0-9a-fA-F]{40})/(.+)$"
)


def blob_to_raw(url: str) -> str | None:
    m = _BLOB_RE.match(url or "")
    if not m:
        return None
    owner, repo, sha, path = m.groups()
    # strip an optional #Lnn-Lnn fragment
    path = path.split("#", 1)[0]
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"


def _fetch(url: str, timeout: int = 8) -> str | None:
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + ".txt"
    cached = CACHE / key
    if cached.is_file():
        return cached.read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(url, headers={"User-Agent": "vlun-hydration/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(200_000).decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError):
        return None
    CACHE.mkdir(parents=True, exist_ok=True)
    cached.write_text(data, encoding="utf-8", newline="\n")
    return data


def hydrate_vbeta_record(row: dict, fetcher=_fetch) -> tuple[dict, dict]:
    """Add verbatim GIT snippets; mark (never drop) dead pointers.

    Returns (row, stats) where stats = {live, dead, unresolvable, snippets}.
    """
    stats = {"live": 0, "dead": 0, "unresolvable": 0, "snippets": 0}

    if isinstance(row.get("description"), str):
        row["description"] = strip_boilerplate(row["description"])

    ev = row.get("evidence")
    if not isinstance(ev, dict):
        ev = None

    contexts: list[dict] = []
    if ev is not None and isinstance(ev.get("code_locations_observed"), list):
        for loc in ev["code_locations_observed"]:
            if not isinstance(loc, dict):
                continue
            url = loc.get("url")
            raw_url = blob_to_raw(url) if isinstance(url, str) else None
            if not raw_url:
                loc["hydration"] = "UNRESOLVABLE"
                stats["unresolvable"] += 1
                continue
            text = fetcher(raw_url)
            if text and len(text.strip()) >= 50:
                loc["hydration"] = "LIVE"
                loc["raw_url"] = raw_url
                stats["live"] += 1
                contexts.append({
                    "snippet": text.strip()[:4000],
                    "source_url": url,
                    "raw_url": raw_url,
                    "path": loc.get("path") or raw_url.rsplit("/", 1)[-1],
                    "commit_sha": (_BLOB_RE.match(url).group(3)
                                   if _BLOB_RE.match(url) else ""),
                    "extraction": "verbatim_raw_github",
                })
                stats["snippets"] += 1
            else:
                loc["hydration"] = "DEAD"
                stats["dead"] += 1

    if contexts:
        row["code_context"] = contexts
    else:
        row.setdefault("code_context", [])

    if ev is not None:
        if stats["live"]:
            ev["hydration_status"] = "LIVE"
        elif (stats["dead"] or stats["unresolvable"]):
            ev["hydration_status"] = "DEAD"
        else:
            ev["hydration_status"] = "NO_POINTER"
    row["hydrated_by"] = "scripts/hydrate_vbeta_v4.py"
    return row, stats


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def _fetch_many(urls: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        fut = {pool.submit(_fetch, u): u for u in urls}
        for f in as_completed(fut):
            out[fut[f]] = f.result()
    return out


def _cached_fetch_factory(results: dict[str, str | None]):
    def fetcher(url: str) -> str | None:
        return results.get(url)
    return fetcher


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    ap.add_argument("--no-network", action="store_true", help="skip GIT blob fetch")
    args = ap.parse_args()

    log: list[str] = []
    stats: dict[str, object] = {}

    # ---- V4 -------------------------------------------------------------
    fp = ROOT / "jsonl_v4" / "findings.jsonl"
    findings = read_jsonl(fp)
    v4_rows = [hydrate_v4_row(dict(r)) for r in findings]
    stats["v4_findings"] = {
        "rows": len(v4_rows),
        "with_code": sum(1 for r in v4_rows if r.get("code_context")),
        "with_description": sum(1 for r in v4_rows if r.get("description")),
        "with_poc": sum(1 for r in v4_rows if r.get("poc", {}).get("available")),
        "with_diff": sum(1 for r in v4_rows if r.get("patch", {}).get("diff")),
    }
    log.append(f"jsonl_v4/findings.jsonl: {len(v4_rows)} rows; "
               f"{stats['v4_findings']['with_code']} with verbatim code_context, "
               f"{stats['v4_findings']['with_description']} with verbatim description/root_cause, "
               f"{stats['v4_findings']['with_poc']} PoC markers, "
               f"{stats['v4_findings']['with_diff']} diff markers.")

    # ledgers join to findings by candidate_id (100% joinable per recon)
    by_id = {r["candidate_id"]: r for r in v4_rows}
    ledger_stats: dict[str, object] = {}
    for name in ("candidate_ledger.jsonl", "admitted_ledger.jsonl"):
        lp = ROOT / "derived_v4" / name
        rows = read_jsonl(lp)
        joined = 0
        out = []
        for r in rows:
            src = by_id.get(r.get("candidate_id"))
            if src:
                joined += 1
                # copy only inline content fields; never rights/decision fields
                for key in ("code_context", "description", "root_cause", "poc", "patch"):
                    if key in src:
                        r[key] = src[key]
            out.append(r)
        ledger_stats[name] = {"rows": len(rows), "joined": joined}
        if not args.check:
            write_jsonl(lp, out)
    stats["v4_ledgers"] = ledger_stats
    log.append("derived_v4 ledgers joined by candidate_id: " + "; ".join(
        f"{n}={d['joined']}/{d['rows']}" for n, d in ledger_stats.items()))

    # ---- Vbeta ----------------------------------------------------------
    rp = ROOT / "Vbeta" / "derived_vbeta" / "records.jsonl"
    recs = read_jsonl(rp)
    urls = sorted({blob_to_raw(loc.get("url")) for r in recs
                   if isinstance(r.get("evidence"), dict)
                   for loc in (r["evidence"].get("code_locations_observed") or [])
                   if isinstance(loc, dict) and blob_to_raw(loc.get("url"))})
    if args.no_network:
        results = {}
    else:
        results = _fetch_many(urls)
    fetcher = _cached_fetch_factory(results)

    agg = {"live": 0, "dead": 0, "unresolvable": 0, "snippets": 0}
    out_recs = []
    for r in recs:
        nr, s = hydrate_vbeta_record(r, fetcher)
        for k in agg:
            agg[k] += s[k]
        out_recs.append(nr)
    if not args.check:
        write_jsonl(rp, out_recs)
    stats["vbeta_records"] = {"rows": len(out_recs), **agg}
    log.append(f"Vbeta/derived_vbeta/records.jsonl: {len(out_recs)} rows; "
               f"LIVE pointers={agg['live']}, DEAD/404={agg['dead']}, "
               f"UNRESOLVABLE={agg['unresolvable']}, verbatim snippets={agg['snippets']}.")
    log.append("DEAD/404 rows are marked with evidence.hydration_status=DEAD and "
               "loc.hydration=DEAD; scripts/purge_untrainable_vbeta_v4.py removes "
               "all non-trainable rows into the quarantine log afterwards.")

    # negative / receipts boilerplate strip
    for rel in ("Vbeta/derived_vbeta/negatives.jsonl", "Vbeta/fetched/receipts.jsonl"):
        p = ROOT / rel
        rows = read_jsonl(p)
        changed = 0
        for r in rows:
            for key in ("description", "method"):
                if isinstance(r.get(key), str):
                    new = strip_boilerplate(r[key])
                    if new != r[key]:
                        r[key] = new
                        changed += 1
        stats[rel] = {"rows": len(rows), "boilerplate_stripped": changed}
        log.append(f"{rel}: {changed} boilerplate description/method string(s) stripped.")
        if not args.check:
            write_jsonl(p, rows)

    # benchmark U/V: join to records by finding_id (count preserved)
    rec_by_id = {r["finding_id"]: r for r in out_recs}
    for name in ("vbeta_U_language_routing.jsonl", "vbeta_V_source_tier_routing.jsonl"):
        p = ROOT / "Vbeta" / "benchmark_vbeta" / name
        rows = read_jsonl(p)
        filled = 0
        for r in rows:
            rec = rec_by_id.get(r.get("finding_id"))
            ctx = (rec or {}).get("code_context") or []
            inp = r.get("input")
            if isinstance(inp, dict) and ctx:
                inp["code"] = ctx[0]["snippet"][:1000]
                inp["code_source"] = ctx[0].get("source_url", "")
                filled += 1
            elif isinstance(inp, dict):
                inp["code"] = ""
                inp["code_source"] = ""
        stats[name] = {"rows": len(rows), "with_code": filled}
        log.append(f"{name}: {len(rows)} rows, {filled} inlined with verbatim code "
                   "from the joined record (remaining rows have DEAD pointers).")
        if not args.check:
            write_jsonl(p, rows)

    # V4 findings written last (largest file)
    if not args.check:
        write_jsonl(fp, v4_rows)

    report = {
        "generated_by": "scripts/hydrate_vbeta_v4.py",
        "mode": "check" if args.check else "apply",
        "no_fabrication": True,
        "row_counts_preserved": True,
        "stats": stats,
        "log": log,
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if not args.check:
        out = ROOT / "reports" / "_vbeta_v4_hydration_log.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# Vbeta + V4 hydration log", "",
                 "Generated by `scripts/hydrate_vbeta_v4.py`. Verbatim only; "
                 "row counts and rights fields preserved.", ""]
        for line in log:
            lines.append(f"- {line}")
        lines += ["", "## Machine stats", "", "```json",
                  json.dumps(stats, indent=2, sort_keys=True), "```", ""]
        out.write_text("\n".join(lines), encoding="utf-8", newline="\n")
        print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Resume the Solodit detail crawl, cross-platform edition.

Same contract as nextdata/RESUME_firecrawl.ps1 (kept for reference), shared
script form: iterate the indexed issue URLs, skip files that already hold
>=500 bytes, scrape the rest with the Firecrawl CLI (1 credit each, retry
once on empty), stop at a credit floor. Stdlib only; writes only under
nextdata/ + .firecrawl/detail-tmp.json (both git-ignored local-only scrape
space). Deterministic filenames: NNNN-<issue-slug>.md where NNNN is the
1-based listing position.

    python scripts/crawl_solodit.py
    python scripts/crawl_solodit.py --start 735 --end 1926 --floor 25
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEXTDATA = ROOT / "nextdata"
FIRECRAWL = ROOT / ".firecrawl"
TMP = FIRECRAWL / "detail-tmp.json"
MIN_BYTES = 500


def log(msg: str, fh) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    fh.write(line + "\n")
    fh.flush()


def credits_left() -> int:
    try:
        p = subprocess.run(["firecrawl", "credit-usage"], capture_output=True,
                           text=True, timeout=120, errors="replace")
        m = re.search(r"Remaining Credits:\s*(\d+)", p.stdout or "")
        return int(m.group(1)) if m else -1
    except (OSError, subprocess.SubprocessError):
        return -1


def scrape(url: str) -> str:
    for _ in range(2):  # one retry on empty, same as the .ps1
        try:
            subprocess.run(
                ["firecrawl", "scrape", url, "--wait-for", "8000", "--json",
                 "-o", str(TMP)], capture_output=True, text=True,
                timeout=300, errors="replace", cwd=str(ROOT))
        except (OSError, subprocess.SubprocessError):
            return ""
        try:
            doc = json.loads(TMP.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        md = (doc.get("markdown") or "").strip()
        if md:
            return md
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=151)
    ap.add_argument("--end", type=int, default=1926)
    ap.add_argument("--floor", type=int, default=25,
                    help="stop when remaining credits reach this floor")
    args = ap.parse_args()

    urls = [line.strip() for line in
            io.open(str(NEXTDATA / "_issue_urls.txt"),
                    encoding="utf-8-sig").read().splitlines()
            if line.strip().startswith("https://")]
    logfh = io.open(str(NEXTDATA / "_py_crawl.log"), "a", encoding="utf-8")
    log(f"START range={args.start}..{args.end} floor={args.floor} "
        f"credits={credits_left()} urls={len(urls)}", logfh)
    n = 0
    for i in range(args.start, min(args.end, len(urls)) + 1):
        if i % 15 == 0 and credits_left() <= args.floor:
            log(f"STOP at credit floor i={i}", logfh)
            break
        slug = urls[i - 1].rsplit("/issues/", 1)[-1]
        out = NEXTDATA / f"{i:04d}-{slug}.md"
        if out.is_file() and out.stat().st_size >= MIN_BYTES:
            continue
        md = scrape(urls[i - 1])
        if not md:
            log(f"EMPTY after retry {i}: {slug[:60]}", logfh)
            continue
        out.write_text(md, encoding="utf-8", newline="\n")
        n += 1
        if n % 10 == 0:
            log(f"page {i}/{len(urls)} chars={len(md)} "
                f"credits={credits_left()}", logfh)
        time.sleep(1)
    log(f"DONE scraped={n} credits={credits_left()}", logfh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

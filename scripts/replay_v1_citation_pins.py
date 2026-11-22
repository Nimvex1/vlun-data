#!/usr/bin/env python3
"""Re-apply the published v1 citation pins to a rebuilt derived layer.

``resolve_citations.py --apply`` refuses to run in a partial checkout (its local
clones are gone): it would shrink the published 639 immutable pins. The report
``reports/citation_resolution.json`` already holds every pin verbatim. This
script replays those exact values onto the rebuilt records, matching the field
writes of ``resolve_citations.apply_resolutions`` byte for byte. No pin is
recomputed and no URL is invented.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from vlun import DERIVED, REPORTS, log, write_jsonl  # noqa: E402

BLOB_URL = re.compile(
    r"^https://github\.com/([^/]+/[^/#?]+?)(?:\.git)?/blob/([^/]+)/(.*?)(?:#.*)?$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REF_KEYS = ("code_context", "vulnerable_code", "code_reference_only",
            "code_context_expanded")


def main() -> int:
    report = json.loads((REPORTS / "citation_resolution.json").read_text(encoding="utf-8"))
    by_key = {}
    for c in report.get("citations") or []:
        if c.get("commit_resolution_status") != "resolved" or not c.get("resolved_commit"):
            continue
        by_key[(c.get("record_id"), c.get("context_key"), c.get("source_url_original"))] = c

    path = DERIVED / "records.jsonl"
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    pinned = records_touched = urls_rewritten = 0
    for rec in records:
        touched = False
        for key in REF_KEYS:
            for c in rec.get(key) or []:
                if not isinstance(c, dict):
                    continue
                if c.get("commit_sha") and SHA40.match(c["commit_sha"]):
                    continue
                url = c.get("source_url") or ""
                m = BLOB_URL.match(url)
                if not m:
                    continue
                res = by_key.get((rec.get("id"), key, url))
                if res is None:
                    # Some pins were recorded with the expanded-entry's own URL
                    # shape; fall back to (record_id, context_key, resolved ref).
                    for cand in report.get("citations") or []:
                        if (cand.get("record_id") == rec.get("id")
                                and cand.get("context_key") == key
                                and cand.get("original_reference") == m.group(2)):
                            res = cand
                            break
                new = (res or {}).get("resolved_commit")
                if not new or not SHA40.match(new):
                    continue
                c["commit_sha"] = new
                c["source_url"] = re.sub(
                    r"^(https://github\.com/" + re.escape(m.group(1)) + r"/blob/)[^/]+/",
                    lambda mo: mo.group(1) + new + "/", url)
                if c["source_url"] != url:
                    urls_rewritten += 1
                    refs = c.get("source_refs")
                    if isinstance(refs, list):
                        c["source_refs"] = [
                            c["source_url"] if r == url else r for r in refs]
                c["original_reference"] = m.group(2)
                c["source_url_original"] = url
                c["commit_resolution_status"] = res.get("commit_resolution_status")
                c["resolution_method"] = res.get("resolution_method")
                c["resolution_confidence"] = res.get("resolution_confidence")
                c["commit_pinned_by"] = "scripts/resolve_citations.py"
                pinned += 1
                touched = True
        if touched:
            records_touched += 1
    write_jsonl(path, records)
    log(f"replayed citation pins: pinned={pinned} records_touched={records_touched} "
        f"urls_rewritten={urls_rewritten}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

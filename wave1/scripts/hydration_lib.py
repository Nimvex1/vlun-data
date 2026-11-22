"""hydration_lib.py -- shared, stdlib-only verbatim hydration helpers for Wave-1.

Every string this module produces is copied verbatim from either
  * a real local file (work/sources/, work/hydration_cache/), or
  * a deterministic HTTP fetch cached under work/hydration_cache/.
No field is synthesised, paraphrased or inferred: when a source cannot supply
both >= CODE_MIN chars of inline code and >= PROSE_MIN chars of prose, the row
is reported as unhydratable and the caller quarantines it.

Scope of the FULLY_TRAINABLE gate (per the hydration brief):
    inline code >= CODE_MIN chars  AND  prose >= PROSE_MIN chars
(A unified diff / PoC is added *when a real one exists*, but is not required
by the gate.)
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from _common import API_CACHE, ROOT, WORK_SOURCES, sha256_text

CODE_MIN = 50
PROSE_MIN = 100

# Fields that hold inline code / a verbatim diff / a verbatim PoC.
CODE_FIELDS = ("code_context", "patch", "poc", "rule_body", "target_code_context")
# Fields that hold technical prose copied verbatim from a source.
PROSE_FIELDS = ("description", "root_cause", "impact", "judge_quote", "invalidation_reason")

# Fields admitted to hold long verbatim strings in 04_admitted rows.  Everything
# else still obeys the legacy <=1000-char METADATA_ONLY guard in gate_d.
ALLOWED_INLINE_FIELDS = frozenset({
    "code_context", "patch", "poc", "description", "root_cause", "impact",
    "judge_quote", "invalidation_reason", "rule_body", "target_code_context",
    "hydration", "hydration_source", "hydration_at",
})

HYDRATION_CACHE = WORK_SOURCES.parent / "hydration_cache"

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+#.\-]*\s*\n(.*?)```", re.S)
_INLINE_RE = re.compile(r"`([^`\n]{20,})`")
_URL_RE = re.compile(r"https?://\S+")
_LOC_RE = re.compile(
    r"github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/blob/(?P<ref>[^/\s]+)/"
    r"(?P<path>[^\s#)]+)(?:#L(?P<start>\d+)(?:-L(?P<end>\d+))?)?$",
    re.I,
)
_CODE_TOKEN_RE = re.compile(r"(;[ \t]*\n|\{|;|=>|\bfunction\b|\brequire\(|\bcontract\b|=+)", re.I)


# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------
def _walk_code(value: Any) -> str:
    """Collect code text from a field of arbitrary shape."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # code_context[].snippet is the canonical code holder
        return " ".join(_walk_code(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_walk_code(v) for v in value)
    return ""


def code_chars(row: dict) -> int:
    total = 0
    for key in CODE_FIELDS:
        total += len(_walk_code(row.get(key, "")))
    return total


def prose_chars(row: dict) -> int:
    total = 0
    for key in PROSE_FIELDS:
        v = row.get(key, "")
        total += len(v) if isinstance(v, str) else len(_walk_code(v))
    return total


def fully_trainable(row: dict) -> bool:
    return code_chars(row) >= CODE_MIN and prose_chars(row) >= PROSE_MIN


def trainable_stats(row: dict) -> dict:
    c, p = code_chars(row), prose_chars(row)
    return {"code_chars": c, "prose_chars": p, "fully_trainable": c >= CODE_MIN and p >= PROSE_MIN}


# ---------------------------------------------------------------------------
# verbatim extraction
# ---------------------------------------------------------------------------
def fenced_code(text: str, min_len: int = 20) -> str:
    blocks = [m.group(1).strip() for m in _FENCE_RE.finditer(text or "")]
    return "\n".join(b for b in blocks if len(b) >= min_len)


def inline_code(text: str, min_len: int = 20) -> str:
    """Backtick inline spans that actually look like code (not just names)."""
    spans = [s.strip() for s in _INLINE_RE.findall(text or "")]
    codey = [s for s in spans if len(s) >= min_len and _CODE_TOKEN_RE.search(s)]
    return "\n".join(codey)


def prose_from_body(text: str) -> str:
    t = _FENCE_RE.sub(" ", text or "")
    t = _URL_RE.sub(" ", t)
    t = re.sub(r"^#{1,6}\s*", "", t, flags=re.M)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{2,}", "\n", t)
    return t.strip()


def code_from_body(text: str) -> str:
    c = fenced_code(text)
    if len(c) < CODE_MIN:
        c = inline_code(text)
    return c


def file_window(path: Path, line_no: int, before: int = 6, after: int = 14) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return ""
    ln = max(1, int(line_no or 1))
    lo, hi = max(0, ln - 1 - before), min(len(lines), ln + after)
    return "\n".join(lines[lo:hi]).strip()


def comment_prose(path: Path) -> str:
    """Verbatim comment text from a source file (CVL/Solidity/Markdown)."""
    lines = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if s.startswith(("//", "#", "/*", "*", "///", "//!")):
            cleaned = re.sub(r"^(\/\/|\/\*|\*|#|///|//!)\s?", "", s).strip("*/ \t")
            if len(cleaned) >= 4:
                lines.append(cleaned)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# API cache index (offline first)
# ---------------------------------------------------------------------------
def load_api_index() -> tuple[dict[str, dict], dict[str, list[dict]]]:
    issues: dict[str, dict] = {}
    comments: dict[str, list[dict]] = {}
    if not API_CACHE.exists():
        return issues, comments
    for f in API_CACHE.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for obj in data:
            if not isinstance(obj, dict):
                continue
            url = str(obj.get("html_url") or "")
            if "/issues/comments/" in str(obj.get("url") or ""):
                comments.setdefault(str(obj.get("issue_url") or ""), []).append(obj)
            elif "number" in obj and "repository_url" in obj and "/issues/" in url:
                issues[url] = obj
    return issues, comments


def judge_quote_for(issue: dict | None, comments: dict[str, list[dict]]) -> str:
    if not issue:
        return ""
    for c in comments.get(str(issue.get("url") or ""), []):
        body = str(c.get("body") or "").strip()
        if len(body) >= 40:
            return body
    return ""


# ---------------------------------------------------------------------------
# cached deterministic raw fetch (graceful DEAD fallback)
# ---------------------------------------------------------------------------
def raw_fetch(url: str, timeout: int = 15) -> str | None:
    """GET a raw URL, caching success AND failure under work/hydration_cache/.

    Returns None on any non-200 / timeout so the caller can quarantine the row
    honestly instead of fabricating content.  Never re-fetches the same URL.
    """
    HYDRATION_CACHE.mkdir(parents=True, exist_ok=True)
    key = sha256_text(url)
    cache = HYDRATION_CACHE / (key + ".txt")
    marker = HYDRATION_CACHE / (key + ".dead")
    if cache.exists():
        try:
            return cache.read_text(encoding="utf-8")
        except Exception:
            return None
    if marker.exists():
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vlun-wave1-hydration"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", "replace")
        cache.write_text(data, encoding="utf-8", newline="\n")
        return data
    except Exception:
        marker.write_text(url + "\n", encoding="utf-8", newline="\n")
        return None


def raw_from_blob(blob_url: str) -> tuple[str, str, str, str | None]:
    """Convert a github blob URL into (ref, path, line-range, raw text)."""
    m = _LOC_RE.search(blob_url or "")
    if not m:
        return "", "", "", None
    owner, repo, ref, path = m.group("owner"), m.group("repo"), m.group("ref"), m.group("path")
    start, end = m.group("start"), m.group("end")
    raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    text = raw_fetch(raw)
    rng = f"{start}-{end}" if start and end else (start or "")
    return ref, path, rng, text


def slice_lines(text: str, rng: str, before: int = 4, after: int = 12) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    if not rng:
        return "\n".join(lines[:30]).strip()
    start = int(rng.split("-")[0])
    end = int(rng.split("-")[-1])
    lo, hi = max(0, start - 1 - before), min(len(lines), end + after)
    return "\n".join(lines[lo:hi]).strip()


# ---------------------------------------------------------------------------
# local-source root mapping
# ---------------------------------------------------------------------------
FORMAL_LOCAL = {
    "recon-fuzz/audits": WORK_SOURCES / "Recon-Fuzz__audits",
    "certora/gho-competition": WORK_SOURCES / "Certora__gho-competition",
    "certora/uniswap-v4-periphery-cantina-fv": WORK_SOURCES / "Certora__uniswap-v4-periphery-cantina-fv",
}
MD_LOCAL = WORK_SOURCES / "markdown__asymmetric-research__security-advisories"
REVM_LOCAL = WORK_SOURCES / "blocksecteam__ReEVMBench"
OZ_LOCAL = WORK_SOURCES / "OpenZeppelin__openzeppelin-contracts"


def add_inline(row: dict, *, code_blocks: list[str] | None = None,
               prose: str = "", judge_quote: str = "", invalidation: str = "",
               diff: str = "", poc: str = "", rule_body: str = "",
               target_code: str = "", source: str = "",
               code_file: str = "", code_function: str = "") -> dict:
    """Return a COPY of row with additive inline fields (no key is deleted)."""
    out = dict(row)
    if code_blocks:
        out["code_context"] = [
            {"snippet": b[:900], "file": code_file[:300], "function": code_function[:200]}
            for b in code_blocks if len(b) >= CODE_MIN
        ][:8]
    if prose:
        out["description"] = prose[:900]
    if judge_quote:
        out["judge_quote"] = judge_quote[:900]
    if invalidation:
        out["invalidation_reason"] = invalidation[:400]
    if diff:
        out["patch"] = {"diff": diff[:900]}
    if poc:
        out["poc"] = {"code": poc[:900]}
    if rule_body:
        out["rule_body"] = rule_body[:900]
    if target_code:
        out["target_code_context"] = target_code[:900]
    if source:
        out["hydration_source"] = source[:200]
    return out


def quarantine(row: dict, reason: str) -> dict:
    q = dict(row)
    q["_quarantine_reason"] = "UNHYDRATABLE_DEAD_POINTER"
    q["_quarantine_detail"] = reason[:300]
    q["decision"] = "QUARANTINED_UNHYDRATABLE"
    return q

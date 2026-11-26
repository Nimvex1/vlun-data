"""Wave-1 shared helpers. Stdlib only.

Single-writer rule: every writer resolves its output path and asserts it is
inside wave1/. Scratch/clone reads may additionally use the git-ignored
work/sources/ tree, but no code in this module ever writes outside wave1/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

# wave1/scripts/_common.py -> parents[1] is the wave1/ root
WAVE1 = Path(__file__).resolve().parents[1]
ROOT = WAVE1.parent
WORK_SOURCES = ROOT / "work" / "sources"
REGISTRY = WAVE1 / "01_dedup" / "registry.jsonl"
OVERLAP = WAVE1 / "01_dedup" / "overlap_manifest.jsonl"
API_CACHE = WORK_SOURCES / "_api_cache"

_SENTINEL_HASHES = {
    "README.md": None,
    "benchmark/manifest.json": None,
    "derived_v3/manifest.json": None,
    "pyproject.toml": None,
    "scripts/vlun_v3.py": None,
}


# --------------------------------------------------------------------------
# path confinement
# --------------------------------------------------------------------------
def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def guard_wave1(path: str | os.PathLike) -> Path:
    """Assert a WRITE target resolves inside wave1/. Raises on any escape."""
    p = Path(path)
    if not _inside(p, WAVE1):
        raise PermissionError(f"single-writer violation: {p.resolve()} is outside {WAVE1}")
    return p


def guard_scratch(path: str | os.PathLike) -> Path:
    """Assert a READ/scratch target is inside wave1/ or work/sources/."""
    p = Path(path)
    if not (_inside(p, WAVE1) or _inside(p, WORK_SOURCES)):
        raise PermissionError(f"scratch violation: {p.resolve()} is outside wave1/ and work/sources/")
    return p


def ensure_parent(path: str | os.PathLike) -> Path:
    p = guard_wave1(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# --------------------------------------------------------------------------
# hashing / normalization
# --------------------------------------------------------------------------
def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def sha256_file(path: str | os.PathLike) -> str:
    """Line-ending-independent SHA-256 of a text file.

    Mirrors Vbeta's PRESENT rule: a file is the same artefact whether a
    Windows checkout materialised it with CRLF or LF. Hashing raw bytes would
    make PRESENT drift on every gate run that regenerates README.md.
    """
    data = Path(path).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CWA_RE = re.compile(r"CWA-\d{4}-\d{3,4}", re.I)
_RUSTSEC_RE = re.compile(r"RUSTSEC-\d{4}-\d{4}", re.I)
_TX_RE = re.compile(r"0x[0-9a-f]{64}", re.I)
_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b", re.I)


def norm_repo_slug(s: str) -> str:
    s = str(s or "").strip().lower()
    s = re.sub(r"^https?://(www\.)?github\.com/", "", s)
    s = re.sub(r"\.git$", "", s)
    s = s.strip("/")
    return s


def norm_id(s: Any) -> str:
    return str(s or "").strip().upper()


def norm_tx(s: str) -> str:
    m = _TX_RE.search(str(s or ""))
    return m.group(0).lower() if m else ""


def norm_url(s: str) -> str:
    s = str(s or "").strip().lower().split("#")[0].split("?")[0]
    return re.sub(r"/+$", "", s)


def ids_from_text(text: str) -> dict[str, list[str]]:
    return {
        "ghsa": sorted({m.upper() for m in _GHSA_RE.findall(text)}),
        "cve": sorted({m.upper() for m in _CVE_RE.findall(text)}),
        "cwa": sorted({m.upper() for m in _CWA_RE.findall(text)}),
        "rustsec": sorted({m.upper() for m in _RUSTSEC_RE.findall(text)}),
        "tx": sorted({m.lower() for m in _TX_RE.findall(text)}),
        "sha40": sorted({m.lower() for m in _SHA_RE.findall(text)}),
    }


# --------------------------------------------------------------------------
# JSONL IO
# --------------------------------------------------------------------------
def read_jsonl(path: str | os.PathLike) -> Iterable[dict]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: str | os.PathLike, rows: Iterable[dict]) -> int:
    p = ensure_parent(path)
    n = 0
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def append_jsonl(path: str | os.PathLike, rows: Iterable[dict]) -> int:
    p = ensure_parent(path)
    n = 0
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def write_json(path: str | os.PathLike, obj: Any) -> None:
    p = ensure_parent(path)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")


# --------------------------------------------------------------------------
# dedup registry
# --------------------------------------------------------------------------
def load_registry(path: str | os.PathLike | None = None) -> dict[str, dict]:
    p = guard_scratch(path or REGISTRY)
    out: dict[str, dict] = {}
    if not Path(p).exists():
        return out
    for row in read_jsonl(p):
        k = row.get("key")
        if k:
            out[k] = row
    return out


def check_keys(keys: Iterable[str], registry: dict[str, dict]) -> list[dict]:
    """Return one collision record per key already present in the registry."""
    hits = []
    for k in keys:
        if k in registry:
            r = registry[k]
            hits.append({"key": k, "layer": r.get("layer"), "value": r.get("value")})
    return hits


def record_overlap(source: str, key: str, candidate_id: str, hit: dict) -> dict:
    return {
        "source": source,
        "candidate_id": candidate_id,
        "key": key,
        "duplicate_of_layer": hit.get("layer"),
        "duplicate_of_value": hit.get("value"),
        "decision": "DROPPED_CROSS_LAYER_DUPLICATE",
    }


# --------------------------------------------------------------------------
# network (cached, rate-limit aware)
# --------------------------------------------------------------------------
def github_get(api_path: str, *, quiet: bool = False) -> dict | list | None:
    """GET https://api.github.com/<api_path> with an on-disk cache.

    Returns None on rate-limit / network failure so callers can degrade
    honestly rather than fabricate records. Cache lives in work/sources/.
    """
    cache = API_CACHE / (sha256_text(api_path) + ".json")
    if cache.exists():
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            # Corrupt/unreadable cache is a cache miss; refetch below.
            if not quiet:
                print(f"[github_get] cache read failed for {api_path}: {exc}")
    url = "https://api.github.com/" + api_path.lstrip("/")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "vlun-wave1-audit", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data), encoding="utf-8")
        return data
    except urllib.error.HTTPError as exc:
        if not quiet:
            print(f"[github_get] HTTP {exc.code} on {api_path}")
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        # Network down, timeout, or non-JSON response: degrade honestly.
        if not quiet:
            print(f"[github_get] failure on {api_path}: {exc}")
        return None


def git_clone(url: str, name: str) -> Path | None:
    """Shallow-clone into work/sources/<name> (git-ignored). Idempotent."""
    dest = guard_scratch(WORK_SOURCES / name)
    if (dest / ".git").exists():
        return dest
    import subprocess

    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
            check=True,
            timeout=300,
            capture_output=True,
        )
        return dest
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        # git absent, non-zero clone, or timeout: no checkout, no fabricated data.
        print(f"[git_clone] failed {url}: {exc}")
        return None


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

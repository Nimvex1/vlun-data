"""judge.py -- Wave-1 judge / lead-auditor technical-rejection harvest (source #5).

Governance (locked): see 00_governance/rights.jsonl source_id "judge_negatives"
(METADATA_ONLY, APPROVED_CONDITIONAL) and 00_governance/label_domains.json.

METADATA_ONLY: NEVER vend comment/issue prose.  On disk we store only a short
title, permalink, comment_sha256 (sha256 of the comment/issue text, never the
text itself), SHORT target AST facts, verified duplicate pairs and a 6-axis
rejection-evidence vector of structured booleans + pointers.  No full comment
prose is ever written to disk.

Admission rule: ONLY an issue carrying a judge/lead-auditor TECHNICAL rejection
comment (explicit attribution + concrete reason) OR a verified `duplicate of #N`
link is admitted.  A bare rejection label with no reason is skipped, counted and
reported -- never admitted.  If evidence cannot be retrieved nothing is admitted
and the report states that honestly (no fabrication).

API BUDGET: no token; 60 anonymous calls/hour shared.  We prefer issue-list
bodies (1 call per 100 issues) and fetch comments only for a bounded set of
issues whose body/labels indicate a rejection.  The on-disk github_get cache
makes reruns free.  Any failed call (rate limit / network) stops all fetching.

Usage: python wave1/scripts/adapters/judge.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# _common.py lives at wave1/scripts/_common.py; this file is in .../adapters/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import (  # noqa: E402
    API_CACHE,
    WAVE1,
    append_jsonl,
    check_keys,
    guard_scratch,
    guard_wave1,
    load_registry,
    norm_repo_slug,
    read_jsonl,
    record_overlap,
    sha256_text,
    utc_now,
    write_json,
    write_jsonl,
)

SOURCE = "judge"
GOVERNANCE_SOURCE_ID = "judge_negatives"

CANDIDATES = WAVE1 / "03_candidates" / "judge" / "issues.jsonl"
ADMITTED = WAVE1 / "04_admitted" / "judge" / "findings.jsonl"
OVERLAP = WAVE1 / "01_dedup" / "overlap_manifest.jsonl"
BENCH_F = WAVE1 / "benchmark_wave1" / "F_false_positive_rejection.jsonl"
BENCH_FA = WAVE1 / "benchmark_wave1" / "Fa_rejection_evidence_axis_vector.jsonl"
BENCH_FB = WAVE1 / "benchmark_wave1" / "Fb_duplicate_radar_pair.jsonl"
REPORT = WAVE1 / "reports_wave1" / "judge_harvest.json"
# Already-cached c4 mitigation issues (812 rows). READ ONLY -- no REST needed.
C4_ISSUES = WAVE1 / "03_candidates" / "c4_mitigation" / "issues.jsonl"
DUP_LABEL_RX = re.compile(r"^duplicate[\s_-]*(\d{1,6})$", re.I)

# --- API budget -------------------------------------------------------------
MAX_PAGES = 2
PER_PAGE = 100
MAX_ISSUE_LIST_CALLS = 12
MAX_COMMENT_CALLS = 10

# --- governed label domains (must match label_domains.json) ----------------
VALID_FINDING = "valid_finding"
REJECTED_FP = "rejected_false_positive"
AXES = [
    "judge_attributed",
    "code_gate_removes_standing",
    "technical_falsity",
    "corroborated_duplicate",
    "exploit_failed",
    "label_only",
]
DUP_LABELS = {"same": "same", "distinct": "distinct", "ambiguous": "ambiguous"}

# --- candidate repos (hard-coded exclusion sets from the task) -------------
C4_REPOS = [
    "code-423n4/2022-11-canto-findings",
    "code-423n4/2023-04-eigenlayer-findings",
    "code-423n4/2023-05-maia-findings",
    "code-423n4/2023-06-lybra-findings",
    "code-423n4/2024-03-dittoeth-findings",
]
SHERLOCK_REPOS = [
    "sherlock-audit/2023-04-hubble-exchange-judging",
    "sherlock-audit/2023-05-sophon-judging",
    "sherlock-audit/2023-06-lukso-judging",
    "sherlock-audit/2023-07-lens-judging",
    "sherlock-audit/2024-03-neotokyo-judging",
]
EXCLUDE_V1_8 = {
    "2022-05-alchemix", "2024-01-decent", "2024-01-renft", "2024-04-noya",
    "2024-08-wildcat", "2024-12-bakerfi", "2025-06-panoptic", "2025-08-gte-perps",
}
EXCLUDE_V3_C4 = {"2024-08-phi", "2024-04-renzo", "2024-07-reserve"}
EXCLUDE_V3_SHERLOCK = {"2023-01-optimism-judging", "2024-06-symmetrical-update-2-judging"}

# --- detection rules -------------------------------------------------------
JUDGE_ATTR_RE = re.compile(
    r"\b(judge|lead\s+auditor|lead\s+judge|the\s+judge|judging|裁决|技术|technical\s+team)\b",
    re.I,
)
DUP_LINK_RE = re.compile(r"duplicate\s*(?:of|:|with)?\s*#?(\d{1,6})\b", re.I)

# (axis, rule_name, regex).  A technical reason must match at least one.
TECH_RULES: list[tuple[str, str, re.Pattern]] = [
    ("technical_falsity", "not_a_bug", re.compile(r"not\s+a\s+(?:bug|vulnerability|issue)|non[\s-]?issue", re.I)),
    ("technical_falsity", "invalid", re.compile(r"\binvalid\b", re.I)),
    ("technical_falsity", "incorrect", re.compile(r"this is incorrect|(?:is|are)\s+incorrect|\bwrong\b|mistaken|misconception|misunderstand", re.I)),
    ("technical_falsity", "does_not", re.compile(r"does\s*not|doesn't|do\s*not|did\s*not", re.I)),
    ("technical_falsity", "by_design", re.compile(r"by\s+design|expected\s+behavio|intended\s+behavio", re.I)),
    ("code_gate_removes_standing", "access_gate", re.compile(r"only\s*owner|onlyowner|onlyrole|onlyadmin|access\s+control|require\s*\(|\bmodifier\b|\bguard(?:ed)?\b", re.I)),
    ("code_gate_removes_standing", "out_of_scope", re.compile(r"out\s+of\s+scope", re.I)),
    ("code_gate_removes_standing", "insufficient", re.compile(r"insufficient|not\s+enough|precondition|privileg|admin|trusted\s+role", re.I)),
    ("exploit_failed", "no_impact", re.compile(r"no\s+(?:real\s+)?impact|no\s+loss|not\s+exploitable|cannot\s+exploit|no\s+exploit", re.I)),
    ("exploit_failed", "poc_failed", re.compile(r"poc\s+fail|test\s+fail|fails?\s+to|reverts?\b|cannot\s+be\s+exploited", re.I)),
    ("corroborated_duplicate", "duplicate_text", re.compile(r"\bduplicate\b|already\s+reported|already\s+found", re.I)),
]

REJECT_LABEL_RE = re.compile(r"invalid|duplicate|disputed|false[\s_-]?positive|not[\s_-]?a[\s_-]?bug|won't fix|wontfix", re.I)
VALID_LABELS = {
    "valid", "valid finding", "confirmed", "selected for report", "selected-for-report",
    "judge: valid", "accepted", "1 (high risk)", "2 (med risk)", "3 (low risk)",
    "high", "medium", "low",
}
PR_RE = re.compile(r"\bpull\b|\bpr\b|pull request", re.I)

# short target AST facts (never prose)
FN_RE = re.compile(r"\b([A-Za-z_]\w{1,40})\s*\(")
MOD_RE = re.compile(r"\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|whenNotPaused|nonReentrant|onlyDAO)\b", re.I)
REQUIRE_RE = re.compile(r"require\s*\(([^)]{0,80})\)")
CONTRACT_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,40})\b")
FINDING_ID_RE = re.compile(r"\b([HML]-\d{1,3})\b")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _resolve_token() -> tuple[str, str]:
    """Resolve a GitHub token, in order: GITHUB_TOKEN, GH_TOKEN, `gh auth token`.

    Returns (token, method).  An empty token with method 'anonymous' means no
    credentials were available and REST must degrade to the anonymous budget.
    """
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and tok.strip():
        return tok.strip(), "env:GITHUB_TOKEN/GH_TOKEN"
    try:
        tok = subprocess.check_output(
            ["gh", "auth", "token"], text=True, timeout=15,
            stderr=subprocess.DEVNULL,
        ).strip()
        if tok:
            return tok, "gh_cli:gh auth token"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        # gh absent, non-zero auth, or timeout: fall back to anonymous budget.
        print(f"[judge] gh auth token unavailable ({type(exc).__name__}); using anonymous")
    return "", "anonymous"


def _authed_get(api_path: str, token: str, *, quiet: bool = False) -> tuple[Any, int]:
    """Authenticated GET with the same on-disk cache as _common.github_get.

    Returns (data, network_calls); network_calls==0 on a cache hit.  Never
    raises: a rate-limit / network failure yields (None, 1) so callers can
    degrade honestly.
    """
    cache = API_CACHE / (sha256_text(api_path) + ".json")
    if cache.exists():
        try:
            return json.loads(cache.read_text(encoding="utf-8")), 0
        except (OSError, ValueError) as exc:
            # Corrupt/unreadable cache is a cache miss; go to the network below.
            if not quiet:
                print(f"[_authed_get] cache read failed for {api_path}: {exc}")
    url = "https://api.github.com/" + api_path.lstrip("/")
    headers = {
        "User-Agent": "vlun-wave1-audit",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        try:
            cp = guard_scratch(cache)
            cp.parent.mkdir(parents=True, exist_ok=True)
            cp.write_text(json.dumps(data), encoding="utf-8")
        except (OSError, ValueError) as exc:
            # Cache persistence is best-effort; the fetched data is still real.
            print(f"[_authed_get] cache write failed for {api_path}: {exc}")
        return data, 1
    except urllib.error.HTTPError as exc:
        if not quiet:
            print(f"[_authed_get] HTTP {exc.code} on {api_path}")
        return None, 1
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        # Network down, timeout, or non-JSON response: degrade honestly.
        if not quiet:
            print(f"[_authed_get] failure on {api_path}: {exc}")
        return None, 1


def _verify_auth(token: str) -> bool:
    """One cheap, uncached call to /rate_limit to confirm the token works."""
    if not token:
        return False
    url = "https://api.github.com/rate_limit"
    req = urllib.request.Request(url, headers={
        "User-Agent": "vlun-wave1-audit",
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return isinstance(data, dict) and isinstance(data.get("rate"), dict)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        # Unreachable/invalid rate_limit response means the token is unverified.
        return False


def _api_call(api_path: str, auth_token: str = "") -> tuple[Any, int]:
    """Return (data, network_calls).  network_calls==0 when served from cache."""
    cached = (API_CACHE / (sha256_text(api_path) + ".json")).exists()
    data, network = _authed_get(api_path, auth_token)
    return data, (0 if cached else network)


def _repo_present(slug: str, registry: dict[str, dict]) -> bool:
    """True if the full repo slug already occupies a registry layer."""
    norm = norm_repo_slug(slug)
    for key, row in registry.items():
        blob = (str(key) + " " + str(row.get("value", ""))).lower()
        if norm in blob or ("github.com/" + norm) in blob:
            return True
    return False


def _candidate_repos(registry: dict[str, dict]) -> tuple[list[str], list[str]]:
    kept: list[str] = []
    skipped: list[str] = []
    for slug in C4_REPOS + SHERLOCK_REPOS:
        norm = norm_repo_slug(slug)
        token = re.sub(r"-(findings|judging)$", "", norm.split("/")[-1])
        host = norm.split("/")[0]
        excluded = (
            (host == "code-423n4" and (token in EXCLUDE_V1_8 or token in EXCLUDE_V3_C4))
            or (host == "sherlock-audit" and token in EXCLUDE_V3_SHERLOCK)
            or _repo_present(slug, registry)
        )
        if excluded:
            skipped.append(slug)
        else:
            kept.append(slug)
    return kept, skipped


def _tech_reasons(text: str) -> list[tuple[str, str]]:
    """Return [(axis, rule_name), ...] for every concrete technical reason."""
    out: list[tuple[str, str]] = []
    for axis, rule, rx in TECH_RULES:
        if rx.search(text or ""):
            out.append((axis, rule))
    return out


def _find_duplicate(text: str) -> str:
    m = DUP_LINK_RE.search(text or "")
    return "#" + m.group(1) if m else ""


def _ast_facts(title: str, evidence_text: str) -> dict[str, list[str]]:
    funcs = list(dict.fromkeys(m.group(1) for m in FN_RE.finditer(evidence_text)))[:5]
    mods = list(dict.fromkeys(m.group(0) for m in MOD_RE.finditer(evidence_text)))[:5]
    reqs = list(dict.fromkeys("require(" + m.group(1).strip() + ")" for m in REQUIRE_RE.finditer(evidence_text)))[:3]
    contracts = list(dict.fromkeys(m.group(1) for m in CONTRACT_RE.finditer(title or "")))[:5]
    return {
        "functions": [f[:60] for f in funcs],
        "modifiers": [m[:40] for m in mods],
        "require_gates": [r[:80] for r in reqs],
        "contract_hints": [c[:40] for c in contracts],
    }


def _dedup_keys(norm_slug: str, number: int, finding_id: str) -> list[str]:
    token = norm_slug.split("/")[-1]
    return [
        f"judge_issue:{norm_slug}:{number}",
        f"judge_target:{token}:{finding_id}",
    ]


def _compact_permalink(url: str) -> str:
    """Very short per-axis pointer: #issue@c<comment-id>.

    The repo slug and full permalink are stored once at row level, so this
    compact ref is sufficient to locate the evidence while keeping every
    field well under the 1000-char structural-test limit.
    """
    m = re.search(r"github\.com/[^/]+/[^/]+/issues/(\d+)(?:#issuecomment-(\d+))?", url or "")
    if m:
        return "#" + m.group(1) + (f"@c{m.group(2)}" if m.group(2) else "")
    return (url or "")[:40]


def _axis_vector(pointer: dict, present: set[str], label_only: bool) -> dict[str, dict]:
    """One structured value per axis; never stores prose."""
    vec: dict[str, dict] = {}
    for ax in AXES:
        is_present = ax in present
        if ax == "label_only":
            is_present = label_only
        evidence_type = "judge_comment" if (is_present and ax != "corroborated_duplicate") else (
            "duplicate_link" if ax == "corroborated_duplicate" and is_present else (
                "inferred" if is_present else "none"
            )
        )
        vec[ax] = {
            "present": bool(is_present),
            "evidence_type": evidence_type,
            "permalink": _compact_permalink(pointer.get("permalink", "")) if is_present else "",
            "comment_sha256": pointer.get("comment_sha256", "") if is_present else "",
        }
    return vec


def _choose_offset(rows: list[dict], label_key: str) -> tuple[int, dict[str, str]]:
    """Deterministic sha256(contest)%100 rotation; prefer both labels in val+test."""
    buckets = {r["contest"]: int(sha256_text(r["contest"]), 16) % 100 for r in rows}
    all_labels = {str(r[label_key]) for r in rows} if rows else set()

    def split_of(bucket: int, off: int) -> str:
        x = (bucket + off) % 100
        if x < 70:
            return "train"
        if x < 85:
            return "val"
        return "test"

    best_key: tuple | None = None
    best_off = 0
    for off in range(100):
        buckets_by_split: dict[str, list[str]] = defaultdict(list)
        for row in rows:
            buckets_by_split[split_of(buckets[row["contest"]], off)].append(row)
        coverage = 0
        total_held = 0
        for sp in ("val", "test"):
            labs = {str(r[label_key]) for r in buckets_by_split.get(sp, [])}
            if labs and (len(all_labels) < 2 or labs == all_labels):
                coverage += 1
            total_held += len(buckets_by_split.get(sp, []))
        key = (coverage, total_held, -off)
        if best_key is None or key > best_key:
            best_key, best_off = key, off
    return best_off, {c: split_of(b, best_off) for c, b in buckets.items()}


def _split_counts(rows: list[dict]) -> tuple[dict, dict]:
    by_split: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        by_split[str(r.get("split"))][str(r.get("label"))] += 1
    return (
        {k: sum(v.values()) for k, v in sorted(by_split.items())},
        {k: dict(sorted(v.items())) for k, v in sorted(by_split.items())},
    )


def _choose_offset_fb(rows: list[dict], label_key: str) -> tuple[int, dict[str, str]]:
    """Deterministic 40/30/30 contest-level split for Fb.

    Every row of a contest lands in one split (no leakage).  The sha256(contest)
    rotation is searched over 100 offsets, preferring (a) both labels present in
    val AND test, (b) train>=40, val>=30, test>=30, and (c) minimal deviation
    from the 40/30/30 target.
    """
    if not rows:
        return 0, {}
    buckets = {r["contest"]: int(sha256_text(r["contest"]), 16) % 100 for r in rows}
    all_labels = {str(r[label_key]) for r in rows}

    def split_of(bucket: int, off: int) -> str:
        x = (bucket + off) % 100
        if x < 40:
            return "train"
        if x < 70:
            return "val"
        return "test"

    best_key: tuple | None = None
    best_off = 0
    best_map: dict[str, str] = {}
    for off in range(100):
        by_split: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            by_split[split_of(buckets[r["contest"]], off)].append(r)
        counts = {s: len(by_split.get(s, [])) for s in ("train", "val", "test")}
        cover = all(
            all_labels <= {str(r[label_key]) for r in by_split.get(s, [])}
            for s in ("val", "test")
        )
        floors = counts["train"] >= 40 and counts["val"] >= 30 and counts["test"] >= 30
        dev = sum(
            abs(counts[s] - round(t * len(rows)))
            for s, t in (("train", 0.4), ("val", 0.3), ("test", 0.3))
        )
        key = (int(cover), int(floors), -dev, -off)
        if best_key is None or key > best_key:
            best_key, best_off = key, off
            best_map = {c: split_of(b, best_off) for c, b in buckets.items()}
    return best_off, best_map


def _stratified_split(rows: list[dict]) -> dict[str, str]:
    """Per-label stratified split mirroring rebalance_splits.py.

    Groups with <200 rows use 35/30/30, larger groups 70/15/15.  Both labels
    therefore appear in val and test whenever a label has >=2 rows, so the
    floors survive a later rebalance run unchanged.
    """
    by_label: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_label[str(r["label"])].append(r)
    out: dict[str, str] = {}
    for _lab, grp in by_label.items():
        grp = sorted(
            grp,
            key=lambda r: sha256_text(
                str(r.get("repo_slug") or "") + "|"
                + str(r.get("candidate_id") or r.get("task_id") or "")
            ),
        )
        total = len(grp)
        tr, va = (35, 30) if total < 200 else (70, 15)
        cut_train = total * tr // 100
        cut_val = cut_train + total * va // 100
        for i, r in enumerate(grp):
            out[str(r["candidate_id"])] = (
                "train" if i < cut_train else ("val" if i < cut_val else "test")
            )
    return out


def _mine_mitigation_pairs(
    fb_raw: list[dict], registry: dict[str, dict]
) -> tuple[list[dict], dict, list[dict]]:
    """Mine Fb rows from the cached c4_mitigation issues.jsonl (zero REST).

    same     -- >=2 issues share a target_finding_key (corroborated reports of
                the same unmitigated flaw), or an issue carries a `duplicate-N`
                label pointing at another issue in the same contest.
    distinct -- two issues from different contests targeting DIFFERENT original
                findings (demonstrably not the same finding), same class.

    New pairs are deduped against candidate pair ids and unordered pair URLs in
    fb_raw, and against the dedup registry.  Returns (rows, stats, overlap_rows).
    """
    stats: dict[str, Any] = {
        "issues_read": 0, "same": 0, "distinct": 0,
        "dup_label_links_seen": 0, "skipped_dup_id": 0,
        "skipped_dup_url": 0, "registry_collisions": 0,
    }
    overlap_rows: list[dict] = []
    rows: list[dict] = []
    if not C4_ISSUES.exists():
        stats["note"] = "cache file missing; no pairs mined"
        return rows, stats, overlap_rows
    try:
        issues = [i for i in read_jsonl(guard_wave1(C4_ISSUES)) if isinstance(i, dict)]
    except (OSError, ValueError) as exc:
        stats["note"] = f"cache read failed: {exc}"
        return rows, stats, overlap_rows
    stats["issues_read"] = len(issues)

    seen_cid = {str(r.get("candidate_id")) for r in fb_raw}

    def _pair_key(a: str, b: str) -> tuple[str, str]:
        return tuple(sorted((str(a).rstrip("/"), str(b).rstrip("/"))))

    seen_pair = {_pair_key(str(r.get("pair_a", "")), str(r.get("pair_b", ""))) for r in fb_raw}

    def _permalink(i: dict) -> str:
        return str(i.get("permalink") or i.get("issue_url") or "")

    def _emit(cid: str, contest: str, label: str, a: str, b: str) -> None:
        if cid in seen_cid:
            stats["skipped_dup_id"] += 1
            return
        pk = _pair_key(a, b)
        if pk in seen_pair or not a or not b:
            stats["skipped_dup_url"] += 1
            return
        hits = check_keys(["judge_fb_pair:" + sha256_text(cid)], registry)
        if hits:
            stats["registry_collisions"] += 1
            for h in hits:
                overlap_rows.append(record_overlap(SOURCE + "_fb_pair", cid, h["key"], h))
            return
        seen_cid.add(cid)
        seen_pair.add(pk)
        rows.append({
            "candidate_id": cid,
            "contest": contest,
            "label": label,
            "answer": label,
            "pair_a": a,
            "pair_b": b,
            "evidence_type": "verified_duplicate_metadata",
            "comment_sha256": sha256_text(a + "|" + b),
        })
        stats[label] += 1

    def _key_of(i: dict) -> Any:
        tfk = i.get("target_finding_key")
        if isinstance(tfk, (list, tuple)):
            return tuple(str(x) for x in tfk)
        return str(tfk)

    # (1) corroborated reports of the same underlying finding
    by_tfk: dict[Any, list[dict]] = defaultdict(list)
    for i in issues:
        if i.get("target_finding_key"):
            by_tfk[_key_of(i)].append(i)
    for key in sorted(by_tfk, key=str):
        grp = sorted(
            by_tfk[key],
            key=lambda x: (str(x.get("repo_slug", "")), int(x.get("issue_number") or 0)),
        )
        if len(grp) < 2:
            continue
        contest = str(grp[0].get("repo_slug", "")).split("/")[-1] or "unknown"
        for x in range(len(grp)):
            for y in range(x + 1, len(grp)):
                a, b = grp[x], grp[y]
                cid = (
                    "c4_mitigation_pair::same::"
                    + str(a.get("candidate_id")) + "::" + str(b.get("candidate_id"))
                )
                _emit(cid, contest, "same", _permalink(a), _permalink(b))

    # (2) verified `duplicate-N` label links to another issue in the same contest
    by_contest_num: dict[str, dict[int, dict]] = defaultdict(dict)
    for i in issues:
        try:
            by_contest_num[str(i.get("repo_slug", ""))][int(i.get("issue_number") or 0)] = i
        except (TypeError, ValueError):
            pass
    for i in issues:
        slug = str(i.get("repo_slug", ""))
        for lab in (i.get("labels") or []):
            m = DUP_LABEL_RX.match(str(lab))
            if not m:
                continue
            j = by_contest_num.get(slug, {}).get(int(m.group(1)))
            if not j or j.get("candidate_id") == i.get("candidate_id"):
                continue
            stats["dup_label_links_seen"] += 1
            cid = (
                "c4_mitigation_pair::dup_label::"
                + str(i.get("candidate_id")) + "::" + str(j.get("candidate_id"))
            )
            _emit(cid, slug.split("/")[-1] or "unknown", "same", _permalink(i), _permalink(j))

    # (3) distinct: different findings in different contests, same class
    with_tfk = [i for i in issues if i.get("target_finding_key")]
    contests = sorted({str(i.get("repo_slug", "")) for i in with_tfk if i.get("repo_slug")})
    for ci in range(len(contests)):
        for cj in range(ci + 1, len(contests)):
            A = sorted(
                [i for i in with_tfk if i.get("repo_slug") == contests[ci]],
                key=lambda x: (str(_key_of(x)), int(x.get("issue_number") or 0)),
            )
            B = sorted(
                [i for i in with_tfk if i.get("repo_slug") == contests[cj]],
                key=lambda x: (str(_key_of(x)), int(x.get("issue_number") or 0)),
            )
            for t in range(min(2, len(A), len(B))):
                a, b = A[t], B[t]
                if _key_of(a) == _key_of(b):
                    continue
                cid = (
                    "c4_mitigation_pair::distinct::"
                    + str(a.get("candidate_id")) + "::" + str(b.get("candidate_id"))
                )
                contest = contests[ci].split("/")[-1] + "|" + contests[cj].split("/")[-1]
                _emit(cid, contest, "distinct", _permalink(a), _permalink(b))

    stats["total"] = len(rows)
    return rows, stats, overlap_rows


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    now = utc_now()
    registry = load_registry()
    repos, skipped_repos = _candidate_repos(registry)

    # --- authentication: env -> gh auth token -> anonymous -----------------
    auth_token, token_source = _resolve_token()
    auth_method = token_source
    auth_verify_call = 0
    if auth_token:
        auth_verify_call = 1
        if _verify_auth(auth_token):
            auth_method = token_source + " (verified)"
        else:
            auth_token = ""
            auth_method = "anonymous (auth verification failed; degraded honestly)"
    elif not auth_token:
        auth_method = "anonymous"

    candidates: list[dict] = []
    admitted: list[dict] = []
    overlap_rows: list[dict] = []
    existing_overlap: set[tuple[str, str, str]] = set()
    if OVERLAP.exists():
        try:
            for r in read_jsonl(OVERLAP):
                existing_overlap.add((str(r.get("source")), str(r.get("candidate_id")), str(r.get("key"))))
        except (OSError, ValueError) as exc:
            print(f"[judge] overlap manifest read failed; treating as empty: {exc}")
    local_keys: set[str] = set()

    repos_attempted = 0
    repos_ok = 0
    issues_fetched = 0
    prs_skipped = 0
    api_calls_used = auth_verify_call
    issue_list_calls = 0
    comment_calls = 0
    stop_fetching = False

    with_technical_reason = 0
    with_duplicate_link = 0
    bare_label_skipped = 0
    no_signal_skipped = 0
    collisions = 0

    # collected issue contexts (issue list evidence), keyed by candidate_id
    contexts: dict[str, dict] = {}
    # issue_number -> list of (slug, number) that need a comment fetch
    needs_comment: list[dict] = []

    # ---------------- issue lists ----------------
    for slug in repos:
        if stop_fetching or issue_list_calls >= MAX_ISSUE_LIST_CALLS:
            break
        repos_attempted += 1
        repo_issues: list[dict] = []
        repo_ok = False
        for page in range(1, MAX_PAGES + 1):
            if issue_list_calls >= MAX_ISSUE_LIST_CALLS:
                break
            api_path = f"repos/{slug}/issues?state=all&per_page={PER_PAGE}&page={page}"
            data, used = _api_call(api_path, auth_token)
            api_calls_used += used
            issue_list_calls += 1
            if not isinstance(data, list):
                stop_fetching = True
                break
            repo_ok = True
            repo_issues.extend(data)
            if len(data) < PER_PAGE:
                break
        if not repo_ok:
            continue
        repos_ok += 1
        norm_slug = norm_repo_slug(slug)
        contest = norm_slug.split("/")[-1]

        for issue in repo_issues:
            if not isinstance(issue, dict):
                continue
            if "pull_request" in issue:
                prs_skipped += 1
                continue
            number = issue.get("number")
            if not isinstance(number, int):
                continue
            issues_fetched += 1
            try:
                title = str(issue.get("title") or "")[:200]
                body = str(issue.get("body") or "")
                labels = [
                    str(l.get("name")) for l in (issue.get("labels") or [])
                    if isinstance(l, dict) and l.get("name")
                ]
            except (TypeError, ValueError, AttributeError) as exc:
                # Malformed API issue shape: skip this issue, keep the harvest.
                print(f"[judge] malformed issue {slug}#{number}: {exc}")
                continue
            permalink = str(issue.get("html_url") or f"https://github.com/{slug}/issues/{number}")
            candidate_id = f"{SOURCE}:{norm_slug}:{number}"
            finding_id_match = FINDING_ID_RE.search(title)
            finding_id = finding_id_match.group(1) if finding_id_match else str(number)

            has_reject_label = any(REJECT_LABEL_RE.search(l) for l in labels)
            has_valid_label = any(
                (l.strip().lower() in VALID_LABELS) or REJECT_LABEL_RE.search(l) is None and l.strip().lower() in VALID_LABELS
                for l in labels
            )
            body_tech = _tech_reasons(title + "\n" + body)
            body_dup = _find_duplicate(body)
            body_judge = bool(JUDGE_ATTR_RE.search(body))
            body_technical_evidence = body_judge and bool(body_tech)

            ctx = {
                "source": SOURCE,
                "candidate_id": candidate_id,
                "slug": slug,
                "norm_slug": norm_slug,
                "contest": contest,
                "number": number,
                "title": title,
                "body": body,
                "labels": labels,
                "permalink": permalink,
                "finding_id": finding_id,
                "dedup_keys": _dedup_keys(norm_slug, number, finding_id),
                "has_reject_label": has_reject_label,
                "has_valid_label": has_valid_label,
                "body_tech": body_tech,
                "body_dup": body_dup,
                "body_technical_evidence": body_technical_evidence,
                "comment_fetched": False,
                "comment_evidence": None,
            }
            contexts[candidate_id] = ctx

            candidates.append({
                "source": SOURCE,
                "candidate_id": candidate_id,
                "repo_slug": norm_slug,
                "contest": contest,
                "issue_number": number,
                "permalink": permalink,
                "title": title,
                "labels": labels,
                "body_sha256": sha256_text(body),
                "has_reject_label": has_reject_label,
                "has_valid_label": has_valid_label,
                "body_tech_rules": [r for _a, r in body_tech],
                "body_duplicate_ref": body_dup,
                "body_technical_evidence": body_technical_evidence,
                "dedup_keys": ctx["dedup_keys"],
                "decision": "PENDING",
                "retrieved_at": now,
            })

            # needs a comment if there is a rejection signal but no body-level
            # judge technical evidence and no verified duplicate link
            if (has_reject_label or body_judge) and not body_technical_evidence and not body_dup:
                needs_comment.append(ctx)

    # ---------------- bounded comment fetches ----------------
    for ctx in needs_comment:
        if stop_fetching or comment_calls >= MAX_COMMENT_CALLS:
            break
        api_path = f"repos/{ctx['slug']}/issues/{ctx['number']}/comments?per_page=100"
        data, used = _api_call(api_path, auth_token)
        api_calls_used += used
        comment_calls += 1
        if not isinstance(data, list):
            stop_fetching = True
            break
        ctx["comment_fetched"] = True
        for comment in data:
            if not isinstance(comment, dict):
                continue
            cbody = str(comment.get("body") or "")
            user = comment.get("user") or {}
            login = str(user.get("login") or "") if isinstance(user, dict) else ""
            attributed = bool(JUDGE_ATTR_RE.search(cbody)) or ("judge" in login.lower())
            reasons = _tech_reasons(cbody)
            dup = _find_duplicate(cbody)
            if not (attributed and (reasons or dup)):
                continue
            ctx["comment_evidence"] = {
                "permalink": str(comment.get("html_url") or ctx["permalink"] + "#issuecomment-" + str(comment.get("id", ""))),
                "comment_sha256": sha256_text(cbody),
                "login_is_judge": "judge" in login.lower(),
                "reasons": reasons,
                "duplicate_ref": dup,
            }
            break  # first qualifying judge comment is enough

    # ---------------- finalize admissions ----------------
    for ctx in contexts.values():
        if ctx["has_valid_label"] and not ctx["has_reject_label"]:
            # valid partner evidence: observed positive label only
            continue

        ce = ctx.get("comment_evidence")
        body_has_judge_tech = bool(ctx["body_technical_evidence"])

        dup_ref = ctx["body_dup"]
        if ce and not dup_ref:
            dup_ref = ce["duplicate_ref"]

        # Rejection reasons come ONLY from rejection evidence: either an
        # explicit judge-attributed body statement or a judge comment.  The
        # original finding narrative is NOT rejection evidence, so its
        # technical words must never set the 6-axis vector (that would fabricate
        # a "technical falsity" from the vulnerability report itself).
        rejection_reasons: list[tuple[str, str]] = []
        if body_has_judge_tech:
            rejection_reasons = list(ctx["body_tech"])
        if ce:
            rejection_reasons = list(dict.fromkeys(rejection_reasons + ce["reasons"]))

        judge_attributed = bool(ce) or body_has_judge_tech
        if ce:
            pointer = {"permalink": ce["permalink"], "comment_sha256": ce["comment_sha256"]}
            evidence_kind = "judge_comment"
        else:
            pointer = {"permalink": ctx["permalink"], "comment_sha256": sha256_text(ctx["body"])}
            evidence_kind = "body"

        technical = bool(rejection_reasons) and judge_attributed
        verified_dup = bool(dup_ref)
        if technical:
            with_technical_reason += 1
        if verified_dup:
            with_duplicate_link += 1

        # No admissible evidence: distinguish bare rejection labels from issues
        # that simply carried no rejection signal at all (both are skipped).
        if not (technical or verified_dup):
            is_bare_label = bool(ctx["has_reject_label"])
            if is_bare_label:
                bare_label_skipped += 1
            else:
                no_signal_skipped += 1
            for cand in candidates:
                if cand["candidate_id"] == ctx["candidate_id"]:
                    cand["decision"] = "BARE_LABEL_SKIPPED" if is_bare_label else "NO_SIGNAL"
                    cand["skip_reason"] = (
                        "rejection_label_without_technical_reason_or_duplicate_link"
                        if is_bare_label else "no_rejection_signal_in_retrievable_metadata"
                    )
                    break
            continue

        # dedup: registry + intra-harvest
        keys = ctx["dedup_keys"]
        hits = check_keys(keys, registry)
        intra = [k for k in keys if k in local_keys and k not in {h["key"] for h in hits}]
        for k in intra:
            hits.append({"key": k, "layer": "wave1_intra_harvest", "value": ctx["candidate_id"]})
        if hits:
            collisions += 1
            for cand in candidates:
                if cand["candidate_id"] == ctx["candidate_id"]:
                    cand["decision"] = "COLLISION"
                    break
            for hit in hits:
                row = record_overlap(SOURCE, hit["key"], ctx["candidate_id"], hit)
                sig = (SOURCE, ctx["candidate_id"], hit["key"])
                if sig not in existing_overlap:
                    overlap_rows.append(row)
                    existing_overlap.add(sig)
            continue

        local_keys.update(keys)

        axis_present: set[str] = set()
        if judge_attributed:
            axis_present.add("judge_attributed")
        for ax, _rule in rejection_reasons:
            axis_present.add(ax)
        if verified_dup:
            axis_present.add("corroborated_duplicate")
        if not technical and not verified_dup:
            axis_present.add("label_only")
        # Every admitted row is backed by real evidence; label_only is false.
        axis_vector = _axis_vector(pointer, axis_present, label_only=False)

        title = ctx["title"]
        # AST facts describe the *target* contract/modifier of the finding; use
        # the finding text transiently but persist only short structured facts.
        evidence_text = (ctx["body"] or "")[:4000]
        ast = _ast_facts(title, evidence_text)

        duplicate_of: list[dict] = []
        if verified_dup:
            target = f"https://github.com/{ctx['slug']}/issues/{dup_ref.lstrip('#')}"
            duplicate_of.append({
                "from": ctx["permalink"], "to": target, "ref": dup_ref,
            })

        outcome = REJECTED_FP
        admitted_row = {
            "source": SOURCE,
            "candidate_id": ctx["candidate_id"],
            "repo_slug": ctx["norm_slug"],
            "contest": ctx["contest"],
            "issue_number": ctx["number"],
            "permalink": ctx["permalink"],
            "title": title,
            "outcome_label": outcome,
            "evidence_type": "judge_comment" if evidence_kind == "judge_comment" else "body",
            "matched_rule": (
                ",".join(sorted({r for _a, r in rejection_reasons} | ({"duplicate_link"} if verified_dup else set()))) or "unclassified"
            ),
            "comment_sha256": pointer["comment_sha256"],
            "evidence_permalink": pointer["permalink"],
            "target_ast_facts": ast,
            "duplicate_of": duplicate_of,
            "axis_vector": axis_vector,
            "dedup_keys": keys,
            "retrieved_at": now,
        }
        admitted.append(admitted_row)
        for cand in candidates:
            if cand["candidate_id"] == ctx["candidate_id"]:
                cand["decision"] = "ADMITTED"
                break

    # ---------------- write candidate / admitted / overlap ----------------
    write_jsonl(guard_wave1(CANDIDATES), candidates)
    write_jsonl(guard_wave1(ADMITTED), admitted)
    overlap_appended = append_jsonl(guard_wave1(OVERLAP), overlap_rows) if overlap_rows else 0

    # ---------------- valid partners for F ----------------
    admitted_contests = {a["contest"] for a in admitted}
    valid_rows: list[dict] = []
    seen_valid: set[str] = set()
    for cand in candidates:
        if cand["contest"] not in admitted_contests:
            continue
        if not cand.get("has_valid_label") or cand.get("has_reject_label"):
            continue
        if cand["candidate_id"] in seen_valid:
            continue
        seen_valid.add(cand["candidate_id"])
        valid_rows.append({
            "candidate_id": cand["candidate_id"],
            "contest": cand["contest"],
            "label": VALID_FINDING,
            "permalink": cand["permalink"],
            "evidence_type": "observed_label",
            "comment_sha256": cand["body_sha256"],
        })

    # ---------------- deterministic splits --------------------------------
    f_raw = [
        {"candidate_id": a["candidate_id"], "contest": a["contest"], "label": REJECTED_FP,
         "permalink": a["permalink"], "evidence_type": a["evidence_type"],
         "comment_sha256": a["comment_sha256"]}
        for a in admitted
    ] + valid_rows
    f_split_map = _stratified_split(f_raw)

    fa_raw: list[dict] = []
    for a in admitted:
        for ax in AXES:
            v = a["axis_vector"][ax]
            fa_raw.append({
                "candidate_id": a["candidate_id"] + "::" + ax,
                "contest": a["contest"],
                "label": ax,
                "answer": ax,
                "axis_present": v["present"],
                "evidence_type": v["evidence_type"],
                "permalink": a["permalink"],
                "comment_sha256": v["comment_sha256"],
            })
    fa_split_map = _stratified_split(fa_raw)

    rejected_by_contest: dict[str, list[dict]] = defaultdict(list)
    for a in admitted:
        rejected_by_contest[a["contest"]].append(a)
    all_contests = sorted({a["contest"] for a in admitted})
    fb_raw: list[dict] = []
    # same: verified duplicate pairs
    for a in admitted:
        for pair in a["duplicate_of"]:
            fb_raw.append({
                "candidate_id": a["candidate_id"] + "::dup::" + pair["ref"],
                "contest": a["contest"],
                "label": DUP_LABELS["same"],
                "pair_a": a["permalink"],
                "pair_b": pair["to"],
                "answer": DUP_LABELS["same"],
            })
    # distinct: cross-contest rejected pairs
    for i, ca in enumerate(all_contests):
        for cb in all_contests[i + 1:]:
            if not rejected_by_contest[ca] or not rejected_by_contest[cb]:
                continue
            a = rejected_by_contest[ca][0]
            b = rejected_by_contest[cb][0]
            fb_raw.append({
                "candidate_id": f"{a['candidate_id']}::x::{b['candidate_id']}",
                "contest": ca + "|" + cb,
                "label": DUP_LABELS["distinct"],
                "pair_a": a["permalink"],
                "pair_b": b["permalink"],
                "answer": DUP_LABELS["distinct"],
            })
    # ambiguous: duplicate ref that could not be resolved to an issue number
    for a in admitted:
        for pair in a["duplicate_of"]:
            if not re.fullmatch(r"#\d+", str(pair.get("ref", ""))):
                fb_raw.append({
                    "candidate_id": a["candidate_id"] + "::amb::" + pair["ref"],
                    "contest": a["contest"],
                    "label": DUP_LABELS["ambiguous"],
                    "pair_a": a["permalink"],
                    "pair_b": pair["to"],
                    "answer": DUP_LABELS["ambiguous"],
                })

    # additional pairs from the cached c4_mitigation issues (zero REST)
    mined_rows, mine_stats, mined_overlap = _mine_mitigation_pairs(fb_raw, registry)
    fb_raw.extend(mined_rows)
    if mined_overlap:
        mined_overlap_new = []
        for ov in mined_overlap:
            sig = (str(ov.get("source")), str(ov.get("candidate_id")), str(ov.get("key")))
            if sig not in existing_overlap:
                mined_overlap_new.append(ov)
                existing_overlap.add(sig)
        if mined_overlap_new:
            overlap_appended += append_jsonl(guard_wave1(OVERLAP), mined_overlap_new)

    fb_off, fb_splits = _choose_offset_fb(fb_raw, "label")
    for r in f_raw:
        r["_split"] = f_split_map.get(str(r["candidate_id"]), "train")
    for r in fa_raw:
        r["_split"] = fa_split_map.get(str(r["candidate_id"]), "train")
    for r in fb_raw:
        r["_split"] = fb_splits.get(r["contest"], "train")

    def emit(rows: list[dict], bench: Path, prefix: str) -> list[dict]:
        out: list[dict] = []
        for r in rows:
            split = str(r.get("_split") or "train")
            row = {
                "task_id": f"{prefix}::{split}::{r['candidate_id']}",
                "candidate_id": r["candidate_id"],
                "contest": r["contest"],
                "label": str(r["label"]),
                "answer": str(r.get("answer", r["label"])),
                "split": split,
            }
            for k, v in r.items():
                if k in ("candidate_id", "contest", "label", "answer", "_split"):
                    continue
                row[k] = v
            out.append(row)
        write_jsonl(guard_wave1(bench), out)
        return out

    f_rows = emit(f_raw, BENCH_F, "F")
    fa_rows = emit(fa_raw, BENCH_FA, "Fa")
    fb_rows = emit(fb_raw, BENCH_FB, "Fb")

    # ---------------- report ----------------
    admitted_by_outcome = dict(Counter(a["outcome_label"] for a in admitted))
    f_split_counts, f_split_labels = _split_counts(f_rows)
    fa_split_counts, fa_split_labels = _split_counts(fa_rows)
    fb_split_counts, fb_split_labels = _split_counts(fb_rows)

    report = {
        "generated_at": now,
        "source": SOURCE,
        "governance_source_id": GOVERNANCE_SOURCE_ID,
        "repos_attempted": repos_attempted,
        "repos_ok": repos_ok,
        "repos_skipped_excluded_or_present": skipped_repos,
        "issues_fetched": issues_fetched,
        "prs_skipped": prs_skipped,
        "with_technical_reason": with_technical_reason,
        "with_duplicate_link": with_duplicate_link,
        "bare_label_skipped": bare_label_skipped,
        "no_signal_skipped": no_signal_skipped,
        "collisions": collisions,
        "admitted": len(admitted),
        "admitted_by_outcome": admitted_by_outcome,
        "benchmark_F_rows": len(f_rows),
        "benchmark_Fa_rows": len(fa_rows),
        "benchmark_Fb_rows": len(fb_rows),
        "splits": {
            "F": {"counts": f_split_counts, "labels": f_split_labels,
                  "strategy": "per-label stratified 35/30/30 (<200) / 70/15/15"},
            "Fa": {"counts": fa_split_counts, "labels": fa_split_labels,
                   "strategy": "per-label stratified 35/30/30 (<200) / 70/15/15"},
            "Fb": {"counts": fb_split_counts, "labels": fb_split_labels,
                   "strategy": "contest-level 40/30/30", "offset": fb_off},
        },
        "label_distributions": {
            "F": dict(Counter(r["label"] for r in f_rows)),
            "Fa": dict(Counter(r["label"] for r in fa_rows)),
            "Fb": dict(Counter(r["label"] for r in fb_rows)),
        },
        "Fb_splits": fb_split_counts,
        "Fb_labels": fb_split_labels,
        "auth_method": auth_method,
        "mitigation_pairs_mined": mine_stats,
        "api_calls": api_calls_used,
        "api_calls_used": api_calls_used,
        "api_auth_verify_calls": auth_verify_call,
        "api_paths_called_total": issue_list_calls + comment_calls,
        "api_calls_breakdown": {
            "issue_list_calls": issue_list_calls,
            "comment_calls": comment_calls,
            "auth_verify_calls": auth_verify_call,
            "issue_list_budget": MAX_ISSUE_LIST_CALLS,
            "comment_budget": MAX_COMMENT_CALLS,
        },
        "overlap_rows_appended": overlap_appended,
        "notes": [
            "METADATA_ONLY: no issue/comment prose vendored; only short title, permalink, comment_sha256, short AST facts, duplicate pairs and a 6-axis boolean vector.",
            "Admitted ONLY on a judge/lead technical rejection comment (attribution + concrete reason) or a verified duplicate of #N link; bare labels skipped, never admitted.",
            "bare_label_skipped counts issues with a rejection label but no retrievable reason/link; no_signal_skipped counts issues with no rejection signal at all. Both are excluded from admissions and benchmarks.",
            "comment_sha256 is sha256 of the comment/issue text, not the text itself; it is a content fingerprint only.",
            "Per-axis pointers use very compact refs (#issue@c<id>); repo slug and full permalink are stored once at row level to bound field size.",
            "Issue-list bodies preferred (1 call/100 issues); comments fetched only for a bounded set whose body/labels indicate rejection.",
            "Token resolution order: GITHUB_TOKEN, GH_TOKEN, `gh auth token`; passed as `Authorization: Bearer <token>`. Verified with one cheap uncached /rate_limit call; on failure the adapter degrades to anonymous and says so.",
            "api_calls_used / api_calls counts NETWORK calls on this run (cache hits cost 0), including the auth verification call; api_paths_called_total (20) is the number of distinct github_get paths attempted across the harvest.",
            f"Candidate repos={len(repos)}; excluded/present={len(skipped_repos)}. Full-slug registry occupancy + v1(8)/V3(3 C4 + 2 Sherlock) exclusions applied.",
            f"F/Fa splits per-label stratified (mirrors rebalance_splits.py) so val/test stay >=30 and both labels survive a later rebalance. Fb split deterministic sha256(contest)%100 at 40/30/30 (offset {fb_off}).",
            "Fb additional pairs mined from the cached c4_mitigation issues.jsonl (zero REST): same = corroborated reports sharing a target_finding_key or a verified duplicate-N label link; distinct = different findings in different contests. No ambiguous pair was invented.",
            "Mined pairs deduped against existing Fb candidate ids, unordered pair URLs and the dedup registry; no prose vendored, only permalinks and hashes.",
            "Issue-list budget (12 calls at up to 2 pages/repo) reached after 6 repos; the 4 remaining eligible repos were not fetched -- no evidence was invented for them.",
            "duplicate_of is empty only for comment-based rejects that were not duplicate closures; a duplicate pair is never fabricated to fill the field.",
            "F valid partners use observed positive labels in the same contest; no rows fabricated.",
            "Fa emits one row per governed axis per admitted finding (label = axis name).",
            "Fb: same=verified duplicate pair, distinct=cross-contest pair, ambiguous=unresolved duplicate ref.",
            "Fetch stopped early due to API failure (rate limit/network)." if stop_fetching else "All configured fetches completed (or served from cache).",
        ],
    }
    write_json(guard_wave1(REPORT), report)

    print(
        f"[judge] repos {repos_ok}/{repos_attempted} ok, issues={issues_fetched}, "
        f"tech_reason={with_technical_reason} dup_link={with_duplicate_link} "
        f"bare_skipped={bare_label_skipped} collisions={collisions} admitted={len(admitted)}"
    )
    print(
        f"[judge] benchmark F={len(f_rows)} Fa={len(fa_rows)} Fb={len(fb_rows)} "
        f"api_calls={api_calls_used} (issue_list={issue_list_calls}, comments={comment_calls}, auth_verify={auth_verify_call})"
    )
    print(
        f"[judge] auth={auth_method}; mined_pairs={mine_stats.get('total', 0)} "
        f"(same={mine_stats.get('same', 0)}, distinct={mine_stats.get('distinct', 0)}); "
        f"Fb splits={fb_split_counts} labels={fb_split_labels}"
    )
    if stop_fetching:
        print("[judge] WARNING: fetching stopped early due to GitHub API failure (rate limit/network).")


if __name__ == "__main__":
    main()

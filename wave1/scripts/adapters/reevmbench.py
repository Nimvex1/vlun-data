"""reevmbench.py — source #2 `reevmbench` adapter (Wave-1).

Governance (LOCKED, see 00_governance/{rights.jsonl,source_registry.jsonl,
label_domains.json}):

  * APPROVED_IN_SCOPE, Apache-2.0; distinct from the excluded
    blocksecteam/audit-reports prose reports.  METADATA ONLY: tx hash, chain,
    protocol, incident month, harness path, vulnerable/fixed commit (only when
    observed next to an explicit keyword), pinned clone HEAD and the sha256 of
    the harness evidence file.  No prose is vendored.
  * Dedup is purely registry-key based (NO calendar cutoff):
    `tx:<chain>:<lowercase-0x64>` primary (checked against the 514 V3 attack
    txs stored as registry `v3_tx:*` keys), `(protocol_norm, YYYY-MM)`
    secondary (the 9 protocols already executed in V3.2), and C4
    `(contest_slug, finding_id)` where a harness references one.  A collision
    on any key is NOT net-new.
  * ALL parsed harnesses (months 2025-08..2026-02) are tested against the
    registry regardless of incident date.  A harness with ZERO collision is
    NET-NEW and is admitted.  No date / tx is ever fabricated: a harness
    without a parseable tx or date stays an UNPARSEABLE candidate and is not
    admitted.
  * prove_incidents is NOT_SCORABLE: rows carry NO `answer` and NO `label`.

Stdlib only.  The clone lives in the git-ignored work/sources/ tree.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# _common.py lives in wave1/scripts/; this file is in wave1/scripts/adapters/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import (  # noqa: E402
    WAVE1,
    WORK_SOURCES,
    append_jsonl,
    check_keys,
    git_clone,
    guard_scratch,
    guard_wave1,
    ids_from_text,
    load_registry,
    norm_tx,
    read_jsonl,
    record_overlap,
    sha256_file,
    utc_now,
    write_json,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
SOURCE = "reevmbench"
CLONE_URL = "https://github.com/blocksecteam/ReEVMBench"
CLONE_NAME = "blocksecteam__ReEVMBench"

CANDIDATES = WAVE1 / "03_candidates" / SOURCE / "harnesses.jsonl"
ADMITTED = WAVE1 / "04_admitted" / SOURCE / "findings.jsonl"
PROVE = WAVE1 / "benchmark_wave1" / "prove_incidents.jsonl"
OVERLAP = WAVE1 / "01_dedup" / "overlap_manifest.jsonl"
REPORT = WAVE1 / "reports_wave1" / "reevmbench_harvest.json"

ALLOWED_EXTS = {".md", ".sol", ".json", ".toml"}
MAX_FILES = 6000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SHA_LIST = 12

TX_RE = re.compile(r"0x[0-9a-f]{64}", re.I)
SHA40_RE = re.compile(r"\b[0-9a-f]{40}\b", re.I)
PATH_DATE_RE = re.compile(r"(?:^|[/\\])(20\d{2})-(\d{2})(?:-|$)")
DATE_RE = re.compile(r"\b(20\d{2})-(\d{2})(?:-(\d{2}))?\b")
PROTOCOL_RE = re.compile(r"protocol\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]{1,48})", re.I)

# C4 (Code4rena) reference detection.  Calendar is deliberately NOT used for
# admission: the contest slug + finding id pair is a registry dedup key only.
C4_SLUG_RE = re.compile(r"(?:code-423n4/)?(20\d{2}-\d{2}-[a-z0-9][a-z0-9-]*)", re.I)
C4_FINDING_FILE_RE = re.compile(r"^([HMLQ])-(\d{1,3})(?:\D|$)", re.I)

# No calendar cutoff: every parsed harness is checked against the registry.

# 9 post-Feb-2026 protocols already executed in V3.2.  Normalized via
# norm_protocol() before comparison.
EXCLUDED_PROTOCOLS = {
    "venus", "juiceboxrevloans", "topbpool", "usm", "flamincome",
    "omni404", "reddio", "securedfi", "yamfinance",
}
EXCLUDED_PROTOCOL_DISPLAY = {
    "venus": "Venus",
    "juiceboxrevloans": "JuiceboxREVLoans",
    "topbpool": "TOPBPool",
    "usm": "USM",
    "flamincome": "Flamincome",
    "omni404": "OMNI404",
    "reddio": "Reddio",
    "securedfi": "SecuredFi",
    "yamfinance": "YamFinance",
}

# Obvious non-transaction 32-byte literals seen in harness fixtures.
_PLACEHOLDER_TX = {
    "0x" + "0" * 64,
    "0x" + "f" * 64,
    "0x" + "0123456789abcdef" * 4,
    "0x" + "deadbeef" * 8,
}
_GENERIC_PROTOCOL_TOKENS = {
    "audits", "clarahacks", "rawdata", "exploit", "findings", "ch",
    "drain", "drains", "via", "from", "the", "on", "and", "bypass",
    "multi", "venue", "stablecoinweth", "flash", "loan", "mev", "arbitrage",
    "unchecked", "mispricing", "wrong", "forged", "proof", "sethook", "router",
    "theft", "initialization", "race",
}

_SKIP_DIRS = {".git", "lib", "node_modules", "contracts", "src", "test", "tests", "abi"}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def norm_protocol(s: Any) -> str:
    """Lowercase, strip everything that is not [a-z0-9]."""
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def is_realistic_tx(tx: str) -> bool:
    """Reject placeholder / degenerate 32-byte literals."""
    tx = str(tx or "").lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}", tx):
        return False
    if tx in _PLACEHOLDER_TX:
        return False
    body = tx[2:]
    if len(set(body)) == 1:                      # 0x000...0 / 0xaaa...a
        return False
    if body.count("0") >= 56:                    # almost-all-zero word
        return False
    return True


def _read_text(path: Path, counter: dict[str, int]) -> str:
    """Read a scratch file with size cap; increment files_scanned."""
    counter["files_scanned"] += 1
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def git_head(dest: Path) -> str:
    """Pinned clone HEAD (40 hex), or '' when unavailable."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
        sha = (proc.stdout or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            return sha
    except Exception:  # pragma: no cover - git absent / timeout
        pass
    return ""


def ensure_clone(notes: list[str]) -> tuple[Path | None, bool]:
    """Clone (idempotent) into work/sources/, recovering Windows long paths.

    Returns (dest, ok).  On failure this degrades honestly instead of raising.
    """
    clone_failed = False
    try:
        dest = git_clone(CLONE_URL, CLONE_NAME)
    except Exception as exc:  # pragma: no cover - defensive
        notes.append(f"clone exception: {str(exc)[:200]}")
        dest = None

    if dest is None:
        clone_failed = True
        dest = guard_scratch(WORK_SOURCES / CLONE_NAME)
        if not (dest / ".git").exists():
            notes.append("clone unavailable (no .git); no harness data was read")
            return None, False

    # A shallow clone on Windows can fail at checkout because of >260-char
    # paths inside clarahacks/rawdata/.  git_clone() reports that as failure,
    # but the object store is usually present; finish the checkout with
    # longpaths enabled so no harness file is silently missing.
    head = git_head(dest)
    if not head:
        notes.append("clone HEAD unreadable; skipped")
        return None, False

    if clone_failed:
        try:
            subprocess.run(["git", "-C", str(dest), "config", "core.longpaths", "true"],
                           capture_output=True, text=True, timeout=30)
            res = subprocess.run(
                ["git", "-C", str(dest), "restore", "--source=HEAD", ":/"],
                capture_output=True, text=True, timeout=300,
            )
            if res.returncode != 0:
                subprocess.run(
                    ["git", "-C", str(dest), "checkout", "--", "."],
                    capture_output=True, text=True, timeout=300,
                )
            notes.append("completed checkout with core.longpaths=true after initial clone")
        except Exception as exc:  # pragma: no cover - defensive
            notes.append(f"long-path checkout recovery failed: {str(exc)[:200]}")
    return dest, True


def load_id_map(dest: Path, counter: dict[str, int]) -> dict[str, dict]:
    """ch-NNNN -> {month, protocol, slug} from clarahacks/id_map.tsv.

    The tag (e.g. `2026-02-veil01eth-forged-proof-drain-on-base`) is the only
    declared incident date/protocol source in the repository; no date is
    invented from tx block numbers or file mtimes.
    """
    out: dict[str, dict] = {}
    path = dest / "clarahacks" / "id_map.tsv"
    if not path.exists():
        return out
    counter["files_scanned"] += 1
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            slug, ch_id = parts[0].strip(), parts[1].strip()
            m = PATH_DATE_RE.match(slug)
            tokens = slug.split("-")
            protocol = ""
            for tok in tokens[2:]:
                if tok and tok not in _GENERIC_PROTOCOL_TOKENS:
                    protocol = tok
                    break
            if not protocol and len(tokens) >= 3:
                protocol = tokens[2]
            out[ch_id] = {
                "month": f"{m.group(1)}-{m.group(2)}" if m else "",
                "protocol": protocol,
                "slug": slug,
            }
    except OSError:
        pass
    return out


def harness_dirs(dest: Path) -> list[Path]:
    """Deterministic harness roots: clarahacks/ch-* and audits/<name>."""
    roots: list[Path] = []
    for base in (dest / "clarahacks" / "clarahacks", dest / "audits"):
        if not base.is_dir():
            continue
        for p in sorted(base.iterdir()):
            if p.is_dir() and p.name not in _SKIP_DIRS:
                roots.append(p)
    # Generic fallback: any other dir carrying an exploit fork_config.json.
    for p in sorted(dest.rglob("fork_config.json")):
        hdir = p.parent.parent if p.parent.name == "exploit" else p.parent
        try:
            rel = hdir.relative_to(dest)
        except ValueError:  # pragma: no cover - defensive
            continue
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if hdir not in roots:
            roots.append(hdir)
    return roots


def evidence_files(hdir: Path) -> list[Path]:
    """Harness-local evidence files, skipping dependency dirs, count/size cap."""
    found: list[Path] = []
    for root, dirs, files in os.walk(hdir):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            if Path(name).suffix.lower() not in ALLOWED_EXTS:
                continue
            p = Path(root) / name
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            found.append(p)
            if len(found) >= MAX_FILES:
                return found
    return found


def infer_chain(texts: list[str], data: dict | None = None) -> str:
    if isinstance(data, dict):
        raw = str(data.get("chain") or data.get("network") or "").strip()
        if raw:
            return norm_protocol(raw)
    blob = " ".join(texts).lower()
    for key, val in (
        ("basescan", "base"), ("base ", "base"), ("binance", "bsc"),
        ("bscscan", "bsc"), ("arbitrum", "arbitrum"), ("optimism", "optimism"),
        ("polygon", "polygon"), ("avalanche", "avalanche"),
        ("etherscan", "ethereum"), ("mainnet", "ethereum"),
    ):
        if key in blob:
            return val
    return "unknown"


def extract_commits(texts: list[str]) -> tuple[str, str, list[str]]:
    """Only record a commit when a 40-hex sits next to an explicit keyword."""
    vul = fix = ""
    shas: list[str] = []
    for text in texts:
        shas.extend(m.lower() for m in SHA40_RE.findall(text))
        for line in text.splitlines():
            low = line.lower()
            hexes = [m.lower() for m in SHA40_RE.findall(line)]
            if not hexes:
                continue
            if "vulnerable" in low or "vulnerability" in low or "before" in low:
                vul = vul or hexes[0]
            if "fixed" in low or "patch" in low or "after" in low or "mitigat" in low:
                fix = fix or hexes[-1]
    uniq = list(dict.fromkeys(shas))[:MAX_SHA_LIST]
    return vul, fix, uniq


def detect_c4_refs(dest: Path, hdir: Path, texts: list[str]) -> list[tuple[str, str]]:
    """Return (contest_slug, finding_id) pairs referenced by a harness.

    The contest slug comes from an `audits/<YYYY-MM-slug>` path or a
    `code-423n4/<slug>` URL in the evidence; finding ids come from finding
    file basenames (e.g. findings/H-02.md, patch/H-04.diff, test/H-02-*.ts).
    Returns [] when either side is absent, so no C4 key is fabricated.
    """
    slug = ""
    for part in hdir.relative_to(dest).parts:
        if re.fullmatch(r"20\d{2}-\d{2}-[a-z0-9][a-z0-9-]*", part):
            slug = part.lower()
            break
    if not slug:
        for text in texts:
            m = C4_SLUG_RE.search(text)
            if m:
                slug = m.group(1).lower()
                break
    if not slug:
        return []

    ids: set[str] = set()
    for root, dirs, files in os.walk(hdir):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in files:
            fm = C4_FINDING_FILE_RE.match(name)
            if fm:
                ids.add(f"{fm.group(1).upper()}-{int(fm.group(2)):02d}")
    return [(slug, fid) for fid in sorted(ids)]


def c4_registry_pairs(registry: dict[str, dict]) -> set[str]:
    """Normalized `(contest_slug, finding_id)` pairs already in the registry.

    The v1 layer stores C4 findings as `v1_finding:2024-04-NOYA/H-01` with a
    value of `2024-04-noya/H-01`; both forms normalize to `2024-04-noya/h-01`.
    """
    pairs: set[str] = set()
    for key, row in registry.items():
        if not key.startswith("v1_finding:"):
            continue
        for raw in (str(row.get("value") or ""), key[len("v1_finding:"):]):
            raw = raw.strip().lower()
            if "/" in raw:
                pairs.add(raw)
    return pairs


def parse_harness(dest: Path, hdir: Path, id_map: dict[str, dict],
                  head: str, counter: dict[str, int]) -> dict[str, Any]:
    """Parse one harness directory into a metadata-only candidate row."""
    rel = hdir.relative_to(dest).as_posix()
    files = evidence_files(hdir)
    texts = [_read_text(p, counter) for p in files]

    # Prefer the exploit fork_config.json's declared exploit tx + chain.
    data: dict | None = None
    primary = files[0] if files else None
    for p in files:
        if p.name == "fork_config.json":
            try:
                data = json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
                primary = p
                break
            except (ValueError, OSError):
                data = None

    tx = ""
    if isinstance(data, dict):
        for entry in (data.get("exploit_transactions") or []):
            if isinstance(entry, dict):
                cand = norm_tx(str(entry.get("tx_hash") or ""))
                if is_realistic_tx(cand):
                    tx = cand
                    break
    if not tx:
        for text in texts:
            for cand in ids_from_text(text)["tx"]:
                if is_realistic_tx(cand):
                    tx = cand
                    break
            if tx:
                break

    chain = infer_chain(texts, data)

    # Date + protocol: prefer the declared id_map tag, then the path, then text.
    ch_id = hdir.name if re.fullmatch(r"ch-\d{4}", hdir.name) else ""
    meta = id_map.get(ch_id, {}) if ch_id else {}
    month = str(meta.get("month") or "")
    protocol = str(meta.get("protocol") or "")
    if not month:
        m = PATH_DATE_RE.search(rel)
        if m:
            month = f"{m.group(1)}-{m.group(2)}"
    if not month:
        for text in texts:
            dm = DATE_RE.search(text)
            if dm:
                month = f"{dm.group(1)}-{dm.group(2)}"
                break
    if not protocol:
        toks = [t for t in re.split(r"[^A-Za-z0-9]+", rel) if t]
        for t in toks:
            if re.fullmatch(r"20\d{2}", t) or re.fullmatch(r"\d{2}", t):
                continue
            if t in _GENERIC_PROTOCOL_TOKENS:
                continue
            protocol = t
            break
    if not protocol:
        for text in texts:
            pm = PROTOCOL_RE.search(text)
            if pm:
                protocol = pm.group(1)
                break

    vul, fix, sha_list = extract_commits(texts)

    c4_refs = detect_c4_refs(dest, hdir, texts)
    c4_keys = [f"c4:{slug}:{fid.lower()}" for slug, fid in c4_refs]

    pnorm = norm_protocol(protocol)
    if tx:
        chain_norm = norm_protocol(chain) or "unknown"
        keys = [
            f"tx:{chain_norm}:{tx}",
            f"protocol_month:{pnorm}:{month}" if month else f"protocol:{pnorm}",
            f"reevmbench_harness:{rel}",
        ] + c4_keys
    else:
        keys = [f"reevmbench_harness:{rel}"] + c4_keys

    file_hash = sha256_file(primary) if primary and primary.exists() else ""
    return {
        "source": SOURCE,
        "candidate_id": f"reevmbench:{rel}",
        "tx_hash": tx,
        "chain": norm_protocol(chain) or "unknown",
        "protocol": protocol,
        "protocol_norm": pnorm,
        "incident_month": month,
        "harness_path": rel,
        "evidence_file": primary.relative_to(dest).as_posix() if primary else "",
        "pinned_commit": head,
        "file_sha256": file_hash,
        "vulnerable_commit": vul,
        "fixed_commit": fix,
        "sha40_candidates": sha_list,
        "dedup_keys": keys,
        "c4_refs": [[slug, fid] for slug, fid in c4_refs],
        "evidence_type": "observed_harness_fact",
        "retrieved_at": utc_now(),
        "decision": "PENDING",
        "reason": "",
    }


def existing_manifest_keys() -> set[tuple[Any, ...]]:
    seen: set[tuple[Any, ...]] = set()
    if OVERLAP.exists():
        try:
            for row in read_jsonl(OVERLAP):
                seen.add((row.get("source"), row.get("candidate_id"), row.get("key")))
        except Exception:  # pragma: no cover - defensive
            pass
    return seen


def write_outputs(candidates: list[dict], admitted: list[dict],
                  prove: list[dict], overlaps: list[dict]) -> dict[str, int]:
    written = {
        "candidates": write_jsonl(guard_wave1(CANDIDATES), candidates),
        "admitted": write_jsonl(guard_wave1(ADMITTED), admitted),
        "prove_incidents": write_jsonl(guard_wave1(PROVE), prove),
        "overlap_appended": append_jsonl(guard_wave1(OVERLAP), overlaps) if overlaps else 0,
    }
    return written


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    notes: list[str] = [
        "METADATA_ONLY: tx hash, chain, protocol, incident month, harness path, "
        "observed vulnerable/fixed commit, pinned clone HEAD, harness-file sha256; no prose vendored.",
        "prove_incidents is NOT_SCORABLE: rows contain no answer and no label field.",
        "Calendar cutoff removed: ALL parsed harnesses (2025-08..2026-02) are checked "
        "against the dedup registry regardless of incident date; admission is purely "
        "registry-key based.",
        "Dedup dimensions: tx (vs 514 registry v3_tx:* keys), protocol_month "
        "(vs the 9 V3.2-executed protocols) and C4 (contest_slug, finding_id) where a "
        "harness references one; no canonical file is read.",
    ]
    counter: dict[str, int] = {"files_scanned": 0}
    registry = load_registry()
    c4_pairs = c4_registry_pairs(registry)
    v3_tx_hashes = {
        k[len("v3_tx:"):].lower()
        for k, row in registry.items()
        if k.startswith("v3_tx:") and row.get("value")
    }
    v3_tx_hashes |= {
        str(row.get("value", "")).lower()
        for k, row in registry.items() if k.startswith("v3_tx:")
    }
    v3_tx_hashes.discard("")

    report: dict[str, Any] = {
        "built_at": utc_now(),
        "source": SOURCE,
        "clone_url": CLONE_URL,
        "clone_ok": False,
        "pinned_commit": "",
        "files_scanned": 0,
        "harnesses_found": 0,
        "parsed": 0,
        "tx_collisions": 0,
        "protocol_month_collisions": 0,
        "c4_collisions": 0,
        "unparseable": 0,
        "admitted": 0,
        "admitted_protocols": [],
        "prove_incidents_rows": 0,
        "overlap_rows_appended": 0,
        "notes": notes,
    }

    candidates: list[dict] = []
    admitted: list[dict] = []
    prove: list[dict] = []
    overlaps: list[dict] = []
    seen_manifest = existing_manifest_keys()

    dest, ok = ensure_clone(notes)
    report["clone_ok"] = ok
    if dest is None or not ok:
        notes.append("no clone data; all outputs written empty (no fabrication)")
        report.update(write_outputs(candidates, admitted, prove, overlaps))
        write_json(guard_wave1(REPORT), report)
        print(f"[reevmbench] clone failed; empty outputs written -> {REPORT}")
        return

    head = git_head(dest)
    report["pinned_commit"] = head
    notes.append(f"pinned clone HEAD={head or '<unavailable>'}")

    id_map = load_id_map(dest, counter)
    notes.append(f"id_map rows={len(id_map)} (declared incident dates/protocols)")

    def add_overlap(cand: dict, key: str, layer: Any, value: Any,
                    decision: str, reason: str) -> None:
        sig = (SOURCE, cand["candidate_id"], key)
        if sig in seen_manifest:
            return
        seen_manifest.add(sig)
        row = record_overlap(SOURCE, key, cand["candidate_id"],
                             {"layer": layer, "value": value})
        row["decision"] = decision
        row["reason"] = reason
        overlaps.append(row)
        cand.setdefault("overlap_keys", []).append(key)

    hdirs = harness_dirs(dest)
    report["harnesses_found"] = len(hdirs)

    for hdir in hdirs:
        try:
            cand = parse_harness(dest, hdir, id_map, head, counter)
        except Exception as exc:  # pragma: no cover - defensive per harness
            notes.append(f"parse failed for {hdir.name}: {str(exc)[:160]}")
            continue
        candidates.append(cand)

        tx = cand["tx_hash"]
        month = cand["incident_month"]
        pnorm = cand["protocol_norm"]

        if not tx or not month:
            cand["decision"] = "UNPARSEABLE"
            cand["reason"] = "missing_tx_or_date" if not tx else "missing_date"
            report["unparseable"] += 1
            continue
        report["parsed"] += 1

        # No calendar filter: date is metadata only, never an admission gate.

        # --- tx collision (primary) -------------------------------------
        tx_key = f"tx:{cand['chain']}:{tx}"
        checks = list(cand["dedup_keys"]) + [f"v3_tx:{tx}"]
        hits = check_keys(checks, registry)
        v3_hit = registry.get(f"v3_tx:{tx}")
        if tx in v3_tx_hashes or v3_hit or any(h.get("key") == f"v3_tx:{tx}" for h in hits):
            cand["decision"] = "DROPPED_TX_COLLISION"
            cand["reason"] = "tx_matches_v3_attack_tx"
            layer = (v3_hit or hits[0]).get("layer", "V3")
            value = (v3_hit or hits[0]).get("value", tx)
            add_overlap(cand, tx_key, layer, value, cand["decision"],
                        "tx_collision")
            report["tx_collisions"] += 1
            continue

        # --- protocol-month collision (secondary) ----------------------
        pm_key = f"protocol_month:{pnorm}:{month}"
        pm_hits = [h for h in hits if h.get("key") == pm_key]
        if pnorm in EXCLUDED_PROTOCOLS:
            cand["decision"] = "DROPPED_PROTOCOL_MONTH_COLLISION"
            cand["reason"] = "protocol_executed_in_v3_2"
            add_overlap(cand, pm_key, "V3.2_EXECUTION",
                        EXCLUDED_PROTOCOL_DISPLAY.get(pnorm, cand["protocol"]),
                        cand["decision"], "protocol_month_collision")
            report["protocol_month_collisions"] += 1
            continue
        if pm_hits:
            cand["decision"] = "DROPPED_PROTOCOL_MONTH_COLLISION"
            cand["reason"] = "protocol_month_in_registry"
            h = pm_hits[0]
            add_overlap(cand, pm_key, h.get("layer"), h.get("value"),
                        cand["decision"], "protocol_month_collision")
            report["protocol_month_collisions"] += 1
            continue

        # --- C4 (contest_slug, finding_id) collision (tertiary) ----------
        c4_hits = [ref for ref in cand.get("c4_refs", [])
                   if f"{ref[0].lower()}/{ref[1].lower()}" in c4_pairs]
        if c4_hits:
            slug, fid = c4_hits[0]
            cand["decision"] = "DROPPED_C4_KEY_COLLISION"
            cand["reason"] = "c4_contest_finding_in_registry"
            add_overlap(cand, f"c4:{slug}:{fid.lower()}", "V1_FINDING",
                        f"{slug}/{fid.lower()}", cand["decision"],
                        "c4_key_collision")
            report["c4_collisions"] += 1
            continue

        # --- net-new: admit ---------------------------------------------
        cand["decision"] = "ADMITTED"
        cand["reason"] = "net_new_registry_key_no_collision"
        admitted.append({
            "source": SOURCE,
            "candidate_id": cand["candidate_id"],
            "tx_hash": tx,
            "chain": cand["chain"],
            "protocol": cand["protocol"],
            "incident_month": month,
            "harness_path": cand["harness_path"],
            "pinned_commit": cand["pinned_commit"],
            "file_sha256": cand["file_sha256"],
            "vulnerable_commit": cand["vulnerable_commit"],
            "fixed_commit": cand["fixed_commit"],
            "evidence_type": cand["evidence_type"],
            "retrieved_at": cand["retrieved_at"],
            "dedup_keys": cand["dedup_keys"],
        })
        prove.append({
            "candidate_id": cand["candidate_id"],
            "tx_hash": tx,
            "chain": cand["chain"],
            "protocol": cand["protocol"],
            "incident_month": month,
            "harness_path": cand["harness_path"],
            "pinned_commit": cand["pinned_commit"],
            "source": SOURCE,
        })

    report["files_scanned"] = counter["files_scanned"]
    report["admitted"] = len(admitted)
    report["admitted_protocols"] = sorted({r["protocol"] for r in admitted})
    report["prove_incidents_rows"] = len(prove)

    written = write_outputs(candidates, admitted, prove, overlaps)
    report["overlap_rows_appended"] = written["overlap_appended"]

    months = Counter(c["incident_month"] for c in candidates if c["incident_month"])
    report["incident_months_observed"] = dict(sorted(months.items()))
    report["decisions"] = dict(sorted(Counter(c["decision"] for c in candidates).items()))
    if not admitted:
        notes.append(
            "No parsed harness survived registry-key dedup in this pinned HEAD; "
            "admitted=0 and prove_incidents_rows=0. This is an honest observation, "
            "not a suppressed or fabricated result."
        )
    report["notes"] = notes

    write_json(guard_wave1(REPORT), report)
    print(
        f"[reevmbench] clone={report['clone_ok']} files={report['files_scanned']} "
        f"harnesses={report['harnesses_found']} parsed={report['parsed']} "
        f"tx_collisions={report['tx_collisions']} "
        f"protocol_month_collisions={report['protocol_month_collisions']} "
        f"c4_collisions={report['c4_collisions']} "
        f"unparseable={report['unparseable']} "
        f"admitted={report['admitted']} prove={report['prove_incidents_rows']} "
        f"overlap_appended={report['overlap_rows_appended']}"
    )
    print(f"[reevmbench] decisions={report['decisions']}")
    print(f"[reevmbench] report -> {REPORT}")


if __name__ == "__main__":
    main()

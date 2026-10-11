"""Source harvesters for the V3 layer (build_v3.py group).

Split out mechanically from scripts/build_v3.py: every harvester
below is the exact code, dedented and unmodified. scripts/build_v3.py
keeps the HARVESTERS registry, scoring, writers and main(); behaviour
and build output are byte-identical.
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlun_v3 as V  # noqa: E402

U = V.UNKNOWN


def _head_line(text: str, prefix: str) -> str | None:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(prefix):
            return s[len(prefix):].strip()
    return None


def _section(text: str, header: str, max_chars: int = 4000) -> str:
    """Return the markdown section under `header` (## header), else ''."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().lower() == header.lower():
            start = i + 1
            break
    if start is None:
        return ""
    out: list[str] = []
    for line in lines[start:]:
        if line.startswith("## ") or line.startswith("# "):
            break
        out.append(line)
    return "\n".join(out).strip()[:max_chars]


def _has_code_block(text: str) -> bool:
    return "```" in text


# ---------------------------------------------------------------------------
# C4 contests (machine-readable data/*.json + report.md scope evidence)
# ---------------------------------------------------------------------------

def _parse_c4_report(report_path: Path) -> dict:
    info: dict = {"sponsor": U, "slug": U, "date": U, "contest": None,
                  "scope_repo": None, "scope_commit": None}
    if not report_path.exists():
        return info
    text = report_path.read_text(encoding="utf-8", errors="ignore")
    head = text[:1500]
    for key in ("sponsor", "slug", "date", "title", "contest", "findings"):
        m = re.search(rf'^{key}:\s*"?(.*?)"?\s*$', head, re.M)
        if m and m.group(1).strip():
            info[key] = m.group(1).strip()
    shas = V.SHA40_RE.findall(text)
    if shas:
        info["scope_commit"] = shas[0]
    repos = V.GITHUB_REPO_RE.findall(text)
    # Prefer a scope (audited protocol) repo over code-423n4 meta links.
    for repo in repos:
        if not repo.startswith("code-423n4/"):
            info["scope_repo"] = f"https://github.com/{repo}"
            break
    if info["scope_repo"] is None and repos:
        info["scope_repo"] = f"https://github.com/{repos[0]}"
    return info


def harvest_c4(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    sid = spec["source_id"]
    rep = _parse_c4_report(clone_dir / "report.md")
    project = rep.get("sponsor") or U
    if project == U:
        project = {"c4-renzo-findings": "Renzo", "c4-phi-findings": "Phi",
                   "c4-reserve-findings": "Reserve"}.get(sid, U)
    data_dir = clone_dir / "data"
    files = sorted(data_dir.glob("*.json")) if data_dir.exists() else []
    cands: list[dict] = []
    for path in files:
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        risk = str(row.get("risk", U))
        sev = V.C4_RISK_TO_SEVERITY.get(risk, U)
        title = str(row.get("title", U))[:500]
        issue_id = row.get("issueId")
        cid = f"{sid}:{issue_id}" if issue_id is not None else f"{sid}:{path.stem}"
        is_hm = risk in ("2", "3")
        poc = 0
        level = "L0"
        if is_hm:
            decision, reason = "IMPORT_AS_UNVERIFIED", \
                "judged-track submission (High/Medium risk) with title; no PoC text or scope commit in JSON -- L0"
            neg: dict = {"negative_class": None}
            spec3 = 2
        else:
            decision, reason = "RESEARCH_ONLY", \
                f"QA/Gas bulk submission (risk={risk}); low/non-critical with no judging evidence in JSON"
            neg = {"negative_class": None}
            spec3 = 1
        vuln_commit = rep.get("scope_commit") or U
        cands.append({
            "candidate_id": cid, "source_id": sid,
            "source_location": f"V3/clones/{spec['clone']}/data/{path.name}",
            "source_report_id": f"{sid}-report",
            "project": project, "protocol": project,
            "repository": rep.get("scope_repo") or U,
            "finding_title": title, "original_title": title,
            "severity_reported": f"risk {risk}" if risk != U else U,
            "severity_normalized": sev,
            "normalized_vulnerability_class": U,
            "original_vulnerability_class": U,
            "affected_file": U, "affected_lines": None,
            "language": "solidity", "language_evidence": "observed_fact: report.md states the audited system is written in Solidity",
            "ecosystem": "evm", "ecosystem_evidence": "observed_fact: Code4rena EVM contest (Solidity system)",
            "vulnerable_commit": vuln_commit if is_hm else U,
            "vulnerable_commit_confidence": "inferred" if (vuln_commit != U and is_hm) else U,
            "fixed_commit": U, "fixed_commit_confidence": U,
            "poc_available": False, "patch_available": False,
            "verification_level": level,
            "verification_status": "UNVERIFIED",
            "report_date": rep.get("date") or U,
            "license": U, "license_status": U,
            "tier": 2, "first_party": True, "judged": False,
            "warden": row.get("handle", U),
            "issue_url": row.get("issueUrl", U),
            "original_issue_url": row.get("originalIssueUrl", U),
            "contest": row.get("contest", rep.get("contest")),
            "decision": decision, "decision_reason": reason,
            "negative_class": neg["negative_class"],
            "_signals": {"tier": 2, "first_party": True, "judged": False,
                         "has_repo": rep.get("scope_repo") is not None,
                         "has_commit40": vuln_commit != U and is_hm,
                         "scope_evidence": True,
                         "specificity": spec3, "poc": poc, "patch": 0,
                         "multi_auditor": False, "non_evm": False,
                         "negative": 0},
            "_file_sha256": V.sha256_file(path),
            "_clone_head": head,
        })
    # Within-contest title duplicates: same title, different warden -> the
    # lowest issueId is canonical, the rest corroborate (never deleted).
    by_title: dict[str, list[dict]] = collections.defaultdict(list)
    for c in cands:
        if c["decision"] == "IMPORT_AS_UNVERIFIED":
            by_title[V.norm_title(c["finding_title"])].append(c)
    for group in by_title.values():
        if len(group) > 1:
            group.sort(key=lambda c: c["candidate_id"])
            canon = group[0]["candidate_id"]
            for dup in group[1:]:
                dup["decision"] = "CORROBORATION_ONLY"
                dup["decision_reason"] = f"same-contest duplicate title of {canon} (different warden); kept as corroboration"
                dup["duplicate_of"] = canon
                dup["_signals"]["negative"] = 1
    for c in cands:
        c.setdefault("duplicate_of", None)
    return cands


# ---------------------------------------------------------------------------
# Sherlock judging repos
# ---------------------------------------------------------------------------

def _parse_sherlock_md(text: str, fallback_sev: str = U) -> dict:
    title = U
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("# "):
            title = s[2:].strip()[:500]
            break
    sev = fallback_sev
    m = re.match(r"(?:Issue\s+)?([HML])-\d+\s*:\s*(.*)$", title, re.I)
    if m:
        sev = {"H": "High", "M": "Medium", "L": "Low"}.get(m.group(1).upper(), fallback_sev)
        title = m.group(2).strip()[:500] or title
    found_by = U
    fm = re.search(r"## Found by\s*\n(.+?)(?:\n## |\Z)", text, re.S)
    if fm:
        found_by = " ".join(fm.group(1).split())[:300]
    source_url = U
    sm = re.search(r"Source:\s*(https?://\S+)", text)
    if sm:
        source_url = sm.group(1).rstrip(")")
    poc_text = _section(text, "## Proof of Concept") or _section(text, "## PoC") or ""
    has_poc = len(poc_text) > 100
    return {"title": title, "severity": sev, "found_by": found_by,
            "source_url": source_url, "has_poc": has_poc,
            "has_code": _has_code_block(text)}


def harvest_sherlock(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    sid = spec["source_id"]
    project = {"sherlock-symmetrical": "Symmetrical",
               "sherlock-optimism": "Optimism"}.get(sid, U)
    cands: list[dict] = []
    sev_dirs = sorted([d for d in clone_dir.iterdir()
                       if d.is_dir() and re.fullmatch(r"\d+-[HML]", d.name)
                       and d.name not in (".git", ".data", ".github")])
    folder_best: dict[str, str] = {}
    for sev_dir in sev_dirs:
        sev = {"H": "High", "M": "Medium", "L": "Low"}[sev_dir.name.rsplit("-", 1)[1]]
        files = sorted([f for f in sev_dir.iterdir()
                        if f.is_file() and f.suffix == ".md"])
        best = [f for f in files if f.stem.endswith("-best")]
        best_name = best[0].name if best else None
        for path in files:
            text = path.read_text(encoding="utf-8", errors="ignore")
            par = _parse_sherlock_md(text, sev)
            is_best = best_name is not None and path.name == best_name
            if best_name is None:
                # No -best marker: keep the first file as canonical, rest dup.
                is_best = (path.name == files[0].name)
                dup_note = True
            else:
                dup_note = False
            cid = f"{sid}:{sev_dir.name}/{path.stem}"
            if is_best:
                decision = "IMPORT_AS_UNVERIFIED"
                reason = ("judged primary finding"
                          + (" (no -best marker; first file taken as canonical)" if dup_note else "")
                          + "; scope commit not vendored -- L0" + ("; PoC section present -- L1" if par["has_poc"] else ""))
                neg_class = None
                dup_of = None
                neg_sig = 0
            else:
                decision = "CORROBORATION_ONLY"
                reason = f"duplicate/corroborating submission in judged folder {sev_dir.name}"
                neg_class = None
                dup_of = f"{sid}:{sev_dir.name}/{best[0].stem}" if best else f"{sid}:{sev_dir.name}/{files[0].stem}"
                neg_sig = 1
            level = "L1" if (is_best and par["has_poc"]) else "L0"
            cands.append({
                "candidate_id": cid, "source_id": sid,
                "source_location": f"V3/clones/{spec['clone']}/{sev_dir.name}/{path.name}",
                "source_report_id": f"{sid}-{sev_dir.name}",
                "project": project, "protocol": project,
                "repository": U,
                "finding_title": par["title"], "original_title": par["title"],
                "severity_reported": sev, "severity_normalized": sev,
                "normalized_vulnerability_class": U,
                "original_vulnerability_class": U,
                "affected_file": U, "affected_lines": None,
                "language": "solidity", "language_evidence": "observed_fact: Sherlock Solidity contest finding with inline vulnerable code",
                "ecosystem": "evm", "ecosystem_evidence": "observed_fact: Sherlock EVM contest",
                "vulnerable_commit": U, "vulnerable_commit_confidence": U,
                "fixed_commit": U, "fixed_commit_confidence": U,
                "poc_available": bool(par["has_poc"]), "patch_available": False,
                "verification_level": level,
                "verification_status": "UNVERIFIED",
                "report_date": U, "license": U, "license_status": U,
                "tier": 2, "first_party": True, "judged": True,
                "warden": par["found_by"], "issue_url": par["source_url"],
                "original_issue_url": U, "contest": U,
                "decision": decision, "decision_reason": reason,
                "negative_class": neg_class, "duplicate_of": dup_of,
                "_signals": {"tier": 2, "first_party": True, "judged": True,
                             "has_repo": False, "has_commit40": False,
                             "scope_evidence": False, "specificity": 2,
                             "poc": 2 if par["has_poc"] else (1 if par["has_code"] else 0),
                             "patch": 0, "multi_auditor": False, "non_evm": False,
                             "negative": neg_sig},
                "_file_sha256": V.sha256_file(path),
                "_clone_head": head,
            })
        if best:
            folder_best[sev_dir.name] = f"{sid}:{sev_dir.name}/{best[0].stem}"
    # invalid/ folder: judged rejections -> hard negatives.
    invalid_dir = clone_dir / "invalid"
    if invalid_dir.exists():
        for path in sorted(invalid_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8", errors="ignore")
            par = _parse_sherlock_md(text)
            cid = f"{sid}:invalid/{path.stem}"
            cands.append({
                "candidate_id": cid, "source_id": sid,
                "source_location": f"V3/clones/{spec['clone']}/invalid/{path.name}",
                "source_report_id": f"{sid}-invalid",
                "project": project, "protocol": project,
                "repository": U,
                "finding_title": par["title"], "original_title": par["title"],
                "severity_reported": U, "severity_normalized": U,
                "normalized_vulnerability_class": U,
                "original_vulnerability_class": U,
                "affected_file": U, "affected_lines": None,
                "language": "solidity", "language_evidence": "reported_claim: filed as a Sherlock contest submission",
                "ecosystem": "evm", "ecosystem_evidence": "reported_claim: filed as a Sherlock EVM contest submission",
                "vulnerable_commit": U, "vulnerable_commit_confidence": U,
                "fixed_commit": U, "fixed_commit_confidence": U,
                "poc_available": bool(par["has_poc"]), "patch_available": False,
                "verification_level": "L0",
                "verification_status": "UNVERIFIED",
                "report_date": U, "license": U, "license_status": U,
                "tier": 2, "first_party": True, "judged": True,
                "warden": par["found_by"], "issue_url": par["source_url"],
                "original_issue_url": U, "contest": U,
                "decision": "IMPORT_AS_NEGATIVE",
                "decision_reason": "judge-placed in invalid/ folder; rejection rationale lives in judging comments, not vendored",
                "negative_class": "externally_rejected", "duplicate_of": None,
                "_signals": {"tier": 2, "first_party": True, "judged": True,
                             "has_repo": False, "has_commit40": False,
                             "scope_evidence": False, "specificity": 2,
                             "poc": 0, "patch": 0, "multi_auditor": False,
                             "non_evm": False, "negative": 2},
                "_file_sha256": V.sha256_file(path),
                "_clone_head": head,
            })
    # Top-level README when it carries a judged issue (symmetrical pattern).
    readme = clone_dir / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8", errors="ignore")
        if text.lstrip().startswith("# Issue"):
            par = _parse_sherlock_md(text)
            cid = f"{sid}:README"
            cands.append({
                "candidate_id": cid, "source_id": sid,
                "source_location": f"V3/clones/{spec['clone']}/README.md",
                "source_report_id": f"{sid}-readme",
                "project": project, "protocol": project,
                "repository": U,
                "finding_title": par["title"], "original_title": par["title"],
                "severity_reported": par["severity"], "severity_normalized": par["severity"],
                "normalized_vulnerability_class": U,
                "original_vulnerability_class": U,
                "affected_file": U, "affected_lines": None,
                "language": "solidity", "language_evidence": "observed_fact: judged Sherlock finding with inline vulnerable code",
                "ecosystem": "evm", "ecosystem_evidence": "observed_fact: Sherlock EVM contest",
                "vulnerable_commit": U, "vulnerable_commit_confidence": U,
                "fixed_commit": U, "fixed_commit_confidence": U,
                "poc_available": bool(par["has_poc"]), "patch_available": False,
                "verification_level": "L1" if par["has_poc"] else "L0",
                "verification_status": "UNVERIFIED",
                "report_date": U, "license": U, "license_status": U,
                "tier": 2, "first_party": True, "judged": True,
                "warden": par["found_by"], "issue_url": par["source_url"],
                "original_issue_url": U, "contest": U,
                "decision": "IMPORT_AS_UNVERIFIED",
                "decision_reason": "top-level judged issue write-up; scope commit not vendored",
                "negative_class": None, "duplicate_of": None,
                "_sic_signals": None,
                "_signals": {"tier": 2, "first_party": True, "judged": True,
                             "has_repo": False, "has_commit40": False,
                             "scope_evidence": False, "specificity": 2,
                             "poc": 2 if par["has_poc"] else 0,
                             "patch": 0, "multi_auditor": False, "non_evm": False,
                             "negative": 0},
                "_file_sha256": V.sha256_file(readme),
                "_clone_head": head,
            })
    # Top-level raw submissions (*.md excluding README): unjudged, kept as
    # RESEARCH_ONLY so nothing is silently dropped. Many are off-topic spam;
    # without judging evidence no rejection claim is made.
    for path in sorted(clone_dir.glob("*.md")):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        par = _parse_sherlock_md(text)
        title = par["title"] if par["title"] != U else path.stem
        cands.append({
            "candidate_id": f"{sid}:raw/{path.stem}", "source_id": sid,
            "source_location": f"V3/clones/{spec['clone']}/{path.name}",
            "source_report_id": f"{sid}-raw",
            "project": project, "protocol": project,
            "repository": U,
            "finding_title": title[:500], "original_title": title[:500],
            "severity_reported": U, "severity_normalized": U,
            "normalized_vulnerability_class": U,
            "original_vulnerability_class": U,
            "affected_file": U, "affected_lines": None,
            "language": "solidity", "language_evidence": "reported_claim: filed as a contest submission; content not verified",
            "ecosystem": "evm", "ecosystem_evidence": "reported_claim: filed as a contest submission; content not verified",
            "vulnerable_commit": U, "vulnerable_commit_confidence": U,
            "fixed_commit": U, "fixed_commit_confidence": U,
            "poc_available": False, "patch_available": False,
            "verification_level": "L0",
            "verification_status": "UNVERIFIED",
            "report_date": U, "license": U, "license_status": U,
            "tier": 2, "first_party": True, "judged": False,
            "warden": par["found_by"], "issue_url": U,
            "original_issue_url": U, "contest": U,
            "decision": "RESEARCH_ONLY",
            "decision_reason": "raw unjudged submission (not referenced by any judged folder); no validity claim made",
            "negative_class": None, "duplicate_of": None,
            "_signals": {"tier": 2, "first_party": True, "judged": False,
                         "has_repo": False, "has_commit40": False,
                         "scope_evidence": False, "specificity": 1,
                         "poc": 0, "patch": 0, "multi_auditor": False,
                         "non_evm": False, "negative": 0},
            "_file_sha256": V.sha256_file(path),
            "_clone_head": head,
        })
    # Audit_Report.pdf: report-level pointer (per-finding parsing needs PDF work).
    audit_pdf = clone_dir / "Audit_Report.pdf"
    if audit_pdf.exists():
        cands.append(_report_pointer(spec, audit_pdf, head, project=project,
                                     tier=2, first_party=True,
                                     note="final Sherlock audit report PDF; per-finding rows above carry the judged content"))
    return cands


# ---------------------------------------------------------------------------
# Generic report-level pointer (PDF/MD archives without per-finding parsing)
# ---------------------------------------------------------------------------

def _report_pointer(spec: dict, path: Path, head: str, project: str = U,
                    language: str = U, lang_ev: str = "",
                    ecosystem: str = U, eco_ev: str = "",
                    tier: int = 1, first_party: bool = True,
                    report_date: str = U, extra: dict | None = None,
                    note: str = "") -> dict:
    p = Path(path)
    if not p.exists() and not p.is_absolute():
        p = V.CLONES / spec["clone"] / p
    path = p
    try:
        rel = f"V3/clones/{spec['clone']}/{path.relative_to(V.CLONES / spec['clone']).as_posix()}"
    except ValueError:
        rel = f"V3/clones/{spec['clone']}/{path.name}"
    stem = path.stem
    if report_date == U:
        m = V.DATE_RE.search(stem) or V.DATE_RE.search(path.parent.name)
        if m:
            report_date = m.group(0)
    cid = f"{spec['source_id']}:{path.parent.name}/{stem}" if path.parent.name not in (".", spec["clone"]) else f"{spec['source_id']}:{stem}"
    row: dict = {
        "candidate_id": cid, "source_id": spec["source_id"],
        "source_location": rel,
        "source_report_id": stem,
        "project": project, "protocol": project,
        "repository": U,
        "finding_title": f"Report-level pointer: {stem}",
        "original_title": stem,
        "severity_reported": U, "severity_normalized": U,
        "normalized_vulnerability_class": U,
        "original_vulnerability_class": U,
        "affected_file": U, "affected_lines": None,
        "language": language,
        "language_evidence": lang_ev or "unknown: per-finding language not extracted (PDF parsing queued)",
        "ecosystem": ecosystem,
        "ecosystem_evidence": eco_ev or "unknown: per-finding ecosystem not extracted (PDF parsing queued)",
        "vulnerable_commit": U, "vulnerable_commit_confidence": U,
        "fixed_commit": U, "fixed_commit_confidence": U,
        "poc_available": False, "patch_available": False,
        "verification_level": "L0",
        "verification_status": "UNVERIFIED",
        "report_date": report_date, "license": U, "license_status": U,
        "tier": tier, "first_party": first_party, "judged": False,
        "warden": U, "issue_url": U, "original_issue_url": U, "contest": None,
        "decision": "RESEARCH_ONLY",
        "decision_reason": ("report-level pointer only; no per-finding title/severity extracted. "
                            "PDF/MD parsing is queued work, not done here. " + note).strip(),
        "negative_class": None, "duplicate_of": None,
        "_signals": {"tier": tier, "first_party": first_party, "judged": False,
                     "has_repo": False, "has_commit40": False,
                     "scope_evidence": False, "specificity": 0, "poc": 0,
                     "patch": 0, "multi_auditor": False,
                     "non_evm": (ecosystem not in ("evm", U)),
                     "negative": 0},
        "_file_sha256": V.sha256_file(path),
        "_file_bytes": path.stat().st_size,
        "_clone_head": head,
    }
    if extra:
        row.update(extra)
    return row


def _md_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("|") and "---" not in s:
            cells = [c.strip() for c in s.strip("|").split("|")]
            rows.append(cells)
    return rows


# ---------------------------------------------------------------------------
# Pashov (structured markdown: review hashes + [S-NN] findings)
# ---------------------------------------------------------------------------

PASHOV_SEV = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low"}
PASHOV_FINDING_RE = re.compile(r"^# \[([CHML])-(\d+[A-Za-z]?)\]\s*(.+)$", re.M)


def harvest_pashov(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    sid = spec["source_id"]
    md_files: list[Path] = []
    for sub in ("team", "solo", "agentic"):
        d = clone_dir / sub
        if d.exists():
            md_files.extend(sorted((d).rglob("*.md")))
    # Keep report markdown (md/ subdirs hold the reports; READMEs excluded).
    md_files = [f for f in md_files if "/md/" in f.as_posix().replace("\\", "/")]
    cands: list[dict] = []
    for path in md_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        review_hashes = re.findall(
            r"_review commit hashes_:(.*?)(?:_fixes review|### Scope|# Findings|\Z)",
            text, re.S | re.I)
        fix_hashes = re.findall(
            r"_fixes review commit hashes_:(.*?)(?:### Scope|# Findings|\Z)",
            text, re.S | re.I)
        review40 = list(dict.fromkeys(V.SHA40_RE.findall(review_hashes[0]))) if review_hashes else []
        fix40 = list(dict.fromkeys(V.SHA40_RE.findall(fix_hashes[0]))) if fix_hashes else []
        repo_urls = [f"https://github.com/{r}" for r in
                     dict.fromkeys(V.GITHUB_REPO_RE.findall(text))]
        repo_urls = [u for u in repo_urls if "pashov/audits" not in u]
        repo = repo_urls[0] if repo_urls else U
        project = path.stem.replace("-security-review", "").replace("_", " ").strip() or U
        findings = PASHOV_FINDING_RE.findall(text)
        rel = f"V3/clones/{spec['clone']}/{path.relative_to(clone_dir).as_posix()}"
        fsha = V.sha256_file(path)
        mdate = V.DATE_RE.search(path.stem)
        rdate = mdate.group(0) if mdate else U
        multi = project.lower() in V.MULTI_AUDITOR_PROJECTS
        if not findings:
            cands.append(_report_pointer(
                spec, path.relative_to(V.CLONES / spec["clone"]), head,
                project=project, language="solidity",
                lang_ev="reported_claim: Pashov EVM (Solidity) audit practice; verify per report",
                ecosystem="evm", eco_ev="reported_claim: Pashov EVM audit practice",
                report_date=rdate,
                note="no [S-NN] finding headers matched this file.",
                extra={"repository": repo,
                       "vulnerable_commit": review40[0] if review40 else U,
                       "vulnerable_commit_confidence": "strong" if review40 else U,
                       "fixed_commit": fix40[0] if fix40 else U,
                       "fixed_commit_confidence": "strong" if fix40 else U}))
            continue
        for letter, num, title in findings:
            sev = PASHOV_SEV[letter]
            sub = path.relative_to(clone_dir).parts[0]
            cid = f"{sid}:{sub}/{path.stem}:[{letter}-{num}]"
            vuln = review40[0] if review40 else U
            fix = fix40[0] if fix40 else U
            cands.append({
                "candidate_id": cid, "source_id": sid,
                "source_location": rel,
                "source_report_id": path.stem,
                "project": project, "protocol": project,
                "repository": repo,
                "finding_title": title.strip()[:500], "original_title": f"[{letter}-{num}] {title.strip()[:500]}",
                "severity_reported": sev, "severity_normalized": sev,
                "normalized_vulnerability_class": U,
                "original_vulnerability_class": U,
                "affected_file": U, "affected_lines": None,
                "language": "solidity",
                "language_evidence": "reported_claim: Pashov EVM (Solidity) audit practice; verify per report",
                "ecosystem": "evm",
                "ecosystem_evidence": "reported_claim: Pashov EVM audit practice",
                "vulnerable_commit": vuln,
                "vulnerable_commit_confidence": "strong" if vuln != U else U,
                "commit_note": f"review_hashes={review40}; fix_review_hashes={fix40}; repo_links={repo_urls[:4]}",
                "fixed_commit": fix,
                "fixed_commit_confidence": "strong" if fix != U else U,
                "poc_available": False, "patch_available": fix != U,
                "verification_level": "L0",
                "verification_status": "UNVERIFIED",
                "report_date": rdate, "license": U, "license_status": U,
                "tier": 1, "first_party": True, "judged": False,
                "warden": U, "issue_url": U, "original_issue_url": U,
                "contest": None,
                "decision": "IMPORT",
                "decision_reason": "professional audit finding with exact review commit(s), severity and title; fix-review commit recorded where present",
                "negative_class": None, "duplicate_of": None,
                "_signals": {"tier": 1, "first_party": True, "judged": False,
                             "has_repo": repo != U, "has_commit40": vuln != U,
                             "scope_evidence": True, "specificity": 2, "poc": 0,
                             "patch": 2 if fix != U else 0,
                             "multi_auditor": multi, "non_evm": False,
                             "negative": 0},
                "_file_sha256": fsha,
                "_clone_head": head,
            })
    return cands


# ---------------------------------------------------------------------------
# SmartBugs Curated (Tier 4 -- taxonomy reference only)
# ---------------------------------------------------------------------------

def harvest_smartbugs(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    sid = spec["source_id"]
    vuln_path = clone_dir / "vulnerabilities.json"
    data = json.loads(vuln_path.read_text(encoding="utf-8"))
    cands: list[dict] = []
    for contract in data:
        name = contract.get("name", U)
        cpath = contract.get("path", U)
        pragma = contract.get("pragma", U)
        origin = contract.get("source", U)
        for v in contract.get("vulnerabilities", []):
            cat = str(v.get("category", U))
            lines = v.get("lines", [])
            norm = V.DASP_TO_VLUN.get(cat, "Other" if cat != U else U)
            cid = f"{sid}:{name}:{cat}:{','.join(map(str, lines)) or 'nolines'}"
            sol_rel = f"V3/clones/{spec['clone']}/{cpath}"
            cands.append({
                "candidate_id": cid, "source_id": sid,
                "source_location": sol_rel,
                "source_report_id": name,
                "project": "smartbugs-curated", "protocol": "smartbugs-curated",
                "repository": "https://github.com/smartbugs/smartbugs-curated",
                "finding_title": f"{cat} in {name} (lines {lines})",
                "original_title": f"{cat} in {name}",
                "severity_reported": U, "severity_normalized": U,
                "normalized_vulnerability_class": norm,
                "original_vulnerability_class": cat,
                "affected_file": cpath, "affected_lines": lines,
                "language": "solidity", "language_evidence": "observed_fact: vendored .sol contract",
                "ecosystem": "evm", "ecosystem_evidence": "observed_fact: SmartBugs EVM dataset contract",
                "vulnerable_commit": U, "vulnerable_commit_confidence": U,
                "fixed_commit": U, "fixed_commit_confidence": U,
                "poc_available": False, "patch_available": False,
                "verification_level": "L0",
                "verification_status": "UNVERIFIED",
                "report_date": U, "license": U, "license_status": U,
                "tier": 4, "first_party": False, "judged": False,
                "warden": U, "issue_url": U, "original_issue_url": origin,
                "contest": None,
                "origin_dataset": "smartbugs_curated",
                "solidity_pragma": pragma,
                "decision": "RESEARCH_ONLY",
                "decision_reason": "Tier-4 curated benchmark label: taxonomy/overlap reference only, never ground truth",
                "negative_class": None, "duplicate_of": None,
                "_signals": {"tier": 4, "first_party": False, "judged": False,
                             "has_repo": True, "has_commit40": False,
                             "scope_evidence": False, "specificity": 3, "poc": 0,
                             "patch": 0, "multi_auditor": False, "non_evm": False,
                             "negative": 0},
                "_file_sha256": V.sha256_file(vuln_path),
                "_clone_head": head,
            })
    return cands


# ---------------------------------------------------------------------------
# DeFiHackLabs (executable Foundry PoCs -- L1, never executed here)
# ---------------------------------------------------------------------------

KEYINFO_RES = {
    "total_lost": re.compile(r"@KeyInfo\s*-\s*Total Lost\s*:\s*(.+)", re.I),
    "attacker": re.compile(r"Attacker\s*:\s*(https?://\S+)", re.I),
    "attack_contract": re.compile(r"Attack Contract\s*:\s*(https?://\S+)", re.I),
    "vulnerable_contract": re.compile(r"Vulnerable Contract\s*:\s*(https?://\S+)", re.I),
    "attack_tx": re.compile(r"Attack Tx\s*:\s*(https?://\S+)", re.I),
    "postmortem": re.compile(r"Post-?mortem\s*:\s*(https?://\S+)", re.I),
}
FORK_RE = re.compile(r'createSelectFork\(\s*"([A-Za-z0-9_-]+)"')


def harvest_defihacklabs(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    sid = spec["source_id"]
    files = sorted((clone_dir / "src").rglob("*_exp.sol"))
    files += sorted((clone_dir / "past").rglob("*_exp.sol"))
    files = sorted(set(files))
    cands: list[dict] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        stem = path.stem
        proj = stem[:-4] if stem.endswith("_exp") else stem
        proj = proj.split("_")[0] if "_" in proj else proj
        try:
            dater = path.relative_to(clone_dir).parent.as_posix()
        except ValueError:
            dater = "nodate"
        cid = f"{sid}:{dater}/{stem}"
        keyinfo: dict[str, str] = {}
        for k, rx in KEYINFO_RES.items():
            m = rx.search(text)
            keyinfo[k] = m.group(1).strip() if m else U
        fork = FORK_RE.search(text)
        chain = fork.group(1) if fork else U
        has_test = ("function test" in text or "function testExploit" in text
                    or "function testPoC" in text)
        level = "L1" if has_test else "L0"
        cands.append({
            "candidate_id": cid, "source_id": sid,
            "source_location": f"V3/clones/{spec['clone']}/{path.relative_to(clone_dir).as_posix()}",
            "source_report_id": stem,
            "project": proj or U, "protocol": proj or U,
            "project_note": "filename heuristic: first segment of PoC filename; verify against KeyInfo before use",
            "repository": U,
            "finding_title": f"Incident reproduction PoC: {stem}",
            "original_title": stem,
            "severity_reported": U, "severity_normalized": U,
            "normalized_vulnerability_class": U,
            "original_vulnerability_class": U,
            "affected_file": U, "affected_lines": None,
            "language": "solidity", "language_evidence": "observed_fact: Foundry .sol exploit test",
            "ecosystem": "evm", "ecosystem_evidence": f"observed_fact: Foundry exploit PoC (fork chain: {chain})",
            "fork_chain": chain,
            "vulnerable_commit": U, "vulnerable_commit_confidence": U,
            "fixed_commit": U, "fixed_commit_confidence": U,
            "poc_available": True,
            "poc_entrypoint": "testExploit/testPoC (verify per file)" if has_test else U,
            "patch_available": False,
            "verification_level": level,
            "verification_status": "UNVERIFIED",
            "keyinfo_total_lost_reported": keyinfo["total_lost"],
            "keyinfo_attacker": keyinfo["attacker"],
            "keyinfo_attack_contract": keyinfo["attack_contract"],
            "keyinfo_vulnerable_contract": keyinfo["vulnerable_contract"],
            "keyinfo_attack_tx": keyinfo["attack_tx"],
            "keyinfo_postmortem": keyinfo["postmortem"],
            "report_date": (V.DATE_RE.search(path.as_posix()).group(0)
                            if V.DATE_RE.search(path.as_posix()) else U),
            "license": U, "license_status": U,
            "tier": 0, "first_party": False, "judged": False,
            "warden": U, "issue_url": U, "original_issue_url": U,
            "contest": None,
            "decision": "IMPORT_AS_UNVERIFIED",
            "decision_reason": "third-party incident reproduction with executable Foundry PoC (L1 published PoC; not executed in this pass)",
            "negative_class": None, "duplicate_of": None,
            "_signals": {"tier": 0, "first_party": False, "judged": False,
                         "has_repo": False, "has_commit40": False,
                         "scope_evidence": False, "specificity": 1, "poc": 3,
                         "patch": 0, "multi_auditor": False, "non_evm": False,
                         "negative": 0},
            "_file_sha256": V.sha256_file(path),
            "_clone_head": head,
        })
    # Same PoC vendored twice (src/ + past/ mirrors): keep first, link rest.
    by_sha: dict[str, list[dict]] = collections.defaultdict(list)
    for c in cands:
        by_sha[c["_file_sha256"]].append(c)
    for group in by_sha.values():
        if len(group) > 1:
            group.sort(key=lambda c: c["candidate_id"])
            canon = group[0]["candidate_id"]
            for dup in group[1:]:
                dup["decision"] = "CORROBORATION_ONLY"
                dup["decision_reason"] = f"byte-identical PoC vendored twice in source (mirror of {canon})"
                dup["duplicate_of"] = canon
                dup["_signals"]["negative"] = 1
    for c in cands:
        c.setdefault("duplicate_of", None)
    return cands


# ---------------------------------------------------------------------------
# README-table PDF archives (report-level pointers with honest per-row fields)
# ---------------------------------------------------------------------------

def harvest_zellic(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    readme = clone_dir / "README.md"
    rows = _md_table_rows(readme.read_text(encoding="utf-8", errors="ignore")) if readme.exists() else []
    # Header: Product | Date | Network | Report
    cands: list[dict] = []
    seen: set[str] = set()
    for cells in rows:
        if len(cells) < 4 or cells[0].lower().startswith("product"):
            continue
        product, date, network = cells[0].strip(), cells[1].strip(), cells[2].strip().lower()
        pdf_name = U
        link_m = re.search(r"\./([^)]+)", cells[3])
        if link_m:
            pdf_name = unquote(link_m.group(1)).strip()
        lang, eco = V.ZELLIC_NETWORK_MAP.get(network, (U, U))
        lang_ev = f"observed_fact: Zellic README Network column = '{network}'" if lang != U else U
        eco_ev = f"observed_fact: Zellic README Network column = '{network}'" if eco != U else U
        path = clone_dir / pdf_name if pdf_name != U else None
        if path is None or not path.exists():
            # Fall back: match by product prefix among PDFs.
            matches = sorted(clone_dir.glob(f"{product[:12]}*.pdf"))
            path = matches[0] if matches else None
        if path is None or not path.exists():
            cands.append(_report_pointer(
                spec, readme, head,
                project=product, language=lang,
                lang_ev=lang_ev if isinstance(lang_ev, str) else U,
                ecosystem=eco, eco_ev=eco_ev if isinstance(eco_ev, str) else U,
                report_date=date or U,
                note=f"README row without vendored PDF (expected file '{pdf_name}')."))
            continue
        seen.add(path.name)
        cands.append(_report_pointer(
            spec, path, head,
            project=product, language=lang,
            lang_ev=lang_ev if isinstance(lang_ev, str) else U,
            ecosystem=eco, eco_ev=eco_ev if isinstance(eco_ev, str) else U,
            report_date=date or U,
            note="Zellic README table row; per-finding extraction needs PDF parsing."))
    # PDFs with no README row: still pointer them (nothing silently dropped).
    for pdf in sorted(clone_dir.glob("*.pdf")):
        if pdf.name not in seen:
            cands.append(_report_pointer(
                spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
                note="vendored PDF with no parsed README row."))
    return cands


def harvest_certora(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    readme = clone_dir / "README.md"
    rows = _md_table_rows(readme.read_text(encoding="utf-8", errors="ignore")) if readme.exists() else []
    cands: list[dict] = []
    linked: set[str] = set()
    for cells in rows:
        if len(cells) < 7 or "protocol" in cells[0].lower():
            continue
        protocol, date, project, platform = (cells[0].strip(), cells[1].strip(),
                                            cells[2].strip(), cells[3].strip().lower())
        pdf_rel = None
        for cell in cells:
            m = re.search(r"Reports/([^)]+\.pdf)", cell)
            if m:
                pdf_rel = "Reports/" + unquote(m.group(1)).strip()
                break
        lang, eco = V.CERTORA_PLATFORM_MAP.get(platform, (U, U))
        path = clone_dir / pdf_rel if pdf_rel else None
        if path is None or not path.exists():
            continue
        linked.add(path.name)
        proj = project or protocol or U
        cands.append(_report_pointer(
            spec, path.relative_to(V.CLONES / spec["clone"]), head,
            project=proj, language=lang,
            lang_ev=f"observed_fact: Certora README Platform column = '{platform}'" if lang != U else U,
            ecosystem=eco,
            eco_ev=f"observed_fact: Certora README Platform column = '{platform}'" if eco != U else U,
            report_date=date or U,
            note="Certora README portfolio row (FV+Audit flags in source table); per-finding extraction needs PDF parsing."))
    for pdf in sorted((clone_dir / "Reports").rglob("*.pdf")):
        if pdf.name not in linked:
            cands.append(_report_pointer(
                spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
                note="vendored PDF with no parsed README row."))
    return cands


def harvest_cyba(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    readme = clone_dir / "README.md"
    text = readme.read_text(encoding="utf-8", errors="ignore") if readme.exists() else ""
    rows = _md_table_rows(text)
    cands: list[dict] = []
    linked: set[str] = set()
    for cells in rows:
        if len(cells) < 5 or cells[0].strip("` ").lower().startswith("date"):
            continue
        date, client = cells[0].strip("` "), cells[1].strip()
        audit_name = re.sub(r"\[|\]|\(.*?\)", "", cells[2]).strip()
        tech = cells[3]
        badge = re.search(r"EVM-Solidity|Stacks-Clarity", tech)
        if badge:
            lang, eco = (("solidity", "evm") if "EVM" in badge.group(0)
                         else ("clarity", "stacks"))
        else:
            lang, eco = U, U
        link_m = re.search(r"reports/([^)]+\.pdf)", cells[4])
        path = clone_dir / "reports" / link_m.group(1) if link_m else None
        if path is None or not path.exists():
            continue
        linked.add(path.name)
        proj = client or audit_name or U
        cands.append(_report_pointer(
            spec, path.relative_to(V.CLONES / spec["clone"]), head,
            project=proj, language=lang,
            lang_ev="observed_fact: Cyba README Ecosystem & Tech badge" if lang != U else U,
            ecosystem=eco,
            eco_ev="observed_fact: Cyba README Ecosystem & Tech badge" if eco != U else U,
            report_date=date or U,
            note=f"Cyba engagement '{audit_name}'. Granite rows belong to the 5-auditor confirmation set (see V3/02_source_dossiers.md)."))
    for pdf in sorted((clone_dir / "reports").glob("*.pdf")):
        if pdf.name not in linked:
            cands.append(_report_pointer(
                spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
                note="vendored PDF with no parsed README row."))
    return cands


def harvest_sigmaprime(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    readme = clone_dir / "README.md"
    text = readme.read_text(encoding="utf-8", errors="ignore") if readme.exists() else ""
    rows = _md_table_rows(text)
    cands: list[dict] = []
    linked: set[str] = set()
    for cells in rows:
        if len(cells) < 5 or cells[0].strip().lower().startswith("project"):
            continue
        project = re.sub(r"\[|\]|\(.*?\)", "", cells[0]).strip() or U
        date, target = cells[1].strip(), cells[2].strip()
        commit = U
        cm = V.SHA40_RE.search(target)
        if cm:
            commit = cm.group(0)
        else:
            sm = re.search(r"\b[0-9a-f]{7,40}\b", target)
            if sm:
                commit = sm.group(0)
        link_m = re.search(r"\./(reports/[^)]+?)(?:\.pdf)?\)", cells[4])
        raw = unquote(link_m.group(1)).strip() if link_m else None
        path = clone_dir / raw if raw else None
        if path is not None and path.is_dir():
            # Directory pointer: use its README/review entry file when present.
            for cand in ("README.md", "review.md", "review.pdf"):
                if (path / cand).exists():
                    path = path / cand
                    break
        if path is not None and path.suffix == "" and (clone_dir / (raw + ".pdf")).exists():
            path = clone_dir / (raw + ".pdf")
        if path is None or not path.exists() or not path.is_file():
            continue
        linked.add(path.relative_to(clone_dir).as_posix())
        extra = {}
        if commit != U:
            extra = {"vulnerable_commit": commit,
                     "vulnerable_commit_confidence": "exact" if len(commit) == 40 else "strong",
                     "commit_note": f"audit target commit from Sigma Prime README table: '{target[:200]}'",
                     "repository": (V.GITHUB_REPO_RE.search(target).group(0)
                                    if V.GITHUB_REPO_RE.search(target) else U)}
            sig = {"has_commit40": len(commit) == 40, "has_repo": extra["repository"] != U}
        else:
            sig = {}
        row = _report_pointer(
            spec, path.relative_to(V.CLONES / spec["clone"]), head,
            project=project, report_date=date or U,
            note="Sigma Prime review table row; target commit is the audit scope revision, not a per-finding vulnerable revision.",
            extra=extra)
        if sig:
            row["_signals"].update(sig)
            if sig.get("has_commit40") or sig.get("has_repo"):
                row["_signals"]["scope_evidence"] = True
        cands.append(row)
    for pdf in sorted((clone_dir / "reports").rglob("*.pdf")):
        if pdf.relative_to(clone_dir).as_posix() not in linked:
            cands.append(_report_pointer(
                spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
                project=pdf.parent.name,
                note="vendored PDF with no parsed README row."))
    return cands


def harvest_anza(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    cands: list[dict] = []
    for pdf in sorted(clone_dir.rglob("*.pdf")):
        if ".git/" in pdf.as_posix():
            continue
        try:
            prog = pdf.relative_to(clone_dir).parts[0]
        except ValueError:
            prog = U
        cands.append(_report_pointer(
            spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
            project=prog, language="rust",
            lang_ev="reported_claim: Anza aggregator hosts Solana (Rust) core-program audits",
            ecosystem="solana",
            eco_ev="reported_claim: Anza aggregator hosts Solana core-program audits",
            tier=1, first_party=False,
            note="mirror_of the auditor original (Halborn/OtterSec/Neodyme/Zellic/ToB/NCC/Certora/LeastAuthority/ZKSecurity/Qedit/Asymmetric/Code4rena); canonical source is the auditor report."))
    return cands


def harvest_flat_pdfs(spec: dict, clone_dir: Path, head: str, sub: str = ".",
                      project_from: str = "filename") -> list[dict]:
    base = clone_dir if sub == "." else clone_dir / sub
    cands: list[dict] = []
    if not base.exists():
        return cands
    for pdf in sorted(base.glob("*.pdf")):
        nm = re.match(r"^(NM-?\d+)[-_ ]?(.*)$", pdf.stem, re.I)
        proj = (nm.group(2).strip() or U) if nm and project_from == "filename" else pdf.stem
        cands.append(_report_pointer(
            spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
            project=proj,
            note="flat PDF archive; per-finding extraction needs PDF parsing."))
    return cands


def harvest_ackee(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    cands: list[dict] = []
    for pdf in sorted(clone_dir.rglob("*.pdf")):
        if ".git/" in pdf.as_posix():
            continue
        parts = pdf.relative_to(clone_dir).parts
        year = parts[0] if parts and re.fullmatch(r"20\d\d", parts[0]) else U
        cands.append(_report_pointer(
            spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
            project=pdf.stem, language="solidity",
            lang_ev="reported_claim: Ackee EVM audit practice; verify per report (Solana possible)",
            ecosystem="evm",
            eco_ev="reported_claim: Ackee EVM audit practice",
            report_date=year if year != U else U,
            note="year-directory layout; report year taken from directory name."))
    return cands


def harvest_abdk(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    cands: list[dict] = []
    for pdf in sorted(clone_dir.rglob("*.pdf")):
        if ".git/" in pdf.as_posix():
            continue
        parts = pdf.relative_to(clone_dir).parts
        client = parts[0] if len(parts) > 1 else U
        cands.append(_report_pointer(
            spec, pdf.relative_to(V.CLONES / spec["clone"]), head,
            project=client if client not in (".", U) else pdf.stem,
            note="per-client directory layout; crypto+circuit depth back to 2017 (see dossiers)."))
    return cands


def harvest_informal(spec: dict, clone_dir: Path, head: str) -> list[dict]:
    cands: list[dict] = []
    for path in sorted(clone_dir.rglob("*")):
        if ".git/" in path.as_posix() or not path.is_file():
            continue
        if path.suffix.lower() not in (".pdf", ".md") or path.name == "README.md":
            continue
        parts = path.relative_to(clone_dir).parts
        client = parts[0] if len(parts) > 1 else U
        lang = "go" if client == "IBC-GO" else U
        cands.append(_report_pointer(
            spec, path.relative_to(V.CLONES / spec["clone"]), head,
            project=client, language=lang,
            lang_ev="observed_fact: IBC-GO directory is Go" if lang != U else U,
            ecosystem="cosmos",
            eco_ev="reported_claim: Informal Systems Cosmos/IBC audit practice",
            note="Cosmos/IBC/CosmWasm archive (Rust+Go+TLA+); .tla specs counted at source level only."))
    return cands


def _load_existing_overlap() -> tuple[set[str], set[str], set[str]]:
    """Names, normalized titles and commit SHAs from v1 + v2.2 records.

    Schema-agnostic by design: commits are harvested from the serialized row
    (any field), names from the known protocol/title/repository slots. Flags
    are reviewer attention markers, never auto-merge evidence.
    """
    names: set[str] = set()
    titles: set[str] = set()
    commits: set[str] = set()
    for path in (V.ROOT / "derived" / "records.jsonl",
                 V.ROOT / "derived_v2_2" / "records.jsonl"):
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                blob = json.dumps(r)
                commits.update(V.SHA40_RE.findall(blob))
                for repo in V.GITHUB_REPO_RE.findall(blob):
                    names.add(repo.strip().lower())
                proto = r.get("protocol")
                if isinstance(proto, dict) and proto.get("name"):
                    names.add(str(proto["name"]).strip().lower())
                elif isinstance(proto, str) and proto.strip().lower() != U:
                    names.add(proto.strip().lower())
                finding = r.get("finding", {})
                if isinstance(finding, dict):
                    if finding.get("title"):
                        titles.add(V.norm_title(str(finding["title"])))
                    for k in ("project", "protocol"):
                        if finding.get(k):
                            names.add(str(finding[k]).strip().lower())
    return names, titles, commits

"""V3.1 source-text extraction: text cache, finding boundaries, field regexes.

Reads the V3.0 candidate ledger, resolves each row's source bytes (vendored
PDF/MD in V3/clones), and extracts machine-checkable fragments with character
spans. Extracted full text is METADATA_ONLY working data: it lives in temp
space (never committed); only structured attributed facts enter the dataset.

Boundary profiles are per-source (sec 27): each was calibrated against decoded
samples (see reports/v3/normalization_report.md methods). The generic fallback
requires severity evidence inside the segment; segments without it are
rejected fragments, never findings. All ordering is sorted (deterministic).

Public entry points used by scripts/normalize_v3.py:

    get_text(candidate) -> (text, quality)
    split_findings(candidate, text) -> list[Fragment]
    extract_fields(fragment, text) -> dict of evidenced fields
    enrich_markdown_row(candidate) -> dict of evidenced fields (MD sources)
    extract_attack_sequence(sol_path) -> structural call list (DeFiHackLabs)
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdf_text import extract_text as _pdf_extract  # noqa: E402
from pdf_text import readability as _readability  # noqa: E402
from pdf_text import word_hits as _word_hits  # noqa: E402
import vlun_v3 as V  # noqa: E402

U = V.UNKNOWN
ROOT = V.ROOT
CLONES = V.CLONES

_CACHE = Path(tempfile.gettempdir()) / "vlun-v31-texts"

SEVERITY_WORDS = ("Critical", "High", "Medium", "Low", "Informational")
SEV_RE = r"(Critical|High|Medium|Low|Informational)"

CODE_EXTS = (r"sol", r"rs", r"clar", r"move", r"cairo", r"go", r"tact",
             r"fc", r"vy", r"cpp", r"hpp", r"c", r"h", r"ts", r"js",
             r"py", r"sw", r"leo", r"nr", r"circom")
FILE_RE = re.compile(
    r"([\w\-./@]+\.(?:" + "|".join(CODE_EXTS) + r"))\b")
FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z0-9_]+)\s*\(")
GITHUB_BLOB_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/blob/([0-9a-f]{7,40})/([^#\s)]+)(?:#L(\d+)(?:-L?(\d+))?)?")
ABDK_LISTING_RE = re.compile(r"Listing\s+(\d+)\s*:\s*(\d+)")
STATUS_WORDS = (r"Fixed|Fix verified|Acknowledged|Resolved|Closed|"
                r"Partially fixed|Won't fix|Won.t fix|Info\b")


def resolve_path(source_location: str) -> Path | None:
    p = ROOT / source_location
    return p if p.exists() and p.is_file() else None


def get_text(candidate: dict) -> tuple[str, dict]:
    """Source text + quality for one v3.0 candidate row (PDF or MD)."""
    path = resolve_path(candidate.get("source_location", ""))
    quality: dict = {"available": False, "kind": None, "chars": 0,
                     "readability": 0.0, "word_hits": 0, "method": None,
                     "reason": None}
    if path is None:
        quality["reason"] = "source file absent from V3/clones"
        return "", quality
    suffix = path.suffix.lower()
    if suffix not in (".pdf", ".md"):
        quality["reason"] = f"unsupported suffix {suffix}"
        return "", quality
    try:
        digest = V.sha256_file(path)
    except OSError:
        quality["reason"] = "unreadable file"
        return "", quality
    if digest != candidate.get("provenance", {}).get("file_sha256"):
        quality["reason"] = "sha256 mismatch vs v3.0 provenance (clone moved?)"
        return "", quality
    cached = _CACHE / f"{digest}.txt"
    meta_path = _CACHE / f"{digest}.meta.json"
    if cached.exists():
        import json as _j
        try:
            text = cached.read_text(encoding="utf-8")
            meta = _j.loads(meta_path.read_text(encoding="utf-8"))
            meta["available"] = True
            meta["cached"] = True
            return text, meta
        except (OSError, ValueError):
            pass
    try:
        raw = path.read_bytes()
    except OSError:
        quality["reason"] = "unreadable file"
        return "", quality
    if suffix == ".md":
        text = raw.decode("utf-8", errors="replace")
        quality.update({"available": True, "kind": "markdown",
                        "chars": len(text),
                        "readability": round(_readability(text), 3),
                        "word_hits": _word_hits(text), "method": "markdown"})
    else:
        try:
            text, stats = _pdf_extract(raw)
        except Exception as exc:  # never fail the pipeline on one PDF
            quality["reason"] = f"extractor exception: {type(exc).__name__}"
            return "", quality
        quality.update({"available": True, "kind": "pdf",
                        "chars": len(text),
                        "readability": round(_readability(text), 3),
                        "word_hits": _word_hits(text),
                        "method": stats.get("method"),
                        "pdf_pages": stats.get("cmap_pages"),
                        "pdf_fonts": stats.get("cmap_fonts")})
    try:
        _CACHE.mkdir(parents=True, exist_ok=True)
        cached.write_text(text, encoding="utf-8")
        import json as _j
        meta_path.write_text(_j.dumps({k: v for k, v in quality.items()
                                       if k != "available"}), encoding="utf-8")
    except OSError:
        pass
    return text, quality


def page_hint(text: str, offset: int) -> str | None:
    """Nearest preceding 'Page N of M' marker, if any (weak location hint)."""
    hint = None
    for m in re.finditer(r"Page\s+(\d+)\s+of\s+(\d+)", text[:offset]):
        hint = m.group(0)
    return hint


# ---------------------------------------------------------------------------
# Finding boundary profiles. Each returns raw segments:
# (native_id, char_start, char_end, header_text). Validation (severity
# evidence) happens in normalize_v3, not here.
# ---------------------------------------------------------------------------

def _TOC_line(line: str) -> bool:
    """Dot-leader runs or multiple finding IDs: table-of-contents, not body."""
    if re.search(r"\.\s*\.\s*\.", line):
        return True
    if len(re.findall(r"\[[CHMLS]-\d+\]", line)) > 1:
        return True
    if len(re.findall(r"CVF-\d+", line)) > 1:
        return True
    return False


def _split_zellic(text: str) -> list[tuple[str, int, int, str]]:
    # Body headings look like "10 3.1." (page number + section) or bare
    # "3.1."; the TOC uses the same numbers, so TOC/body duplicates are
    # resolved downstream by preferring the severity-bearing instance.
    heads = [(m.group(1), m.start())
             for m in re.finditer(r"(?m)^(?:\d+\s+)?(\d+\.\d+)\.?\s*$", text)]
    segs = []
    for i, (num, start) in enumerate(heads):
        end = heads[i + 1][1] if i + 1 < len(heads) else len(text)
        title = ""
        for line in text[start:end].splitlines()[1:5]:
            s = line.strip()
            if s and not re.fullmatch(r"\d+", s):
                title = s[:200]
                break
        segs.append((num, start, end, title))
    return segs


def despace_text(t: str) -> str:
    """Collapse letter-spaced runs ("C V F - 3" -> "CVF-3").

    Some ABDK reports space out headings letter by letter. Runs of 3+
    single-letter tokens are glued; digits and punctuation always break
    runs (so "8 M o d e r a t e" -> "8 Moderate", never "8Moderate").
    Operates per line so newlines never merge into tokens (which would
    silently break 3-runs). Deterministic; applied only to clearly spaced
    reports, recorded in the fragment method.
    """
    out_lines = []
    for line in t.split("\n"):
        toks = line.split(" ")
        parts: list[str] = []
        buf = ""
        nbuf = 0
        for tok in toks:
            if len(tok) == 1 and tok.isalpha():
                buf += tok
                nbuf += 1
            else:
                if nbuf >= 3:
                    parts.append(buf)
                elif buf:
                    parts.append(" ".join(buf))
                buf, nbuf = "", 0
                parts.append(tok)
        if nbuf >= 3:
            parts.append(buf)
        elif buf:
            parts.append(" ".join(buf))
        out_lines.append(" ".join(p for p in parts if p != ""))
    out = "\n".join(out_lines)
    out = re.sub(r"([A-Z]{2,})\s+-\s+(\d+)", r"\1-\2", out)
    # Split issue numbers ("CVF-1 0" -> "CVF-10"); scoped to CVF ids only.
    out = re.sub(r"\b(CVF-\d+) (\d+)\b", r"\1\2", out)
    return out


def _split_abdk_spaced(work: str) -> list[tuple[str, int, int, str]]:
    """Letter-spaced ABDK variant (post-despace): findings live under "<N>
    <Sev> Issues" sections as "CVF-N. STATUS" entries. Severity comes from
    the section; TOC lines match the same shape, so a mark is kept only when
    Category/Source/Description evidence follows (TOC never has it)."""
    cands: list[tuple[str, int, int, str]] = []
    sections = [(m.group(1), m.start()) for m in re.finditer(
        r"(Critical|Major|Moderate|Minor)\s*Issues", work)]
    bounds = [s for _, s in sections] + [len(work)]
    for si, (sev, sstart) in enumerate(sections):
        for m in re.finditer(
                r"(CVF-\d+)\s*\.\s*([A-Z][A-Z /]{1,20}?)(?:\s*•|\s*\n)",
                work[sstart:bounds[si + 1]]):
            start = sstart + m.start()
            head = work[start:start + 1500]
            # TOC lines match the same shape; only detail entries are
            # followed by Category/Source/Description evidence.
            if not re.search(r"Category|Source|Description", head):
                continue
            cands.append((m.group(1), sev, m.group(2).strip(), start))
    marks = cands
    segs = []
    for i, (num, sev, status, start) in enumerate(marks):
        end = marks[i + 1][3] if i + 1 < len(marks) else len(work)
        head = work[start:start + 1500]
        title = head[:200]
        dm = re.search(r"Description\s+(.{10,200}?)"
                       r"(?:\s+Recommendation|\s+Client Comment|$)",
                       head, re.S)
        if dm:
            title = f"{num}: " + re.sub(r"\s+", " ", dm.group(1)).strip()
        segs.append((num, start, end,
                     f"[{sev}] {title[:180]} <<status:{status.title()}>>"))
    return segs


def _split_abdk(text: str) -> list[tuple[str, int, int, str]]:
    # Detail separator glyph varies by report (U+2022, U+02C6, ...): anchor
    # on the CVF id + Severity keyword instead of the glyph.
    marks = [(m.group(2), m.start())
             for m in re.finditer(
                 r"(\d+\.\d+)\s+(CVF-\d+)\s+[^\w\s]\s*Severity\s+"
                 r"(Critical|Major|Moderate|Minor)", text)]
    segs = []
    for i, (num, start) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        head = text[start:start + 1500]
        # Finding title ~ first Description sentence (bounded, attributed).
        title = head[:200]
        dm = re.search(r"Description\s+(.{10,200}?)"
                       r"(?:\s+Recommendation|\s+Client Comment|$)",
                       head, re.S)
        if dm:
            title = f"CVF-{num}: " + re.sub(r"\s+", " ", dm.group(1)).strip()
        segs.append((f"CVF-{num}", start, end, title[:220]))
    return segs


def _split_cyba(text: str) -> list[tuple[str, int, int, str]]:
    marks = []
    for m in re.finditer(r"\[([CHMLS])-(\d+)\]\s*([^\n]{3,200})", text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start:line_end if line_end > 0 else len(text)]
        if _TOC_line(line):
            continue
        marks.append((f"{m.group(1)}-{m.group(2)}", m.start(),
                      m.group(3).strip()[:200]))
    segs = []
    for i, (nid, start, title) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        segs.append((nid, start, end, title))
    return segs


def _split_sigmaprime(text: str) -> list[tuple[str, int, int, str]]:
    # Native IDs look like 1IFM-01 (report-prefixed). Anchor on the ID line;
    # the title is the next non-field line, severity must follow within the
    # segment (validated downstream).
    marks = []
    for m in re.finditer(r"(?m)^([A-Z][A-Z0-9]{1,12}-\d{1,3})\s*$", text):
        nid = m.group(1)
        after = text[m.end():m.end() + 400].splitlines()
        title = ""
        for line in after:
            s = line.strip()
            if not s:
                continue
            if re.match(r"^(Status|Rating|Impact|Likelihood|Description|"
                        r"Severity|Resolution|Asset)\b", s, re.I):
                continue
            if re.fullmatch(r"[\w\-./]+\.(sol|rs|t\.sol)", s):
                continue
            title = s[:200]
            break
        marks.append((nid, m.start(), title))
    segs = []
    for i, (nid, start, title) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        segs.append((nid, start, end, title))
    return segs


def _split_nethermind(text: str) -> list[tuple[str, int, int, str]]:
    # Summary-table cards read number / title / severity / status on
    # consecutive lines (columns flattened). Page furniture never forms the
    # full tuple, which is what makes this safe.
    lines = text.splitlines()
    marks = []
    for i, line in enumerate(lines):
        if not re.fullmatch(r"\d+", line.strip() or ""):
            continue
        window = [w.strip() for w in lines[i + 1:i + 5]]
        if len(window) >= 3 and len(window[0]) >= 10 \
                and re.fullmatch(
                    r"Critical|High|Medium|Low|Informational|Info|"
                    r"Best Practices", window[1] or "", re.I) \
                and re.fullmatch(
                    r"Fixed|Acknowledged|Partially fixed|Won't fix|Won.t fix|"
                    r"Resolved|Closed|Unfixed", window[2] or "", re.I):
            off = sum(len(prev) + 1 for prev in lines[:i])
            sev, status = window[1], window[2]
            marks.append((line.strip(), off,
                          f"[{sev}] {window[0][:180]} "
                          f"<<status:{status[:40]}>>"))
    segs = []
    for i, (num, start, title) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        segs.append((num, start, end, title))
    return segs


def _split_generic_severity(text: str) -> list[tuple[str, int, int, str]]:
    """Fallback: `Severity:`-field segments. Requires >=2 hits with titles."""
    marks = [(m.group(1), m.start())
             for m in re.finditer(
                 r"(?m)^Severity\s*:\s*(Critical|High|Medium|Low|Informational)\s*$",
                 text)]
    if len(marks) < 2:
        return []
    segs = []
    for i, (sev, start) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        before = text[max(0, start - 400):start].splitlines()
        title = " / ".join(prev.strip() for prev in before if prev.strip())[-200:]
        segs.append((f"finding-{i + 1}", start, end, f"[{sev}] {title}"))
    return segs


def _split_certora(text: str) -> list[tuple[str, int, int, str]]:
    # Certora manual-review reports: H-01 / M-02 / C-03 style IDs with
    # Severity fields nearby. TOC/table repeats are resolved downstream by
    # preferring the severity-bearing instance.
    marks = []
    for m in re.finditer(r"(?m)^([CHML]-\d{1,3})\s*$", text):
        nid = m.group(1)
        after = text[m.end():m.end() + 400].splitlines()
        title = ""
        for line in after:
            s = line.strip()
            if not s:
                continue
            if re.match(r"^(Status|Rating|Impact|Likelihood|Description|"
                        r"Severity|Recommendation|Resolution)\b", s, re.I):
                continue
            title = s[:200]
            break
        marks.append((nid, m.start(), title))
    segs = []
    for i, (nid, start, title) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(text)
        segs.append((nid, start, end, title))
    return segs


def _split_anza(text: str, filename: str = "") -> list[tuple[str, int, int, str]]:
    # Aggregator of auditor originals: dispatch on the authoring auditor
    # named in the filename; unknown authors fall back to generic.
    lower = filename.lower()
    if "zellic" in lower:
        return _split_zellic(text)
    if "certora" in lower:
        return _split_certora(text)
    return _split_generic_severity(text)


SPLITTERS = {
    "zellic-publications": _split_zellic,
    "abdk-audits": _split_abdk,
    "cyba-audits": _split_cyba,
    "sigmaprime-audits": _split_sigmaprime,
    "nethermind-audits": _split_nethermind,
    "certora-reports": _split_certora,
}


def title_quality_ok(title: str) -> tuple[bool, str]:
    """Title sanity gate against word-salad segments from spaced/garbled
    text. Real auditor titles are prose; garbage titles contain code
    punctuation, URLs, or spaced-slash salad separators."""
    t = (title or "").strip()
    if len(t) < 12:
        return False, "title shorter than 12 chars"
    for bad in ("http", "{", "}", ";"):
        if bad in t:
            return False, f"title contains {bad!r} (code, not prose)"
    if re.search(r"\s/\s", t):
        return False, "title contains spaced-slash salad separators"
    words = re.findall(r"[A-Za-z]{4,}", t)
    if len(words) < 2:
        return False, "fewer than 2 alphabetic words (len>=4)"
    return True, "prose-like title"


def split_findings(candidate: dict, text: str
                   ) -> tuple[list[dict], dict, str]:
    """Raw finding segments + info + the working text they index into.

    The working text is the source text except for letter-spaced ABDK
    reports, where it is the deterministic de-spaced copy (flagged in
    info and on every downstream fragment method).
    """
    sid = candidate["source_id"]
    fn = SPLITTERS.get(sid, _split_generic_severity)
    if sid == "anza-security-audits":
        loc = candidate.get("source_location", "")

        def fn(text):
            return _split_anza(text, loc.rsplit("/", 1)[-1])

        fn.__name__ = "_split_anza"
    work_text = text
    despaced = False
    raw: list[tuple[str, int, int, str]] = []
    if sid == "abdk-audits":
        raw = fn(text)
        if not raw and re.search(r"C\s*V\s*F\s*-\s*\d+", text):
            work_text = despace_text(text)
            despaced = True
            raw = _split_abdk(work_text)
            if not raw:
                raw = _split_abdk_spaced(work_text)
    else:
        raw = fn(text)
    info = {"splitter": fn.__name__, "raw_segments": len(raw),
            "despaced_copy": despaced}
    frags = []
    for native_id, start, end, header in raw:
        frags.append({
            "native_finding_id": native_id,
            "char_start": start, "char_end": end,
            "header_text": header,
            "page_hint": page_hint(work_text, start),
        })
    return frags, info, work_text


# ---------------------------------------------------------------------------
# Field extractors over a segment (offsets relative to full text).
# Every returned field: {"value", "evidence_type", "method", "span"}.
# ---------------------------------------------------------------------------

def _span(text: str, seg_start: int, match: re.Match) -> dict:
    s, e = match.start() + seg_start, match.end() + seg_start
    return {"char_start": s, "char_end": e, "page_hint": page_hint(text, s),
            "excerpt": match.group(0)[:160]}


FIELD_SEV = re.compile(
    r"Severity\s*[:：]\s*(Critical|High|Medium|Low|Informational|"
    r"Info\b|Best Practices|Major|Moderate|Minor)"
    r"|Severity\s+(Critical|High|Medium|Low|Informational)"
    r"(?=\s+(?:Likelihood|Impact|Category|Description|Status|Target|•)|\s*$)",
    re.I)
STATUS_VALUE_RE = re.compile(
    r"^(Fixed|Fix verified|Acknowledged|Resolved|Closed|Partially fixed|"
    r"Won't fix|Wont fix|Won.t fix|Unfixed|Open|New|Accepted|Confirmed|"
    r"Invalid|Duplicate|Info\b|Acknowledged.*|Fixed.*|Resolved.*|Closed.*)",
    re.I)
FIELD_STATUS = re.compile(
    r"(?:Status|Fix status)\s*(?:[:：]\s*|\n\s*)([^\n]{2,80})", re.I)
# Cyba-style: "Severity: High risk (Resolved)" -- status in parens.
SEV_PAREN_STATUS_RE = re.compile(
    r"Severity\s*:[^\n]{0,60}?\(([^)]{2,40})\)")
# Cyba-style code context: "Context: pyth-oracle.clar :21-23 ,30-47".
CONTEXT_RE = re.compile(
    r"Context\s*:\s*([\w\-./@]+\.(?:" + "|".join(CODE_EXTS) + r"))"
    r"\s*:?\s*([\d][\d,\- ]{1,60})?")
FIELD_CATEGORY = re.compile(
    r"(?:Category|Vulnerability(?:\s+type)?|Type|Class)\s*[:：]\s*([^\n•]{2,80})"
    r"|Category\s+([A-Z][\w /-]{2,40}?)"
    r"(?=\s+(?:Severity|Likelihood|Impact|Description|Target|Status|•)|\s*$)",
    re.I)
FIELD_TARGET = re.compile(
    r"(?:Target|Source|Contract|Component|Module|File|Location|Affects)\s*"
    r"[:：]\s*([A-Za-z0-9_\-./@]+\.(?:" + "|".join(CODE_EXTS) + r")\b"
    r"|[^\n•]{2,80})"
    r"|Target\s+([^\n•]{2,60}?)"
    r"(?=\s+(?:Category|Severity|Likelihood|Impact|Description|Status)\b)",
    re.I)
FIELD_FUNC = re.compile(r"(?:Function|Method)\s*[:：]\s*([A-Za-z0-9_]+)")
POC_HEADER_RE = re.compile(
    r"(?im)^#{0,4}\s*(proof of concept|poc|exploit|attack scenario|"
    r"reproduction steps)\b")
REM_HEADER_RE = re.compile(
    r"(?im)^#{0,4}\s*(remediation|recommendation|fix|mitigation|resolution|"
    r"client (comment|response)|developer response)\b")


def _poc_window(segment: str, start: int, limit: int = 4000) -> str:
    """Text after a section header, cut at the next markdown header.

    Without the cut, a code fence kilobytes later (next finding's fix
    snippet, an appendix) would falsely mark this section as code-bearing.
    """
    window = segment[start:start + limit]
    nxt = re.search(r"(?m)^#{1,4}\s+\S", window)
    if nxt and nxt.start() > 20:
        window = window[:nxt.start()]
    return window


def ev(value, evidence_type, method, span=None) -> dict:
    return {"value": value, "evidence_type": evidence_type,
            "method": method, "span": span}


def extract_fields(segment: str, seg_start: int, text: str,
                   source_id: str) -> dict:
    """Evidenced fields from one segment. Unknowns stay unknown."""
    out: dict = {}
    m = FIELD_SEV.search(segment)
    if m:
        val = (m.group(1) or m.group(2) or "").strip()
        form = "explicit Severity field" if m.group(1) else \
            "inline Severity value bounded by field keywords"
        out["severity_reported"] = ev(
            val, "reported_claim", f"{form} in finding segment",
            _span(text, seg_start, m))
    m = FIELD_STATUS.search(segment)
    if m:
        val = m.group(1).strip()[:80]
        # Status-like headers followed by arbitrary prose would fabricate a
        # fix claim: only accept values starting with a known status token.
        if STATUS_VALUE_RE.match(val):
            out["fix_status_reported"] = ev(
                val, "reported_claim",
                "explicit Status field with status-vocabulary value",
                _span(text, seg_start, m))
    if "fix_status_reported" not in out:
        pm = SEV_PAREN_STATUS_RE.search(segment)
        if pm and STATUS_VALUE_RE.match(pm.group(1).strip()):
            out["fix_status_reported"] = ev(
                pm.group(1).strip()[:40], "reported_claim",
                "status in parens on the Severity line "
                "(Cyba-style 'Severity: High risk (Resolved)')",
                _span(text, seg_start, pm))
    cm = CONTEXT_RE.search(segment)
    if cm:
        line_refs = sorted({int(x) for x in
                            re.findall(r"\d{1,6}", cm.group(2) or "")
                            if x.isdigit()})[:30]
        out["context_ref"] = ev(
            {"file": cm.group(1),
             "report_line_refs": line_refs}, "observed_fact",
            "explicit Context: file + line ranges in finding segment "
            "(report lines; anchor to a revision before use as source lines)",
            _span(text, seg_start, cm))
    m = FIELD_CATEGORY.search(segment)
    if m:
        val = (m.group(1) or m.group(2) or "").strip()[:80]
        form = "explicit Category/Type field" if m.group(1) else \
            "inline Category value bounded by field keywords"
        out["category_reported"] = ev(
            val, "reported_claim", f"{form} in finding segment",
            _span(text, seg_start, m))
    m = FIELD_TARGET.search(segment)
    if m:
        val = (m.group(1) or m.group(2) or "").strip()[:160]
        val = val.strip(" ;:,.•")
        if len(val) < 2:
            pass
        else:
            form = "explicit Target/Source/Contract field" if m.group(1) else \
                "inline Target value bounded by field keywords"
            out["target_reported"] = ev(
                val, "reported_claim", f"{form} in finding segment",
                _span(text, seg_start, m))
    m = FIELD_FUNC.search(segment)
    if m:
        out["function_reported"] = ev(
            m.group(1).strip(), "reported_claim",
            "explicit Function field in finding segment",
            _span(text, seg_start, m))
    files = sorted({mm.group(1) for mm in FILE_RE.finditer(segment)
                    if not mm.group(1).startswith(("http", "www."))})
    if files:
        out["code_files"] = ev(
            files[:12], "observed_fact",
            "code-filename regex over finding segment", None)
    line_refs = sorted({int(x) for x in
                        re.findall(r"(?:#L|:|line\s+)(\d{1,6})", segment)
                        if x.isdigit()})[:20]
    if line_refs:
        out["line_refs"] = ev(
            line_refs, "observed_fact",
            "line-number regex over finding segment "
            "(PDF/report lines, NOT source lines until anchored)", None)
    blobs = []
    for mm in GITHUB_BLOB_RE.finditer(segment):
        blobs.append({"repository": f"https://github.com/{mm.group(1)}",
                      "revision": mm.group(2), "path": mm.group(3),
                      "line_start": mm.group(4), "line_end": mm.group(5)})
    if blobs:
        out["code_permalinks"] = ev(
            blobs[:8], "observed_fact",
            "github blob permalink regex over finding segment", None)
    abdk_listings = [f"{a}:{b}" for a, b in
                     ABDK_LISTING_RE.findall(segment)][:10]
    if abdk_listings:
        out["abdk_listings"] = ev(
            abdk_listings, "observed_fact",
            "ABDK 'Listing N : LINE' refs in finding segment", None)
    poc_m = POC_HEADER_RE.search(segment)
    if poc_m:
        after = _poc_window(segment, poc_m.end())
        has_code = ("```" in after) or bool(
            re.search(r"(?m)^\s*(function\s+\w+|forge|cast|vm\.)", after))
        fns = sorted(set(re.findall(
            r"(?m)^\s*function\s+([A-Za-z0-9_]+)\s*\(", after)))[:10]
        out["poc_section"] = ev(
            {"present": True, "has_code": has_code,
             "poc_functions": fns}, "observed_fact",
            "PoC section header + code scan within the section "
            "(cut at next header)",
            _span(text, seg_start, poc_m))
    elif re.search(r"\[PoC\]", segment):
        # Auditor PoC tag without a prose header (Cyba-style): the tag marks
        # a referenced proof; code presence checked structurally below.
        pm2 = re.search(r"\[PoC\]", segment)
        after = segment[pm2.end():pm2.end() + 4000]
        out["poc_section"] = ev(
            {"present": True,
             "has_code": ("```" in after) or bool(
                 re.search(r"(?m)^\s*(function\s+\w+|\( define-|forge|cast)",
                           after)),
             "tag": "[PoC]"}, "observed_fact",
            "auditor [PoC] tag in finding segment (referenced proof)",
            _span(text, seg_start, pm2))
    rem_m = REM_HEADER_RE.search(segment)
    if rem_m:
        out["remediation_section"] = ev(
            {"present": True}, "observed_fact",
            "remediation section header in finding segment",
            _span(text, seg_start, rem_m))
    shas = sorted(set(V.SHA40_RE.findall(segment)))
    if shas:
        out["commit_shas"] = ev(
            shas[:8], "observed_fact",
            "40-hex regex over finding segment (context required for role)",
            None)
    return out


# ---------------------------------------------------------------------------
# Markdown-row enrichment (Pashov / Sherlock / Informal report rows).
# ---------------------------------------------------------------------------

def enrich_markdown_row(candidate: dict) -> dict:
    """Evidenced enrichment for rows whose source_location is a .md file."""
    path = resolve_path(candidate.get("source_location", ""))
    out: dict = {}
    if path is None or path.suffix.lower() != ".md":
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    # Scope the body: Pashov per-finding rows already split in v3.0 by header;
    # re-anchor the body under this row's own header when recognisable.
    title = candidate.get("original_title", "")
    body = text
    mh = re.search(r"^# (\[.+-.+\].*)$", title, re.M)
    if mh:
        anchor = re.escape(mh.group(1)[:60])
        am = re.search(r"(?m)^# " + anchor, text)
        if am:
            nxt = re.search(r"(?m)^# \[[CHML]-", text[am.end():])
            body = text[am.start():am.end() + (nxt.start() if nxt else len(text))]
    files = sorted({m.group(1) for m in FILE_RE.finditer(body)
                    if not m.group(1).startswith(("http", "www."))})
    # Drop the auditor's own boilerplate paths (badges, logos).
    files = [f for f in files
             if not f.startswith(("img.shields.io", "raw.githubusercontent"))]
    if files:
        out["code_files"] = ev(files[:12], "observed_fact",
                                "code-filename regex over finding body", None)
    funcs = sorted(set(FUNC_RE.findall(body)))[:10]
    if funcs:
        out["code_functions"] = ev(funcs, "observed_fact",
                                   "function-signature regex over finding body "
                                   "(candidate set, not attribution)", None)
    pm = POC_HEADER_RE.search(body)
    if pm:
        after = _poc_window(body, pm.end())
        fns = sorted(set(re.findall(
            r"(?m)^\s*function\s+([A-Za-z0-9_]+)\s*\(", after)))[:10]
        out["poc_section"] = ev(
            {"present": True, "has_code": ("```" in after),
             "poc_functions": fns}, "observed_fact",
            "PoC section scan over finding body (cut at next header)", None)
    shas = sorted(set(V.SHA40_RE.findall(body)))
    if shas:
        out["commit_shas"] = ev(shas[:8], "observed_fact",
                                "40-hex regex over finding body", None)
    return out


# ---------------------------------------------------------------------------
# DeFiHackLabs attack-sequence structure (observed from the PoC code itself).
# ---------------------------------------------------------------------------

SELECTOR_RE = re.compile(
    r'keccak256\("([A-Za-z0-9_]+\([^)]*\))"\)')
CALL_RE = re.compile(
    r"([A-Za-z0-9_\[\]]+)\.call\s*(?:\{[^}]*\})?\s*\(")
IFACE_CALL_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s*\(\s*(0x[0-9a-fA-F]{40})\s*\)\s*\.\s*"
    r"([A-Za-z0-9_]+)\s*\(")
FORK_RE = re.compile(r'createSelectFork\(\s*"([A-Za-z0-9_-]+)"')
ENTRY_RE = re.compile(r"(?m)^\s*function\s+(test[A-Za-z0-9_]*)\s*\(")


def extract_attack_sequence(sol_path: Path) -> dict:
    """Ordered external-call structure of a Foundry PoC (observed facts)."""
    try:
        text = sol_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"available": False, "reason": "unreadable file"}
    steps: list[dict] = []
    for m in CALL_RE.finditer(text):
        sel = None
        window = text[m.start():m.start() + 400]
        sm = re.search(r"abi\.encodeWithSelector\(\s*(?:bytes4\(keccak256\("
                       r"\"([^\"]+)\"\)\)|0x[0-9a-fA-F]+|(\w+))", window)
        if sm:
            sel = sm.group(1) or sm.group(2)
        steps.append({"order": len(steps), "kind": "low_level_call",
                      "target_expr": m.group(1)[:80],
                      "selector_or_fn": (sel or U)[:120]})
        if len(steps) >= 50:
            break
    for m in IFACE_CALL_RE.finditer(text):
        steps.append({"order": len(steps), "kind": "interface_call",
                      "target_expr": m.group(2),
                      "selector_or_fn": m.group(3)[:120]})
        if len(steps) >= 50:
            break
    steps.sort(key=lambda s: s["order"])
    for i, s in enumerate(steps):
        s["order"] = i
    fork = FORK_RE.search(text)
    entries = ENTRY_RE.findall(text)
    selectors = sorted({m.group(1) for m in SELECTOR_RE.finditer(text)})[:20]
    return {"available": True,
            "entrypoints": entries[:10],
            "fork_chain": fork.group(1) if fork else U,
            "selectors_referenced": selectors,
            "steps": steps[:50],
            "evidence_type": "observed_fact",
            "method": "structural parse of PoC source (calls in file order; "
                      "no execution, no semantic claims)"}

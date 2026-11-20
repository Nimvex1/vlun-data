"""Minimal indentation-aware YAML reader for ReEVMBench ``config.yaml`` files.

Stdlib only. Deliberately narrow: it understands top-level scalars, top-level
dash lists, ``vulnerabilities`` list items, and the two path-mapping mappings
used by the harness configs. Anything it cannot understand is ignored rather
than guessed, so the execution runner never fabricates a target test.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_TOP_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$")


def _strip_comment(s: str) -> str:
    out: list[str] = []
    quote: str | None = None
    for ch in s:
        if ch in ("'", '"'):
            quote = None if quote == ch else (quote or ch)
        if ch == "#" and quote is None:
            break
        out.append(ch)
    return "".join(out)


def _scalar(text: str) -> Any:
    s = _strip_comment(text).strip()
    if not s:
        return ""
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1]
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        if re.fullmatch(r"-?\d+(?:\.\d+)?", s):
            return float(s) if "." in s else int(s)
    except ValueError:
        pass
    return s


def _pair(text: str) -> tuple[str, str] | None:
    """Split ``key: value`` on the first colon outside quotes."""
    quote: str | None = None
    for i, ch in enumerate(text):
        if ch in ("'", '"'):
            quote = None if quote == ch else (quote or ch)
        elif ch == ":" and quote is None:
            key = _scalar(text[:i])
            val = _scalar(text[i + 1:])
            if isinstance(key, str) and key:
                return key, val
            return None
    return None


def parse_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}

    out: dict[str, Any] = {}
    vulns: list[dict[str, Any]] = []
    section: str | None = None
    current: dict[str, Any] | None = None
    mapping: str | None = None

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        text = raw.strip()

        if indent == 0:
            current = None
            mapping = None
            m = _TOP_KEY.match(text)
            if not m:
                section = None
                continue
            key, val = m.group(1), m.group(2)
            if not val.strip():
                section = key
                if key in ("vulnerabilities", "tests_allowed_to_fail"):
                    out[key] = [] if key == "tests_allowed_to_fail" else vulns
                continue
            section = None
            out[key] = _scalar(val)
            continue

        if section == "vulnerabilities":
            if indent <= 2 and text.startswith("- "):
                current = {}
                vulns.append(current)
                mapping = None
                pair = _pair(text[2:].strip())
                if pair:
                    current[pair[0]] = pair[1]
                continue
            if current is None:
                continue
            if mapping and indent >= 6:
                pair = _pair(text)
                if pair:
                    current.setdefault(mapping, {})[pair[0]] = pair[1]
                    continue
            pair = _pair(text)
            if pair:
                key, val = pair
                if not val and key in ("test_path_mapping", "patch_path_mapping"):
                    current[key] = {}
                    mapping = key
                else:
                    current[key] = val
                    mapping = None
            continue

        if section and text.startswith("- "):
            lst = out.setdefault(section, [])
            if isinstance(lst, list):
                lst.append(_scalar(text[2:]))

    out["vulnerabilities"] = vulns
    return out


def exploit_vulnerabilities(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Vulnerabilities that carry both a target test and a test path mapping."""
    picked: list[dict[str, Any]] = []
    for v in cfg.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        if v.get("test") and v.get("test_path_mapping"):
            picked.append(v)
    return picked

#!/usr/bin/env python3
"""Naive PDF text layer for VLUN V3.1 (stdlib only).

Moved verbatim out of scripts/pdf_text.py: FlateDecode streams are
decompressed by the caller, and text-showing operators (Tj / TJ) inside
BT..ET blocks are read in content-stream order. No font remapping beyond
WinAnsi-ish bytes; no CMap/CID decoding (see scripts/pdf_cmap.py); no
layout reconstruction, table parsing, or OCR.
"""

from __future__ import annotations

import re

STREAM_RE = re.compile(rb"stream\r?\n(.*?)endstream", re.S)
BT_RE = re.compile(rb"BT(.*?)ET", re.S)
# Literal string with PDF escapes; hex string <...>.
LIT_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")
HEX_RE = re.compile(rb"<([0-9A-Fa-f\s]+)>")
TJ_ARRAY_RE = re.compile(rb"\[(.*?)\]\s*TJ", re.S)
TJ_OP_RE = re.compile(rb"(?P<arr>\[.*?\]\s*TJ)|(?P<lit>\((?:\\.|[^\\()])*\))\s*Tj", re.S)

ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
           b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}

def _unescape_literal(raw: bytes) -> bytes:
    """Strip parens, resolve \\ooo octal + single-char escapes."""
    inner = raw[1:-1]
    out = bytearray()
    i = 0
    while i < len(inner):
        c = inner[i:i + 1]
        if c == b"\\":
            nxt = inner[i + 1:i + 2]
            if nxt in ESCAPES:
                out += ESCAPES[nxt]
                i += 2
            elif nxt and 48 <= nxt[0] <= 55:  # \ooo octal
                octal = inner[i + 1:i + 4]
                m = re.match(rb"[0-7]{1,3}", octal)
                tok = m.group(0) if m else b""
                out.append(int(tok, 8) % 256)
                i += 1 + len(tok)
            else:  # line continuation or unknown: drop the backslash
                i += 2 if nxt else 1
        else:
            out += c
            i += 1
    return bytes(out)

def _decode_bytes(raw: bytes) -> str:
    """Bytes -> str with a documented best effort (WinAnsi-ish -> cp1252).

    Falls back through: UTF-16 BOM -> UTF-16BE/LE heuristic (alternating NULs,
    common when producers emit UTF-16 without a BOM) -> cp1252. Custom font
    encodings without a ToUnicode map are NOT recoverable here; those bytes
    surface as replacement characters and the file scores low on readability.
    """
    if raw.startswith(b"\xfe\xff"):  # UTF-16BE BOM
        try:
            return raw[2:].decode("utf-16-be")
        except UnicodeDecodeError:
            pass
    if raw.startswith(b"\xff\xfe"):  # UTF-16LE BOM
        try:
            return raw[2:].decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    if len(raw) >= 4:
        even_nul = sum(1 for i in range(0, len(raw), 2) if raw[i:i + 1] == b"\x00")
        odd_nul = sum(1 for i in range(1, len(raw), 2) if raw[i:i + 1] == b"\x00")
        pairs = len(raw) // 2
        if even_nul > pairs * 0.7:
            try:
                return raw.decode("utf-16-be")
            except UnicodeDecodeError:
                pass
        elif odd_nul > pairs * 0.7:
            try:
                return raw.decode("utf-16-le")
            except UnicodeDecodeError:
                pass
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")

def _block_text(block: bytes) -> str:
    """Text of one BT..ET block, in content-stream order."""
    parts: list[str] = []
    for m in TJ_OP_RE.finditer(block):
        if m.group("arr") is not None:
            parts.append(_tj_array_text(m.group("arr")))
            parts.append(" ")
        else:
            parts.append(_decode_bytes(_unescape_literal(m.group("lit"))))
    return "".join(parts)

def _tj_array_text(arr: bytes) -> str:
    """TJ array with kerning-aware word spacing.

    Large negative kerning adjustments between two shown strings mean the next
    glyph starts a new word leftwards of the natural advance -- without
    emitting a space here, words glue together ("Theinitialmodelstate").
    """
    parts: list[str] = []
    prev_was_string = False
    for sm in re.finditer(
            rb"(\((?:\\.|[^\\()])*\))|<([0-9A-Fa-f\s]+)>|(-?\d+(?:\.\d+)?)",
            arr):
        if sm.group(1) is not None:
            parts.append(_decode_bytes(_unescape_literal(sm.group(1))))
            prev_was_string = True
        elif sm.group(2) is not None:
            try:
                parts.append(_decode_bytes(bytes.fromhex(
                    re.sub(rb"\s", b"", sm.group(2)).decode("ascii"))))
            except (ValueError, UnicodeDecodeError):
                pass
            prev_was_string = True
        else:
            try:
                kern = float(sm.group(3))
            except ValueError:
                kern = 0.0
            if kern < -120 and prev_was_string:
                parts.append(" ")
            prev_was_string = False
    return "".join(parts)

def readability(text: str) -> float:
    """Fraction of characters in the safe printable class. A custom-encoded
    font decoded with the wrong map scores low here; that is the honest
    signal, not a number to optimise."""
    if not text:
        return 0.0
    ok = len(re.findall(r"[A-Za-z0-9 .,;:()\[\]{}\-/'+_=%$#@!?\"<>|&*^~`]", text))
    return ok / len(text)


_COMMON_WORDS = ("audit", "finding", "contract", "function", "severity",
                 "recommendation", "impact", "description")


def word_hits(text: str) -> int:
    low = text.lower()
    return sum(low.count(w) for w in _COMMON_WORDS)

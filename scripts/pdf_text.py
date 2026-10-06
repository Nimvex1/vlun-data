#!/usr/bin/env python3
"""Stdlib-only PDF text extractor for the VLUN V3.1 normalization pass.

No third-party PDF tools exist in this environment (and the pipeline is
standard-library only by policy), so this implements the minimal honest
subset: decompress FlateDecode streams with zlib and read the text-showing
operators (Tj / TJ) inside BT..ET blocks.

What it does NOT do (stated, not hidden): font-encoding remapping beyond
WinAnsi-ish bytes, CMap/CID decoding, layout reconstruction, table parsing,
scanned-image OCR. Output is reading-order-ish plain text sufficient for
finding-boundary detection, severity/title capture and code-location regexes
-- never a faithful reflow of the report.

Extracted full text is third-party content under METADATA_ONLY: it is written
to stdout or a caller-chosen path (operator temp space), and is NEVER
committed. Only structured attributed facts derived from it may enter the
dataset. Use --stats for a machine-readable extraction-quality summary.

    python scripts/pdf_text.py report.pdf
    python scripts/pdf_text.py report.pdf --out text.txt
    python scripts/pdf_text.py report.pdf --stats
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zlib
from pathlib import Path

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


# ---------------------------------------------------------------------------
# CMap-aware path: PDF object layer, ToUnicode maps, TrueType cmap tables.
#
# Many auditor PDFs subset fonts with scrambled single-byte encodings or
# Identity CIDFonts and no usable WinAnsi mapping. For those, the naive path
# above yields mojibake. This path parses the object layer (including
# compressed object streams), resolves each page's font resources, and decodes
# text through ToUnicode CMaps or the embedded TrueType cmap -- all still
# standard-library only (zlib + struct + re).
# ---------------------------------------------------------------------------

OBJ_RE = re.compile(rb"(\d+) (\d+) obj(.*?)endobj", re.S)


def _parse_objects(data: bytes) -> dict[tuple[int, int], bytes]:
    """All indirect objects, expanding compressed object streams (ObjStm).

    Authority rule: when classic xref tables are present, the object at the
    xref-recorded offset wins; an ObjStm member reusing the same number (seen
    in malformed producers) must not overwrite it. Without xref tables the
    legacy scan order applies.
    """
    objs: dict[tuple[int, int], bytes] = {}
    xref_offsets: dict[tuple[int, int], int] = {}
    for xm in re.finditer(rb"^xref\r?\n", data, re.M):
        pos = xm.end()
        while True:
            hm = re.match(rb"(\d+)\s+(\d+)\s*\r?\n", data[pos:])
            if not hm:
                break
            first, count = int(hm.group(1)), int(hm.group(2))
            pos += hm.end()
            for i in range(count):
                entry = data[pos:pos + 20]
                if len(entry) < 18:
                    break
                try:
                    off = int(entry[0:10])
                    gen = int(entry[11:16])
                except ValueError:
                    pass
                else:
                    if entry[17:18] == b"n":
                        xref_offsets[(first + i, gen)] = off
                pos += 20
                if data[pos:pos + 1] in (b"\r", b"\n"):
                    pos += 1
                    if data[pos:pos + 1] == b"\n" and entry[18:19] == b"\r":
                        pos += 1
            if data[pos:pos + 7] == b"trailer":
                break
    if xref_offsets:
        for (num, gen), off in xref_offsets.items():
            m = re.match(rb"(\d+)\s+(\d+)\s+obj(.*?)endobj", data[off:], re.S)
            if m:
                objs[(num, gen)] = m.group(3)
    else:
        for m in OBJ_RE.finditer(data):
            objs[(int(m.group(1)), int(m.group(2)))] = m.group(3)
    for (_num, _gen), body in list(objs.items()):
        sm = re.search(rb"stream\r?\n(.*?)endstream", body, re.S)
        if not sm or b"ObjStm" not in body:
            continue
        hdr = body[:sm.start()]
        nm = re.search(rb"/N\s+(\d+)", hdr)
        fm = re.search(rb"/First\s+(\d+)", hdr)
        if not nm or not fm:
            continue
        try:
            dec = zlib.decompress(sm.group(1).strip())
        except Exception:
            continue
        n, first = int(nm.group(1)), int(fm.group(1))
        tab = list(map(int, re.findall(rb"\d+", dec[:first])))
        if len(tab) < 2 * n:
            continue
        pairs = sorted(((tab[i + 1], tab[i]) for i in range(0, 2 * n, 2)))
        # pairs are (offset, objnum): ends come from offset order, not
        # object-number order (sorting by number slices garbage/empty).
        for idx, (off, onum) in enumerate(pairs):
            if (onum, 0) in xref_offsets:
                continue  # xref-recorded object wins over ObjStm reuse
            end = pairs[idx + 1][0] if idx + 1 < len(pairs) else len(dec) - first
            if off < 0 or first + off > len(dec):
                continue
            objs[(onum, 0)] = dec[first + off:first + end]
    return objs


def _stream_bytes(obj_body: bytes | None) -> bytes | None:
    if not obj_body:
        return None
    sm = re.search(rb"stream\r?\n(.*?)endstream", obj_body, re.S)
    if not sm:
        return None
    payload = sm.group(1).strip()
    try:
        return zlib.decompress(payload)
    except Exception:
        pass
    if not payload.startswith(b"\x78"):
        # Not a deflate stream (raw content, images): return as-is.
        return payload
    # Truncated deflate streams occur in the wild (a producer bug seen in some
    # Zellic ToUnicode maps): recover the decodable prefix chunk-by-chunk
    # rather than discarding the whole stream. Whatever is missing stays
    # missing and is counted downstream via lower readability -- never
    # synthesised.
    out: list[bytes] = []
    try:
        decomp = zlib.decompressobj()
        for i in range(0, len(payload), 32):
            try:
                out.append(decomp.decompress(payload[i:i + 32]))
            except Exception:
                break
    except Exception:
        pass
    joined = b"".join(out)
    return joined if joined else None


def _parse_tounicode(text: bytes) -> dict[int, str]:
    """beginbfchar/beginbfrange map: source code -> unicode string."""
    mapping: dict[int, str] = {}
    try:
        s = text.decode("latin-1")
    except Exception:
        return mapping
    for m in re.finditer(r"beginbfchar(.*?)endbfchar", s, re.S):
        for sm, dm in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>",
                                 m.group(1)):
            try:
                code = int(sm, 16)
                raw = bytes.fromhex(dm)
                ch = raw.decode("utf-16-be") if len(raw) % 2 == 0 \
                    else raw.decode("latin-1")
            except (ValueError, UnicodeDecodeError):
                continue
            mapping[code] = ch
    for m in re.finditer(r"beginbfrange(.*?)endbfrange", s, re.S):
        for lo, hi, dst in re.findall(
                r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>",
                m.group(1)):
            try:
                lo_i, hi_i = int(lo, 16), int(hi, 16)
                raw = bytes.fromhex(dst)
                base = raw.decode("utf-16-be") if len(raw) % 2 == 0 \
                    else raw.decode("latin-1")
            except (ValueError, UnicodeDecodeError):
                continue
            if len(base) == 1:
                for c in range(lo_i, min(hi_i, lo_i + 255) + 1):
                    mapping[c] = chr(ord(base) + (c - lo_i))
    # Array-destination bfranges are rare in these reports; skipped rather
    # than guessed (their absence lowers readability, honestly counted).
    return mapping


def _parse_ttf_cmap(ttf: bytes) -> dict[int, str]:
    """TrueType cmap -> {glyph_id: character}. Format 4 (+12). Best effort."""
    gid2char: dict[int, str] = {}
    try:
        if len(ttf) < 12:
            return gid2char
        num_tables = struct.unpack(">H", ttf[4:6])[0]
        tables: dict[bytes, tuple[int, int]] = {}
        for i in range(num_tables):
            off = 12 + 16 * i
            if off + 16 > len(ttf):
                break
            tag, _cs, toff, tlen = struct.unpack(">4sIII", ttf[off:off + 16])
            tables[tag] = (toff, tlen)
        if b"cmap" not in tables:
            return gid2char
        coff, _clen = tables[b"cmap"]
        _ver, nsub = struct.unpack(">HH", ttf[coff:coff + 4])
        best_off: int | None = None
        for i in range(nsub):
            plat, enc, soff = struct.unpack(
                ">HHI", ttf[coff + 4 + 8 * i:coff + 12 + 8 * i])
            if (plat, enc) in ((3, 1), (0, 4), (0, 3)):
                best_off = coff + soff
                break
        if best_off is None:
            for i in range(nsub):
                _p, _e, soff = struct.unpack(
                    ">HHI", ttf[coff + 4 + 8 * i:coff + 12 + 8 * i])
                best_off = coff + soff
                break
        if best_off is None:
            return gid2char
        fmt = struct.unpack(">H", ttf[best_off:best_off + 2])[0]
        char2gid: dict[int, int] = {}
        if fmt == 4:
            seg = struct.unpack(">H", ttf[best_off + 6:best_off + 8])[0] // 2
            base = best_off + 14
            end = struct.unpack(f">{seg}H", ttf[base:base + 2 * seg])
            start = struct.unpack(
                f">{seg}H", ttf[base + 2 * seg + 2:base + 4 * seg + 2])
            delta = struct.unpack(
                f">{seg}h", ttf[base + 4 * seg + 2:base + 6 * seg + 2])
            roff_pos = base + 6 * seg + 2
            roff = struct.unpack(f">{seg}H", ttf[roff_pos:roff_pos + 2 * seg])
            for i in range(seg):
                if start[i] == 0xFFFF and end[i] == 0xFFFF:
                    continue
                for ch in range(start[i], min(end[i], 0xFFFF) + 1):
                    if roff[i] == 0:
                        gid = (ch + delta[i]) % 65536
                    else:
                        goff = roff_pos + 2 * i + roff[i] + 2 * (ch - start[i])
                        if goff + 2 > len(ttf):
                            continue
                        g = struct.unpack(">H", ttf[goff:goff + 2])[0]
                        gid = (g + delta[i]) % 65536 if g else 0
                    if gid:
                        char2gid[ch] = gid
        elif fmt == 12:
            _r, ngroups = struct.unpack(">II", ttf[best_off + 4:best_off + 12])
            for i in range(min(ngroups, 5000)):
                off = best_off + 12 + 12 * i
                sc, ec, sg = struct.unpack(">III", ttf[off:off + 12])
                for ch in range(sc, min(ec, sc + 5000) + 1):
                    char2gid[ch] = sg + (ch - sc)
        for ch, gid in char2gid.items():
            if gid and gid not in gid2char:
                try:
                    gid2char[gid] = chr(ch)
                except ValueError:
                    pass
    except (struct.error, IndexError, ValueError):
        return {}
    return gid2char


_CMAP_OP_RE = re.compile(
    rb"(/[A-Za-z0-9+\-.]+\s+[\d.]+\s+Tf)|(\[.*?\]\s*TJ)"
    rb"|(\((?:\\.|[^\\()])*\))\s*Tj|(<[0-9A-Fa-f\s]+>)\s*Tj|(\bT\*)|(')|(\")",
    re.S)


def _decode_codes(raw: bytes, decoder: dict) -> str:
    """Raw string bytes -> text via a font decoder.

    Width comes from the font's encoding: Identity-H CIDFonts address glyphs
    in 2-byte codes (in BOTH literal and hex strings); simple fonts use
    single bytes. A wrong width is silent mojibake, so it is recorded on the
    decoder from the font dictionary, never inferred per string.
    """
    width = decoder.get("width", 1)
    codes = (list(raw) if width == 1
             else [raw[i] * 256 + raw[i + 1]
                   for i in range(0, len(raw) - 1, 2)])
    if decoder["kind"] == "cp1252":
        return bytes(c for c in codes if c < 256).decode("cp1252", "replace")
    table: dict[int, str] = decoder["table"]
    return "".join(table.get(c, "\ufffd") for c in codes)


def _hex_bytes(h: bytes) -> bytes:
    return bytes.fromhex(re.sub(rb"\s", b"", h).decode("ascii", "ignore"))


def _tj_array_decoded(arr: bytes, decoder: dict) -> str:
    parts: list[str] = []
    prev_was_string = False
    for sm in re.finditer(
            rb"(\((?:\\.|[^\\()])*\))|<([0-9A-Fa-f\s]+)>|(-?\d+(?:\.\d+)?)",
            arr):
        if sm.group(1) is not None:
            parts.append(_decode_codes(_unescape_literal(sm.group(1)),
                                       decoder))
            prev_was_string = True
        elif sm.group(2) is not None:
            try:
                parts.append(_decode_codes(_hex_bytes(sm.group(2)), decoder))
            except ValueError:
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


def _cmap_block_text(block: bytes, fonts: dict[str, dict], cur: list) -> str:
    """Font-tracked decoding of one BT..ET block. cur[0] = current font key."""
    parts: list[str] = []
    decoder = fonts.get(cur[0], {"kind": "cp1252", "table": {}, "width": 1})
    for m in _CMAP_OP_RE.finditer(block):
        if m.group(1) is not None:
            name = m.group(1).split()[0].decode("latin-1", "ignore")
            if name in fonts:
                cur[0] = name
                decoder = fonts[name]
        elif m.group(2) is not None:
            parts.append(_tj_array_decoded(m.group(2), decoder))
            parts.append(" ")
        elif m.group(3) is not None:
            parts.append(_decode_codes(_unescape_literal(m.group(3)), decoder))
        elif m.group(4) is not None:
            try:
                parts.append(_decode_codes(
                    _hex_bytes(m.group(4).strip(b"<>")), decoder))
            except ValueError:
                pass
        elif m.group(5) is not None or m.group(6) is not None \
                or m.group(7) is not None:
            parts.append("\n")
    return "".join(parts)


def _collect_decoders(objs: dict[tuple[int, int], bytes]
                      ) -> tuple[dict[str, dict], dict[str, str], dict]:
    """Resource font name -> decoder, plus document metadata.

    Decoder: {"kind": "cp1252"|"table", "table": {code: char}}.
    """
    fonts: dict[str, dict] = {}
    meta: dict[str, str] = {}
    info = {"tounicode_fonts": 0, "ttf_fonts": 0, "simple_fonts": 0, "pages": 0}
    for body in objs.values():
        m = re.search(rb"/Info\s+(\d+)\s+(\d+)\s+R", body)
        if m:
            ibody = objs.get((int(m.group(1)), int(m.group(2))))
            if ibody:
                for key in (b"Title", b"Author", b"Subject", b"Creator",
                            b"Producer", b"CreationDate", b"ModDate"):
                    km = re.search(rb"/" + key
                                   + rb"\s*(?:\((.*?)\)|<([0-9A-Fa-f\s]+)>)",
                                   ibody, re.S)
                    if km:
                        if km.group(1) is not None:
                            meta[key.decode()] = _decode_bytes(
                                _unescape_literal(b"(" + km.group(1) + b")"))
                        else:
                            try:
                                raw = bytes.fromhex(re.sub(
                                    rb"\s", b"", km.group(2)).decode("ascii"))
                                meta[key.decode()] = _decode_bytes(raw)
                            except ValueError:
                                pass
            break
    pages: list[tuple[dict[str, tuple[int, int]], list[tuple[int, int]]]] = []
    for _pkey, body in objs.items():
        if not re.search(rb"/Type\s*/Page(?!s)", body):
            continue
        info["pages"] += 1
        fbody = None
        seen = {_pkey}
        cursor: bytes | None = body
        # /Resources inherit down the page tree: walk /Parent refs.
        for _depth in range(6):
            if cursor is None:
                break
            fm = re.search(rb"/Font\s*<<(.*?)>>", cursor, re.S)
            if fm:
                fbody = fm.group(1)
                break
            rm = re.search(rb"/Resources\s+(\d+)\s+(\d+)\s+R", cursor)
            if rm:
                rbody = objs.get((int(rm.group(1)), int(rm.group(2))))
                if rbody:
                    fm2 = re.search(rb"/Font\s*<<(.*?)>>", rbody, re.S)
                    if fm2:
                        fbody = fm2.group(1)
                        break
            pm = re.search(rb"/Parent\s+(\d+)\s+(\d+)\s+R", cursor)
            if not pm:
                break
            pref = (int(pm.group(1)), int(pm.group(2)))
            if pref in seen:
                break
            seen.add(pref)
            cursor = objs.get(pref)
        resmap: dict[str, tuple[int, int]] = {}
        if fbody:
            for nm, a, b in re.findall(rb"(/[A-Za-z0-9+\-.]+)\s+(\d+)\s+(\d+)\s+R",
                                       fbody):
                resmap[nm.decode()] = (int(a), int(b))
        contents: list[tuple[int, int]] = []
        cm = re.search(rb"/Contents\s*(\[.*?\]|(?:\d+\s+\d+\s+R))", body, re.S)
        if cm:
            tok = cm.group(1)
            if tok.startswith(b"["):
                for a, b in re.findall(rb"(\d+)\s+(\d+)\s+R", tok):
                    contents.append((int(a), int(b)))
            else:
                mm = re.match(rb"\s*(\d+)\s+(\d+)\s+R", tok)
                if mm:
                    contents.append((int(mm.group(1)), int(mm.group(2))))
        pages.append((resmap, contents, body))
    cache: dict[tuple[int, int], dict] = {}

    def decoder_for(ref: tuple[int, int]) -> dict:
        if ref in cache:
            return cache[ref]
        dec: dict = {"kind": "cp1252", "table": {}, "width": 1}
        body = objs.get(ref)
        if body:
            dm = re.search(rb"/DescendantFonts\s*\[\s*(\d+)\s+(\d+)\s+R", body)
            fbody = objs.get((int(dm.group(1)), int(dm.group(2)))) if dm else body
            if fbody is None:
                fbody = body
            # /ToUnicode sits on the Type0 wrapper; /FontFile on the
            # descendant CIDFont. Check the wrapper first, then fall through.
            tm = re.search(rb"/ToUnicode\s+(\d+)\s+(\d+)\s+R", body)
            if tm is None:
                tm = re.search(rb"/ToUnicode\s+(\d+)\s+(\d+)\s+R", fbody)
            tu_table: dict[int, str] = {}
            if tm:
                tstream = _stream_bytes(
                    objs.get((int(tm.group(1)), int(tm.group(2)))))
                if tstream:
                    tu_table = _parse_tounicode(tstream)
            ttf_table: dict[int, str] = {}
            # TrueType cmap parsing is the slowest step here: attempt it only
            # when the ToUnicode map is absent or suspiciously small (a
            # truncated producer map must not block the embedded-font fallback).
            if len(tu_table) < 50:
                for pat in (rb"/FontFile2\s+(\d+)\s+(\d+)\s+R",
                            rb"/FontFile3\s+(\d+)\s+(\d+)\s+R",
                            rb"/FontFile\s+(\d+)\s+(\d+)\s+R"):
                    f2m = re.search(pat, fbody)
                    if f2m:
                        f2 = _stream_bytes(
                            objs.get((int(f2m.group(1)), int(f2m.group(2)))))
                        if f2:
                            ttf_table = _parse_ttf_cmap(f2)
                            if ttf_table:
                                break
            # Keep the larger map: a truncated ToUnicode prefix must not beat
            # a complete embedded-font cmap (seen on subset mono fonts), and a
            # richer ToUnicode beats a sparse cmap. Ties prefer ToUnicode.
            is_identity = b"Identity-H" in body or b"Identity-H" in fbody
            if len(ttf_table) > len(tu_table):
                dec = {"kind": "table", "table": ttf_table,
                       "width": 2 if (dm is not None or is_identity) else 1}
                info["ttf_fonts"] += 1
            elif tu_table:
                dec = {"kind": "table", "table": tu_table,
                       "width": 2 if is_identity else 1}
                info["tounicode_fonts"] += 1
            if dec["kind"] == "cp1252":
                if b"Identity-H" in body or b"Identity-H" in fbody:
                    # Unmapped Identity font: pair the bytes so later text at
                    # least keeps code alignment (still mojibake -- counted).
                    dec["width"] = 2
                info["simple_fonts"] += 1
        cache[ref] = dec
        return dec

    ordered: list[str] = []
    for resmap, _contents, _pagebody in pages:
        for name, ref in resmap.items():
            if name not in fonts:
                fonts[name] = decoder_for(ref)
                ordered.append(name)
    if not fonts and cache:
        fonts["/F0"] = next(iter(cache.values()))
        ordered.append("/F0")
    return fonts, meta, {"pages": pages, "info": info, "ordered": ordered}


def extract_text_cmap(data: bytes) -> tuple[str, dict] | None:
    """CMap-aware extraction. None when the object layer is unusable."""
    try:
        objs = _parse_objects(data)
    except Exception:
        return None
    if len(objs) < 5:
        return None
    try:
        fonts, meta, aux = _collect_decoders(objs)
    except Exception:
        return None
    pages = aux["pages"]
    if not pages or not fonts:
        return None
    ordered = aux["ordered"]
    first_font = ordered[0] if ordered else next(iter(fonts))
    chunks: list[str] = []
    nblocks = 0
    for _resmap, contents, pagebody in pages:
        cur = [first_font]
        seen_streams: set[bytes] = set()
        # Some producers inline the page content as the page object's own
        # stream while /Contents points at a stub (seen in Ackee reports):
        # prefer the object's own stream when it carries text.
        own = _stream_bytes(pagebody)
        bodies: list[bytes | None] = [own] + [objs.get(ref) for ref in contents]
        for body in bodies:
            if body is None:
                continue
            stream = _stream_bytes(body) if body is not own else own
            if stream is None or stream in seen_streams:
                continue
            seen_streams.add(stream)
            for bm in BT_RE.finditer(stream):
                nblocks += 1
                chunks.append(_cmap_block_text(bm.group(1), fonts, cur))
                chunks.append("\n")
    if nblocks == 0:
        return None
    text = "".join(chunks)
    text = re.sub(r"[ \t\x0b\x0c\r]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    stats = {"method": "cmap", "pages": aux["info"]["pages"],
             "fonts": len(fonts),
             "tounicode_fonts": aux["info"]["tounicode_fonts"],
             "ttf_fonts": aux["info"]["ttf_fonts"],
             "simple_fonts": aux["info"]["simple_fonts"],
             "text_blocks": nblocks, "chars": len(text.strip()),
             "meta": meta}
    return text.strip(), stats


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


def extract_text(data: bytes) -> tuple[str, dict]:
    """Return (text, stats). Deterministic; never raises on malformed input.

    Tries the CMap-aware path first, keeps whichever of the two paths scores
    higher on readability (with common-word hits as tiebreak), and records
    both scores. A low winning score means the file is genuinely hard
    (custom encoding without maps, or scanned images), not a bug to hide.
    """
    try:
        cmap_out = extract_text_cmap(data)
    except Exception:
        cmap_out = None
    stats = {"streams": 0, "flated": 0, "text_blocks": 0, "chars": 0,
             "undecoded_streams": 0}
    chunks: list[str] = []
    for m in STREAM_RE.finditer(data):
        stats["streams"] += 1
        payload = m.group(1).strip()
        try:
            decoded = zlib.decompress(payload)
            stats["flated"] += 1
        except Exception:
            # Not flate (images, already-raw content): skip, counted.
            stats["undecoded_streams"] += 1
            continue
        for bm in BT_RE.finditer(decoded):
            stats["text_blocks"] += 1
            chunks.append(_block_text(bm.group(1)))
            chunks.append("\n")
    naive = "".join(chunks)
    naive = re.sub(r"[ \t\x0b\x0c\r]+", " ", naive)
    naive = re.sub(r"\n\s*\n\s*\n+", "\n\n", naive).strip()
    stats["chars"] = len(naive)
    stats["readability_naive"] = round(readability(naive), 3)
    stats["word_hits_naive"] = word_hits(naive)
    if cmap_out is not None:
        ctext, cstats = cmap_out
        cstats["readability_cmap"] = round(readability(ctext), 3)
        cstats["word_hits_cmap"] = word_hits(ctext)
        stats.update({f"cmap_{k}": v for k, v in cstats.items()})
        # Readability decides at 2-decimal granularity (finer gaps are noise);
        # word hits then character count break ties, favouring the more
        # complete decoding rather than the shorter cleaner-looking one.
        ckey = (round(cstats["readability_cmap"], 2),
                cstats["word_hits_cmap"], len(ctext))
        nkey = (round(stats["readability_naive"], 2),
                stats["word_hits_naive"], len(naive))
        if ckey >= nkey:
            stats["method"] = cstats.get("method", "cmap")
            stats["chars"] = len(ctext)
            return ctext, stats
    stats["method"] = "naive"
    return naive, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf", help="PDF file to extract")
    ap.add_argument("--out", default=None, help="write text here (default: stdout)")
    ap.add_argument("--stats", action="store_true",
                    help="print JSON stats to stderr instead of text")
    args = ap.parse_args()
    data = Path(args.pdf).read_bytes()
    text, stats = extract_text(data)
    stats["file"] = str(args.pdf)
    stats["bytes"] = len(data)
    if args.stats:
        sys.stderr.write(json.dumps(stats, sort_keys=True) + "\n")
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    elif not args.stats:
        sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

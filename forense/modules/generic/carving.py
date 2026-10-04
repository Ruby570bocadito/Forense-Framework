"""File carving: recover files from raw images or unallocated space by their structure.

JPEG, PNG and GIF are validated by walking their internal structure (segments,
chunks, blocks), which avoids truncating JPEGs at an embedded thumbnail's end
marker. PDF ends at its first ``%%EOF`` and ZIP at its end-of-central-directory
record. Fragmented files cannot be recovered by this technique.
"""

from __future__ import annotations

import hashlib
import mmap
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from forense.modules.base import AnalysisContext, Module, Option, register

Finder = Callable[[mmap.mmap, int, int], Optional[int]]


def _jpeg_end(mm: mmap.mmap, start: int, limit: int) -> Optional[int]:
    pos = start + 2
    while pos + 2 <= limit:
        if mm[pos] != 0xFF:
            return None
        marker = mm[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD9:
            return pos + 2
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            pos += 2
            continue
        if pos + 4 > limit:
            return None
        length = struct.unpack_from(">H", mm, pos + 2)[0]
        if length < 2:
            return None
        pos += 2 + length
        if marker == 0xDA:  # start of scan: skip entropy-coded data
            while True:
                idx = mm.find(b"\xff", pos, limit - 1)
                if idx == -1:
                    return None
                nxt = mm[idx + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    pos = idx + 2
                elif nxt == 0xFF:
                    pos = idx + 1
                else:
                    pos = idx
                    break
    return None


def _png_end(mm: mmap.mmap, start: int, limit: int) -> Optional[int]:
    pos = start + 8
    while pos + 12 <= limit:
        length = struct.unpack_from(">I", mm, pos)[0]
        chunk_type = mm[pos + 4:pos + 8]
        if not chunk_type.isalpha():
            return None
        pos += 12 + length
        if chunk_type == b"IEND":
            return pos if pos <= limit else None
    return None


def _skip_subblocks(mm: mmap.mmap, pos: int, limit: int) -> Optional[int]:
    while pos < limit:
        size = mm[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size
    return None


def _gif_end(mm: mmap.mmap, start: int, limit: int) -> Optional[int]:
    pos = start + 6
    if pos + 7 > limit:
        return None
    packed = mm[pos + 4]
    pos += 7
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    while pos is not None and pos < limit:
        block = mm[pos]
        if block == 0x3B:
            return pos + 1
        if block == 0x21:
            pos = _skip_subblocks(mm, pos + 2, limit)
        elif block == 0x2C:
            if pos + 10 > limit:
                return None
            packed = mm[pos + 9]
            pos += 10
            if packed & 0x80:
                pos += 3 * (2 ** ((packed & 0x07) + 1))
            pos = _skip_subblocks(mm, pos + 1, limit)
        else:
            return None
    return None


def _pdf_end(mm: mmap.mmap, start: int, limit: int) -> Optional[int]:
    idx = mm.find(b"%%EOF", start, limit)
    if idx == -1:
        return None
    end = idx + 5
    for newline in (b"\r\n", b"\n", b"\r"):
        if mm[end:end + len(newline)] == newline:
            return end + len(newline)
    return end


def _zip_end(mm: mmap.mmap, start: int, limit: int) -> Optional[int]:
    idx = mm.find(b"PK\x05\x06", start, limit)
    if idx == -1 or idx + 22 > limit:
        return None
    end = idx + 22 + struct.unpack_from("<H", mm, idx + 20)[0]
    return end if end <= limit else None


@dataclass(frozen=True)
class CarveSpec:
    ext: str
    headers: tuple[bytes, ...]
    max_size: int
    finder: Finder


SPECS = {
    "jpg": CarveSpec("jpg", (b"\xff\xd8\xff",), 30 * 1024 * 1024, _jpeg_end),
    "png": CarveSpec("png", (b"\x89PNG\r\n\x1a\n",), 30 * 1024 * 1024, _png_end),
    "gif": CarveSpec("gif", (b"GIF87a", b"GIF89a"), 10 * 1024 * 1024, _gif_end),
    "pdf": CarveSpec("pdf", (b"%PDF-",), 100 * 1024 * 1024, _pdf_end),
    "zip": CarveSpec("zip", (b"PK\x03\x04",), 200 * 1024 * 1024, _zip_end),
}


@register
class CarvingModule(Module):
    name = "carving"
    category = "generic"
    targets = ("file",)
    options = (
        Option("types", tuple(SPECS), "list"),
        Option("max_files", 10000, "int"),
    )

    def analyze(self, ctx: AnalysisContext) -> None:
        types = [t for t in ctx.options["types"] if t in SPECS]
        out_dir = ctx.output_dir / "carved"
        out_dir.mkdir(exist_ok=True)
        limit_files = ctx.options["max_files"]
        found: dict[str, int] = {t: 0 for t in types}
        with open(ctx.target, "rb") as fh:
            size = fh.seek(0, 2)
            if size == 0:
                ctx.summary.update({"image_size": 0, "carved": 0})
                return
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                total = 0
                for ext in types:
                    spec = SPECS[ext]
                    for header in spec.headers:
                        pos = mm.find(header)
                        while pos != -1 and total < limit_files:
                            end = spec.finder(mm, pos, min(pos + spec.max_size, size))
                            if end is None:
                                pos = mm.find(header, pos + 1)
                                continue
                            data = mm[pos:end]
                            name = f"{ext}_{pos:012x}.{ext}"
                            (out_dir / name).write_bytes(data)
                            ctx.add_artifact(out_dir / name)
                            digest = hashlib.sha256(data).hexdigest()
                            ctx.record("carved_file", {"name": f"carved/{name}", "type": ext, "offset": pos,
                                                       "end_offset": end, "size": end - pos, "sha256": digest})
                            found[ext] += 1
                            total += 1
                            pos = mm.find(header, end)
                    ctx.progress(f"{ext}: {found[ext]}")
        ctx.summary.update({"image_size": size, "carved": sum(found.values()), "per_type": found})

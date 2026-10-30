"""RDP Bitmap Cache (Cache*.bin / bCache*.bin): historical evidence of Remote Desktop sessions.

The Remote Desktop client keeps tiles of the remote screen it drew in
``Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\``. The container is
headerless-of-metadata: a 12-byte file header and then raw tiles (8-byte key, width, height, a
40-byte BITMAPINFOHEADER and the pixels bottom-up). Reassembling the tiles shows fragments of
what was on the remote screen, so they are saved as BMP artifacts for the report. No timestamps
exist inside the container: the evidence is the activity itself, not when it happened.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from sabueso.core.utils import find_files, read_capped, relative_name
from sabueso.modules.base import AnalysisContext, Module, register

_CACHE_NAME = re.compile(r"^b?cache\d{3,4}\.bin$", re.IGNORECASE)
FILE_HEADER = 12
MAX_CACHE_FILE = 256 * 1024 * 1024  # real cache containers are kilobytes; a bigger one is not one
TILE_HEADER = 8
INFO_HEADER = 40
MAX_DIMENSION = 2048
MAX_TILES = 65535
_BIT_COUNTS = {16, 24, 32}


def _pixel_size(width: int, height: int, bit_count: int) -> int:
    row = ((width * bit_count + 31) // 32) * 4  # rows are DWORD-aligned in BMP
    return row * height


def _tile_at(data: bytes, offset: int) -> tuple[int, int, int, int, int] | None:
    """(width, height, bit_count, pixels_offset, total_size) of the tile at ``offset``, or None."""
    if offset + TILE_HEADER + 4 > len(data):
        return None
    width, height = struct.unpack_from("<HH", data, offset + TILE_HEADER)
    if not (0 < width <= MAX_DIMENSION and 0 < height <= MAX_DIMENSION):
        return None
    info = offset + TILE_HEADER + 4
    if info + INFO_HEADER > len(data):
        return None
    info_size = struct.unpack_from("<I", data, info)[0]
    bit_count = struct.unpack_from("<H", data, info + 14)[0]  # after biSize, biWidth, biHeight, biPlanes
    if info_size != INFO_HEADER or bit_count not in _BIT_COUNTS:
        return None
    total = TILE_HEADER + 4 + info_size + _pixel_size(width, height, bit_count)
    if offset + total > len(data):
        return None
    return width, height, bit_count, info + info_size, total


def _save_tile(ctx: AnalysisContext, path: Path, index: int, data: bytes,
               width: int, height: int, bit_count: int, pixels: int) -> Path:
    """Write the tile as a standalone BMP (14-byte file header + its info header + pixels)."""
    out = ctx.output_dir / f"{path.stem}_Tile_{index:03d}.bmp"
    row = ((width * bit_count + 31) // 32) * 4
    body = data[pixels:pixels + row * height]
    header = struct.pack("<2sIHHI", b"BM", 14 + INFO_HEADER + len(body), 0, 0, 14 + INFO_HEADER)
    info = data[pixels - INFO_HEADER:pixels]
    out.write_bytes(header + info + body)
    ctx.add_artifact(out)
    return out


@register
class RDPCacheModule(Module):
    name = "rdp_cache"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: bool(_CACHE_NAME.match(p.name.lower())))

    def analyze(self, ctx: AnalysisContext) -> None:
        tiles_total = 0
        per_file: dict[str, int] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                if path.stat().st_size <= FILE_HEADER:
                    continue
                data = read_capped(path, MAX_CACHE_FILE)
            except (OSError, ValueError) as exc:  # FileTooLarge included: the container is not a cache
                ctx.error(rel, exc)
                continue
            count = 0
            offset = FILE_HEADER
            while offset + TILE_HEADER + 4 <= len(data) and count < MAX_TILES:
                tile = _tile_at(data, offset)
                if tile is None:
                    break  # a corrupt tile ends the chain: everything before it is still evidence
                width, height, bit_count, pixels, total = tile
                count += 1
                tiles_total += 1
                key1, key2 = struct.unpack_from("<II", data, offset)
                saved = _save_tile(ctx, path, count, data, width, height, bit_count, pixels)
                ctx.record("rdp_tile", {
                    "file": rel, "tile": count, "key": f"{key1:08x}{key2:08x}", "width": width,
                    "height": height, "bpp": bit_count, "offset": offset, "saved_to": saved.name,
                })
                offset += total
            if count:
                per_file[rel] = count
                ctx.finding("rdp_cache.historic_activity", "low", None, file=rel, tiles=count)
        ctx.summary.update({"tiles": tiles_total, "cache_files": per_file})

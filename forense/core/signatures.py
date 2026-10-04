"""File type identification by magic bytes and extension mismatch detection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

HEADER_SIZE = 64


@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    extensions: frozenset
    offset: int = 0

    def matches(self, header: bytes) -> bool:
        return header[self.offset:self.offset + len(self.magic)] == self.magic


def _sig(name: str, magic: bytes, extensions: str, offset: int = 0, empty_ok: bool = False) -> Signature:
    """``empty_ok``: files of this type commonly have no extension (SYSTEM, History, $MFT...)."""
    exts = set(extensions.split())
    if empty_ok:
        exts.add("")
    return Signature(name, magic, frozenset(exts), offset)


# Most specific signatures first.
SIGNATURES: tuple[Signature, ...] = (
    _sig("SQLite", b"SQLite format 3\x00", "sqlite sqlite3 db db3 sqlitedb", empty_ok=True),
    _sig("OLE2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "doc xls ppt msg msi db pub vsd automaticdestinations-ms"),
    _sig("PNG", b"\x89PNG\r\n\x1a\n", "png"),
    _sig("7-Zip", b"7z\xbc\xaf\x27\x1c", "7z"),
    _sig("RAR", b"Rar!\x1a\x07", "rar"),
    _sig("EVTX", b"ElfFile\x00", "evtx"),
    _sig("LNK", b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    _sig("GIF", b"GIF87a", "gif"),
    _sig("GIF", b"GIF89a", "gif"),
    _sig("PDF", b"%PDF-", "pdf"),
    _sig("Registry hive", b"regf", "dat hve sav", empty_ok=True),
    _sig("NTFS MFT", b"FILE0", "mft", empty_ok=True),
    _sig("Prefetch (MAM)", b"MAM\x04", "pf"),
    _sig("Prefetch", b"SCCA", "pf", offset=4),
    _sig("PCAPNG", b"\x0a\x0d\x0d\x0a", "pcapng"),
    _sig("PCAP", b"\xd4\xc3\xb2\xa1", "pcap cap"),
    _sig("PCAP", b"\xa1\xb2\xc3\xd4", "pcap cap"),
    _sig("ELF", b"\x7fELF", "so o elf bin axf ko", empty_ok=True),
    _sig("ZIP", b"PK\x03\x04", "zip docx xlsx pptx jar apk odt ods odp epub vsdx xpi nupkg whl "
         "ipa xps oxps kmz appx msix vsix appxbundle msixbundle 3mf"),
    _sig("JPEG", b"\xff\xd8\xff", "jpg jpeg jpe jfif"),
    _sig("TIFF", b"II*\x00", "tif tiff"),
    _sig("TIFF", b"MM\x00*", "tif tiff"),
    _sig("GZIP", b"\x1f\x8b\x08", "gz tgz svgz emz"),
    _sig("BZIP2", b"BZh", "bz2 tbz2"),
    _sig("MP3", b"ID3", "mp3"),
    _sig("RIFF", b"RIFF", "wav avi webp ani"),
    _sig("MP4/QuickTime", b"ftyp", "mp4 m4a m4v mov 3gp heic heif avif", offset=4),
    _sig("Windows PE", b"MZ", "exe dll sys scr com ocx cpl efi drv mui ax tlb pyd node winmd ime msstyles"),
)

# Extensions used by several unrelated formats: having no signature is not suspicious.
_AMBIGUOUS = frozenset("dat db bin o so com elf log sav cap tlb".split()) | {""}
_EXPECT_SIGNATURE = frozenset().union(*(s.extensions for s in SIGNATURES)) - _AMBIGUOUS


def read_header(path: Path, size: int = HEADER_SIZE) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(size)


def detect(header: bytes) -> Optional[Signature]:
    for signature in SIGNATURES:
        if signature.matches(header):
            return signature
    return None


def extension_of(path: Path) -> str:
    return Path(path).suffix.lower().lstrip(".")


def check_extension(path: Path, header: bytes) -> tuple[Optional[Signature], Optional[str]]:
    """Return ``(signature, reason)``; ``reason`` is set when content and extension disagree.

    Reasons are stable codes: ``content_mismatch`` (the content is a known type
    that does not use this extension) or ``missing_signature`` (the extension
    belongs to a type with a signature but the content does not have it).
    """
    signature = detect(header)
    ext = extension_of(path)
    if not header:
        return None, None
    if signature is not None:
        if ext not in signature.extensions:
            return signature, "content_mismatch"
        return signature, None
    if ext in _EXPECT_SIGNATURE:
        return None, "missing_signature"
    return None, None

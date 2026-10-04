"""Disk images (E01/Ex01, raw/dd, split raw, fixed VHD) and file system access through The Sleuth Kit.

Used to extract the forensically relevant Windows artifacts from an image (or,
by the live collector, from a raw volume such as ``\\\\.\\C:``) without mounting
it, so that locked files ($MFT, registry hives, SRUM, event logs) are read
directly from NTFS.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Optional

from forense.core.errors import ForenseError
from forense.core.utils import ts_to_iso

EWF_SIGNATURES = (b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00")
IMAGE_SUFFIXES = {".e01", ".ex01", ".dd", ".raw", ".img", ".001", ".vhd", ".bin", ".iso"}
CHUNK = 4 * 1024 * 1024

# Paths (relative to the root of each NTFS volume) collected by the triage profile.
TRIAGE_PATTERNS = (
    "$MFT",
    "Windows/System32/config/SAM", "Windows/System32/config/SAM.LOG*",
    "Windows/System32/config/SYSTEM", "Windows/System32/config/SYSTEM.LOG*",
    "Windows/System32/config/SOFTWARE", "Windows/System32/config/SOFTWARE.LOG*",
    "Windows/System32/config/SECURITY", "Windows/System32/config/SECURITY.LOG*",
    "Windows/System32/config/DEFAULT",
    "Windows/System32/winevt/Logs/*.evtx",
    "Windows/System32/sru/SRUDB.dat",
    "Windows/System32/Tasks/**",
    "Windows/Prefetch/*.pf",
    "Windows/appcompat/Programs/Amcache.hve", "Windows/appcompat/Programs/Amcache.hve.LOG*",
    "Windows/inf/setupapi.dev.log",
    "Users/*/NTUSER.DAT", "Users/*/NTUSER.DAT.LOG*",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat", "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG*",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/**",
    "Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*",
    "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/*",
    "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/*.txt",
    "Users/*/AppData/Local/Google/Chrome/User Data/*/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History",
    "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data/*/History",
    "Users/*/AppData/Roaming/Opera Software/*/History",
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite-wal",
    "$Recycle.Bin/*/$I*",
    "Users/Public/**/*.exe", "Users/*/AppData/Local/Temp/*.exe", "Users/*/Downloads/*.exe",
    "Windows/Temp/*.exe", "Windows/Temp/*.ps1", "Users/*/AppData/Local/Temp/*.ps1",
)


class ImageError(ForenseError):
    pass


def is_disk_image(path: Path) -> bool:
    path = Path(path)
    if not path.is_file():
        return False
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head in EWF_SIGNATURES:
        return True
    if path.suffix.lower() not in IMAGE_SUFFIXES:
        return False
    with open(path, "rb") as fh:  # MBR/GPT or a file system boot sector
        fh.seek(510)
        return fh.read(2) == b"\x55\xaa" or path.suffix.lower() in (".dd", ".raw", ".img", ".001")


def find_image(target: Path) -> Path:
    """The image file of an evidence item (the file itself or the first segment in a folder)."""
    target = Path(target)
    if target.is_file():
        return target
    candidates = sorted(p for p in target.iterdir() if p.is_file() and p.suffix.lower() in (".e01", ".ex01", ".001",
                                                                                            ".dd", ".raw", ".img"))
    if not candidates:
        raise ImageError("error.image_not_found", path=str(target))
    return candidates[0]


@dataclass
class ImageInfo:
    path: str
    format: str
    size: int
    sector_size: int = 512
    segments: list[str] = field(default_factory=list)
    stored_hashes: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)


def open_image(path: Path):
    """Open an image and return ``(pytsk3 Img_Info, ImageInfo)``."""
    import pytsk3

    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(8)
        fh.seek(-512, 2)
        footer = fh.read(512)
    if head in EWF_SIGNATURES:
        import pyewf

        segments = pyewf.glob(str(path))
        handle = pyewf.handle()
        handle.open(segments)
        hashes = {k.lower(): v for k, v in (handle.get_hash_values() or {}).items() if v}
        headers = {k: v for k, v in (handle.get_header_values() or {}).items() if v}
        info = ImageInfo(str(path), "ewf", handle.get_media_size(), handle.get_bytes_per_sector(),
                         [Path(s).name for s in segments], hashes, headers)
        return _HandleImage(pytsk3, handle.read, handle.seek, handle.get_media_size(), handle.close), info
    if footer[:8] == b"conectix":
        disk_type = int.from_bytes(footer[60:64], "big")
        if disk_type != 2:
            raise ImageError("error.image_vhd_dynamic", path=str(path))
        size = path.stat().st_size - 512
        fh = open(path, "rb")
        return _FileImage(pytsk3, [fh], [size]), ImageInfo(str(path), "vhd", size)
    if re.search(r"\.0*1$", path.name):  # split raw: .001, .002...
        stem = path.name[: path.name.rfind(".")]
        parts = sorted(p for p in path.parent.iterdir() if re.fullmatch(re.escape(stem) + r"\.\d+", p.name))
        handles = [open(p, "rb") for p in parts]
        sizes = [p.stat().st_size for p in parts]
        return _FileImage(pytsk3, handles, sizes), ImageInfo(str(path), "raw", sum(sizes),
                                                             segments=[p.name for p in parts])
    img = pytsk3.Img_Info(str(path))
    return img, ImageInfo(str(path), "raw", img.get_size())


def _HandleImage(pytsk3, read, seek, size, close):
    class HandleImage(pytsk3.Img_Info):
        def __init__(self) -> None:
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):  # noqa: D401 - pytsk3 callback
            seek(offset)
            return read(length)

        def get_size(self):
            return size

        def close(self):
            close()

    return HandleImage()


def _FileImage(pytsk3, handles, sizes):
    starts = [sum(sizes[:i]) for i in range(len(sizes))]
    total = sum(sizes)

    class FileImage(pytsk3.Img_Info):
        def __init__(self) -> None:
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):
            out = bytearray()
            while length > 0 and offset < total:
                index = max(i for i, s in enumerate(starts) if s <= offset)
                local = offset - starts[index]
                handles[index].seek(local)
                chunk = handles[index].read(min(length, sizes[index] - local))
                if not chunk:
                    break
                out += chunk
                offset += len(chunk)
                length -= len(chunk)
            return bytes(out)

        def get_size(self):
            return total

        def close(self):
            for handle in handles:
                handle.close()

    return FileImage()


@dataclass
class Partition:
    index: int
    offset: int
    length: int
    description: str
    filesystem: str = ""


def _fs_name(fs) -> str:
    import pytsk3

    names: dict[int, str] = {}
    for name in sorted((n for n in dir(pytsk3) if n.startswith("TSK_FS_TYPE_")), key=lambda n: "DETECT" not in n):
        value = getattr(pytsk3, name)
        if isinstance(value, int):
            names[value] = name.replace("TSK_FS_TYPE_", "").lower()
    return names.get(int(fs.info.ftype), str(fs.info.ftype))


def filesystems(img) -> Iterator[tuple[Partition, object]]:
    """Yield ``(partition, FS_Info)`` for every readable file system in the image."""
    import pytsk3

    found = False
    try:
        volumes = pytsk3.Volume_Info(img)
        block = volumes.info.block_size
        for part in volumes:
            if not part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                continue
            partition = Partition(int(part.addr), int(part.start) * block, int(part.len) * block,
                                  part.desc.decode(errors="replace"))
            try:
                fs = pytsk3.FS_Info(img, offset=partition.offset)
            except OSError:
                continue
            partition.filesystem = _fs_name(fs)
            found = True
            yield partition, fs
    except OSError:
        pass
    if not found:
        try:
            fs = pytsk3.FS_Info(img, offset=0)
        except OSError as exc:
            raise ImageError("error.image_no_filesystem", error=str(exc).splitlines()[0]) from exc
        yield Partition(0, 0, img.get_size(), "volume", _fs_name(fs)), fs


@dataclass
class ExtractedFile:
    source: str  # path inside the file system (/Windows/...)
    dest: Path
    size: int
    sha256: str
    md5: str
    mtime: Optional[str]
    atime: Optional[str]
    ctime: Optional[str]
    crtime: Optional[str]
    inode: int


def _matches(segments: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    if not pattern:
        return not segments
    head, *rest = pattern
    if head == "**":
        return any(_matches(segments[i:], tuple(rest)) for i in range(len(segments) + 1))
    return bool(segments) and fnmatch.fnmatch(segments[0].lower(), head.lower()) and _matches(segments[1:], tuple(rest))


def _could_match(segments: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    """Whether a directory at ``segments`` can contain matches of ``pattern``."""
    for i, seg in enumerate(segments):
        if i >= len(pattern):
            return False
        if pattern[i] == "**":
            return True
        if not fnmatch.fnmatch(seg.lower(), pattern[i].lower()):
            return False
    return True


class Extractor:
    """Copy files matching glob patterns out of a TSK file system, preserving paths and timestamps."""

    def __init__(self, fs, dest: Path, patterns: tuple[str, ...] = TRIAGE_PATTERNS, max_file_size: int = 4 * 1024 ** 3,
                 on_error: Optional[Callable[[str, BaseException], None]] = None,
                 progress: Optional[Callable[[str], None]] = None) -> None:
        self.fs = fs
        self.dest = Path(dest)
        self.patterns = [tuple(p.split("/")) for p in patterns]
        self.max_file_size = max_file_size
        self.on_error = on_error
        self.progress = progress

    def run(self) -> list[ExtractedFile]:
        results: list[ExtractedFile] = []
        self._walk("/", (), results, depth=0)
        return results

    def _walk(self, path: str, segments: tuple[str, ...], results: list, depth: int) -> None:
        import pytsk3

        if depth > 64:
            return
        try:
            directory = self.fs.open_dir(path=path)
        except OSError as exc:
            if self.on_error:
                self.on_error(path, exc)
            return
        for entry in directory:
            name = entry.info.name.name.decode("utf-8", errors="replace")
            if name in (".", "..") or entry.info.meta is None:
                continue
            if entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                continue
            child = segments + (name,)
            child_path = f"{path.rstrip('/')}/{name}"
            meta_type = entry.info.meta.type
            if meta_type == pytsk3.TSK_FS_META_TYPE_DIR:
                if name == "$OrphanFiles" or not any(_could_match(child, p) for p in self.patterns):
                    continue
                self._walk(child_path, child, results, depth + 1)
            elif meta_type == pytsk3.TSK_FS_META_TYPE_REG and any(_matches(child, p) for p in self.patterns):
                extracted = self._extract(entry, child_path, child)
                if extracted:
                    results.append(extracted)

    def _extract(self, entry, source: str, segments: tuple[str, ...]) -> Optional[ExtractedFile]:
        meta = entry.info.meta
        size = int(meta.size)
        if size > self.max_file_size:
            return None
        safe = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", s) for s in segments]
        dest = self.dest.joinpath(*safe)
        dest.parent.mkdir(parents=True, exist_ok=True)
        sha256, md5 = hashlib.sha256(), hashlib.md5()
        if self.progress:
            self.progress(source)
        try:
            with open(dest, "wb") as out:
                offset = 0
                while offset < size:
                    data = entry.read_random(offset, min(CHUNK, size - offset))
                    if not data:
                        break
                    out.write(data)
                    sha256.update(data)
                    md5.update(data)
                    offset += len(data)
        except OSError as exc:
            if self.on_error:
                self.on_error(source, exc)
            return None
        times = {k: getattr(meta, k, 0) or None for k in ("mtime", "atime", "ctime", "crtime")}
        if times["mtime"]:
            os.utime(dest, (times["atime"] or times["mtime"], times["mtime"]))
        return ExtractedFile(source, dest, size, sha256.hexdigest(), md5.hexdigest(),
                             *(ts_to_iso(times[k]) if times[k] else None for k in ("mtime", "atime", "ctime", "crtime")),
                             int(meta.addr))


def verify_media(img, info: ImageInfo, progress: Optional[Callable[[int], None]] = None) -> dict:
    """Hash the media data and compare with the hashes stored in the image (EWF)."""
    md5, sha1 = hashlib.md5(), hashlib.sha1()
    offset, size = 0, info.size
    while offset < size:
        data = img.read(offset, min(CHUNK, size - offset))
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        offset += len(data)
        if progress:
            progress(offset)
    computed = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest()}
    compared = {k: computed[k] == v.lower() for k, v in info.stored_hashes.items() if k in computed}
    return {"computed": computed, "stored": info.stored_hashes, "match": all(compared.values()) if compared else None}


def volume_label(partition: Partition, index: int) -> str:
    """Folder name for an extracted volume: C, D... for the first NTFS volumes."""
    return chr(ord("C") + index) if index < 23 else f"volume{partition.index}"


def posix(path: str) -> str:
    return str(PurePosixPath(path))

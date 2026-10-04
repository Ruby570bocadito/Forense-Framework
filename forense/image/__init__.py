"""Disk images and file system access through The Sleuth Kit.

Containers: E01/Ex01 (libewf), raw/dd, split raw, VHD and VHDX of every type
(fixed, dynamic, differencing; libvhdi), VMDK (libvmdk) and QCOW2 (libqcow).
Inside them: MBR/GPT partitions, BitLocker volumes (libbde, with a recovery
password, password or startup key) and volume shadow copies (libvshadow).

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
from forense.core.utils import iso, ts_to_iso

EWF_SIGNATURES = (b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00")
IMAGE_SUFFIXES = {".e01", ".ex01", ".dd", ".raw", ".img", ".001", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".qcow",
                  ".bin", ".iso"}
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
    "$Extend/$UsnJrnl:$J",
    "Windows/System32/wbem/Repository/OBJECTS.DATA",
    "Windows/System32/wbem/Repository/INDEX.BTR", "Windows/System32/wbem/Repository/MAPPING*.MAP",
    "Windows/inf/setupapi*.log",
    "Users/*/AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db*",
    "Users/Public/**/*.exe", "Users/*/AppData/Local/Temp/*.exe", "Users/*/Downloads/*.exe",
    "Windows/Temp/*.exe", "Windows/Temp/*.ps1", "Users/*/AppData/Local/Temp/*.ps1",
)


class ImageError(ForenseError):
    pass


def _container(head: bytes, footer: bytes) -> Optional[str]:
    if head[:8] in EWF_SIGNATURES:
        return "ewf"
    if head[:8] == b"vhdxfile":
        return "vhdx"
    if footer[:8] == b"conectix" or head[:8] == b"conectix":
        return "vhd"
    if head[:4] == b"KDMV" or b"# Disk DescriptorFile" in head:
        return "vmdk"
    if head[:4] == b"QFI\xfb":
        return "qcow2"
    return None


def _probe(path: Path) -> tuple[bytes, bytes]:
    with open(path, "rb") as fh:
        head = fh.read(1024)
        size = fh.seek(0, 2)
        fh.seek(max(0, size - 512))
        footer = fh.read(512)
    return head, footer


def is_disk_image(path: Path) -> bool:
    path = Path(path)
    if not path.is_file():
        return False
    head, footer = _probe(path)
    if _container(head, footer):
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
    candidates = sorted(p for p in target.iterdir() if p.is_file() and p.suffix.lower() in (
        ".e01", ".ex01", ".001", ".dd", ".raw", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2"))
    # a differencing disk is preferred to its parent; a VMDK descriptor to its extents
    candidates.sort(key=lambda p: ("-flat" in p.stem or re.search(r"-s\d{3}$", p.stem) is not None, p.name))
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
    head, footer = _probe(path)
    kind = _container(head, footer)
    if kind == "ewf":
        import pyewf

        segments = pyewf.glob(str(path))
        handle = pyewf.handle()
        handle.open(segments)
        hashes = {k.lower(): v for k, v in (handle.get_hash_values() or {}).items() if v}
        headers = {k: v for k, v in (handle.get_header_values() or {}).items() if v}
        info = ImageInfo(str(path), "ewf", handle.get_media_size(), handle.get_bytes_per_sector(),
                         [Path(s).name for s in segments], hashes, headers)
        return _HandleImage(pytsk3, handle, handle.get_media_size()), info
    if kind in ("vhd", "vhdx", "vmdk", "qcow2"):
        handle, files, keep = _open_virtual_disk(path, kind)
        info = ImageInfo(str(path), kind, handle.get_media_size(), segments=[p.name for p in files],
                         headers={"disk_type": _disk_type(handle, kind)} if kind != "qcow2" else {})
        return _HandleImage(pytsk3, handle, handle.get_media_size(), keep=keep), info
    if re.search(r"\.0*1$", path.name):  # split raw: .001, .002...
        stem = path.name[: path.name.rfind(".")]
        parts = sorted(p for p in path.parent.iterdir() if re.fullmatch(re.escape(stem) + r"\.\d+", p.name))
        handles = [open(p, "rb") for p in parts]
        sizes = [p.stat().st_size for p in parts]
        return _FileImage(pytsk3, handles, sizes), ImageInfo(str(path), "raw", sum(sizes),
                                                             segments=[p.name for p in parts])
    img = pytsk3.Img_Info(str(path))
    return img, ImageInfo(str(path), "raw", img.get_size())


def _disk_type(handle, kind: str) -> str:
    value = getattr(handle, "disk_type", None)
    names = {"vhd": {2: "fixed", 3: "dynamic", 4: "differencing"}, "vhdx": {2: "fixed", 3: "dynamic",
                                                                              4: "differencing"}}
    return names.get(kind, {}).get(value, str(value) if value is not None else "")


def _open_virtual_disk(path: Path, kind: str, depth: int = 0) -> tuple[object, list[Path], list]:
    """Open a VHD/VHDX/VMDK/QCOW2 file and, for differencing disks, its chain of parents."""
    if depth > 16:
        raise ImageError("error.image_parent_missing", path=str(path), parent="(loop)")
    if kind in ("vhd", "vhdx"):
        import pyvhdi

        handle = pyvhdi.file()
        handle.open(str(path))
        parent_name = handle.parent_filename if handle.disk_type == 4 else None
    elif kind == "vmdk":
        import pyvmdk

        handle = pyvmdk.handle()
        handle.open(str(path))
        handle.open_extent_data_files()
        parent_name = handle.parent_filename
    else:
        import pyqcow

        handle = pyqcow.file()
        handle.open(str(path))
        parent_name = handle.backing_filename
    files: list[Path] = [path]
    keep: list = []
    if parent_name:
        parent = path.parent / re.split(r"[\\/]", parent_name)[-1]
        if not parent.is_file():
            raise ImageError("error.image_parent_missing", path=str(path), parent=parent_name)
        parent_head, parent_footer = _probe(parent)
        parent_handle, parent_files, parent_keep = _open_virtual_disk(
            parent, _container(parent_head, parent_footer) or kind, depth + 1)
        handle.set_parent(parent_handle)
        files += parent_files
        keep += [parent_handle, *parent_keep]  # parents must outlive the child handle
    return handle, files, keep


def _HandleImage(pytsk3, handle, size: int, keep: Optional[list] = None):
    """pytsk3 image over any object with ``read_buffer_at_offset`` (libyal handles, shadow copies...)."""

    class HandleImage(pytsk3.Img_Info):
        def __init__(self) -> None:
            self._keep = [handle, *(keep or [])]
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, length):  # noqa: D401 - pytsk3 callback
            return handle.read_buffer_at_offset(length, offset)

        def get_size(self):
            return size

        def close(self):
            for item in self._keep:  # the handle first, then the parents of a differencing disk
                if hasattr(item, "close"):
                    try:
                        item.close()
                    except OSError:
                        pass

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


class VolumeWindow:
    """File-like view of ``length`` bytes at ``offset`` of a pytsk3 image (for libbde and libvshadow)."""

    def __init__(self, img, offset: int, length: int) -> None:
        self.img, self.offset, self.length, self.position = img, offset, length, 0

    def read(self, size: int = -1) -> bytes:
        size = self.length - self.position if size is None or size < 0 else min(size, self.length - self.position)
        if size <= 0:
            return b""
        data = self.img.read(self.offset + self.position, size)
        self.position += len(data)
        return data

    def read_buffer_at_offset(self, size: int, offset: int) -> bytes:
        self.position = offset
        return self.read(size)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        base = {os.SEEK_SET: 0, os.SEEK_CUR: self.position, os.SEEK_END: self.length}[whence]
        self.position = max(0, base + offset)
        return self.position

    def tell(self) -> int:
        return self.position

    def get_offset(self) -> int:
        return self.position

    def get_size(self) -> int:
        return self.length


@dataclass
class Partition:
    index: int
    offset: int
    length: int
    description: str
    filesystem: str = ""
    encryption: str = ""  # "bitlocker" when the volume was decrypted (or is still locked)
    locked: bool = False
    volume: object = field(default=None, repr=False)  # pytsk3 image of the (decrypted) volume


@dataclass
class ShadowCopy:
    index: int
    identifier: str
    created: Optional[str]
    size: int
    img: object = field(repr=False)


def _fs_name(fs) -> str:
    import pytsk3

    names: dict[int, str] = {}
    for name in sorted((n for n in dir(pytsk3) if n.startswith("TSK_FS_TYPE_")), key=lambda n: "DETECT" not in n):
        value = getattr(pytsk3, name)
        if isinstance(value, int):
            names[value] = name.replace("TSK_FS_TYPE_", "").lower()
    return names.get(int(fs.info.ftype), str(fs.info.ftype))


def _volume_image(img, offset: int, length: int):
    """pytsk3 image of one volume of ``img`` (so shadow copies and BitLocker can address it from 0)."""
    import pytsk3

    if offset == 0 and length == img.get_size():
        return img
    return _HandleImage(pytsk3, VolumeWindow(img, offset, length), length)


def _unlock_bitlocker(volume_img, length: int, keys: dict):
    """Decrypted image of a BitLocker volume, ``"locked"`` without valid keys, or None if not BitLocker."""
    import pybde
    import pytsk3

    window = VolumeWindow(volume_img, 0, length)
    if not pybde.check_volume_signature_file_object(window):
        return None
    volume = pybde.volume()
    if keys.get("recovery_password"):
        volume.set_recovery_password(keys["recovery_password"])
    if keys.get("password"):
        volume.set_password(keys["password"])
    if keys.get("startup_key"):
        volume.read_startup_key(str(keys["startup_key"]))
    try:
        volume.open_file_object(window)
        if volume.is_locked():
            volume.unlock()
    except OSError:
        return "locked"
    if volume.is_locked():
        return "locked"
    return _HandleImage(pytsk3, volume, volume.get_size(), keep=[window])


def filesystems(img, bitlocker: Optional[dict] = None,
                locked: Optional[list] = None) -> Iterator[tuple[Partition, object]]:
    """Yield ``(partition, FS_Info)`` for every readable file system in the image.

    BitLocker volumes are decrypted with ``bitlocker`` keys (``recovery_password``,
    ``password`` or ``startup_key``); volumes that stay locked are appended to ``locked``.
    """
    import pytsk3

    def open_volume(partition: Partition):
        volume = _volume_image(img, partition.offset, partition.length)
        # BitLocker first: BitLocker To Go volumes also carry a readable FAT "discovery volume".
        decrypted = _unlock_bitlocker(volume, partition.length, bitlocker or {})
        if decrypted == "locked":
            partition.encryption, partition.locked = "bitlocker", True
            if locked is not None:
                locked.append(partition)
            return None
        if decrypted is not None:
            partition.encryption, volume = "bitlocker", decrypted
        try:
            fs = pytsk3.FS_Info(volume, offset=0)
        except OSError:
            return None
        partition.volume = volume
        partition.filesystem = _fs_name(fs)
        return fs

    found = False
    try:
        volumes = pytsk3.Volume_Info(img)
        block = volumes.info.block_size
        parts = [p for p in volumes if p.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC]
    except OSError:
        parts = []
    for part in parts:
        partition = Partition(int(part.addr), int(part.start) * block, int(part.len) * block,
                              part.desc.decode(errors="replace"))
        fs = open_volume(partition)
        found = found or fs is not None or partition.locked
        if fs is not None:
            yield partition, fs
    if not found:
        partition = Partition(0, 0, img.get_size(), "volume")
        fs = open_volume(partition)
        if fs is not None:
            yield partition, fs
        elif not partition.locked:
            raise ImageError("error.image_no_filesystem", error="no file system or BitLocker volume found")


def shadow_copies(partition: Partition) -> list[ShadowCopy]:
    """Volume shadow copies (VSS) of an NTFS volume, oldest first, each as a pytsk3 image."""
    import pytsk3
    import pyvshadow

    if partition.volume is None or not partition.filesystem.startswith("ntfs"):
        return []
    size = partition.volume.get_size()
    window = VolumeWindow(partition.volume, 0, size)
    try:
        if not pyvshadow.check_volume_signature_file_object(window):
            return []
        volume = pyvshadow.volume()
        volume.open_file_object(window)
    except OSError:
        return []
    copies = []
    for index, store in enumerate(volume.stores, 1):
        created = store.get_creation_time()
        copies.append(ShadowCopy(index, str(store.identifier), iso(created) if created else None,
                                 store.volume_size, _HandleImage(pytsk3, store, store.volume_size,
                                                                 keep=[volume, window])))
    return copies


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
        # "dir/file:stream" selects an alternate data stream ($Extend/$UsnJrnl:$J, file.exe:Zone.Identifier)
        self.streams: list[tuple[tuple[str, ...], Optional[str]]] = []
        for pattern in patterns:
            path, _, stream = pattern.partition(":")
            self.streams.append((tuple(path.split("/")), stream or None))
        self.patterns = [segments for segments, _ in self.streams]
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
            elif meta_type == pytsk3.TSK_FS_META_TYPE_REG:
                wanted = {stream for segments, stream in self.streams if _matches(child, segments)}
                for stream in sorted(wanted, key=lambda x: x or ""):
                    extracted = self._extract(entry, child_path, child) if stream is None \
                        else self._extract_stream(entry, child_path, child, stream)
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
        return self._finish(entry, source, dest, size, sha256, md5)

    def _finish(self, entry, source: str, dest: Path, size: int, sha256, md5) -> ExtractedFile:
        meta = entry.info.meta
        times = {k: getattr(meta, k, 0) or None for k in ("mtime", "atime", "ctime", "crtime")}
        if times["mtime"]:
            os.utime(dest, (times["atime"] or times["mtime"], times["mtime"]))
        return ExtractedFile(source, dest, size, sha256.hexdigest(), md5.hexdigest(),
                             *(ts_to_iso(times[k]) if times[k] else None for k in ("mtime", "atime", "ctime", "crtime")),
                             int(meta.addr))

    def _extract_stream(self, entry, source: str, segments: tuple[str, ...], stream: str) -> Optional[ExtractedFile]:
        """Copy a named $DATA stream, skipping sparse runs (the $J journal is mostly sparse)."""
        import pytsk3

        attribute = None
        for attr in entry:
            name = attr.info.name.decode("utf-8", errors="replace") if attr.info.name else ""
            if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and name.lower() == stream.lower():
                attribute = attr
                break
        if attribute is None:
            return None
        size = int(attribute.info.size)
        block = self.fs.info.block_size
        try:
            runs = [(int(r.offset) * block, int(r.len) * block, int(r.flags)) for r in attribute]
        except (OSError, TypeError):
            runs = []
        if not runs:  # resident stream
            runs = [(0, size, 0)]
        sparse = pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE | pytsk3.TSK_FS_ATTR_RUN_FLAG_FILLER
        data_runs = [(off, min(length, size - off)) for off, length, flags in runs if not flags & sparse and off < size]
        if sum(length for _, length in data_runs) > self.max_file_size:
            return None
        safe = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", s) for s in _stream_dest(segments, stream)]
        dest = self.dest.joinpath(*safe)
        dest.parent.mkdir(parents=True, exist_ok=True)
        sha256, md5 = hashlib.sha256(), hashlib.md5()
        if self.progress:
            self.progress(f"{source}:{stream}")
        written = 0
        try:
            with open(dest, "wb") as out:
                for offset, length in data_runs:
                    done = 0
                    while done < length:
                        data = entry.read_random(offset + done, min(CHUNK, length - done), attribute.info.type,
                                                 attribute.info.id)
                        if not data:
                            break
                        out.write(data)
                        sha256.update(data)
                        md5.update(data)
                        done += len(data)
                    written += done
        except OSError as exc:
            if self.on_error:
                self.on_error(f"{source}:{stream}", exc)
            return None
        return self._finish(entry, f"{source}:{stream}", dest, written, sha256, md5)


def _stream_dest(segments: tuple[str, ...], stream: str) -> tuple[str, ...]:
    """Where an alternate data stream is written: $Extend/$UsnJrnl:$J -> $Extend/$J (KAPE layout)."""
    if segments[-1].lower() == "$usnjrnl":
        return segments[:-1] + (stream,)
    return segments[:-1] + (f"{segments[-1]}_{stream}",)


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

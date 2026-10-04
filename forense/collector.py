"""Live triage collector: copies Windows artifacts from a running system (or an image) by reading NTFS directly.

Reading the raw volume (``\\\\.\\C:``) with The Sleuth Kit gets around file locks, so registry hives, the
$MFT, SRUM and event logs in use can be collected. Every file is hashed into a manifest and the collection
itself is described (host, user, tool, times, errors) in ``collection.json``.
"""

from __future__ import annotations

import csv
import getpass
import hashlib
import json
import os
import platform
import socket
import subprocess
from pathlib import Path
from typing import Callable, Optional

from forense import __version__
from forense.core.errors import ForenseError
from forense.core.utils import utc_now
from forense.image import TRIAGE_PATTERNS, Extractor, filesystems, open_image, volume_label

VOLATILE_COMMANDS = {
    "processes.csv": ["tasklist", "/v", "/fo", "csv"],
    "services.csv": ["tasklist", "/svc", "/fo", "csv"],
    "network_connections.txt": ["netstat", "-anob"],
    "ipconfig.txt": ["ipconfig", "/all"],
    "dns_cache.txt": ["ipconfig", "/displaydns"],
    "arp.txt": ["arp", "-a"],
    "routes.txt": ["route", "print"],
    "logged_on_users.txt": ["query", "user"],
    "net_sessions.txt": ["net", "session"],
    "net_shares.txt": ["net", "share"],
    "scheduled_tasks.csv": ["schtasks", "/query", "/fo", "csv", "/v"],
    "systeminfo.txt": ["systeminfo"],
}


def default_source() -> Optional[str]:
    if os.name == "nt":
        return "\\\\.\\" + os.environ.get("SystemDrive", "C:")
    return None


def _hash(path: Path) -> tuple[str, str]:
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def collect(dest: Path, source: Optional[str] = None, patterns: tuple[str, ...] = TRIAGE_PATTERNS,
            volatile: bool = False, progress: Optional[Callable[[str], None]] = None) -> dict:
    """Collect artifacts into ``dest`` (``dest/C/...``). Returns the collection description."""
    source = source or default_source()
    if not source:
        raise ForenseError("error.collect_no_source")
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise ForenseError("error.collect_dest_not_empty", path=str(dest))
    dest.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    errors: list[dict] = []

    def on_error(path: str, exc: BaseException) -> None:
        errors.append({"path": path, "error": f"{type(exc).__name__}: {exc}"})

    try:
        img, _info = open_image(Path(source)) if Path(source).is_file() else _open_device(source)
    except OSError as exc:
        raise ForenseError("error.collect_open", source=source, error=str(exc).splitlines()[0]) from exc

    device = source.rstrip("\\/")
    letter = device[-2].upper() if not Path(source).is_file() and device.endswith(":") else None
    manifest: list[dict] = []
    ntfs_index = 0
    for partition, fs in filesystems(img):
        if letter:
            label = letter
        elif partition.filesystem.startswith("ntfs"):
            label = volume_label(partition, ntfs_index)
            ntfs_index += 1
        else:
            label = f"volume{partition.index}"
        for item in Extractor(fs, dest / label, patterns, on_error=on_error, progress=progress).run():
            manifest.append({"path": f"{label}{item.source}", "size": item.size, "sha256": item.sha256,
                             "md5": item.md5, "mtime": item.mtime, "crtime": item.crtime, "mft_entry": item.inode})

    if volatile:
        manifest += _volatile(dest / "volatile", on_error, progress)

    with open(dest / "manifest.csv", "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "size", "sha256", "md5", "mtime", "crtime", "mft_entry"])
        writer.writeheader()
        writer.writerows(manifest)
    manifest_sha256, _ = _hash(dest / "manifest.csv")
    description = {
        "tool": f"Forense-Framework {__version__}", "source": source, "host": socket.gethostname(),
        "user": getpass.getuser(), "platform": platform.platform(), "started": started, "finished": utc_now(),
        "files": len(manifest), "bytes": sum(m["size"] for m in manifest), "manifest_sha256": manifest_sha256,
        "volatile": volatile, "errors": errors,
    }
    (dest / "collection.json").write_text(json.dumps(description, ensure_ascii=False, indent=1), encoding="utf-8")
    return description


def _open_device(source: str):
    import pytsk3

    from forense.image import ImageInfo

    img = pytsk3.Img_Info(source)
    return img, ImageInfo(source, "device", img.get_size())


def _volatile(folder: Path, on_error: Callable, progress: Optional[Callable[[str], None]]) -> list[dict]:
    if os.name != "nt":
        return []
    folder.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, command in VOLATILE_COMMANDS.items():
        if progress:
            progress(" ".join(command))
        target = folder / name
        try:
            result = subprocess.run(command, capture_output=True, timeout=300, check=False)  # noqa: S603
            target.write_bytes(result.stdout + (b"\n" + result.stderr if result.stderr else b""))
        except (OSError, subprocess.SubprocessError) as exc:
            on_error(" ".join(command), exc)
            continue
        sha256, md5 = _hash(target)
        rows.append({"path": f"volatile/{name}", "size": target.stat().st_size, "sha256": sha256, "md5": md5,
                     "mtime": utc_now(), "crtime": None, "mft_entry": None})
    return rows

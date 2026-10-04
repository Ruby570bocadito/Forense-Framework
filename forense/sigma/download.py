"""Download the Windows rules of the public SigmaHQ repository."""

from __future__ import annotations

import io
import urllib.request
import zipfile
from pathlib import Path

from forense.core.errors import ForenseError

SIGMAHQ_ZIP = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"


def download_sigmahq(dest: Path, url: str = SIGMAHQ_ZIP, timeout: int = 120) -> int:
    """Extract ``rules/windows`` of SigmaHQ into ``dest``. Returns the number of rule files written."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed https URL
            data = response.read()
    except OSError as exc:
        raise ForenseError("error.download_failed", url=url, error=str(exc)) from exc
    return extract_windows_rules(data, dest)


def extract_windows_rules(zip_bytes: bytes, dest: Path) -> int:
    dest = Path(dest)
    count = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        for name in archive.namelist():
            parts = name.split("/")
            if len(parts) < 4 or parts[1:3] != ["rules", "windows"] or not name.endswith(".yml"):
                continue
            target = dest.joinpath(*parts[3:])
            if ".." in parts or not target.resolve().is_relative_to(dest.resolve()):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
            count += 1
    return count

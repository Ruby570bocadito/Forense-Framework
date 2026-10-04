"""Cryptographic hashing of evidence (files and directory trees)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from forense.core.utils import ErrorHandler, iter_files, relative_name

DEFAULT_ALGORITHMS = ("md5", "sha1", "sha256")
CHUNK_SIZE = 1024 * 1024

ProgressCallback = Callable[[int, int], None]  # (files_done, bytes_done)


def validate_algorithms(algorithms: Iterable[str]) -> list[str]:
    algorithms = [a.strip().lower() for a in algorithms if a.strip()]
    unknown = [a for a in algorithms if a not in hashlib.algorithms_available]
    if unknown:
        raise ValueError(", ".join(unknown))
    return algorithms


def hash_file(path: Path, algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
              progress: Optional[Callable[[int], None]] = None) -> dict[str, str]:
    """Hash a file in a single read pass. The file is only ever opened read-only."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
            if progress:
                progress(len(chunk))
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def hash_bytes(data: bytes, algorithms: Iterable[str] = DEFAULT_ALGORITHMS) -> dict[str, str]:
    return {name: hashlib.new(name, data).hexdigest() for name in algorithms}


@dataclass
class TreeHash:
    """Hash of a directory: a manifest hash per algorithm plus totals.

    The manifest hash of an algorithm is the hash of the sorted lines
    ``<relative path>\\t<file digest>\\n``, so any added, removed, renamed or
    modified file changes it.
    """

    hashes: dict[str, str]
    file_count: int
    total_size: int
    files: dict[str, dict[str, str]] = field(default_factory=dict)


def hash_tree(root: Path, algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
              progress: Optional[ProgressCallback] = None,
              on_error: Optional[ErrorHandler] = None) -> TreeHash:
    algorithms = list(algorithms)
    files: dict[str, dict[str, str]] = {}
    total = 0
    errors: list[BaseException] = []

    def _error(path: Path, exc: BaseException) -> None:
        errors.append(exc)
        if on_error:
            on_error(path, exc)

    for path in iter_files(root, on_error=_error):
        rel = relative_name(path, root)

        def _bytes(n: int) -> None:
            nonlocal total
            total += n
            if progress:
                progress(len(files), total)

        try:
            files[rel] = hash_file(path, algorithms, progress=_bytes)
        except OSError as exc:
            _error(path, exc)
        if progress:
            progress(len(files), total)

    if errors and on_error is None:
        raise errors[0]
    manifest = {}
    for name in algorithms:
        hasher = hashlib.new(name)
        for rel in sorted(files):
            hasher.update(f"{rel}\t{files[rel][name]}\n".encode("utf-8", "surrogateescape"))
        manifest[name] = hasher.hexdigest()
    return TreeHash(hashes=manifest, file_count=len(files), total_size=total, files=files)

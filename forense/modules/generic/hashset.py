"""Known-file hash matching (malware hash sets, IOC feeds, NSRL-style lists).

The hash list accepts one hash per line (MD5, SHA-1 or SHA-256, detected by
length) optionally followed by a description, as written by ``sha256sum`` or
in ``hash,description`` CSV form. Lines starting with ``#`` are ignored.
"""

from __future__ import annotations

import re
from pathlib import Path

from forense.core.hashing import hash_file
from forense.core.utils import iter_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register

_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def load_hashset(path: Path) -> dict[str, dict[str, str]]:
    """``{algorithm: {hash: description}}``."""
    result: dict[str, dict[str, str]] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[\s,;]+", line, maxsplit=1)
            value = parts[0].lower()
            algorithm = _LENGTHS.get(len(value))
            if algorithm and _HEX.match(value):
                result.setdefault(algorithm, {})[value] = parts[1].strip().lstrip("*") if len(parts) > 1 else ""
    return result


@register
class HashsetModule(Module):
    name = "hashset"
    category = "generic"
    options = (Option("hash_list", None, "path", required=True),)

    def analyze(self, ctx: AnalysisContext) -> None:
        hashset = load_hashset(ctx.options["hash_list"])
        algorithms = sorted(hashset)
        files = matches = 0
        if algorithms:
            for path in iter_files(ctx.target, on_error=ctx.error):
                rel = relative_name(path, ctx.target)
                try:
                    digests = hash_file(path, algorithms)
                except OSError as exc:
                    ctx.error(rel, exc)
                    continue
                files += 1
                for algorithm, digest in digests.items():
                    if digest in hashset[algorithm]:
                        matches += 1
                        description = hashset[algorithm][digest]
                        ctx.record("hash_match", {"path": rel, "algorithm": algorithm, "hash": digest,
                                                  "description": description})
                        ctx.finding("hashset.match", "high", None, path=rel, algorithm=algorithm.upper(),
                                    hash=digest, description=description or "-")
                        break
        ctx.summary.update({
            "hash_list": str(ctx.options["hash_list"]),
            "hashes_loaded": {a: len(v) for a, v in hashset.items()},
            "files_hashed": files, "matches": matches,
        })

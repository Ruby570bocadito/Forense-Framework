"""Disk images: verify acquisition hashes and extract Windows artifacts from every volume.

Also lists the volume shadow copies of each NTFS volume (and extracts from them
with ``vss``) and decrypts BitLocker volumes with a recovery password, password
or startup key (never stored in the case: only a fingerprint is kept).
"""

from __future__ import annotations

from forense.core.errors import ModuleError
from forense.image import (
    TRIAGE_PATTERNS,
    Extractor,
    ImageError,
    filesystems,
    find_image,
    open_image,
    shadow_copies,
    verify_media,
    volume_label,
)
from forense.modules.base import AnalysisContext, Module, Option, register


@register
class ImageModule(Module):
    name = "image"
    category = "generic"
    options = (
        Option("verify", False, "bool"),
        Option("patterns", None, "list"),
        Option("all_files", False, "bool"),
        Option("max_file_mb", 4096, "int"),
        Option("vss", False, "bool"),
        Option("bitlocker_recovery", None, "secret"),
        Option("bitlocker_password", None, "secret"),
        Option("bitlocker_startup_key", None, "path"),
    )

    def analyze(self, ctx: AnalysisContext) -> None:
        image_path = find_image(ctx.target)
        try:
            img, info = open_image(image_path)
        except ImageError:
            raise
        except OSError as exc:
            raise ModuleError("error.image_open", path=str(image_path), error=str(exc).splitlines()[0]) from exc
        ctx.record("image_info", {"file": image_path.name, "format": info.format, "size": info.size,
                                  "sector_size": info.sector_size, "segments": info.segments,
                                  "stored_hashes": info.stored_hashes, "headers": info.headers})
        ctx.summary["image"] = {"format": info.format, "size": info.size, "segments": len(info.segments) or 1,
                                **{f"stored_{k}": v for k, v in info.stored_hashes.items()}}
        if ctx.options["verify"]:
            ctx.progress("verify")
            result = verify_media(img, info)
            ctx.summary["verification"] = result
            if result["match"] is False:
                ctx.finding("image.hash_mismatch", "critical", None, file=image_path.name,
                            stored=", ".join(f"{k}={v}" for k, v in result["stored"].items()),
                            computed=", ".join(f"{k}={v}" for k, v in result["computed"].items()))

        options = ctx.options
        keys = {"recovery_password": options["bitlocker_recovery"], "password": options["bitlocker_password"],
                "startup_key": options["bitlocker_startup_key"]}
        patterns = ("**",) if options["all_files"] else tuple(options["patterns"] or TRIAGE_PATTERNS)
        extracted_root = ctx.output_dir / "extracted"
        max_size = options["max_file_mb"] * 1024 * 1024
        volumes, locked, total, ntfs_index, copies = [], [], 0, 0, 0
        for partition, fs in filesystems(img, bitlocker=keys, locked=locked):
            label = volume_label(partition, ntfs_index) if partition.filesystem.startswith("ntfs") \
                else f"volume{partition.index}"
            ntfs_index += partition.filesystem.startswith("ntfs")
            ctx.progress(f"{label}: {partition.filesystem}")
            files = Extractor(fs, extracted_root / label, patterns, max_size, on_error=ctx.error,
                              progress=ctx.progress).run()
            stores = shadow_copies(partition)
            volumes.append({"label": label, "partition": partition.index, "offset": partition.offset,
                            "length": partition.length, "description": partition.description,
                            "filesystem": partition.filesystem, "encryption": partition.encryption,
                            "files": len(files), "shadow_copies": len(stores)})
            ctx.record("image_partition", volumes[-1])
            total += self._record_files(ctx, label, files)
            live = {f.source: f.sha256 for f in files}
            for store in stores:
                copies += 1
                ctx.record("image_shadow_copy", {"volume": label, "index": store.index, "identifier": store.identifier,
                                                 "created": store.created, "size": store.size})
                ctx.event(store.created, "shadow_copy_created", f"{label}: VSS {store.index} {store.identifier}")
                if options["vss"]:
                    total += self._extract_shadow_copy(ctx, store, f"{label}_vss{store.index}", extracted_root,
                                                       patterns, max_size, live)
        for partition in locked:
            volumes.append({"label": f"volume{partition.index}", "partition": partition.index,
                            "offset": partition.offset, "length": partition.length,
                            "description": partition.description, "filesystem": "", "encryption": "bitlocker",
                            "files": 0, "shadow_copies": 0, "locked": True})
            ctx.record("image_partition", volumes[-1])
            ctx.finding("image.bitlocker_locked", "medium", None, partition=partition.index,
                        offset=partition.offset)
        if hasattr(img, "close"):
            img.close()
        if total:
            ctx.add_artifact(extracted_root)
        ctx.summary.update({"volumes": volumes, "files_extracted": total, "shadow_copies": copies})
        ctx.summary["extracted_to"] = extracted_root.name

    @staticmethod
    def _record_files(ctx: AnalysisContext, label: str, files) -> int:
        for item in files:
            ctx.record("extracted_file", {
                "volume": label, "path": item.source, "size": item.size, "sha256": item.sha256, "md5": item.md5,
                "mtime": item.mtime, "atime": item.atime, "ctime": item.ctime, "crtime": item.crtime,
                "mft_entry": item.inode,
            })
        return len(files)

    def _extract_shadow_copy(self, ctx: AnalysisContext, store, label: str, root, patterns, max_size: int,
                             live: dict) -> int:
        """Extract from a shadow copy only the files that differ from the live volume."""
        import pytsk3

        try:
            fs = pytsk3.FS_Info(store.img, offset=0)
        except OSError as exc:
            ctx.error(label, exc)
            return 0
        ctx.progress(label)
        files = Extractor(fs, root / label, patterns, max_size, on_error=ctx.error, progress=ctx.progress).run()
        changed = []
        for item in files:
            if live.get(item.source) == item.sha256:
                item.dest.unlink()
            else:
                changed.append(item)
        for folder in sorted((p for p in (root / label).rglob("*") if p.is_dir()), key=lambda p: -len(p.parts)):
            if not any(folder.iterdir()):
                folder.rmdir()
        if (root / label).is_dir() and not any((root / label).iterdir()):
            (root / label).rmdir()
        return self._record_files(ctx, label, changed)


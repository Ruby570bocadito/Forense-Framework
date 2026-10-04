"""Disk images: verify acquisition hashes and extract Windows artifacts from every NTFS volume."""

from __future__ import annotations

from forense.core.errors import ModuleError
from forense.image import (
    TRIAGE_PATTERNS,
    Extractor,
    ImageError,
    filesystems,
    find_image,
    open_image,
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

        patterns = ("**",) if ctx.options["all_files"] else tuple(ctx.options["patterns"] or TRIAGE_PATTERNS)
        extracted_root = ctx.output_dir / "extracted"
        volumes, total = [], 0
        ntfs_index = 0
        for partition, fs in filesystems(img):
            label = volume_label(partition, ntfs_index) if partition.filesystem.startswith("ntfs") \
                else f"volume{partition.index}"
            ntfs_index += partition.filesystem.startswith("ntfs")
            ctx.progress(f"{label}: {partition.filesystem}")
            extractor = Extractor(fs, extracted_root / label, patterns, ctx.options["max_file_mb"] * 1024 * 1024,
                                  on_error=ctx.error, progress=ctx.progress)
            files = extractor.run()
            volumes.append({"label": label, "partition": partition.index, "offset": partition.offset,
                            "length": partition.length, "description": partition.description,
                            "filesystem": partition.filesystem, "files": len(files)})
            ctx.record("image_partition", volumes[-1])
            for item in files:
                total += 1
                ctx.record("extracted_file", {
                    "volume": label, "path": item.source, "size": item.size, "sha256": item.sha256, "md5": item.md5,
                    "mtime": item.mtime, "atime": item.atime, "ctime": item.ctime, "crtime": item.crtime,
                    "mft_entry": item.inode,
                })
        if hasattr(img, "close"):
            img.close()
        if total:
            ctx.add_artifact(extracted_root)
        ctx.summary.update({"volumes": volumes, "files_extracted": total})
        ctx.summary["extracted_to"] = extracted_root.name

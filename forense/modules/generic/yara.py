"""YARA scanning of evidence files (YARA-X engine)."""

from __future__ import annotations

from pathlib import Path

from forense.core.errors import ModuleError
from forense.core.utils import iter_files, relative_name
from forense.modules.base import AnalysisContext, Module, Option, register

RULE_SUFFIXES = (".yar", ".yara", ".rule", ".rules")
SEVERITIES = {"info", "low", "medium", "high", "critical"}


def compile_rules(path: Path):
    """Compile one rule file or every rule file below a folder (each file becomes a namespace)."""
    import yara_x

    files = sorted(p for p in path.rglob("*") if p.suffix.lower() in RULE_SUFFIXES) if path.is_dir() else [path]
    if not files:
        raise ModuleError("error.yara_no_rules", path=str(path))
    compiler = yara_x.Compiler()
    for file in files:
        compiler.new_namespace(file.stem.replace(" ", "_").replace("-", "_"))
        try:
            compiler.add_source(file.read_text(encoding="utf-8", errors="replace"), origin=str(file))
        except yara_x.CompileError as exc:
            raise ModuleError("error.yara_compile", path=str(file), error=str(exc).splitlines()[0]) from exc
    return compiler.build(), len(files)


def _severity(metadata: dict) -> str:
    for key in ("severity", "level"):
        value = str(metadata.get(key, "")).lower()
        if value in SEVERITIES:
            return value
    score = metadata.get("score")
    if isinstance(score, (int, float)):
        return "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    return "high"


@register
class YaraModule(Module):
    name = "yara"
    category = "generic"
    options = (
        Option("rules", None, "path", required=True),
        Option("max_file_mb", 256, "int"),
    )

    def analyze(self, ctx: AnalysisContext) -> None:
        import yara_x

        rules, rule_files = compile_rules(Path(ctx.options["rules"]))
        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(60)
        limit = ctx.options["max_file_mb"] * 1024 * 1024
        scanned = skipped = matches = 0
        per_rule: dict[str, int] = {}
        for path in iter_files(ctx.target, on_error=ctx.error):
            rel = relative_name(path, ctx.target)
            try:
                if path.stat().st_size > limit:
                    skipped += 1
                    continue
                results = scanner.scan_file(str(path))
            except (OSError, yara_x.TimeoutError, yara_x.ScanError) as exc:
                ctx.error(rel, exc)
                continue
            scanned += 1
            for rule in results.matching_rules:
                matches += 1
                name = f"{rule.namespace}:{rule.identifier}"
                per_rule[name] = per_rule.get(name, 0) + 1
                metadata = {key: value for key, value in rule.metadata}
                offsets = {pattern.identifier: [m.offset for m in pattern.matches][:10]
                           for pattern in rule.patterns if pattern.matches}
                strings = sorted(offsets)
                ctx.record("yara_match", {"file": rel, "rule": rule.identifier, "namespace": rule.namespace,
                                          "tags": list(rule.tags), "metadata": metadata, "strings": strings,
                                          "offsets": offsets})
                ctx.finding("yara.match", _severity(metadata), None, rule=rule.identifier, file=rel,
                            description=str(metadata.get("description", "-")), strings=", ".join(strings) or "-")
        ctx.summary.update({"rule_files": rule_files, "files_scanned": scanned, "files_skipped_size": skipped,
                            "matches": matches, "matches_per_rule": per_rule})

"""The two catalogs must stay in sync and cover every code the framework emits."""

from __future__ import annotations

import re
import string
from pathlib import Path

from forense.i18n import catalog, label, t
from forense.modules import available_modules

ROOT = Path(__file__).parent.parent / "forense"


def _placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def _source() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in ROOT.rglob("*") if p.suffix in (".py", ".html"))


def test_catalogs_have_the_same_keys_and_placeholders():
    es, en = catalog("es"), catalog("en")
    assert set(es) == set(en)
    for key in es:
        assert _placeholders(es[key]) == _placeholders(en[key]), key


def test_every_static_key_used_in_code_exists():
    source = _source()
    keys = set(re.findall(r"""\b(?:t|_)\(\s*["']([a-z_]+\.[A-Za-z0-9_.]+)["']""", source))
    keys |= set(re.findall(r"""(?:Error|CaseError|ModuleError|ForenseError)\(\s*["']([a-z_]+\.[a-z_.]+)["']""", source))
    missing = sorted(k for k in keys if not k.endswith(".") and k not in catalog("en"))  # "prefix." + dynamic part
    assert missing == []


def test_every_finding_code_is_translated():
    source = _source()
    finding_codes = set(re.findall(r"""finding\(\s*["']([a-z_]+\.[a-z_]+)["']""", source))
    finding_codes |= set(re.findall(r'"(recyclebin\.deleted_[a-z]+)"', source))
    finding_codes |= {"file.content_mismatch", "file.missing_signature"}
    for code in finding_codes:
        for lang in ("es", "en"):
            assert f"finding.{code}.title" in catalog(lang), code
            assert f"finding.{code}.description" in catalog(lang), code


def test_every_event_type_and_artifact_is_translated():
    source = _source()
    types = set(re.findall(r'ctx\.event\([^,]+, "([a-z_]+)"', source)) | set(re.findall(r'Rule\("([a-z_]+)"', source))
    artifacts = set(re.findall(r'ctx\.record\("([a-z_]+)"', source))
    assert sorted(x for x in types if f"etype.{x}" not in catalog("en")) == []
    assert sorted(x for x in artifacts if f"artifact.{x}" not in catalog("en")) == []


def test_every_module_has_texts():
    for module in available_modules():
        for lang in ("es", "en"):
            assert module.title(lang) != f"module.{module.name}.title"
            assert module.description(lang) != f"module.{module.name}.description"
            for option in module.options:
                assert module.option_help(option, lang) != f"module.{module.name}.opt.{option.name}"


def test_translation_helpers():
    assert t("nav.evidence", "es") == "Evidencias" and t("nav.evidence", "en") == "Evidence"
    assert t("missing.key", "es") == "missing.key"
    assert t("common.page", "es", page=1) == "Página 1 de {pages}"  # missing params stay visible
    assert label("sha256", "es") == "SHA-256" and label("unknown_field") == "Unknown field"


def test_locale_names_are_normalised():
    from forense.i18n import normalize

    assert normalize("Spanish_Spain") == "es" and normalize("es_ES.UTF-8") == "es" and normalize("ES") == "es"
    assert normalize("English_United States") == "en" and normalize("en-GB") == "en"
    assert normalize("C.UTF-8") is None and normalize("fr_FR") is None

"""Framework exceptions carrying a translatable message code."""

from __future__ import annotations

from typing import Optional

from forense.i18n import t


class ForenseError(Exception):
    """Base error. ``code`` is an i18n key; ``params`` fill its placeholders."""

    def __init__(self, code: str, /, **params: object) -> None:
        self.code = code
        self.params = params
        super().__init__(t(code, "en", **params))

    def message(self, lang: Optional[str] = None) -> str:
        return t(self.code, lang, **self.params)


class CaseError(ForenseError):
    pass


class ModuleError(ForenseError):
    pass

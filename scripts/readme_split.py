"""One-off: move the reference part of README.md / README.en.md to docs/MANUAL.md / docs/MANUAL.en.md.

Kept as a script so the move is reviewable: everything from the contents ("## Índice" / "## Contents") on goes to
the manual unchanged, except relative links, which are rebased from the repository root to docs/.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"(\]\()([^)#][^)]*)(\))")


def rebase(text: str) -> str:
    def fix(m: re.Match) -> str:
        target = m.group(2)
        if re.match(r"[a-z]+:", target) or target.startswith("/"):
            return m.group(0)
        target = target[len("docs/"):] if target.startswith("docs/") else "../" + target
        return m.group(1) + target + m.group(3)
    return LINK.sub(fix, text)


def split(readme: str, manual: str, marker: str, title: str, intro: str) -> None:
    raw = (ROOT / readme).read_bytes().decode()
    nl = "\r\n" if "\r\n" in raw else "\n"
    text = raw.replace("\r\n", "\n")
    start = text.index(f"\n{marker}\n") + 1
    body = rebase(text[start:])
    (ROOT / manual).write_bytes((f"# {title}\n\n{intro}\n\n{body}").replace("\n", nl).encode())


if __name__ == "__main__":
    split("README.md", "docs/MANUAL.md", "## Índice", "Manual de Sabueso",
          "Referencia completa: instalación, órdenes, módulos, informes y garantías forenses. "
          "La presentación del proyecto está en el [README](../README.md).")
    split("README.en.md", "docs/MANUAL.en.md", "## Contents", "Sabueso manual",
          "Complete reference: installation, commands, modules, reports and forensic guarantees. "
          "The project overview is in the [README](../README.en.md).")
    print("ok")

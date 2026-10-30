"""Animated SVG of a real CLI session for the README (docs/assets/terminal-<lang>.svg).

The commands really run (on a fresh demo case in a temporary folder); only the temporary path is shortened to
``lab``. GitHub shows animated SVG in READMEs, and the text stays sharp at any size.

    python scripts/terminal_demo.py [es|en]
"""

from __future__ import annotations

import html
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "docs" / "assets"
WIDTH, HEIGHT, LINE, COLS, TOP = 980, 560, 19, 104, 52
LOOP = 30.0  # seconds

SCENES = {
    "es": [
        ["sabueso"],
        ["sabueso demo lab -a \"R. García\"", "sabueso -c lab/case_demo hallazgos --severidad critical"],
        ["sabueso -c lab/case_demo mitre --resumen", "sabueso -c lab/case_demo info"],
    ],
    "en": [
        ["sabueso -L en"],
        ["sabueso demo lab -a \"R. Garcia\" -L en", "sabueso -c lab/case_demo findings --severity critical -L en"],
        ["sabueso -c lab/case_demo attack --summary -L en", "sabueso -c lab/case_demo info -L en"],
    ],
}
KEEP = {"attack": 5, "mitre": 5}  # last lines of long outputs; summaries keep their first lines


def run(command: str, cwd: Path) -> list[str]:
    import shlex

    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "COLUMNS": str(COLS)}
    out = subprocess.run([sys.executable, "-m", "sabueso", *shlex.split(command)[1:]], cwd=cwd, env=env,
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    lines = [line.replace(str(cwd) + os.sep, "").replace(str(cwd), ".") for line in out.rstrip().splitlines()]
    words = [w for w in shlex.split(command)[1:] if not w.startswith("-")]
    verb = words[1] if len(words) > 1 and words[0].startswith("lab") else (words[0] if words else "")
    if verb in ("info",):  # the figures and the next step (the rest is the case card)
        start = next(i for i, line in enumerate(lines) if line.startswith(("Evidencias:", "Evidence:")))
        lines = lines[start:start + 2] + [""] + lines[-3:]
    elif verb in ("mitre", "attack"):
        lines = lines[:KEEP[verb]] + ["…"]
    elif verb == "demo":
        lines = [line for line in lines if not line.startswith("  ")][:2]
    return [line if len(line) <= COLS else line[:COLS - 1] + "…" for line in lines]


def colour(line: str) -> str:
    if line.startswith("$ "):
        return "cmd"
    if line.startswith(("Siguiente paso", "Next step")):
        return "next"
    if line.startswith("  sabueso"):
        return "hint"
    if any(word in line for word in ("crítico", "critical")):
        return "crit"
    return "out"


def build(lang: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        scenes = []
        for commands in SCENES[lang]:
            lines: list[str] = []
            for command in commands:
                lines += [f"$ {command}", *run(command, Path(tmp)), ""]
            scenes.append(lines[:(HEIGHT - TOP) // LINE - 1])
    span = LOOP / len(scenes)
    css, body = [], []
    n = 0
    for index, lines in enumerate(scenes):
        start, end = index * span, (index + 1) * span
        step = min(0.35, (span - 3) / max(1, len(lines)))
        for row, line in enumerate(lines):
            if not line:
                continue
            appear = start + 0.4 + row * step + (0.6 if line.startswith("$ ") else 0)
            a, e = 100 * appear / LOOP, 100 * end / LOOP - 0.01
            css.append(f"@keyframes k{n}{{0%,{max(a - 0.01, 0):.2f}%{{opacity:0}}{a:.2f}%,{e:.2f}%{{opacity:1}}"
                       f"{e + 0.01:.2f}%,100%{{opacity:0}}}}.l{n}{{animation:k{n} {LOOP}s linear infinite}}")
            text = html.escape(line[2:] if line.startswith("$ ") else line)
            prompt = '<tspan class="ps">$ </tspan>' if line.startswith("$ ") else ""
            body.append(f'<text x="24" y="{TOP + row * LINE}" class="{colour(line)} l{n}" '
                        f'xml:space="preserve">{prompt}{text}</text>')
            n += 1
    title = "Sabueso — sesión de terminal" if lang == "es" else "Sabueso — terminal session"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="{title}">
<style>
text{{font-family:'Cascadia Mono',Consolas,'DejaVu Sans Mono',Menlo,monospace;font-size:13.5px;opacity:0}}
.cmd{{fill:#e6edf3;font-weight:600}}.ps{{fill:#3fb950}}.out{{fill:#b1bac4}}.next{{fill:#e8b84a;font-weight:600}}
.hint{{fill:#79c0ff}}.crit{{fill:#ff7b72}}
{''.join(css)}
</style>
<rect width="{WIDTH}" height="{HEIGHT}" rx="12" fill="#0d1117"/>
<rect width="{WIDTH}" height="30" rx="12" fill="#161b22"/><rect y="18" width="{WIDTH}" height="12" fill="#161b22"/>
<circle cx="20" cy="15" r="6" fill="#ff5f57"/><circle cx="40" cy="15" r="6" fill="#febc2e"/><circle cx="60" cy="15" r="6" fill="#28c840"/>
<text x="{WIDTH // 2}" y="20" text-anchor="middle" style="opacity:1;fill:#8b949e;font-size:12px">sabueso</text>
{''.join(body)}
</svg>
"""


if __name__ == "__main__":
    for lang in sys.argv[1:] or ["es", "en"]:
        (ASSETS / f"terminal-{lang}.svg").write_text(build(lang), encoding="utf-8")
        print(lang, "ok")

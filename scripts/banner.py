"""Build the README banners (es/en) and the social preview from the mascot, docs/assets/sabu.svg.

    python scripts/banner.py            # writes docs/assets/banner-es.svg, banner-en.svg and social-preview.svg
"""

from __future__ import annotations

import re
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "docs" / "assets"
FONT = "'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
TEXTS = {
    "es": ("Sigue el rastro. Las conclusiones, tuyas.",
           "Análisis forense de Windows con cadena de custodia e informe pericial"),
    "en": ("Follow the trail. The conclusions are yours.",
           "Windows forensics with a verifiable chain of custody and expert reports"),
}


def mascot() -> str:
    """The mascot's drawing, without its <svg>/<title> wrapper, to be placed with a transform."""
    svg = (ASSETS / "sabu.svg").read_text(encoding="utf-8")
    body = svg.split(">", 1)[1].rsplit("</svg>", 1)[0]
    return re.sub(r"<title[^>]*>.*?</title>", "", body, flags=re.S)


def paws(points: list[tuple[float, float, float]], color: str) -> str:
    """A trail of small paw prints at (x, y, angle)."""
    out = []
    for x, y, angle in points:
        out.append(f'<g transform="translate({x} {y}) rotate({angle})" fill="{color}">'
                   '<ellipse cx="0" cy="4" rx="7" ry="6"/><circle cx="-7" cy="-5" r="2.8"/>'
                   '<circle cx="-2.5" cy="-8.5" r="2.8"/><circle cx="2.5" cy="-8.5" r="2.8"/>'
                   '<circle cx="7" cy="-5" r="2.8"/></g>')
    return "".join(out)


def banner(lang: str, width: int = 1280, height: int = 320) -> str:
    motto, subtitle = TEXTS[lang]
    trail = [(560 + i * 70, 268 - (i % 2) * 18, 80) for i in range(10)]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-label="Sabueso — {motto}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0f1b2d"/><stop offset="1" stop-color="#16324f"/>
    </linearGradient>
  </defs>
  <rect width="{width}" height="{height}" rx="24" fill="url(#bg)"/>
  {paws(trail, "#ffffff14")}
  <circle cx="190" cy="160" r="122" fill="#1f5f99" opacity=".35"/>
  <g transform="translate(70 30) scale(1.08)">{mascot()}</g>
  <text x="400" y="138" font-family="{FONT}" font-size="86" font-weight="800" fill="#ffffff" letter-spacing="1">Sabueso</text>
  <text x="404" y="190" font-family="{FONT}" font-size="30" font-style="italic" fill="#e8b84a">{motto}</text>
  <text x="404" y="234" font-family="{FONT}" font-size="22" fill="#b9c6d8">{subtitle}</text>
</svg>
"""


def social(width: int = 1280, height: int = 640) -> str:
    motto, subtitle = TEXTS["es"]
    trail = [(80 + i * 120, 590 - (i % 2) * 22, 80) for i in range(10)]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0f1b2d"/><stop offset="1" stop-color="#16324f"/>
    </linearGradient>
  </defs>
  <rect width="{width}" height="{height}" fill="url(#bg)"/>
  {paws(trail, "#ffffff14")}
  <circle cx="300" cy="300" r="190" fill="#1f5f99" opacity=".35"/>
  <g transform="translate(120 110) scale(1.5)">{mascot()}</g>
  <text x="560" y="270" font-family="{FONT}" font-size="104" font-weight="800" fill="#ffffff">Sabueso</text>
  <text x="564" y="336" font-family="{FONT}" font-size="34" font-style="italic" fill="#e8b84a">{motto}</text>
  <text x="564" y="392" font-family="{FONT}" font-size="25" fill="#b9c6d8">Análisis forense de Windows con</text>
  <text x="564" y="426" font-family="{FONT}" font-size="25" fill="#b9c6d8">cadena de custodia e informe pericial</text>
</svg>
"""


if __name__ == "__main__":
    for lang in TEXTS:
        (ASSETS / f"banner-{lang}.svg").write_text(banner(lang), encoding="utf-8")
    (ASSETS / "social-preview.svg").write_text(social(), encoding="utf-8")
    print("ok")

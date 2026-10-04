"""PDF export of the HTML report through a headless Chromium browser (Edge, Chrome or Chromium).

Microsoft Edge is installed on every Windows 10/11 system, so no extra
software is needed there; ``FORENSE_BROWSER`` selects a specific executable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from forense.core.errors import ForenseError
from forense.core.hashing import hash_file

_WINDOWS = (
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
)
_MAC = ("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium")
_NAMES = ("msedge", "microsoft-edge", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")


def find_browser() -> Optional[str]:
    if os.environ.get("FORENSE_BROWSER"):
        return os.environ["FORENSE_BROWSER"]
    candidates = [os.path.expandvars(p) for p in _WINDOWS] if os.name == "nt" else list(_MAC)
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    for name in _NAMES:
        found = shutil.which(name)
        if found:
            return found
    for pattern in ("/opt/pw-browsers/chromium*/chrome-linux/chrome", "/opt/google/chrome/chrome"):
        for path in sorted(Path("/").glob(pattern.lstrip("/")), reverse=True):
            return str(path)
    return None


def html_to_pdf(html: Path, output: Optional[Path] = None, case=None, actor: Optional[str] = None,
                timeout: int = 180) -> Path:
    """Print ``html`` to PDF; when ``case`` is given the PDF is hashed into its chain of custody."""
    browser = find_browser()
    if not browser:
        raise ForenseError("error.pdf_no_browser")
    html, output = Path(html).resolve(), Path(output or Path(html).with_suffix(".pdf")).resolve()
    with tempfile.TemporaryDirectory(prefix="forense_pdf_") as profile:
        command = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
                   "--disable-extensions", f"--user-data-dir={profile}", "--no-pdf-header-footer",
                   "--print-to-pdf-no-header", f"--print-to-pdf={output}", html.as_uri()]
        try:
            subprocess.run(command, capture_output=True, timeout=timeout, check=False)  # noqa: S603
        except (OSError, subprocess.SubprocessError) as exc:
            raise ForenseError("error.pdf_failed", error=str(exc)) from exc
    if not output.is_file() or output.stat().st_size == 0:
        raise ForenseError("error.pdf_failed", error=browser)
    if case is not None:
        case.custody.append("report_pdf_generated", case.actor(actor), {
            "file": str(output), "sha256": hash_file(output, ("sha256",))["sha256"], "source": str(html)})
    return output

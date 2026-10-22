"""E2E regression for ``timeline-export-html`` (IMP-2, bfea922).

The web export of the timeline as printable HTML must:
* require CSRF on the POST and write the document into ``exports/``,
* produce a standalone document (doctype, no external resources, no JS src),
* escape evidence-controlled text (a PowerShell history command carrying
  ``<script>`` must never reach the export as markup),
* anchor the document to the chain of custody with its real SHA-256.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import socket
import sqlite3
import subprocess
import time

import pytest
from _cli import forense_path, run

PASSWORD = "pw-e2e"
COMANDO_HOSTIL = "<script>alert(1)</script> =cmd|'/c calc'!A1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def servidor(tmp_path_factory):
    """Workspace with one hostile case + a running web server (auth on)."""
    ws = tmp_path_factory.mktemp("tl-ws")
    history = ws / "psreadline" / "ConsoleHost_history.txt"
    history.parent.mkdir()
    history.write_text(f"Get-Process\n{COMANDO_HOSTIL}\n", encoding="utf-8")

    case = ws / "c"
    assert run("new", str(case), "-n", "c", "-i", "e2e").returncode == 0
    assert run("-c", str(case), "evidencia", "agregar", str(history.parent), "-d", "x", "--copy").returncode == 0
    proc = run("-c", str(case), "triaje", "EV-001", timeout=300)
    assert proc.returncode == 0, proc.stderr

    port = _free_port()
    server = subprocess.Popen(
        [forense_path(), "web", "-w", str(ws), "--host", "127.0.0.1", "--port", str(port),
         "--password", PASSWORD],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                break
        except OSError:
            if server.poll() is not None:
                pytest.fail("the web server died during startup")
            time.sleep(0.3)
    else:
        server.terminate()
        pytest.fail("the web server did not start in time")
    yield str(port), ws
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()


def _request(port: str, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, http.client.HTTPMessage, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=30)
    base = {"Authorization": "Basic " + base64.b64encode(f"user:{PASSWORD}".encode()).decode()}
    conn.request(method, path, body=body, headers={**base, **(headers or {})})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp.headers, data


def test_export_html_de_timeline_autonomo_y_escapado(servidor, tmp_path) -> None:
    port, ws = servidor
    status1, headers1, _ = _request(port, "GET", "/c/c/timeline")
    assert status1 == 200, "the timeline page requires a session first"
    cookie = (headers1.get("Set-Cookie") or "").split(";")[0]
    status2, _, page_bytes = _request(port, "GET", "/c/c/timeline", headers={"Cookie": cookie})
    page = page_bytes.decode("utf-8", "replace")
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert m, "no CSRF token on the timeline page"
    csrf = m.group(1)

    resp_status, _, _ = _request(port, "POST", "/c/c/export/timeline_html",
                                 body=f"csrf_token={csrf}".encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Cookie": cookie})
    assert resp_status == 200, f"export POST failed: {resp_status}"

    exports = sorted((ws / "c" / "exports").glob("timeline_*.html"))
    assert exports, "no HTML export landed in exports/"
    html = exports[-1].read_text(encoding="utf-8")

    assert html.lstrip().lower().startswith("<!doctype html")
    assert not re.search(r'<script[^>]+src=', html), "the standalone export must not load JS"
    assert not re.search(r'(src|href)="http', html), "the standalone export must not reference external resources"
    assert "<script>alert(1)" not in html, "hostile evidence text reached the export unescaped"
    assert "&lt;script&gt;alert(1)" in html, "the hostile command must appear escaped"

    conn = sqlite3.connect(ws / "c" / "forense.db")
    row = conn.execute("select details from custody where action='export_created' "
                       "order by seq desc limit 1").fetchone()
    conn.close()
    assert row, "the HTML export is not anchored in the chain of custody"
    details = json.loads(row[0])
    assert details["sha256"] == hashlib.sha256(exports[-1].read_bytes()).hexdigest()

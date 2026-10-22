"""E2E regression for ``web-filtros-guardados`` (IMP-2, e7962a7).

Saved case filters (findings and timeline) must:
* require CSRF on save/delete POSTs and live in ``<case>/ui/saved_filters.json``,
* allowlist the query keys per page, so a forged form cannot smuggle parameters,
* escape hostile names in the chips,
* cap at 20 per case with a localized warning,
* stay out of the chain of custody (interface state, not evidence),
* never break the page when the JSON file is damaged.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import sqlite3
import subprocess
import time
from urllib.parse import quote

import pytest
from _cli import forense_path, run

PASSWORD = "pw-e2e"
NOMBRE_HOSTIL = 'Grave"><script>alert(1)</script>'
QUERY_FORJADA = "severity=high&cookie=stolen&q=<script>"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def servidor(tmp_path_factory):
    """Workspace with one case + a running web server (auth on)."""
    ws = tmp_path_factory.mktemp("sf-ws")
    case = ws / "c"
    assert run("new", str(case), "-n", "c", "-i", "e2e").returncode == 0

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


def _session(port: str) -> tuple[str, str]:
    """Login and return (cookie, csrf) — the timeline export form always carries the token."""
    status, headers, _ = _request(port, "GET", "/c/c/timeline")
    assert status == 200, "the page requires a session first"
    cookie = (headers.get("Set-Cookie") or "").split(";")[0]
    _, _, page = _request(port, "GET", "/c/c/timeline", headers={"Cookie": cookie})
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.decode("utf-8", "replace"))
    assert m, "no CSRF token on the page"
    return cookie, m.group(1)


def _post_form(port: str, cookie: str, csrf: str, path: str, extra: str) -> tuple[int, str]:
    """POST a form; return (status, cookie). The 302 refreshes the session cookie that
    carries the flash message: replace the old value (werkzeug keeps the FIRST value of
    a duplicated key, so appending would silently drop the fresh session)."""
    body = f"csrf_token={csrf}&{extra}"
    status, headers, _ = _request(port, "POST", path, body=body.encode(),
                                  headers={"Content-Type": "application/x-www-form-urlencoded",
                                           "Cookie": cookie})
    fresh = [c.split(";")[0] for c in headers.get_all("Set-Cookie") or []]
    if not fresh:
        return status, cookie
    drop = {c.split("=")[0] for c in fresh}
    kept = [c for c in cookie.split("; ") if c.split("=")[0] not in drop]
    return status, "; ".join(kept + fresh)


def _custody_count(ws) -> int:
    conn = sqlite3.connect(ws / "c" / "forense.db")
    n = conn.execute("select count(*) from custody").fetchone()[0]
    conn.close()
    return n


def test_ciclo_guardar_aplicar_borrar(servidor) -> None:
    """Save with a hostile name and a smuggled query, apply the chip, delete it."""
    port, ws = servidor
    cookie, csrf = _session(port)

    # Nothing saved and no active filters: the bar stays hidden.
    _, _, page = _request(port, "GET", "/c/c/findings", headers={"Cookie": cookie})
    assert b"saved-bar" not in page, "the bar must be hidden on a clean findings page"
    before = _custody_count(ws)

    # Save: hostile name + non-allowlisted keys must not survive the sanitize step.
    status, cookie = _post_form(port, cookie, csrf, "/c/c/filters/save",
                                f"page=findings&name={quote(NOMBRE_HOSTIL)}&query={quote(QUERY_FORJADA)}")
    assert status == 302, "the save POST must redirect"

    _, _, page = _request(port, "GET", "/c/c/findings", headers={"Cookie": cookie})
    html = page.decode("utf-8", "replace")
    assert "&lt;script&gt;alert(1)" in html, "the hostile name reached the chip unescaped"
    assert "<script>alert(1)" not in html, "XSS in the saved-filter name"
    chip = re.search(r'class="chip" href="([^"]+)"', html)
    assert chip, "no chip rendered after saving"
    assert "severity=high" in chip.group(1), "the allowlisted key must survive"
    assert "cookie=stolen" not in chip.group(1) and "q=%3Cscript%3E" not in chip.group(1), \
        "a forged form smuggled a parameter into the stored query"

    data = json.loads((ws / "c" / "ui" / "saved_filters.json").read_text(encoding="utf-8"))
    assert len(data["filters"]) == 1, "exactly one filter must be stored"
    assert "cookie" not in data["filters"][0]["query"], "the stored query kept a non-allowlisted key"

    status, _, _ = _request(port, "GET", chip.group(1), headers={"Cookie": cookie})
    assert status == 200, "clicking the chip must render the filtered page"

    # Delete the chip: the file stays, but the filter list is empty again.
    fid = data["filters"][0]["id"]
    assert _post_form(port, cookie, csrf, f"/c/c/filters/{fid}/delete", "")[0] == 302
    data2 = json.loads((ws / "c" / "ui" / "saved_filters.json").read_text(encoding="utf-8"))
    assert data2["filters"] == [], "the deleted filter must be gone from the file"

    assert _custody_count(ws) == before, "saved filters are UI state and must not touch the custody"


def test_limite_veinte_pagina_forjada_y_fichero_danado(servidor) -> None:
    """The 21st filter warns and is dropped; forged pages 404; damaged JSON never breaks the page."""
    port, ws = servidor
    cookie, csrf = _session(port)

    assert _post_form(port, cookie, csrf, "/c/c/filters/save",
                      "page=dashboard&name=x&query=a%3D1")[0] == 404, \
        "a forged page value must be rejected, not stored"

    for i in range(20):  # fill the case to the cap via the real endpoint
        assert _post_form(port, cookie, csrf, "/c/c/filters/save",
                          f"page=findings&name=F{i}&query={quote('severity=high')}")[0] == 302
    status, cookie = _post_form(port, cookie, csrf, "/c/c/filters/save",
                                f"page=findings&name=overflow&query={quote('severity=high')}")
    assert status == 302

    _, _, page = _request(port, "GET", "/c/c/findings", headers={"Cookie": cookie})
    html = page.decode("utf-8", "replace")
    assert re.search(r"Up to 20 saved filters|Máximo 20 filtros", html), \
        "the cap warning must be visible and localized"
    data = json.loads((ws / "c" / "ui" / "saved_filters.json").read_text(encoding="utf-8"))
    assert len(data["filters"]) == 20, "the cap must hold"

    # A damaged file must degrade to "no saved filters", never a 500.
    path = ws / "c" / "ui" / "saved_filters.json"
    path.write_text("{broken", encoding="utf-8")
    status, _, page = _request(port, "GET", "/c/c/findings", headers={"Cookie": cookie})
    assert status == 200, "a damaged saved_filters.json must not break the page"
    assert b'class="chip"' not in page, "a damaged file must yield no chips"

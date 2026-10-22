from __future__ import annotations

import base64
import re
import time

import pytest
from conftest import make_signing_key

from forense.core.case import Case
from forense.web import create_app


@pytest.fixture
def workspace(tmp_path, evidence_dir):
    with Case.create(tmp_path / "ws" / "case1", "Web case", "Wendy") as case:
        evidence = case.add_evidence(evidence_dir, "folder")
        case.run_analysis("inventory", evidence.id)
    return tmp_path / "ws"


@pytest.fixture
def client(workspace):
    app = create_app(workspace)
    app.config["TESTING"] = True
    return app.test_client()


def _token(client, url="/c/case1/analyses") -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(url).get_data(as_text=True)).group(1)


def _wait(client) -> dict:
    for _ in range(200):
        jobs = client.get("/api/jobs?case=case1").get_json()
        if jobs and jobs[0]["status"] in ("done", "failed"):
            return jobs[0]
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("url", ["/", "/c/case1/", "/c/case1/evidence", "/c/case1/analyses", "/c/case1/analyses/1",
                                 "/c/case1/findings", "/c/case1/timeline?q=a.txt", "/c/case1/custody",
                                 "/c/case1/reports"])
def test_pages_render(client, url):
    response = client.get(url)
    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"


def test_language_switch(client):
    assert "Evidencias" in client.get("/c/case1/?lang=es").get_data(as_text=True)
    assert "Evidence" in client.get("/c/case1/?lang=en").get_data(as_text=True)
    # the choice is remembered in a cookie
    assert "Evidencias" in client.get("/c/case1/?lang=es").get_data(as_text=True)
    assert "Línea temporal" in client.get("/c/case1/").get_data(as_text=True)


def test_unknown_or_traversal_cases_are_404(client):
    for url in ("/c/missing/", "/c/..%2F..%2Fetc/", "/c/.hidden/"):
        assert client.get(url).status_code == 404


def test_post_requires_csrf(client):
    assert client.post("/c/case1/triage", data={"evidence": "EV-001"}).status_code == 400


def test_run_analysis_and_report_jobs(client, workspace):
    token = _token(client)
    assert client.post("/c/case1/analyses", data={"csrf_token": token, "module": "ioc",
                                                  "evidence": "EV-001", "opt_ioc_min_length": "4"}).status_code == 302
    job = _wait(client)
    assert job["status"] == "done" and job["link"] == "/c/case1/analyses/2"
    client.set_cookie("analyst", "Web Analyst")
    client.post("/c/case1/reports", data={"csrf_token": token, "language": "es", "verify": "on"})
    job = _wait(client)
    assert job["status"] == "done"
    report = client.get(job["link"])
    assert report.status_code == 200 and "Informe de análisis forense digital" in report.get_data(as_text=True)
    with Case.open(workspace / "case1") as case:
        actions = [(e.action, e.actor) for e in case.custody.entries()]
    assert ("report_generated", "Web Analyst") in actions and ("evidence_verified", "Web Analyst") in actions


def test_invalid_option_is_flashed(client):
    token = _token(client)
    response = client.post("/c/case1/analyses", data={"csrf_token": token, "module": "hashset", "evidence": "EV-001"},
                           follow_redirects=True)
    assert "hash_list" in response.get_data(as_text=True)


def test_create_case_and_export(client, workspace):
    token = _token(client, "/")
    response = client.post("/cases", data={"csrf_token": token, "slug": "case2", "name": "Second",
                                           "investigator": "Zed"})
    assert response.status_code == 302 and Case.is_case(workspace / "case2")
    response = client.post("/c/case1/export/timeline", data={"csrf_token": token})
    assert response.status_code == 200 and "attachment" in response.headers["Content-Disposition"]


def test_password_protection(workspace):
    client = create_app(workspace, password="s3cret").test_client()
    assert client.get("/").status_code == 401
    auth = base64.b64encode(b"any:s3cret").decode()
    assert client.get("/", headers={"Authorization": f"Basic {auth}"}).status_code == 200


def test_web_report_signing(client, workspace, monkeypatch):
    from forense.report import signing

    keys = workspace / "keys"
    keys.mkdir(exist_ok=True)
    pem, _ = make_signing_key(keys)
    monkeypatch.setenv("FORENSE_SIGN_KEY", str(pem))
    token = _token(client, "/c/case1/reports")
    page = client.get("/c/case1/reports").get_data(as_text=True)
    assert 'name="sign"' in page and 'verify-signature' not in page  # checkbox on, nothing signed yet
    client.post("/c/case1/reports", data={"csrf_token": token, "language": "es", "sign": "on"})
    job = _wait(client)
    assert job["status"] == "done"
    client.set_cookie("lang", "en")
    page = client.get("/c/case1/reports").get_data(as_text=True)
    assert 'verify-signature' in page
    name = re.search(r'href="/c/case1/reports/([^"]+\.html)"', page).group(1)
    with Case.open(workspace / "case1") as case:
        assert any(e.action == "report_signed" for e in case.custody.entries())
    response = client.post(f"/c/case1/reports/{name}/verify-signature",
                           data={"csrf_token": token}, follow_redirects=True)
    assert "Valid signature" in response.get_data(as_text=True)
    with Case.open(workspace / "case1") as case:
        assert any(e.action == "report_signature_verified" for e in case.custody.entries())
    assert signing.verify_file(workspace / "case1" / "reports" / name)


def test_web_verify_signature_rejects_traversal(client, workspace, monkeypatch):
    keys = workspace / "keys"
    keys.mkdir(exist_ok=True)
    pem, _ = make_signing_key(keys)
    monkeypatch.setenv("FORENSE_SIGN_KEY", str(pem))
    token = _token(client, "/c/case1/reports")
    assert client.post("/c/case1/reports/case.db/verify-signature", data={"csrf_token": token}).status_code == 404
    assert client.post("/c/case1/reports/../../case.db/verify-signature",
                       data={"csrf_token": token}).status_code == 404
    with Case.open(workspace / "case1") as case:
        assert not any(e.action == "report_signature_verified" for e in case.custody.entries())


def test_findings_and_execution_pagination(tmp_path, monkeypatch):
    from forense.cli import EXIT_OK, main
    from forense.core.attack import techniques_for

    monkeypatch.setattr("forense.web.PAGE_SIZE", 2)
    root = tmp_path / "ws"
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    app = create_app(root)
    app.config["TESTING"] = True
    client = app.test_client()

    page1 = client.get("/c/case_demo/findings").get_data(as_text=True)
    assert "Page 1 of" in page1 and "page=2" in page1 and page1.count("review-form") == 2
    page2 = client.get("/c/case_demo/findings?page=2").get_data(as_text=True)
    assert "Page 2 of" in page2 and page2.count("review-form") == 2

    with Case.open(root / "case_demo") as case:
        techniques = {tech for finding in case.findings() for tech in techniques_for(finding)}
    assert techniques
    filtered = client.get(f"/c/case_demo/findings?technique={sorted(techniques)[0]}").get_data(as_text=True)
    assert filtered.count("review-form") <= 2 and "Page 1 of" in filtered

    programs = client.get("/c/case_demo/execution").get_data(as_text=True)
    assert "Page 1 of" in programs and ">21 programs<" in programs and "page=2" in programs


def test_accessibility_basics(client):
    page = client.get("/c/case1/findings").get_data(as_text=True)
    assert 'class="skip-link" href="#content"' in page and 'id="content"' in page  # skip link target
    assert 'aria-label="Main navigation"' in page and 'aria-current="page"' in page
    assert 'aria-current="false"' in page  # non-active items are explicitly marked


def test_accessibility_workspace_pages(client):
    custody = client.get("/c/case1/custody").get_data(as_text=True)  # the custody table always renders
    assert "<thead>" in custody and 'scope="col"' in custody
    index = client.get("/").get_data(as_text=True)
    assert "<thead>" in index and 'hreflang="es"' in index and 'hreflang="en"' in index


def test_accessibility_timeline_header(tmp_path):
    from forense.cli import EXIT_OK, main

    root = tmp_path / "ws"
    assert main(["demo", str(root), "-a", "Tester"]) == EXIT_OK
    app = create_app(root)
    app.config["TESTING"] = True
    page = app.test_client().get("/c/case_demo/timeline").get_data(as_text=True)
    assert "<thead>" in page and 'aria-label="Bookmark"' in page and 'scope="col"' in page


def test_flash_messages_have_roles(client):
    token = _token(client)
    response = client.post("/c/case1/analyses", data={"csrf_token": token, "module": "hashset", "evidence": "EV-001"},
                           follow_redirects=True)
    assert 'role="alert"' in response.get_data(as_text=True)  # error flash is announced assertively

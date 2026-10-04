from __future__ import annotations

from pathlib import Path

import pytest

from forense.core.case import Case
from forense.demo import generate_demo
from forense.i18n import set_language

DATA = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def _english():
    set_language("en")
    yield
    set_language(None)


@pytest.fixture(scope="session")
def demo(tmp_path_factory) -> dict[str, Path]:
    """Demo scenario files (generated once per test session; never modified by tests)."""
    return generate_demo(tmp_path_factory.mktemp("demo"))


@pytest.fixture
def case(tmp_path) -> Case:
    with Case.create(tmp_path / "case", "Test case", "Tester", "unit tests", "REF-1") as c:
        yield c


@pytest.fixture
def evidence_dir(tmp_path) -> Path:
    root = tmp_path / "evidence"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    (root / "sub" / "b.bin").write_bytes(b"\x00\x01\x02" * 100)
    return root

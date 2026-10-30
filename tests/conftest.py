from __future__ import annotations

from pathlib import Path

import pytest

from sabueso.core.case import Case
from sabueso.demo import generate_demo
from sabueso.i18n import set_language

DATA = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def _english(monkeypatch):
    # the CLI and the e2e subprocesses detect the language again: pin it so a Spanish Windows does not change it
    monkeypatch.setenv("SABUESO_LANG", "en")
    monkeypatch.delenv("FORENSE_LANG", raising=False)
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


def make_signing_key(folder: Path, name: str = "signing") -> tuple[Path, Path]:
    """Write a fresh Ed25519 keypair (private PEM, public PEM) into ``folder`` and return both paths."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = folder / f"{name}.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    pub = folder / f"{name}.pub.pem"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return pem, pub

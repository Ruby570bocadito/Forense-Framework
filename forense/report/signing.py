"""Detached Ed25519 signatures for case reports.

The signing key never enters the case folder: it is read from the analyst's
own storage (``FORENSE_SIGN_KEY`` points to a PEM file) and only the detached
signature (``<file>.sig``) and the public-key fingerprint are recorded in the
chain of custody. Verification needs only the public key
(``FORENSE_SIGN_PUB``) or the private key when the analyst is on the same
machine.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from forense.core.errors import ForenseError
from forense.core.hashing import hash_file

ALGORITHM = "ed25519"


def signing_key_path() -> Optional[Path]:
    value = os.environ.get("FORENSE_SIGN_KEY", "").strip()
    return Path(value) if value else None


def public_key_path() -> Optional[Path]:
    value = os.environ.get("FORENSE_SIGN_PUB", "").strip()
    return Path(value) if value else None


def load_private_key(path: Optional[Path] = None) -> Ed25519PrivateKey:
    """Read the analyst's Ed25519 signing key (PEM, unencrypted)."""
    source = path or signing_key_path()
    if not source:
        raise ForenseError("error.sign_key_missing")
    try:
        key = serialization.load_pem_private_key(Path(source).read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise ForenseError("error.sign_key_invalid", path=str(source)) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ForenseError("error.sign_key_invalid", path=str(source))
    return key


def load_public_key(path: Optional[Path] = None) -> Ed25519PublicKey:
    """Public key from ``FORENSE_SIGN_PUB``; without it, derive it from the private key."""
    source = path or public_key_path()
    if source:
        try:
            key = serialization.load_pem_public_key(Path(source).read_bytes())
        except (OSError, ValueError) as exc:
            raise ForenseError("error.sign_pub_invalid", path=str(source)) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise ForenseError("error.sign_pub_invalid", path=str(source))
        return key
    return load_private_key().public_key()


def public_pem(key: Ed25519PublicKey) -> str:
    """Public key as PEM, ready to hand to a verifier."""
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def fingerprint(key: Ed25519PublicKey) -> str:
    digest = hashlib.sha256(key.public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)).hexdigest()
    return f"sha256:{digest}"


def signature_path(path: Path) -> Path:
    return Path(path).with_name(Path(path).name + ".sig")


def sign_file(path: Path, key: Optional[Ed25519PrivateKey] = None) -> Path:
    """Write the detached ``.sig`` (base64 Ed25519) next to ``path`` and return its path."""
    key = key or load_private_key()
    signature = base64.b64encode(key.sign(Path(path).read_bytes())).decode("ascii")
    sig = signature_path(path)
    sig.write_text(signature, encoding="ascii")
    return sig


def verify_file(path: Path, key: Optional[Ed25519PublicKey] = None) -> bool:
    """True when the detached signature of ``path`` is valid (ForenseError when there is no .sig)."""
    path = Path(path)
    sig = signature_path(path)
    if not sig.is_file():
        raise ForenseError("error.sign_missing", file=path.name)
    pub = key or load_public_key()
    try:
        signature = base64.b64decode(sig.read_text(encoding="ascii"), validate=True)
        pub.verify(signature, path.read_bytes())
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_into_custody(case, path: Path, actor: Optional[str],
                      key: Optional[Ed25519PrivateKey] = None) -> Path:
    """Sign ``path`` and record the detached signature in the chain of custody.

    Only public facts are stored: signature file, its hash and the public-key
    fingerprint. The private key is never persisted.
    """
    key = key or load_private_key()
    path = Path(path)
    sig = sign_file(path, key)
    case.custody.append("report_signed", case.actor(actor), {
        "file": str(path), "sha256": hash_file(path, ("sha256",))["sha256"],
        "signature_file": sig.name, "signature_sha256": hash_file(sig, ("sha256",))["sha256"],
        "algorithm": ALGORITHM, "key_fingerprint": fingerprint(key.public_key()),
    })
    return sig


def record_verification(case, path: Path, actor: Optional[str], ok: bool) -> None:
    """Record a signature verification attempt (valid or not) in the chain of custody."""
    path = Path(path)
    case.custody.append("report_signature_verified", case.actor(actor), {
        "file": str(path), "sha256": hash_file(path, ("sha256",))["sha256"],
        "algorithm": ALGORITHM, "result": "ok" if ok else "failed",
    })

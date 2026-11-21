"""DKIM signing (RFC 6376): what a receiver verifies with our DNS record."""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import dkim
import pytest

from agnusmail.modules.outbound.dkim import (
    DkimKeyError,
    DkimSigner,
    create_dkim_key,
    dns_record,
    generate_dkim_key,
    load_signer,
)

MESSAGE = (
    b"From: alice@mail.example.com\r\nTo: bob@example.org\r\nSubject: hi\r\n"
    b"Date: Fri, 13 Nov 2026 12:00:00 +0000\r\nMessage-ID: <1@mail.example.com>\r\n"
    b"\r\nbody\r\n"
)


@pytest.fixture(scope="module")
def pem() -> bytes:
    return generate_dkim_key()


def receiver_dns(
    pem: bytes, selector: str = "agnus1", domain: str = "mail.example.com"
) -> Callable[..., bytes | None]:
    def lookup(name: bytes, timeout: int = 5) -> bytes | None:
        if name == f"{selector}._domainkey.{domain}.".encode():
            return dns_record(pem).encode()
        return None

    return lookup


def test_signature_verifies_with_the_published_record(pem: bytes) -> None:
    signer = DkimSigner("mail.example.com", "agnus1", pem)
    signed = signer.signature(MESSAGE) + MESSAGE
    assert signed.startswith(b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;")
    assert b"d=mail.example.com" in signed and b"s=agnus1" in signed
    assert dkim.verify(signed, dnsfunc=receiver_dns(pem))


def test_tampering_breaks_the_signature(pem: bytes) -> None:
    signer = DkimSigner("mail.example.com", "agnus1", pem)
    signed = signer.signature(MESSAGE) + MESSAGE
    assert not dkim.verify(signed.replace(b"body", b"BODY"), dnsfunc=receiver_dns(pem))
    # From is oversigned: a second From added in transit breaks it too.
    injected = signed.replace(b"From: alice", b"From: mallory@example.org\r\nFrom: alice")
    assert not dkim.verify(injected, dnsfunc=receiver_dns(pem))


def test_dns_record_format(pem: bytes) -> None:
    record = dns_record(pem)
    assert record.startswith("v=DKIM1; k=rsa; p=MII")


def test_key_files(tmp_path: Path) -> None:
    path = tmp_path / "dkim.pem"
    create_dkim_key(path)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        create_dkim_key(path)
    signer = load_signer(path, domain="mail.example.com", selector="agnus1")
    assert signer.domain == "mail.example.com"


def test_weak_or_wrong_keys_are_refused(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505  (must be refused)
    curve = ec.generate_private_key(ec.SECP256R1())
    keys: list[Any] = [small, curve]
    for index, key in enumerate(keys):
        path = tmp_path / f"bad{index}.pem"
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        with pytest.raises(DkimKeyError):
            load_signer(path, domain="mail.example.com", selector="agnus1")
    garbage = tmp_path / "garbage.pem"
    garbage.write_bytes(b"not a key")
    garbage.chmod(0o600)
    with pytest.raises(DkimKeyError):
        load_signer(garbage, domain="mail.example.com", selector="agnus1")

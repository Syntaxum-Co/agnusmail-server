"""DKIM signing of outbound mail (RFC 6376).

RSA-2048 with SHA-256 (RFC 8301), relaxed/relaxed canonicalization. The private key
exists only in the outbound service. From is signed twice ("oversigned") so that a
From field added later breaks the signature instead of being trusted.
"""

import base64
import os
from dataclasses import dataclass
from pathlib import Path

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agnusmail.modules.inbound.keyfile import check_private_file

RSA_BITS = 2048
SIGNED_HEADERS = (
    b"from",
    b"from",  # oversigned (RFC 6376 §8.15)
    b"sender",
    b"reply-to",
    b"to",
    b"cc",
    b"subject",
    b"date",
    b"message-id",
    b"in-reply-to",
    b"references",
    b"mime-version",
    b"content-type",
    b"content-transfer-encoding",
)


class DkimKeyError(ValueError):
    pass


@dataclass(frozen=True)
class DkimSigner:
    domain: str
    selector: str
    private_key: bytes  # PEM (PKCS#1)

    def signature(self, message: bytes) -> bytes:
        """The DKIM-Signature field (CRLF-terminated) to prepend to ``message``."""
        signed: bytes = dkim.sign(
            message,
            self.selector.encode("ascii"),
            self.domain.encode("ascii"),
            self.private_key,
            canonicalize=(b"relaxed", b"relaxed"),
            include_headers=list(SIGNED_HEADERS),
            linesep=b"\r\n",
        )
        return signed

    def dns_record(self) -> str:
        return dns_record(self.private_key)


def generate_dkim_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _private_key(pem: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise DkimKeyError("not an unencrypted PEM private key") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < RSA_BITS:
        raise DkimKeyError(f"the DKIM key must be RSA with at least {RSA_BITS} bits")
    return key


def dns_record(pem: bytes) -> str:
    """TXT value for ``<selector>._domainkey.<domain>``."""
    public = _private_key(pem).public_key()
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode('ascii')}"


def load_signer(path: Path, *, domain: str, selector: str) -> DkimSigner:
    check_private_file(path)
    pem = path.read_bytes()
    _private_key(pem)
    signer = DkimSigner(domain=domain, selector=selector, private_key=pem)
    probe = b"From: probe@" + domain.encode() + b"\r\nSubject: probe\r\n\r\nprobe\r\n"
    try:
        signer.signature(probe)
    except dkim.DKIMException as exc:
        raise DkimKeyError("the key cannot sign") from exc
    return signer


def create_dkim_key(path: Path) -> bytes:
    """Write a new key with mode 0600; refuses to replace an existing file."""
    pem = generate_dkim_key()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    return pem

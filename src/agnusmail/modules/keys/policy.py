"""Policy applied to a device certificate before it is stored (protocol v1 §3).

Order of the checks (cheapest first):
1. the format must be the protocol's (``openpgp-v6/agnusmail-device-1``);
2. size bounds;
3. a textual guard against obvious private-key encodings (PEM/OpenSSH/PGP armor/PuTTY/
   JWK) — accepting one by mistake would break the guarantee that the server never
   holds private keys;
4. structural validation of the OpenPGP v6 certificate (4.D.1) and its v6 fingerprint
   (4.D.2) — ``infrastructure/openpgp.py``;
5. proof of possession (4.D.3): a detached signature by the certificate's signing subkey
   over a statement that names the service, the account and the fingerprint, so the
   proof cannot be replayed under another account or service.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from agnusmail.core.exceptions import KeyRejectedError
from agnusmail.infrastructure.openpgp import (
    PROTOCOL_KEY_FORMAT,
    CertificateRejectedError,
    DeviceCertificate,
    SignatureInvalidError,
    inspect_device_certificate,
    verify_detached,
)
from agnusmail.modules.keys.models import DIGEST_PREFIX

PRIVATE_KEY_MARKERS = (
    b"PRIVATE KEY",  # PEM: PRIVATE / RSA / EC / ENCRYPTED / OPENSSH; PGP PRIVATE KEY BLOCK
    b"PuTTY-User-Key-File",
)
# JWK members that only exist in private keys (RFC 7517/7518: d, p, q, dp, dq, qi, oth, k).
JWK_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


def material_digest(material: bytes) -> str:
    """Server-side content digest of the stored bytes (the protocol fingerprint is the
    v6 fingerprint of the primary key, kept separately)."""
    return DIGEST_PREFIX + hashlib.sha256(material).hexdigest()


def _jwk_has_private_members(document: Any) -> bool:
    if isinstance(document, dict):
        if JWK_PRIVATE_MEMBERS & document.keys():
            return True
        return any(_jwk_has_private_members(v) for v in document.get("keys", []) or [])
    return False


def looks_like_private_key(material: bytes) -> bool:
    """Heuristic only: detects common textual encodings of private keys."""
    if any(marker in material for marker in PRIVATE_KEY_MARKERS):
        return True
    stripped = material.strip()
    if stripped[:1] in (b"{", b"["):
        try:
            document = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        items = document if isinstance(document, list) else [document]
        return any(_jwk_has_private_members(item) for item in items)
    return False


REGISTRATION_DOMAIN = b"agnusmail/key-registration/v1\n"


def registration_statement(service: str, account: str, fingerprint: str) -> bytes:
    """What the signing subkey signs to prove possession (protocol v1 §3.3)."""
    return REGISTRATION_DOMAIN + f"{service}\n{account.lower()}\n{fingerprint}".encode("ascii")


@dataclass(frozen=True)
class RegistrationContext:
    service: str  # protocol ``service`` (the SIWE domain)
    account: str  # Ethereum address of the account registering the key
    now: datetime


class KeyMaterialPolicy(Protocol):
    def check(
        self, key_format: str, material: bytes, proof: bytes, context: RegistrationContext
    ) -> DeviceCertificate:
        """Return the validated certificate, or raise KeyRejectedError."""


@dataclass(frozen=True)
class DeviceCertificatePolicy:
    max_bytes: int

    def check(
        self, key_format: str, material: bytes, proof: bytes, context: RegistrationContext
    ) -> DeviceCertificate:
        if key_format != PROTOCOL_KEY_FORMAT:
            raise KeyRejectedError(f"unsupported key format; use {PROTOCOL_KEY_FORMAT}")
        if not material:
            raise KeyRejectedError("public key material is empty")
        if len(material) > self.max_bytes:
            raise KeyRejectedError(f"public key material exceeds {self.max_bytes} bytes")
        if looks_like_private_key(material):
            raise KeyRejectedError("private key material is never accepted")
        try:
            info = inspect_device_certificate(material, now=context.now)
        except CertificateRejectedError as exc:
            if exc.reason == "secret_key_material":
                raise KeyRejectedError("private key material is never accepted") from exc
            raise KeyRejectedError(f"invalid device certificate: {exc.reason}") from exc
        statement = registration_statement(context.service, context.account, info.fingerprint)
        try:
            signer = verify_detached(material, statement, proof)
        except SignatureInvalidError as exc:
            raise KeyRejectedError("proof of possession does not verify") from exc
        if signer != info.signing_fingerprint:
            raise KeyRejectedError("proof of possession must be made by the signing subkey")
        return info

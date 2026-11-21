"""A software WebAuthn authenticator for tests (plays the browser + authenticator role).

Produces real ``navigator.credentials.create/get`` JSON responses ("none" attestation,
ES256), so the server-side py_webauthn verification runs unmodified.
"""

import base64
import hashlib
import json
import secrets
import struct
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SoftAuthenticator:
    def __init__(self, rp_id: str = "app.agnusmail", origin: str = "https://app.agnusmail") -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0
        self.user_handle = b""
        self.backed_up = False

    def _cose_public_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _flags(self, user_verified: bool, extra: int = 0) -> int:
        flags = FLAG_UP | extra
        if user_verified:
            flags |= FLAG_UV
        if self.backed_up:
            flags |= FLAG_BE | FLAG_BS
        return flags

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def create(
        self,
        options: dict[str, Any],
        *,
        user_verified: bool = True,
        origin: str | None = None,
        rp_id: str | None = None,
    ) -> dict[str, Any]:
        self.user_handle = unb64url(options["user"]["id"])
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        attested = (
            bytes(16)  # AAGUID
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_public_key()
        )
        auth_data = (
            hashlib.sha256((rp_id or self.rp_id).encode()).digest()
            + bytes([self._flags(user_verified, FLAG_AT)])
            + struct.pack(">I", self.sign_count)
            + attested
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(
        self,
        options: dict[str, Any],
        *,
        user_verified: bool = True,
        origin: str | None = None,
        counter_step: int = 1,
        extensions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """``extensions``: authenticator extension outputs (e.g. CTAP2 hmac-secret, which
        backs the PRF extension); they are signed as part of authenticatorData."""
        self.sign_count += counter_step
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([self._flags(user_verified, FLAG_ED if extensions else 0)])
            + struct.pack(">I", self.sign_count)
            + (cbor2.dumps(extensions) if extensions else b"")
        )
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": b64url(self.user_handle),
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

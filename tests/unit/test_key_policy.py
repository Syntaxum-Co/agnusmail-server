"""Device certificate policy: checks before and around OpenPGP parsing."""

import hashlib
import json
from datetime import UTC, datetime

import pytest

from agnusmail.core.exceptions import KeyRejectedError
from agnusmail.infrastructure.openpgp import PROTOCOL_KEY_FORMAT
from agnusmail.modules.keys.policy import (
    DeviceCertificatePolicy,
    RegistrationContext,
    looks_like_private_key,
    material_digest,
    registration_statement,
)
from tests.openpgp_helpers import new_device

SERVICE = "app.agnusmail"

PRIVATE_SAMPLES = [
    b"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n",
    b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n",
    b"-----BEGIN EC PRIVATE KEY-----\nMHcC...\n",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF...\n",
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...\n",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOY...\n",
    b"PuTTY-User-Key-File-3: ssh-ed25519\n",
    json.dumps({"kty": "OKP", "crv": "X25519", "x": "abc", "d": "secret"}).encode(),
    json.dumps({"kty": "RSA", "n": "abc", "e": "AQAB", "p": "x", "q": "y"}).encode(),
    json.dumps({"kty": "oct", "k": "c2VjcmV0"}).encode(),  # symmetric secret
    json.dumps({"keys": [{"kty": "EC", "x": "a", "y": "b"}, {"kty": "EC", "d": "s"}]}).encode(),
    b"  " + json.dumps([{"kty": "OKP", "d": "secret"}]).encode(),
]
PUBLIC_SAMPLES = [
    b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEA...\n-----END PUBLIC KEY-----\n",
    b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ...\n",
    json.dumps({"kty": "OKP", "crv": "X25519", "x": "abc"}).encode(),
    json.dumps({"keys": [{"kty": "EC", "x": "a", "y": "b"}]}).encode(),
    bytes(range(32)),  # raw binary key bytes
    b"{not json",
]


@pytest.mark.parametrize("material", PRIVATE_SAMPLES)
def test_private_key_material_is_detected(material: bytes) -> None:
    assert looks_like_private_key(material)


@pytest.mark.parametrize("material", PUBLIC_SAMPLES)
def test_public_or_opaque_material_is_not_flagged(material: bytes) -> None:
    assert not looks_like_private_key(material)


def context(account: str = "0x" + "ab" * 20) -> RegistrationContext:
    return RegistrationContext(service=SERVICE, account=account, now=datetime.now(UTC))


def test_policy_checks_format_size_and_private_markers_before_parsing() -> None:
    policy = DeviceCertificatePolicy(max_bytes=4096)
    for key_format, material, message in (
        ("opaque-test-v0", b"x", "unsupported key format"),
        (PROTOCOL_KEY_FORMAT, b"", "empty"),
        (PROTOCOL_KEY_FORMAT, b"x" * 4097, "exceeds 4096 bytes"),
        (PROTOCOL_KEY_FORMAT, PRIVATE_SAMPLES[0], "private key material is never accepted"),
    ):
        with pytest.raises(KeyRejectedError, match=message):
            policy.check(key_format, material, b"", context())


def test_policy_returns_the_validated_certificate() -> None:
    device = new_device()
    account = "0x" + "cd" * 20
    proof = device.sign(registration_statement(SERVICE, account, device.fingerprint))
    info = DeviceCertificatePolicy(max_bytes=8192).check(
        PROTOCOL_KEY_FORMAT, device.material, proof, context(account.upper().replace("0X", "0x"))
    )
    assert info.fingerprint == device.fingerprint


def test_registration_statement_is_domain_separated() -> None:
    statement = registration_statement("svc.example", "0xAbC", "f" * 64)
    assert statement == b"agnusmail/key-registration/v1\nsvc.example\n0xabc\n" + b"f" * 64


def test_material_digest_is_prefixed_sha256_of_raw_bytes() -> None:
    material = b"\x00\x01public"
    assert material_digest(material) == "sha256:" + hashlib.sha256(material).hexdigest()
    assert len(material_digest(material)) == 71

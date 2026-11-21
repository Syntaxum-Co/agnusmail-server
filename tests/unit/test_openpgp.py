"""Device certificate validation and signature verification (4.D.1–4.D.3)."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pysequoia
import pytest

from agnusmail.infrastructure.openpgp import (
    CertificateRejectedError,
    SignatureInvalidError,
    inspect_device_certificate,
    verify_detached,
)
from tests.openpgp_helpers import (
    DIRECT_KEY,
    SUBKEY_BINDING,
    new_device,
    split_packets,
    tamper_signature,
)

NOW = datetime.now(UTC)


def rejected(material: bytes, *, now: datetime = NOW) -> str:
    with pytest.raises(CertificateRejectedError) as caught:
        inspect_device_certificate(material, now=now)
    return caught.value.reason


def test_valid_profile_is_described() -> None:
    device = new_device()
    info = inspect_device_certificate(device.material, now=NOW)
    assert info.fingerprint == device.fingerprint
    assert len(info.fingerprint) == 64  # v6: SHA-256
    assert len({info.fingerprint, info.signing_fingerprint, info.encryption_fingerprint}) == 3
    assert timedelta(days=364) < info.expires_at - NOW <= timedelta(days=366)


def test_secret_keys_are_refused_before_anything_else() -> None:
    assert rejected(bytes(new_device().tsk)) == "secret_key_material"


def test_armor_and_garbage_are_refused() -> None:
    device = new_device()
    assert rejected(str(device.cert).encode()) == "armored"
    assert rejected(b"\x00\x01not openpgp") == "malformed"
    assert rejected(device.material + new_device().material) == "multiple_primary_keys"


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ({"profile": pysequoia.Profile.RFC4880}, "not_v6"),  # v4 key
        ({"encryption_algorithm": pysequoia.EncryptionAlgorithm.X25519}, "subkey_profile"),
        ({"signing_algorithm": pysequoia.SigningAlgorithm.MLDSA65_Ed25519}, "primary_algorithm"),
        ({"user_id": "Alice <alice@example.com>"}, "unexpected_packet"),
    ],
)
def test_other_profiles_are_refused(options: dict[str, Any], reason: str) -> None:
    assert rejected(new_device(**options).material) == reason


def test_expiration_is_required_and_bounded() -> None:
    assert rejected(new_device(validity_days=None).material) == "no_expiration"
    assert rejected(new_device(validity_days=3 * 365).material) == "validity_too_long"
    assert rejected(new_device(validity_days=1).material, now=NOW + timedelta(days=2)) == "expired"


def test_corrupt_self_signatures_are_detected() -> None:
    material = new_device().material
    # Corrupt direct-key signature: the primary key has no valid self-signature.
    assert rejected(tamper_signature(material, DIRECT_KEY)) == "self_signature_invalid"
    # Corrupt encryption-subkey binding (the 2nd subkey binding in Sequoia's layout).
    assert rejected(tamper_signature(material, SUBKEY_BINDING, 1)) == "encryption_subkey_unusable"


def test_detached_signature_proves_the_signing_subkey() -> None:
    device = new_device()
    info = inspect_device_certificate(device.material, now=NOW)
    data = b"agnusmail/key-registration/v1\nexample"
    signature = device.sign(data)
    assert verify_detached(device.material, data, signature) == info.signing_fingerprint

    for bad_data, material in (
        (data + b"!", device.material),  # different statement
        (data, new_device().material),  # someone else's certificate
        (data, tamper_signature(device.material, SUBKEY_BINDING, 0)),  # broken binding
    ):
        with pytest.raises(SignatureInvalidError):
            verify_detached(material, bad_data, signature)
    with pytest.raises(SignatureInvalidError):
        verify_detached(device.material, data, b"\x01garbage")


def test_packet_order_and_profile_violations() -> None:
    primary, direct, signing, signing_sig, encryption, encryption_sig = split_packets(
        new_device().material
    )
    other = split_packets(new_device().material)
    cases = {
        b"".join([signing, signing_sig]): "malformed",  # subkey before any primary
        b"".join([direct, primary]): "malformed",  # signature before any key
        b"".join([primary, signing, signing_sig, encryption, encryption_sig]): (
            "self_signature_missing"
        ),
        # Binding signatures swapped: each subkey now claims the other's flags.
        b"".join([primary, direct, signing, encryption_sig, encryption, signing_sig]): (
            "signing_subkey_flags"
        ),
        b"".join([primary, direct, signing, signing_sig]): "subkey_profile",  # no PQC subkey
        b"".join([primary, direct, signing, signing_sig, encryption, encryption_sig, *other[4:]]): (
            "subkey_profile"  # two encryption subkeys
        ),
    }
    for material, reason in cases.items():
        assert rejected(material) == reason


def test_only_v6_binary_signatures_are_accepted() -> None:
    device = new_device()
    data = b"agnusmail/key-registration/v1\nexample"
    legacy = new_device(profile=pysequoia.Profile.RFC4880)
    with pytest.raises(SignatureInvalidError, match="v6 binary"):
        verify_detached(device.material, data, legacy.sign(data))


def test_revoked_certificates_are_refused() -> None:
    device = new_device()
    revocation = bytes(device.cert.revoke(device.tsk.certifier()))
    primary, *rest = split_packets(device.material)
    assert rejected(b"".join([primary, revocation, *rest])) == "revoked"

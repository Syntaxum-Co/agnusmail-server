"""Typed wrapper over Sequoia OpenPGP (pysequoia) — public-key operations only.

Used to validate device certificates (protocol v1 §3, ``docs/specs/protocol-v1.md``) and
to verify public signatures, and by the inbound SMTP gateway to encrypt to published
certificates (spec §9). Nothing here decrypts, and no secret key is ever accepted:
certificates carrying secret-key packets are rejected before parsing them as keys.

Two lessons from testing the library, enforced here:
- ``Cert.from_bytes`` accepts certificates whose binding signatures are corrupt (it
  keeps them), so validity is proven **functionally**: the encryption subkey must be
  usable for encryption, and the signing subkey must verify the proof of possession.
- encryption still works with an expired certificate, so expiry is checked explicitly.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import pysequoia
from pysequoia.packet import HashAlgorithm, PacketPile, PublicKeyAlgorithm, SignatureType, Tag

PROTOCOL_KEY_FORMAT = "openpgp-v6/agnusmail-device-1"
V6_FINGERPRINT_HEX_LENGTH = 64
MAX_KEY_VALIDITY = timedelta(days=2 * 365 + 1)  # spec §3.1: at most 2 years
# RFC 9580/9980: v6 signatures with a digest of at least 256 bits.
ALLOWED_HASHES = (
    HashAlgorithm.SHA256,
    HashAlgorithm.SHA384,
    HashAlgorithm.SHA512,
    HashAlgorithm.SHA3_256,
    HashAlgorithm.SHA3_512,
)


class CertificateRejectedError(ValueError):
    """The material is not a valid protocol v1 device certificate. ``reason`` is stable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SignatureInvalidError(ValueError):
    pass


@dataclass(frozen=True)
class DeviceCertificate:
    fingerprint: str  # v6 fingerprint of the primary key, lowercase hex
    signing_fingerprint: str
    encryption_fingerprint: str
    expires_at: datetime


@dataclass
class _Component:
    packet: Any
    signatures: list[Any]


def _components(material: bytes) -> tuple[_Component, list[_Component]]:
    try:
        packets = list(PacketPile.from_bytes(material))
    except Exception as exc:  # the parser raises plain RuntimeError
        raise CertificateRejectedError("malformed") from exc
    primary: _Component | None = None
    subkeys: list[_Component] = []
    current: _Component | None = None
    for packet in packets:
        tag = packet.tag
        if tag in (Tag.SecretKey, Tag.SecretSubkey):
            raise CertificateRejectedError("secret_key_material")
        if tag == Tag.PublicKey:
            if primary is not None or subkeys:
                raise CertificateRejectedError("multiple_primary_keys")
            primary = current = _Component(packet, [])
        elif tag == Tag.PublicSubkey:
            if primary is None:
                raise CertificateRejectedError("malformed")
            current = _Component(packet, [])
            subkeys.append(current)
        elif tag == Tag.Signature:
            if current is None:
                raise CertificateRejectedError("malformed")
            current.signatures.append(packet)
        else:  # user IDs, user attributes, literal data, ... are not part of the profile
            raise CertificateRejectedError("unexpected_packet")
    if primary is None:
        raise CertificateRejectedError("malformed")
    return primary, subkeys


FLAG_NAMES = (
    "certification",
    "signing",
    "authentication",
    "transport_encryption",
    "storage_encryption",
)


def _only(flags: Any, *wanted: str) -> bool:
    return all(bool(getattr(flags, name)) == (name in wanted) for name in FLAG_NAMES)


def _self_signatures_conform(
    component: _Component, expected_type: Any, *wanted: str, optional: tuple[str, ...] = ()
) -> bool:
    """Every self-signature of the type is v6, strong and carries exactly ``wanted`` flags
    (plus, at most, the ``optional`` ones).

    A certificate accumulates self-signatures (e.g. each expiry refresh adds one) and the
    library uses the newest VALID one, which we cannot tell from the packets alone; so
    all of them must conform. Then whichever one is used, the flags are the profile's.
    """
    matching = [s for s in component.signatures if s.signature_type == expected_type]
    if not matching:
        raise CertificateRejectedError("self_signature_missing")
    for signature in matching:
        if signature.signature_version != 6:
            raise CertificateRejectedError("signature_not_v6")
        if signature.hash_algorithm not in ALLOWED_HASHES:
            raise CertificateRejectedError("weak_hash")
        flags = signature.key_flags
        if flags is None or not any(
            _only(flags, *wanted, *extra) for extra in ((), *((name,) for name in optional))
        ):
            return False
    return True


def inspect_device_certificate(material: bytes, *, now: datetime) -> DeviceCertificate:
    """Validate the protocol v1 device profile (spec §3.1/§3.2) and describe it.

    Signing-subkey binding validity is NOT proven here; ``verify_detached`` with the
    proof of possession does that (spec §3.3).
    """
    if material.lstrip()[:10] == b"-----BEGIN":
        raise CertificateRejectedError("armored")
    primary, subkeys = _components(material)

    if primary.packet.key_algorithm != PublicKeyAlgorithm.Ed25519:
        raise CertificateRejectedError("primary_algorithm")
    fingerprint = str(primary.packet.fingerprint).lower()
    if len(fingerprint) != V6_FINGERPRINT_HEX_LENGTH:
        raise CertificateRejectedError("not_v6")
    # Sequoia sets "certify" only; OpenPGP.js sets "certify + sign" on the primary. Both
    # are accepted: protocol proofs must come from the signing SUBKEY anyway (spec §3.3).
    if not _self_signatures_conform(
        primary, SignatureType.DirectKey, "certification", optional=("signing",)
    ):
        raise CertificateRejectedError("primary_flags")

    signing = [s for s in subkeys if s.packet.key_algorithm == PublicKeyAlgorithm.Ed25519]
    encryption = [
        s for s in subkeys if s.packet.key_algorithm == PublicKeyAlgorithm.MLKEM768_X25519
    ]
    if len(subkeys) != 2 or len(signing) != 1 or len(encryption) != 1:
        raise CertificateRejectedError("subkey_profile")
    if not _self_signatures_conform(signing[0], SignatureType.SubkeyBinding, "signing"):
        raise CertificateRejectedError("signing_subkey_flags")
    if not _self_signatures_conform(
        encryption[0], SignatureType.SubkeyBinding, "transport_encryption", "storage_encryption"
    ):
        raise CertificateRejectedError("encryption_subkey_flags")

    try:
        cert = pysequoia.Cert.from_bytes(material)
    except Exception as exc:
        raise CertificateRejectedError("malformed") from exc
    if str(cert.fingerprint).lower() != fingerprint:
        raise CertificateRejectedError("malformed")
    try:  # both need a valid self-signature; Sequoia raises without one
        revoked = bool(cert.is_revoked)
        expires_at: datetime | None = cert.expiration
    except Exception as exc:
        raise CertificateRejectedError("self_signature_invalid") from exc
    if revoked:
        raise CertificateRejectedError("revoked")
    if expires_at is None:
        raise CertificateRejectedError("no_expiration")
    if expires_at <= now:
        raise CertificateRejectedError("expired")
    if expires_at - now > MAX_KEY_VALIDITY:
        raise CertificateRejectedError("validity_too_long")
    try:  # functional proof that the encryption subkey is validly bound (public-key op)
        pysequoia.encrypt(b"", recipients=[cert], armor=False)
    except Exception as exc:
        raise CertificateRejectedError("encryption_subkey_unusable") from exc

    return DeviceCertificate(
        fingerprint=fingerprint,
        signing_fingerprint=str(signing[0].packet.fingerprint).lower(),
        encryption_fingerprint=str(encryption[0].packet.fingerprint).lower(),
        expires_at=expires_at,
    )


def verify_detached(material: bytes, data: bytes, signature: bytes) -> str:
    """Verify a v6 binary detached signature by the certificate; return the signing key.

    Sequoia only accepts a signature from a key that is validly bound to the certificate
    (signing subkeys need the back-signature), alive and signing-capable.
    """
    try:
        sig = pysequoia.Sig.from_bytes(signature)
    except Exception as exc:
        raise SignatureInvalidError("malformed signature") from exc
    if sig.version != 6 or sig.signature_type != SignatureType.Binary:
        raise SignatureInvalidError("signature must be a v6 binary signature")
    if sig.hash_algorithm not in ALLOWED_HASHES:
        raise SignatureInvalidError("weak hash")
    try:
        cert = pysequoia.Cert.from_bytes(material)
        result = pysequoia.verify(bytes=data, store=lambda _ids: [cert], signature=sig)
    except Exception as exc:
        raise SignatureInvalidError("signature does not verify") from exc
    valid = list(result.valid_sigs)
    if len(valid) != 1:
        raise SignatureInvalidError("signature does not verify")
    return str(valid[0].signing_key).lower()


# --- Message envelopes (protocol v1 §6.2, §6.5) ----------------------------------------
#
# The library frames packets (headers, lengths, partial bodies); from the framed body we
# read only fixed-layout header fields defined by RFC 9580. Nothing is decrypted.

PKESK_VERSION = 6  # RFC 9580 §5.1.2
SEIPD_VERSION = 2  # RFC 9580 §5.13.2
ALGORITHM_MLKEM768_X25519 = 35  # RFC 9980
CIPHER_AES256 = 9
AEAD_OCB = 2
MAX_CHUNK_SIZE_OCTET = 16  # RFC 9580: chunk size octet MUST be at most 16
SEIPD_SALT_BYTES = 32
AEAD_TAG_BYTES = 16


class EnvelopeRejectedError(ValueError):
    """Not a protocol v1 message part. ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _single_packet(data: bytes, expected_tag: Any) -> bytes:
    if data.lstrip()[:10] == b"-----BEGIN":
        raise EnvelopeRejectedError("armored")
    try:
        packets = list(PacketPile.from_bytes(data))
    except Exception as exc:
        raise EnvelopeRejectedError("malformed") from exc
    if len(packets) != 1:
        raise EnvelopeRejectedError("not_a_single_packet")
    if packets[0].tag != expected_tag:
        raise EnvelopeRejectedError("unexpected_packet")
    return bytes(packets[0].body)


def pkesk_recipient(data: bytes) -> str:
    """The v6 fingerprint a v6 PKESK (algorithm 35) is encrypted to; lowercase hex.

    Layout: version (6), length of the next two fields (33), key version (6), the
    32-byte v6 fingerprint, public-key algorithm, algorithm-specific fields. Anonymous
    recipients (length 0) are refused: the server must route (spec §6.2).
    """
    body = _single_packet(data, Tag.PKESK)
    if len(body) < 36 or body[0] != PKESK_VERSION:
        raise EnvelopeRejectedError("pkesk_not_v6")
    if body[1] != 33 or body[2] != 6:
        raise EnvelopeRejectedError("pkesk_recipient_not_v6")
    if body[35] != ALGORITHM_MLKEM768_X25519:
        raise EnvelopeRejectedError("pkesk_algorithm")
    return body[3:35].hex()


def check_seipd_v2(data: bytes) -> None:
    """A single SEIPDv2 packet with AES-256 + OCB and a valid chunk size (spec §6.2)."""
    body = _single_packet(data, Tag.SEIP)
    if len(body) < 4 or body[0] != SEIPD_VERSION:
        raise EnvelopeRejectedError("seipd_not_v2")
    if body[1] != CIPHER_AES256:
        raise EnvelopeRejectedError("seipd_cipher")
    if body[2] != AEAD_OCB:
        raise EnvelopeRejectedError("seipd_aead_mode")
    if body[3] > MAX_CHUNK_SIZE_OCTET:
        raise EnvelopeRejectedError("seipd_chunk_size")
    if len(body) < 4 + SEIPD_SALT_BYTES + AEAD_TAG_BYTES:
        raise EnvelopeRejectedError("seipd_truncated")


# --- Recovery backup (protocol v1 §8.3) --------------------------------------------------

SKESK_VERSION = 6  # RFC 9580 §5.3.2
S2K_ARGON2 = 4  # RFC 9580 §3.7.1.4
# Floor below the spec's t = 1, p = 4, m = 2^16 KiB: refuse anything weaker than that.
MIN_ARGON2_PASSES = 1
MIN_ARGON2_PARALLELISM = 4
MIN_ARGON2_ENCODED_MEMORY = 16


def _check_skesk(skesk: bytes, min_passes: int) -> None:
    """SKESK v6 body: AES-256 + OCB, Argon2 S2K at least (``min_passes``, p = 4,
    m = 2^16 KiB). Layout: version, count, cipher, AEAD, S2K length, S2K specifier
    (type 4: salt[16], t, p, encoded_m), IV, encrypted key."""
    if len(skesk) < 25 or skesk[0] != SKESK_VERSION:
        raise EnvelopeRejectedError("skesk_not_v6")
    if skesk[2] != CIPHER_AES256 or skesk[3] != AEAD_OCB:
        raise EnvelopeRejectedError("skesk_cipher_suite")
    if skesk[4] != 20 or skesk[5] != S2K_ARGON2:  # type + 16-byte salt + t + p + m
        raise EnvelopeRejectedError("s2k_not_argon2")
    passes, parallelism, encoded_memory = skesk[22], skesk[23], skesk[24]
    if (
        passes < min_passes
        or parallelism < MIN_ARGON2_PARALLELISM
        or encoded_memory < MIN_ARGON2_ENCODED_MEMORY
    ):
        raise EnvelopeRejectedError("argon2_too_weak")


def check_recovery_backup(data: bytes) -> None:
    """Exactly one SKESK v6 (Argon2 S2K, AES-256, OCB) followed by one SEIPDv2.

    SKESK v6 layout: version, count, cipher, AEAD, S2K length, S2K specifier
    (type 4: salt[16], t, p, encoded_m), IV, encrypted key. Nothing is decrypted.
    """
    if data.lstrip()[:10] == b"-----BEGIN":
        raise EnvelopeRejectedError("armored")
    try:
        packets = list(PacketPile.from_bytes(data))
    except Exception as exc:
        raise EnvelopeRejectedError("malformed") from exc
    if len(packets) != 2 or packets[0].tag != Tag.SKESK or packets[1].tag != Tag.SEIP:
        raise EnvelopeRejectedError("not_skesk_then_seipd")
    _check_skesk(bytes(packets[0].body), MIN_ARGON2_PASSES)
    body = bytes(packets[1].body)
    if len(body) < 4 or body[0] != SEIPD_VERSION:
        raise EnvelopeRejectedError("seipd_not_v2")
    if body[1] != CIPHER_AES256 or body[2] != AEAD_OCB or body[3] > MAX_CHUNK_SIZE_OCTET:
        raise EnvelopeRejectedError("seipd_cipher_suite")


# --- Encryption on arrival (inbound SMTP gateway, protocol v1 §9) ------------------------


@dataclass(frozen=True)
class EncryptedMessage:
    """``pkesks``: encryption-subkey fingerprint → PKESK packet; ``body``: SEIPDv2 packet.
    A device's OpenPGP message is ``pkesks[its fingerprint] || body`` (spec §6.3)."""

    pkesks: dict[str, bytes]
    body: bytes


# Packets RFC 9580 §4.2.1.4 lets carry partial body lengths (data packets only).
PARTIAL_LENGTH_TAGS = frozenset({8, 9, 11, 18, 20})
MIN_FIRST_PARTIAL_BYTES = 512  # RFC 9580 §4.2.1.4


def _body_length(data: bytes, at: int) -> tuple[int, int | None]:
    """One new-format length field at ``at``: (its size, the length), or None as the
    length for a partial body length (whose chunk size is 2 ** (octet & 0x1F))."""
    if at >= len(data):
        raise EnvelopeRejectedError("truncated")
    first = data[at]
    if first < 192:
        return 1, first
    if first < 224:
        if at + 1 >= len(data):
            raise EnvelopeRejectedError("truncated")
        return 2, ((first - 192) << 8) + data[at + 1] + 192
    if first == 255:
        if at + 5 > len(data):
            raise EnvelopeRejectedError("truncated")
        return 5, int.from_bytes(data[at + 1 : at + 5], "big")
    return 1, None


def split_packets(data: bytes) -> list[bytes]:
    """Raw packets (header + body) of a binary OpenPGP stream, by reading the headers.

    Only OpenPGP (new-format) headers (RFC 9580 §4.2.1); legacy headers are refused.
    Partial body lengths (§4.2.1.4) are accepted only where the RFC allows them (data
    packets, e.g. the SEIPD OpenPGP.js writes for any message over 512 bytes), with a
    first chunk of at least 512 bytes and a definite-length last chunk. The raw packet
    keeps its original framing.
    """
    packets: list[bytes] = []
    offset = 0
    while offset < len(data):
        if data[offset] & 0xC0 != 0xC0:
            raise EnvelopeRejectedError("legacy_packet_header")
        tag = data[offset] & 0x3F
        cursor = offset + 1
        size, length = _body_length(data, cursor)
        if length is None:
            if tag not in PARTIAL_LENGTH_TAGS:
                raise EnvelopeRejectedError("partial_length")
            chunk = 1 << (data[cursor] & 0x1F)
            if chunk < MIN_FIRST_PARTIAL_BYTES:
                raise EnvelopeRejectedError("partial_length")
            while length is None:
                cursor += size + chunk
                if cursor > len(data):
                    raise EnvelopeRejectedError("truncated")
                size, length = _body_length(data, cursor)
                if length is None:
                    chunk = 1 << (data[cursor] & 0x1F)
        end = cursor + size + length
        if end > len(data):
            raise EnvelopeRejectedError("truncated")
        packets.append(data[offset:end])
        offset = end
    return packets


TAG_PKESK = 1
TAG_SKESK = 3
TAG_SEIPD = 18


def packet_tag(packet: bytes) -> int:
    """Tag of a raw OpenPGP (new-format) packet from ``split_packets``."""
    return packet[0] & 0x3F


def single_recipient_message(data: bytes) -> str:
    """Exactly one v6 PKESK (algorithm 35) followed by one SEIPDv2 (spec §6.2): the
    outbound queue format (spec §10). Returns the PKESK's recipient fingerprint."""
    if data.lstrip()[:10] == b"-----BEGIN":
        raise EnvelopeRejectedError("armored")
    packets = split_packets(data)
    if len(packets) != 2 or [packet_tag(p) for p in packets] != [TAG_PKESK, TAG_SEIPD]:
        raise EnvelopeRejectedError("not_pkesk_then_seipd")
    fingerprint = pkesk_recipient(packets[0])
    check_seipd_v2(packets[1])
    return fingerprint


PORTAL_MIN_ARGON2_PASSES = 3  # spec §11: t = 3, p = 4, m = 2^16 KiB


def portal_envelope_pkesks(data: bytes) -> list[bytes]:
    """A secure-portal message (spec §11): PKESKs (for the sender's own keys) and exactly
    one SKESK v6 (Argon2, password chosen by the client), in any order, then one SEIPDv2
    AES-256/OCB. Returns the PKESK packets for routing. Nothing is decrypted."""
    if data.lstrip()[:10] == b"-----BEGIN":
        raise EnvelopeRejectedError("armored")
    packets = split_packets(data)
    if len(packets) < 3 or packet_tag(packets[-1]) != TAG_SEIPD:
        raise EnvelopeRejectedError("not_portal_message")
    check_seipd_v2(packets[-1])
    skesks = [p for p in packets[:-1] if packet_tag(p) == TAG_SKESK]
    pkesks = [p for p in packets[:-1] if packet_tag(p) == TAG_PKESK]
    if len(skesks) != 1 or len(skesks) + len(pkesks) != len(packets) - 1:
        raise EnvelopeRejectedError("not_portal_message")
    _check_skesk(_single_packet(skesks[0], Tag.SKESK), PORTAL_MIN_ARGON2_PASSES)
    return pkesks


def encrypt_to_certificates(
    plaintext: bytes, certificates: list[bytes], signer: "GatewayKey | None" = None
) -> EncryptedMessage:
    """Sign (with the gateway key) and encrypt once to every certificate, then split into
    PKESKs + SEIPDv2 (spec §6.2/§6.3, §9).

    The certificates were validated when registered (§3.2); the output is checked against
    the same rules the server applies to clients, so the gateway cannot store anything a
    client would not be allowed to send.
    """
    if not certificates:
        raise ValueError("no certificates")
    certs = [pysequoia.Cert.from_bytes(material) for material in certificates]
    message: bytes = pysequoia.encrypt(
        plaintext,
        recipients=certs,
        signer=None if signer is None else signer.signer(),
        armor=False,
    )
    *pkesk_packets, body = split_packets(message)
    check_seipd_v2(body)
    pkesks: dict[str, bytes] = {}
    for packet in pkesk_packets:
        fingerprint = pkesk_recipient(packet)
        if fingerprint in pkesks:
            raise EnvelopeRejectedError("duplicate_pkesk")
        pkesks[fingerprint] = packet
    return EncryptedMessage(pkesks, body)


# --- Gateway signing key (protocol v1 §9) ------------------------------------------------
#
# The inbound gateway signs what it encrypts, attesting "received by this gateway" (it
# does not authenticate the external sender). Its key is a v6 Ed25519 certificate with
# a signing subkey and **no encryption subkey**: the gateway holds no decryption key at
# all. The library always generates one, so it is removed before the key is first saved,
# and every load proves functionally that nothing can be encrypted to the certificate.

GATEWAY_KEY_VALIDITY = timedelta(days=730)


class GatewayKeyRejectedError(ValueError):
    pass


@dataclass(frozen=True)
class GatewayKey:
    tsk: Any
    certificate: bytes  # public, published by the API
    fingerprint: str  # v6 primary fingerprint, lowercase hex
    expires_at: datetime

    def signer(self) -> Any:
        return self.tsk.signer()


def _encryptable(cert: Any) -> bool:
    try:
        pysequoia.encrypt(b"", recipients=[cert], armor=False)
    except Exception:
        return False
    return True


def generate_gateway_key() -> bytes:
    """A new gateway TSK (binary), without any encryption-capable subkey."""
    tsk = pysequoia.Tsk.generate(
        profile=pysequoia.Profile.RFC9580,
        signing_algorithm=pysequoia.SigningAlgorithm.Ed25519,
        encryption_algorithm=pysequoia.EncryptionAlgorithm.X25519,  # removed below
        validity_seconds=int(GATEWAY_KEY_VALIDITY.total_seconds()),
    )
    raw = bytes(tsk)
    framed = split_packets(raw)
    parsed = list(PacketPile.from_bytes(raw))
    if len(framed) != len(parsed):
        raise GatewayKeyRejectedError("unexpected key layout")
    keep: list[bytes] = []
    index = 0
    while index < len(parsed):
        packet = parsed[index]
        following = parsed[index + 1] if index + 1 < len(parsed) else None
        flags = str(getattr(following, "key_flags", "")) if following is not None else ""
        if packet.tag == Tag.SecretSubkey and "encryption" in flags:
            index += 2  # the subkey and its binding signature
            continue
        keep.append(framed[index])
        index += 1
    stripped = b"".join(keep)
    load_gateway_key(stripped, now=datetime.now().astimezone())  # proves the result
    return stripped


def load_gateway_key(data: bytes, *, now: datetime) -> GatewayKey:
    try:
        tsk = pysequoia.Tsk.from_bytes(data)
        cert = tsk.extract_certificate()
    except Exception as exc:
        raise GatewayKeyRejectedError("not an OpenPGP secret key") from exc
    fingerprint = str(cert.fingerprint).lower()
    if len(fingerprint) != V6_FINGERPRINT_HEX_LENGTH:
        raise GatewayKeyRejectedError("not a v6 key")
    if _encryptable(cert):
        raise GatewayKeyRejectedError("the gateway key must not have an encryption subkey")
    expiration = cert.expiration
    if expiration is None or expiration <= now:
        raise GatewayKeyRejectedError("expired or without expiration")
    certificate = bytes(cert)
    probe = b"agnusmail/gateway-key-check/v1"
    try:  # also refuses a public certificate: there is no secret signing key
        signature: bytes = pysequoia.sign(
            tsk.signer(), probe, mode=pysequoia.SignatureMode.DETACHED, armor=False
        )
        verify_detached(certificate, probe, signature)
    except Exception as exc:
        raise GatewayKeyRejectedError("the key cannot sign") from exc
    return GatewayKey(tsk, certificate, fingerprint, expiration)

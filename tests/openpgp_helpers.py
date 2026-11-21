"""Real protocol v1 device certificates for tests (generated with Sequoia).

Private keys exist only in the test process, playing the client's role; the server
code under test only ever receives the public certificate and signatures.
"""

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pysequoia
from pysequoia.packet import PacketPile, SignatureType, Tag

DAY = 86400


@dataclass
class DeviceKeys:
    tsk: Any

    @property
    def cert(self) -> Any:
        return self.tsk.extract_certificate()

    @property
    def material(self) -> bytes:
        return bytes(self.cert)

    @property
    def fingerprint(self) -> str:
        return str(self.cert.fingerprint).lower()

    def sign(self, data: bytes) -> bytes:
        signed: bytes = pysequoia.sign(
            self.tsk.signer(), data, mode=pysequoia.SignatureMode.DETACHED, armor=False
        )
        return signed

    def refreshed(self, expiration: datetime) -> bytes:
        """Same primary key, new self-signatures: a new version of the certificate."""
        cert = self.cert.set_expiration(expiration=expiration, certifier=self.tsk.certifier())
        return bytes(cert)


def new_device(validity_days: int | None = 365, **overrides: Any) -> DeviceKeys:
    options: dict[str, Any] = {
        "profile": pysequoia.Profile.RFC9580,
        "signing_algorithm": pysequoia.SigningAlgorithm.Ed25519,
        "encryption_algorithm": pysequoia.EncryptionAlgorithm.MLKEM768_X25519,
        "validity_seconds": None if validity_days is None else validity_days * DAY,
    }
    options.update(overrides)
    return DeviceKeys(pysequoia.Tsk.generate(**options))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def tamper_signature(material: bytes, signature_type: Any, occurrence: int = 0) -> bytes:
    """Flip a bit near the end of the n-th self-signature of the given type."""
    bodies = [
        bytes(packet.body)
        for packet in PacketPile.from_bytes(material)
        if packet.tag == Tag.Signature and packet.signature_type == signature_type
    ]
    body = bodies[occurrence]
    position = material.find(body) + len(body) - 3
    damaged = bytearray(material)
    damaged[position] ^= 0x01
    return bytes(damaged)


DIRECT_KEY = SignatureType.DirectKey
SUBKEY_BINDING = SignatureType.SubkeyBinding


def split_packets(material: bytes) -> list[bytes]:
    """Raw packets (header + body) of a binary OpenPGP stream, in order."""
    chunks: list[bytes] = []
    offset = 0
    for packet in PacketPile.from_bytes(material):
        body = bytes(packet.body)
        start = material.find(body, offset)
        end = start + len(body)
        chunks.append(material[offset:end])
        offset = end
    assert offset == len(material)
    return chunks


def encrypt_split(
    plaintext: bytes, certs: list[Any], signer: DeviceKeys
) -> tuple[list[bytes], bytes]:
    """Client role: sign + encrypt to every certificate, then split the OpenPGP message
    into its PKESK packets and the SEIPDv2 body (protocol v1 §6.3)."""
    message: bytes = pysequoia.encrypt(
        plaintext, recipients=certs, signer=signer.tsk.signer(), armor=False
    )
    packets = split_packets(message)
    return packets[:-1], packets[-1]


def decrypt_joined(
    keys: DeviceKeys, pkesk: bytes, body: bytes, sender_cert: Any
) -> tuple[bytes, int]:
    """Client role: decrypt ``PKESK || body``; returns plaintext and valid signature count."""
    result = pysequoia.decrypt(
        decryptor=keys.tsk.decryptor(), bytes=pkesk + body, store=lambda _ids: [sender_cert]
    )
    return bytes(result.bytes or b""), len(list(result.valid_sigs))

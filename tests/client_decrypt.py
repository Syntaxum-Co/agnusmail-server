"""The client's side of decryption, for this repository's tests only.

Kept out of ``agnusmail.testing`` on purpose: nothing installed with the server may
decrypt user data (see tests/unit/test_outbound_service.py).
"""

import base64
from typing import Any

import pysequoia

from agnusmail.testing.openpgp import DeviceKeys
from agnusmail.testing.people import MESSAGES, Person


def decrypt_joined(
    keys: DeviceKeys, pkesk: bytes, body: bytes, sender_cert: Any
) -> tuple[bytes, int]:
    """Client role: decrypt ``PKESK || body``; returns plaintext and valid signature count."""
    result = pysequoia.decrypt(
        decryptor=keys.tsk.decryptor(), bytes=pkesk + body, store=lambda _ids: [sender_cert]
    )
    return bytes(result.bytes or b""), len(list(result.valid_sigs))


def open_message(reader: Person, message_id: str, sender: Person) -> bytes:
    data = reader.client.get(f"{MESSAGES}/{message_id}").json()
    assert data["pkesks"], data
    plaintext, signatures = decrypt_joined(
        reader.keys,
        base64.b64decode(data["pkesks"][0]),
        base64.b64decode(data["body"]),
        sender.keys.cert,
    )
    assert signatures == 1  # signed by the sender's device
    return plaintext

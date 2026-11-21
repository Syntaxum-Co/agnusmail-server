"""Server + Sequoia side of the OpenPGP.js interoperability test (protocol v1 §14).

    python -m tests.interop.sequoia_side prepare <dir>
    python -m tests.interop.sequoia_side check <dir>

``check`` runs the SERVER's own validation on what OpenPGP.js produced (device certificate,
proof of possession, device-session proof, message envelope), then decrypts the message
as a Sequoia client and writes a signed reply for OpenPGP.js to decrypt.
"""

import json
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

import pysequoia

from agnusmail.infrastructure.openpgp import (
    PROTOCOL_KEY_FORMAT,
    check_seipd_v2,
    inspect_device_certificate,
    pkesk_recipient,
    verify_detached,
)
from agnusmail.modules.authentication.device_binding import session_statement
from agnusmail.modules.keys.policy import DeviceCertificatePolicy, RegistrationContext
from agnusmail.testing.openpgp import DeviceKeys, new_device, split_packets


def prepare(directory: Path) -> None:
    device = new_device()
    (directory / "sequoia_cert.bin").write_bytes(device.material)
    (directory / "sequoia_key.bin").write_bytes(bytes(device.tsk))  # test-only secret
    params = {
        "service": "app.agnusmail",
        "account": "0x" + secrets.token_hex(20),
        "challenge": secrets.token_hex(32),
        "plaintext": "From: web@example\r\nSubject: hello from OpenPGP.js\r\n\r\nPQC works.\r\n",
        "reply": "Subject: hello from Sequoia\r\n\r\nReceived.\r\n",
    }
    (directory / "params.json").write_text(json.dumps(params))
    print(json.dumps({"step": "prepare", "fingerprint": device.fingerprint}))


def check(directory: Path) -> None:
    params = json.loads((directory / "params.json").read_text())
    now = datetime.now(UTC)
    ojs_cert = (directory / "ojs_cert.bin").read_bytes()
    sequoia = DeviceKeys(pysequoia.Tsk.from_bytes((directory / "sequoia_key.bin").read_bytes()))

    # 1. Server: the OpenPGP.js certificate and proof pass the real registration policy.
    context = RegistrationContext(params["service"], params["account"], now)
    info = DeviceCertificatePolicy(max_bytes=8192).check(
        PROTOCOL_KEY_FORMAT, ojs_cert, (directory / "ojs_proof.sig").read_bytes(), context
    )
    # 2. Server: the device-session proof (spec §5) verifies with the signing subkey.
    statement = session_statement(params["service"], info.fingerprint, params["challenge"])
    signer = verify_detached(ojs_cert, statement, (directory / "ojs_session.sig").read_bytes())
    assert signer == info.signing_fingerprint, "session proof not by the signing subkey"

    # 3. Server: the OpenPGP.js message splits into PKESK v6 + SEIPDv2 the API accepts.
    packets = split_packets((directory / "ojs_message.pgp").read_bytes())
    *pkesks, body = packets
    check_seipd_v2(body)
    own = inspect_device_certificate(sequoia.material, now=now)
    routed = {pkesk_recipient(p): p for p in pkesks}
    assert set(routed) == {own.encryption_fingerprint, info.encryption_fingerprint}, routed

    # 4. Client (Sequoia): decrypt ``PKESK(sequoia) || body`` and check the signature.
    result = pysequoia.decrypt(
        decryptor=sequoia.tsk.decryptor(),
        bytes=routed[own.encryption_fingerprint] + body,
        store=lambda _ids: [pysequoia.Cert.from_bytes(ojs_cert)],
    )
    assert bytes(result.bytes or b"").decode() == params["plaintext"], "plaintext mismatch"
    assert len(list(result.valid_sigs)) == 1, "OpenPGP.js signature not valid"

    # 5. Reply from Sequoia for OpenPGP.js to decrypt (step2).
    reply = pysequoia.encrypt(
        params["reply"].encode(),
        recipients=[pysequoia.Cert.from_bytes(ojs_cert)],
        signer=sequoia.tsk.signer(),
        armor=False,
    )
    (directory / "sequoia_reply.pgp").write_bytes(reply)
    print(
        json.dumps(
            {
                "step": "check",
                "certificate": "accepted",
                "proof": "valid",
                "session_proof": "valid",
                "envelope": "accepted",
                "decrypted": True,
                "signature": "valid",
            }
        )
    )


if __name__ == "__main__":
    {"prepare": prepare, "check": check}[sys.argv[1]](Path(sys.argv[2]))

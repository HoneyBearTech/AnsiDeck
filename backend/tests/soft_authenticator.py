"""A software WebAuthn authenticator (ES256, "none" attestation) for tests: it answers
navigator.credentials.create() and .get() options as a browser would return them."""

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, sign_count_step: int = 1) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0
        self.step = sign_count_step  # 0: like a synced passkey, which never counts

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        )

    def _auth_data(self, rp_id: str, flags: int, attested: bool = False) -> bytes:
        data = (
            hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.count)
        )
        if attested:
            data += b"\0" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        return data

    def create(
        self, options: dict, origin: str, rp_id: str | None = None, flags: int = 0x45
    ) -> dict:
        client = json.dumps(
            {"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}
        ).encode()
        # Flags: UP 0x01, UV 0x04, BE 0x08 (synced), BS 0x10 (backed up), AT 0x40.
        data = self._auth_data(rp_id or options["rp"]["id"], flags, attested=True)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": data})
        return {
            "id": b64u(self.cred_id),
            "rawId": b64u(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client),
                "attestationObject": b64u(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(self, options: dict, origin: str, rp_id: str | None = None, flags: int = 0x05) -> dict:
        self.count += self.step
        client = json.dumps(
            {"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}
        ).encode()
        data = self._auth_data(rp_id or options["rpId"], flags)
        signature = self.key.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64u(self.cred_id),
            "rawId": b64u(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client),
                "authenticatorData": b64u(data),
                "signature": b64u(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

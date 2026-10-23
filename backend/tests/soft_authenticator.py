"""A software WebAuthn authenticator for tests: creates and signs credentials the way a browser's passkey would, so the server's real
verification code (py_webauthn) runs end to end. ES256 keys, "none" attestation, user verification always on."""
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.counter = 0

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}).encode()

    def create(self, options: dict, origin: str | None = None) -> dict:
        """The credential a browser would hand back for navigator.credentials.create(options)."""
        client = self._client_data("webauthn.create", options["challenge"], origin)
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        attested = bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + self.counter.to_bytes(4, "big") + attested
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = bytes_to_base64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": bytes_to_base64url(client), "attestationObject": bytes_to_base64url(attestation),
                             "transports": ["internal"]}}

    def get(self, options: dict, origin: str | None = None, tamper: bool = False) -> dict:
        """The assertion a browser would hand back for navigator.credentials.get(options)."""
        self.counter += 1
        client = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + self.counter.to_bytes(4, "big")
        signature = self.key.sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            signature = signature[:-2] + bytes([signature[-2] ^ 0xFF, signature[-1]])
        cid = bytes_to_base64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": bytes_to_base64url(client), "authenticatorData": bytes_to_base64url(auth_data),
                             "signature": bytes_to_base64url(signature), "userHandle": None}}

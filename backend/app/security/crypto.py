"""Field-level encryption for personal data.

- AES-256-GCM with a random 96-bit nonce per value.
- Associated data binds each ciphertext to its organization and column, so a value
  copied into another row or tenant fails to decrypt.
- Keys are versioned. Ciphertext is "v7:<nonce>:<ct>", so old rows still decrypt
  after rotation and can be re-encrypted in the background.
- Blind index: HMAC-SHA256 of the normalized value with a separate key, so we can
  find a user by email without storing the email in readable form.

Key sources:
- LocalKeyring  : keys from environment (development only)
- OpenBaoKeyring: data keys unwrapped by OpenBao/Vault transit at startup (production)
"""
import base64
import hashlib
import hmac
import os
import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _unb64(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class LocalKeyring:
    """SENTRAIL_DATA_KEYS="v7:<base64 32 bytes>,v6:<...>"  (first one is current)
       SENTRAIL_INDEX_KEY="<base64 32 bytes>" """
    def __init__(self):
        raw = os.environ.get("SENTRAIL_DATA_KEYS", "")
        if not raw:
            raise RuntimeError("SENTRAIL_DATA_KEYS is not set")
        self.keys = {}
        for i, part in enumerate(raw.split(",")):
            ver, k = part.split(":", 1)
            key = _unb64(k)
            if len(key) != 32:
                raise RuntimeError(f"Key {ver} must be 32 bytes")
            self.keys[ver] = key
            if i == 0:
                self.current = ver
        self.index_key = _unb64(os.environ["SENTRAIL_INDEX_KEY"])


class OpenBaoKeyring(LocalKeyring):
    """Data keys are stored only in wrapped form; OpenBao transit unwraps them at startup.
    The master key never leaves OpenBao. Works the same with HashiCorp Vault."""
    def __init__(self):
        addr, token = os.environ["BAO_ADDR"], os.environ["BAO_TOKEN"]
        key_name = os.environ.get("BAO_TRANSIT_KEY", "sentrail-data")
        wrapped = os.environ["SENTRAIL_WRAPPED_KEYS"]  # "v7:vault:v1:....,v6:vault:v1:..."
        unwrapped = []
        with httpx.Client(base_url=addr, headers={"X-Vault-Token": token}, timeout=10) as c:
            for part in wrapped.split(","):
                ver, ct = part.split(":", 1)
                r = c.post(f"/v1/transit/decrypt/{key_name}", json={"ciphertext": ct})
                r.raise_for_status()
                unwrapped.append(f"{ver}:{r.json()['data']['plaintext']}")
            r = c.post(f"/v1/transit/decrypt/{key_name}", json={"ciphertext": os.environ["SENTRAIL_WRAPPED_INDEX_KEY"]})
            r.raise_for_status()
        os.environ["SENTRAIL_DATA_KEYS"] = ",".join(unwrapped)
        os.environ["SENTRAIL_INDEX_KEY"] = r.json()["data"]["plaintext"]
        super().__init__()


_ring = None
def ring():
    global _ring
    if _ring is None:
        _ring = OpenBaoKeyring() if os.environ.get("BAO_ADDR") else LocalKeyring()
    return _ring


# Who a person is (email, name, phone, authenticator secret) belongs to the PERSON, not to one organization: with memberships a user can
# belong to several tenants. These columns are bound to the user context. Case data ("str") stays bound to its organization.
IDENTITY_COLUMNS = {"email", "name", "phone", "totp"}


def _aad(org_id, column: str) -> bytes:
    if column in IDENTITY_COLUMNS:
        return f"user|{column}".encode()
    return _legacy_aad(org_id, column)


def _legacy_aad(org_id, column: str) -> bytes:
    """How identity columns were bound before access model v2 (to the user's organization, or 'platform')."""
    return f"{org_id or 'platform'}|{column}".encode()


def _seal(value: str, aad: bytes) -> str:
    r = ring()
    nonce = os.urandom(12)
    ct = AESGCM(r.keys[r.current]).encrypt(nonce, value.encode(), aad)
    return f"{r.current}:{_b64(nonce)}:{_b64(ct)}"


def _open(token: str, aad: bytes) -> str:
    ver, nonce, ct = token.split(":")
    return AESGCM(ring().keys[ver]).decrypt(_unb64(nonce), _unb64(ct), aad).decode()


def encrypt(value: str | None, org_id, column: str) -> str | None:
    if value is None:
        return None
    return _seal(value, _aad(org_id, column))


def decrypt(token: str | None, org_id, column: str) -> str | None:
    if token is None:
        return None
    try:
        return _open(token, _aad(org_id, column))
    except InvalidTag:
        if column not in IDENTITY_COLUMNS:
            raise
        return _open(token, _legacy_aad(org_id, column))      # written before access model v2; scripts.reencrypt_identity upgrades it


def reencrypt_identity(token: str | None, org_id, column: str, down: bool = False) -> str | None:
    """The token re-sealed under the per-user context (or, with down=True, the legacy organization context).
    None when it is already in the target context (or empty)."""
    if token is None:
        return None
    target, other = (_legacy_aad(org_id, column), _aad(org_id, column)) if down else (_aad(org_id, column), _legacy_aad(org_id, column))
    try:
        _open(token, target)
        return None
    except InvalidTag:
        return _seal(_open(token, other), target)


def needs_rotation(token: str) -> bool:
    return token.split(":", 1)[0] != ring().current


def normalize_email(email: str) -> str:
    return email.strip().lower()


def blind_index(value: str) -> bytes:
    return hmac.new(ring().index_key, normalize_email(value).encode(), hashlib.sha256).digest()


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}•••@{domain}"


def sha256(b: bytes | str) -> bytes:
    return hashlib.sha256(b.encode() if isinstance(b, str) else b).digest()


def generate_key_b64() -> str:
    return _b64(os.urandom(32))

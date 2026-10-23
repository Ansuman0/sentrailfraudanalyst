"""Short-lived signed access tokens + rotating refresh tokens with reuse detection.

Access token: Ed25519-signed JWT, 10 minutes, carries user, org, role, session_version.
Refresh token: 256-bit random, stored only as SHA-256, rotated on every use. Presenting
an already-used refresh token revokes the whole family (likely theft).
"""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app import config

ACCESS_TTL = timedelta(minutes=10)
REFRESH_TTL = timedelta(hours=12)
MFA_PENDING_TTL = timedelta(minutes=5)
AUDIENCE, ISSUER = "sentrail-api", "sentrail"

_priv = None
def _keys():
    global _priv
    if _priv is None:
        pem = os.environ.get("SENTRAIL_JWT_PRIVATE_KEY")
        if not pem and not config.IS_DEV:
            # An ephemeral key would sign everyone out on every restart and give each worker a different key.
            raise RuntimeError("SENTRAIL_JWT_PRIVATE_KEY is not set (python -m scripts.generate_keys)")
        _priv = (serialization.load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
                 if pem else Ed25519PrivateKey.generate())  # dev only: ephemeral key
    return _priv, _priv.public_key()


def _now(): return datetime.now(timezone.utc)


def issue_access(user_id, org_id, role_id, session_version: int, mfa: bool, ttl: timedelta | None = None,
                 session_id=None, scope: str | None = None, last_mfa_at: datetime | None = None,
                 platform_role_id=None, access_session_id=None, factor: str = "totp") -> str:
    """ttl defaults to ACCESS_TTL; it is shortened when the organization's idle timeout is shorter,
    so an active user always refreshes inside the idle window. session_id is the refresh-token family,
    so /me/sessions can tell which session is the caller's (the refresh cookie is only sent to /auth).

    Claims (access model v2): sub = user_id, org/tid = active tenant (null in the console), rid = role, prid = platform role,
    asid = access session (an owner inside a tenant, phase 5), sv = session_version, lmfa = when a second factor was last
    proved (epoch seconds, drives step-up), scp = 'tenant' | 'platform' | 'select' (signed in, tenant not chosen yet)."""
    priv, _ = _keys()
    now = _now()
    ttl = min(ttl or ACCESS_TTL, ACCESS_TTL)
    scope = scope or ("platform" if org_id is None else "tenant")
    return jwt.encode({"sub": str(user_id), "org": str(org_id) if org_id else None, "tid": str(org_id) if org_id else None,
                       "rid": str(role_id), "prid": str(platform_role_id) if platform_role_id else None,
                       "asid": str(access_session_id) if access_session_id else None,
                       "sv": session_version, "amr": (["pwd", "hwk"] if factor == "passkey" else ["pwd", "otp"]) if mfa else ["pwd"],
                       "lmfa": int(last_mfa_at.timestamp()) if last_mfa_at else None, "scp": scope,
                       "sid": str(session_id) if session_id else None,
                       "iat": now, "exp": now + ttl, "aud": AUDIENCE, "iss": ISSUER,
                       "jti": uuid.uuid4().hex}, priv, algorithm="EdDSA")


def issue_mfa_pending(user_id) -> str:
    priv, _ = _keys()
    now = _now()
    return jwt.encode({"sub": str(user_id), "typ": "mfa_pending", "iat": now, "exp": now + MFA_PENDING_TTL,
                       "aud": AUDIENCE, "iss": ISSUER}, priv, algorithm="EdDSA")


def decode(token: str, typ: str | None = None) -> dict:
    _, pub = _keys()
    claims = jwt.decode(token, pub, algorithms=["EdDSA"], audience=AUDIENCE, issuer=ISSUER,
                        options={"require": ["exp", "iat", "sub"]})
    if claims.get("typ") != typ:
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def new_opaque() -> str:
    return secrets.token_urlsafe(32)


def refresh_expiry():
    return _now() + REFRESH_TTL

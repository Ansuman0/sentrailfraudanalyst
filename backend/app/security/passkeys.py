"""Passkeys (WebAuthn) as a second factor.

Platform owners must use one (platform_settings.platform_staff_passkey_only); anyone may register passkeys as an alternative to an
authenticator app. Challenges are one-time and live five minutes in `webauthn_challenges`; credentials in `user_passkeys`.
The relying party is the app's own host (APP_URL) unless WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS say otherwise. A passkey registered on one host
(for example sentrail.qatech.world) does not work on another (the AWS fallback address): that is how WebAuthn protects against phishing.
"""
import base64
import json
import os
from urllib.parse import urlparse

from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                      UserVerificationRequirement)

MAX_PER_USER = 10


def relying_party() -> tuple[str, list[str]]:
    app_url = os.environ.get("APP_URL", "http://localhost:5173")
    parsed = urlparse(app_url)
    rp_id = os.environ.get("WEBAUTHN_RP_ID") or parsed.hostname or "localhost"
    origins = [o.strip() for o in os.environ.get("WEBAUTHN_ORIGINS", "").split(",") if o.strip()] or [f"{parsed.scheme}://{parsed.netloc}"]
    return rp_id, origins


def count(cur, user_id) -> int:
    cur.execute("SELECT count(*) FROM user_passkeys WHERE user_id=%s", (user_id,))
    return cur.fetchone()[0]


def _descriptors(cur, user_id):
    cur.execute("SELECT credential_id FROM user_passkeys WHERE user_id=%s", (user_id,))
    return [PublicKeyCredentialDescriptor(id=bytes(r[0])) for r in cur.fetchall()]


def _keep_challenge(cur, user_id, purpose, challenge: bytes):
    cur.execute("DELETE FROM webauthn_challenges WHERE user_id=%s AND (purpose=%s OR expires_at < now())", (user_id, purpose))
    cur.execute("INSERT INTO webauthn_challenges (user_id, purpose, challenge) VALUES (%s,%s,%s)", (user_id, purpose, challenge))


def _take_challenge(cur, user_id, purpose) -> bytes:
    """The latest unexpired challenge, consumed (single use)."""
    cur.execute("""DELETE FROM webauthn_challenges WHERE user_id=%s AND purpose=%s RETURNING challenge, expires_at""", (user_id, purpose))
    rows = [r for r in cur.fetchall() if r[1] is not None]
    cur.execute("SELECT now()")
    now = cur.fetchone()[0]
    live = [bytes(r[0]) for r in rows if r[1] > now]
    if not live:
        raise ValueError("That passkey request expired. Start again")
    return live[-1]


def registration_options(cur, user_id, email: str) -> dict:
    if count(cur, user_id) >= MAX_PER_USER:
        raise ValueError(f"You can register at most {MAX_PER_USER} passkeys")
    rp_id, _ = relying_party()
    opts = generate_registration_options(
        rp_id=rp_id, rp_name="Sentrail", user_id=str(user_id).encode(), user_name=email, user_display_name=email,
        exclude_credentials=_descriptors(cur, user_id),
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                               user_verification=UserVerificationRequirement.REQUIRED))
    _keep_challenge(cur, user_id, "register", opts.challenge)
    return json.loads(options_to_json(opts))


def finish_registration(cur, user_id, credential: dict, name: str) -> dict:
    rp_id, origins = relying_party()
    challenge = _take_challenge(cur, user_id, "register")
    verified = verify_registration_response(credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                                            expected_origin=origins, require_user_verification=True)
    transports = [t for t in (credential.get("response", {}).get("transports") or []) if isinstance(t, str)][:6]
    cur.execute("""INSERT INTO user_passkeys (user_id, credential_id, public_key, sign_count, name, transports)
                   VALUES (%s,%s,%s,%s,%s,%s) RETURNING id, created_at""",
                (user_id, verified.credential_id, verified.credential_public_key, verified.sign_count, name.strip()[:60] or "Passkey", transports))
    pid, created = cur.fetchone()
    return {"id": str(pid), "name": name.strip()[:60] or "Passkey", "created_at": created}


def authentication_options(cur, user_id, purpose: str) -> dict:
    rp_id, _ = relying_party()
    opts = generate_authentication_options(rp_id=rp_id, allow_credentials=_descriptors(cur, user_id),
                                           user_verification=UserVerificationRequirement.REQUIRED)
    _keep_challenge(cur, user_id, purpose, opts.challenge)
    return json.loads(options_to_json(opts))


def finish_authentication(cur, user_id, credential: dict, purpose: str) -> str:
    """Verify an assertion for one of this user's passkeys. Returns the passkey's id. Raises ValueError when it doesn't check out."""
    rp_id, origins = relying_party()
    challenge = _take_challenge(cur, user_id, purpose)
    try:
        raw_id = base64url_to_bytes(credential["id"])
    except Exception as exc:
        raise ValueError("That passkey response isn't valid") from exc
    cur.execute("SELECT id, public_key, sign_count FROM user_passkeys WHERE user_id=%s AND credential_id=%s", (user_id, raw_id))
    row = cur.fetchone()
    if not row:
        raise ValueError("That passkey isn't registered for this account")
    try:
        verified = verify_authentication_response(credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                                                  expected_origin=origins, credential_public_key=bytes(row[1]),
                                                  credential_current_sign_count=int(row[2]), require_user_verification=True)
    except Exception as exc:
        raise ValueError("That passkey didn't check out. Try again") from exc
    cur.execute("UPDATE user_passkeys SET sign_count=%s, last_used_at=now() WHERE id=%s", (verified.new_sign_count, row[0]))
    return str(row[0])


def list_passkeys(cur, user_id) -> list[dict]:
    cur.execute("SELECT id, name, created_at, last_used_at, transports FROM user_passkeys WHERE user_id=%s ORDER BY created_at", (user_id,))
    return [{"id": str(r[0]), "name": r[1], "created_at": r[2], "last_used_at": r[3], "transports": r[4]} for r in cur.fetchall()]

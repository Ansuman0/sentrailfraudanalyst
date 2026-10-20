"""Provision Sentrail users in Keycloak through its Admin REST API.

Only the email goes to Keycloak. Names and everything else stay encrypted in Sentrail.
Uses the 'sentrail-admin' service account (manage-users, view-users, query-users only).
"""
import os
import time
import httpx

from app.security import oidc

ADMIN_CLIENT = os.environ.get("KEYCLOAK_ADMIN_CLIENT_ID", "sentrail-admin")
ADMIN_SECRET = os.environ.get("KEYCLOAK_ADMIN_CLIENT_SECRET", "")
BASE = f"{oidc.KC_INTERNAL}/admin/realms/{oidc.REALM}"
SETUP_ACTIONS = ["VERIFY_EMAIL", "UPDATE_PASSWORD", "CONFIGURE_TOTP"]
_token = {"value": None, "exp": 0}


def _headers():
    if time.time() > _token["exp"] - 30:
        r = httpx.post(f"{oidc.KC_INTERNAL}/realms/{oidc.REALM}/protocol/openid-connect/token", timeout=10,
                       data={"grant_type": "client_credentials"}, auth=(ADMIN_CLIENT, ADMIN_SECRET))
        r.raise_for_status()
        _token.update(value=r.json()["access_token"], exp=time.time() + r.json()["expires_in"])
    return {"Authorization": f"Bearer {_token['value']}"}


def create_user(email: str, org_id: str, email_verified: bool = False, required_actions: list | None = None) -> str:
    """Returns the Keycloak user id (becomes users.idp_subject). Two-factor setup is always required."""
    actions = SETUP_ACTIONS if required_actions is None else required_actions
    if "CONFIGURE_TOTP" not in actions:
        actions = [*actions, "CONFIGURE_TOTP"]
    body = {"username": email, "email": email, "enabled": True, "emailVerified": email_verified,
            "requiredActions": actions, "attributes": {"sentrail_org": [org_id]}}
    r = httpx.post(f"{BASE}/users", json=body, headers=_headers(), timeout=10)
    if r.status_code == 409:
        raise ValueError("This email already exists in the identity provider")
    r.raise_for_status()
    return r.headers["Location"].rstrip("/").split("/")[-1]


def send_setup_email(user_id: str):
    """Keycloak emails a single-use link to verify the email, set a password and set up two-factor."""
    r = httpx.put(f"{BASE}/users/{user_id}/execute-actions-email", headers=_headers(), timeout=10,
                  params={"lifespan": 259200, "client_id": oidc.CLIENT_ID, "redirect_uri": os.environ.get("APP_URL", "")},
                  json=SETUP_ACTIONS)
    r.raise_for_status()


def set_password(user_id: str, password: str, temporary: bool = False):
    r = httpx.put(f"{BASE}/users/{user_id}/reset-password", headers=_headers(), timeout=10,
                  json={"type": "password", "value": password, "temporary": temporary})
    r.raise_for_status()


def set_enabled(user_id: str, enabled: bool):
    httpx.put(f"{BASE}/users/{user_id}", json={"enabled": enabled}, headers=_headers(), timeout=10).raise_for_status()
    if not enabled:
        end_sessions(user_id)


def end_sessions(user_id: str):
    httpx.post(f"{BASE}/users/{user_id}/logout", headers=_headers(), timeout=10).raise_for_status()


def reset_second_factor(user_id: str):
    """Remove OTP and passkey credentials and make the user set up two-factor again."""
    h = _headers()
    creds = httpx.get(f"{BASE}/users/{user_id}/credentials", headers=h, timeout=10).json()
    for c in creds:
        if c.get("type") in ("otp", "webauthn", "webauthn-passwordless"):
            httpx.delete(f"{BASE}/users/{user_id}/credentials/{c['id']}", headers=h, timeout=10).raise_for_status()
    httpx.put(f"{BASE}/users/{user_id}", json={"requiredActions": ["CONFIGURE_TOTP"]}, headers=h, timeout=10).raise_for_status()
    end_sessions(user_id)


def delete_user(user_id: str):
    httpx.delete(f"{BASE}/users/{user_id}", headers=_headers(), timeout=10)

"""OpenID Connect sign-in through Keycloak (backend-for-frontend pattern).

The browser never handles OIDC tokens. Flow:
  1. GET /auth/oidc/login  -> server creates state, nonce and a PKCE verifier, redirects to Keycloak.
  2. Keycloak authenticates (password + TOTP/passkey, or brokers to the company's own IdP).
  3. GET /auth/oidc/callback -> server swaps the code (with client secret + PKCE verifier),
     validates the ID token (signature via JWKS, issuer, audience, expiry, nonce),
     links it to a Sentrail user and issues Sentrail's own session (refresh cookie).
"""
import base64
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode
import httpx
import jwt

KC_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")            # browser-facing URL
KC_INTERNAL = os.environ.get("KEYCLOAK_INTERNAL_URL", KC_URL)               # server-to-server URL
REALM = os.environ.get("KEYCLOAK_REALM", "sentrail")
CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "sentrail-web")
CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")
API_URL = os.environ.get("API_URL", "http://localhost:8000")
REDIRECT_URI = f"{API_URL}/auth/oidc/callback"
# Keycloak enforces MFA for every user (required action CONFIGURE_TOTP or a passkey, or the company IdP).
# Set to "false" only if you also verify an acr/amr claim that proves MFA.
TRUST_IDP_MFA = os.environ.get("TRUST_IDP_MFA", "true") == "true"

ISSUER = f"{KC_URL}/realms/{REALM}"
_meta, _jwks = None, None


def metadata() -> dict:
    global _meta
    if _meta is None:
        r = httpx.get(f"{KC_INTERNAL}/realms/{REALM}/.well-known/openid-configuration", timeout=10)
        r.raise_for_status()
        _meta = r.json()
    return _meta


def jwks_client() -> jwt.PyJWKClient:
    global _jwks
    if _jwks is None:
        uri = metadata()["jwks_uri"].replace(KC_URL, KC_INTERNAL)
        _jwks = jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600)
    return _jwks


def new_login() -> dict:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
            "verifier": verifier, "challenge": challenge}


def authorize_url(login: dict, login_hint: str | None = None, idp_hint: str | None = None) -> str:
    params = {"client_id": CLIENT_ID, "response_type": "code", "scope": "openid email profile",
              "redirect_uri": REDIRECT_URI, "state": login["state"], "nonce": login["nonce"],
              "code_challenge": login["challenge"], "code_challenge_method": "S256", "prompt": "login"}
    if login_hint:
        params["login_hint"] = login_hint
    if idp_hint:
        params["kc_idp_hint"] = idp_hint          # home-realm discovery: go straight to the company's IdP
    endpoint = metadata()["authorization_endpoint"].replace(KC_INTERNAL, KC_URL)
    return f"{endpoint}?{urlencode(params)}"


def exchange_code(code: str, verifier: str) -> dict:
    endpoint = metadata()["token_endpoint"].replace(KC_URL, KC_INTERNAL)
    r = httpx.post(endpoint, timeout=10, data={"grant_type": "authorization_code", "code": code,
                   "redirect_uri": REDIRECT_URI, "code_verifier": verifier},
                   auth=(CLIENT_ID, CLIENT_SECRET))
    if r.status_code != 200:
        raise ValueError("Sign-in couldn't be completed")
    return r.json()


def validate_id_token(id_token: str, nonce: str) -> dict:
    key = jwks_client().get_signing_key_from_jwt(id_token).key
    claims = jwt.decode(id_token, key, algorithms=["RS256", "ES256", "PS256"], audience=CLIENT_ID,
                        issuer=ISSUER, leeway=30, options={"require": ["exp", "iat", "sub", "nonce"]})
    if not secrets.compare_digest(claims["nonce"], nonce):
        raise jwt.InvalidTokenError("nonce mismatch")
    if claims.get("azp", CLIENT_ID) != CLIENT_ID:
        raise jwt.InvalidTokenError("token issued to another client")
    if time.time() - claims.get("auth_time", claims["iat"]) > 600:
        raise jwt.InvalidTokenError("authentication is too old")
    if not claims.get("email_verified"):
        raise jwt.InvalidTokenError("email not verified")
    amr = set(claims.get("amr", []))
    if not TRUST_IDP_MFA and not ({"otp", "mfa", "hwk", "swk"} & amr):
        raise jwt.InvalidTokenError("two-factor sign-in required")
    return claims


def logout_url() -> str:
    endpoint = metadata()["end_session_endpoint"].replace(KC_INTERNAL, KC_URL)
    return f"{endpoint}?{urlencode({'client_id': CLIENT_ID, 'post_logout_redirect_uri': os.environ.get('APP_URL', '') + '/signed-out'})}"

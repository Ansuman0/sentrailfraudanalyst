"""Shared fixtures for the access-control suites: tenants, users with and without two-factor, sign-in helpers."""
import time
import jwt
import psycopg
import pyotp
from app import pg
from app.security import crypto, passwords

PW = "violet harbour tram sixteen"
CSRF = {"X-Sentrail-CSRF": "1"}
claims = lambda tok: jwt.decode(tok, options={"verify_signature": False})
bearer = lambda tok: {"Authorization": "Bearer " + tok}
code_at = lambda secret, offset=0: pyotp.TOTP(secret).at((int(time.time()) // 30 + offset) * 30)


def add_user(org, role_id, email, name=None, secret=None, status="active"):
    """A user with a password (and two-factor when `secret` is given). Returns the user id as a string."""
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, mfa_enabled, totp_secret_enc, status)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (org, role_id, crypto.encrypt(email, org, "email"), crypto.blind_index(email),
                     crypto.encrypt(name or email.split("@")[0], org, "name"), passwords.hash_password(PW), secret is not None,
                     crypto.encrypt(secret, org, "totp") if secret else None, status))
        return str(cur.fetchone()[0])


def password_login(client, email):
    return client.post("/auth/login", json={"email": email, "password": PW})


def two_factor_token(client, email, secret):
    """Sign in with a password and a TOTP code; returns the access token. (offset -1: leaves the next code free for a step-up)"""
    r = password_login(client, email)
    assert r.status_code == 200 and "mfa_token" in r.json(), r.text
    r = client.post("/auth/mfa", json={"mfa_token": r.json()["mfa_token"], "code": code_at(secret, -1)})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def password_token(client, email):
    r = password_login(client, email)
    assert r.status_code == 200 and "access_token" in r.json(), r.text
    return r.json()["access_token"]


def sql(super_url, text, *params):
    """Run a statement as the database superuser (bypasses row-level security): fixtures and verification only."""
    with psycopg.connect(super_url, autocommit=True) as conn:
        cur = conn.execute(text, params)
        return cur.fetchall() if cur.description else None

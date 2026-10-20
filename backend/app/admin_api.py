"""Identity, organizations, users, roles, features, security settings and audit."""
import ipaddress
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie, Query
from fastapi.responses import RedirectResponse
import jwt as pyjwt
import psycopg
from pydantic import BaseModel, EmailStr, Field, field_validator

from app import config, pg
from app.security import crypto, passwords, mfa, tokens, audit
from app.security.rbac import Principal, require, require_any, current_user, signed_in_user, client_ip
from app.security.middleware import limiter
from app.services import mailer
from app.security import oidc

router = APIRouter()
APP_URL = os.environ.get("APP_URL", "http://localhost:5173")
MAX_FAILED, LOCK_MIN = 5, 15

PLATFORM_OWNER_ROLE = "00000000-0000-0000-0000-000000000002"
# Roles and permissions are seed data in the database (migrations/005): role_templates, role_template_permissions.
FEATURES = ["screening", "alerts", "ai", "trace", "statements", "export"]
GENERIC_LOGIN_ERROR = "Email or password is incorrect"
# keycloak: organization users sign in through Keycloak (OIDC). Local password sign-in stays available
# only for platform admins as a break-glass account. local: everything uses the built-in sign-in.
AUTH_MODE = os.environ.get("AUTH_MODE", "keycloak")


def kc():
    from app.services import keycloak_admin
    return keycloak_admin


def _now(): return datetime.now(timezone.utc)


def _audit(cur, p: Principal | None, action, target=None, detail=None, org_id=None, ip=None):
    audit.write(cur, org_id if org_id is not None else (p.org_id if p else None),
                p.user_id if p and p.kind == "user" else None, p.role if p else "system",
                action, target, detail, ip or (p.ip if p else None))


# =====================================================================
# Sign-in: password -> TOTP -> short access token + rotating refresh cookie
# =====================================================================
class Login(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)


TOO_MANY = "Too many attempts. Try again in a few minutes"


def _throttle_locked(key: bytes, ip: str) -> bool:
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT locked_until FROM login_throttle WHERE key_hash=%s AND ip=%s", (key, ip))
        r = cur.fetchone()
    return bool(r and r[0] and r[0] > _now())


def _throttle_fail(key: bytes, ip: str) -> int:
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO login_throttle (key_hash, ip, failed, updated_at) VALUES (%s,%s,1,now())
                       ON CONFLICT (key_hash, ip) DO UPDATE SET
                         failed = CASE WHEN login_throttle.locked_until < now() THEN 1 ELSE login_throttle.failed + 1 END,
                         locked_until = CASE WHEN login_throttle.locked_until < now() THEN NULL ELSE login_throttle.locked_until END,
                         updated_at = now()
                       RETURNING failed""", (key, ip))
        failed = cur.fetchone()[0]
        if failed >= MAX_FAILED:
            cur.execute("UPDATE login_throttle SET locked_until=%s WHERE key_hash=%s AND ip=%s",
                        (_now() + timedelta(minutes=LOCK_MIN), key, ip))
        conn.commit()
    return failed


def _throttle_clear(key: bytes, ip: str):
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM login_throttle WHERE key_hash=%s AND ip=%s", (key, ip))
        conn.commit()


@router.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, response: Response, body: Login):
    """Every failure looks the same: unknown email, wrong password, an organization user who must use
    Keycloak, or a non-active account all get the same 401 after the same password-hash work.
    Lockout is per (email, client IP) and applies to unknown emails too, so a 429 reveals nothing,
    and someone guessing from one network can't lock the real owner out of the break-glass login."""
    bidx = crypto.blind_index(body.email)
    ip = client_ip(request) or ""
    if _throttle_locked(bidx, ip):
        raise HTTPException(429, TOO_MANY)
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, org_id FROM auth_lookup(%s)", (bidx,))
        found = cur.fetchone()
    if not found or (AUTH_MODE == "keycloak" and found[1] is not None):
        passwords.verify_password(None, body.password)          # same timing as a real check
        _throttle_fail(bidx, ip)
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    uid, org = found
    error = None
    result = None
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""SELECT password_hash, status, failed_logins, mfa_enabled, role_id, session_version
                       FROM users WHERE id=%s FOR UPDATE""", (uid,))
        pw_hash, status, failed, mfa_enabled, role_id, sv = cur.fetchone()
        if not passwords.verify_password(pw_hash, body.password) or status != "active":
            failed += 1
            cur.execute("UPDATE users SET failed_logins=%s WHERE id=%s", (failed, uid))
            audit.write(cur, org, uid, None, "login_failed", None, {"failed": failed}, client_ip(request))
            error = HTTPException(401, GENERIC_LOGIN_ERROR)       # raised after commit so the count is kept
        else:
            if passwords.needs_rehash(pw_hash):
                cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (passwords.hash_password(body.password), uid))
            cur.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=%s", (uid,))
            if not mfa_enabled:
                # No two-factor yet: a password-only session. The API limits it (rbac.current_user) until the
                # user sets two-factor up, or, where the organization allows it, chooses to skip it.
                cur.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))
                audit.write(cur, org, uid, None, "login", None, {"method": "password", "mfa": False}, client_ip(request))
                result = _issue(cur, response, uid, org, role_id, sv, request, method="password", mfa=False)
    if error:
        _throttle_fail(bidx, ip)
        raise error
    _throttle_clear(bidx, ip)
    if result:
        return {**result, "mfa_enabled": False}
    return {"mfa_token": tokens.issue_mfa_pending(uid), "next": "Enter the code from your authenticator app"}


class MfaIn(BaseModel):
    mfa_token: str
    code: str | None = None
    recovery_code: str | None = None


def _set_refresh(response: Response, raw: str):
    response.set_cookie("sentrail_rt", raw, httponly=True, secure=True, samesite="strict",
                        path="/auth", max_age=int(tokens.REFRESH_TTL.total_seconds()))


def _session_limits(cur, org) -> tuple[int, int]:
    """(idle timeout in minutes, maximum session length in hours) for this organization or the platform."""
    cur.execute("SELECT max_idle_timeout_min, max_session_hours FROM platform_settings")
    idle, max_hours = cur.fetchone()
    if org is not None:
        cur.execute("SELECT idle_timeout_min FROM security_settings WHERE org_id=%s", (org,))
        r = cur.fetchone()
        if r:
            idle = min(idle, r[0])
    return idle, max_hours


def _issue(cur, response, uid, org, role_id, sv, request, family=None, method="password+totp", mfa=True):
    idle, _ = _session_limits(cur, org)
    raw = tokens.new_opaque()
    family = family or uuid.uuid4()
    cur.execute("""INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at, user_agent, ip, auth_method)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (uid, family, crypto.sha256(raw), tokens.refresh_expiry(),
                 request.headers.get("user-agent", "")[:200], client_ip(request), method))
    _set_refresh(response, raw)
    ttl = min(tokens.ACCESS_TTL, timedelta(minutes=idle))
    return {"access_token": tokens.issue_access(uid, org, role_id, sv, mfa=mfa, ttl=ttl, session_id=family),
            "token_type": "Bearer",
            "expires_in": int(ttl.total_seconds())}


@router.post("/auth/mfa")
@limiter.limit("10/minute")
def verify_mfa(request: Request, response: Response, body: MfaIn):
    try:
        uid = tokens.decode(body.mfa_token, typ="mfa_pending")["sub"]
    except Exception:
        raise HTTPException(401, "Sign-in expired. Start again")
    org = _org_of(uid)
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""SELECT totp_secret_enc, totp_last_step, role_id, session_version, mfa_enabled, status
                       FROM users WHERE id=%s FOR UPDATE""", (uid,))
        row = cur.fetchone()
        if not row or not row[4] or not row[0] or row[5] != "active":
            # Account removed, suspended, or two-factor turned off since the password step: start over.
            raise HTTPException(401, "Sign-in expired. Start again")
        enc, last, role_id, sv = row[:4]
        ok = False
        if body.code:
            step = mfa.verify(crypto.decrypt(enc, org, "totp"), body.code, last)
            if step:
                cur.execute("UPDATE users SET totp_last_step=%s WHERE id=%s", (step, uid)); ok = True
        elif body.recovery_code:
            cur.execute("SELECT ctid, code_hash FROM recovery_codes WHERE user_id=%s AND used_at IS NULL", (uid,))
            rows = cur.fetchall()
            i = mfa.check_recovery(body.recovery_code, [r[1] for r in rows])
            if i is not None:
                cur.execute("UPDATE recovery_codes SET used_at=now() WHERE ctid=%s", (rows[i][0],)); ok = True
        if not ok:
            audit.write(cur, org, uid, None, "mfa_failed", None, {}, client_ip(request))
        else:
            cur.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))
            audit.write(cur, org, uid, None, "login", None, {"method": "totp" if body.code else "recovery_code"}, client_ip(request))
            result = _issue(cur, response, uid, org, role_id, sv, request)
    if not ok:
        raise HTTPException(401, "That code didn't work. Check your app and try again")
    return result


def _org_of(uid):
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT org_id FROM user_org_lookup(%s)", (uid,))
        r = cur.fetchone()
    if not r:
        raise HTTPException(401, "Sign in again")
    return r[0]


@router.post("/auth/refresh")
def refresh(request: Request, response: Response, sentrail_rt: str | None = Cookie(None)):
    if not sentrail_rt:
        raise HTTPException(401, "Sign in again")
    h = crypto.sha256(sentrail_rt)
    error = None
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT t.id, t.user_id, t.family_id, t.expires_at, t.revoked_at, t.created_at,
                              (SELECT min(created_at) FROM refresh_tokens f WHERE f.family_id=t.family_id), t.auth_method
                       FROM refresh_tokens t WHERE t.token_hash=%s FOR UPDATE""", (h,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(401, "Sign in again")
        tid, uid, fam, exp, revoked, last_active, started, method = row
        if revoked:   # reuse of a rotated token: assume theft, end every session in this family
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (fam,))
            error = "reuse"
        elif exp < _now():
            error = "expired"
        else:
            # Organization idle timeout and the platform's maximum session length. Each refresh token is
            # issued when the previous one is used, so its created_at is the last time this session was active.
            idle, max_hours = _session_limits(cur, _org_of(uid))
            if _now() - last_active > timedelta(minutes=idle) or _now() - started > timedelta(hours=max_hours):
                cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (fam,))
                error = "timed_out"
            else:
                cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE id=%s", (tid,))
    if error:
        org = _org_of(uid)
        if error == "reuse":
            with pg.tx(org, platform=org is None) as cur:
                audit.write(cur, org, uid, None, "refresh_token_reuse_detected", str(fam), {}, client_ip(request))
        raise HTTPException(401, "Sign in again")
    org = _org_of(uid)
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("SELECT status, role_id, session_version FROM users WHERE id=%s", (uid,))
        status, role_id, sv = cur.fetchone()
        if status != "active":
            raise HTTPException(401, "Your account isn't active")
        # same assurance as the original sign-in: a password-only session stays password-only
        return _issue(cur, response, uid, org, role_id, sv, request, family=fam, method=method or "password+totp",
                      mfa=method != "password")


# =====================================================================
# Sign-in through Keycloak (OpenID Connect, authorization code + PKCE)
# =====================================================================
class Discover(BaseModel):
    email: EmailStr


@router.post("/auth/discover")
@limiter.limit("20/minute")
def discover(request: Request, body: Discover):
    """Home-realm discovery: company domains with SSO go straight to their identity provider.
    Unknown emails get the same answer as known ones, so this can't be used to find accounts."""
    domain = body.email.split("@", 1)[1].lower()
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT org_id, idp_alias, enforced FROM sso_domain_lookup(%s)", (domain,))
        r = cur.fetchone()
    if r and r[1]:
        return {"method": "sso", "next": "/auth/oidc/login?" + urlencode({"email": body.email, "idp": r[1]})}
    return {"method": "keycloak", "next": "/auth/oidc/login?" + urlencode({"email": body.email})}


@router.get("/auth/oidc/login")
@limiter.limit("30/minute")
def oidc_login(request: Request, email: str | None = None, idp: str | None = None, return_to: str = "/"):
    if not return_to.startswith("/") or return_to.startswith("//"):
        return_to = "/"                                   # no open redirects
    login = oidc.new_login()
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM oidc_login_states WHERE expires_at < now()")
        cur.execute("INSERT INTO oidc_login_states (state_hash, nonce, code_verifier, return_to) VALUES (%s,%s,%s,%s)",
                    (crypto.sha256(login["state"]), login["nonce"], login["verifier"], return_to))
        conn.commit()
    return RedirectResponse(oidc.authorize_url(login, email, idp), status_code=302)


def _fail(reason: str):
    return RedirectResponse(f"{APP_URL}/signin?error={reason}", status_code=302)


@router.get("/auth/oidc/callback")
def oidc_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error or not code or not state:
        return _fail("cancelled")
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("""DELETE FROM oidc_login_states WHERE state_hash=%s AND expires_at > now()
                       RETURNING nonce, code_verifier, return_to""", (crypto.sha256(state),))
        st = cur.fetchone()
        conn.commit()
    if not st:
        return _fail("expired")                           # unknown, reused or expired state
    nonce, verifier, return_to = st
    try:
        tok = oidc.exchange_code(code, verifier)
        claims = oidc.validate_id_token(tok["id_token"], nonce)
    except (ValueError, KeyError, pyjwt.PyJWTError):
        return _fail("invalid")

    uid, org = _link_identity(claims)
    if not uid:
        return _fail("no_account")
    response = RedirectResponse(f"{APP_URL}{return_to}", status_code=302)
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("SELECT status, role_id, session_version FROM users WHERE id=%s FOR UPDATE", (uid,))
        status, role_id, sv = cur.fetchone()
        if status == "suspended":
            audit.write(cur, org, uid, None, "login_blocked_suspended", None, {"via": "oidc"}, client_ip(request))
            blocked = True
        else:
            blocked = False
            if status == "invited":
                cur.execute("UPDATE users SET status='active' WHERE id=%s", (uid,))
            cur.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))
            audit.write(cur, org, uid, None, "login", None, {"via": "oidc", "amr": claims.get("amr")}, client_ip(request))
            _issue(cur, response, uid, org, role_id, sv, request, method="keycloak")
    return _fail("suspended") if blocked else response


def _link_identity(claims) -> tuple:
    """Find the Sentrail user for this Keycloak identity. Never creates accounts: admins invite people."""
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, org_id FROM idp_lookup(%s)", (claims["sub"],))
        r = cur.fetchone()
        if r:
            return r
        email = claims.get("email")
        if not email:
            return None, None
        cur.execute("SELECT id, org_id FROM auth_lookup(%s)", (crypto.blind_index(email),))
        r = cur.fetchone()
    if not r:
        return None, None
    uid, org = r
    # First sign-in of an invited user through their company's SSO: link by verified email,
    # but only if the email domain is the organization's verified SSO domain.
    domain = email.split("@", 1)[1].lower()
    with pg.tx(org) as cur:
        cur.execute("SELECT idp_subject, status FROM users WHERE id=%s FOR UPDATE", (uid,))
        subj, status = cur.fetchone()
    with pg.pool().connection() as conn, conn.cursor() as c2:
        c2.execute("SELECT org_id FROM sso_domain_lookup(%s)", (domain,))
        d = c2.fetchone()
    if subj or not d or str(d[0]) != str(org):
        return None, None
    with pg.tx(org) as cur:
        cur.execute("UPDATE users SET idp_subject=%s, auth_method='keycloak' WHERE id=%s AND idp_subject IS NULL",
                    (claims["sub"], uid))
        audit.write(cur, org, uid, None, "identity_linked", None, {"via": "company_sso"}, None)
    return uid, org


@router.get("/auth/oidc/logout")
def oidc_logout(sentrail_rt: str | None = Cookie(None)):
    if sentrail_rt:
        with pg.tx(platform=True) as cur:
            cur.execute("""UPDATE refresh_tokens SET revoked_at=now() WHERE family_id =
                           (SELECT family_id FROM refresh_tokens WHERE token_hash=%s) AND revoked_at IS NULL""",
                        (crypto.sha256(sentrail_rt),))
    resp = RedirectResponse(oidc.logout_url(), status_code=302)
    resp.delete_cookie("sentrail_rt", path="/auth")
    return resp


@router.post("/auth/logout")
def logout(response: Response, sentrail_rt: str | None = Cookie(None)):
    if sentrail_rt:
        with pg.tx(platform=True) as cur:
            cur.execute("""UPDATE refresh_tokens SET revoked_at=now() WHERE family_id =
                           (SELECT family_id FROM refresh_tokens WHERE token_hash=%s) AND revoked_at IS NULL""",
                        (crypto.sha256(sentrail_rt),))
    response.delete_cookie("sentrail_rt", path="/auth")
    return {"signed_out": True}


# =====================================================================
# Organizations (platform admins only; they never see customer data)
# =====================================================================
class OrgIn(BaseModel):
    legal_name: str = Field(min_length=2, max_length=200)
    environment: str = Field("production", pattern="^(production|sandbox)$")
    brand_color: str = Field("#0F6E56", pattern="^#[0-9A-Fa-f]{6}$")
    business_type: str
    registration: str = Field(min_length=3, max_length=40)
    data_region: str = "ca-central"
    plan: str = Field("professional", pattern="^(starter|professional|enterprise)$")
    features: list[str] | None = None        # default: whatever the plan includes
    admin_email: EmailStr


def provision_org(cur, legal_name, business_type, registration, data_region="ca-central", plan="professional",
                  environment="production", brand_color="#0F6E56", features=None):
    """Create an organization with its system roles, settings, features and policy. Used by the API and the seed."""
    slug = re.sub(r"[^a-z0-9]+", "-", legal_name.lower()).strip("-")[:40] + "-" + secrets.token_hex(2)
    cur.execute("""INSERT INTO organizations (legal_name, business_type, registration, data_region, plan, slug, environment, brand_color, status)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'active') RETURNING id""",
                (legal_name, business_type, registration, data_region, plan, slug, environment, brand_color))
    org = cur.fetchone()[0]
    if features is None:
        cur.execute("SELECT features FROM plans WHERE key=%s", (plan,))
        features = cur.fetchone()[0]
    cur.execute("""INSERT INTO security_settings (org_id, min_password_len, idle_timeout_min, retention_years)
                   SELECT %s, min_password_len_floor, LEAST(15, max_idle_timeout_min), retention_years_floor FROM platform_settings""", (org,))
    for f in FEATURES:
        cur.execute("INSERT INTO org_features VALUES (%s,%s,%s,%s)", (org, f, f in features, f in features))
    role_ids = {}
    cur.execute("SELECT name FROM role_templates WHERE scope='tenant' ORDER BY sort")
    for (name,) in cur.fetchall():
        cur.execute("INSERT INTO roles (org_id, name, is_system) VALUES (%s,%s,true) RETURNING id", (org, name))
        role_ids[name] = cur.fetchone()[0]
        cur.execute("""INSERT INTO role_permissions SELECT %s, perm FROM role_template_permissions WHERE template=%s""",
                    (role_ids[name], name))
    # the org's own data is written inside its tenant scope (platform scope can't write customer-side tables)
    cur.execute("SELECT set_config('app.org_id', %s, true)", (str(org),))
    cur.execute("""INSERT INTO screening_policy VALUES (%s, '{"hold_at":40,"block_at":75,"travel_rule_threshold":1000,
                   "self_hosted_proof_above":1000,"always_block_sanctions":true}')""", (org,))
    return org, role_ids


@router.post("/platform/orgs")
def create_org(body: OrgIn, p: Principal = Depends(require("orgs.manage"))):
    if body.features and not set(body.features) <= set(FEATURES):
        raise HTTPException(400, "Unknown feature")
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT allowed_regions FROM platform_settings")
        if body.data_region not in cur.fetchone()[0]:
            raise HTTPException(422, "That data region isn't allowed on this platform")
        org, role_ids = provision_org(cur, body.legal_name, body.business_type, body.registration, body.data_region,
                                      body.plan, body.environment, body.brand_color, body.features)
        link = _invite(cur, org, body.legal_name, body.admin_email, role_ids["Organization admin"], "Organization admin", None)
        _audit(cur, p, "org_created", body.legal_name, {"plan": body.plan, "features": body.features,
               "admin": crypto.mask_email(body.admin_email)}, org_id=org)
    return {"org_id": str(org), "invited": crypto.mask_email(body.admin_email), **({"dev_link": link} if _dev() else {})}


@router.get("/platform/orgs")
def list_orgs(p: Principal = Depends(require_any("orgs.manage", "platform.support"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT o.id, o.legal_name, o.business_type, o.registration, o.data_region, o.plan, o.status,
                              (SELECT count(*) FROM users u WHERE u.org_id=o.id),
                              (SELECT array_agg(feature) FROM org_features f WHERE f.org_id=o.id AND f.in_plan)
                       FROM organizations o ORDER BY o.created_at""")
        cols = ["id", "legal_name", "business_type", "registration", "data_region", "plan", "status", "users", "features"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


class PlanFeatures(BaseModel):
    features: list[str]


@router.put("/platform/orgs/{org_id}/features")
def set_plan_features(org_id: uuid.UUID, body: PlanFeatures, p: Principal = Depends(require("platform.plans.manage"))):
    with pg.tx(platform=True) as cur:
        for f in FEATURES:
            cur.execute("UPDATE org_features SET in_plan=%s, enabled = enabled AND %s WHERE org_id=%s AND feature=%s",
                        (f in body.features, f in body.features, org_id, f))
        _audit(cur, p, "plan_features_changed", str(org_id), {"features": body.features}, org_id=org_id)
    return {"ok": True}


# =====================================================================
# Invitations and enrollment
# =====================================================================
def _dev() -> bool:
    """Invitation links are returned in API responses only when ENV=dev is set explicitly."""
    return config.IS_DEV


def _invite(cur, org, org_name, email, role_id, role_name, invited_by) -> str:
    bidx = crypto.blind_index(email)
    cur.execute("SELECT 1 FROM auth_lookup(%s)", (bidx,))
    if cur.fetchone():
        raise HTTPException(409, "This person already has an account or invitation")
    cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, status)
                   VALUES (%s,%s,%s,%s,'invited') RETURNING id""",
                (org, role_id, crypto.encrypt(crypto.normalize_email(email), org, "email"), bidx))
    uid = cur.fetchone()[0]
    if AUTH_MODE == "keycloak":
        sso_domain = None
        if org is not None:
            cur.execute("SELECT sso_domain FROM organizations WHERE id=%s", (org,))
            sso_domain = (cur.fetchone() or [None])[0]
        if sso_domain and email.lower().endswith("@" + str(sso_domain).lower()):
            # Company SSO: nothing to set up. They sign in with their work account; we link on first sign-in.
            cur.execute("UPDATE users SET auth_method='keycloak' WHERE id=%s", (uid,))
            mailer.send_invitation(email, org_name, role_name, f"{APP_URL}/signin")
            return f"{APP_URL}/signin"
        # Everyone else: Keycloak emails a single-use link to verify email, set a password and set up two-factor.
        sub = kc().create_user(crypto.normalize_email(email), str(org) if org else "platform")
        try:
            cur.execute("UPDATE users SET idp_subject=%s, auth_method='keycloak' WHERE id=%s", (sub, uid))
            kc().send_setup_email(sub)
        except Exception:
            kc().delete_user(sub)      # don't leave an orphan account in Keycloak if ours isn't saved
            raise
        return "sent by Keycloak"
    raw = tokens.new_opaque()
    cur.execute("""INSERT INTO invitations (org_id, user_id, token_hash, invited_by, expires_at)
                   VALUES (%s,%s,%s,%s, now() + interval '72 hours')""", (org, uid, crypto.sha256(raw), invited_by))
    link = f"{APP_URL}/join#{raw}"          # fragment: never sent to servers or logged by proxies
    mailer.send_invitation(email, org_name, role_name, link)
    return link


class InviteIn(BaseModel):
    email: EmailStr
    role_id: uuid.UUID


@router.post("/admin/invitations")
@limiter.limit("30/hour")
def invite(request: Request, body: InviteIn, p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id) as cur:
        role = _role_in_org(cur, body.role_id, p.org_id)
        _no_escalation(cur, p, body.role_id)
        link = _invite(cur, p.org_id, _org_name(p.org_id), body.email, body.role_id, role, p.user_id)
        _audit(cur, p, "user_invited", crypto.mask_email(body.email), {"role": role})
    return {"invited": crypto.mask_email(body.email), **({"dev_link": link} if _dev() else {})}


def _org_name(org_id):
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT legal_name FROM organizations WHERE id=%s", (org_id,))
        return cur.fetchone()[0]


def _role_in_org(cur, role_id, org_id) -> str:
    cur.execute("SELECT name FROM roles WHERE id=%s AND org_id=%s", (role_id, org_id))
    r = cur.fetchone()
    if not r:
        raise HTTPException(404, "Role not found")
    return r[0]


def _no_escalation(cur, p: Principal, role_id):
    """You can only give someone permissions you hold yourself."""
    cur.execute("SELECT perm FROM role_permissions WHERE role_id=%s", (role_id,))
    extra = {r[0] for r in cur.fetchall()} - p.perms
    if extra and not p.can("roles.manage"):
        raise HTTPException(403, f"You can't assign permissions you don't have: {', '.join(sorted(extra))}")


def _invitation(token: str):
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, org_id, user_id, expires_at, accepted_at FROM invitation_lookup(%s)", (crypto.sha256(token),))
        r = cur.fetchone()
    if not r or r[4] or r[3] < _now():
        raise HTTPException(410, "This invitation has expired or was already used. Ask your admin for a new one")
    return r


class AcceptIn(BaseModel):
    token: str
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(max_length=256)


@router.post("/invitations/accept")
@limiter.limit("10/minute")
def accept(request: Request, body: AcceptIn):
    """Set name and password and activate the account. Two-factor is set up after the first sign-in
    (POST /me/mfa/setup): required or optional depending on the organization and the role."""
    inv_id, org, uid, _, _ = _invitation(body.token)
    with pg.tx(org, platform=org is None) as cur:
        if org is None:
            cur.execute("SELECT min_password_len_floor FROM platform_settings")
        else:
            cur.execute("SELECT min_password_len FROM security_settings WHERE org_id=%s", (org,))
        min_len = cur.fetchone()[0]
        cur.execute("SELECT email_enc FROM users WHERE id=%s FOR UPDATE", (uid,))
        email = crypto.decrypt(cur.fetchone()[0], org, "email")
        problems = passwords.check_policy(body.password, min_len, [body.full_name, *body.full_name.split(), email.split("@")[0]])
        if problems:
            raise HTTPException(422, problems)
        cur.execute("""UPDATE users SET name_enc=%s, password_hash=%s, status='active' WHERE id=%s""",
                    (crypto.encrypt(body.full_name, org, "name"), passwords.hash_password(body.password), uid))
        cur.execute("UPDATE invitations SET accepted_at=now() WHERE id=%s", (inv_id,))
        audit.write(cur, org, uid, None, "user_enrolled", None, {"mfa": "after_sign_in"}, client_ip(request))
    return {"activated": True, "next": "Sign in with your email and new password"}


# =====================================================================
# Two-factor setup for the signed-in user (also from a password-only session)
# =====================================================================
class MfaConfirm(BaseModel):
    code: str = Field(max_length=10)


def _local_user(cur, p: Principal):
    cur.execute("SELECT mfa_enabled, auth_method, email_enc FROM users WHERE id=%s FOR UPDATE", (p.user_id,))
    enabled, method, email_enc = cur.fetchone()
    if method == "keycloak":
        raise HTTPException(409, "Your sign-in provider manages your two-factor authentication")
    if enabled:
        raise HTTPException(409, "Two-factor authentication is already on")
    return email_enc


@router.post("/me/mfa/setup")
@limiter.limit("10/minute")
def mfa_setup(request: Request, p: Principal = Depends(signed_in_user)):
    """Start TOTP setup: a new secret, kept unconfirmed until /me/mfa/confirm. Calling it again replaces it."""
    with pg.tx(p.org_id, platform=p.platform) as cur:
        email = crypto.decrypt(_local_user(cur, p), p.org_id, "email")
        secret = mfa.new_secret()
        cur.execute("UPDATE users SET totp_secret_enc=%s, totp_last_step=0 WHERE id=%s",
                    (crypto.encrypt(secret, p.org_id, "totp"), p.user_id))
    return {"otpauth_uri": mfa.provisioning_uri(secret, email), "secret": secret,
            "next": "Add it to your authenticator app, then send a 6-digit code to /me/mfa/confirm"}


@router.post("/me/mfa/confirm")
@limiter.limit("10/minute")
def mfa_confirm(request: Request, response: Response, body: MfaConfirm, p: Principal = Depends(signed_in_user)):
    """Turn two-factor on. Ends every session of this user (they were password-only) and starts a new,
    two-factor session for this device. Returns single-use recovery codes, shown once."""
    with pg.tx(p.org_id, platform=p.platform) as cur:
        _local_user(cur, p)
        cur.execute("SELECT totp_secret_enc, totp_last_step, role_id, session_version FROM users WHERE id=%s", (p.user_id,))
        enc, last, role_id, sv = cur.fetchone()
        if not enc:
            raise HTTPException(409, "Start the setup first")
        step = mfa.verify(crypto.decrypt(enc, p.org_id, "totp"), body.code, last)
        if not step:
            raise HTTPException(401, "That code didn't work. Check your app's time and try again")
        codes, hashes = mfa.new_recovery_codes()
        cur.execute("""UPDATE users SET mfa_enabled=true, totp_last_step=%s, session_version=session_version+1
                       WHERE id=%s""", (step, p.user_id))
        cur.execute("DELETE FROM recovery_codes WHERE user_id=%s", (p.user_id,))
        for h in hashes:
            cur.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (%s,%s)", (p.user_id, h))
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (p.user_id,))
        _audit(cur, p, "mfa_enabled", None, {"method": "totp"})
        session = _issue(cur, response, p.user_id, p.org_id, role_id, sv + 1, request)
    return {**session, "recovery_codes": codes,
            "message": "Save these codes somewhere safe. Each works once and they won't be shown again"}


# =====================================================================
# Users
# =====================================================================
@router.get("/admin/users")
def list_users(p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("""SELECT u.id, u.name_enc, u.email_enc, r.name, u.status, u.mfa_enabled, u.last_login_at, u.mfa_enabled_at
                       FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.created_at""")
        rows = cur.fetchall()
        _audit(cur, p, "users_listed")
    return [{"id": str(r[0]), "name": crypto.decrypt(r[1], p.org_id, "name"),
             "email": crypto.mask_email(crypto.decrypt(r[2], p.org_id, "email")),
             "role": r[3], "status": r[4], "mfa": r[5], "mfa_enabled_at": r[7], "last_login": r[6]} for r in rows]


class Reason(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


@router.post("/admin/users/{uid}/reveal-email")
def reveal(uid: uuid.UUID, body: Reason, p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("SELECT email_enc FROM users WHERE id=%s", (uid,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "User not found")
        _audit(cur, p, "email_revealed", str(uid), {"reason": body.reason})
    return {"email": crypto.decrypt(r[0], p.org_id, "email")}


class UserPatch(BaseModel):
    role_id: uuid.UUID | None = None
    status: str | None = Field(None, pattern="^(active|suspended)$")


@router.patch("/admin/users/{uid}")
def update_user(uid: uuid.UUID, body: UserPatch, p: Principal = Depends(require("users.manage"))):
    if str(uid) == p.user_id:
        raise HTTPException(403, "You can't change your own role or status. Ask another admin")
    with pg.tx(p.org_id) as cur:
        cur.execute("SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s", (uid,))
        cur_role = cur.fetchone()
        if not cur_role:
            raise HTTPException(404, "User not found")
        if body.role_id:
            new_role = _role_in_org(cur, body.role_id, p.org_id)
            _no_escalation(cur, p, body.role_id)
            if cur_role[0] == "Organization admin" and new_role != "Organization admin":
                _keep_one_admin(cur, p.org_id)
            cur.execute("UPDATE users SET role_id=%s, session_version=session_version+1 WHERE id=%s", (body.role_id, uid))
            _audit(cur, p, "role_changed", str(uid), {"from": cur_role[0], "to": new_role})
        if body.status:
            cur.execute("SELECT status FROM users WHERE id=%s", (uid,))
            if body.status == "active" and cur.fetchone()[0] == "invited":
                raise HTTPException(409, "This person hasn't finished setting up their account yet")
            if body.status == "suspended" and cur_role[0] == "Organization admin":
                _keep_one_admin(cur, p.org_id)
            cur.execute("UPDATE users SET status=%s, session_version=session_version+1 WHERE id=%s RETURNING idp_subject", (body.status, uid))
            subj = cur.fetchone()[0]
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
            if AUTH_MODE == "keycloak" and subj:
                kc().set_enabled(subj, body.status == "active")   # also ends their Keycloak sessions
            _audit(cur, p, f"user_{body.status}", str(uid), {"sessions_ended": True})
    return {"ok": True}


def _keep_one_admin(cur, org_id):
    cur.execute("""SELECT count(*) FROM users u JOIN roles r ON r.id=u.role_id
                   WHERE r.name='Organization admin' AND u.status='active'""")
    if cur.fetchone()[0] <= 1:
        raise HTTPException(409, "Your organization needs at least one active admin")


@router.post("/admin/users/{uid}/reset-mfa")
def reset_mfa(uid: uuid.UUID, body: Reason, p: Principal = Depends(require("users.manage"))):
    if str(uid) == p.user_id:
        raise HTTPException(403, "Ask another admin to reset your two-factor")
    if AUTH_MODE == "keycloak":
        with pg.tx(p.org_id) as cur:
            cur.execute("UPDATE users SET session_version=session_version+1 WHERE id=%s RETURNING idp_subject", (uid,))
            r = cur.fetchone()
            if not r:
                raise HTTPException(404, "User not found")
            if not r[0]:
                raise HTTPException(409, "This person signs in with company SSO. Their company manages two-factor")
            kc().reset_second_factor(r[0])
            _audit(cur, p, "mfa_reset", str(uid), {"reason": body.reason, "via": "keycloak"})
        return {"ok": True}
    with pg.tx(p.org_id) as cur:
        cur.execute("""UPDATE users SET totp_secret_enc=NULL, mfa_enabled=false, totp_last_step=0,
                       session_version=session_version+1 WHERE id=%s RETURNING 1""", (uid,))
        if not cur.fetchone():
            raise HTTPException(404, "User not found")
        cur.execute("DELETE FROM recovery_codes WHERE user_id=%s", (uid,))
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
        _audit(cur, p, "mfa_reset", str(uid), {"reason": body.reason})
    return {"ok": True, "next": "They'll be asked to set up two-factor again at their next sign-in"}


# =====================================================================
# Roles and permissions
# =====================================================================
@router.get("/admin/roles")
def list_roles(p: Principal = Depends(require("roles.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("""SELECT r.id, r.name, r.is_system, COALESCE(array_agg(rp.perm) FILTER (WHERE rp.perm IS NOT NULL), '{}')
                       FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id GROUP BY r.id ORDER BY r.name""")
        roles = [{"id": str(r[0]), "name": r[1], "system": r[2], "perms": sorted(r[3])} for r in cur.fetchall()]
    return {"roles": roles, "warnings": _sod_warnings(roles)}


def _sod_warnings(roles):
    return [f"{r['name']} can both manage users and decide cases. One person could create an account and approve their own work."
            for r in roles if "users.manage" in r["perms"] and ({"cases.decide", "str.approve"} & set(r["perms"]))]


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    perms: list[str]

    @field_validator("perms")
    @classmethod
    def tenant_only(cls, v):
        if any(x == "orgs.manage" or x.startswith("platform.") for x in v):
            raise ValueError("Platform permissions can't be given to organization roles")
        return v


def _write_perms(cur, p, role_id, perms):
    # No self-escalation: nobody can change the permissions of the role they hold.
    cur.execute("SELECT 1 FROM users WHERE id=%s AND role_id=%s", (p.user_id, role_id))
    if cur.fetchone():
        raise HTTPException(403, "You can't change the permissions of your own role. Ask another admin")
    cur.execute("DELETE FROM role_permissions WHERE role_id=%s", (role_id,))
    for perm in perms:
        cur.execute("INSERT INTO role_permissions VALUES (%s,%s)", (role_id, perm))


@router.post("/admin/roles")
def create_role(body: RoleIn, p: Principal = Depends(require("roles.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("INSERT INTO roles (org_id, name) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING id", (p.org_id, body.name))
        r = cur.fetchone()
        if not r:
            raise HTTPException(409, "A role with this name already exists")
        _write_perms(cur, p, r[0], body.perms)
        _audit(cur, p, "role_created", body.name, {"perms": body.perms})
    return {"id": str(r[0])}


@router.put("/admin/roles/{role_id}")
def update_role(role_id: uuid.UUID, body: RoleIn, p: Principal = Depends(require("roles.manage"))):
    with pg.tx(p.org_id) as cur:
        name = _role_in_org(cur, role_id, p.org_id)
        if name == "Organization admin" and "users.manage" not in body.perms:
            raise HTTPException(409, "Organization admin must keep 'users.manage' so nobody is locked out")
        cur.execute("SELECT array_agg(perm) FROM role_permissions WHERE role_id=%s", (role_id,))
        before = cur.fetchone()[0] or []
        _write_perms(cur, p, role_id, body.perms)
        cur.execute("UPDATE users SET session_version=session_version+1 WHERE role_id=%s", (role_id,))  # apply now
        _audit(cur, p, "role_permissions_changed", name, {"added": sorted(set(body.perms) - set(before)),
                                                          "removed": sorted(set(before) - set(body.perms))})
    return {"ok": True}


# =====================================================================
# Features and security settings
# =====================================================================
class FeatureToggle(BaseModel):
    feature: str
    enabled: bool


@router.get("/admin/features")
def get_features(p: Principal = Depends(require("features.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("SELECT feature, in_plan, enabled FROM org_features ORDER BY feature")
        return [{"feature": r[0], "in_plan": r[1], "enabled": r[2]} for r in cur.fetchall()]


@router.put("/admin/features")
def toggle_feature(body: FeatureToggle, p: Principal = Depends(require("features.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("UPDATE org_features SET enabled=%s WHERE feature=%s AND in_plan RETURNING 1", (body.enabled, body.feature))
        if not cur.fetchone():
            raise HTTPException(403, "This feature isn't in your plan")
        _audit(cur, p, "feature_toggled", body.feature, {"enabled": body.enabled})
    return {"ok": True}


class SecurityIn(BaseModel):
    """Every field is optional: only the fields you send change, the rest keep their current values."""
    mfa_required: bool | None = None
    sso_enabled: bool | None = None
    oidc_issuer: str | None = Field(None, pattern=r"^https://")
    oidc_client_id: str | None = None
    idle_timeout_min: int | None = Field(None, ge=5, le=60)
    min_password_len: int | None = Field(None, ge=12, le=64)
    ip_allowlist: list[str] | None = None
    retention_years: int | None = Field(None, ge=5, le=15)

    @field_validator("ip_allowlist")
    @classmethod
    def cidrs(cls, v):
        for c in v or []:
            ipaddress.ip_network(c, strict=False)
        return v


SECURITY_COLS = ["mfa_required", "sso_enabled", "oidc_issuer", "oidc_client_id", "idle_timeout_min",
                 "min_password_len", "ip_allowlist", "retention_years"]


@router.get("/admin/security")
def get_security(p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("""SELECT mfa_required, sso_enabled, oidc_issuer, oidc_client_id, idle_timeout_min,
                              min_password_len, ip_allowlist, retention_years FROM security_settings""")
        r = cur.fetchone()
    out = dict(zip(SECURITY_COLS, r)); out["ip_allowlist"] = [str(x) for x in out["ip_allowlist"]]
    out["encryption"] = {"algorithm": "AES-256-GCM", "current_key": crypto.ring().current,
                         "key_manager": "OpenBao transit" if os.environ.get("BAO_ADDR") else "local (dev only)"}
    return out


@router.put("/admin/security")
def set_security(body: SecurityIn, p: Principal = Depends(require("users.manage"))):
    changes = body.model_dump(exclude_unset=True)
    with pg.tx(p.org_id) as cur:
        cur.execute(f"SELECT {', '.join(SECURITY_COLS)} FROM security_settings FOR UPDATE")
        current = dict(zip(SECURITY_COLS, cur.fetchone()))
        current["ip_allowlist"] = [str(x) for x in current["ip_allowlist"]]
        new = {**current, **{k: v for k, v in changes.items() if v is not None or k in ("oidc_issuer", "oidc_client_id")}}
        if new["ip_allowlist"] and (p.ip is None or not any(ipaddress.ip_address(p.ip) in ipaddress.ip_network(c, strict=False)
                                                            for c in new["ip_allowlist"])):
            raise HTTPException(409, "This allowlist would lock you out. Include your current network")
        cur.execute("SELECT min_password_len_floor, max_idle_timeout_min, retention_years_floor FROM platform_settings")
        pw_floor, idle_max, ret_floor = cur.fetchone()
        if new["min_password_len"] < pw_floor or new["idle_timeout_min"] > idle_max or new["retention_years"] < ret_floor:
            raise HTTPException(422, f"The platform requires passwords of at least {pw_floor} characters, "
                                     f"sign-out after at most {idle_max} minutes and {ret_floor}+ years of retention")
        cur.execute("""UPDATE security_settings SET mfa_required=%s, sso_enabled=%s, oidc_issuer=%s, oidc_client_id=%s,
                       idle_timeout_min=%s, min_password_len=%s, ip_allowlist=%s::cidr[], retention_years=%s""",
                    (new["mfa_required"], new["sso_enabled"], new["oidc_issuer"], new["oidc_client_id"], new["idle_timeout_min"],
                     new["min_password_len"], new["ip_allowlist"], new["retention_years"]))
        _audit(cur, p, "security_settings_changed", None,
               {"changed": {k: {"from": current[k], "to": new[k]} for k in changes if current.get(k) != new.get(k)}})
    return {"ok": True}


# =====================================================================
# API keys for the on/off-ramp
# =====================================================================
class ApiKeyIn(BaseModel):
    label: str | None = Field(None, max_length=80)


@router.post("/admin/api-keys")
def create_api_key(body: ApiKeyIn | None = None, p: Principal = Depends(require("users.manage", feature="screening"))):
    prefix = "sk_live_" + tokens.new_opaque()[:8].replace("_", "x").replace("-", "x")
    raw = f"{prefix}_{tokens.new_opaque()}"
    label = body.label if body else None
    with pg.tx(p.org_id) as cur:
        cur.execute("INSERT INTO api_keys (org_id, prefix, key_hash, created_by, label) VALUES (%s,%s,%s,%s,%s)",
                    (p.org_id, prefix, crypto.sha256(raw), p.user_id, label))
        _audit(cur, p, "api_key_created", prefix, {"label": label})
    return {"api_key": raw, "prefix": prefix, "message": "Copy this key now. It won't be shown again"}


@router.get("/admin/api-keys")
def list_api_keys(p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("SELECT prefix, label, created_at, created_by, revoked_at FROM api_keys ORDER BY created_at DESC")
        rows = cur.fetchall()
    return [{"prefix": r[0], "label": r[1], "created_at": r[2], "created_by": str(r[3]) if r[3] else None,
             "revoked_at": r[4], "active": r[4] is None} for r in rows]


@router.delete("/admin/api-keys/{prefix}")
def revoke_api_key(prefix: str, p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id) as cur:
        cur.execute("UPDATE api_keys SET revoked_at=now() WHERE prefix=%s AND revoked_at IS NULL RETURNING 1", (prefix,))
        if not cur.fetchone():
            raise HTTPException(404, "No active key with that prefix")
        _audit(cur, p, "api_key_revoked", prefix)
    return {"revoked": prefix}


# =====================================================================
# Audit
# =====================================================================
COLS = "seq, org_id, at, actor_id, actor_role, action, target, detail, ip, prev_hash, hash"


@router.get("/admin/audit")
def audit_events(limit: int = Query(200, ge=1, le=1000), p: Principal = Depends(require_any("audit.view", "platform.audit.view"))):
    with pg.tx(p.org_id, platform=p.platform) as cur:
        cur.execute(f"SELECT {COLS} FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq DESC LIMIT %s",
                    (p.org_id, limit))
        rows = cur.fetchall()
    return [{"seq": r[0], "at": r[2], "actor": str(r[3]) if r[3] else None, "role": r[4], "action": r[5],
             "target": r[6], "detail": r[7], "ip": str(r[8]) if r[8] else None} for r in rows]


@router.get("/admin/audit/verify")
def audit_verify(p: Principal = Depends(require_any("audit.view", "platform.audit.view"))):
    with pg.tx(p.org_id, platform=p.platform) as cur:
        cur.execute(f"SELECT {COLS} FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", (p.org_id,))
        return audit.verify_rows(cur.fetchall())


@router.get("/me")
def me(p: Principal = Depends(signed_in_user)):
    """Who is signed in and which tenant, so the UI can show the organization under the app name."""
    tenant = {"name": "Platform console", "slug": "platform", "environment": "platform", "brand_color": "#534AB7"}
    if p.org_id:
        with pg.pool().connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT legal_name, slug, environment, brand_color FROM org_display(%s)", (p.org_id,))
            n, slug, env, color = cur.fetchone()
        tenant = {"id": p.org_id, "name": n, "slug": slug, "environment": env, "brand_color": color}
    with pg.tx(p.org_id, platform=p.platform) as cur:
        cur.execute("SELECT name_enc, email_enc FROM users WHERE id=%s", (p.user_id,))
        n_enc, e_enc = cur.fetchone()
    return {"user_id": p.user_id, "name": crypto.decrypt(n_enc, p.org_id, "name"),
            "email": crypto.mask_email(crypto.decrypt(e_enc, p.org_id, "email")), "role": p.role,
            "tenant": tenant, "permissions": sorted(p.perms), "features": sorted(p.features),
            # mfa_setup: "required" (the organization insists), "optional" (turn it on from My account), or None (it's on)
            "mfa_enabled": p.mfa_setup is None, "mfa_setup": p.mfa_setup, "session_mfa": p.mfa}


def _current_family(p: Principal):
    """The caller's own session, from the signed access token. (The refresh cookie is scoped to /auth,
    so browsers never send it to /me/*: reading it here made every session look 'not current'.)"""
    try:
        return uuid.UUID(p.session_id) if p.session_id else None
    except ValueError:
        return None


@router.get("/me/sessions")
def my_sessions(p: Principal = Depends(current_user)):
    current = _current_family(p)
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT DISTINCT ON (family_id) family_id, user_agent, ip, auth_method, created_at
                       FROM refresh_tokens WHERE user_id=%s AND revoked_at IS NULL AND expires_at > now()
                       ORDER BY family_id, created_at DESC""", (p.user_id,))
        rows = cur.fetchall()
    return [{"id": str(r[0]), "device": r[1], "ip": str(r[2]) if r[2] else None, "method": r[3],
             "last_active": r[4], "current": r[0] == current} for r in rows]


@router.delete("/me/sessions/{family_id}")
def end_session(family_id: uuid.UUID, p: Principal = Depends(current_user)):
    with pg.tx(platform=True) as cur:
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND user_id=%s AND revoked_at IS NULL",
                    (family_id, p.user_id))
    with pg.tx(p.org_id, platform=p.platform) as cur:
        _audit(cur, p, "session_ended", str(family_id))
    return {"ok": True}


@router.post("/me/sessions/end-others")
def end_other_sessions(p: Principal = Depends(current_user)):
    current = _current_family(p)
    if current is None:
        raise HTTPException(409, "Sign in again first, so your current session can be kept")
    with pg.tx(platform=True) as cur:
        cur.execute("""UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL
                       AND family_id IS DISTINCT FROM %s""", (p.user_id, current))
        n = cur.rowcount
    with pg.tx(p.org_id, platform=p.platform) as cur:
        _audit(cur, p, "other_sessions_ended", None, {"count": n})
    return {"ended": n}



# =====================================================================
# Company single sign-on: prove the email domain by DNS, then route it to the company's IdP
# =====================================================================
class SsoIn(BaseModel):
    domain: str = Field(pattern=r"^[a-z0-9.-]+\.[a-z]{2,}$")
    idp_alias: str = Field(pattern=r"^[a-z0-9-]{2,40}$", description="Identity provider alias configured in Keycloak")
    enforced: bool = False


@router.put("/admin/sso")
def set_sso(body: SsoIn, p: Principal = Depends(require("users.manage"))):
    token = "sentrail-verify=" + secrets.token_urlsafe(24)
    with pg.tx(p.org_id) as cur:
        cur.execute("""UPDATE organizations SET sso_domain_pending=%s, sso_idp_alias=%s, sso_enforced=%s,
                       domain_verify_token=%s WHERE id=%s""", (body.domain, body.idp_alias, body.enforced, token, p.org_id))
        _audit(cur, p, "sso_configured", body.domain, {"idp_alias": body.idp_alias, "enforced": body.enforced})
    return {"txt_record": {"name": f"_sentrail.{body.domain}", "value": token},
            "next": "Add this TXT record to your DNS, then call /admin/sso/verify"}


@router.post("/admin/sso/verify")
def verify_sso(p: Principal = Depends(require("users.manage"))):
    import dns.resolver
    with pg.tx(p.org_id) as cur:
        cur.execute("SELECT sso_domain_pending, domain_verify_token FROM organizations WHERE id=%s", (p.org_id,))
        domain, token = cur.fetchone() or (None, None)
    if not domain:
        raise HTTPException(409, "Set up a domain first")
    try:
        answers = dns.resolver.resolve(f"_sentrail.{domain}", "TXT", lifetime=5)
        found = any(token == b"".join(r.strings).decode() for r in answers)
    except Exception:
        found = False
    if not found:
        raise HTTPException(409, "The TXT record wasn't found yet. DNS changes can take up to an hour")
    try:
        with pg.tx(p.org_id) as cur:
            cur.execute("UPDATE organizations SET sso_domain=sso_domain_pending, sso_domain_pending=NULL WHERE id=%s", (p.org_id,))
            _audit(cur, p, "sso_domain_verified", str(domain))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Another organization already uses this domain for sign-in. Contact support")
    return {"verified": str(domain)}



# =====================================================================
# Platform console: the SaaS operator's own team, roles, plans and security baseline.
# Platform staff manage the service; they never get access to customer data (enforced by the DB).
# =====================================================================
def _platform_role(cur, role_id) -> str:
    cur.execute("SELECT name FROM roles WHERE id=%s AND org_id IS NULL", (role_id,))
    r = cur.fetchone()
    if not r:
        raise HTTPException(404, "Platform role not found")
    return r[0]


@router.get("/platform/users")
def platform_users(p: Principal = Depends(require("platform.users.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT u.id, u.name_enc, u.email_enc, r.name, u.status, u.auth_method, u.last_login_at
                       FROM users u JOIN roles r ON r.id=u.role_id WHERE u.org_id IS NULL ORDER BY r.name""")
        rows = cur.fetchall()
    return [{"id": str(r[0]), "name": crypto.decrypt(r[1], None, "name"),
             "email": crypto.mask_email(crypto.decrypt(r[2], None, "email")), "role": r[3], "status": r[4],
             "sign_in": "break-glass password + TOTP" if r[5] == "local" else "Keycloak", "last_login": r[6]} for r in rows]


@router.post("/platform/invitations")
@limiter.limit("20/hour")
def invite_platform_staff(request: Request, body: InviteIn, p: Principal = Depends(require("platform.users.manage"))):
    with pg.tx(platform=True) as cur:
        role = _platform_role(cur, body.role_id)
        if str(body.role_id) == PLATFORM_OWNER_ROLE and p.role != "Platform owner":
            raise HTTPException(403, "Only a platform owner can add another platform owner")
        link = _invite(cur, None, "the Sentrail platform team", body.email, body.role_id, role, p.user_id)
        _audit(cur, p, "platform_user_invited", crypto.mask_email(body.email), {"role": role})
    return {"invited": crypto.mask_email(body.email), **({"dev_link": link} if _dev() else {})}


@router.patch("/platform/users/{uid}")
def update_platform_user(uid: uuid.UUID, body: UserPatch, p: Principal = Depends(require("platform.users.manage"))):
    if str(uid) == p.user_id:
        raise HTTPException(403, "You can't change your own role or status. Ask another platform admin")
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT r.name, u.role_id FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s AND u.org_id IS NULL", (uid,))
        cur_role = cur.fetchone()
        if not cur_role:
            raise HTTPException(404, "Platform user not found")
        touching_owner = cur_role[0] == "Platform owner" or (body.role_id and str(body.role_id) == PLATFORM_OWNER_ROLE)
        if touching_owner and p.role != "Platform owner":
            raise HTTPException(403, "Only a platform owner can change a platform owner")
        if cur_role[0] == "Platform owner" and (body.status == "suspended" or (body.role_id and str(body.role_id) != PLATFORM_OWNER_ROLE)):
            cur.execute("""SELECT count(*) FROM users WHERE org_id IS NULL AND status='active' AND role_id=%s""", (PLATFORM_OWNER_ROLE,))
            if cur.fetchone()[0] <= 1:
                raise HTTPException(409, "The platform needs at least one active owner")
        if body.role_id:
            new_role = _platform_role(cur, body.role_id)
            cur.execute("UPDATE users SET role_id=%s, session_version=session_version+1 WHERE id=%s", (body.role_id, uid))
            _audit(cur, p, "platform_role_changed", str(uid), {"from": cur_role[0], "to": new_role})
        if body.status:
            cur.execute("UPDATE users SET status=%s, session_version=session_version+1 WHERE id=%s RETURNING idp_subject", (body.status, uid))
            subj = cur.fetchone()[0]
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
            if AUTH_MODE == "keycloak" and subj:
                kc().set_enabled(subj, body.status == "active")
            _audit(cur, p, f"platform_user_{body.status}", str(uid))
    return {"ok": True}


@router.get("/platform/roles")
def platform_roles(p: Principal = Depends(require_any("platform.roles.manage", "platform.users.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT r.id, r.name, r.is_system, COALESCE(array_agg(rp.perm) FILTER (WHERE rp.perm IS NOT NULL), '{}')
                       FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id WHERE r.org_id IS NULL
                       GROUP BY r.id ORDER BY r.name""")
        roles = [{"id": str(r[0]), "name": r[1], "system": r[2], "perms": sorted(r[3])} for r in cur.fetchall()]
        cur.execute("SELECT key, description, grp FROM permissions WHERE scope='platform' ORDER BY grp, key")
        perms = [{"key": k, "description": d, "group": g} for k, d, g in cur.fetchall()]
    return {"roles": roles, "permissions": perms}


class PlatformRoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    perms: list[str]


def _write_platform_perms(cur, p, role_id, name, perms):
    if name == "Platform owner":
        raise HTTPException(409, "The platform owner role always has every platform permission")
    cur.execute("SELECT 1 FROM users WHERE id=%s AND role_id=%s", (p.user_id, role_id))
    if cur.fetchone():
        raise HTTPException(403, "You can't change the permissions of your own role")
    cur.execute("SELECT key FROM permissions WHERE scope='platform'")
    allowed = {r[0] for r in cur.fetchall()}
    if not set(perms) <= allowed:
        raise HTTPException(422, "Platform roles can only hold platform permissions. Customer data is never available to platform staff")
    cur.execute("DELETE FROM role_permissions WHERE role_id=%s", (role_id,))
    for perm in perms:
        cur.execute("INSERT INTO role_permissions VALUES (%s,%s)", (role_id, perm))
    cur.execute("UPDATE users SET session_version=session_version+1 WHERE role_id=%s", (role_id,))


@router.put("/platform/roles/{role_id}")
def update_platform_role(role_id: uuid.UUID, body: PlatformRoleIn, p: Principal = Depends(require("platform.roles.manage"))):
    with pg.tx(platform=True) as cur:
        name = _platform_role(cur, role_id)
        _write_platform_perms(cur, p, role_id, name, body.perms)
        _audit(cur, p, "platform_role_permissions_changed", name, {"perms": body.perms})
    return {"ok": True}


@router.post("/platform/roles")
def create_platform_role(body: PlatformRoleIn, p: Principal = Depends(require("platform.roles.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT 1 FROM roles WHERE org_id IS NULL AND name=%s", (body.name,))
        if cur.fetchone():
            raise HTTPException(409, "A platform role with this name exists")
        cur.execute("INSERT INTO roles (org_id, name) VALUES (NULL,%s) RETURNING id", (body.name,))
        rid = cur.fetchone()[0]
        _write_platform_perms(cur, p, rid, body.name, body.perms)
        _audit(cur, p, "platform_role_created", body.name, {"perms": body.perms})
    return {"id": str(rid)}


@router.get("/platform/plans")
def get_plans(p: Principal = Depends(require_any("platform.plans.manage", "orgs.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT pl.key, pl.name, pl.features, pl.max_users, count(o.id)
                       FROM plans pl LEFT JOIN organizations o ON o.plan=pl.key GROUP BY pl.key ORDER BY pl.sort""")
        return [{"key": k, "name": n, "features": f, "max_users": m, "organizations": c} for k, n, f, m, c in cur.fetchall()]


@router.put("/platform/plans/{key}")
def update_plan(key: str, body: PlanFeatures, p: Principal = Depends(require("platform.plans.manage"))):
    if not set(body.features) <= set(FEATURES):
        raise HTTPException(400, "Unknown feature")
    with pg.tx(platform=True) as cur:
        cur.execute("UPDATE plans SET features=%s WHERE key=%s RETURNING name", (body.features, key))
        if not cur.fetchone():
            raise HTTPException(404, "Plan not found")
        # every organization on this plan gets the new feature set; features removed from the plan switch off
        cur.execute("""UPDATE org_features f SET in_plan = (f.feature = ANY(%s)), enabled = f.enabled AND (f.feature = ANY(%s))
                       FROM organizations o WHERE o.id=f.org_id AND o.plan=%s""", (body.features, body.features, key))
        _audit(cur, p, "plan_changed", key, {"features": body.features})
    return {"ok": True}


class OrgPlan(BaseModel):
    plan: str = Field(pattern="^(starter|professional|enterprise)$")


@router.put("/platform/orgs/{org_id}/plan")
def set_org_plan(org_id: uuid.UUID, body: OrgPlan, p: Principal = Depends(require("orgs.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("UPDATE organizations SET plan=%s WHERE id=%s RETURNING legal_name", (body.plan, org_id))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Organization not found")
        # features new to the org's plan switch on; features no longer in the plan switch off;
        # features the org had switched off themselves stay off
        cur.execute("""UPDATE org_features f SET in_plan = (f.feature = ANY(pl.features)),
                         enabled = CASE WHEN f.feature = ANY(pl.features) THEN (f.enabled OR NOT f.in_plan) ELSE false END
                       FROM plans pl WHERE pl.key=%s AND f.org_id=%s""", (body.plan, org_id))
        _audit(cur, p, "org_plan_changed", r[0], {"plan": body.plan}, org_id=org_id)
    return {"ok": True}


class PlatformSecurityIn(BaseModel):
    min_password_len_floor: int = Field(14, ge=12, le=64)
    max_idle_timeout_min: int = Field(30, ge=5, le=60)
    max_session_hours: int = Field(12, ge=1, le=24)
    retention_years_floor: int = Field(5, ge=5, le=15)
    passkeys_allowed: bool = True
    platform_staff_passkey_only: bool = True
    allowed_regions: list[str] = ["ca-central", "ca-east"]


@router.get("/platform/security")
def get_platform_security(p: Principal = Depends(require("platform.security.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT min_password_len_floor, max_idle_timeout_min, max_session_hours, retention_years_floor,
                              passkeys_allowed, platform_staff_passkey_only, allowed_regions FROM platform_settings""")
        out = dict(zip(PlatformSecurityIn.model_fields, cur.fetchone()))
    out["mfa"] = ("Each person chooses to turn it on from My account. An organization can make it mandatory for its users; "
                  "without it nobody can approve STRs, export cases, change policy or override screening.")
    return out


@router.put("/platform/security")
def set_platform_security(body: PlatformSecurityIn, p: Principal = Depends(require("platform.security.manage"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""UPDATE platform_settings SET min_password_len_floor=%s, max_idle_timeout_min=%s, max_session_hours=%s,
                       retention_years_floor=%s, passkeys_allowed=%s, platform_staff_passkey_only=%s, allowed_regions=%s,
                       updated_at=now()""", (body.min_password_len_floor, body.max_idle_timeout_min, body.max_session_hours,
                                             body.retention_years_floor, body.passkeys_allowed,
                                             body.platform_staff_passkey_only, body.allowed_regions))
        # bring every tenant up to the new baseline; tenants that are already stricter keep their settings
        cur.execute("""UPDATE security_settings SET min_password_len = GREATEST(min_password_len, %s),
                       idle_timeout_min = LEAST(idle_timeout_min, %s), retention_years = GREATEST(retention_years, %s)""",
                    (body.min_password_len_floor, body.max_idle_timeout_min, body.retention_years_floor))
        raised = cur.rowcount
        _audit(cur, p, "platform_security_changed", None, {**body.model_dump(), "tenants_updated": raised})
    return {"ok": True, "tenants_checked": raised}


# ---- Support access: help a tenant with sign-in without seeing their customer data ----
@router.get("/platform/orgs/{org_id}/users")
def support_list_users(org_id: uuid.UUID, reason: str, p: Principal = Depends(require("platform.support"))):
    if len(reason) < 5:
        raise HTTPException(422, "Give a reason, such as a support ticket number")
    with pg.tx(org_id, platform=True) as cur:
        cur.execute("""SELECT u.id, u.email_enc, r.name, u.status, u.mfa_enabled OR u.idp_subject IS NOT NULL,
                              u.last_login_at FROM users u JOIN roles r ON r.id=u.role_id WHERE u.org_id=%s""", (org_id,))
        rows = cur.fetchall()
        # access transparency: the support access is written to the tenant's own audit log too
        _audit(cur, p, "support_viewed_users", None, {"reason": reason}, org_id=org_id)
    return [{"id": str(r[0]), "email": crypto.mask_email(crypto.decrypt(r[1], org_id, "email")), "role": r[2],
             "status": r[3], "sign_in_set_up": r[4], "last_login": r[5]} for r in rows]


@router.post("/platform/orgs/{org_id}/users/{uid}/resend-invitation")
def support_resend(org_id: uuid.UUID, uid: uuid.UUID, body: Reason, p: Principal = Depends(require("platform.support"))):
    with pg.tx(org_id, platform=True) as cur:
        cur.execute("SELECT email_enc, status, idp_subject FROM users WHERE id=%s AND org_id=%s", (uid, org_id))
        r = cur.fetchone()
        if not r or r[1] != "invited":
            raise HTTPException(409, "Only pending invitations can be resent")
        if AUTH_MODE == "keycloak" and r[2]:
            kc().send_setup_email(r[2])
        else:
            raw = tokens.new_opaque()
            cur.execute("""INSERT INTO invitations (org_id, user_id, token_hash, invited_by, expires_at)
                           VALUES (%s,%s,%s,%s, now() + interval '72 hours')""", (org_id, uid, crypto.sha256(raw), p.user_id))
            mailer.send_invitation(crypto.decrypt(r[0], org_id, "email"), _org_name(org_id), "your role", f"{APP_URL}/join#{raw}")
        _audit(cur, p, "support_resent_invitation", str(uid), {"reason": body.reason}, org_id=org_id)
    return {"ok": True}

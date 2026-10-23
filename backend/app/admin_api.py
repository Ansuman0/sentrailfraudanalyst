"""Identity, organizations, users, roles, features, security settings and audit."""
import ipaddress
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie, Query
from fastapi.responses import RedirectResponse
import jwt as pyjwt
import psycopg
from pydantic import BaseModel, EmailStr, Field, field_validator

from app import config, pg
from app.security import crypto, passwords, mfa, passkeys, tokens, audit
from app.security.rbac import Principal, require, require_any, current_user, signed_in_user, client_ip
from app.security.middleware import limiter
from app.access import catalogue
from app.access.catalogue import TENANT_ADMIN
from app.services import mailer, notify
from app.security import oidc

router = APIRouter()
APP_URL = os.environ.get("APP_URL", "http://localhost:5173")
# 10 failures within 15 minutes lock an (account, IP) pair for 15 minutes, so someone guessing from one network can't lock the real
# owner out from theirs. Failures against one account from ALL networks also slow every answer (progressive delay) and, past
# MAX_ACCOUNT_FAILED, lock it for everyone: distributed guessing is rare enough that this cap is high.
MAX_FAILED, MAX_ACCOUNT_FAILED, LOCK_MIN, WINDOW_MIN = 10, 50, 15, 15
LOGIN_DELAY_STEP = float(os.environ.get("LOGIN_DELAY_STEP", "0.25"))
_UNSET = object()
DEVICE_COOKIE = "sentrail_dv"

PLATFORM_OWNER_ROLE = "00000000-0000-0000-0000-000000000002"
# Roles and permissions are seed data in the database (migrations/005): role_templates, role_template_permissions.
FEATURES = ["screening", "alerts", "ai", "trace", "statements", "export", "scim", "audit_streaming"]
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
    """Locked per (account, IP) or per account across every IP."""
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM login_throttle WHERE key_hash=%s AND ip IN (%s, '') AND locked_until > now()", (key, ip))
        return cur.fetchone() is not None


def _throttle_fail(key: bytes, ip: str) -> int:
    """Count a failed sign-in against the (account, IP) pair and against the account as a whole; the count restarts when the last
    failure is older than the window. Returns the highest count, which also drives the progressive delay."""
    failed = 0
    with pg.pool().connection() as conn, conn.cursor() as cur:
        # no known client address: the account row is also the pair row, with the ordinary limit
        for where, limit in ([("", MAX_FAILED)] if ip == "" else [(ip, MAX_FAILED), ("", MAX_ACCOUNT_FAILED)]):
            cur.execute("""INSERT INTO login_throttle (key_hash, ip, failed, updated_at) VALUES (%s,%s,1,now())
                           ON CONFLICT (key_hash, ip) DO UPDATE SET
                             failed = CASE WHEN login_throttle.locked_until < now()
                                             OR login_throttle.updated_at < now() - make_interval(mins => %s) THEN 1
                                           ELSE login_throttle.failed + 1 END,
                             locked_until = CASE WHEN login_throttle.locked_until < now() THEN NULL ELSE login_throttle.locked_until END,
                             updated_at = now()
                           RETURNING failed""", (key, where, WINDOW_MIN))
            n = cur.fetchone()[0]
            failed = max(failed, n)
            if n >= limit:
                cur.execute("UPDATE login_throttle SET locked_until=now() + make_interval(mins => %s) WHERE key_hash=%s AND ip=%s",
                            (LOCK_MIN, key, where))
        conn.commit()
    return failed


def _throttle_clear(key: bytes, ip: str):
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM login_throttle WHERE key_hash=%s AND ip IN (%s, '')", (key, ip))
        conn.commit()


def _progressive_delay(failed: int):
    """After the second failure each further one answers a little slower (0.25 s more each, at most 1 s)."""
    if failed > 2 and LOGIN_DELAY_STEP > 0:
        time.sleep(min(1.0, LOGIN_DELAY_STEP * (failed - 2)))


def csrf_guard(request: Request):
    """Cookie-authenticated writes (refresh, sign-out) need a header a cross-site form or image can't send, and, when the browser
    sends an Origin, it must be this app (or the host the API was reached on, for the same-origin fallback address)."""
    if request.headers.get("x-sentrail-csrf") != "1":
        raise HTTPException(403, "Request refused (missing CSRF header)")
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc not in {urlparse(APP_URL).netloc, request.headers.get("host", "")}:
        raise HTTPException(403, "Request refused (cross-site)")


@router.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, response: Response, body: Login):
    """The one sign-in for everybody. Every failure looks the same: unknown email, wrong password, an organization user who must
    use Keycloak, or a non-active account all get the same 401 after the same password-hash work. Lockout (10 failures in 15
    minutes) is per (email, client IP), plus a high cap per email across IPs, and applies to unknown emails too, so a 429 reveals nothing.
    A successful sign-in answers with `route`: console | tenant | picker | no_access (see _route)."""
    bidx = crypto.blind_index(body.email)
    ip = client_ip(request) or ""
    if _throttle_locked(bidx, ip):
        raise HTTPException(429, TOO_MANY)
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, org_id FROM auth_lookup(%s)", (bidx,))
        found = cur.fetchone()
    if not found or (AUTH_MODE == "keycloak" and found[1] is not None):
        passwords.verify_password(None, body.password)          # same timing as a real check
        _progressive_delay(_throttle_fail(bidx, ip))
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    uid, org = found
    error = None
    result = None
    notice = None
    break_glass = False
    pk_options, methods = None, []
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""SELECT password_hash, status, failed_logins, mfa_enabled, role_id, session_version, email_enc, break_glass, sso_emergency
                       FROM users WHERE id=%s FOR UPDATE""", (uid,))
        pw_hash, status, failed, mfa_enabled, role_id, sv, email_enc, break_glass, sso_emergency = cur.fetchone()
        if not passwords.verify_password(pw_hash, body.password) or status != "active":
            failed += 1
            cur.execute("UPDATE users SET failed_logins=%s WHERE id=%s", (failed, uid))
            audit.write(cur, org, uid, None, "auth.signin_failed", None, {"failed": failed}, client_ip(request))
            error = HTTPException(401, GENERIC_LOGIN_ERROR)       # raised after commit so the count is kept
        else:
            if passwords.needs_rehash(pw_hash):
                cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (passwords.hash_password(body.password), uid))
            cur.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=%s", (uid,))
            _require_open_tenant(uid, org)
            sso_enforced = _sso_enforced(cur, org)
            if sso_enforced and not sso_emergency:
                raise HTTPException(403, "Your organization requires company sign-in. Use your company account, not a password")
            if break_glass:
                _break_glass_used(cur, uid, request)
            n_pk = passkeys.count(cur, uid) if _passkeys_on(cur) else 0
            if n_pk:
                pk_options = passkeys.authentication_options(cur, uid, "login")
            owner_with_passkey = n_pk > 0 and str(role_id) == PLATFORM_OWNER_ROLE      # owners: a passkey, nothing else
            if sso_enforced and sso_emergency:
                if not n_pk:
                    raise HTTPException(403, "The emergency login needs a passkey. Ask another administrator to set one up")
                owner_with_passkey = True               # emergency login: the passkey is the only second factor
            methods = (["totp"] if mfa_enabled and not owner_with_passkey else []) + (["passkey"] if n_pk else [])
            if not mfa_enabled and not n_pk:
                # No two-factor yet: a password-only session. The API limits it (rbac.current_user) until the
                # user sets two-factor up, or, where the organization allows it, chooses to skip it.
                cur.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))
                result = _start_session(cur, response, request, uid, org, role_id, sv, method="password", mfa=False)
                audit.write(cur, org, uid, None, "auth.signin", None,
                            {"method": "password", "mfa": False, "route": result["route"]}, client_ip(request))
                notice = _device_notice(cur, request, response, uid, org, email_enc)
    if error:
        failed_total = _throttle_fail(bidx, ip)
        if _throttle_locked(bidx, ip):
            with pg.tx(org, platform=org is None) as cur:
                audit.write(cur, org, uid, None, "auth.locked", None, {"failures": failed_total, "minutes": LOCK_MIN}, client_ip(request))
        _progressive_delay(failed_total)
        raise error
    _throttle_clear(bidx, ip)
    if break_glass:
        _alert_owners(uid, request)
    if notice:
        notify.security_event(*notice)
    if result:
        return {**result, "mfa_enabled": False}
    return {"mfa_token": tokens.issue_mfa_pending(uid), "methods": methods,
            "next": "Use your passkey" if methods == ["passkey"] else "Enter the code from your authenticator app",
            **({"passkey_options": pk_options} if pk_options else {})}


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


def _issue(cur, response, uid, org, role_id, sv, request, family=None, method="password+totp", mfa=True,
           scope=None, last_mfa_at=_UNSET, access_session_id=None, factor="totp"):
    """Start or renew a session: a refresh token (cookie) in family `family` and a short access token.
    The session is bound to one active tenant (org; None for the console or while choosing). last_mfa_at defaults to now when this
    sign-in used a second factor; a refresh passes the stored value so renewing a session never refreshes the step-up clock."""
    scope = scope or ("platform" if org is None else "tenant")
    if last_mfa_at is _UNSET:
        last_mfa_at = _now() if mfa else None
    with pg.tx(org, platform=org is None) as limits_cur:        # the target tenant's own timeouts, whatever tenant `cur` is in
        idle, _ = _session_limits(limits_cur, org)

    if org is not None:      # the person is using this tenant, so it is not dormant (in `cur`'s own transaction: a login has just touched this row)
        cur.execute("""UPDATE tenant_memberships SET last_active_at=now() WHERE user_id=%s AND tenant_id=%s
                       AND (last_active_at IS NULL OR last_active_at < now() - interval '1 hour')""", (uid, org))
    raw = tokens.new_opaque()
    family = family or uuid.uuid4()
    cur.execute("""INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at, user_agent, ip, auth_method,
                                               last_mfa_at, tenant_id, scope, access_session_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (uid, family, crypto.sha256(raw), tokens.refresh_expiry(),
                 request.headers.get("user-agent", "")[:200], client_ip(request), method, last_mfa_at, org, scope, access_session_id))
    _set_refresh(response, raw)
    ttl = min(tokens.ACCESS_TTL, timedelta(minutes=idle))
    return {"access_token": tokens.issue_access(uid, org, role_id, sv, mfa=mfa, ttl=ttl, session_id=family, scope=scope,
                                                last_mfa_at=last_mfa_at, access_session_id=access_session_id, factor=factor),
            "token_type": "Bearer",
            "expires_in": int(ttl.total_seconds())}


def _require_open_tenant(uid, org):
    """Old model: a person whose tenant is suspended, pending or deleted is refused at sign-in (new model: the tenant is simply absent from
    their choices). Checked as soon as the password is right, so a second factor is never asked for a tenant that can't be entered."""
    if org is None or config.ACCESS_MODEL_V2:
        return
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT tenant_status FROM membership_lookup(%s) WHERE tenant_id=%s", (uid, org))
        st = cur.fetchone()
    if st and st[0] not in ("active", "trial"):
        raise HTTPException(403, "Your organization's access is suspended or not open yet. Contact your administrator")


def _route(uid, home_org) -> dict:
    """Where a fresh sign-in lands (brief 3.5). Old model: the user's own organization, or the console for platform staff.
    New model (ACCESS_MODEL_V2): platform staff -> console; exactly one active membership -> that tenant; several -> the picker
    (a session with no tenant yet); none -> the no-access page (also tenant-less)."""
    if not config.ACCESS_MODEL_V2:
        if home_org is not None:
            with pg.pool().connection() as conn, conn.cursor() as cur:
                cur.execute("SELECT tenant_status FROM membership_lookup(%s) WHERE tenant_id=%s", (uid, home_org))
                st = cur.fetchone()
            if st and st[0] not in ("active", "trial"):
                raise HTTPException(403, "Your organization's access is suspended or not open yet. Contact your administrator")
        return {"route": "console" if home_org is None else "tenant", "org": home_org, "role_id": None,
                "scope": "platform" if home_org is None else "tenant", "tenants": []}
    staff, mems = _memberships(uid)
    tenants = [{"id": str(m[0]), "name": m[1], "slug": m[2], "role": m[5]} for m in mems]
    if staff:
        return {"route": "console", "org": None, "role_id": staff[0], "scope": "platform", "tenants": tenants}
    if len(mems) == 1:
        return {"route": "tenant", "org": mems[0][0], "role_id": mems[0][4], "scope": "tenant", "tenants": tenants}
    return {"route": "picker" if mems else "no_access", "org": None, "role_id": None, "scope": "select", "tenants": tenants}


def _memberships(uid):
    """(platform staff row if active, active memberships in tenants that are active) without needing a tenant context."""
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT role_id, role_name, status FROM platform_staff_lookup(%s)", (uid,))
        staff = cur.fetchone()
        cur.execute("""SELECT tenant_id, tenant_name, slug, tenant_status, role_id, role_name, status
                       FROM membership_lookup(%s)""", (uid,))
        mems = [m for m in cur.fetchall() if m[6] == "active" and m[3] in ("active", "trial")]
    return (staff if staff and staff[2] == "active" else None), mems


def _start_session(cur, response, request, uid, home_org, role_id, sv, *, method, mfa, factor="totp"):
    r = _route(uid, home_org)
    session = _issue(cur, response, uid, r["org"], r["role_id"] or role_id, sv, request, method=method, mfa=mfa, scope=r["scope"], factor=factor)
    return {**session, "route": r["route"], "tenants": r["tenants"]}


def _device_notice(cur, request, response, uid, org, email_enc):
    """Remember this browser (a random device cookie; only its hash is stored). Returns (email, "new_device", detail) when it is a
    device this person has not used before and they have signed in before, so the address can be told."""
    raw = request.cookies.get(DEVICE_COOKIE)
    cur.execute("SELECT count(*) FROM user_devices WHERE user_id=%s", (uid,))
    known = cur.fetchone()[0]
    if raw:
        cur.execute("UPDATE user_devices SET last_seen=now(), ip=%s WHERE user_id=%s AND device_hash=%s RETURNING 1",
                    (client_ip(request), uid, crypto.sha256(raw)))
        if cur.fetchone():
            return None
    raw = tokens.new_opaque()
    cur.execute("INSERT INTO user_devices (user_id, device_hash, ip, user_agent) VALUES (%s,%s,%s,%s)",
                (uid, crypto.sha256(raw), client_ip(request), request.headers.get("user-agent", "")[:200]))
    response.set_cookie(DEVICE_COOKIE, raw, httponly=True, secure=True, samesite="strict", path="/auth", max_age=2 * 365 * 86400)
    from app import governance
    governance.note_country(cur, request, uid, org, email_enc)
    if not known:
        return None
    return (crypto.decrypt(email_enc, org, "email"), "new_device", {"where": (request.headers.get("user-agent", "")[:60] or None)})


def _second_factor(cur, uid, org, enc, last, code, recovery_code) -> bool:
    """Check a TOTP code (with replay protection) or a single-use recovery code for this user."""
    if code:
        step = mfa.verify(crypto.decrypt(enc, org, "totp"), code, last)
        if step:
            cur.execute("UPDATE users SET totp_last_step=%s WHERE id=%s", (step, uid))
            return True
    elif recovery_code:
        cur.execute("SELECT ctid, code_hash FROM recovery_codes WHERE user_id=%s AND used_at IS NULL", (uid,))
        rows = cur.fetchall()
        i = mfa.check_recovery(recovery_code, [r[1] for r in rows])
        if i is not None:
            cur.execute("UPDATE recovery_codes SET used_at=now() WHERE ctid=%s", (rows[i][0],))
            return True
    return False


@router.post("/auth/mfa")
@limiter.limit("10/minute")
def verify_mfa(request: Request, response: Response, body: MfaIn):
    try:
        uid = tokens.decode(body.mfa_token, typ="mfa_pending")["sub"]
    except Exception:
        raise HTTPException(401, "Sign-in expired. Start again")
    org = _org_of(uid)
    notice = None
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("""SELECT totp_secret_enc, totp_last_step, role_id, session_version, mfa_enabled, status, email_enc
                       FROM users WHERE id=%s FOR UPDATE""", (uid,))
        row = cur.fetchone()
        if not row or not row[4] or not row[0] or row[5] != "active":
            # Account removed, suspended, or two-factor turned off since the password step: start over.
            raise HTTPException(401, "Sign-in expired. Start again")
        enc, last, role_id, sv, _, _, email_enc = row
        if str(role_id) == PLATFORM_OWNER_ROLE and _passkeys_on(cur) and passkeys.count(cur, uid):
            raise HTTPException(403, "Platform owners sign in with a passkey")
        cur.execute("SELECT sso_emergency FROM users WHERE id=%s", (uid,))
        if cur.fetchone()[0] and _sso_enforced(cur, org):
            raise HTTPException(403, "The emergency login uses a passkey")
        ok = _second_factor(cur, uid, org, enc, last, body.code, body.recovery_code)
        if not ok:
            audit.write(cur, org, uid, None, "auth.signin_failed", None, {"stage": "second_factor"}, client_ip(request))
        else:
            cur.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))
            result = _start_session(cur, response, request, uid, org, role_id, sv, method="password+totp", mfa=True)
            audit.write(cur, org, uid, None, "auth.signin", None,
                        {"method": "totp" if body.code else "recovery_code", "mfa": True, "route": result["route"]}, client_ip(request))
            notice = _device_notice(cur, request, response, uid, org, email_enc)
    if not ok:
        raise HTTPException(401, "That code didn't work. Check your app and try again")
    if notice:
        notify.security_event(*notice)
    return result


def _org_of(uid):
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT org_id FROM user_org_lookup(%s)", (uid,))
        r = cur.fetchone()
    if not r:
        raise HTTPException(401, "Sign in again")
    return r[0]


@router.post("/auth/refresh", dependencies=[Depends(csrf_guard)])
def refresh(request: Request, response: Response, sentrail_rt: str | None = Cookie(None)):
    if not sentrail_rt:
        raise HTTPException(401, "Sign in again")
    h = crypto.sha256(sentrail_rt)
    error = None
    result = None
    # One transaction: the old token is revoked and the new one stored together, so the session is never without a live token.
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT t.id, t.user_id, t.family_id, t.expires_at, t.revoked_at, t.created_at,
                              (SELECT min(created_at) FROM refresh_tokens f WHERE f.family_id=t.family_id), t.auth_method,
                              t.tenant_id, t.scope, t.last_mfa_at, t.access_session_id
                       FROM refresh_tokens t WHERE t.token_hash=%s FOR UPDATE""", (h,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(401, "Sign in again")
        tid, uid, fam, exp, revoked, last_active, started, method, tenant, scope, lmfa, asid = row
        if revoked:   # reuse of a rotated token: assume theft, end every session in this family
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (fam,))
            error = "reuse"
        elif exp < _now():
            error = "expired"
        else:
            # The tenant's idle timeout and the platform's maximum session length. Each refresh token is
            # issued when the previous one is used, so its created_at is the last time this session was active.
            idle, max_hours = _session_limits(cur, tenant)
            if _now() - last_active > timedelta(minutes=idle) or _now() - started > timedelta(hours=max_hours):
                cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (fam,))
                error = "timed_out"
            else:
                with pg.pool().connection() as conn, conn.cursor() as c2:
                    c2.execute("SELECT status, session_version, role_id FROM session_user_lookup(%s)", (uid,))
                    u = c2.fetchone()
                access_ok = bool(u and u[0] == "active")
                if access_ok and asid:       # an owner inside a tenant: the access session must still be live
                    cur.execute("""SELECT 1 FROM tenant_access_sessions WHERE id=%s AND status='active' AND expires_at > now()""", (asid,))
                    access_ok = cur.fetchone() is not None
                elif access_ok and config.ACCESS_MODEL_V2 and scope != "select":
                    staff, mems = _memberships(uid)
                    access_ok = not ((scope == "platform" and not staff) or (scope == "tenant" and tenant not in [m[0] for m in mems]))
                if not access_ok:
                    cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (fam,))
                    error = "access_changed"
                else:
                    cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE id=%s", (tid,))
                    # same assurance as the original sign-in: a password-only session stays password-only, and renewing a
                    # session never refreshes its step-up clock (last_mfa_at is carried over as it was)
                    result = _issue(cur, response, uid, tenant, u[2], u[1], request, family=fam,
                                    method=method or "password+totp", mfa=method != "password", scope=scope, last_mfa_at=lmfa,
                                    access_session_id=asid, factor="passkey" if (method or "").endswith("passkey") else "totp")
    if error:
        if error == "reuse":
            with pg.tx(tenant, platform=tenant is None) as cur:
                audit.write(cur, tenant, uid, None, "refresh_token_reuse_detected", str(fam), {}, client_ip(request))
        raise HTTPException(401, "Sign in again")
    return result


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
        return {"method": "sso", "enforced": bool(r[2]), "next": "/auth/oidc/login?" + urlencode({"email": body.email, "idp": r[1]})}
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
            audit.write(cur, org, uid, None, "auth.signin", None, {"via": "oidc", "amr": claims.get("amr")}, client_ip(request))
            _issue(cur, response, uid, org, role_id, sv, request, method="keycloak")
    return _fail("suspended") if blocked else response


def _jit_provision(claims, email):
    """Just-in-time membership: nobody invited this person, but their company's VERIFIED domain has an identity provider and a default role,
    and the identity provider vouches for the address. They get an account in that tenant with that role (never Tenant admin), within the
    plan's seats. Anything else: no account."""
    if not claims.get("email_verified"):
        return None, None
    domain = email.split("@", 1)[1].lower()
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT org_id, role_id FROM sso_jit_lookup(%s)", (domain,))
        target = cur.fetchone()
    if not target:
        return None, None
    org, role_id = target
    try:
        with pg.tx(org) as cur:
            cur.execute("SELECT is_locked FROM roles WHERE id=%s AND org_id=%s", (role_id, org))
            role = cur.fetchone()
            if not role or role[0]:
                return None, None
            _require_seat(cur, org)
            name = claims.get("name") or " ".join(x for x in (claims.get("given_name"), claims.get("family_name")) if x) or email.split("@")[0]
            cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, status, idp_subject, auth_method)
                           VALUES (%s,%s,%s,%s,%s,'active',%s,'keycloak') RETURNING id""",
                        (org, role_id, crypto.encrypt(crypto.normalize_email(email), org, "email"), crypto.blind_index(email),
                         crypto.encrypt(name, org, "name"), claims["sub"]))
            uid = cur.fetchone()[0]
            audit.write(cur, org, uid, None, "sso_jit_provisioned", crypto.mask_email(email), {"role_id": str(role_id)}, None)
    except HTTPException:
        return None, None            # no seat left (or similar): the sign-in ends as "no account"
    return uid, org


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
        return _jit_provision(claims, email)
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
def oidc_logout(request: Request, sentrail_rt: str | None = Cookie(None)):
    _end_session(sentrail_rt, request)
    resp = RedirectResponse(oidc.logout_url(), status_code=302)
    resp.delete_cookie("sentrail_rt", path="/auth")
    return resp


def _end_session(cookie: str | None, request: Request):
    """Revoke the whole session family behind this refresh cookie and record `auth.signout` in its tenant's audit log."""
    if not cookie:
        return
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT user_id, tenant_id, family_id FROM refresh_tokens WHERE token_hash=%s", (crypto.sha256(cookie),))
        row = cur.fetchone()
        if row:
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (row[2],))
    if row:
        with pg.tx(row[1], platform=row[1] is None) as cur:
            audit.write(cur, row[1], row[0], None, "auth.signout", None, {}, client_ip(request))


@router.post("/auth/logout", dependencies=[Depends(csrf_guard)])
def logout(request: Request, response: Response, sentrail_rt: str | None = Cookie(None)):
    _end_session(sentrail_rt, request)
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
    slug: str | None = Field(None, min_length=3, max_length=40, pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")   # permanent: it never changes


def provision_org(cur, legal_name, business_type, registration, data_region="ca-central", plan="professional",
                  environment="production", brand_color="#0F6E56", features=None, status="active", slug=None):
    """Create an organization with its system roles, settings, features and policy. Used by the API and the seed.
    The API creates tenants `pending`; they become `active` when their first Tenant admin accepts the invitation."""
    slug = slug or re.sub(r"[^a-z0-9]+", "-", legal_name.lower()).strip("-")[:40] + "-" + secrets.token_hex(2)
    cur.execute("""INSERT INTO organizations (legal_name, business_type, registration, data_region, plan, slug, environment, brand_color, status)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (legal_name, business_type, registration, data_region, plan, slug, environment, brand_color, status))
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
        cur.execute("INSERT INTO roles (org_id, name, is_system, is_locked) VALUES (%s,%s,true,%s) RETURNING id", (org, name, name == TENANT_ADMIN))
        role_ids[name] = cur.fetchone()[0]
        cur.execute("""INSERT INTO role_permissions SELECT %s, perm FROM role_template_permissions WHERE template=%s""",
                    (role_ids[name], name))
    # the org's own data is written inside its tenant scope (platform scope can't write customer-side tables)
    cur.execute("SELECT set_config('app.org_id', %s, true)", (str(org),))
    cur.execute("""INSERT INTO screening_policy VALUES (%s, '{"hold_at":40,"block_at":75,"travel_rule_threshold":1000,
                   "self_hosted_proof_above":1000,"always_block_sanctions":true}')""", (org,))
    return org, role_ids


@router.post("/platform/orgs")
def create_org(body: OrgIn, p: Principal = Depends(require("platform.tenants.manage"))):
    """Create a tenant: validated slug, status `pending`, its roles and baseline settings, an audit entry, and a 72-hour invitation for
    its first Tenant admin (or a membership when that email already has an account). It becomes `active` when the invitation is accepted."""
    if body.features and not set(body.features) <= set(FEATURES):
        raise HTTPException(400, "Unknown feature")
    # no actor here: provision_org also writes the NEW tenant's own rows (its policy), which nobody is a member of yet
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT allowed_regions FROM platform_settings")
        if body.data_region not in cur.fetchone()[0]:
            raise HTTPException(422, "That data region isn't allowed on this platform")
        if body.slug:
            cur.execute("SELECT 1 FROM organizations WHERE slug=%s", (body.slug,))
            if cur.fetchone():
                raise HTTPException(409, "That slug is taken. A slug is permanent, so pick the one you want to keep")
        org, role_ids = provision_org(cur, body.legal_name, body.business_type, body.registration, body.data_region,
                                      body.plan, body.environment, body.brand_color, body.features, status="pending", slug=body.slug)
        link, joined = None, False
        cur.execute("SELECT id FROM auth_lookup(%s)", (crypto.blind_index(body.admin_email),))
        known = cur.fetchone()
        if known and config.ACCESS_MODEL_V2:
            # The email already has an account: it gets a membership in the new tenant (Tenant admin) and the tenant is live at once.
            cur.execute("""INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status) VALUES (%s,%s,%s,'active')""",
                        (known[0], org, role_ids[TENANT_ADMIN]))
            cur.execute("UPDATE organizations SET status='active', status_changed_at=now() WHERE id=%s", (org,))
            joined = True
        else:
            link = _invite(cur, org, body.legal_name, body.admin_email, role_ids[TENANT_ADMIN], TENANT_ADMIN, p.user_id)
        detail = {"plan": body.plan, "features": body.features, "slug": body.slug, "admin": crypto.mask_email(body.admin_email),
                  "first_admin": "added as a member" if joined else "invited (72 hours)"}
        _audit(cur, p, "tenant_created", body.legal_name, detail, org_id=org)      # the tenant's own log starts with who created it
        _audit(cur, p, "tenant_created", body.legal_name, {**detail, "org_id": str(org)})   # and the platform log
    return {"org_id": str(org), "status": "active" if joined else "pending", "invited": crypto.mask_email(body.admin_email),
            **({"dev_link": link} if (_dev() and link) else {})}


@router.get("/platform/orgs")
def list_orgs(p: Principal = Depends(require_any("platform.tenants.manage", "platform.support"))):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT o.id, o.legal_name, o.business_type, o.registration, o.data_region, o.plan, o.status,
                              (SELECT count(*) FROM users u WHERE u.org_id=o.id),
                              (SELECT array_agg(feature) FROM org_features f WHERE f.org_id=o.id AND f.in_plan),
                              o.owner_access, o.legal_hold, o.slug
                       FROM organizations o ORDER BY o.created_at""")
        cols = ["id", "legal_name", "business_type", "registration", "data_region", "plan", "status", "users", "features",
                "owner_access", "legal_hold", "slug"]
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


def _require_seat(cur, org):
    """The plan's seat limit: active memberships may not exceed it (None = unlimited)."""
    cur.execute("""SELECT pl.name, pl.max_users, (SELECT count(*) FROM tenant_memberships m WHERE m.tenant_id=o.id AND m.status='active')
                   FROM organizations o JOIN plans pl ON pl.key=o.plan WHERE o.id=%s""", (org,))
    name, limit, used = cur.fetchone()
    if limit is not None and used >= limit:
        raise HTTPException(409, f"The {name} plan includes {limit} people and all {limit} seats are in use. "
                                 "Suspend or remove someone, or ask for a plan change")


@router.post("/admin/invitations")
@limiter.limit("30/hour")
def invite(request: Request, body: InviteIn, p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        _require_seat(cur, p.org_id)
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
        cur.execute("SELECT u.email_enc, r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s FOR UPDATE", (uid,))
        email_enc, role_name = cur.fetchone()
        email = crypto.decrypt(email_enc, org, "email")
        problems = passwords.check_policy(body.password, min_len, [body.full_name, *body.full_name.split(), email.split("@")[0]])
        if problems:
            raise HTTPException(422, problems)
        first_admin = False
        if org is not None:
            cur.execute("SELECT status FROM organizations WHERE id=%s", (org,))
            if cur.fetchone()[0] in ("suspended", "deleted"):
                raise HTTPException(409, "This organization isn't active, so the invitation can't be accepted right now")
            _require_seat(cur, org)               # checked again here: seats may have filled since the invitation went out
            first_admin = role_name == TENANT_ADMIN
        cur.execute("""UPDATE users SET name_enc=%s, password_hash=%s, status='active', mfa_mandatory=%s WHERE id=%s""",
                    (crypto.encrypt(body.full_name, org, "name"), passwords.hash_password(body.password), first_admin, uid))
        cur.execute("UPDATE invitations SET accepted_at=now() WHERE id=%s", (inv_id,))
        audit.write(cur, org, uid, None, "user_enrolled", None, {"mfa": "required" if first_admin else "after_sign_in"}, client_ip(request))
        if first_admin:
            cur.execute("""UPDATE organizations SET status='active', status_changed_at=now() WHERE id=%s AND status='pending' RETURNING 1""", (org,))
            if cur.fetchone():
                audit.write(cur, org, uid, None, "tenant_activated", None, {"by": "first Tenant admin accepted the invitation"}, client_ip(request))
    return {"activated": True,
            "next": "Sign in with your email and new password, then set up two-factor authentication (required for Tenant admins)"
                    if first_admin else "Sign in with your email and new password"}


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@router.post("/me/password")
@limiter.limit("10/minute")
def change_password(request: Request, response: Response, body: PasswordIn, p: Principal = Depends(signed_in_user)):
    """Change your own password. Every session of yours ends (including the break-glass rotation lock) and you get a fresh one."""
    home = _org_of(p.user_id)
    notice = None
    with pg.tx(home, platform=home is None, actor=p.user_id) as cur:
        cur.execute("""SELECT password_hash, role_id, session_version, email_enc, auth_method FROM users WHERE id=%s FOR UPDATE""", (p.user_id,))
        pw_hash, role_id, sv, email_enc, method = cur.fetchone()
        if method == "keycloak":
            raise HTTPException(409, "Your sign-in provider manages your password")
        if not passwords.verify_password(pw_hash, body.current_password):
            raise HTTPException(401, "The current password isn't right")
        if home is None:
            cur.execute("SELECT min_password_len_floor FROM platform_settings")
        else:
            cur.execute("SELECT min_password_len FROM security_settings WHERE org_id=%s", (home,))
        email = crypto.decrypt(email_enc, home, "email")
        problems = passwords.check_policy(body.new_password, cur.fetchone()[0], [email.split("@")[0]])
        if body.new_password == body.current_password:
            problems.append("Choose a password you haven't used just now")
        if problems:
            raise HTTPException(422, problems)
        cur.execute("""UPDATE users SET password_hash=%s, password_changed_at=now(), must_rotate=false,
                       session_version=session_version+1 WHERE id=%s""", (passwords.hash_password(body.new_password), p.user_id))
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (p.user_id,))
        audit.write(cur, home, p.user_id, None, "auth.password_changed", None, {}, client_ip(request))
        session = _issue(cur, response, p.user_id, p.org_id, role_id, sv + 1, request, scope=p.scope,
                         method="password+totp" if p.mfa else "password", mfa=p.mfa)
        notice = (email, "password_changed", None)
    notify.security_event(*notice)
    return session


def _sso_enforced(cur, org) -> bool:
    """Company sign-in is enforced for this tenant: a VERIFIED domain with an identity provider, and the enforce switch on."""
    if org is None:
        return False
    cur.execute("SELECT sso_enforced AND sso_domain IS NOT NULL AND sso_idp_alias IS NOT NULL FROM organizations WHERE id=%s", (org,))
    r = cur.fetchone()
    return bool(r and r[0])


def _passkeys_on(cur) -> bool:
    cur.execute("SELECT passkeys_allowed FROM platform_settings")
    return bool(cur.fetchone()[0])


def _break_glass_used(cur, uid, request):
    """The sealed account was just used: its password must be rotated, and every owner is told."""
    cur.execute("UPDATE users SET must_rotate=true WHERE id=%s", (uid,))
    audit.write(cur, None, uid, "Platform owner", "break_glass_used", None, {"ip": client_ip(request)}, client_ip(request))


def _alert_owners(uid, request):
    with pg.tx(platform=True) as cur:
        cur.execute("""SELECT email_enc FROM users WHERE org_id IS NULL AND role_id=%s AND status='active' AND id<>%s""", (PLATFORM_OWNER_ROLE, uid))
        addresses = [crypto.decrypt(r[0], None, "email") for r in cur.fetchall()]
    for address in addresses:
        notify.security_event(address, "break_glass_used", {"where": f"from {client_ip(request) or 'an unknown address'}"})


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
    with pg.tx(p.org_id, platform=p.platform, actor=p.actor, access_session=p.access_session_id) as cur:
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
    with pg.tx(p.org_id, platform=p.platform, actor=p.actor, access_session=p.access_session_id) as cur:
        email_enc = _local_user(cur, p)
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
        session = _issue(cur, response, p.user_id, p.org_id, role_id, sv + 1, request, scope=p.scope)
        address = crypto.decrypt(email_enc, p.org_id, "email")
    notify.security_event(address, "mfa_enabled")
    return {**session, "recovery_codes": codes,
            "message": "Save these codes somewhere safe. Each works once and they won't be shown again"}


# =====================================================================
# Users
# =====================================================================
@router.get("/admin/users")
def list_users(p: Principal = Depends(require("users.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
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
def reveal(uid: uuid.UUID, body: Reason, p: Principal = Depends(require("users.pii.reveal"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
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
    role_notice = None
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s", (uid,))
        cur_role = cur.fetchone()
        if not cur_role:
            raise HTTPException(404, "User not found")
        if body.role_id:
            new_role = _role_in_org(cur, body.role_id, p.org_id)
            _no_escalation(cur, p, body.role_id)
            if cur_role[0] == TENANT_ADMIN and new_role != TENANT_ADMIN:
                _keep_one_admin(cur, p.org_id)
            cur.execute("UPDATE users SET role_id=%s, session_version=session_version+1 WHERE id=%s RETURNING email_enc", (body.role_id, uid))
            role_notice = (crypto.decrypt(cur.fetchone()[0], p.org_id, "email"), "role_changed", {"where": new_role})
            _audit(cur, p, "role_changed", str(uid), {"from": cur_role[0], "to": new_role})
        if body.status:
            cur.execute("SELECT status FROM users WHERE id=%s", (uid,))
            if body.status == "active" and cur.fetchone()[0] == "invited":
                raise HTTPException(409, "This person hasn't finished setting up their account yet")
            if body.status == "suspended" and cur_role[0] == TENANT_ADMIN:
                _keep_one_admin(cur, p.org_id)
            cur.execute("UPDATE users SET status=%s, session_version=session_version+1 WHERE id=%s RETURNING idp_subject", (body.status, uid))
            subj = cur.fetchone()[0]
            if body.status == "active":
                cur.execute("UPDATE tenant_memberships SET reactivated_at=now() WHERE user_id=%s AND tenant_id=%s", (uid, p.org_id))
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
            if AUTH_MODE == "keycloak" and subj:
                kc().set_enabled(subj, body.status == "active")   # also ends their Keycloak sessions
            _audit(cur, p, f"user_{body.status}", str(uid), {"sessions_ended": True})
    if role_notice:
        notify.security_event(*role_notice)
    return {"ok": True}


def _keep_one_admin(cur, org_id):
    cur.execute("""SELECT count(*) FROM users u JOIN roles r ON r.id=u.role_id
                   WHERE r.name=%s AND u.status='active'""", (TENANT_ADMIN,))
    if cur.fetchone()[0] <= 1:
        raise HTTPException(409, "Your organization needs at least one active admin")


@router.post("/admin/users/{uid}/reset-mfa")
def reset_mfa(uid: uuid.UUID, body: Reason, p: Principal = Depends(require("users.manage"))):
    if str(uid) == p.user_id:
        raise HTTPException(403, "Ask another admin to reset your two-factor")
    if AUTH_MODE == "keycloak":
        with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
            cur.execute("UPDATE users SET session_version=session_version+1 WHERE id=%s RETURNING idp_subject", (uid,))
            r = cur.fetchone()
            if not r:
                raise HTTPException(404, "User not found")
            if not r[0]:
                raise HTTPException(409, "This person signs in with company SSO. Their company manages two-factor")
            kc().reset_second_factor(r[0])
            _audit(cur, p, "mfa_reset", str(uid), {"reason": body.reason, "via": "keycloak"})
        return {"ok": True}
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""UPDATE users SET totp_secret_enc=NULL, mfa_enabled=false, totp_last_step=0,
                       session_version=session_version+1 WHERE id=%s RETURNING email_enc""", (uid,))
        gone = cur.fetchone()
        if not gone:
            raise HTTPException(404, "User not found")
        address = crypto.decrypt(gone[0], p.org_id, "email")
        cur.execute("DELETE FROM recovery_codes WHERE user_id=%s", (uid,))
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
        _audit(cur, p, "mfa_reset", str(uid), {"reason": body.reason})
    notify.security_event(address, "mfa_reset")
    return {"ok": True, "next": "They'll be asked to set up two-factor again at their next sign-in"}


# =====================================================================
# Roles and permissions
# =====================================================================
@router.get("/admin/roles")
def list_roles(p: Principal = Depends(require("roles.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT r.id, r.name, r.is_system, COALESCE(array_agg(rp.perm) FILTER (WHERE rp.perm IS NOT NULL), '{}'), r.is_locked
                       FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id GROUP BY r.id ORDER BY r.name""")
        roles = [{"id": str(r[0]), "name": r[1], "system": r[2], "perms": sorted(r[3]), "locked": r[4]} for r in cur.fetchall()]
    return {"roles": roles, "warnings": _sod_warnings(roles)}


def _sod_warnings(roles):
    """Separation-of-duties warnings (catalogue.SOD_CONFLICTS), one sentence per conflict, for every role that isn't locked."""
    out = []
    for r in roles:
        if r.get("locked"):
            continue
        held = set(r["perms"])
        out += [f"{r['name']} can both {_say(a)} and {_say(b)}. {why}" for a, b, why in catalogue.SOD_CONFLICTS if a in held and b in held]
    return out


def _say(perm: str) -> str:
    return {p.key: p.description[0].lower() + p.description[1:] for p in catalogue.PERMISSIONS}.get(perm, perm)


def _effective(cur, org, role_id) -> dict:
    """What a role can do: each permission with its wording and whether it asks for a fresh second factor, plus the plan features switched on."""
    cur.execute("SELECT name, is_locked FROM roles WHERE id=%s AND org_id=%s", (role_id, org))
    role = cur.fetchone()
    if not role:
        raise HTTPException(404, "Role not found")
    cur.execute("SELECT perm FROM role_permissions WHERE role_id=%s", (role_id,))
    held = {r[0] for r in cur.fetchall()}
    meta = {p.key: p for p in catalogue.PERMISSIONS}
    cur.execute("SELECT feature FROM org_features WHERE in_plan AND enabled ORDER BY feature")
    return {"role": role[0], "locked": role[1],
            "permissions": [{"key": k, "group": meta[k].group, "description": meta[k].description, "step_up": meta[k].step_up}
                            for k in sorted(held) if k in meta],
            "features": [r[0] for r in cur.fetchall()],
            "warnings": [] if role[1] else _sod_warnings([{"name": role[0], "perms": sorted(held), "locked": False}])}


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    perms: list[str]

    @field_validator("perms")
    @classmethod
    def tenant_only(cls, v):
        if any(x in ("orgs.manage", "orgs.delete") or x.startswith("platform.") for x in v):
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


@router.get("/admin/roles/{role_id}/effective")
def role_effective(role_id: uuid.UUID, p: Principal = Depends(require("roles.manage"))):
    """What this role can do (also drives 'Preview as role' in the web app: the screens that role would see)."""
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        return _effective(cur, p.org_id, role_id)


@router.get("/admin/users/{uid}/effective-permissions")
def user_effective(uid: uuid.UUID, p: Principal = Depends(require("users.manage"))):
    """What this person can do in this tenant, and through which role."""
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT role_id FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s", (uid, p.org_id))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "User not found")
        return _effective(cur, p.org_id, r[0])


@router.post("/admin/roles")
def create_role(body: RoleIn, p: Principal = Depends(require("roles.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("INSERT INTO roles (org_id, name) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING id", (p.org_id, body.name))
        r = cur.fetchone()
        if not r:
            raise HTTPException(409, "A role with this name already exists")
        _write_perms(cur, p, r[0], body.perms)
        _audit(cur, p, "role_created", body.name, {"perms": body.perms})
    return {"id": str(r[0]), "warnings": _sod_warnings([{"name": body.name, "perms": body.perms}])}


@router.put("/admin/roles/{role_id}")
def update_role(role_id: uuid.UUID, body: RoleIn, p: Principal = Depends(require("roles.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        name = _role_in_org(cur, role_id, p.org_id)
        cur.execute("SELECT 1 FROM users WHERE id=%s AND role_id=%s", (p.user_id, role_id))
        if cur.fetchone():       # checked before "locked" so nobody learns more than "not your own role"
            raise HTTPException(403, "You can't change the permissions of your own role. Ask another admin")
        cur.execute("SELECT is_locked FROM roles WHERE id=%s", (role_id,))
        if cur.fetchone()[0]:
            raise HTTPException(409, f"The {name} role is locked: it always holds every permission and can't be edited")
        cur.execute("SELECT array_agg(perm) FROM role_permissions WHERE role_id=%s", (role_id,))
        before = cur.fetchone()[0] or []
        _write_perms(cur, p, role_id, body.perms)
        cur.execute("UPDATE users SET session_version=session_version+1 WHERE role_id=%s", (role_id,))  # apply now
        _audit(cur, p, "role_permissions_changed", name, {"added": sorted(set(body.perms) - set(before)),
                                                          "removed": sorted(set(before) - set(body.perms))})
    return {"ok": True, "warnings": _sod_warnings([{"name": name, "perms": body.perms}])}


# =====================================================================
# Features and security settings
# =====================================================================
class FeatureToggle(BaseModel):
    feature: str
    enabled: bool


@router.get("/admin/features")
def get_features(p: Principal = Depends(require("features.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT feature, in_plan, enabled FROM org_features ORDER BY feature")
        return [{"feature": r[0], "in_plan": r[1], "enabled": r[2]} for r in cur.fetchall()]


@router.put("/admin/features")
def toggle_feature(body: FeatureToggle, p: Principal = Depends(require("features.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("UPDATE org_features SET enabled=%s WHERE feature=%s AND in_plan RETURNING 1", (body.enabled, body.feature))
        if not cur.fetchone():
            raise HTTPException(403, "This feature isn't in your plan")
        _audit(cur, p, "feature_toggled", body.feature, {"enabled": body.enabled})
    return {"ok": True}


class SecurityIn(BaseModel):
    """Every field is optional: only the fields you send change, the rest keep their current values."""
    mfa_required: bool | None = None
    idle_timeout_min: int | None = Field(None, ge=5, le=60)
    min_password_len: int | None = Field(None, ge=12, le=64)
    ip_allowlist: list[str] | None = None
    retention_years: int | None = Field(None, ge=5, le=15)
    owner_access: str | None = Field(None, pattern="^(allow|require_approval|deny)$")   # may a Sentrail platform owner enter this tenant?
    dormant_days: int | None = Field(None, ge=30, le=365)                # memberships unused this long are suspended
    access_review_days: int | None = Field(None, ge=30, le=365)           # how often a review is opened
    export_limit_per_hour: int | None = Field(None, ge=1, le=1000)        # exports one person may make per hour
    anomaly_searches_per_hour: int | None = Field(None, ge=5, le=10000)   # alert the admins past this many searches by one person
    anomaly_exports_per_hour: int | None = Field(None, ge=1, le=1000)
    alert_new_country: bool | None = None

    @field_validator("ip_allowlist")
    @classmethod
    def cidrs(cls, v):
        for c in v or []:
            ipaddress.ip_network(c, strict=False)
        return v


SECURITY_COLS = ["mfa_required", "idle_timeout_min", "min_password_len", "ip_allowlist", "retention_years",
                 "dormant_days", "access_review_days", "export_limit_per_hour", "anomaly_searches_per_hour", "anomaly_exports_per_hour",
                 "alert_new_country"]


@router.get("/admin/security")
def get_security(p: Principal = Depends(require("security.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute(f"SELECT {', '.join(SECURITY_COLS)} FROM security_settings")
        r = cur.fetchone()
    out = dict(zip(SECURITY_COLS, r)); out["ip_allowlist"] = [str(x) for x in out["ip_allowlist"]]
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT owner_access, legal_hold, sso_domain IS NOT NULL AND sso_idp_alias IS NOT NULL,
                              sso_enforced AND sso_domain IS NOT NULL AND sso_idp_alias IS NOT NULL FROM organizations WHERE id=%s""", (p.org_id,))
        out["owner_access"], out["legal_hold"], out["sso_enabled"], out["sso_enforced"] = cur.fetchone()
    out["encryption"] = {"algorithm": "AES-256-GCM", "current_key": crypto.ring().current,
                         "key_manager": "OpenBao transit" if os.environ.get("BAO_ADDR") else "local (dev only)"}
    return out


@router.put("/admin/security")
def set_security(body: SecurityIn, p: Principal = Depends(require("security.manage"))):
    changes = body.model_dump(exclude_unset=True)
    owner_access = changes.pop("owner_access", None)
    if owner_access is not None and p.access_session_id:
        raise HTTPException(403, "A platform owner working inside this organization can't change who may enter it")
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        if owner_access is not None:
            cur.execute("SELECT owner_access FROM organizations WHERE id=%s FOR UPDATE", (p.org_id,))
            before = cur.fetchone()[0]
            if before != owner_access:
                cur.execute("UPDATE organizations SET owner_access=%s WHERE id=%s", (owner_access, p.org_id))
                _audit(cur, p, "owner_access_setting_changed", None, {"from": before, "to": owner_access})
        cur.execute(f"SELECT {', '.join(SECURITY_COLS)} FROM security_settings FOR UPDATE")
        current = dict(zip(SECURITY_COLS, cur.fetchone()))
        current["ip_allowlist"] = [str(x) for x in current["ip_allowlist"]]
        new = {**current, **{k: v for k, v in changes.items() if v is not None}}
        if new["ip_allowlist"] and (p.ip is None or not any(ipaddress.ip_address(p.ip) in ipaddress.ip_network(c, strict=False)
                                                            for c in new["ip_allowlist"])):
            raise HTTPException(409, "This allowlist would lock you out. Include your current network")
        cur.execute("SELECT min_password_len_floor, max_idle_timeout_min, retention_years_floor FROM platform_settings")
        pw_floor, idle_max, ret_floor = cur.fetchone()
        if new["min_password_len"] < pw_floor or new["idle_timeout_min"] > idle_max or new["retention_years"] < ret_floor:
            raise HTTPException(422, f"The platform requires passwords of at least {pw_floor} characters, "
                                     f"sign-out after at most {idle_max} minutes and {ret_floor}+ years of retention")
        cur.execute("""UPDATE security_settings SET mfa_required=%s,
                       idle_timeout_min=%s, min_password_len=%s, ip_allowlist=%s::cidr[], retention_years=%s,
                       dormant_days=%s, access_review_days=%s, export_limit_per_hour=%s, anomaly_searches_per_hour=%s,
                       anomaly_exports_per_hour=%s, alert_new_country=%s""",
                    (new["mfa_required"], new["idle_timeout_min"], new["min_password_len"], new["ip_allowlist"], new["retention_years"],
                     new["dormant_days"], new["access_review_days"], new["export_limit_per_hour"], new["anomaly_searches_per_hour"],
                     new["anomaly_exports_per_hour"], new["alert_new_country"]))
        _audit(cur, p, "security_settings_changed", None,
               {"changed": {k: {"from": current[k], "to": new[k]} for k in changes if current.get(k) != new.get(k)}})
    return {"ok": True}


# =====================================================================
# API keys for the on/off-ramp
# =====================================================================
class ApiKeyIn(BaseModel):
    label: str | None = Field(None, max_length=80)
    expires_in_days: int | None = Field(None, ge=1, le=730)              # optional; no expiry unless set
    ip_allowlist: list[str] | None = None                                   # empty / omitted = any address
    rate_limit_per_min: int = Field(600, ge=1, le=6000)

    @field_validator("ip_allowlist")
    @classmethod
    def cidrs(cls, v):
        for c in v or []:
            ipaddress.ip_network(c, strict=False)
        return v


def _new_key():
    prefix = "sk_live_" + tokens.new_opaque()[:8].replace("_", "x").replace("-", "x")
    return prefix, f"{prefix}_{tokens.new_opaque()}"


def _insert_key(cur, p: Principal, body: "ApiKeyIn", label, replaces: str | None = None):
    prefix, raw = _new_key()
    cur.execute("""INSERT INTO api_keys (org_id, prefix, key_hash, created_by, label, expires_at, ip_allowlist, rate_limit_per_min)
                   VALUES (%s,%s,%s,%s,%s, CASE WHEN %s::int IS NULL THEN NULL ELSE now() + make_interval(days => %s::int) END, %s::cidr[], %s)""",
                (p.org_id, prefix, crypto.sha256(raw), p.user_id, label, body.expires_in_days, body.expires_in_days,
                 body.ip_allowlist or [], body.rate_limit_per_min))
    _audit(cur, p, "api_key_created", prefix, {"label": label, "expires_in_days": body.expires_in_days,
                                               "ip_allowlist": body.ip_allowlist or [], "rate_limit_per_min": body.rate_limit_per_min,
                                               **({"replaces": replaces} if replaces else {})})
    return prefix, raw


@router.post("/admin/api-keys")
def create_api_key(body: ApiKeyIn | None = None, p: Principal = Depends(require("apikeys.manage", feature="screening"))):
    body = body or ApiKeyIn()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        prefix, raw = _insert_key(cur, p, body, body.label)
    return {"api_key": raw, "prefix": prefix, "message": "Copy this key now. It won't be shown again"}


@router.post("/admin/api-keys/{prefix}/rotate")
def rotate_api_key(prefix: str, body: ApiKeyIn | None = None, p: Principal = Depends(require("apikeys.manage", feature="screening"))):
    """Issue a replacement key (same label and limits unless you send new ones) and keep the old one working for 24 hours, so the
    ramp can switch over without downtime. The old key then expires by itself."""
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT label, expires_at, ip_allowlist, rate_limit_per_min FROM api_keys
                       WHERE prefix=%s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) FOR UPDATE""", (prefix,))
        old = cur.fetchone()
        if not old:
            raise HTTPException(404, "No active key with that prefix")
        if body is None:
            body = ApiKeyIn(label=old[0], ip_allowlist=[str(x) for x in old[2]], rate_limit_per_min=old[3])
        new_prefix, raw = _insert_key(cur, p, body, body.label or old[0], replaces=prefix)
        cur.execute("""UPDATE api_keys SET expires_at = LEAST(COALESCE(expires_at, 'infinity'::timestamptz), now() + interval '24 hours'),
                       rotated_at=now(), replaced_by=%s WHERE prefix=%s RETURNING expires_at""", (new_prefix, prefix))
        until = cur.fetchone()[0]
        _audit(cur, p, "api_key_rotated", prefix, {"replaced_by": new_prefix, "old_key_works_until": until.isoformat()})
    return {"api_key": raw, "prefix": new_prefix, "old_key_expires_at": until,
            "message": "Copy the new key now. The old one keeps working for 24 hours"}


@router.get("/admin/api-keys")
def list_api_keys(p: Principal = Depends(require("apikeys.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT prefix, label, created_at, created_by, revoked_at, expires_at, ip_allowlist, last_used_at, rate_limit_per_min,
                              rotated_at, replaced_by FROM api_keys ORDER BY created_at DESC""")
        rows = cur.fetchall()
    now = _now()
    return [{"prefix": r[0], "label": r[1], "created_at": r[2], "created_by": str(r[3]) if r[3] else None,
             "revoked_at": r[4], "active": r[4] is None and (r[5] is None or r[5] > now), "expires_at": r[5],
             "ip_allowlist": [str(x) for x in r[6]], "last_used_at": r[7], "rate_limit_per_min": r[8],
             "rotated_at": r[9], "replaced_by": r[10]} for r in rows]


@router.delete("/admin/api-keys/{prefix}")
def revoke_api_key(prefix: str, p: Principal = Depends(require("apikeys.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
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
    with pg.tx(p.org_id, platform=p.platform, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute(f"SELECT {COLS} FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq DESC LIMIT %s",
                    (p.org_id, limit))
        rows = cur.fetchall()
    return [{"seq": r[0], "at": r[2], "actor": str(r[3]) if r[3] else None, "role": r[4], "action": r[5],
             "target": r[6], "detail": r[7], "ip": str(r[8]) if r[8] else None} for r in rows]


@router.get("/admin/audit/verify")
def audit_verify(p: Principal = Depends(require_any("audit.view", "platform.audit.view"))):
    with pg.tx(p.org_id, platform=p.platform, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute(f"SELECT {COLS} FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", (p.org_id,))
        return audit.verify_rows(cur.fetchall())


def _tenant_list(p: Principal) -> list[dict]:
    """The places this person can work: the console (platform staff) and every tenant with an active membership.
    Only with the access model v2 (one session, one tenant at a time; the old model has exactly one)."""
    if not config.ACCESS_MODEL_V2:
        return []
    staff, mems = _memberships(p.user_id)
    out = [{"id": str(m[0]), "name": m[1], "slug": m[2], "role": m[5], "kind": "tenant",
            "current": p.scope == "tenant" and p.org_id == str(m[0])} for m in mems]
    if staff:
        out.insert(0, {"id": None, "name": "Platform console", "slug": "platform", "role": staff[1], "kind": "platform",
                       "current": p.scope == "platform"})
    return out


@router.get("/me")
def me(p: Principal = Depends(signed_in_user)):
    """Who is signed in and which tenant, so the UI can show the organization under the app name."""
    home = _org_of(p.user_id)         # the person's own row sits in their home organization (see migration 010)
    with pg.tx(home, platform=home is None) as cur:
        cur.execute("SELECT name_enc, email_enc FROM users WHERE id=%s", (p.user_id,))
        n_enc, e_enc = cur.fetchone()
    person = {"user_id": p.user_id, "name": crypto.decrypt(n_enc, home, "name"),
              "email": crypto.mask_email(crypto.decrypt(e_enc, home, "email"))}
    tenants = _tenant_list(p)
    if p.selecting:        # signed in but no tenant chosen yet (several memberships) or no access at all
        return {**person, "role": None, "access_session": None, "must_rotate": p.must_rotate, "tenant": None, "permissions": [], "features": [], "mfa_enabled": True, "mfa_setup": None,
                "session_mfa": p.mfa, "scope": "select", "selecting": True, "tenants": tenants}
    tenant = {"name": "Platform console", "slug": "platform", "environment": "platform", "brand_color": "#534AB7"}
    if p.org_id:
        with pg.pool().connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT legal_name, slug, environment, brand_color FROM org_display(%s)", (p.org_id,))
            n, slug, env, color = cur.fetchone()
        tenant = {"id": p.org_id, "name": n, "slug": slug, "environment": env, "brand_color": color}
    access = None
    if p.access_session_id:
        with pg.tx(p.org_id, actor=p.actor) as cur:
            cur.execute("SELECT expires_at, reason, extended FROM tenant_access_sessions WHERE id=%s", (p.access_session_id,))
            r = cur.fetchone()
        if r:
            access = {"id": p.access_session_id, "expires_at": r[0], "reason": r[1], "extended": r[2]}
    return {**person, "role": p.role, "access_session": access, "must_rotate": p.must_rotate,
            "passkeys": p.passkey_count, "must_enroll_passkey": p.must_enroll_passkey,
            "tenant": tenant, "permissions": sorted(p.perms), "features": sorted(p.features),
            # mfa_setup: "required" (the organization insists), "optional" (turn it on from My account), or None (it's on)
            "mfa_enabled": p.mfa_setup is None, "mfa_setup": p.mfa_setup, "session_mfa": p.mfa,
            "scope": p.scope, "selecting": False, "tenants": tenants, "step_up_fresh": p.mfa_fresh(),
            "teams_enabled": config.teams_enabled()}


@router.get("/me/tenants")
def my_tenants(p: Principal = Depends(signed_in_user)):
    return {"tenants": _tenant_list(p)}


class TenantSwitch(BaseModel):
    tenant_id: uuid.UUID | None = None      # null = the platform console (platform staff only)


@router.post("/session/tenant")
@limiter.limit("20/minute")
def switch_tenant(request: Request, response: Response, body: TenantSwitch, p: Principal = Depends(signed_in_user)):
    """Move this sign-in to another tenant (or the console). The target must be one of the caller's active memberships; the
    old session ends and a new one (new session id) starts, so nothing from one tenant carries into the next. Audited."""
    target, role_id, asid = body.tenant_id, None, None
    from app import owner_access
    access = owner_access.live_session(p.user_id, target) if target else None     # an owner's live access session lets them in
    staff, mems = _memberships(p.user_id)
    if not config.ACCESS_MODEL_V2 and not access and not (target is None and staff):     # (staff may always return to the console)
        raise HTTPException(403, "Switching tenants isn't available yet")
    if access:
        with pg.tx(platform=True, actor=p.actor) as cur:
            cur.execute("SELECT id FROM roles WHERE org_id=%s AND is_locked", (target,))
            role_id = cur.fetchone()[0]
        asid = access[0]
    elif target is None:
        if not staff:
            raise HTTPException(403, "You don't have access to the platform console")
        role_id = staff[0]
    else:
        m = next((m for m in mems if m[0] == target), None)
        if not m:
            raise HTTPException(403, "You don't have access to that tenant")
        role_id = m[4]
    family = None
    try:
        family = uuid.UUID(p.session_id) if p.session_id else None
    except ValueError:
        pass
    old = None
    with pg.tx(platform=True) as cur:
        if family:
            cur.execute("""SELECT auth_method, last_mfa_at, tenant_id FROM refresh_tokens WHERE family_id=%s
                           ORDER BY created_at DESC LIMIT 1""", (family,))
            old = cur.fetchone()
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND revoked_at IS NULL", (family,))
        cur.execute("SELECT session_version FROM session_user_lookup(%s)", (p.user_id,))
        sv = cur.fetchone()[0]
    method, last_mfa, source = (old[0], old[1], old[2]) if old else ("password" if not p.mfa else "password+totp", None, p.org_id)
    with pg.tx(target, platform=target is None) as cur:
        session = _issue(cur, response, p.user_id, target, role_id, sv, request, method=method, mfa=p.mfa,
                         scope="platform" if target is None else "tenant", last_mfa_at=last_mfa, access_session_id=asid)
        audit.write(cur, target, p.user_id, None, "auth.tenant_switch", None,
                    {"from": str(source) if source else "platform", "to": str(target) if target else "platform",
                     **({"access_session_id": str(asid)} if asid else {})}, client_ip(request))
    if source != target:
        with pg.tx(source, platform=source is None) as cur:
            audit.write(cur, source, p.user_id, None, "auth.tenant_switch", None,
                        {"from": str(source) if source else "platform", "to": str(target) if target else "platform"}, client_ip(request))
    return session


class StepUpIn(BaseModel):
    code: str | None = Field(None, max_length=10)
    recovery_code: str | None = Field(None, max_length=40)
    credential: dict | None = None            # a passkey assertion (after POST /session/step-up/options)


@router.post("/session/step-up")
@limiter.limit("10/minute")
def step_up(request: Request, body: StepUpIn, p: Principal = Depends(signed_in_user)):
    """Prove a second factor again for a sensitive action. Answers with a new access token whose last-two-factor time is now."""
    if p.selecting:
        raise HTTPException(403, "Choose a tenant first")
    home = _org_of(p.user_id)
    with pg.tx(home, platform=home is None) as cur:
        cur.execute("""SELECT totp_secret_enc, totp_last_step, role_id, session_version, mfa_enabled, status
                       FROM users WHERE id=%s FOR UPDATE""", (p.user_id,))
        row = cur.fetchone()
        n_pk = passkeys.count(cur, p.user_id) if row and _passkeys_on(cur) else 0
        if not row or row[5] != "active" or not ((row[4] and row[0]) or n_pk):
            raise HTTPException(409, "Turn on two-factor authentication first")
        enc, last, role_id, sv = row[:4]
        used_passkey = False
        if body.credential is not None:
            try:
                passkeys.finish_authentication(cur, p.user_id, body.credential, "step_up")
                ok, used_passkey = True, True
            except ValueError:
                ok = False
        elif str(role_id) == PLATFORM_OWNER_ROLE and n_pk:
            raise HTTPException(403, "Platform owners confirm with a passkey")
        elif not enc:
            raise HTTPException(409, "Confirm with a passkey: no authenticator app is set up")
        else:
            ok = _second_factor(cur, p.user_id, home, enc, last, body.code, body.recovery_code)
    with pg.tx(p.org_id, platform=p.org_id is None, actor=p.actor, access_session=p.access_session_id) as cur:
        if not ok:
            audit.write(cur, p.org_id, p.user_id, None, "auth.step_up_failed", None, {}, client_ip(request))
        else:
            audit.write(cur, p.org_id, p.user_id, None, "auth.step_up", None,
                        {"method": "passkey" if used_passkey else "totp" if body.code else "recovery_code"}, client_ip(request))
            idle, _ = _session_limits(cur, p.org_id)
    if not ok:
        raise HTTPException(401, "That code didn't work. Check your app and try again")
    now = _now()
    with pg.tx(platform=True) as cur:
        if p.session_id:
            cur.execute("UPDATE refresh_tokens SET last_mfa_at=%s WHERE family_id=%s AND revoked_at IS NULL", (now, p.session_id))
    ttl = min(tokens.ACCESS_TTL, timedelta(minutes=idle))
    return {"access_token": tokens.issue_access(p.user_id, p.org_id, role_id, sv, mfa=True, ttl=ttl, session_id=p.session_id,
                                                scope=p.scope, last_mfa_at=now, factor="passkey" if used_passkey else "totp"),
            "token_type": "Bearer", "expires_in": int(ttl.total_seconds())}


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
        cur.execute("""UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=%s AND user_id=%s AND revoked_at IS NULL
                       RETURNING 1""", (family_id, p.user_id))
        ended = cur.fetchone()
    if not ended:       # someone else's session, one that doesn't exist, or one that already ended: all look the same
        raise HTTPException(404, "That isn't one of your active sessions")
    with pg.tx(p.org_id, platform=p.platform, actor=p.actor, access_session=p.access_session_id) as cur:
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
    with pg.tx(p.org_id, platform=p.platform, actor=p.actor, access_session=p.access_session_id) as cur:
        _audit(cur, p, "other_sessions_ended", None, {"count": n})
    return {"ended": n}



# =====================================================================
# Company single sign-on: prove the email domain by DNS, then route it to the company's IdP
# =====================================================================
class SsoIn(BaseModel):
    domain: str = Field(pattern=r"^[a-z0-9.-]+\.[a-z]{2,}$")
    idp_alias: str = Field(pattern=r"^[a-z0-9-]{2,40}$", description="Identity provider alias configured in Keycloak")
    enforced: bool = False
    protocol: str = Field("oidc", pattern="^(oidc|saml)$", description="How the company's identity provider is connected in Keycloak (it brokers both)")
    default_role_id: uuid.UUID | None = Field(None, description="Role given to people created on their first company sign-in (never the Tenant admin)")


@router.get("/admin/sso")
def get_sso(p: Principal = Depends(require("security.manage"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT sso_domain, sso_domain_pending, sso_idp_alias, sso_enforced, sso_protocol, sso_default_role_id FROM organizations WHERE id=%s""", (p.org_id,))
        r = cur.fetchone()
        cur.execute("SELECT id FROM users WHERE org_id=%s AND sso_emergency", (p.org_id,))
        em = cur.fetchone()
    return {"domain": r[0], "pending_domain": r[1], "idp_alias": r[2], "enforced": bool(r[3] and r[0] and r[2]),
            "enforce_switch": r[3], "protocol": r[4], "default_role_id": str(r[5]) if r[5] else None,
            "emergency_user_id": str(em[0]) if em else None}


@router.put("/admin/sso")
def set_sso(body: SsoIn, p: Principal = Depends(require("security.manage"))):
    token = "sentrail-verify=" + secrets.token_urlsafe(24)
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        if body.default_role_id:
            cur.execute("SELECT is_locked FROM roles WHERE id=%s AND org_id=%s", (body.default_role_id, p.org_id))
            role = cur.fetchone()
            if not role:
                raise HTTPException(404, "Role not found")
            if role[0]:
                raise HTTPException(422, "New people created by company sign-in can't be given the Tenant admin role")
        cur.execute("""UPDATE organizations SET sso_domain_pending=%s, sso_idp_alias=%s, sso_enforced=%s, sso_protocol=%s,
                       sso_default_role_id=%s, domain_verify_token=%s WHERE id=%s""",
                    (body.domain, body.idp_alias, body.enforced, body.protocol, body.default_role_id, token, p.org_id))
        _audit(cur, p, "sso_configured", body.domain, {"idp_alias": body.idp_alias, "enforced": body.enforced, "protocol": body.protocol,
                                                      "default_role_id": str(body.default_role_id) if body.default_role_id else None})
    return {"txt_record": {"name": f"_sentrail.{body.domain}", "value": token},
            "next": "Add this TXT record to your DNS, then call /admin/sso/verify"}


class EmergencyIn(BaseModel):
    user_id: uuid.UUID


@router.put("/admin/sso/emergency")
def set_sso_emergency(body: EmergencyIn, p: Principal = Depends(require("security.manage"))):
    """Keep ONE Tenant admin able to sign in with a password when company sign-in is enforced (if the identity provider is down).
    That login always needs a passkey as its second factor, so the person must have one."""
    if p.access_session_id:
        raise HTTPException(403, "A platform owner working inside this organization can't change its sign-in rules")
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("""SELECT u.status, r.is_locked, (SELECT count(*) FROM user_passkeys k WHERE k.user_id=u.id)
                       FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s AND u.org_id=%s""", (body.user_id, p.org_id))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "User not found")
        if r[0] != "active" or not r[1]:
            raise HTTPException(409, "The emergency login must be an active Tenant admin")
        if not r[2]:
            raise HTTPException(409, "That person has no passkey yet. The emergency login needs one (My account > Passkeys)")
        cur.execute("UPDATE users SET sso_emergency=false WHERE org_id=%s AND sso_emergency AND id<>%s", (p.org_id, body.user_id))
        cur.execute("UPDATE users SET sso_emergency=true WHERE id=%s", (body.user_id,))
        _audit(cur, p, "sso_emergency_login_set", str(body.user_id))
    return {"emergency_user_id": str(body.user_id)}


@router.delete("/admin/sso/emergency")
def clear_sso_emergency(p: Principal = Depends(require("security.manage"))):
    if p.access_session_id:
        raise HTTPException(403, "A platform owner working inside this organization can't change its sign-in rules")
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("UPDATE users SET sso_emergency=false WHERE org_id=%s AND sso_emergency RETURNING 1", (p.org_id,))
        if not cur.fetchone():
            raise HTTPException(404, "No emergency login is set")
        _audit(cur, p, "sso_emergency_login_cleared")
    return {"cleared": True}


@router.post("/admin/sso/verify")
def verify_sso(p: Principal = Depends(require("security.manage"))):
    import dns.resolver
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
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
        with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
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
        if str(body.role_id) == PLATFORM_OWNER_ROLE and not p.can("platform.owners.manage"):
            raise HTTPException(403, "Only a platform owner can add another platform owner")
        if str(body.role_id) == PLATFORM_OWNER_ROLE:
            # adding an owner needs a second owner (the email is kept encrypted until then)
            return _request_approval(cur, p, "owner.add", {"email_enc": crypto.encrypt(crypto.normalize_email(body.email), None, "email"),
                                                          "role_id": str(body.role_id)}, f"Add a platform owner ({crypto.mask_email(body.email)})")
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
        if touching_owner and not p.can("platform.owners.manage"):
            raise HTTPException(403, "Only a platform owner can change a platform owner")
        if cur_role[0] == "Platform owner" and (body.status == "suspended" or (body.role_id and str(body.role_id) != PLATFORM_OWNER_ROLE)):
            cur.execute("""SELECT count(*) FROM users WHERE org_id IS NULL AND status='active' AND role_id=%s""", (PLATFORM_OWNER_ROLE,))
            if cur.fetchone()[0] <= 1:
                raise HTTPException(409, "The platform needs at least one active owner")
        if touching_owner:
            # changing, demoting or suspending an owner (or promoting someone to owner) needs a second owner
            return _request_approval(cur, p, "owner.change", {"uid": str(uid), "role_id": str(body.role_id) if body.role_id else None,
                                                              "status": body.status}, "Change a platform owner")
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
def get_plans(p: Principal = Depends(require_any("platform.plans.manage", "platform.tenants.manage"))):
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
def set_org_plan(org_id: uuid.UUID, body: OrgPlan, p: Principal = Depends(require("platform.tenants.manage"))):
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
    platform_staff_passkey_only: bool = False    # when on, Platform owners must use a passkey (those without one can only register one)
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
    """Tightening the baseline applies at once. LOOSENING it (shorter passwords, longer sessions or idle time, less retention, more regions,
    passkeys no longer required) is parked until a second owner approves it."""
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("""SELECT min_password_len_floor, max_idle_timeout_min, max_session_hours, retention_years_floor,
                              passkeys_allowed, platform_staff_passkey_only, allowed_regions FROM platform_settings""")
        old = dict(zip(PlatformSecurityIn.model_fields, cur.fetchone()))
        new = body.model_dump()
        looser = _baseline_loosens(old, new)
        if looser:
            return _request_approval(cur, p, "baseline.loosen", new, "Loosen the security baseline: " + ", ".join(looser))
        raised = _apply_baseline(cur, p, new)
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


# =====================================================================
# Tenant lifecycle: suspend / reactivate, delete (second-owner approval), replace the Tenant admin
# =====================================================================
class StatusIn(BaseModel):
    status: str = Field(pattern="^(active|suspended)$")
    reason: str = Field(min_length=5, max_length=500)


STATUS_TRANSITIONS = {("active", "suspended"), ("trial", "suspended"), ("suspended", "active")}


def _end_tenant_sessions(cur, org_id):
    """Every session inside the tenant ends now (and every person's permissions are re-read)."""
    cur.execute("""UPDATE refresh_tokens SET revoked_at=now() WHERE revoked_at IS NULL
                   AND (tenant_id=%s OR user_id IN (SELECT id FROM users WHERE org_id=%s))""", (org_id, org_id))
    cur.execute("UPDATE users SET session_version=session_version+1 WHERE org_id=%s", (org_id,))


@router.post("/platform/orgs/{org_id}/status")
def set_org_status(org_id: uuid.UUID, body: StatusIn, p: Principal = Depends(require("platform.tenants.manage"))):
    """Suspend a tenant (nobody can sign in, every session and API key stops, data is kept) or reactivate it."""
    with pg.tx(platform=True, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT status, legal_name FROM organizations WHERE id=%s FOR UPDATE", (org_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Organization not found")
        if (r[0], body.status) not in STATUS_TRANSITIONS:
            raise HTTPException(409, f"A {r[0]} organization can't become {body.status}")
        cur.execute("UPDATE organizations SET status=%s, status_reason=%s, status_changed_at=now() WHERE id=%s", (body.status, body.reason, org_id))
        if body.status == "suspended":
            _end_tenant_sessions(cur, org_id)
        action = "tenant_suspended" if body.status == "suspended" else "tenant_reactivated"
        _audit(cur, p, action, r[1], {"reason": body.reason, "from": r[0]}, org_id=org_id)
        _audit(cur, p, action, r[1], {"reason": body.reason, "org_id": str(org_id)})
    return {"org_id": str(org_id), "status": body.status}


APPROVAL_PERMS = {"tenant.delete": "platform.tenants.delete", "owner.add": "platform.owners.manage",
                  "owner.change": "platform.owners.manage", "baseline.loosen": "platform.security.manage"}   # owner_access adds tenant.legal_hold
APPROVAL_VIEW = ("platform.tenants.delete", "platform.owners.manage", "platform.security.manage", "platform.tenants.manage")
EXECUTORS: dict = {}       # action -> fn(cur, approver, payload, reason, approval_id) -> (result dict, callable run after commit or None)


def _request_approval(cur, p: Principal, action: str, payload: dict, reason: str) -> dict:
    """Park a high-risk platform action until a SECOND owner approves it (within 24 hours). Nothing is applied now."""
    cur.execute("""SELECT 1 FROM platform_approvals WHERE action=%s AND status='pending' AND expires_at > now() AND payload=%s::jsonb""",
                (action, json.dumps(payload)))
    if cur.fetchone():
        raise HTTPException(409, "The same request is already waiting for a second owner")
    cur.execute("""INSERT INTO platform_approvals (action, payload, requested_by, reason, expires_at)
                   VALUES (%s, %s, %s, %s, now() + interval '24 hours') RETURNING id, expires_at""",
                (action, json.dumps(payload), p.user_id, reason))
    aid, exp = cur.fetchone()
    _audit(cur, p, "approval_requested", str(aid), {"action": action, "reason": reason})
    return {"approval_id": str(aid), "pending": True, "expires_at": exp,
            "next": "A second Platform owner has to approve this within 24 hours (POST /platform/approvals/{id}/approve)"}


@router.post("/platform/orgs/{org_id}/delete")
def request_org_delete(org_id: uuid.UUID, body: Reason, p: Principal = Depends(require("platform.tenants.delete"))):
    """Ask to delete a tenant. Nothing happens until a SECOND owner approves within 24 hours (POST /platform/approvals/{id}/approve)."""
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("SELECT status, legal_name FROM organizations WHERE id=%s", (org_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Organization not found")
        if r[0] == "deleted":
            raise HTTPException(409, "This organization is already deleted")
        return _request_approval(cur, p, "tenant.delete", {"org_id": str(org_id), "name": r[1]}, body.reason)


@router.get("/platform/approvals")
def list_approvals(p: Principal = Depends(require_any(*APPROVAL_VIEW))):
    with pg.tx(platform=True, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT id, action, payload, requested_by, approved_by, status, reason, created_at, decided_at, expires_at
                       FROM platform_approvals ORDER BY created_at DESC LIMIT 100""")
        return [{"id": str(r[0]), "action": r[1], "payload": {k: v for k, v in r[2].items() if k != "email_enc"}, "requested_by": str(r[3]), "approved_by": str(r[4]) if r[4] else None,
                 "status": "expired" if r[5] == "pending" and r[9] < _now() else r[5], "reason": r[6], "created_at": r[7],
                 "decided_at": r[8], "expires_at": r[9]} for r in cur.fetchall()]


def _delete_tenant(cur, p: Principal, org_id, name, reason, approval_id):
    cur.execute("SELECT retention_years FROM security_settings WHERE org_id=%s", (org_id,))
    years = (cur.fetchone() or [5])[0]
    cur.execute("""UPDATE organizations SET status='deleted', deleted_at=now(), status_reason=%s, status_changed_at=now(),
                   deletion_due_at = now() + make_interval(years => %s) WHERE id=%s RETURNING deletion_due_at""", (reason, years, org_id))
    due = cur.fetchone()[0]
    _end_tenant_sessions(cur, org_id)
    cur.execute("UPDATE tenant_access_sessions SET status='ended', ended_at=now(), ended_reason='tenant deleted' WHERE tenant_id=%s AND status IN ('requested','approved','active')", (org_id,))
    detail = {"reason": reason, "approval": str(approval_id), "data_removal_due": due.isoformat(), "retention_years": years}
    _audit(cur, p, "tenant_deleted", name, detail, org_id=org_id)
    _audit(cur, p, "tenant_deleted", name, {**detail, "org_id": str(org_id)})
    return due


def _exec_tenant_delete(cur, p, payload, reason, approval_id):
    org_id = payload["org_id"]
    due = _delete_tenant(cur, p, org_id, payload.get("name"), reason, approval_id)

    def revoke_keys():                       # API keys are tenant data: revoked from inside the tenant scope
        with pg.tx(org_id) as c2:
            c2.execute("UPDATE api_keys SET revoked_at=now() WHERE revoked_at IS NULL")
    return {"executed": "tenant.delete", "data_removal_due": due}, revoke_keys


def _exec_owner_add(cur, p, payload, reason, approval_id):
    email = crypto.decrypt(payload["email_enc"], None, "email")
    link = _invite(cur, None, "the Sentrail platform team", email, payload["role_id"], "Platform owner", p.user_id)
    _audit(cur, p, "platform_owner_invited", crypto.mask_email(email), {"approval": str(approval_id)})
    return {"executed": "owner.add", "invited": crypto.mask_email(email), **({"dev_link": link} if _dev() else {})}, None


def _exec_owner_change(cur, p, payload, reason, approval_id):
    uid, new_role, new_status = payload["uid"], payload.get("role_id"), payload.get("status")
    cur.execute("SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=%s AND u.org_id IS NULL", (uid,))
    cur_role = cur.fetchone()
    if not cur_role:
        raise HTTPException(404, "Platform user not found")
    leaving = cur_role[0] == "Platform owner" and (new_status == "suspended" or (new_role and str(new_role) != PLATFORM_OWNER_ROLE))
    if leaving:
        cur.execute("SELECT count(*) FROM users WHERE org_id IS NULL AND status='active' AND role_id=%s", (PLATFORM_OWNER_ROLE,))
        if cur.fetchone()[0] <= 1:
            raise HTTPException(409, "The platform needs at least one active owner")
    if new_role:
        _platform_role(cur, new_role)
        cur.execute("UPDATE users SET role_id=%s, session_version=session_version+1 WHERE id=%s", (new_role, uid))
    if new_status:
        cur.execute("UPDATE users SET status=%s, session_version=session_version+1 WHERE id=%s", (new_status, uid))
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
    _audit(cur, p, "platform_owner_changed", uid, {"role_id": new_role, "status": new_status, "approval": str(approval_id)})
    return {"executed": "owner.change"}, None


def _baseline_loosens(old: dict, new: dict) -> list[str]:
    out = []
    if new["min_password_len_floor"] < old["min_password_len_floor"]: out.append("shorter minimum password")
    if new["max_idle_timeout_min"] > old["max_idle_timeout_min"]: out.append("longer idle timeout")
    if new["max_session_hours"] > old["max_session_hours"]: out.append("longer sessions")
    if new["retention_years_floor"] < old["retention_years_floor"]: out.append("shorter retention")
    if old["platform_staff_passkey_only"] and not new["platform_staff_passkey_only"]: out.append("passkeys no longer required for staff")
    if set(new["allowed_regions"]) - set(old["allowed_regions"]): out.append("more data regions")
    return out


def _apply_baseline(cur, p: Principal, body: dict, extra: dict | None = None):
    cur.execute("""UPDATE platform_settings SET min_password_len_floor=%s, max_idle_timeout_min=%s, max_session_hours=%s,
                   retention_years_floor=%s, passkeys_allowed=%s, platform_staff_passkey_only=%s, allowed_regions=%s,
                   updated_at=now()""", (body["min_password_len_floor"], body["max_idle_timeout_min"], body["max_session_hours"],
                                         body["retention_years_floor"], body["passkeys_allowed"],
                                         body["platform_staff_passkey_only"], body["allowed_regions"]))
    # bring every tenant up to the new baseline; tenants that are already stricter keep their settings
    cur.execute("""UPDATE security_settings SET min_password_len = GREATEST(min_password_len, %s),
                   idle_timeout_min = LEAST(idle_timeout_min, %s), retention_years = GREATEST(retention_years, %s)""",
                (body["min_password_len_floor"], body["max_idle_timeout_min"], body["retention_years_floor"]))
    raised = cur.rowcount
    _audit(cur, p, "platform_security_changed", None, {**body, "tenants_updated": raised, **(extra or {})})
    return raised


def _exec_baseline(cur, p, payload, reason, approval_id):
    raised = _apply_baseline(cur, p, payload, {"approval": str(approval_id), "loosening": True})
    return {"executed": "baseline.loosen", "tenants_checked": raised}, None


EXECUTORS.update({"tenant.delete": _exec_tenant_delete, "owner.add": _exec_owner_add, "owner.change": _exec_owner_change,
                  "baseline.loosen": _exec_baseline})


def _decide(approval_id, p: Principal, approve: bool, note: str | None = None):
    error, after, result = None, None, {"status": "approved" if approve else "denied"}
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("""SELECT action, payload, requested_by, status, expires_at, reason FROM platform_approvals WHERE id=%s FOR UPDATE""", (approval_id,))
        a = cur.fetchone()
        if not a:
            raise HTTPException(404, "Approval not found")
        action, payload, requester, status, expires, reason = a
        if status != "pending":
            raise HTTPException(409, f"This request is already {status}")
        if expires < _now():
            cur.execute("UPDATE platform_approvals SET status='expired', decided_at=now() WHERE id=%s", (approval_id,))
            error = HTTPException(410, "This request expired after 24 hours. Ask again")
        elif not p.can(APPROVAL_PERMS.get(action, "platform.owners.manage")):
            raise HTTPException(403, "Your role can't decide this kind of request")
        elif str(requester) == p.user_id:
            raise HTTPException(403, "A second Platform owner has to decide this: you can't approve your own request")
        elif not approve:
            cur.execute("UPDATE platform_approvals SET status='denied', approved_by=NULL, decided_at=now() WHERE id=%s", (approval_id,))
            _audit(cur, p, "approval_denied", str(approval_id), {"action": action, "note": note})
        else:
            cur.execute("UPDATE platform_approvals SET status='approved', approved_by=%s, decided_at=now() WHERE id=%s", (p.user_id, approval_id))
            _audit(cur, p, "approval_approved", str(approval_id), {"action": action})
            done, after = EXECUTORS[action](cur, p, payload, reason, approval_id)
            result = {"status": "approved", **done}
    if error:
        raise error
    if after:
        after()
    return result


@router.post("/platform/approvals/{approval_id}/approve")
def approve_request(approval_id: uuid.UUID, p: Principal = Depends(require_any(*APPROVAL_VIEW))):
    return _decide(approval_id, p, True)


@router.post("/platform/approvals/{approval_id}/deny")
def deny_request(approval_id: uuid.UUID, body: Reason, p: Principal = Depends(require_any(*APPROVAL_VIEW))):
    return _decide(approval_id, p, False, body.reason)


class AdminRecoveryIn(BaseModel):
    email: EmailStr
    reason: str = Field(min_length=5, max_length=500)


@router.post("/platform/orgs/{org_id}/admin")
def assign_tenant_admin(org_id: uuid.UUID, body: AdminRecoveryIn, p: Principal = Depends(require("platform.tenants.manage"))):
    """When a tenant has lost its administrator: make this person its Tenant admin (a member is promoted, anyone else is invited for
    72 hours). Needs a reason and is written to the tenant's audit log AND the platform's."""
    with pg.tx(platform=True, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT status, legal_name FROM organizations WHERE id=%s FOR UPDATE", (org_id,))
        org = cur.fetchone()
        if not org:
            raise HTTPException(404, "Organization not found")
        if org[0] == "deleted":
            raise HTTPException(409, "This organization is deleted")
        cur.execute("SELECT id FROM roles WHERE org_id=%s AND name=%s", (org_id, TENANT_ADMIN))
        admin_role = cur.fetchone()[0]
        cur.execute("SELECT id, org_id FROM auth_lookup(%s)", (crypto.blind_index(body.email),))
        known = cur.fetchone()
        link, how = None, "invited (72 hours)"
        if known and known[1] == org_id:
            cur.execute("""UPDATE users SET role_id=%s, status='active', mfa_mandatory=true, session_version=session_version+1
                           WHERE id=%s AND status <> 'invited'""", (admin_role, known[0]))
            if cur.rowcount == 0:
                raise HTTPException(409, "That person hasn't accepted their invitation yet. Resend it from the user list instead")
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (known[0],))
            how = "promoted"
        elif known and config.ACCESS_MODEL_V2:
            cur.execute("""INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status) VALUES (%s,%s,%s,'active')
                           ON CONFLICT (user_id, tenant_id) DO UPDATE SET role_id=EXCLUDED.role_id, status='active'""",
                        (known[0], org_id, admin_role))
            how = "added as a member"
        else:
            link = _invite(cur, org_id, org[1], body.email, admin_role, TENANT_ADMIN, p.user_id)
        detail = {"reason": body.reason, "who": crypto.mask_email(body.email), "how": how}
        _audit(cur, p, "tenant_admin_assigned", org[1], detail, org_id=org_id)
        _audit(cur, p, "tenant_admin_assigned", org[1], {**detail, "org_id": str(org_id)})
    return {"ok": True, "how": how, **({"dev_link": link} if (_dev() and link) else {})}


@router.post("/platform/orgs/{org_id}/users/{uid}/resend-invitation")
def support_resend(org_id: uuid.UUID, uid: uuid.UUID, body: Reason, p: Principal = Depends(require("platform.support"))):
    with pg.tx(org_id, platform=True) as cur:
        cur.execute("SELECT email_enc, status, idp_subject FROM users WHERE id=%s AND org_id=%s", (uid, org_id))
        r = cur.fetchone()
        if not r or r[1] != "invited":
            raise HTTPException(409, "Only pending invitations can be resent")
        link = None
        if AUTH_MODE == "keycloak" and r[2]:
            kc().send_setup_email(r[2])
        else:
            raw = tokens.new_opaque()
            cur.execute("""INSERT INTO invitations (org_id, user_id, token_hash, invited_by, expires_at)
                           VALUES (%s,%s,%s,%s, now() + interval '72 hours')""", (org_id, uid, crypto.sha256(raw), p.user_id))
            link = f"{APP_URL}/join#{raw}"
            mailer.send_invitation(crypto.decrypt(r[0], org_id, "email"), _org_name(org_id), "your role", link)
        _audit(cur, p, "support_resent_invitation", str(uid), {"reason": body.reason}, org_id=org_id)
    return {"ok": True, **({"dev_link": link} if (_dev() and link) else {})}

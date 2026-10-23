"""Passkey routes: register, list and remove them, sign in with one, and confirm a sensitive action with one (step-up)."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app import admin_api as A, pg
from app.security.middleware import limiter
from app.security import audit, crypto, passkeys, tokens
from app.security.rbac import Principal, client_ip, signed_in_user
from app.services import notify

router = APIRouter()


class RegisterIn(BaseModel):
    credential: dict
    name: str = Field("Passkey", min_length=1, max_length=60)


def _home(p: Principal):
    return A._org_of(p.user_id)


def _require_allowed(cur):
    if not A._passkeys_on(cur):
        raise HTTPException(403, "Passkeys are switched off on this platform")


@router.post("/me/passkeys/options")
@limiter.limit("10/minute")
def registration_options(request: Request, p: Principal = Depends(signed_in_user)):
    home = _home(p)
    with pg.tx(home, platform=home is None, actor=p.user_id) as cur:
        _require_allowed(cur)
        cur.execute("SELECT email_enc FROM users WHERE id=%s", (p.user_id,))
        email = crypto.decrypt(cur.fetchone()[0], home, "email")
        try:
            return passkeys.registration_options(cur, p.user_id, email)
        except ValueError as e:
            raise HTTPException(409, str(e))


@router.post("/me/passkeys")
@limiter.limit("10/minute")
def register(request: Request, response: Response, body: RegisterIn, p: Principal = Depends(signed_in_user)):
    """Register a passkey. When it is the person's first second factor, their password-only sessions end (as when enabling an authenticator
    app) and they get a new two-factor session in the answer, because creating the passkey proved they hold it."""
    home = _home(p)
    session = None
    with pg.tx(home, platform=home is None, actor=p.user_id) as cur:
        _require_allowed(cur)
        cur.execute("SELECT email_enc, role_id, session_version, mfa_enabled FROM users WHERE id=%s FOR UPDATE", (p.user_id,))
        email_enc, role_id, sv, totp_on = cur.fetchone()
        email = crypto.decrypt(email_enc, home, "email")
        first_factor = not totp_on and passkeys.count(cur, p.user_id) == 0
        try:
            made = passkeys.finish_registration(cur, p.user_id, body.credential, body.name)
        except ValueError as e:
            raise HTTPException(422, str(e))
        except Exception:
            raise HTTPException(422, "That passkey couldn't be verified. Try again")
        audit.write(cur, home, p.user_id, None, "auth.passkey_registered", made["id"], {"name": made["name"]}, client_ip(request))
        if first_factor:
            cur.execute("UPDATE users SET session_version=session_version+1 WHERE id=%s", (p.user_id,))
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (p.user_id,))
            session = A._issue(cur, response, p.user_id, p.org_id, role_id, sv + 1, request, method="password+passkey", mfa=True,
                               scope=p.scope, factor="passkey")
    notify.security_event(email, "passkey_registered", {"where": made["name"]})
    return {**made, **({"session": session} if session else {})}


@router.get("/me/passkeys")
def mine(p: Principal = Depends(signed_in_user)):
    home = _home(p)
    with pg.tx(home, platform=home is None, actor=p.user_id) as cur:
        return {"passkeys": passkeys.list_passkeys(cur, p.user_id), "allowed": A._passkeys_on(cur)}


@router.delete("/me/passkeys/{passkey_id}")
def remove(passkey_id: uuid.UUID, request: Request, p: Principal = Depends(signed_in_user)):
    home = _home(p)
    with pg.tx(home, platform=home is None, actor=p.user_id) as cur:
        cur.execute("SELECT role_id FROM users WHERE id=%s", (p.user_id,))
        is_owner = str(cur.fetchone()[0]) == A.PLATFORM_OWNER_ROLE
        cur.execute("SELECT platform_staff_passkey_only FROM platform_settings")
        required = cur.fetchone()[0]
        if is_owner and required and passkeys.count(cur, p.user_id) <= 1:
            raise HTTPException(409, "The platform requires every owner to keep a passkey. Register another before removing this one")
        cur.execute("DELETE FROM user_passkeys WHERE id=%s AND user_id=%s RETURNING 1", (passkey_id, p.user_id))
        if not cur.fetchone():
            raise HTTPException(404, "No such passkey")
        audit.write(cur, home, p.user_id, None, "auth.passkey_removed", str(passkey_id), {}, client_ip(request))
    return {"removed": str(passkey_id)}


class PasskeyLogin(BaseModel):
    mfa_token: str
    credential: dict


@router.post("/auth/passkey")
@limiter.limit("10/minute")
def sign_in_with_passkey(request: Request, response: Response, body: PasskeyLogin):
    """The second step of sign-in with a passkey (after POST /auth/login answered with `passkey_options`)."""
    try:
        uid = tokens.decode(body.mfa_token, typ="mfa_pending")["sub"]
    except Exception:
        raise HTTPException(401, "Sign-in expired. Start again")
    org = A._org_of(uid)
    notice = None
    with pg.tx(org, platform=org is None) as cur:
        cur.execute("SELECT role_id, session_version, status, email_enc FROM users WHERE id=%s FOR UPDATE", (uid,))
        row = cur.fetchone()
        if not row or row[2] != "active" or not A._passkeys_on(cur):
            raise HTTPException(401, "Sign-in expired. Start again")
        role_id, sv, _, email_enc = row
        try:
            pid = passkeys.finish_authentication(cur, uid, body.credential, "login")
            ok = True
        except ValueError:
            ok = False
        if not ok:
            audit.write(cur, org, uid, None, "auth.signin_failed", None, {"stage": "passkey"}, client_ip(request))
        else:
            cur.execute("UPDATE users SET last_login_at=now() WHERE id=%s", (uid,))
            result = A._start_session(cur, response, request, uid, org, role_id, sv, method="password+passkey", mfa=True, factor="passkey")
            audit.write(cur, org, uid, None, "auth.signin", None,
                        {"method": "passkey", "mfa": True, "route": result["route"], "passkey": pid}, client_ip(request))
            notice = A._device_notice(cur, request, response, uid, org, email_enc)
    if not ok:
        raise HTTPException(401, "That passkey didn't work. Try again, or use another sign-in method")
    if notice:
        notify.security_event(*notice)
    return result


@router.post("/session/step-up/options")
@limiter.limit("20/minute")
def step_up_options(request: Request, p: Principal = Depends(signed_in_user)):
    """The challenge to answer with a passkey for POST /session/step-up {credential}."""
    if p.selecting:
        raise HTTPException(403, "Choose a tenant first")
    home = _home(p)
    with pg.tx(home, platform=home is None, actor=p.user_id) as cur:
        if not A._passkeys_on(cur) or not passkeys.count(cur, p.user_id):
            raise HTTPException(409, "You have no passkey to confirm with")
        return passkeys.authentication_options(cur, p.user_id, "step_up")

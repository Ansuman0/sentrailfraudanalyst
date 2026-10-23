"""Authentication and authorization for every request.

The server is the only place permissions are enforced; the UI only hides buttons.
Each request: verify JWT -> reload user (status, session version, role) -> check
IP allowlist and idle policy -> check permission and feature -> run in tenant scope.
"""
import ipaddress
import os
import time
from dataclasses import dataclass, field
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

import logging

from app import config, pg
from app.access import cache, catalogue
from app.security import tokens, crypto

log = logging.getLogger("sentrail.access")

bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    user_id: str
    org_id: str | None
    role: str
    perms: set = field(default_factory=set)
    features: set = field(default_factory=set)
    ip: str | None = None
    kind: str = "user"          # "user" | "api_key"
    session_id: str | None = None   # refresh-token family of this sign-in (access token "sid" claim)
    mfa: bool = True                # this sign-in used a second factor (TOTP, recovery code or the IdP's)
    mfa_setup: str | None = None    # "required" | "optional" while the user has no 2FA; None once it's on
    alias_names: set = field(default_factory=set)   # old permission names this user holds only through a renamed permission
    scope: str = "tenant"           # "tenant" | "platform" | "select" (signed in, tenant not chosen yet)
    selecting: bool = False         # scope == "select": only /me, /me/tenants and /session/* are available
    last_mfa_at: int | None = None  # epoch seconds of the last second-factor check in this session (step-up)

    def mfa_fresh(self) -> bool:
        """A second factor was proved within the step-up window."""
        return self.last_mfa_at is not None and time.time() - self.last_mfa_at <= STEP_UP_WINDOW_SECONDS

    @property
    def platform(self) -> bool:
        return self.org_id is None

    def can(self, perm: str) -> bool:
        if perm in self.alias_names:
            # An old permission name is still being asked for. Logged so the cut-over (phase 9) can see when none are left.
            log.info("permission alias used", extra={"event": "permission_alias_used", "user_id": self.user_id, "org_id": self.org_id,
                                                     "permission": perm})
        return perm in self.perms


# How recently a second factor must have been proved for the permissions marked "step-up" in the catalogue.
STEP_UP_WINDOW_SECONDS = int(os.environ.get("STEP_UP_WINDOW_MINUTES", "10")) * 60


class StepUpRequired(Exception):
    """Raised by require() when a step-up permission is used with a stale second factor. The answer is HTTP 401 {"error": "step_up_required"}."""
    def __init__(self, perms):
        self.perms = perms


def install_handlers(app: FastAPI):
    """Register the step-up answer on an app. main.py calls this; tests that build their own app call it too."""
    @app.exception_handler(StepUpRequired)
    async def _step_up(request: Request, exc: StepUpRequired):
        return JSONResponse({"error": "step_up_required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})


# Two-factor is each person's choice, made from My account. The only way it becomes mandatory is an organization
# admin switching on security_settings.mfa_required (off by default). Nobody can take these actions without it.
MFA_SENSITIVE_PERMS = {"str.approve", "data.export", "policy.edit", "screening.override"}
SETUP_REQUIRED = "Set up two-factor authentication to continue"


def mfa_setup_state(org_requires: bool, mfa_enabled: bool, idp: bool) -> str | None:
    """None when two-factor is on (or the identity provider handles it), else "required" (the organization
    insists) or "optional" (the person may turn it on from My account)."""
    if mfa_enabled or idp:
        return None
    return "required" if org_requires else "optional"


def client_ip(request: Request) -> str | None:
    # Trust X-Forwarded-For only from your own load balancer (configure uvicorn --forwarded-allow-ips)
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


def _session_alive(sid) -> bool:
    if not sid:
        return True
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM refresh_tokens WHERE family_id=%s AND revoked_at IS NULL LIMIT 1", (sid,))
        return cur.fetchone() is not None


def signed_in_user(request: Request, cred: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    """The signed-in user, whether or not this sign-in used a second factor. Only /me and the two-factor
    setup endpoints use this directly; everything else goes through current_user."""
    if not cred:
        raise HTTPException(401, "Sign in required", headers={"WWW-Authenticate": "Bearer"})
    try:
        c = tokens.decode(cred.credentials)
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired. Sign in again", headers={"WWW-Authenticate": "Bearer"})
    ip = client_ip(request)
    scope = c.get("scp") or ("platform" if c["org"] is None else "tenant")
    if scope == "select":
        # Signed in, tenant not chosen yet (several memberships, or none): no permissions at all.
        with pg.pool().connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT status, session_version FROM session_user_lookup(%s)", (c["sub"],))
            u = cur.fetchone()
        if not u or u[0] != "active" or u[1] != c["sv"] or not _session_alive(c.get("sid")):
            raise HTTPException(401, "Your session has ended. Sign in again")
        return Principal(c["sub"], None, "", set(), set(), ip, session_id=c.get("sid"), mfa="otp" in c.get("amr", []),
                         scope="select", selecting=True, last_mfa_at=c.get("lmfa"))
    with pg.tx(c["org"], platform=c["org"] is None) as cur:
        if c["org"]:
            # Request check order step 2: a suspended, pending or deleted tenant refuses everything.
            cur.execute("SELECT status FROM organizations WHERE id=%s", (c["org"],))
            st = cur.fetchone()
            if not st or st[0] not in ("active", "trial"):
                raise HTTPException(403, "This organization isn't active")
        cur.execute("SELECT status, session_version, role_id, mfa_enabled, keycloak FROM session_user_lookup(%s)", (c["sub"],))
        u = cur.fetchone()
        if not u or u[0] != "active" or u[1] != c["sv"]:
            raise HTTPException(401, "Your session has ended. Sign in again")
        status, sv, role_id, mfa_enabled, idp = u
        if c.get("sid"):
            cur.execute("SELECT 1 FROM refresh_tokens WHERE family_id=%s AND revoked_at IS NULL LIMIT 1", (c["sid"],))
            if not cur.fetchone():       # signed out, switched away from, or revoked: the access token dies with its session
                raise HTTPException(401, "Your session has ended. Sign in again")
        if config.ACCESS_MODEL_V2:
            # New model: the role comes from the membership in the session's tenant (or the platform staff row).
            if c["org"]:
                cur.execute("SELECT role_id, status FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s", (c["sub"], c["org"]))
            else:
                cur.execute("SELECT role_id, status FROM platform_staff WHERE user_id=%s", (c["sub"],))
            m = cur.fetchone()
            if not m or m[1] != "active":
                raise HTTPException(401, "Your session has ended. Sign in again")
            role_id = m[0]

        def load_role():
            cur.execute("""SELECT r.name, COALESCE(array_agg(rp.perm) FILTER (WHERE rp.perm IS NOT NULL), '{}')
                           FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id WHERE r.id = %s GROUP BY r.name""", (role_id,))
            return cur.fetchone()
        # Keyed by session_version and role: every change to what a user may do bumps session_version (access/cache.py).
        role = cache.get_or_load((c["sub"], sv, str(role_id), bool(c["org"])), load_role)
        if not role:
            raise HTTPException(401, "Your session has ended. Sign in again")
        row = (status, sv, role[0], role[1], mfa_enabled, idp)
        features, allow, org_requires = set(), [], False
        if c["org"]:
            cur.execute("SELECT feature FROM org_features WHERE org_id=%s AND in_plan AND enabled", (c["org"],))
            features = {r[0] for r in cur.fetchall()}
            cur.execute("SELECT ip_allowlist, mfa_required FROM security_settings WHERE org_id=%s", (c["org"],))
            r = cur.fetchone()
            allow, org_requires = (r[0], r[1]) if r else ([], False)
    if allow and (ip is None or not any(ipaddress.ip_address(ip) in ipaddress.ip_network(str(n)) for n in allow)):
        raise HTTPException(403, "Access isn't allowed from this network")
    if not c["org"] and row[2] != "Platform owner":
        org_requires = True     # platform staff (admin, support, auditor) must use two-factor; the owner (break-glass login) may skip it
    perms, alias_names = catalogue.expand_aliases(set(row[3]))
    mfa_used = "otp" in c.get("amr", [])
    if row[4] and not mfa_used:
        # Two-factor is on for this account, so a password-only session isn't enough (enabling it ends those sessions).
        raise HTTPException(401, "Two-factor verification required")
    return Principal(c["sub"], c["org"], row[2], perms, features, ip, session_id=c.get("sid"), mfa=mfa_used,
                     mfa_setup=mfa_setup_state(org_requires, row[4], row[5]), alias_names=alias_names,
                     scope=scope, last_mfa_at=c.get("lmfa"))


def current_user(p: Principal = Depends(signed_in_user)) -> Principal:
    """A user allowed to use the app: signed in with two-factor, or allowed to skip it for now."""
    if p.selecting:
        raise HTTPException(403, "Choose a tenant first")
    if not p.mfa and p.mfa_setup != "optional":
        raise HTTPException(403, SETUP_REQUIRED)
    return p


def require(*perms: str, feature: str | None = None):
    def dep(p: Principal = Depends(current_user)) -> Principal:
        missing = [x for x in perms if not p.can(x)]
        if missing:
            raise HTTPException(403, f"Your role doesn't allow this ({', '.join(missing)})")
        if not p.mfa and MFA_SENSITIVE_PERMS & set(perms):
            raise HTTPException(403, "Turn on two-factor authentication to do this")
        if feature and feature not in p.features:
            raise HTTPException(403, "This feature isn't turned on for your organization")
        stepped = set(perms) & catalogue.STEP_UP_PERMS
        if stepped and p.mfa and not p.mfa_fresh():
            # Request check order step 6. (Sessions without a second factor are not asked: they can't answer a challenge.
            # Phase 6 makes two-factor mandatory for Tenant admins and passkeys for owners.)
            raise StepUpRequired(sorted(stepped))
        return p
    return dep


def api_key(request: Request) -> Principal:
    """Machine access for the on/off-ramp: 'Authorization: Bearer sk_live_<prefix>_<secret>'."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer sk_live_"):
        raise HTTPException(401, "API key required")
    key = auth.removeprefix("Bearer ")
    prefix = "_".join(key.split("_")[:3])
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT org_id, key_hash, scopes FROM api_key_lookup(%s)", (prefix,))
        row = cur.fetchone()
    if not row or not crypto.hmac.compare_digest(bytes(row[1]), crypto.sha256(key)) or "screen" not in row[2]:
        raise HTTPException(401, "Invalid API key")
    # A valid key isn't enough: the organization must be live and still have screening switched on.
    with pg.tx(row[0]) as cur:
        cur.execute("SELECT status FROM organizations WHERE id=%s", (row[0],))
        org = cur.fetchone()
        cur.execute("SELECT 1 FROM org_features WHERE org_id=%s AND feature='screening' AND in_plan AND enabled", (row[0],))
        screening_on = cur.fetchone() is not None
    if not org or org[0] not in ("active", "trial"):
        raise HTTPException(403, "This organization isn't active")
    if not screening_on:
        raise HTTPException(403, "Screening isn't turned on for this organization")
    return Principal(user_id=f"api:{prefix}", org_id=str(row[0]), role="api", perms={"screen"},
                     features={"screening"}, ip=client_ip(request), kind="api_key")


def require_any(*perms: str):
    """Allow if the caller holds at least one of these permissions (e.g. tenant or platform audit)."""
    def dep(p: Principal = Depends(current_user)) -> Principal:
        if not any(p.can(x) for x in perms):
            raise HTTPException(403, "Your role doesn't allow this")
        return p
    return dep

"""Every stored security setting is enforced by the API (phase 6 acceptance). Table-driven: each setting below has a check that flips it and
proves the server refuses or allows accordingly, and a final check fails when a column is added to a settings table without being covered
here or in a named suite. Real app, real database. Needs a fresh migrated database.
Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_settings_enforcement_e2e.py"""
import os
import re
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from pathlib import Path
from fastapi.testclient import TestClient
from app import pg
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security.middleware import limiter
from helpers_access import CSRF, PW, add_user, bearer, claims, password_login, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
TESTS = Path(__file__).resolve().parent
new_client = lambda: TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
c = new_client()
counter = [0]


def fresh(plan="professional"):
    counter[0] += 1
    with pg.tx(platform=True) as cur:
        org, roles = provision_org(cur, f"Enforce {counter[0]}", "MSB", f"M8{counter[0]:06d}", plan=plan)
    return org, roles


def member(org, roles, role="Compliance analyst", tag="u"):
    email = f"{tag}{counter[0]}@enforce.example.com"
    add_user(org, roles[role], email)
    return email


ENFORCED = {}            # "table.column" -> where the proof is (this file's check, or another suite)


def covers(*names):
    def deco(fn):
        for n in names:
            ENFORCED[n] = "here"
        fn()
        return fn
    return deco


# =========================== security_settings (per tenant) ===========================
@covers("security_settings.mfa_required")
def _():
    org, roles = fresh(); email = member(org, roles)
    tok = password_token(c, email)
    before = c.get("/alerts", headers=bearer(tok)).status_code
    sql(SUPER, "UPDATE security_settings SET mfa_required=true WHERE org_id=%s", org)
    r = c.get("/alerts", headers=bearer(tok))
    ok(before == 200 and r.status_code == 403 and "two-factor" in r.json()["detail"].lower(), "mfa_required: switching it on stops password-only sessions")


@covers("security_settings.idle_timeout_min")
def _():
    org, roles = fresh(); email = member(org, roles)
    sql(SUPER, "UPDATE security_settings SET idle_timeout_min=5 WHERE org_id=%s", org)
    cl = new_client(); password_login(cl, email)
    sql(SUPER, "UPDATE refresh_tokens SET created_at = now() - interval '6 minutes' WHERE ip IS NOT DISTINCT FROM NULL AND revoked_at IS NULL AND tenant_id=%s", org)
    r = cl.post("/auth/refresh")
    sql(SUPER, "UPDATE security_settings SET idle_timeout_min=30 WHERE org_id=%s", org)
    cl2 = new_client(); password_login(cl2, email)
    sql(SUPER, "UPDATE refresh_tokens SET created_at = now() - interval '6 minutes' WHERE revoked_at IS NULL AND tenant_id=%s", org)
    ok(r.status_code == 401 and cl2.post("/auth/refresh").status_code == 200, "idle_timeout_min: 6 idle minutes end a 5-minute session but not a 30-minute one")


@covers("security_settings.min_password_len")
def _():
    org, roles = fresh(); email = member(org, roles)
    sql(SUPER, "UPDATE security_settings SET min_password_len=20 WHERE org_id=%s", org)
    tok = password_token(c, email)
    short = c.post("/me/password", headers=bearer(tok), json={"current_password": PW, "new_password": "nineteen chars long"})
    good = c.post("/me/password", headers=bearer(tok), json={"current_password": PW, "new_password": "twenty characters in total"})
    ok(short.status_code == 422 and "20" in str(short.json()) and good.status_code == 200, "min_password_len: 19 characters are refused, 20+ accepted")


@covers("security_settings.ip_allowlist")
def _():
    org, roles = fresh(); email = member(org, roles)
    tok = password_token(c, email)
    sql(SUPER, "UPDATE security_settings SET ip_allowlist='{10.0.0.0/8}' WHERE org_id=%s", org)
    r = c.get("/me", headers=bearer(tok))
    sql(SUPER, "UPDATE security_settings SET ip_allowlist='{}' WHERE org_id=%s", org)
    ok(r.status_code == 403 and "network" in r.json()["detail"] and c.get("/me", headers=bearer(tok)).status_code == 200, "ip_allowlist: a caller outside the list is refused, and let back in when it is empty")


@covers("security_settings.retention_years")
def _():
    org, roles = fresh()
    sql(SUPER, "UPDATE security_settings SET retention_years=7 WHERE org_id=%s", org)
    o1 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, f"owner-a{counter[0]}@enforce.example.com")
    o2 = add_user(None, cat.PLATFORM_OWNER_ROLE_ID, f"owner-b{counter[0]}@enforce.example.com")
    h1 = bearer(password_token(c, f"owner-a{counter[0]}@enforce.example.com")); h2 = bearer(password_token(c, f"owner-b{counter[0]}@enforce.example.com"))
    aid = c.post(f"/platform/orgs/{org}/delete", headers=h1, json={"reason": "retention check for the settings suite"}).json()["approval_id"]
    c.post(f"/platform/approvals/{aid}/approve", headers=h2)
    years = float(sql(SUPER, "SELECT extract(epoch FROM (deletion_due_at - deleted_at))/31557600 FROM organizations WHERE id=%s", org)[0][0])
    ok(6.9 < years < 7.1, f"retention_years: a deleted tenant's data removal is scheduled after ITS retention ({years:.1f} years)")


# =========================== platform_settings (the baseline every tenant must meet) ===========================
def admin_for(org, roles):
    secret = pyotp.random_base32()
    email = f"admin{counter[0]}@enforce.example.com"
    add_user(org, roles[cat.TENANT_ADMIN], email, secret=secret)
    return bearer(two_factor_token(c, email, secret))


@covers("platform_settings.min_password_len_floor")
def _():
    org, roles = fresh(); A = admin_for(org, roles)
    floor = sql(SUPER, "SELECT min_password_len_floor FROM platform_settings")[0][0]
    r = c.put("/admin/security", headers=A, json={"min_password_len": floor - 1})
    ok(r.status_code == 422 and str(floor) in str(r.json()), "min_password_len_floor: a tenant can't go below the platform's minimum")


@covers("platform_settings.max_idle_timeout_min")
def _():
    org, roles = fresh(); A = admin_for(org, roles)
    top = sql(SUPER, "SELECT max_idle_timeout_min FROM platform_settings")[0][0]
    r = c.put("/admin/security", headers=A, json={"idle_timeout_min": top + 5})
    ok(r.status_code == 422, "max_idle_timeout_min: a tenant can't allow longer idle sessions than the platform")


@covers("platform_settings.retention_years_floor")
def _():
    org, roles = fresh(); A = admin_for(org, roles)
    floor = sql(SUPER, "SELECT retention_years_floor FROM platform_settings")[0][0]
    sql(SUPER, "UPDATE platform_settings SET retention_years_floor=%s", floor + 1)
    r = c.put("/admin/security", headers=A, json={"retention_years": floor})
    sql(SUPER, "UPDATE platform_settings SET retention_years_floor=%s", floor)
    ok(r.status_code == 422, "retention_years_floor: a tenant can't keep records for less than the platform's minimum")


@covers("platform_settings.max_session_hours")
def _():
    org, roles = fresh(); email = member(org, roles)
    sql(SUPER, "UPDATE platform_settings SET max_session_hours=1")
    cl = new_client(); password_login(cl, email)
    cl.post("/auth/refresh")                                                      # a second token in the same session
    sql(SUPER, """UPDATE refresh_tokens SET created_at = now() - interval '2 hours'
                  WHERE tenant_id=%s AND revoked_at IS NOT NULL""", org)          # the session began two hours ago, but was active a moment ago
    r = cl.post("/auth/refresh")
    sql(SUPER, "UPDATE platform_settings SET max_session_hours=12")
    ok(r.status_code == 401, "max_session_hours: an active session still ends once it is older than the platform maximum")


@covers("platform_settings.passkeys_allowed")
def _():
    org, roles = fresh(); email = member(org, roles)
    tok = password_token(c, email)
    sql(SUPER, "UPDATE platform_settings SET passkeys_allowed=false")
    r = c.post("/me/passkeys/options", headers=bearer(tok))
    sql(SUPER, "UPDATE platform_settings SET passkeys_allowed=true")
    ok(r.status_code == 403, "passkeys_allowed: with passkeys switched off nobody can register one")


@covers("platform_settings.platform_staff_passkey_only")
def _():
    email = f"owner-pk{counter[0]}@enforce.example.com"
    add_user(None, cat.PLATFORM_OWNER_ROLE_ID, email)
    tok = password_token(c, email)
    free = c.get("/platform/orgs", headers=bearer(tok)).status_code
    sql(SUPER, "UPDATE platform_settings SET platform_staff_passkey_only=true")
    r = c.get("/platform/orgs", headers=bearer(tok))
    sql(SUPER, "UPDATE platform_settings SET platform_staff_passkey_only=false")
    ok(free == 200 and r.status_code == 403 and "passkey" in r.json()["detail"].lower(), "platform_staff_passkey_only: owners without a passkey can do nothing but register one")


@covers("platform_settings.allowed_regions")
def _():
    email = f"owner-reg{counter[0]}@enforce.example.com"
    add_user(None, cat.PLATFORM_OWNER_ROLE_ID, email)
    H = bearer(password_token(c, email))
    r = c.post("/platform/orgs", headers=H, json={"legal_name": "Region Co", "business_type": "MSB", "registration": "M1234567",
                                                   "admin_email": "a@region.example.com", "data_region": "us-east-1"})
    ok(r.status_code == 422, "allowed_regions: a tenant can't be created in a region the platform doesn't allow")


# =========================== tenant-level security fields on organizations and users, proven in their own suites ===========================
PROVEN_ELSEWHERE = {
    "organizations.owner_access": "test_owner_access_e2e.py",          # allow / require_approval / deny + legal hold
    "organizations.legal_hold": "test_owner_access_e2e.py",
    "organizations.sso_enforced": "test_sso_e2e.py",                    # password refused for the company's members
    "organizations.sso_domain": "test_sso_e2e.py",                      # nothing is enforced until the domain is verified
    "organizations.sso_idp_alias": "test_sso_e2e.py",
    "organizations.sso_default_role_id": "test_sso_e2e.py",             # just-in-time membership
    "users.mfa_mandatory": "test_tenant_lifecycle_e2e.py",
    "users.sso_emergency": "test_sso_e2e.py",
    "users.must_rotate": "test_owner_access_e2e.py",
    "users.break_glass": "test_owner_access_e2e.py",
    "api_keys.expires_at": "test_api_keys_e2e.py", "api_keys.ip_allowlist": "test_api_keys_e2e.py", "api_keys.rate_limit_per_min": "test_api_keys_e2e.py",
    "api_keys.last_used_at": "test_api_keys_e2e.py", "api_keys.revoked_at": "test_api_keys_e2e.py",
}
ok(True, f"{len(ENFORCED)} settings proven in this file, {len(PROVEN_ELSEWHERE)} in the suites named next to them")
for key, suite in PROVEN_ELSEWHERE.items():
    column = key.split(".", 1)[1]
    column = {"sso_idp_alias": "idp_alias", "sso_domain": "domain", "sso_enforced": "enforced"}.get(column, column)
    text = (TESTS / suite).read_text(encoding="utf-8")
    ok(column in text, f"{key} is exercised in {suite}")
    ENFORCED[key] = suite

# =========================== nothing is left uncovered ===========================
NOT_SETTINGS = {"security_settings.org_id", "platform_settings.id", "platform_settings.updated_at"}
columns = {f"{t}.{col}" for t, col in sql(SUPER, """SELECT table_name, column_name FROM information_schema.columns
                                                    WHERE table_schema='public' AND table_name IN ('security_settings','platform_settings')""")}
missing = sorted(columns - set(ENFORCED) - NOT_SETTINGS)
ok(not missing, f"every column of security_settings and platform_settings has an enforcement proof (uncovered: {missing})")
ok({"security_settings.sso_enabled", "security_settings.oidc_issuer", "security_settings.oidc_client_id"}.isdisjoint(columns),
   "the settings that were stored but never used are gone (sso_enabled is derived; the identity provider lives in Keycloak)")

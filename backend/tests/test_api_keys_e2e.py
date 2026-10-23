"""API key hardening (G10): hashed and shown once, optional expiry, address allowlist, per-key rate limit, last use, rotation with a
24-hour overlap, and refusal when the tenant is suspended or screening is off. Real app, real database.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_api_keys_e2e.py"""
import os
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from app import pg
from app.main import app
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.security import rbac
from app.security.middleware import limiter
from app.security.rbac import api_key
from helpers_access import CSRF, add_user, bearer, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)
mini = FastAPI()
mini.get("/key-check")(lambda p=Depends(api_key): {"org": p.org_id})


def caller(ip):
    return TestClient(mini, base_url="https://testserver", client=(ip, 4000), raise_server_exceptions=False)


with pg.tx(platform=True) as cur:
    T, tr = provision_org(cur, "Keys Co", "MSB", "M2000001", plan="professional")
secret = pyotp.random_base32()
add_user(T, tr[cat.TENANT_ADMIN], "admin@keys.example.com", secret=secret)
add_user(T, tr["Compliance analyst"], "analyst@keys.example.com")
ADMIN = bearer(two_factor_token(c, "admin@keys.example.com", secret))
use = lambda raw, ip="203.0.113.5": caller(ip).get("/key-check", headers={"Authorization": "Bearer " + raw})
row = lambda prefix: sql(SUPER, "SELECT key_hash, expires_at, last_used_at, rate_limit_per_min, rotated_at, replaced_by, revoked_at FROM api_keys WHERE prefix=%s", prefix)[0]

# ---- create ----
ok(c.post("/admin/api-keys", json={}).status_code == 401, "no sign-in, no keys")
ok(c.post("/admin/api-keys", headers=bearer(password_token(c, "analyst@keys.example.com")), json={}).status_code == 403, "an analyst can't create keys")
r = c.post("/admin/api-keys", headers=ADMIN, json={"label": "ramp", "expires_in_days": 30, "ip_allowlist": ["203.0.113.0/24"], "rate_limit_per_min": 3})
ok(r.status_code == 200 and r.json()["api_key"].startswith("sk_live_"), "an admin creates a key with an expiry, an address allowlist and a rate limit")
RAW, PREFIX = r.json()["api_key"], r.json()["prefix"]
key_hash, expires, last_used, rl, *_ = row(PREFIX)
ok(bytes(key_hash) != RAW.encode() and len(bytes(key_hash)) == 32 and RAW.encode() not in bytes(key_hash), "only a hash of the key is stored")
listing = str(c.get("/admin/api-keys", headers=ADMIN).json())
ok(RAW not in listing and PREFIX in listing, "the list shows the prefix, never the key (it is shown once)")
days = float(sql(SUPER, "SELECT extract(epoch FROM (expires_at - now()))/86400 FROM api_keys WHERE prefix=%s", PREFIX)[0][0])
ok(29 < days <= 30 and rl == 3, f"expiry in 30 days ({days:.1f}) and 3 requests a minute are stored")
ok(c.post("/admin/api-keys", headers=ADMIN, json={"ip_allowlist": ["not-an-address"]}).status_code == 422, "a bad address range is refused")
ok(c.post("/admin/api-keys", headers=ADMIN, json={"expires_in_days": 0}).status_code == 422
   and c.post("/admin/api-keys", headers=ADMIN, json={"rate_limit_per_min": 100000}).status_code == 422, "an expiry of 0 days or an absurd rate limit is refused")

# ---- use ----
ok(use(RAW).status_code == 200, "the key works from an allowed address")
ok(use(RAW, "198.51.100.9").status_code == 403, "from any other address it is refused (allowlist)")
ok(use("sk_live_" + PREFIX[8:] + "_wrongsecret").status_code == 401, "a wrong secret is refused")
ok(row(PREFIX)[2] is not None, "the last use is recorded")
first_use = row(PREFIX)[2]
use(RAW)
ok(row(PREFIX)[2] == first_use, "and written at most once a minute")
rbac._key_windows.clear()
codes = [use(RAW).status_code for _ in range(5)]
ok(codes == [200, 200, 200, 429, 429], f"the per-key rate limit (3 a minute) answers 429 after that: {codes}")
ok(use(RAW).headers.get("retry-after") is not None, "with a Retry-After hint")
ok(use(RAW, "198.51.100.9").status_code == 403, "(refusals by address don't use up the limit)")
rbac._key_windows.clear()

# ---- expiry ----
sql(SUPER, "UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE prefix=%s", PREFIX)
r = use(RAW)
ok(r.status_code == 401 and "expired" in r.json()["detail"], "an expired key is refused with a clear message")
ok([k for k in c.get("/admin/api-keys", headers=ADMIN).json() if k["prefix"] == PREFIX][0]["active"] is False, "and is listed as inactive")
sql(SUPER, "UPDATE api_keys SET expires_at = now() + interval '30 days' WHERE prefix=%s", PREFIX)
ok(use(RAW).status_code == 200, "(it works again when the expiry is moved)")

# ---- rotation with a 24-hour overlap ----
r = c.post(f"/admin/api-keys/{PREFIX}/rotate", headers=ADMIN)
ok(r.status_code == 200 and r.json()["prefix"] != PREFIX, "rotating issues a new key")
NEW, NEW_PREFIX = r.json()["api_key"], r.json()["prefix"]
hours = float(sql(SUPER, "SELECT extract(epoch FROM (expires_at - now()))/3600 FROM api_keys WHERE prefix=%s", PREFIX)[0][0])
ok(23 < hours <= 24, f"the old key keeps working for 24 hours ({hours:.1f} h left)")
rbac._key_windows.clear()
ok(use(RAW).status_code == 200 and use(NEW).status_code == 200, "both keys work during the overlap")
_, _, _, _, rotated_at, replaced_by, _ = row(PREFIX)
ok(rotated_at is not None and replaced_by == NEW_PREFIX, "the old key records what replaced it")
ok(row(NEW_PREFIX)[3] == 3 and sql(SUPER, "SELECT ip_allowlist::text FROM api_keys WHERE prefix=%s", NEW_PREFIX)[0][0] == "{203.0.113.0/24}",
   "the new key keeps the old key's limits and allowlist")
ok("api_key_rotated" in [a[0] for a in sql(SUPER, "SELECT action FROM audit_events WHERE org_id=%s", T)], "rotation is audited")
sql(SUPER, "UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE prefix=%s", PREFIX)
rbac._key_windows.clear()
ok(use(RAW).status_code == 401 and use(NEW).status_code == 200, "after the overlap the old key is dead and the new one works")
ok(c.post(f"/admin/api-keys/{PREFIX}/rotate", headers=ADMIN).status_code == 404, "an expired key can't be rotated")
ok(c.post("/admin/api-keys/sk_live_nothing/rotate", headers=ADMIN).status_code == 404, "an unknown prefix is a 404")

# ---- revoke, tenant and plan state ----
ok(c.delete(f"/admin/api-keys/{NEW_PREFIX}", headers=ADMIN).status_code == 200 and use(NEW).status_code == 401, "a revoked key stops at once")
r = c.post("/admin/api-keys", headers=ADMIN, json={"label": "second"})
K2, P2 = r.json()["api_key"], r.json()["prefix"]
ok(row(P2)[1] is None and row(P2)[3] == 600, "defaults: no expiry, 600 requests a minute, any address")
rbac._key_windows.clear()
ok(use(K2, "198.51.100.77").status_code == 200, "with no allowlist any address works")
sql(SUPER, "UPDATE organizations SET status='suspended' WHERE id=%s", T)
r = use(K2)
ok(r.status_code == 403 and "isn't active" in r.json()["detail"], "a suspended tenant's keys are refused")
sql(SUPER, "UPDATE organizations SET status='active' WHERE id=%s", T)
sql(SUPER, "UPDATE org_features SET enabled=false WHERE org_id=%s AND feature='screening'", T)
r = use(K2)
ok(r.status_code == 403 and "Screening" in r.json()["detail"], "so are keys when screening is switched off")
sql(SUPER, "UPDATE org_features SET enabled=true WHERE org_id=%s AND feature='screening'", T)
ok(use(K2).status_code == 200, "and they work again when it is back on")

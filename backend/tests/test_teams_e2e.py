"""Teams and queues (I11, TEAMS flag), effective permissions and separation-of-duties warnings (phase 8). Real app, real database.
Needs a fresh migrated database. Run: PYTHONPATH=. AUTH_MODE=local ENV=dev python tests/test_teams_e2e.py"""
import os
import pyotp
os.environ.setdefault("AUTH_MODE", "local")
SUPER = os.environ.get("SUPERUSER_DATABASE_URL", "postgresql://postgres:super@localhost/sentrail")
from fastapi.testclient import TestClient
from app import pg
from app.access import catalogue as cat
from app.admin_api import provision_org
from app.main import app
from app.security.middleware import limiter
from helpers_access import CSRF, add_user, bearer, password_token, sql, two_factor_token

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
limiter.enabled = False
c = TestClient(app, headers=CSRF, base_url="https://testserver", raise_server_exceptions=False)

with pg.tx(platform=True) as cur:
    T, tr = provision_org(cur, "Teams Co", "MSB", "M8100001", plan="professional")
    B, br = provision_org(cur, "Teams Other", "MSB", "M8100002", plan="professional")
sec = pyotp.random_base32()
secb = pyotp.random_base32()
admin = add_user(T, tr[cat.TENANT_ADMIN], "admin@teams.example.com", secret=sec)
ana1 = add_user(T, tr["Compliance analyst"], "ana1@teams.example.com")
ana2 = add_user(T, tr["Compliance analyst"], "ana2@teams.example.com")
aud = add_user(T, tr["Auditor (read-only)"], "aud@teams.example.com")
add_user(B, br[cat.TENANT_ADMIN], "admin@teams-other.example.com", secret=secb)
b_ana = add_user(B, br["Compliance analyst"], "ana@teams-other.example.com")
ADMIN = bearer(two_factor_token(c, "admin@teams.example.com", sec))
ADMIN_B = bearer(two_factor_token(c, "admin@teams-other.example.com", secb))
A1, A2, AUD = (bearer(password_token(c, f"{x}@teams.example.com")) for x in ("ana1", "ana2", "aud"))
with pg.tx(T) as cur:
    for i in (1, 2, 3):
        cur.execute("INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel) VALUES (%s,%s,%s,80,'high','[]','crypto')", (f"TM-{i}", T, f"C-{i}"))
    cur.execute("INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, restricted) VALUES ('TM-R', %s, 'C-R', 90, 'high', '[]', 'crypto', true)", (T,))

# =============================== off by default ===============================
print("# flag off")
os.environ["TEAMS"] = "false"
ok(c.get("/admin/teams", headers=ADMIN).status_code == 404 and c.post("/admin/teams", headers=ADMIN, json={"name": "Ops"}).status_code == 404, "with TEAMS off every team route answers 404")
ok(c.get("/me/teams", headers=A1).status_code == 404 and c.get("/alerts", headers=A1, params={"team": "00000000-0000-0000-0000-000000000001"}).status_code == 404, "also the queue filter and my queues")
ok(c.get("/alerts", headers=A1).status_code == 200 and "team_id" in c.get("/alerts", headers=A1).json()[0], "alerts still list normally (team_id is simply empty)")

# =============================== teams ===============================
print("# teams")
os.environ["TEAMS"] = "true"
ok(c.post("/admin/teams", headers=A1, json={"name": "Ops"}).status_code == 403, "an analyst can't create a team")
ok(c.post("/admin/teams", headers=AUD, json={"name": "Ops"}).status_code == 403, "nor an auditor")
ok(c.post("/admin/teams", json={"name": "Ops"}).status_code == 401, "nor anyone not signed in")
r = c.post("/admin/teams", headers=ADMIN, json={"name": "Night shift"})
TEAM = r.json()["id"]
ok(r.status_code == 200, "a Tenant admin creates a team")
ok(c.post("/admin/teams", headers=ADMIN, json={"name": "Night shift"}).status_code == 409, "a duplicate name is refused")
ok(c.post("/admin/teams", headers=ADMIN, json={"name": "x"}).status_code == 422, "a one-letter name is refused")
T2 = c.post("/admin/teams", headers=ADMIN, json={"name": "Day shift"}).json()["id"]
ok(c.put(f"/admin/teams/{T2}", headers=ADMIN, json={"name": "Night shift"}).status_code == 409, "renaming onto an existing name is refused")
ok(c.put(f"/admin/teams/{T2}", headers=ADMIN, json={"name": "Daytime"}).status_code == 200, "rename")
ok(c.put(f"/admin/teams/{TEAM}/members", headers=ADMIN, json={"user_ids": [ana1, b_ana]}).status_code == 422, "someone from another organization can't be a member")
ok(c.put(f"/admin/teams/{TEAM}/members", headers=ADMIN, json={"user_ids": [ana1]}).status_code == 200, "members are set")
sql(SUPER, "UPDATE tenant_memberships SET status='suspended' WHERE user_id=%s AND tenant_id=%s", aud, T)
ok(c.put(f"/admin/teams/{TEAM}/members", headers=ADMIN, json={"user_ids": [ana1, aud]}).status_code == 422, "a suspended member can't be added")
sql(SUPER, "UPDATE tenant_memberships SET status='active' WHERE user_id=%s AND tenant_id=%s", aud, T)
detail = c.get(f"/admin/teams/{TEAM}", headers=ADMIN).json()
ok([m["user_id"] for m in detail["members"]] == [ana1] and "ana1@teams.example.com" not in str(detail), "the team shows its members with masked emails")
ok(c.get(f"/admin/teams/{TEAM}", headers=ADMIN_B).status_code == 404 and c.get("/admin/teams", headers=ADMIN_B).json() == [], "another tenant sees none of it")
ok(c.put(f"/admin/teams/{TEAM}", headers=ADMIN_B, json={"name": "hijack"}).status_code == 404 and c.delete(f"/admin/teams/{TEAM}", headers=ADMIN_B).status_code == 404, "and can't change or delete it")

# =============================== queues ===============================
print("# queues")
ok(c.put("/cases/TM-1/team", headers=AUD, json={"team_id": TEAM}).status_code == 403, "an auditor can't place a case in a queue")
ok(c.put("/cases/TM-1/team", headers=A1, json={"team_id": TEAM}).status_code == 200, "an analyst places an alert in a team's queue")
ok(c.put("/cases/TM-2/team", headers=A1, json={"team_id": TEAM}).status_code == 200, "and another")
ok(c.put("/cases/NOPE/team", headers=A1, json={"team_id": TEAM}).status_code == 404, "a case that doesn't exist is 404")
ok(c.put("/cases/TM-3/team", headers=A1, json={"team_id": "00000000-0000-0000-0000-000000000009"}).status_code == 404, "a team that doesn't exist is 404")
ok(c.put("/cases/TM-1/team", headers=bearer(password_token(c, "ana@teams-other.example.com")), json={"team_id": TEAM}).status_code == 404, "another tenant's analyst can't touch this tenant's case")
q = c.get("/alerts", headers=A1, params={"team": TEAM})
ok(q.status_code == 200 and sorted(a["id"] for a in q.json()) == ["TM-1", "TM-2"], "a member sees the team's queue")
ok(c.get("/alerts", headers=A2, params={"team": TEAM}).status_code == 403, "someone not on the team can't open its queue")
ok(c.get("/alerts", headers=ADMIN, params={"team": TEAM}).status_code == 200, "a team admin can")
ok(c.get("/alerts", headers=AUD, params={"team": TEAM}).status_code == 403, "an auditor who isn't a member can't")
mine = c.get("/me/teams", headers=A1).json()["teams"]
ok(len(mine) == 1 and mine[0]["name"] == "Night shift" and mine[0]["open_alerts"] == 2 and c.get("/me/teams", headers=A2).json()["teams"] == [], "'my queues' lists only my teams, with counts")
ok(len(c.get("/alerts", headers=A2).json()) == 4 - 1, "(someone outside the team still sees the same alerts in the ordinary list: a queue narrows, it doesn't gate)")

print("# a queue never widens what a person may see")
c.put("/admin/teams/%s/members" % TEAM, headers=ADMIN, json={"user_ids": [ana1, ana2]})
c.put("/cases/TM-R/team", headers=ADMIN, json={"team_id": TEAM})
ids = [a["id"] for a in c.get("/alerts", headers=A1, params={"team": TEAM}).json()]
ok("TM-R" not in ids, "a restricted case in a queue is still hidden from members without access to it")
ok("TM-R" in [a["id"] for a in c.get("/alerts", headers=ADMIN, params={"team": TEAM}).json()], "(and visible to the admin, who holds restricted access)")
ok(sql(SUPER, "SELECT count(*) FROM audit_events WHERE org_id=%s AND action='case_team_set'", T)[0][0] >= 3, "each placement is recorded in the audit log")
ok(c.put("/cases/TM-1/team", headers=A1, json={"team_id": None}).status_code == 200 and "TM-1" not in [a["id"] for a in c.get("/alerts", headers=A1, params={"team": TEAM}).json()], "an alert can be taken out of a queue")
ok(c.delete(f"/admin/teams/{TEAM}", headers=ADMIN).status_code == 200 and sql(SUPER, "SELECT count(*) FROM alerts WHERE team_id IS NOT NULL")[0][0] == 0, "deleting a team empties its queue; the alerts stay")
ok(sql(SUPER, "SELECT count(*) FROM alerts WHERE org_id=%s", T)[0][0] == 4, "(no alert was deleted)")

# =============================== effective permissions ===============================
print("# effective permissions")
r = c.get(f"/admin/users/{ana1}/effective-permissions", headers=ADMIN)
body = r.json()
keys = {p["key"] for p in body["permissions"]}
me_perms = set(c.get("/me", headers=A1).json()["permissions"])
ok(r.status_code == 200 and body["role"] == "Compliance analyst" and keys == me_perms, "a person's effective permissions equal what they hold")
ok(all(p["description"] and p["group"] for p in body["permissions"]) and {"alerts", "trace"} <= set(body["features"]), "each carries its wording and group; the plan's features are listed")
ok(c.get(f"/admin/users/{ana1}/effective-permissions", headers=A1).status_code == 403, "an analyst can't read them")
ok(c.get(f"/admin/users/{b_ana}/effective-permissions", headers=ADMIN).status_code == 404, "a person of another tenant is 404")
officer = c.get(f"/admin/roles/{tr['Compliance officer']}/effective", headers=ADMIN).json()
ok({p["key"]: p["step_up"] for p in officer["permissions"]}["str.approve"] is True and officer["role"] == "Compliance officer", "a role's effective list says which permissions ask for a fresh second factor")
ok(c.get(f"/admin/roles/{br['Compliance officer']}/effective", headers=ADMIN).status_code == 404, "another tenant's role is 404")
locked = c.get(f"/admin/roles/{tr[cat.TENANT_ADMIN]}/effective", headers=ADMIN).json()
ok(locked["locked"] and len(locked["permissions"]) == len(cat.TENANT_PERMS) and locked["warnings"] == [], "the locked Tenant admin role has every tenant permission and no warnings")

# =============================== separation of duties ===============================
print("# separation of duties")
r = c.post("/admin/roles", headers=ADMIN, json={"name": "Drafter-approver", "perms": ["cases.view", "str.draft", "str.approve"]})
ok(r.status_code == 200 and any("write a report and approve it" in w for w in r.json()["warnings"]), "creating a role that drafts and approves STRs warns (and still creates it)")
RID = r.json()["id"]
r = c.put(f"/admin/roles/{RID}", headers=ADMIN, json={"name": "Drafter-approver", "perms": ["cases.view", "str.draft"]})
ok(r.status_code == 200 and r.json()["warnings"] == [], "removing the conflict clears the warning")
r = c.post("/admin/roles", headers=ADMIN, json={"name": "Policy-releaser", "perms": ["policy.edit", "screening.override"]})
ok(any("loosen the rules" in w for w in r.json()["warnings"]), "policy edit with screening override warns")
r = c.post("/admin/roles", headers=ADMIN, json={"name": "Self-granter", "perms": ["roles.manage", "users.manage"]})
ok(any("any access" in w for w in r.json()["warnings"]), "role management with user management warns")
r = c.post("/admin/roles", headers=ADMIN, json={"name": "Plain", "perms": ["cases.view", "audit.view"]})
ok(r.json()["warnings"] == [], "a harmless role has none")
listing = c.get("/admin/roles", headers=ADMIN).json()
ok(len(listing["warnings"]) >= 2 and not any(cat.TENANT_ADMIN in w for w in listing["warnings"]), "the list repeats them for every role that has one, never for the locked Tenant admin")
ok(all(len(x) == 3 and x[0] in {p.key for p in cat.PERMISSIONS} and x[1] in {p.key for p in cat.PERMISSIONS} for x in cat.SOD_CONFLICTS), "every conflict pair names real permissions")

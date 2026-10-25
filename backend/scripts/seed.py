"""Seed the master (platform) login and, optionally, demo tenants.

  python -m scripts.seed                 # master login only (production-safe)
  python -m scripts.seed --demo          # plus two demo tenants with a user for every role and sample alerts
  python -m scripts.seed --demo --replace   # also replace demo people that already exist (new password, same roles); demo only

Master login: a local break-glass platform admin (password; two-factor is the person's choice). It keeps working if Keycloak
is down. Credentials come from SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD (or a prompt). Running the
seed again never overwrites existing accounts.
Demo users get SEED_DEMO_PASSWORD. In Keycloak mode they're created in Keycloak with email
verified (Keycloak still asks for TOTP itself); in local mode they have no two-factor until they turn it on.
Never run --demo against production.
"""
import getpass
import json
import os
import sys

from app.access import members
from app import config, pg
from app.admin_api import provision_org, AUTH_MODE, kc, FEATURES
from app.security import crypto, passwords, audit
from app.access.catalogue import TENANT_ADMIN

PLATFORM_ROLES = {"Platform owner": "00000000-0000-0000-0000-000000000002",
                  "Platform support": "00000000-0000-0000-0000-000000000003",
                  "Platform auditor": "00000000-0000-0000-0000-000000000004"}
PLATFORM_ROLE = PLATFORM_ROLES["Platform owner"]     # the master login is a platform owner


def exists(email) -> bool:
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM auth_lookup(%s)", (crypto.blind_index(email),))
        return cur.fetchone() is not None


def remove_person(email):
    """Demo only (--replace): delete the person (their memberships go with them; the audit trail keeps their id) so they can be created again."""
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM auth_lookup(%s)", (crypto.blind_index(email),))
        row = cur.fetchone()
    if not row:
        return
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT idp_subject FROM users WHERE id=%s", (row[0],))
        subj = (cur.fetchone() or [None])[0]
        if AUTH_MODE == "keycloak" and subj:
            try:
                kc().delete_user(subj)
            except Exception as e:                    # noqa: BLE001 - a person already gone from Keycloak is fine
                print(f"  (Keycloak: {type(e).__name__} for {email}, continuing)")
        cur.execute("DELETE FROM users WHERE id=%s", (row[0],))
    print(f"  replaced {email}")


def seed_master():
    email = os.environ.get("SEED_ADMIN_EMAIL") or input("Master admin email: ").strip()
    if exists(email):
        print(f"Master login {crypto.mask_email(email)} already exists, leaving it unchanged")
        return
    pw = os.environ.get("SEED_ADMIN_PASSWORD") or getpass.getpass("Master admin password (14+ characters): ")
    problems = passwords.check_policy(pw, 14, [email.split("@")[0]])
    if problems:
        sys.exit("Password rejected: " + "; ".join(problems))
    with pg.tx(platform=True) as cur:
        members.create_person(cur, None, PLATFORM_ROLE, email_enc=crypto.encrypt(crypto.normalize_email(email), None, "email"),
                              email_bidx=crypto.blind_index(email), name_enc=crypto.encrypt("Platform owner", None, "name"),
                              extra={"password_hash": passwords.hash_password(pw), "mfa_enabled": False, "auth_method": "local"})
        audit.write(cur, None, None, "operator", "master_login_seeded", crypto.mask_email(email), {})
    print("\nMaster login created:", crypto.mask_email(email))
    print("Two-factor is off; turn it on from My account after signing in.")


DEMO_PLATFORM_STAFF = [("dev.k@sentrail.qatech.world", "Dev K.", "Platform owner"),
                       ("priya.n@sentrail.qatech.world", "Priya N.", "Platform support"),
                       ("omar.f@sentrail.qatech.world", "Omar F.", "Platform auditor")]

DEMO = [
    {"name": "Northwind Remit Inc.", "type": "MSB: remittance, FX", "reg": "M23456789", "env": "production", "plan": "enterprise",
     "color": "#0F6E56", "sso_domain": None, "idp_alias": None,
     "users": [("leah.chen@sentrail.qatech.world", "Leah Chen", TENANT_ADMIN),
               ("ansuman.p@sentrail.qatech.world", "Ansuman P.", "Compliance officer"),
               ("ravi.k@sentrail.qatech.world", "Ravi K.", "Compliance analyst"),
               ("marta.g@sentrail.qatech.world", "Marta G.", "Auditor (read-only)")]},
    {"name": "Maple Ridge Digital Assets", "type": "MSB: virtual currency dealer", "reg": "M24567810", "env": "sandbox", "plan": "professional",
     "color": "#993C1D", "sso_domain": None, "idp_alias": None,
     "users": [("amir.h@sentrail.qatech.world", "Amir H.", TENANT_ADMIN),
               ("chloe.b@sentrail.qatech.world", "Chloé B.", "Compliance officer")]},
]
ALERTS = [("A-1042", "C-2291", 87, "high", "12 new senders in 5 days, then funds sent to a crypto wallet", "bank,crypto"),
          ("A-1039", "C-1877", 81, "high", "4 deposits just below 10,000 in 6 days", "bank"),
          ("A-1033", "C-0954", 64, "medium", "71% of card spend at gift card and gambling merchants", "card")]


def create_demo_user(org, role_id, email, name, role, demo_pw):
    sub = None
    if AUTH_MODE == "keycloak":
        # demo: no real company IdP behind the domain, so everyone signs in with a Keycloak password + TOTP
        sub = kc().create_user(email, str(org) if org else "platform", email_verified=True, required_actions=["CONFIGURE_TOTP"])
        kc().set_password(sub, demo_pw)
    with pg.tx(org, platform=org is None) as cur:
        members.create_person(cur, org, role_id, email_enc=crypto.encrypt(email, org, "email"), email_bidx=crypto.blind_index(email),
                              name_enc=crypto.encrypt(name, org, "name"),
                              extra={"password_hash": None if AUTH_MODE == "keycloak" else passwords.hash_password(demo_pw), "mfa_enabled": False,
                                     "idp_subject": sub, "auth_method": "keycloak" if AUTH_MODE == "keycloak" else "local"})
    print(f"  {role:<22} {email}")


def seed_demo():
    demo_pw = os.environ.get("SEED_DEMO_PASSWORD") or getpass.getpass("Password for all demo users (14+ characters): ")
    # Demo only: nobody is forced through two-factor at first sign-in; everyone can turn it on later from My account.
    # (A real environment keeps the platform setting require_two_factor_admins on: Tenant admins and platform staff must use it.)
    with pg.tx(platform=True) as cur:
        cur.execute("UPDATE platform_settings SET require_two_factor_admins=false")
    print("\nPlatform team")
    for email, name, role in DEMO_PLATFORM_STAFF:
        if exists(email) and "--replace" in sys.argv:
            remove_person(email)
        if exists(email):
            print(f"  {email} already exists"); continue
        create_demo_user(None, PLATFORM_ROLES[role], email, name, role, demo_pw)
    for t in DEMO:
        if "--replace" in sys.argv:
            for email, _, _ in t["users"]:
                remove_person(email)
        elif exists(t["users"][0][0]):
            print(f"{t['name']} already seeded, skipping"); continue
        with pg.tx(platform=True) as cur:
            cur.execute("SELECT id FROM organizations WHERE registration=%s", (t["reg"],))
            found = cur.fetchone()
            if found:      # --replace on a database that already has the demo organization: keep it, give it its people again
                org = found[0]
                cur.execute("SELECT name, id FROM roles WHERE org_id=%s", (org,))
                roles = dict(cur.fetchall())
                print(f"{t['name']} already exists, adding its people again")
            else:
                org, roles = provision_org(cur, t["name"], t["type"], t["reg"], plan=t["plan"], environment=t["env"], brand_color=t["color"])
            if t["sso_domain"]:   # demo only: real tenants prove the domain with a DNS TXT record (/admin/sso/verify)
                cur.execute("UPDATE organizations SET sso_domain=%s, sso_idp_alias=%s, sso_enforced=true WHERE id=%s",
                            (t["sso_domain"], t["idp_alias"], org))
            audit.write(cur, org, None, "operator", "demo_tenant_seeded", t["name"], {})
        print(f"\n{t['name']} ({t['env']})  org_id={org}")
        for email, name, role in t["users"]:
            create_demo_user(org, roles[role], email, name, role, demo_pw)
        if t["env"] == "production":
            with pg.tx(org) as cur:
                for aid, cid, score, band, reason, ch in ALERTS:
                    cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel)
                                   VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                                (aid, org, cid, score, band, json.dumps([{"source": "rule", "text": reason}]), ch))
    print("Demo users sign in with the demo password. Two-factor is optional: each person turns it on from My account.")


if __name__ == "__main__":
    seed_master()
    if "--demo" in sys.argv:
        if config.ENV == "production":          # a missing ENV means production, same as the API
            sys.exit("Refusing to seed demo tenants in production")
        seed_demo()

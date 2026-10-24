"""Bootstrap the first platform admin (run once, on the server, by an operator).
Usage: python -m scripts.create_platform_admin admin@yourcompany.com "Full Name"
Two-factor starts off; the person turns it on from My account.
"""
import getpass
import sys
import app.config  # noqa: F401  (loads .env)
from app.access import members
from app import pg
from app.security import crypto, passwords, audit

email, name = sys.argv[1], sys.argv[2]
pw = getpass.getpass("Password (14+ characters): ")
problems = passwords.check_policy(pw, 14, [name, email.split("@")[0]])
if problems:
    sys.exit("; ".join(problems))
with pg.tx(platform=True) as cur:
    members.create_person(cur, None, '00000000-0000-0000-0000-000000000002', email_enc=crypto.encrypt(crypto.normalize_email(email), None, "email"),
                          email_bidx=crypto.blind_index(email), name_enc=crypto.encrypt(name, None, "name"),
                          extra={"password_hash": passwords.hash_password(pw), "mfa_enabled": False})
    audit.write(cur, None, None, "operator", "platform_admin_created", crypto.mask_email(email), {})
print("Created. Two-factor is off: turn it on from My account after signing in.")

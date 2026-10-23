"""Bootstrap the first platform admin (run once, on the server, by an operator).
Usage: python -m scripts.create_platform_admin admin@yourcompany.com "Full Name"
Two-factor starts off; the person turns it on from My account.
"""
import getpass
import sys
import app.config  # noqa: F401  (loads .env)
from app import pg
from app.security import crypto, passwords, audit

email, name = sys.argv[1], sys.argv[2]
pw = getpass.getpass("Password (14+ characters): ")
problems = passwords.check_policy(pw, 14, [name, email.split("@")[0]])
if problems:
    sys.exit("; ".join(problems))
with pg.tx(platform=True) as cur:
    cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, mfa_enabled, status)
                   VALUES (NULL, '00000000-0000-0000-0000-000000000002', %s, %s, %s, %s, false, 'active')""",
                (crypto.encrypt(crypto.normalize_email(email), None, "email"), crypto.blind_index(email),
                 crypto.encrypt(name, None, "name"), passwords.hash_password(pw)))
    audit.write(cur, None, None, "operator", "platform_admin_created", crypto.mask_email(email), {})
print("Created. Two-factor is off: turn it on from My account after signing in.")

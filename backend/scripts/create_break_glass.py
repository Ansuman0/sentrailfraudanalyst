"""Create the sealed break-glass Platform owner (run once, on the server, by an operator). There is exactly one.
Usage: BREAK_GLASS_PASSWORD=... python -m scripts.create_break_glass breakglass@yourcompany.com
(or without the variable: you are prompted). Keep the password sealed (printed, in a safe) and use it only when no owner can sign in:
every use alerts all other owners and forces the password to be changed straight away."""
import getpass
import os
import sys
import app.config  # noqa: F401  (loads .env)
from app import pg
from app.access import catalogue as cat
from app.security import audit, crypto, passwords

email = sys.argv[1]
pw = os.environ.get("BREAK_GLASS_PASSWORD") or getpass.getpass("Break-glass password (20+ characters): ")
problems = passwords.check_policy(pw, 20, [email.split("@")[0]])
if problems:
    sys.exit("; ".join(problems))
with pg.tx(platform=True) as cur:
    cur.execute("SELECT 1 FROM users WHERE break_glass")
    if cur.fetchone():
        sys.exit("A break-glass account already exists. Rotate its password instead of creating another")
    cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, password_hash, mfa_enabled, status, break_glass)
                   VALUES (NULL, %s, %s, %s, %s, %s, false, 'active', true)""",
                (cat.PLATFORM_OWNER_ROLE_ID, crypto.encrypt(crypto.normalize_email(email), None, "email"), crypto.blind_index(email),
                 crypto.encrypt("Break-glass owner", None, "name"), passwords.hash_password(pw)))
    audit.write(cur, None, None, "operator", "break_glass_account_created", crypto.mask_email(email), {})
print("Created. Seal the password. Using it alerts every owner and forces a password change.")

"""Move identity data (email, name, phone, authenticator secret) from per-organization encryption to per-user encryption.

Access model v2 lets one person belong to several tenants, so who they are can no longer be bound to one organization.
The API reads both forms, so running this is not urgent, but run it before the cut-over. Idempotent; safe to re-run.

  python -m scripts.reencrypt_identity           # to per-user encryption
  python -m scripts.reencrypt_identity --down    # back to per-organization encryption (run before reverting migration 009)
"""
import sys
from app import pg
from app.security import crypto, audit

COLUMNS = [("email_enc", "email"), ("name_enc", "name"), ("phone_enc", "phone"), ("totp_secret_enc", "totp")]
down = "--down" in sys.argv

total = 0
with pg.tx(platform=True) as cur:
    cur.execute("SELECT id, org_id, email_enc, name_enc, phone_enc, totp_secret_enc FROM users")
    rows = cur.fetchall()
    for uid, org, *values in rows:
        sets, params = [], []
        for (col, ctx), val in zip(COLUMNS, values):
            new = crypto.reencrypt_identity(val, org, ctx, down=down)
            if new is not None:
                sets.append(f"{col}=%s"); params.append(new)
        if sets:
            cur.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=%s", (*params, uid))
            total += len(sets)
    audit.write(cur, None, None, "system", "identity_reencrypted", "per-organization" if down else "per-user", {"values": total})
print(f"Re-encrypted {total} values ({'to per-organization' if down else 'to per-user'} encryption)")

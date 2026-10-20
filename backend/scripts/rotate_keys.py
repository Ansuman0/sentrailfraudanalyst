"""Re-encrypt personal data under the current key, in small batches.
1. Generate a new key and put it FIRST in SENTRAIL_DATA_KEYS (keep the old ones after it).
2. Restart the API (new writes use the new key, old values still decrypt).
3. Run this script. When it reports 0 remaining, remove the old key.
"""
from app import pg
from app.security import crypto, audit

COLUMNS = {"users": [("email_enc", "email"), ("name_enc", "name"), ("phone_enc", "phone"), ("totp_secret_enc", "totp")],
           "str_drafts": [("ai_draft_enc", "str"), ("final_enc", "str")]}

with pg.tx(platform=True) as cur:
    cur.execute("SELECT id FROM organizations")
    orgs = [r[0] for r in cur.fetchall()] + [None]

total = 0
for org in orgs:
    with pg.tx(org, platform=org is None) as cur:
        for table, cols in COLUMNS.items():
            if org is None and table != "users":
                continue
            key = "id" if table == "users" else "alert_id"
            for col, ctx in cols:
                cur.execute(f"SELECT {key}, {col} FROM {table} WHERE {col} IS NOT NULL AND org_id IS NOT DISTINCT FROM %s", (org,))
                for rid, val in cur.fetchall():
                    if crypto.needs_rotation(val):
                        cur.execute(f"UPDATE {table} SET {col}=%s WHERE {key}=%s",
                                    (crypto.encrypt(crypto.decrypt(val, org, ctx), org, ctx), rid))
                        total += 1
        audit.write(cur, org, None, "system", "data_key_rotated", crypto.ring().current, {})
print(f"Re-encrypted {total} values under key {crypto.ring().current}")

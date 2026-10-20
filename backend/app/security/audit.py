"""Tamper-evident audit log.

Each event stores hash = SHA-256(prev_hash || canonical JSON of the event).
The table is append-only (DB trigger + revoked UPDATE/DELETE). verify_chain()
recomputes every hash; any edit, deletion or reordering breaks the chain.
Serialize writers per org with an advisory lock so two events can't share a prev_hash.
"""
import hashlib
import json
import logging
from datetime import datetime

GENESIS = b"\x00" * 32


def canonical(org_id, at: datetime, actor_id, actor_role, action, target, detail, ip) -> bytes:
    return json.dumps({"org": str(org_id) if org_id else None, "at": at.isoformat(), "actor": str(actor_id) if actor_id else None,
                       "role": actor_role, "action": action, "target": target, "detail": detail, "ip": ip},
                      sort_keys=True, separators=(",", ":"), default=str).encode()


def chain_hash(prev: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(prev + payload).digest()

log = logging.getLogger("sentrail.audit")


def write(cur, org_id, actor_id, actor_role, action, target=None, detail=None, ip=None):
    detail = detail or {}
    lock_key = int.from_bytes(hashlib.sha256(str(org_id).encode()).digest()[:8], "big", signed=True)
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (lock_key,))
    cur.execute("SELECT hash FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq DESC LIMIT 1", (org_id,))
    row = cur.fetchone()
    prev = bytes(row[0]) if row else GENESIS
    cur.execute("SELECT now()")
    at = cur.fetchone()[0]
    h = chain_hash(prev, canonical(org_id, at, actor_id, actor_role, action, target, detail, ip))
    cur.execute("""INSERT INTO audit_events (org_id, at, actor_id, actor_role, action, target, detail, ip, prev_hash, hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (org_id, at, actor_id, actor_role, action, target, json.dumps(detail, default=str), ip, prev, h))
    # Operational copy of the business event (login, login_failed, mfa_failed, ...): ids only, no detail or ip.
    log.info("audit event", extra={"event": "audit_" + action, "org_id": org_id, "user_id": actor_id})


def verify_rows(rows) -> dict:
    """rows: ordered (seq, org_id, at, actor_id, actor_role, action, target, detail, ip, prev_hash, hash)"""
    prev = GENESIS
    for r in rows:
        seq, org, at, actor, role, action, target, detail, ip, prev_hash, h = r
        if bytes(prev_hash) != prev:
            return {"ok": False, "broken_at": seq, "reason": "event links to the wrong previous event"}
        if chain_hash(prev, canonical(org, at, actor, role, action, target, detail, ip and str(ip))) != bytes(h):
            return {"ok": False, "broken_at": seq, "reason": "event content was changed"}
        prev = bytes(h)
    return {"ok": True, "events": len(rows)}

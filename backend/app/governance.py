"""Governance and data controls (G14-G17, I8, I9).

  access reviews    each quarter Tenant admins (owners for platform staff) mark every member keep / change / remove; sign-off applies the
                    decisions and is audited; overdue reviews raise reminders
  dormant members   suspended after the tenant's dormant period (security_settings.dormant_days); Tenant admins are told
  audit export      signed JSON or CSV with a chain check, fetched once through a 15-minute link; optional streaming to the tenant's SIEM
  export controls   per-person hourly limit, watermark, single-use expiring links (I8)
  anomaly alerts    unusual search or export volume, sign-in from a new country; thresholds are tenant settings (I9)
  offboarding       a full export of the tenant's data, and removal of the data (and the audit log) once retention has passed

The background parts are registered in app/access/jobs.py and run by app/jobs.py (python -m scripts.run_jobs).
"""
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
import psycopg
from psycopg import sql
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app import admin_api as A, config, pg
from app.access import jobs
from app.access.catalogue import PLATFORM_OWNER_ROLE_ID, TENANT_ADMIN
from app.security import audit, crypto, tokens
from app.security.rbac import Principal, require, signed_in_user, client_ip
from app.services import notify

log = logging.getLogger("sentrail.governance")
router = APIRouter()

EXPORT_ACTIONS = ("case_exported", "audit_exported", "data_exported")
LINK_MINUTES = 15
REVIEW_DUE_DAYS = 30                 # how long a review stays open before it counts as overdue
REMINDER_EVERY_DAYS = 7
PLATFORM_REVIEW_DAYS = 90


# ---------------------------------------------------------------------------------------------------------------------
# people to tell
# ---------------------------------------------------------------------------------------------------------------------
def _admin_addresses(org) -> list[str]:
    with pg.tx(org) as cur:
        cur.execute("""SELECT u.email_enc FROM users u JOIN roles r ON r.id = u.role_id
                       WHERE u.org_id=%s AND u.status='active' AND r.is_locked""", (org,))
        return [crypto.decrypt(r[0], org, "email") for r in cur.fetchall()]


def _owner_addresses() -> list[str]:
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT email_enc FROM users WHERE org_id IS NULL AND role_id=%s AND status='active' AND NOT break_glass", (PLATFORM_OWNER_ROLE_ID,))
        return [crypto.decrypt(r[0], None, "email") for r in cur.fetchall()]


def _tell(addresses, kind: str, where: str | None = None):
    for a in addresses:
        notify.security_event(a, kind, {"where": where})


# ---------------------------------------------------------------------------------------------------------------------
# memberships: one place that changes them, so reviews, the dormant sweep and SCIM behave the same
# ---------------------------------------------------------------------------------------------------------------------
def set_membership(cur, tenant, uid, *, status: str | None = None, role_id=None) -> bool:
    """Change a person's membership in `tenant` (and the old-model user row while this is their home tenant). Suspending also ends their
    sessions in that tenant at once (every request re-checks the session). Returns False when they have no membership there."""
    cur.execute("SELECT 1 FROM tenant_memberships WHERE tenant_id=%s AND user_id=%s", (tenant, uid))
    if not cur.fetchone():
        return False
    if status:
        cur.execute("UPDATE tenant_memberships SET status=%s, reactivated_at = CASE WHEN %s='active' THEN now() ELSE reactivated_at END "
                    "WHERE tenant_id=%s AND user_id=%s", (status, status, tenant, uid))
        cur.execute("UPDATE users SET status=%s, session_version=session_version+1 WHERE id=%s AND org_id=%s", (status, uid, tenant))
        if status != "active":
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL AND (tenant_id=%s OR tenant_id IS NULL)",
                        (uid, tenant))
    if role_id:
        cur.execute("UPDATE tenant_memberships SET role_id=%s WHERE tenant_id=%s AND user_id=%s", (role_id, tenant, uid))
        cur.execute("UPDATE users SET role_id=%s, session_version=session_version+1 WHERE id=%s AND org_id=%s", (role_id, uid, tenant))
    return True


def provider_disable(cur, tenant, uid):
    """Keep the identity provider in step when a person is suspended (also ends their provider sessions)."""
    if A.AUTH_MODE != "keycloak":
        return
    cur.execute("SELECT idp_subject FROM users WHERE id=%s AND org_id=%s", (uid, tenant))
    r = cur.fetchone()
    if r and r[0]:
        A.kc().set_enabled(r[0], False)


def _is_last_admin(cur, tenant, uid) -> bool:
    cur.execute("""SELECT m.user_id FROM tenant_memberships m JOIN roles r ON r.id=m.role_id
                   WHERE m.tenant_id=%s AND m.status='active' AND r.is_locked""", (tenant,))
    admins = [r[0] for r in cur.fetchall()]
    return admins == [uid]


# ---------------------------------------------------------------------------------------------------------------------
# dormant members
# ---------------------------------------------------------------------------------------------------------------------
def dormant_sweep(org: str) -> dict:
    """Suspend memberships nobody has used for the tenant's dormant period. Never the last Tenant admin and never the SSO emergency login:
    those are skipped and the admins are told instead."""
    suspended, skipped = [], []
    with pg.tx(org) as cur:
        cur.execute("SELECT dormant_days FROM security_settings")
        days = cur.fetchone()[0]
        cur.execute("""SELECT m.user_id, u.email_enc, COALESCE(u.sso_emergency, false)
                       FROM tenant_memberships m LEFT JOIN users u ON u.id = m.user_id
                       WHERE m.tenant_id=%s AND m.status='active'
                         AND GREATEST(COALESCE(m.last_active_at, m.created_at), m.created_at, COALESCE(m.reactivated_at, m.created_at))
                             < now() - make_interval(days => %s)""", (org, days))
        for uid, email_enc, emergency in cur.fetchall():
            if emergency or _is_last_admin(cur, uuid.UUID(str(org)), uid):
                skipped.append(uid)
                continue
            set_membership(cur, org, uid, status="suspended")
            provider_disable(cur, org, uid)
            masked = crypto.mask_email(crypto.decrypt(email_enc, org, "email")) if email_enc else str(uid)
            audit.write(cur, org, None, "system", "membership_dormant_suspended", str(uid), {"dormant_days": days, "who": masked}, None)
            suspended.append(masked)
    if suspended:
        _tell(_admin_addresses(org), "dormant_suspended", f"{len(suspended)} not used for {days} days: {', '.join(suspended[:10])}")
    return {"suspended": len(suspended), "skipped": len(skipped)}


# ---------------------------------------------------------------------------------------------------------------------
# access reviews
# ---------------------------------------------------------------------------------------------------------------------
def open_review(cur, tenant, opened_by, title: str | None = None, days: int = REVIEW_DUE_DAYS) -> str | None:
    """Snapshot every active member (platform staff when tenant is None). Returns the review id, or None if one is already open."""
    cur.execute("SELECT 1 FROM access_reviews WHERE tenant_id IS NOT DISTINCT FROM %s AND status='open'", (tenant,))
    if cur.fetchone():
        return None
    title = title or f"Access review {datetime.now(timezone.utc):%Y-%m-%d}"
    cur.execute("""INSERT INTO access_reviews (tenant_id, title, opened_by, due_at) VALUES (%s,%s,%s, now() + make_interval(days => %s)) RETURNING id""",
                (tenant, title, opened_by, days))
    rid = cur.fetchone()[0]
    if tenant is None:
        cur.execute("""INSERT INTO access_review_items (review_id, user_id, tenant_id, role_name)
                       SELECT %s, s.user_id, NULL, r.name FROM platform_staff s JOIN roles r ON r.id=s.role_id
                       WHERE s.status='active' AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=s.user_id AND u.break_glass)""", (rid,))
    else:
        cur.execute("""INSERT INTO access_review_items (review_id, user_id, tenant_id, role_name)
                       SELECT %s, m.user_id, m.tenant_id, r.name FROM tenant_memberships m JOIN roles r ON r.id=m.role_id
                       WHERE m.tenant_id=%s AND m.status='active'""", (rid, tenant))
    audit.write(cur, tenant, opened_by, "system" if opened_by is None else None, "access_review_opened", str(rid), {"title": title}, None)
    return str(rid)


def review_cycle(org: str) -> dict:
    """Open the quarterly review when the tenant's period has passed; remind about one that is overdue."""
    opened = reminded = 0
    with pg.tx(org) as cur:
        cur.execute("SELECT access_review_days FROM security_settings")
        days = cur.fetchone()[0]
        cur.execute("""SELECT COALESCE((SELECT max(opened_at) FROM access_reviews WHERE tenant_id=o.id), o.created_at)
                       FROM organizations o WHERE o.id=%s""", (org,))
        last = cur.fetchone()[0]                      # the last review, or the day the tenant started
        if last < datetime.now(timezone.utc) - timedelta(days=days) and open_review(cur, org, None):
            opened = 1
        cur.execute("""SELECT id FROM access_reviews WHERE tenant_id=%s AND status='open' AND due_at < now()
                       AND (last_reminder_at IS NULL OR last_reminder_at < now() - make_interval(days => %s))""", (org, REMINDER_EVERY_DAYS))
        for (rid,) in cur.fetchall():
            cur.execute("UPDATE access_reviews SET last_reminder_at=now() WHERE id=%s", (rid,))
            audit.write(cur, org, None, "system", "access_review_overdue", str(rid), {}, None)
            reminded += 1
    if opened:
        _tell(_admin_addresses(org), "access_review_opened", "a new review is waiting under Access reviews")
    if reminded:
        _tell(_admin_addresses(org), "access_review_overdue", "sign it off under Access reviews")
    return {"opened": opened, "reminded": reminded}


def platform_review_cycle() -> dict:
    opened = reminded = 0
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT max(opened_at) FROM access_reviews WHERE tenant_id IS NULL")
        last = cur.fetchone()[0]
        if last is None or last < datetime.now(timezone.utc) - timedelta(days=PLATFORM_REVIEW_DAYS):
            if open_review(cur, None, None, days=14):
                opened = 1
        cur.execute("""SELECT id FROM access_reviews WHERE tenant_id IS NULL AND status='open' AND due_at < now()
                       AND (last_reminder_at IS NULL OR last_reminder_at < now() - make_interval(days => %s))""", (REMINDER_EVERY_DAYS,))
        for (rid,) in cur.fetchall():
            cur.execute("UPDATE access_reviews SET last_reminder_at=now() WHERE id=%s", (rid,))
            audit.write(cur, None, None, "system", "access_review_overdue", str(rid), {}, None)
            reminded += 1
    if opened:
        _tell(_owner_addresses(), "access_review_opened", "the platform staff review is waiting")
    if reminded:
        _tell(_owner_addresses(), "access_review_overdue", "sign off the platform staff review")
    return {"opened": opened, "reminded": reminded}


class ReviewIn(BaseModel):
    title: str | None = Field(None, max_length=120)


class DecisionIn(BaseModel):
    decision: str = Field(pattern="^(keep|change|remove)$")
    new_role_id: uuid.UUID | None = None
    note: str | None = Field(None, max_length=300)


def _tx(p: Principal, platform: bool):
    return pg.tx(None if platform else p.org_id, platform=platform, actor=p.actor, access_session=p.access_session_id)


def _review_row(cur, rid, platform: bool, tenant):
    cur.execute("""SELECT id, title, status, opened_at, due_at, signed_off_at, signed_off_by FROM access_reviews
                   WHERE id=%s AND tenant_id IS NOT DISTINCT FROM %s""", (rid, tenant))
    r = cur.fetchone()
    if not r:
        raise HTTPException(404, "No such review")
    return r


def _review_summary(r, counts=None) -> dict:
    out = {"id": str(r[0]), "title": r[1], "status": r[2], "opened_at": r[3], "due_at": r[4], "signed_off_at": r[5],
           "signed_off_by": str(r[6]) if r[6] else None, "overdue": r[2] == "open" and r[4] < datetime.now(timezone.utc)}
    if counts:
        out.update(items=counts[0], decided=counts[1])
    return out


def _list_reviews(p, platform):
    with _tx(p, platform) as cur:
        t = None if platform else p.org_id
        cur.execute("""SELECT r.id, r.title, r.status, r.opened_at, r.due_at, r.signed_off_at, r.signed_off_by,
                              (SELECT count(*) FROM access_review_items i WHERE i.review_id=r.id),
                              (SELECT count(*) FROM access_review_items i WHERE i.review_id=r.id AND i.decision IS NOT NULL)
                       FROM access_reviews r WHERE r.tenant_id IS NOT DISTINCT FROM %s ORDER BY r.opened_at DESC LIMIT 50""", (t,))
        return [_review_summary(r, (r[7], r[8])) for r in cur.fetchall()]


def _open_review_api(p, platform, body):
    with _tx(p, platform) as cur:
        t = None if platform else p.org_id
        rid = open_review(cur, t, p.user_id, body.title)
        if not rid:
            raise HTTPException(409, "A review is already open. Sign it off first")
        cur.execute("SELECT count(*) FROM access_review_items WHERE review_id=%s", (rid,))
        n = cur.fetchone()[0]
    return {"id": rid, "items": n}


def _show_review(p, platform, rid):
    t = None if platform else p.org_id
    with _tx(p, platform) as cur:
        r = _review_row(cur, rid, platform, t)
        cur.execute("""SELECT i.user_id, i.role_name, i.decision, i.new_role_id, i.note, i.decided_at, u.email_enc, u.name_enc
                       FROM access_review_items i LEFT JOIN users u ON u.id=i.user_id
                       WHERE i.review_id=%s ORDER BY i.role_name, i.user_id""", (rid,))
        items = []
        for uid, role, dec, new_role, note, at, e, n in cur.fetchall():
            items.append({"user_id": str(uid), "name": crypto.decrypt(n, t, "name") if n else None,
                          "email": crypto.mask_email(crypto.decrypt(e, t, "email")) if e else None, "role": role,
                          "decision": dec, "new_role_id": str(new_role) if new_role else None, "note": note, "decided_at": at})
    return {**_review_summary(r, (len(items), sum(1 for i in items if i["decision"]))), "members": items}


def _decide(p, platform, rid, uid, body: DecisionIn):
    t = None if platform else p.org_id
    if str(uid) == p.user_id:
        raise HTTPException(403, "You can't review your own access. Ask another reviewer")
    with _tx(p, platform) as cur:
        r = _review_row(cur, rid, platform, t)
        if r[2] != "open":
            raise HTTPException(409, "This review is closed")
        cur.execute("SELECT role_name FROM access_review_items WHERE review_id=%s AND user_id=%s", (rid, uid))
        item = cur.fetchone()
        if not item:
            raise HTTPException(404, "That person isn't part of this review")
        if body.decision == "change":
            if not body.new_role_id:
                raise HTTPException(422, "Choose the new role")
            if platform:
                cur.execute("SELECT 1 FROM roles WHERE id=%s AND org_id IS NULL", (body.new_role_id,))
            else:
                cur.execute("SELECT 1 FROM roles WHERE id=%s AND org_id=%s AND NOT is_locked", (body.new_role_id, p.org_id))
            if not cur.fetchone():
                raise HTTPException(422, "That role can't be assigned here")
            if str(body.new_role_id) == PLATFORM_OWNER_ROLE_ID:
                raise HTTPException(409, "Owners are added with a second owner's approval, not through a review")
        if platform:
            cur.execute("SELECT role_id FROM platform_staff WHERE user_id=%s", (uid,))
            if body.decision != "keep" and str(cur.fetchone()[0]) == PLATFORM_OWNER_ROLE_ID:
                raise HTTPException(409, "Changing or removing an owner needs a second owner's approval. Use the owners screen")
        elif body.decision != "keep" and _is_last_admin(cur, uuid.UUID(str(p.org_id)), uid):
            raise HTTPException(409, "Your organization needs at least one active admin")
        cur.execute("""UPDATE access_review_items SET decision=%s, new_role_id=%s, note=%s, decided_by=%s, decided_at=now()
                       WHERE review_id=%s AND user_id=%s""",
                    (body.decision, body.new_role_id if body.decision == "change" else None, body.note, p.user_id, rid, uid))
    return {"user_id": str(uid), "decision": body.decision}


def _sign_off(p, platform, rid):
    t = None if platform else p.org_id
    applied = {"keep": 0, "change": 0, "remove": 0}
    with _tx(p, platform) as cur:
        r = _review_row(cur, rid, platform, t)
        if r[2] != "open":
            raise HTTPException(409, "This review is already closed")
        cur.execute("SELECT count(*) FROM access_review_items WHERE review_id=%s AND decision IS NULL", (rid,))
        if cur.fetchone()[0]:
            raise HTTPException(409, "Every person needs a decision before you can sign off")
        cur.execute("SELECT user_id, decision, new_role_id FROM access_review_items WHERE review_id=%s ORDER BY user_id", (rid,))
        items = cur.fetchall()
        # Permission was checked on the way in. The decisions are applied as the system: one of them may remove the signer's own access,
        # and the database must not refuse the rest of the changes because of it.
        cur.execute("SELECT set_config('app.actor', '', true)")
        for uid, decision, new_role in items:
            applied[decision] += 1
            if decision == "keep":
                continue
            if platform:
                if decision == "remove":
                    cur.execute("UPDATE users SET status='suspended', session_version=session_version+1 WHERE id=%s AND org_id IS NULL", (uid,))
                    cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (uid,))
                else:
                    cur.execute("UPDATE users SET role_id=%s, session_version=session_version+1 WHERE id=%s AND org_id IS NULL", (new_role, uid))
                continue
            if _is_last_admin(cur, uuid.UUID(str(p.org_id)), uid):
                raise HTTPException(409, "Your organization needs at least one active admin. Change that decision first")
            if decision == "remove":
                set_membership(cur, p.org_id, uid, status="suspended")
                provider_disable(cur, p.org_id, uid)
            else:
                set_membership(cur, p.org_id, uid, role_id=new_role)
            audit.write(cur, p.org_id, p.user_id, p.role, f"access_review_{decision}", str(uid), {"review": str(rid)}, p.ip)
        cur.execute("UPDATE access_reviews SET status='signed_off', signed_off_at=now(), signed_off_by=%s WHERE id=%s", (p.user_id, rid))
        audit.write(cur, t, p.user_id, p.role, "access_review_signed_off", str(rid), {**applied, "people": sum(applied.values())}, p.ip)
    return {"id": str(rid), "status": "signed_off", **applied}


@router.get("/admin/access-reviews")
def list_reviews(p: Principal = Depends(require("access.review"))):
    return _list_reviews(p, False)


@router.post("/admin/access-reviews")
def open_review_route(body: ReviewIn, p: Principal = Depends(require("access.review"))):
    return _open_review_api(p, False, body)


@router.get("/admin/access-reviews/{rid}")
def get_review(rid: uuid.UUID, p: Principal = Depends(require("access.review"))):
    return _show_review(p, False, rid)


@router.put("/admin/access-reviews/{rid}/members/{uid}")
def decide(rid: uuid.UUID, uid: uuid.UUID, body: DecisionIn, p: Principal = Depends(require("access.review"))):
    return _decide(p, False, rid, uid, body)


@router.post("/admin/access-reviews/{rid}/sign-off")
def sign_off(rid: uuid.UUID, p: Principal = Depends(require("access.review"))):
    return _sign_off(p, False, rid)


# the platform's own staff are reviewed by owners
@router.get("/platform/access-reviews")
def list_platform_reviews(p: Principal = Depends(require("platform.owners.manage"))):
    return _list_reviews(p, True)


@router.post("/platform/access-reviews")
def open_platform_review(body: ReviewIn, p: Principal = Depends(require("platform.owners.manage"))):
    return _open_review_api(p, True, body)


@router.get("/platform/access-reviews/{rid}")
def get_platform_review(rid: uuid.UUID, p: Principal = Depends(require("platform.owners.manage"))):
    return _show_review(p, True, rid)


@router.put("/platform/access-reviews/{rid}/members/{uid}")
def decide_platform(rid: uuid.UUID, uid: uuid.UUID, body: DecisionIn, p: Principal = Depends(require("platform.owners.manage"))):
    return _decide(p, True, rid, uid, body)


@router.post("/platform/access-reviews/{rid}/sign-off")
def sign_off_platform(rid: uuid.UUID, p: Principal = Depends(require("platform.owners.manage"))):
    return _sign_off(p, True, rid)


# ---------------------------------------------------------------------------------------------------------------------
# export controls (I8) and anomaly alerts (I9)
# ---------------------------------------------------------------------------------------------------------------------
def export_guard(cur, p: Principal):
    """At most `export_limit_per_hour` exports per person per hour (cases, audit, tenant data together)."""
    cur.execute("SELECT export_limit_per_hour FROM security_settings")
    limit = cur.fetchone()[0]
    cur.execute("""SELECT count(*) FROM audit_events WHERE org_id=%s AND actor_id=%s AND action = ANY(%s) AND at > now() - interval '1 hour'""",
                (p.org_id, p.user_id, list(EXPORT_ACTIONS)))
    if cur.fetchone()[0] >= limit:
        raise HTTPException(429, f"You can export at most {limit} times an hour. Try again later", headers={"Retry-After": "600"})


def watermark(cur, p: Principal, what: str) -> dict:
    """Who took this file out, from which tenant, and when: carried inside every export."""
    cur.execute("SELECT legal_name FROM organizations WHERE id=%s", (p.org_id,))
    name = cur.fetchone()[0]
    cur.execute("SELECT email_enc FROM users WHERE id=%s", (p.user_id,))
    r = cur.fetchone()
    who = crypto.mask_email(crypto.decrypt(r[0], p.org_id, "email")) if r else p.user_id
    return {"exported_by": {"user_id": p.user_id, "email": who}, "tenant": {"id": str(p.org_id), "name": name},
            "exported_at": datetime.now(timezone.utc).isoformat(), "content": what,
            "notice": "Confidential. This file is traced to the person named here."}


def anomaly_check(p: Principal, kind: str):
    """After a search or an export: past the tenant's threshold for this person in the last hour, tell the Tenant admins (once an hour)."""
    action, col = ("search", "anomaly_searches_per_hour") if kind == "search" else (None, "anomaly_exports_per_hour")
    actions = [action] if action else list(EXPORT_ACTIONS)
    fire = None
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute(f"SELECT {col} FROM security_settings")
        threshold = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM audit_events WHERE org_id=%s AND actor_id=%s AND action = ANY(%s) AND at > now() - interval '1 hour'",
                    (p.org_id, p.user_id, actions))
        n = cur.fetchone()[0]
        if n <= threshold:
            return
        cur.execute("""SELECT 1 FROM audit_events WHERE org_id=%s AND action='anomaly_alert' AND target=%s AND detail->>'user'=%s
                       AND at > now() - interval '1 hour'""", (p.org_id, kind, p.user_id))
        if cur.fetchone():
            return
        audit.write(cur, p.org_id, None, "system", "anomaly_alert", kind, {"user": p.user_id, "count": n, "threshold": threshold, "window": "1 hour"}, p.ip)
        cur.execute("SELECT email_enc FROM users WHERE id=%s", (p.user_id,))
        r = cur.fetchone()
        who = crypto.mask_email(crypto.decrypt(r[0], p.org_id, "email")) if r else p.user_id
        fire = f"{who} made {n} {'searches' if kind == 'search' else 'exports'} in an hour (limit {threshold})"
    _tell(_admin_addresses(p.org_id), "anomaly_alert", fire)


def country_of(request: Request) -> str | None:
    """The caller's country, from the header the CDN or load balancer sets (COUNTRY_HEADER, default CF-IPCountry). Only honoured when
    TRUST_COUNTRY_HEADER=true, because anyone can send the header when nothing in front strips it."""
    if os.environ.get("TRUST_COUNTRY_HEADER", "false").lower() != "true":
        return None
    v = (request.headers.get(os.environ.get("COUNTRY_HEADER", "CF-IPCountry")) or "").strip().upper()
    return v if len(v) == 2 and v.isalpha() and v not in ("XX", "T1") else None


def note_country(cur, request: Request, uid, org, email_enc):
    """Record the country of a successful sign-in. A country this person has not signed in from before (and they have signed in before)
    alerts the Tenant admins when the tenant has that switched on."""
    country = country_of(request)
    if not country or org is None:
        return
    cur.execute("SELECT count(*) FROM user_countries WHERE user_id=%s", (uid,))
    known = cur.fetchone()[0]
    cur.execute("INSERT INTO user_countries (user_id, country) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING 1", (uid, country))
    if not cur.fetchone() or not known:
        return
    cur.execute("SELECT alert_new_country FROM security_settings")        # (same transaction: the sign-in already holds this tenant's audit chain)
    on = cur.fetchone()
    if not on or not on[0]:
        return
    who = crypto.mask_email(crypto.decrypt(email_enc, org, "email"))
    audit.write(cur, org, None, "system", "anomaly_alert", "new_country", {"user": str(uid), "country": country}, client_ip(request))
    # the admins are told from a thread: no mail server round trip inside the sign-in's database transaction
    threading.Thread(target=lambda: _tell(_admin_addresses(org), "anomaly_alert", f"{who} signed in from a new country ({country})"), daemon=True).start()


# ---------------------------------------------------------------------------------------------------------------------
# audit export (signed), single-use download links
# ---------------------------------------------------------------------------------------------------------------------
def _signing_key() -> bytes:
    return hmac.new(crypto.ring().index_key, b"sentrail/audit-export/v1", hashlib.sha256).digest()


def sign(data: bytes) -> str:
    return hmac.new(_signing_key(), data, hashlib.sha256).hexdigest()


def _canonical_doc(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditExportIn(BaseModel):
    format: str = Field("json", pattern="^(json|csv)$")
    since: datetime | None = None
    until: datetime | None = None


def _event_dict(r) -> dict:
    return {"seq": r[0], "org": str(r[1]) if r[1] else None, "at": r[2].isoformat(), "actor": str(r[3]) if r[3] else None, "role": r[4],
            "action": r[5], "target": r[6], "detail": r[7], "ip": str(r[8]) if r[8] else None,
            "prev_hash": bytes(r[9]).hex(), "hash": bytes(r[10]).hex()}


def build_audit_export(cur, p: Principal, body: AuditExportIn) -> tuple[str, str, str]:
    cur.execute(f"SELECT {A.COLS} FROM audit_events WHERE org_id IS NOT DISTINCT FROM %s ORDER BY seq", (p.org_id,))
    rows = cur.fetchall()
    chain = audit.verify_rows(rows)
    head = bytes(rows[-1][10]).hex() if rows else None
    utc = lambda d: d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)
    since, until = utc(body.since), utc(body.until)
    picked = [r for r in rows if (not since or r[2] >= since) and (not until or r[2] <= until)]
    marks = watermark(cur, p, "audit log")
    events = [_event_dict(r) for r in picked]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    chain_info = {"verified": chain["ok"], "events_in_chain": len(rows), "head_hash": head,
                  "first_seq": picked[0][0] if picked else None, "last_seq": picked[-1][0] if picked else None,
                  **({} if chain["ok"] else {"broken_at": chain.get("broken_at"), "reason": chain.get("reason")})}
    if body.format == "json":
        doc = {"watermark": marks, "chain": chain_info, "events": events}
        doc["signature"] = {"alg": "HMAC-SHA256", "over": "canonical JSON of this document without 'signature'", "value": sign(_canonical_doc(doc))}
        return f"audit-{stamp}.json", "application/json", json.dumps(doc, indent=1, default=str)
    out = io.StringIO()
    out.write(f"# Sentrail audit export | {marks['tenant']['name']} | by {marks['exported_by']['email']} | {marks['exported_at']}\n")
    out.write(f"# chain verified={chain_info['verified']} events_in_chain={len(rows)} head_hash={head}\n")
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["seq", "at", "actor", "role", "action", "target", "detail", "ip", "prev_hash", "hash"])
    for e in events:
        w.writerow([e["seq"], e["at"], e["actor"], e["role"], e["action"], e["target"], json.dumps(e["detail"], sort_keys=True), e["ip"], e["prev_hash"], e["hash"]])
    text = out.getvalue()
    text += f"# signature=HMAC-SHA256:{sign(text.encode())}\n"
    return f"audit-{stamp}.csv", "text/csv", text


def verify_export(doc: dict) -> dict:
    """What a recipient (or an examiner) can check on a JSON export: the signature, and that the events link into one unbroken chain."""
    body = {k: v for k, v in doc.items() if k != "signature"}
    sig_ok = hmac.compare_digest(doc.get("signature", {}).get("value", ""), sign(_canonical_doc(body)))
    prev, linked = None, True
    for e in doc["events"]:
        if prev is not None and e["prev_hash"] != prev:
            linked = False
        recomputed = audit.chain_hash(bytes.fromhex(e["prev_hash"]), audit.canonical(
            e["org"], datetime.fromisoformat(e["at"]), e["actor"], e["role"], e["action"], e["target"], e["detail"], e["ip"])).hex()
        if recomputed != e["hash"]:
            linked = False
        prev = e["hash"]
    return {"signature_ok": sig_ok, "events_intact": linked}


def make_link(cur, p: Principal, kind: str, filename: str, content_type: str, text: str) -> dict:
    raw = tokens.new_opaque()
    cur.execute("""INSERT INTO export_links (tenant_id, user_id, kind, filename, content_type, content_enc, token_hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING expires_at""",
                (p.org_id, p.user_id, kind, filename, content_type, crypto.encrypt(text, p.org_id, "export"), crypto.sha256(raw)))
    return {"download_path": f"/me/exports/{raw}", "expires_at": cur.fetchone()[0], "filename": filename,
            "note": f"Fetch it once, while signed in as yourself, within {LINK_MINUTES} minutes"}


@router.post("/admin/audit/export")
def export_audit(body: AuditExportIn, p: Principal = Depends(require("audit.export"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        export_guard(cur, p)
        name, ctype, text = build_audit_export(cur, p, body)
        link = make_link(cur, p, "audit", name, ctype, text)
        audit.write(cur, p.org_id, p.user_id, p.role, "audit_exported", name, {"format": body.format}, p.ip)
    anomaly_check(p, "export")
    return link


@router.get("/me/exports/{token}")
def download_export(token: str, p: Principal = Depends(signed_in_user)):
    """The file behind a link: only the person who asked, only once, only within 15 minutes. The content is deleted when it is fetched."""
    if p.org_id is None:
        raise HTTPException(404, "No such download")
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT id, filename, content_type, content_enc, used_at, expires_at FROM export_links
                       WHERE token_hash=%s AND tenant_id=%s AND user_id=%s FOR UPDATE""", (crypto.sha256(token), p.org_id, p.user_id))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "No such download")
        if r[4] is not None or r[5] <= datetime.now(timezone.utc) or r[3] is None:
            raise HTTPException(410, "This download link has expired or was already used. Export again")
        cur.execute("UPDATE export_links SET used_at=now(), content_enc=NULL WHERE id=%s", (r[0],))
        audit.write(cur, p.org_id, p.user_id, p.role, "export_downloaded", r[1], {}, p.ip)
        text = crypto.decrypt(r[3], p.org_id, "export")
    return Response(text, media_type=r[2], headers={"Content-Disposition": f'attachment; filename="{r[1]}"', "Cache-Control": "no-store"})


def expire_exports(org: str) -> dict:
    """Used or expired links lose their content (an expired one was never fetched, so nothing should linger)."""
    with pg.tx(org) as cur:
        cur.execute("UPDATE export_links SET content_enc=NULL WHERE content_enc IS NOT NULL AND (used_at IS NOT NULL OR expires_at < now())")
        n = cur.rowcount
        cur.execute("DELETE FROM export_links WHERE expires_at < now() - interval '7 days'")
    return {"cleared": n}


# ---------------------------------------------------------------------------------------------------------------------
# audit streaming to the tenant's SIEM
# ---------------------------------------------------------------------------------------------------------------------
class StreamIn(BaseModel):
    url: str = Field(max_length=500)
    enabled: bool = True


def _blocked_address(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified


def check_stream_url(url: str):
    """https only, and never an address inside our own network (the stream must not become a way to reach internal services)."""
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        raise HTTPException(422, "The stream address must start with https://")
    try:
        if _blocked_address(u.hostname):
            raise HTTPException(422, "That address is inside a private network")
    except ValueError:
        pass                                                        # a host name: resolved and checked again at every delivery


def post_json(url: str, body: bytes, headers: dict) -> int:
    """One delivery. Resolves the host and refuses private addresses (also protects against DNS pointing inward), no redirects."""
    host = urlparse(url).hostname
    for info in socket.getaddrinfo(host, None):
        if _blocked_address(info[4][0]):
            raise RuntimeError("stream address resolves to a private network")
    return httpx.post(url, content=body, headers=headers, timeout=5, follow_redirects=False).status_code


def _stream_sign(secret: str, ts: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


@router.put("/admin/audit/stream")
def set_stream(body: StreamIn, p: Principal = Depends(require("audit.export", feature="audit_streaming"))):
    check_stream_url(body.url)
    secret = None
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT 1 FROM audit_streams")
        if cur.fetchone():
            cur.execute("UPDATE audit_streams SET url=%s, enabled=%s, failures=0, last_error=NULL WHERE tenant_id=%s", (body.url, body.enabled, p.org_id))
        else:
            secret = tokens.new_opaque()
            cur.execute("""INSERT INTO audit_streams (tenant_id, url, secret_enc, enabled, created_by, last_seq)
                           VALUES (%s,%s,%s,%s,%s, COALESCE((SELECT max(seq) FROM audit_events WHERE org_id=%s), 0))""",
                        (p.org_id, body.url, crypto.encrypt(secret, p.org_id, "stream"), body.enabled, p.user_id, p.org_id))
        audit.write(cur, p.org_id, p.user_id, p.role, "audit_stream_configured", urlparse(body.url).hostname, {"enabled": body.enabled}, p.ip)
    return {"ok": True, **({"signing_secret": secret, "note": "Copy the secret now. Every delivery carries X-Sentrail-Signature: "
                            "sha256=HMAC(secret, timestamp + '.' + body)"} if secret else {})}


@router.get("/admin/audit/stream")
def get_stream(p: Principal = Depends(require("audit.export", feature="audit_streaming"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT url, enabled, last_seq, failures, last_error, last_success_at FROM audit_streams")
        r = cur.fetchone()
    if not r:
        return {"configured": False}
    return {"configured": True, "url": r[0], "enabled": r[1], "delivered_up_to": r[2], "failures": r[3], "last_error": r[4], "last_success_at": r[5]}


@router.delete("/admin/audit/stream")
def delete_stream(p: Principal = Depends(require("audit.export", feature="audit_streaming"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("DELETE FROM audit_streams RETURNING 1")
        if not cur.fetchone():
            raise HTTPException(404, "No stream is configured")
        audit.write(cur, p.org_id, p.user_id, p.role, "audit_stream_removed", None, {}, p.ip)
    return {"ok": True}


MAX_STREAM_FAILURES = 50
BATCH = 500


def stream_audit(org: str) -> dict:
    """Deliver new audit events to the tenant's endpoint, oldest first, in batches. The position only moves after the receiver answered 2xx, so
    a failure repeats the batch (at least once delivery; events carry their seq and hash). Too many failures in a row switch the stream off."""
    sent = 0
    with pg.tx(org) as cur:
        cur.execute("SELECT url, secret_enc, last_seq, failures FROM audit_streams WHERE enabled")
        s = cur.fetchone()
        if not s:
            return {"sent": 0}
        url, secret_enc, last, failures = s
        secret = crypto.decrypt(secret_enc, org, "stream")
        cur.execute(f"SELECT {A.COLS} FROM audit_events WHERE org_id=%s AND seq > %s ORDER BY seq LIMIT %s", (org, last, BATCH))
        rows = cur.fetchall()
    if not rows:
        return {"sent": 0}
    body = json.dumps({"tenant": str(org), "events": [_event_dict(r) for r in rows]}, default=str).encode()
    ts = str(int(datetime.now(timezone.utc).timestamp()))
    err = None
    try:
        code = post_json(url, body, {"Content-Type": "application/json", "X-Sentrail-Timestamp": ts,
                                      "X-Sentrail-Signature": _stream_sign(secret, ts, body)})
        if not 200 <= code < 300:
            err = f"the receiver answered {code}"
    except Exception as e:                                           # noqa: BLE001 - any delivery problem is a failure, never a crash
        err = type(e).__name__ + (": " + str(e) if isinstance(e, RuntimeError) else "")
    with pg.tx(org) as cur:
        if err is None:
            cur.execute("UPDATE audit_streams SET last_seq=%s, failures=0, last_error=NULL, last_success_at=now() WHERE tenant_id=%s", (rows[-1][0], org))
            sent = len(rows)
        else:
            cur.execute("UPDATE audit_streams SET failures=failures+1, last_error=%s, enabled = failures + 1 < %s WHERE tenant_id=%s RETURNING enabled, failures",
                        (err, MAX_STREAM_FAILURES, org))
            enabled, n = cur.fetchone()
            if not enabled:
                audit.write(cur, org, None, "system", "audit_stream_disabled", None, {"after_failures": n, "last_error": err}, None)
    if err is not None and sent == 0 and failures + 1 == 3:
        _tell(_admin_addresses(org), "audit_stream_failing", f"{err}. It keeps trying; after {MAX_STREAM_FAILURES} failures it switches off")
    return {"sent": sent, "error": err}


# ---------------------------------------------------------------------------------------------------------------------
# offboarding: full data export, and removal after retention
# ---------------------------------------------------------------------------------------------------------------------
def build_data_export(cur, p: Principal) -> tuple[str, str, str]:
    org = p.org_id
    cur.execute("SELECT legal_name, business_type, registration, data_region, plan, slug, status, created_at FROM organizations WHERE id=%s", (org,))
    o = cur.fetchone()
    doc = {"watermark": watermark(cur, p, "all tenant data"),
           "organization": dict(zip(["legal_name", "business_type", "registration", "data_region", "plan", "slug", "status", "created_at"], o))}
    cur.execute("""SELECT retention_years, min_password_len, idle_timeout_min, mfa_required, ip_allowlist::text[], dormant_days, access_review_days
                   FROM security_settings""")
    doc["security_settings"] = dict(zip(["retention_years", "min_password_len", "idle_timeout_min", "mfa_required", "ip_allowlist",
                                         "dormant_days", "access_review_days"], cur.fetchone()))
    cur.execute("SELECT feature, in_plan, enabled FROM org_features ORDER BY feature")
    doc["features"] = [dict(zip(["feature", "in_plan", "enabled"], r)) for r in cur.fetchall()]
    cur.execute("""SELECT r.name, r.is_locked, array_agg(rp.perm ORDER BY rp.perm) FILTER (WHERE rp.perm IS NOT NULL)
                   FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id WHERE r.org_id=%s GROUP BY r.id ORDER BY r.name""", (org,))
    doc["roles"] = [{"name": r[0], "locked": r[1], "permissions": r[2] or []} for r in cur.fetchall()]
    cur.execute("""SELECT u.id, u.email_enc, u.name_enc, r.name, m.status, m.created_at, m.last_active_at FROM tenant_memberships m
                   JOIN users u ON u.id=m.user_id JOIN roles r ON r.id=m.role_id WHERE m.tenant_id=%s ORDER BY m.created_at""", (org,))
    doc["members"] = [{"user_id": str(r[0]), "email": crypto.decrypt(r[1], org, "email"), "name": crypto.decrypt(r[2], org, "name"),
                       "role": r[3], "status": r[4], "joined_at": r[5], "last_active_at": r[6]} for r in cur.fetchall()]
    cur.execute("SELECT id, customer_id, score, band, reasons, channel, status, assigned_to, created_at FROM alerts ORDER BY created_at")
    doc["cases"] = [dict(zip(["id", "customer_id", "score", "band", "reasons", "channel", "status", "assigned_to", "created_at"], r)) for r in cur.fetchall()]
    cur.execute("SELECT alert_id, ai_draft_enc, final_enc, drafted_by, approved_by, status, updated_at FROM str_drafts ORDER BY alert_id")
    doc["str_reports"] = [{"alert_id": r[0], "ai_draft": crypto.decrypt(r[1], org, "str"), "final_text": crypto.decrypt(r[2], org, "str"),
                           "drafted_by": r[3], "approved_by": r[4], "status": r[5], "updated_at": r[6]} for r in cur.fetchall()]
    cur.execute("SELECT id, customer_id, direction, address, amount, score, decision, reasons, override, created_at FROM screenings ORDER BY created_at")
    doc["screenings"] = [dict(zip(["id", "customer_id", "direction", "address", "amount", "score", "decision", "reasons", "override", "created_at"], r))
                         for r in cur.fetchall()]
    cur.execute("SELECT policy FROM screening_policy")
    r = cur.fetchone()
    doc["screening_policy"] = r[0] if r else None
    cur.execute("SELECT prefix, scopes, created_at, revoked_at, expires_at, last_used_at FROM api_keys ORDER BY created_at")
    doc["api_keys"] = [dict(zip(["prefix", "scopes", "created_at", "revoked_at", "expires_at", "last_used_at"], r)) for r in cur.fetchall()]
    cur.execute("SELECT title, status, opened_at, signed_off_at FROM access_reviews ORDER BY opened_at")
    doc["access_reviews"] = [dict(zip(["title", "status", "opened_at", "signed_off_at"], r)) for r in cur.fetchall()]
    cur.execute(f"SELECT {A.COLS} FROM audit_events WHERE org_id=%s ORDER BY seq", (org,))
    rows = cur.fetchall()
    doc["audit"] = {"chain": audit.verify_rows(rows), "events": [_event_dict(r) for r in rows]}
    doc["signature"] = {"alg": "HMAC-SHA256", "over": "canonical JSON of this document without 'signature'", "value": sign(_canonical_doc(doc))}
    return f"tenant-data-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json", "application/json", json.dumps(doc, indent=1, default=str)


@router.post("/admin/data-export")
def export_tenant_data(p: Principal = Depends(require("data.export"))):
    """Everything the organization has in Sentrail, in one signed JSON file: for moving elsewhere or leaving. Secrets (password hashes,
    authenticator seeds, API key hashes, passkeys) are never part of it."""
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        export_guard(cur, p)
        name, ctype, text = build_data_export(cur, p)
        link = make_link(cur, p, "tenant_data", name, ctype, text)
        audit.write(cur, p.org_id, p.user_id, p.role, "data_exported", name, {"scope": "all tenant data"}, p.ip)
    anomaly_check(p, "export")
    return link


def _delete_rows(cur, org, tables) -> list:
    """DELETE this tenant's rows from each (table, column), repeating while foreign keys make some wait. Returns what is still left."""
    pending = list(tables)
    for _ in range(8):
        waiting = []
        for t, c in pending:
            try:
                with cur.connection.transaction():
                    cur.execute(sql.SQL("DELETE FROM {} WHERE {}=%s").format(sql.Identifier(t), sql.Identifier(c)), (org,))
            except psycopg.errors.ForeignKeyViolation:
                waiting.append((t, c))
        if len(waiting) == len(pending):
            break
        pending = waiting
        if not pending:
            break
    return pending


def _purge_one(org) -> None:
    with pg.tx(org) as cur:                      # what is about to go, for the deletion record
        cur.execute("SELECT count(*), max(seq) FROM audit_events WHERE org_id=%s", (org,))
        n_events, last = cur.fetchone()
        head = None
        if last:
            cur.execute("SELECT hash FROM audit_events WHERE seq=%s", (last,))
            head = bytes(cur.fetchone()[0]).hex()
        cur.execute("SELECT count(*) FROM users WHERE org_id=%s", (org,))
        n_users = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM alerts")
        n_cases = cur.fetchone()[0]
    with pg.tx(platform=True) as cur:
        # People who also belong to another tenant stay (they only lose this membership; their role no longer points at a removed one).
        # Only platform scope sees the memberships of every tenant. (Their sync trigger re-creates the membership here: it goes below.)
        cur.execute("""UPDATE users u SET role_id = (SELECT m.role_id FROM tenant_memberships m WHERE m.user_id=u.id AND m.tenant_id<>%s LIMIT 1)
                       WHERE u.org_id=%s AND EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.user_id=u.id AND m.tenant_id<>%s)""", (org, org, org))
    with pg.tx(org) as cur:
        cur.execute("SELECT set_config('app.role_sync', 'on', true)")
        # Everything that carries this tenant's id, discovered from the schema so a new table can't be forgotten. Parents wait for their
        # children, so it repeats; the roles wait for the people (below), who wait for the tables that point at them.
        cur.execute("""SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public'
                       AND column_name IN ('org_id','tenant_id') AND table_name NOT IN ('audit_events','organizations','users')""")
        waiting = _delete_rows(cur, org, cur.fetchall())
    with pg.tx(platform=True) as cur:
        cur.execute("DELETE FROM users u WHERE u.org_id=%s AND NOT EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.user_id=u.id)", (org,))
    with pg.tx(org) as cur:
        cur.execute("SELECT set_config('app.role_sync', 'on', true)")
        left = _delete_rows(cur, org, waiting)
        if left:
            raise RuntimeError(f"could not remove {left}")
        cur.execute("SELECT purge_tenant_audit(%s)", (org,))
        removed_events = cur.fetchone()[0]
    with pg.tx(platform=True) as cur:
        cur.execute("""UPDATE organizations SET legal_name='[removed]', registration='[removed]', sso_domain=NULL, sso_idp_alias=NULL, sso_enforced=false,
                       sso_default_role_id=NULL WHERE id=%s""", (org,))
        audit.write(cur, None, None, "system", "tenant_data_removed", str(org),
                    {"tenant": str(org), "events_removed": removed_events, "events_expected": n_events, "audit_head_hash": head, "people": n_users,
                     "cases": n_cases, "retention_elapsed": True}, None)


def purge_deleted_tenants() -> dict:
    """Remove the data of tenants that were deleted and whose retention period has passed. The organization row stays as a tombstone (its
    permanent slug is never reused) with its name blanked. The platform log gets a deletion record with what was removed and the head of the
    tenant's audit chain, so the removal itself stays provable."""
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT id FROM organizations WHERE status='deleted' AND deletion_due_at <= now() AND legal_name <> '[removed]'")
        due = [r[0] for r in cur.fetchall()]
    done = []
    for org in due:
        try:
            _purge_one(org)
            done.append(str(org))
        except Exception:                          # noqa: BLE001 - one tenant's problem must not stop the others
            log.exception("tenant data removal failed", extra={"event": "tenant_purge_failed", "org_id": org})
    return {"removed": done}


# ---------------------------------------------------------------------------------------------------------------------
# housekeeping that every deployment needs
# ---------------------------------------------------------------------------------------------------------------------
def housekeeping() -> dict:
    with pg.tx(platform=True) as cur:
        cur.execute("DELETE FROM webauthn_challenges WHERE expires_at < now()")
        a = cur.rowcount
        cur.execute("DELETE FROM oidc_login_states WHERE expires_at < now()")
        b = cur.rowcount
    from app import owner_access
    ended = owner_access.expire_stale()
    return {"challenges": a, "login_states": b, "access_sessions_closed": ended if isinstance(ended, int) else len(ended or [])}


jobs.TENANT_JOBS.update({"dormant_sweep": dormant_sweep, "review_cycle": review_cycle, "audit_stream": stream_audit,
                         "expire_exports": expire_exports})
jobs.GLOBAL_JOBS.update({"platform_review_cycle": platform_review_cycle, "purge_deleted_tenants": purge_deleted_tenants,
                         "housekeeping": housekeeping})

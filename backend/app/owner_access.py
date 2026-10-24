"""Owner access sessions (G3, G18): the only way a Platform owner reaches a tenant's data.

An owner asks to enter a tenant with a reason. What happens next follows the tenant's own setting (organizations.owner_access):
  allow             the session starts at once
  require_approval  one of the tenant's own administrators approves or denies it in the app
  deny              refused, unless a second owner approved a recorded legal hold on the tenant (organizations.legal_hold)
A session lasts 60 minutes and can be extended once. Inside it the owner acts with Tenant admin rights; every audit event they cause is
tagged with the session id in the tenant's log AND mirrored into the platform's log (security/audit.py). The tenant's administrators are
told when a session is requested, starts and ends. When it expires access is cut at the next request (rbac) and the end is recorded here.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import admin_api as A, pg
from app.security import audit, crypto, rbac
from app.security.rbac import Principal, require, require_any, client_ip
from app.services import notify

router = APIRouter()

SESSION_MINUTES = 60
REQUEST_HOURS = 24
OWNER_ROLE_NAME = "Platform owner"


class AccessIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


# ---------------------------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------------------------
def _admin_addresses(org_id) -> list[str]:
    """Plain email addresses of the tenant's active Tenant admins (to be told about owner access)."""
    with pg.tx(org_id) as cur:
        cur.execute("""SELECT u.email_enc FROM tenant_memberships m JOIN users u ON u.id = m.user_id JOIN roles r ON r.id = m.role_id
                       WHERE m.tenant_id=%s AND m.status='active' AND r.is_locked""", (org_id,))
        return [crypto.decrypt(r[0], org_id, "email") for r in cur.fetchall()]


def _tell_admins(org_id, kind: str, where: str | None = None):
    for address in _admin_addresses(org_id):
        notify.security_event(address, kind, {"where": where})


def _log_both(cur, org_id, actor_id, role, action, target, detail, ip=None):
    """The event goes into the tenant's audit log and the platform's (same transaction, two chains)."""
    audit.write(cur, org_id, actor_id, role, action, target, detail, ip)
    audit.write(cur, None, actor_id, role, action, target, {**detail, "tenant": str(org_id)}, ip)


def expire_stale() -> int:
    """End sessions past their time and requests nobody answered. Without a job runner (phase 7) this runs whenever access is used or listed."""
    ended = []
    with pg.tx(platform=True) as cur:
        cur.execute("""UPDATE tenant_access_sessions SET status='ended', ended_at=now(), ended_reason='expired'
                       WHERE status='active' AND expires_at <= now() RETURNING id, tenant_id, owner_user_id""")
        ended = cur.fetchall()
        cur.execute("""UPDATE tenant_access_sessions SET status='denied', decided_at=now(), ended_reason='request expired unanswered'
                       WHERE status='requested' AND request_expires_at <= now() RETURNING id, tenant_id, owner_user_id""")
        lapsed = cur.fetchall()
        if ended:
            cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE revoked_at IS NULL AND access_session_id = ANY(%s)", ([e[0] for e in ended],))
        for sid, org, owner in ended:
            _log_both(cur, org, owner, OWNER_ROLE_NAME, "owner_access_ended", str(sid), {"reason": "expired", "access_session_id": str(sid)})
        for sid, org, owner in lapsed:
            _log_both(cur, org, owner, OWNER_ROLE_NAME, "owner_access_denied", str(sid), {"reason": "request expired unanswered", "access_session_id": str(sid)})
    for _, org, _ in ended:
        _tell_admins(org, "owner_access_ended", "it expired")
    return len(ended) + len(lapsed)


rbac.access_session_ended_hook = lambda sid: expire_stale()


def live_session(owner_id, org_id):
    """(id, expires_at) of this owner's live session in that tenant, or None."""
    with pg.tx(platform=True, actor=owner_id) as cur:
        cur.execute("""SELECT id, expires_at FROM tenant_access_sessions WHERE owner_user_id=%s AND tenant_id=%s
                       AND status='active' AND expires_at > now()""", (owner_id, org_id))
        return cur.fetchone()


def _public(r) -> dict:
    return {"id": str(r[0]), "tenant_id": str(r[1]), "tenant": r[2], "owner_user_id": str(r[3]), "reason": r[4], "status": r[5],
            "requested_at": r[6], "started_at": r[7], "expires_at": r[8], "extended": r[9], "ended_at": r[10], "ended_reason": r[11],
            "legal_hold": r[12], "request_expires_at": r[13]}


COLS = """s.id, s.tenant_id, o.legal_name, s.owner_user_id, s.reason, s.status, s.requested_at, s.started_at, s.expires_at, s.extended,
          s.ended_at, s.ended_reason, s.legal_hold, s.request_expires_at"""


# ---------------------------------------------------------------------------------------------------------------------
# the owner's side
# ---------------------------------------------------------------------------------------------------------------------
@router.post("/platform/orgs/{org_id}/access")
def request_access(org_id: uuid.UUID, body: AccessIn, request: Request, p: Principal = Depends(require("platform.tenant.access"))):
    """Ask to enter a tenant. Then call POST /session/tenant {tenant_id} to work inside it while the session is live."""
    expire_stale()
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("SELECT status, legal_name, owner_access, legal_hold FROM organizations WHERE id=%s FOR UPDATE", (org_id,))
        org = cur.fetchone()
        if not org:
            raise HTTPException(404, "Organization not found")
        status, name, mode, hold = org
        if status not in ("active", "trial"):
            raise HTTPException(409, f"This organization is {status}, so it can't be entered")
        if mode == "deny" and not hold:
            raise HTTPException(403, "This organization doesn't allow platform owners in. Only a recorded legal hold, approved by a second "
                                     "owner, overrides that")
        cur.execute("""SELECT 1 FROM tenant_access_sessions WHERE owner_user_id=%s AND tenant_id=%s
                       AND status IN ('requested','approved','active')""", (p.user_id, org_id))
        if cur.fetchone():
            raise HTTPException(409, "You already have an open request or session for this organization")
        immediate = mode == "allow" or (mode == "deny" and hold)
        if immediate:
            cur.execute("""INSERT INTO tenant_access_sessions (owner_user_id, tenant_id, reason, status, started_at, expires_at, legal_hold)
                           VALUES (%s,%s,%s,'active', now(), now() + make_interval(mins => %s), %s) RETURNING id, expires_at""",
                        (p.user_id, org_id, body.reason, SESSION_MINUTES, bool(hold and mode == "deny")))
        else:
            cur.execute("""INSERT INTO tenant_access_sessions (owner_user_id, tenant_id, reason, status, request_expires_at)
                           VALUES (%s,%s,%s,'requested', now() + make_interval(hours => %s)) RETURNING id, request_expires_at""",
                        (p.user_id, org_id, body.reason, REQUEST_HOURS))
        sid, until = cur.fetchone()
        action = "owner_access_started" if immediate else "owner_access_requested"
        _log_both(cur, org_id, p.user_id, p.role, action, str(sid),
                  {"reason": body.reason, "mode": mode, "legal_hold": bool(hold and mode == "deny"), "access_session_id": str(sid)}, p.ip)
    _tell_admins(org_id, "owner_access_started" if immediate else "owner_access_requested", f"reason given: {body.reason}")
    return {"session_id": str(sid), "status": "active" if immediate else "requested", "until": until,
            "next": "Enter the tenant with POST /session/tenant" if immediate else
                    "A Tenant admin of that organization has to approve this within 24 hours"}


@router.get("/platform/access")
def list_sessions(p: Principal = Depends(require_any("platform.tenant.access", "platform.audit.view"))):
    expire_stale()
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute(f"""SELECT {COLS} FROM tenant_access_sessions s JOIN organizations o ON o.id = s.tenant_id
                        ORDER BY s.requested_at DESC LIMIT 200""")
        return [_public(r) for r in cur.fetchall()]


@router.post("/platform/access/{sid}/extend")
def extend(sid: uuid.UUID, p: Principal = Depends(require("platform.tenant.access"))):
    """One extension of 60 minutes, for the owner who holds the session."""
    expire_stale()
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("""SELECT tenant_id, extended, expires_at FROM tenant_access_sessions
                       WHERE id=%s AND owner_user_id=%s AND status='active' FOR UPDATE""", (sid, p.user_id))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "You have no live access session with that id")
        if r[1]:
            raise HTTPException(409, "A session can be extended only once. Request access again if you still need it")
        cur.execute("""UPDATE tenant_access_sessions SET extended=true, expires_at = expires_at + make_interval(mins => %s)
                       WHERE id=%s RETURNING expires_at""", (SESSION_MINUTES, sid))
        until = cur.fetchone()[0]
        _log_both(cur, r[0], p.user_id, p.role, "owner_access_extended", str(sid), {"until": until.isoformat(), "access_session_id": str(sid)}, p.ip)
    return {"session_id": str(sid), "until": until}


def _end(sid, org_id, owner_id, why: str, by_id, by_role: str, ip=None):
    with pg.tx(platform=True) as cur:
        cur.execute("""UPDATE tenant_access_sessions SET status='ended', ended_at=now(), ended_reason=%s
                       WHERE id=%s AND status='active' RETURNING 1""", (why, sid))
        if not cur.fetchone():
            return False
        cur.execute("UPDATE refresh_tokens SET revoked_at=now() WHERE revoked_at IS NULL AND access_session_id=%s", (sid,))
        _log_both(cur, org_id, by_id, by_role, "owner_access_ended", str(sid), {"reason": why, "owner": str(owner_id), "access_session_id": str(sid)}, ip)
    _tell_admins(org_id, "owner_access_ended", why)
    return True


@router.delete("/platform/access/{sid}")
def end_early(sid: uuid.UUID, p: Principal = Depends(require("platform.tenant.access"))):
    """End a session before it expires (the owner's own, or one held by a colleague)."""
    expire_stale()
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("SELECT tenant_id, owner_user_id FROM tenant_access_sessions WHERE id=%s AND status='active'", (sid,))
        r = cur.fetchone()
    if not r or not _end(sid, r[0], r[1], "ended early by " + ("the owner" if str(r[1]) == p.user_id else "a platform owner"), p.user_id, p.role, p.ip):
        raise HTTPException(404, "No live access session with that id")
    return {"ended": str(sid)}


@router.delete("/me/access-session")
def end_my_access(p: Principal = Depends(rbac.signed_in_user)):
    """The owner ends the access session they are working in (the banner's "End access"). Self-service: it only ever touches their own."""
    if not p.access_session_id:
        raise HTTPException(404, "You are not working inside a tenant through an access session")
    if not _end(p.access_session_id, p.org_id, p.user_id, "ended by the owner from inside the tenant", p.user_id, p.role, p.ip):
        raise HTTPException(404, "That access session has already ended")
    return {"ended": p.access_session_id}


# ---------------------------------------------------------------------------------------------------------------------
# the tenant's side: its own administrators decide
# ---------------------------------------------------------------------------------------------------------------------
@router.get("/admin/access-requests")
def tenant_requests(p: Principal = Depends(require("security.manage"))):
    expire_stale()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute(f"""SELECT {COLS} FROM tenant_access_sessions s JOIN organizations o ON o.id = s.tenant_id
                        ORDER BY s.requested_at DESC LIMIT 100""")
        return [_public(r) for r in cur.fetchall()]


def _decide(sid, p: Principal, approve: bool, note: str | None):
    if p.access_session_id:
        raise HTTPException(403, "Only the organization's own administrators decide who may enter it")
    expire_stale()
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("""SELECT owner_user_id, status FROM tenant_access_sessions WHERE id=%s AND tenant_id=%s FOR UPDATE""", (sid, p.org_id))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "No such request")
        if r[1] != "requested":
            raise HTTPException(409, f"This request is already {r[1]}")
        if approve:
            cur.execute("""UPDATE tenant_access_sessions SET status='active', approved_by=%s, decided_at=now(), started_at=now(),
                           expires_at = now() + make_interval(mins => %s) WHERE id=%s RETURNING expires_at""", (p.user_id, SESSION_MINUTES, sid))
        else:
            cur.execute("""UPDATE tenant_access_sessions SET status='denied', approved_by=%s, decided_at=now(), ended_reason=%s
                           WHERE id=%s RETURNING expires_at""", (p.user_id, note or "denied", sid))
        until = cur.fetchone()[0]
        audit.write(cur, p.org_id, p.user_id, p.role, "owner_access_approved" if approve else "owner_access_denied", str(sid),
                    {"owner": str(r[0]), "note": note, "access_session_id": str(sid)}, p.ip)
    with pg.tx(platform=True) as cur:
        audit.write(cur, None, p.user_id, p.role, "owner_access_approved" if approve else "owner_access_denied", str(sid),
                    {"tenant": str(p.org_id), "owner": str(r[0]), "access_session_id": str(sid)}, p.ip)
    if approve:
        _tell_admins(p.org_id, "owner_access_started", "approved in the app")
    return {"session_id": str(sid), "status": "active" if approve else "denied", "until": until if approve else None}


@router.post("/admin/access-requests/{sid}/approve")
def approve_request(sid: uuid.UUID, p: Principal = Depends(require("security.manage"))):
    return _decide(sid, p, True, None)


@router.post("/admin/access-requests/{sid}/deny")
def deny_request(sid: uuid.UUID, body: AccessIn, p: Principal = Depends(require("security.manage"))):
    return _decide(sid, p, False, body.reason)


@router.delete("/admin/access-requests/{sid}")
def tenant_ends_session(sid: uuid.UUID, p: Principal = Depends(require("security.manage"))):
    """The tenant cuts an owner's live session short."""
    if p.access_session_id:
        raise HTTPException(403, "Only the organization's own administrators decide who may enter it")
    expire_stale()
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT owner_user_id FROM tenant_access_sessions WHERE id=%s AND tenant_id=%s AND status='active'", (sid, p.org_id))
        r = cur.fetchone()
    if not r or not _end(sid, p.org_id, r[0], "ended by the organization", p.user_id, p.role, p.ip):
        raise HTTPException(404, "No live access session with that id")
    return {"ended": str(sid)}


# ---------------------------------------------------------------------------------------------------------------------
# legal hold: a second owner's approval lets an owner into a tenant that says "deny"
# ---------------------------------------------------------------------------------------------------------------------
class HoldIn(BaseModel):
    hold: bool
    reason: str = Field(min_length=5, max_length=500)


@router.post("/platform/orgs/{org_id}/legal-hold")
def request_legal_hold(org_id: uuid.UUID, body: HoldIn, p: Principal = Depends(require("platform.tenants.manage"))):
    with pg.tx(platform=True, actor=p.actor) as cur:
        cur.execute("SELECT legal_name, legal_hold FROM organizations WHERE id=%s", (org_id,))
        org = cur.fetchone()
        if not org:
            raise HTTPException(404, "Organization not found")
        if org[1] == body.hold:
            raise HTTPException(409, "The tenant is already " + ("under a legal hold" if body.hold else "free of a legal hold"))
        return A._request_approval(cur, p, "tenant.legal_hold", {"org_id": str(org_id), "name": org[0], "hold": body.hold}, body.reason)


def _execute_legal_hold(cur, p, payload, reason, approval_id):
    cur.execute("""UPDATE organizations SET legal_hold=%s, legal_hold_reason=%s, legal_hold_at=CASE WHEN %s THEN now() END
                   WHERE id=%s""", (payload["hold"], reason if payload["hold"] else None, payload["hold"], payload["org_id"]))
    action = "legal_hold_placed" if payload["hold"] else "legal_hold_lifted"
    detail = {"reason": reason, "approval": str(approval_id)}
    A._audit(cur, p, action, payload.get("name"), detail, org_id=payload["org_id"])
    A._audit(cur, p, action, payload.get("name"), {**detail, "org_id": payload["org_id"]})
    return {"executed": "tenant.legal_hold", "hold": payload["hold"]}, None


A.EXECUTORS["tenant.legal_hold"] = _execute_legal_hold
A.APPROVAL_PERMS["tenant.legal_hold"] = "platform.tenants.manage"

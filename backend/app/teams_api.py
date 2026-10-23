"""Teams and queues (I11, optional, behind the TEAMS flag).

A Tenant admin (teams.manage) defines teams and their members. An alert can be placed in a team's queue (cases.decide). A member sees the
queues of the teams they belong to (`GET /me/teams`, `GET /alerts?team=...`). A queue only narrows what someone already sees: it never widens
`cases.view` or reaches a restricted case (row-level security still decides which alerts come back).
With the flag off every route here answers 404.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app import admin_api as A, config, pg
from app.security import audit, crypto
from app.security.rbac import Principal, require, signed_in_user

router = APIRouter()


def _on():
    if not config.teams_enabled():
        raise HTTPException(404, "Teams aren't turned on")


class TeamIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)


class MembersIn(BaseModel):
    user_ids: list[uuid.UUID] = Field(max_length=500)


class QueueIn(BaseModel):
    team_id: uuid.UUID | None = None


def _team(cur, tid):
    cur.execute("SELECT id, name FROM teams WHERE id=%s", (tid,))
    t = cur.fetchone()
    if not t:
        raise HTTPException(404, "No such team")
    return t


@router.get("/admin/teams")
def list_teams(p: Principal = Depends(require("teams.manage"))):
    _on()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT t.id, t.name, (SELECT count(*) FROM team_members m WHERE m.team_id=t.id),
                              (SELECT count(*) FROM alerts a WHERE a.team_id=t.id AND a.status='open')
                       FROM teams t ORDER BY t.name""")
        return [{"id": str(r[0]), "name": r[1], "members": r[2], "open_alerts": r[3]} for r in cur.fetchall()]


@router.post("/admin/teams")
def create_team(body: TeamIn, p: Principal = Depends(require("teams.manage"))):
    _on()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("INSERT INTO teams (org_id, name) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING id", (p.org_id, body.name.strip()))
        r = cur.fetchone()
        if not r:
            raise HTTPException(409, "A team with this name already exists")
        A._audit(cur, p, "team_created", body.name, {"team_id": str(r[0])})
    return {"id": str(r[0])}


@router.put("/admin/teams/{tid}")
def rename_team(tid: uuid.UUID, body: TeamIn, p: Principal = Depends(require("teams.manage"))):
    _on()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        old = _team(cur, tid)[1]
        cur.execute("SELECT 1 FROM teams WHERE name=%s AND id<>%s", (body.name.strip(), tid))
        if cur.fetchone():
            raise HTTPException(409, "A team with this name already exists")
        cur.execute("UPDATE teams SET name=%s WHERE id=%s", (body.name.strip(), tid))
        A._audit(cur, p, "team_renamed", body.name, {"team_id": str(tid), "from": old})
    return {"ok": True}


@router.delete("/admin/teams/{tid}")
def delete_team(tid: uuid.UUID, p: Principal = Depends(require("teams.manage"))):
    _on()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        name = _team(cur, tid)[1]
        cur.execute("DELETE FROM teams WHERE id=%s", (tid,))              # alerts in its queue fall back to no team
        A._audit(cur, p, "team_deleted", name, {"team_id": str(tid)})
    return {"deleted": str(tid)}


@router.get("/admin/teams/{tid}")
def get_team(tid: uuid.UUID, p: Principal = Depends(require("teams.manage"))):
    _on()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        t = _team(cur, tid)
        cur.execute("""SELECT m.user_id, u.name_enc, u.email_enc FROM team_members m LEFT JOIN users u ON u.id=m.user_id
                       WHERE m.team_id=%s ORDER BY m.user_id""", (tid,))
        members = [{"user_id": str(r[0]), "name": crypto.decrypt(r[1], p.org_id, "name") if r[1] else None,
                    "email": crypto.mask_email(crypto.decrypt(r[2], p.org_id, "email")) if r[2] else None} for r in cur.fetchall()]
    return {"id": str(t[0]), "name": t[1], "members": members}


@router.put("/admin/teams/{tid}/members")
def set_members(tid: uuid.UUID, body: MembersIn, p: Principal = Depends(require("teams.manage"))):
    """Replace the member list. Only active members of this tenant can be on a team."""
    _on()
    wanted = set(body.user_ids)
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        name = _team(cur, tid)[1]
        if wanted:
            cur.execute("SELECT user_id FROM tenant_memberships WHERE tenant_id=%s AND status='active' AND user_id = ANY(%s)", (p.org_id, list(wanted)))
            if {r[0] for r in cur.fetchall()} != wanted:
                raise HTTPException(422, "Everyone on a team must be an active member of this organization")
        cur.execute("SELECT user_id FROM team_members WHERE team_id=%s", (tid,))
        before = {r[0] for r in cur.fetchall()}
        cur.execute("DELETE FROM team_members WHERE team_id=%s AND NOT (user_id = ANY(%s))", (tid, list(wanted)))
        for u in wanted - before:
            cur.execute("INSERT INTO team_members (team_id, user_id, org_id) VALUES (%s,%s,%s)", (tid, u, p.org_id))
        A._audit(cur, p, "team_members_set", name, {"team_id": str(tid), "added": len(wanted - before), "removed": len(before - wanted)})
    return {"members": len(wanted)}


@router.get("/me/teams")
def my_teams(p: Principal = Depends(signed_in_user)):
    """The queues I belong to, with how many open alerts each holds that I can see."""
    _on()
    if p.org_id is None:
        return {"teams": []}
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT t.id, t.name, (SELECT count(*) FROM alerts a WHERE a.team_id=t.id AND a.status='open')
                       FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.user_id=%s ORDER BY t.name""", (p.user_id,))
        return {"teams": [{"id": str(r[0]), "name": r[1], "open_alerts": r[2]} for r in cur.fetchall()]}


def may_view_queue(cur, p: Principal, tid) -> bool:
    cur.execute("SELECT 1 FROM team_members WHERE team_id=%s AND user_id=%s", (tid, p.user_id))
    return cur.fetchone() is not None or p.can("teams.manage")


@router.put("/cases/{alert_id}/team")
def set_case_team(alert_id: str, body: QueueIn, p: Principal = Depends(require("cases.decide"))):
    """Put an alert in a team's queue (or take it out). Doesn't change who can see the case."""
    _on()
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT team_id FROM alerts WHERE id=%s FOR UPDATE", (alert_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Alert not found")
        name = None
        if body.team_id:
            name = _team(cur, body.team_id)[1]
        cur.execute("UPDATE alerts SET team_id=%s WHERE id=%s", (body.team_id, alert_id))
        audit.write(cur, p.org_id, p.user_id, p.role, "case_team_set", alert_id, {"team": name, "from": str(r[0]) if r[0] else None}, p.ip)
    return {"alert_id": alert_id, "team_id": str(body.team_id) if body.team_id else None}

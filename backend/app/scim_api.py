"""SCIM 2.0 (G13, Enterprise): the company's identity provider creates, updates and removes people and groups here.

  - A tenant admin creates a SCIM token (`POST /admin/scim/tokens`, shown once). The identity provider sends it as `Authorization: Bearer ...`;
    the token fixes the tenant, so nothing in a request can name another one.
  - Users: create, read, replace, patch, delete. `active: false` and DELETE deprovision: the membership is suspended and every session in the
    tenant ends at once (the next request is refused). Nobody is ever deleted. The last active Tenant admin can't be deprovisioned.
  - Groups map to roles (`PUT /admin/scim/groups/{id}` sets the role; a locked role can't be mapped). A person in several mapped groups gets
    the role with the most permissions; leaving all mapped groups returns them to the tenant's default role. Tenant admins are never changed
    by groups.
  - New people start without a password: they sign in through the company's identity provider (single sign-on).
"""
import re
import uuid
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from app import admin_api as A, governance, pg
from app.security import audit, crypto, tokens
from app.security.rbac import Principal, require, client_ip

router = APIRouter()
USER, GROUP, ERROR = ("urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:core:2.0:Group",
                      "urn:ietf:params:scim:api:messages:2.0:Error")
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
CT = "application/scim+json"


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        self.status, self.detail, self.scim_type = status, detail, scim_type


def scim_error_response(_request, exc: ScimError):
    body = {"schemas": [ERROR], "status": str(exc.status), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return JSONResponse(body, status_code=exc.status, media_type=CT)


def _ok(body, status=200):
    return JSONResponse(body, status_code=status, media_type=CT)


# ---------------------------------------------------------------------------------------------------------------------
# the token
# ---------------------------------------------------------------------------------------------------------------------
def scim_auth(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer sct_"):
        raise ScimError(401, "A SCIM token is required")
    key = auth.removeprefix("Bearer ")
    prefix = "_".join(key.split("_")[:2])
    with pg.pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT tenant_id, token_hash FROM scim_token_lookup(%s)", (prefix,))
        row = cur.fetchone()
    if not row or not crypto.hmac.compare_digest(bytes(row[1]), crypto.sha256(key)):
        raise ScimError(401, "Invalid SCIM token")
    org = str(row[0])
    with pg.tx(org) as cur:
        cur.execute("SELECT status FROM organizations WHERE id=%s", (org,))
        status = cur.fetchone()
        cur.execute("SELECT 1 FROM org_features WHERE feature='scim' AND in_plan AND enabled")
        on = cur.fetchone()
        if status and status[0] in ("active", "trial") and on:
            cur.execute("UPDATE scim_tokens SET last_used_at=now() WHERE prefix=%s AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')", (prefix,))
    if not status or status[0] not in ("active", "trial"):
        raise ScimError(403, "This organization isn't active")
    if not on:
        raise ScimError(403, "SCIM isn't turned on for this organization")
    return SimpleNamespace(org=org, prefix=prefix, ip=client_ip(request))


scim_auth.sentrail_kind, scim_auth.sentrail_perms = "scim", ("scim",)


# ---------------------------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------------------------
def _filter_value(filter_: str | None, attr: str) -> str | None:
    if not filter_:
        return None
    m = re.fullmatch(rf'\s*{attr}\s+eq\s+"([^"]*)"\s*', filter_, re.I)
    if not m:
        raise ScimError(400, f'Only filters like {attr} eq "value" are supported', "invalidFilter")
    return m.group(1)


def _truthy(v) -> bool:
    return v if isinstance(v, bool) else str(v).strip().lower() == "true"


def _page(request: Request):
    q = request.query_params
    try:
        start, count = max(int(q.get("startIndex", 1)), 1), min(max(int(q.get("count", 100)), 0), 200)
    except ValueError:
        raise ScimError(400, "startIndex and count must be numbers", "invalidValue")
    return start, count


def _user_json(org, row, groups=()):
    uid, email_enc, name_enc, status, ext, role = row
    email, name = crypto.decrypt(email_enc, org, "email"), crypto.decrypt(name_enc, org, "name")
    return {"schemas": [USER], "id": str(uid), "externalId": ext, "userName": email, "displayName": name, "name": {"formatted": name},
            "emails": [{"value": email, "primary": True}], "active": status == "active",
            "groups": [{"value": str(g[0]), "display": g[1]} for g in groups], "meta": {"resourceType": "User"}}


USER_COLS = "u.id, u.email_enc, u.name_enc, m.status, u.scim_external_id, m.role_id"
USER_FROM = "FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=u.org_id"


def _groups_of(cur, uid):
    cur.execute("SELECT g.id, g.display_name FROM scim_group_members x JOIN scim_groups g ON g.id=x.group_id WHERE x.user_id=%s", (uid,))
    return cur.fetchall()


def _get_user(cur, org, uid):
    try:
        uid = uuid.UUID(str(uid))
    except ValueError:
        raise ScimError(404, "No such user")
    cur.execute(f"SELECT {USER_COLS} {USER_FROM} WHERE u.id=%s AND u.org_id=%s", (uid, org))
    r = cur.fetchone()
    if not r:
        raise ScimError(404, "No such user")
    return r


def _name_of(body) -> str | None:
    n = body.get("name") or {}
    return (body.get("displayName") or n.get("formatted") or " ".join(x for x in (n.get("givenName"), n.get("familyName")) if x) or None)


def _deprovision(cur, org, uid, ctx, why="scim"):
    if governance._is_last_admin(cur, uuid.UUID(org), uuid.UUID(str(uid))):
        raise ScimError(409, "The last active administrator can't be deprovisioned. Appoint another one first", "mutability")
    if governance.set_membership(cur, org, uid, status="suspended"):
        governance.provider_disable(cur, org, uid)
        audit.write(cur, org, None, "scim", "scim_user_deprovisioned", str(uid), {"sessions_ended": True, "via": why}, ctx.ip)


def _reactivate(cur, org, uid, ctx):
    try:
        A._require_seat(cur, org)
    except HTTPException as e:
        raise ScimError(409, e.detail, "mutability")
    governance.set_membership(cur, org, uid, status="active")
    audit.write(cur, org, None, "scim", "scim_user_reactivated", str(uid), {}, ctx.ip)


def _recompute_roles(cur, org, user_ids, ctx):
    """Role from the groups a person is in (see the module note). Never touches a locked role (Tenant admins)."""
    cur.execute("SELECT sso_default_role_id FROM organizations WHERE id=%s", (org,))
    default = cur.fetchone()[0]
    for uid in user_ids:
        cur.execute("""SELECT m.role_id, r.is_locked FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.tenant_id=%s AND m.user_id=%s""", (org, uid))
        cur_role = cur.fetchone()
        if not cur_role or cur_role[1]:
            continue
        cur.execute("""SELECT g.role_id FROM scim_group_members x JOIN scim_groups g ON g.id=x.group_id
                       LEFT JOIN role_permissions rp ON rp.role_id=g.role_id
                       WHERE x.user_id=%s AND g.role_id IS NOT NULL GROUP BY g.role_id ORDER BY count(rp.perm) DESC, g.role_id LIMIT 1""", (uid,))
        r = cur.fetchone()
        target = r[0] if r else default
        if target and target != cur_role[0]:
            governance.set_membership(cur, org, uid, role_id=target)
            audit.write(cur, org, None, "scim", "scim_role_assigned", str(uid), {"role_id": str(target), "from_groups": bool(r)}, ctx.ip)


# ---------------------------------------------------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------------------------------------------------
@router.get("/scim/v2/ServiceProviderConfig")
def service_provider_config(ctx=Depends(scim_auth)):
    return _ok({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True}, "bulk": {"supported": False}, "filter": {"supported": True, "maxResults": 200},
                "changePassword": {"supported": False}, "sort": {"supported": False}, "etag": {"supported": False},
                "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "A SCIM token from the Security screen"}]})


@router.get("/scim/v2/ResourceTypes")
def resource_types(ctx=Depends(scim_auth)):
    return _ok({"schemas": [LIST], "totalResults": 2, "Resources": [
        {"id": "User", "name": "User", "endpoint": "/Users", "schema": USER},
        {"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": GROUP}]})


# ---------------------------------------------------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------------------------------------------------
@router.get("/scim/v2/Users")
def list_users(request: Request, ctx=Depends(scim_auth)):
    username = _filter_value(request.query_params.get("filter"), "userName")
    start, count = _page(request)
    with pg.tx(ctx.org) as cur:
        where, args = "WHERE u.org_id=%s", [ctx.org]
        if username is not None:
            where += " AND u.email_bidx=%s"
            args.append(crypto.blind_index(username))
        cur.execute(f"SELECT count(*) {USER_FROM} {where}", args)
        total = cur.fetchone()[0]
        cur.execute(f"SELECT {USER_COLS} {USER_FROM} {where} ORDER BY m.created_at, u.id OFFSET %s LIMIT %s", args + [start - 1, count])
        rows = [_user_json(ctx.org, r, _groups_of(cur, r[0])) for r in cur.fetchall()]
    return _ok({"schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": len(rows), "Resources": rows})


@router.get("/scim/v2/Users/{uid}")
def get_user(uid: str, ctx=Depends(scim_auth)):
    with pg.tx(ctx.org) as cur:
        r = _get_user(cur, ctx.org, uid)
        return _ok(_user_json(ctx.org, r, _groups_of(cur, r[0])))


@router.post("/scim/v2/Users")
def create_user(body: dict, ctx=Depends(scim_auth)):
    email = (body.get("userName") or ((body.get("emails") or [{}])[0].get("value")) or "").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ScimError(400, "userName must be an email address", "invalidValue")
    name = _name_of(body) or email.split("@")[0]
    active = _truthy(body.get("active", True))
    with pg.tx(ctx.org) as cur:
        cur.execute("SELECT id FROM auth_lookup(%s)", (crypto.blind_index(email),))
        if cur.fetchone():
            raise ScimError(409, "A person with that email already exists", "uniqueness")
        cur.execute("SELECT sso_default_role_id FROM organizations WHERE id=%s", (ctx.org,))
        role = cur.fetchone()[0]
        if not role:
            raise ScimError(400, "Choose a default role for new people under Security > Single sign-on first", "invalidValue")
        if active:
            try:
                A._require_seat(cur, ctx.org)
            except HTTPException as e:
                raise ScimError(409, e.detail, "mutability")
        cur.execute("""INSERT INTO users (org_id, role_id, email_enc, email_bidx, name_enc, status, auth_method, scim_external_id)
                       VALUES (%s,%s,%s,%s,%s,%s,'keycloak',%s) RETURNING id""",
                    (ctx.org, role, crypto.encrypt(crypto.normalize_email(email), ctx.org, "email"), crypto.blind_index(email),
                     crypto.encrypt(name, ctx.org, "name"), "active" if active else "suspended", body.get("externalId")))
        uid = cur.fetchone()[0]
        cur.execute("UPDATE tenant_memberships SET status=%s WHERE user_id=%s AND tenant_id=%s", ("active" if active else "suspended", uid, ctx.org))
        audit.write(cur, ctx.org, None, "scim", "scim_user_created", crypto.mask_email(email), {"user_id": str(uid), "active": active}, ctx.ip)
        return _ok(_user_json(ctx.org, _get_user(cur, ctx.org, uid)), 201)


def _apply_user_changes(cur, ctx, uid, changes: dict):
    """changes: any of userName, name (display name), externalId, active."""
    if "active" in changes:
        cur.execute("SELECT status FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s", (uid, ctx.org))
        was = cur.fetchone()[0]
        if changes["active"] and was != "active":
            _reactivate(cur, ctx.org, uid, ctx)
        elif not changes["active"] and was == "active":
            _deprovision(cur, ctx.org, uid, ctx)
    if "userName" in changes:
        email = changes["userName"].strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ScimError(400, "userName must be an email address", "invalidValue")
        cur.execute("SELECT id FROM auth_lookup(%s)", (crypto.blind_index(email),))
        other = cur.fetchone()
        if other and str(other[0]) != str(uid):
            raise ScimError(409, "A person with that email already exists", "uniqueness")
        cur.execute("UPDATE users SET email_enc=%s, email_bidx=%s WHERE id=%s", (crypto.encrypt(crypto.normalize_email(email), ctx.org, "email"),
                                                                              crypto.blind_index(email), uid))
        audit.write(cur, ctx.org, None, "scim", "scim_user_updated", str(uid), {"field": "userName"}, ctx.ip)
    if "name" in changes and changes["name"]:
        cur.execute("UPDATE users SET name_enc=%s WHERE id=%s", (crypto.encrypt(changes["name"], ctx.org, "name"), uid))
    if "externalId" in changes:
        cur.execute("UPDATE users SET scim_external_id=%s WHERE id=%s", (changes["externalId"], uid))


@router.put("/scim/v2/Users/{uid}")
def replace_user(uid: str, body: dict, ctx=Depends(scim_auth)):
    with pg.tx(ctx.org) as cur:
        r = _get_user(cur, ctx.org, uid)
        changes = {"userName": body.get("userName") or crypto.decrypt(r[1], ctx.org, "email"), "name": _name_of(body),
                   "externalId": body.get("externalId"), "active": _truthy(body.get("active", True))}
        _apply_user_changes(cur, ctx, r[0], changes)
        return _ok(_user_json(ctx.org, _get_user(cur, ctx.org, uid), _groups_of(cur, r[0])))


@router.patch("/scim/v2/Users/{uid}")
def patch_user(uid: str, body: dict, ctx=Depends(scim_auth)):
    ops = body.get("Operations") or body.get("operations") or []
    if not ops:
        raise ScimError(400, "No operations", "invalidSyntax")
    changes = {}
    for op in ops:
        if str(op.get("op", "")).lower() not in ("replace", "add"):
            raise ScimError(400, "Only add and replace are supported for users", "invalidSyntax")
        path, value = op.get("path"), op.get("value")
        pairs = value.items() if not path and isinstance(value, dict) else [(path, value)]
        for k, v in pairs:
            k = (k or "").strip()
            if k == "active":
                changes["active"] = _truthy(v)
            elif k == "userName":
                changes["userName"] = str(v)
            elif k in ("displayName", "name.formatted"):
                changes["name"] = str(v)
            elif k == "externalId":
                changes["externalId"] = str(v)
            elif k == "name" and isinstance(v, dict):
                changes["name"] = _name_of({"name": v})
    with pg.tx(ctx.org) as cur:
        r = _get_user(cur, ctx.org, uid)
        _apply_user_changes(cur, ctx, r[0], changes)
        return _ok(_user_json(ctx.org, _get_user(cur, ctx.org, uid), _groups_of(cur, r[0])))


@router.delete("/scim/v2/Users/{uid}")
def delete_user(uid: str, ctx=Depends(scim_auth)):
    """Deprovision: the person is suspended and signed out everywhere, never deleted (their audit trail stays attributable)."""
    with pg.tx(ctx.org) as cur:
        r = _get_user(cur, ctx.org, uid)
        if r[3] == "active":
            _deprovision(cur, ctx.org, r[0], ctx, why="delete")
    return Response(status_code=204)


# ---------------------------------------------------------------------------------------------------------------------
# groups
# ---------------------------------------------------------------------------------------------------------------------
def _group_json(cur, org, g):
    cur.execute("SELECT u.id, u.email_enc FROM scim_group_members x JOIN users u ON u.id=x.user_id WHERE x.group_id=%s ORDER BY u.id", (g[0],))
    members = [{"value": str(r[0]), "display": crypto.decrypt(r[1], org, "email")} for r in cur.fetchall()]
    return {"schemas": [GROUP], "id": str(g[0]), "displayName": g[1], "externalId": g[2], "members": members, "meta": {"resourceType": "Group"}}


def _get_group(cur, org, gid):
    try:
        gid = uuid.UUID(str(gid))
    except ValueError:
        raise ScimError(404, "No such group")
    cur.execute("SELECT id, display_name, external_id FROM scim_groups WHERE id=%s AND tenant_id=%s", (gid, org))
    g = cur.fetchone()
    if not g:
        raise ScimError(404, "No such group")
    return g


def _set_members(cur, org, gid, ids, ctx):
    """Replace the member list. Only people of this tenant can be members."""
    wanted = set()
    for i in ids:
        try:
            wanted.add(uuid.UUID(str(i)))
        except ValueError:
            raise ScimError(400, f"{i} isn't a user id", "invalidValue")
    if wanted:
        cur.execute("SELECT id FROM users WHERE id = ANY(%s) AND org_id=%s", (list(wanted), org))
        found = {r[0] for r in cur.fetchall()}
        if found != wanted:
            raise ScimError(400, "A member isn't a person in this organization", "invalidValue")
    cur.execute("SELECT user_id FROM scim_group_members WHERE group_id=%s", (gid,))
    before = {r[0] for r in cur.fetchall()}
    cur.execute("DELETE FROM scim_group_members WHERE group_id=%s AND NOT (user_id = ANY(%s))", (gid, list(wanted)))
    for u in wanted - before:
        cur.execute("INSERT INTO scim_group_members (group_id, user_id, tenant_id) VALUES (%s,%s,%s)", (gid, u, org))
    _recompute_roles(cur, org, before ^ wanted, ctx)


@router.get("/scim/v2/Groups")
def list_groups(request: Request, ctx=Depends(scim_auth)):
    name = _filter_value(request.query_params.get("filter"), "displayName")
    start, count = _page(request)
    with pg.tx(ctx.org) as cur:
        cur.execute("""SELECT id, display_name, external_id FROM scim_groups WHERE tenant_id=%s AND (%s::text IS NULL OR display_name=%s)
                       ORDER BY display_name OFFSET %s LIMIT %s""", (ctx.org, name, name, start - 1, count))
        rows = [_group_json(cur, ctx.org, g) for g in cur.fetchall()]
        cur.execute("SELECT count(*) FROM scim_groups WHERE tenant_id=%s AND (%s::text IS NULL OR display_name=%s)", (ctx.org, name, name))
        total = cur.fetchone()[0]
    return _ok({"schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": len(rows), "Resources": rows})


@router.get("/scim/v2/Groups/{gid}")
def get_group(gid: str, ctx=Depends(scim_auth)):
    with pg.tx(ctx.org) as cur:
        return _ok(_group_json(cur, ctx.org, _get_group(cur, ctx.org, gid)))


@router.post("/scim/v2/Groups")
def create_group(body: dict, ctx=Depends(scim_auth)):
    name = (body.get("displayName") or "").strip()
    if not name:
        raise ScimError(400, "displayName is required", "invalidValue")
    with pg.tx(ctx.org) as cur:
        cur.execute("SELECT 1 FROM scim_groups WHERE tenant_id=%s AND display_name=%s", (ctx.org, name))
        if cur.fetchone():
            raise ScimError(409, "A group with that name exists", "uniqueness")
        cur.execute("INSERT INTO scim_groups (tenant_id, display_name, external_id) VALUES (%s,%s,%s) RETURNING id, display_name, external_id",
                    (ctx.org, name, body.get("externalId")))
        g = cur.fetchone()
        _set_members(cur, ctx.org, g[0], [m.get("value") for m in body.get("members") or []], ctx)
        audit.write(cur, ctx.org, None, "scim", "scim_group_created", name, {"group_id": str(g[0])}, ctx.ip)
        return _ok(_group_json(cur, ctx.org, g), 201)


@router.put("/scim/v2/Groups/{gid}")
def replace_group(gid: str, body: dict, ctx=Depends(scim_auth)):
    with pg.tx(ctx.org) as cur:
        g = _get_group(cur, ctx.org, gid)
        name = (body.get("displayName") or g[1]).strip()
        cur.execute("UPDATE scim_groups SET display_name=%s, external_id=%s WHERE id=%s", (name, body.get("externalId"), g[0]))
        _set_members(cur, ctx.org, g[0], [m.get("value") for m in body.get("members") or []], ctx)
        audit.write(cur, ctx.org, None, "scim", "scim_group_updated", name, {"group_id": str(g[0])}, ctx.ip)
        return _ok(_group_json(cur, ctx.org, _get_group(cur, ctx.org, gid)))


@router.patch("/scim/v2/Groups/{gid}")
def patch_group(gid: str, body: dict, ctx=Depends(scim_auth)):
    ops = body.get("Operations") or body.get("operations") or []
    if not ops:
        raise ScimError(400, "No operations", "invalidSyntax")
    with pg.tx(ctx.org) as cur:
        g = _get_group(cur, ctx.org, gid)
        cur.execute("SELECT user_id FROM scim_group_members WHERE group_id=%s", (g[0],))
        members = {str(r[0]) for r in cur.fetchall()}
        for op in ops:
            kind, path, value = str(op.get("op", "")).lower(), (op.get("path") or ""), op.get("value")
            if path == "members" and kind == "add":
                members |= {m["value"] for m in value or []}
            elif path == "members" and kind == "replace":
                members = {m["value"] for m in value or []}
            elif path == "members" and kind == "remove" and value:
                members -= {m["value"] for m in value}
            elif path == "members" and kind == "remove":
                members = set()
            elif kind == "remove" and path.startswith("members["):
                m = re.search(r'value\s+eq\s+"([^"]+)"', path)
                if m:
                    members.discard(m.group(1))
            elif path == "displayName" and kind in ("replace", "add"):
                cur.execute("UPDATE scim_groups SET display_name=%s WHERE id=%s", (str(value).strip(), g[0]))
            elif not path and isinstance(value, dict) and "displayName" in value:
                cur.execute("UPDATE scim_groups SET display_name=%s WHERE id=%s", (str(value["displayName"]).strip(), g[0]))
            else:
                raise ScimError(400, "Unsupported operation", "invalidSyntax")
        _set_members(cur, ctx.org, g[0], list(members), ctx)
        audit.write(cur, ctx.org, None, "scim", "scim_group_updated", g[1], {"group_id": str(g[0])}, ctx.ip)
        return _ok(_group_json(cur, ctx.org, _get_group(cur, ctx.org, gid)))


@router.delete("/scim/v2/Groups/{gid}")
def delete_group(gid: str, ctx=Depends(scim_auth)):
    with pg.tx(ctx.org) as cur:
        g = _get_group(cur, ctx.org, gid)
        cur.execute("SELECT user_id FROM scim_group_members WHERE group_id=%s", (g[0],))
        members = [r[0] for r in cur.fetchall()]
        cur.execute("DELETE FROM scim_groups WHERE id=%s", (g[0],))
        _recompute_roles(cur, ctx.org, members, ctx)
        audit.write(cur, ctx.org, None, "scim", "scim_group_deleted", g[1], {"group_id": str(g[0])}, ctx.ip)
    return Response(status_code=204)


# ---------------------------------------------------------------------------------------------------------------------
# administration (Tenant admins)
# ---------------------------------------------------------------------------------------------------------------------
class TokenIn(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class GroupRoleIn(BaseModel):
    role_id: uuid.UUID | None = None


@router.post("/admin/scim/tokens")
def create_token(body: TokenIn, request: Request, p: Principal = Depends(require("security.manage", feature="scim"))):
    prefix = "sct_" + tokens.new_opaque()[:8].replace("_", "x").replace("-", "x")
    raw = f"{prefix}_{tokens.new_opaque()}"
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("INSERT INTO scim_tokens (tenant_id, prefix, token_hash, label, created_by) VALUES (%s,%s,%s,%s,%s)",
                    (p.org_id, prefix, crypto.sha256(raw), body.label, p.user_id))
        A._audit(cur, p, "scim_token_created", prefix, {"label": body.label})
    return {"token": raw, "prefix": prefix, "base_url": f"{A.APP_URL}/scim/v2", "message": "Copy the token now. It is not shown again"}


@router.get("/admin/scim/tokens")
def list_tokens(p: Principal = Depends(require("security.manage", feature="scim"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT prefix, label, created_at, last_used_at, revoked_at FROM scim_tokens ORDER BY created_at DESC")
        return {"base_url": f"{A.APP_URL}/scim/v2",
                "tokens": [dict(zip(["prefix", "label", "created_at", "last_used_at", "revoked_at"], r)) for r in cur.fetchall()]}


@router.delete("/admin/scim/tokens/{prefix}")
def revoke_token(prefix: str, p: Principal = Depends(require("security.manage", feature="scim"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("UPDATE scim_tokens SET revoked_at=now() WHERE prefix=%s AND revoked_at IS NULL RETURNING 1", (prefix,))
        if not cur.fetchone():
            raise HTTPException(404, "No active token with that prefix")
        A._audit(cur, p, "scim_token_revoked", prefix)
    return {"revoked": prefix}


@router.get("/admin/scim/groups")
def list_group_roles(p: Principal = Depends(require("security.manage", feature="scim"))):
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("""SELECT g.id, g.display_name, g.role_id, r.name, (SELECT count(*) FROM scim_group_members x WHERE x.group_id=g.id)
                       FROM scim_groups g LEFT JOIN roles r ON r.id=g.role_id ORDER BY g.display_name""")
        return [{"id": str(r[0]), "name": r[1], "role_id": str(r[2]) if r[2] else None, "role": r[3], "members": r[4]} for r in cur.fetchall()]


@router.put("/admin/scim/groups/{gid}")
def set_group_role(gid: uuid.UUID, body: GroupRoleIn, p: Principal = Depends(require("security.manage", feature="scim"))):
    ctx = SimpleNamespace(ip=p.ip)
    with pg.tx(p.org_id, actor=p.actor, access_session=p.access_session_id) as cur:
        cur.execute("SELECT display_name FROM scim_groups WHERE id=%s", (gid,))
        g = cur.fetchone()
        if not g:
            raise HTTPException(404, "No such group")
        if body.role_id:
            cur.execute("SELECT is_locked FROM roles WHERE id=%s AND org_id=%s", (body.role_id, p.org_id))
            r = cur.fetchone()
            if not r:
                raise HTTPException(422, "That role doesn't exist in this organization")
            if r[0]:
                raise HTTPException(422, "The Tenant admin role can't be given through a group. Appoint admins directly")
        cur.execute("UPDATE scim_groups SET role_id=%s WHERE id=%s", (body.role_id, gid))
        cur.execute("SELECT user_id FROM scim_group_members WHERE group_id=%s", (gid,))
        _recompute_roles(cur, p.org_id, [r[0] for r in cur.fetchall()], ctx)
        A._audit(cur, p, "scim_group_role_set", g[0], {"role_id": str(body.role_id) if body.role_id else None})
    return {"id": str(gid), "role_id": str(body.role_id) if body.role_id else None}

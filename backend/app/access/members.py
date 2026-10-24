"""People and their place in a tenant (or on the platform team): the one module that creates and changes memberships.

A person is a row in `users` (identity, credentials, two-factor, account status). What they may do, and where, lives only in
`tenant_memberships` (one per tenant) and `platform_staff` (the platform team): role and status per place. `users.org_id` is just the
person's home tenant (where their identity row sits for row-level security); it grants nothing.

`org` is a tenant id, or None for the platform team. Callers pass a cursor already scoped to that tenant (or to the platform).
"""


def create_person(cur, org, role_id, *, email_enc, email_bidx, name_enc=None, status="active", extra: dict | None = None,
                  invited_by=None) -> str:
    """Create the person and their membership / staff row. `extra` are further users columns (idp_subject, auth_method, break_glass ...)."""
    cols = {"org_id": org, "email_enc": email_enc, "email_bidx": email_bidx, "status": status, **({"name_enc": name_enc} if name_enc else {}),
            **(extra or {})}
    cur.execute(f"INSERT INTO users ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id", list(cols.values()))
    uid = cur.fetchone()[0]
    if org is None:
        cur.execute("INSERT INTO platform_staff (user_id, role_id, status) VALUES (%s,%s,%s)", (uid, role_id, status))
    else:
        cur.execute("INSERT INTO tenant_memberships (user_id, tenant_id, role_id, status, invited_by) VALUES (%s,%s,%s,%s,%s)",
                    (uid, org, role_id, status, invited_by))
    return uid


def person_role(cur, uid, org):
    """(role_id, status) of this person in that tenant (or on the platform team), or None."""
    if org is None:
        cur.execute("SELECT role_id, status FROM platform_staff WHERE user_id=%s", (uid,))
    else:
        cur.execute("SELECT role_id, status FROM tenant_memberships WHERE user_id=%s AND tenant_id=%s", (uid, org))
    return cur.fetchone()


def role_name(cur, uid, org):
    if org is None:
        cur.execute("SELECT r.name FROM platform_staff s JOIN roles r ON r.id=s.role_id WHERE s.user_id=%s", (uid,))
    else:
        cur.execute("SELECT r.name FROM tenant_memberships m JOIN roles r ON r.id=m.role_id WHERE m.user_id=%s AND m.tenant_id=%s", (uid, org))
    r = cur.fetchone()
    return r[0] if r else None


def holds_role(cur, uid, role_id) -> bool:
    """Does this person hold this role anywhere? (Used for 'you can't change the permissions of your own role'.)"""
    cur.execute("""SELECT 1 FROM tenant_memberships WHERE user_id=%s AND role_id=%s
                   UNION ALL SELECT 1 FROM platform_staff WHERE user_id=%s AND role_id=%s LIMIT 1""", (uid, role_id, uid, role_id))
    return cur.fetchone() is not None


def active_holders(cur, role_id, org=None) -> list:
    """Ids of the people whose active membership (or platform staff row, org None) holds this role."""
    if org is None:
        cur.execute("SELECT user_id FROM platform_staff WHERE role_id=%s AND status='active'", (role_id,))
    else:
        cur.execute("SELECT user_id FROM tenant_memberships WHERE role_id=%s AND tenant_id=%s AND status='active'", (role_id, org))
    return [r[0] for r in cur.fetchall()]


def bump(cur, uids):
    """End the sessions of these people (their next request reloads permissions). Only those whose identity row this scope can see."""
    uids = list(uids)
    if uids:
        cur.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ANY(%s)", (uids,))


def bump_role_holders(cur, role_id, org=None):
    bump(cur, active_holders(cur, role_id, org))


def set_role(cur, uid, org, role_id) -> bool:
    if org is None:
        cur.execute("UPDATE platform_staff SET role_id=%s WHERE user_id=%s", (role_id, uid))
    else:
        cur.execute("UPDATE tenant_memberships SET role_id=%s WHERE user_id=%s AND tenant_id=%s", (role_id, uid, org))
    changed = cur.rowcount > 0
    bump(cur, [uid])
    return changed


def set_status(cur, uid, org, status) -> bool:
    """Change the status of the membership (or staff row). The account's own status follows: it is 'suspended' when the person has no
    active place left (so they can't sign in at all), 'active' as soon as they have one."""
    if org is None:
        cur.execute("UPDATE platform_staff SET status=%s WHERE user_id=%s", (status, uid))
    else:
        cur.execute("""UPDATE tenant_memberships SET status=%s, reactivated_at = CASE WHEN %s='active' THEN now() ELSE reactivated_at END
                       WHERE user_id=%s AND tenant_id=%s""", (status, status, uid, org))
    changed = cur.rowcount > 0
    cur.execute("""UPDATE users SET session_version = session_version + 1,
                     status = CASE WHEN status = 'invited' THEN status WHEN person_has_active_place(users.id) THEN 'active' ELSE 'suspended' END
                   WHERE id=%s""", (uid,))
    if status != "active":
        # sessions in this place end at once; when the person has no active place left, every session does
        cur.execute("""UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL
                       AND (%s::uuid IS NULL OR tenant_id = %s OR NOT person_has_active_place(user_id))""", (uid, org, org))
    return changed


def activate(cur, uid, org):
    """First sign-in or accepted invitation: the membership (or staff row) and the account become active. No session bump (a session is being issued)."""
    if org is None:
        cur.execute("UPDATE platform_staff SET status='active' WHERE user_id=%s AND status='invited'", (uid,))
    else:
        cur.execute("UPDATE tenant_memberships SET status='active' WHERE user_id=%s AND tenant_id=%s AND status='invited'", (uid, org))
    cur.execute("UPDATE users SET status='active' WHERE id=%s AND status='invited'", (uid,))

"""Case data on PostgreSQL, always scoped to the caller's organization (row-level security).
STR text is encrypted like other personal data.

Alert lifecycle (enforced here, and the status values by a CHECK constraint):

    open ─┬─ false_positive ─▶ closed
          ├─ request_info ───▶ pending_info ─▶ (same three decisions)
          └─ escalate ───────▶ escalated ─▶ STR submitted ─▶ awaiting_approval ─▶ approved ─▶ str_filed

Closed and filed alerts are final.
"""
import json
from app import pg
from app.security import audit as auditlog, crypto

DECIDABLE = ("open", "pending_info")
DECISION_STATUS = {"false_positive": "closed", "request_info": "pending_info", "escalate": "escalated"}
STR_SUBMITTABLE = ("escalated", "awaiting_approval")   # awaiting_approval = revise a submitted draft


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def audit(p, action: str, target: str, detail: dict | str = ""):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        auditlog.write(cur, p.org_id, p.user_id if p.kind == "user" else None, p.role, action, target,
                       detail if isinstance(detail, dict) else {"note": detail}, p.ip)


def save_alert(org_id, a: dict):
    with pg.tx(org_id) as cur:
        cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, status, screening_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (org_id, id) DO UPDATE SET score=EXCLUDED.score, band=EXCLUDED.band, reasons=EXCLUDED.reasons""",
                    (a["id"], org_id, a["customer_id"], a["score"], a["band"], json.dumps(a["reasons"]),
                     a["channel"], a.get("status", "open"), a.get("screening_id")))


ALERT_COLS = ["id", "customer_id", "score", "band", "reasons", "channel", "status", "created_at", "assigned_to", "screening_id", "restricted"]


def list_alerts(p, band=None, status="open"):
    q, args = f"SELECT {', '.join(ALERT_COLS)} FROM alerts WHERE status=%s", [status]
    if band:
        q += " AND band=%s"; args.append(band)
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute(q + " ORDER BY score DESC LIMIT 500", args)
        return [_alert(r) for r in cur.fetchall()]


def _alert(r) -> dict:
    a = dict(zip(ALERT_COLS, r))
    a["assigned_to"] = str(a["assigned_to"]) if a["assigned_to"] else None
    return a


def get_alert(p, alert_id):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute(f"SELECT {', '.join(ALERT_COLS)} FROM alerts WHERE id=%s", (alert_id,))
        r = cur.fetchone()
    return _alert(r) if r else None


def decide(p, alert_id, decision: str, reason: str) -> str:
    """Apply an analyst decision. Raises NotFound or Conflict; audits inside the same transaction."""
    new = DECISION_STATUS[decision]
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT status FROM alerts WHERE id=%s FOR UPDATE", (alert_id,))
        r = cur.fetchone()
        if not r:
            raise NotFound(alert_id)
        if r[0] not in DECIDABLE:
            raise Conflict(f"This alert is {r[0].replace('_', ' ')} and can't be decided again")
        cur.execute("UPDATE alerts SET status=%s WHERE id=%s", (new, alert_id))
        auditlog.write(cur, p.org_id, p.user_id, p.role, f"decision:{decision}", alert_id,
                       {"reason": reason, "from": r[0], "to": new}, p.ip)
    return new


def assign(p, alert_id, user_id) -> None:
    with pg.tx(p.org_id, actor=p.actor) as cur:
        if user_id:
            cur.execute("""SELECT 1 FROM users u JOIN role_permissions rp ON rp.role_id=u.role_id
                           WHERE u.id=%s AND u.status='active' AND rp.perm='cases.decide'""", (user_id,))
            if not cur.fetchone():
                raise Conflict("That person can't work cases")
        cur.execute("UPDATE alerts SET assigned_to=%s WHERE id=%s RETURNING 1", (user_id, alert_id))
        if not cur.fetchone():
            raise NotFound(alert_id)
        auditlog.write(cur, p.org_id, p.user_id, p.role, "case_assigned", alert_id, {"to": user_id}, p.ip)


def set_status(p, alert_id, status):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("UPDATE alerts SET status=%s WHERE id=%s", (status, alert_id))


def save_ai_draft(p, alert_id, text):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("""INSERT INTO str_drafts (org_id, alert_id, ai_draft_enc, drafted_by) VALUES (%s,%s,%s,%s)
                       ON CONFLICT (org_id, alert_id) DO UPDATE SET ai_draft_enc=EXCLUDED.ai_draft_enc, updated_at=now()""",
                    (p.org_id, alert_id, crypto.encrypt(text, p.org_id, "str"), p.user_id))


def submit_str(p, alert_id, final_text):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT status FROM alerts WHERE id=%s FOR UPDATE", (alert_id,))
        r = cur.fetchone()
        if not r:
            raise NotFound(alert_id)
        if r[0] not in STR_SUBMITTABLE:
            raise Conflict("Escalate the alert before submitting an STR" if r[0] in DECIDABLE
                           else f"This alert is {r[0].replace('_', ' ')}; an STR can't be submitted")
        cur.execute("""INSERT INTO str_drafts (org_id, alert_id, final_enc, drafted_by, status)
                       VALUES (%s,%s,%s,%s,'awaiting_approval')
                       ON CONFLICT (org_id, alert_id) DO UPDATE SET final_enc=EXCLUDED.final_enc,
                       drafted_by=EXCLUDED.drafted_by, status='awaiting_approval', updated_at=now()""",
                    (p.org_id, alert_id, crypto.encrypt(final_text, p.org_id, "str"), p.user_id))
        cur.execute("UPDATE alerts SET status='awaiting_approval' WHERE id=%s", (alert_id,))
        auditlog.write(cur, p.org_id, p.user_id, p.role, "str_submitted", alert_id, {}, p.ip)


def get_str(p, alert_id) -> dict | None:
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("""SELECT ai_draft_enc, final_enc, drafted_by, approved_by, status, updated_at
                       FROM str_drafts WHERE alert_id=%s""", (alert_id,))
        r = cur.fetchone()
        if r:        # reading a suspicious transaction report is a sensitive read: who, when, which case
            auditlog.write(cur, p.org_id, p.user_id if p.kind == "user" else None, p.role, "str_viewed", alert_id, {}, p.ip)
    if not r:
        return None
    return {"ai_draft": crypto.decrypt(r[0], p.org_id, "str"), "final_text": crypto.decrypt(r[1], p.org_id, "str"),
            "drafted_by": str(r[2]) if r[2] else None, "approved_by": str(r[3]) if r[3] else None,
            "status": r[4], "updated_at": r[5]}


def approve_str(p, alert_id) -> bool:
    """Four-eyes: the database CHECK rejects approval by the drafter as a second line of defence."""
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("""SELECT d.drafted_by FROM str_drafts d JOIN alerts a ON a.org_id=d.org_id AND a.id=d.alert_id
                       WHERE d.alert_id=%s AND d.status='awaiting_approval' AND a.status='awaiting_approval'
                       FOR UPDATE""", (alert_id,))
        r = cur.fetchone()
        if not r or str(r[0]) == p.user_id:
            return False
        cur.execute("UPDATE str_drafts SET approved_by=%s, status='approved', updated_at=now() WHERE alert_id=%s", (p.user_id, alert_id))
        cur.execute("UPDATE alerts SET status='str_filed' WHERE id=%s", (alert_id,))
        auditlog.write(cur, p.org_id, p.user_id, p.role, "str_approved", alert_id, {}, p.ip)
        return True


def find_screening_by_ref(org_id, client_ref) -> dict | None:
    """The stored answer for a retried request (same client_ref), so retries never create a second alert."""
    if not client_ref:
        return None
    with pg.tx(org_id) as cur:
        cur.execute("SELECT id, result FROM screenings WHERE client_ref=%s", (client_ref,))
        r = cur.fetchone()
    return {"screening_id": r[0], **(r[1] or {}), "replayed": True} if r else None


def save_screening(org_id, sid, req, result, alert: dict | None = None) -> bool:
    """Store the screening (and its alert) atomically. Returns False if another request with the
    same client_ref won the race; the caller then returns the stored answer."""
    import psycopg
    try:
        with pg.tx(org_id) as cur:
            cur.execute("""INSERT INTO screenings (id, org_id, customer_id, direction, address, amount, score, decision,
                                                   reasons, client_ref, asset, fiat_value, result)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (sid, org_id, req["customer_id"], req["direction"], req["address"], req["amount"],
                         result["score"], result["decision"], json.dumps(result["reasons"] + result["signals"]),
                         req.get("client_ref"), req.get("asset"), result.get("fiat_value"), json.dumps(result, default=str)))
            if alert:
                cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, status, screening_id)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,'open',%s)""",
                            (alert["id"], org_id, alert["customer_id"], alert["score"], alert["band"],
                             json.dumps(alert["reasons"]), alert["channel"], sid))
    except psycopg.errors.UniqueViolation:
        return False
    return True


SCREENING_COLS = ["id", "customer_id", "direction", "address", "amount", "asset", "fiat_value", "score", "decision",
                  "reasons", "override", "override_by", "override_reason", "override_at", "created_at"]


def get_screening(p, sid) -> dict | None:
    if not sid:
        return None
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute(f"SELECT {', '.join(SCREENING_COLS)} FROM screenings WHERE id=%s", (sid,))
        r = cur.fetchone()
    if not r:
        return None
    s = dict(zip(SCREENING_COLS, r))
    for k in ("amount", "fiat_value"):
        s[k] = float(s[k]) if s[k] is not None else None
    s["override_by"] = str(s["override_by"]) if s["override_by"] else None
    return s


def override_screening(p, sid, action: str, reason: str) -> dict:
    """An analyst releases or blocks a HELD transfer, once. Engine blocks and releases can't be overridden."""
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT decision, override FROM screenings WHERE id=%s FOR UPDATE", (sid,))
        r = cur.fetchone()
        if not r:
            raise NotFound(sid)
        decision, existing = r
        if existing:
            raise Conflict(f"An analyst already chose to {existing} this transfer")
        if decision != "hold":
            raise Conflict(f"Only held transfers can be released or blocked (the engine's decision was '{decision}')")
        cur.execute("""UPDATE screenings SET override=%s, override_by=%s, override_reason=%s, override_at=now()
                       WHERE id=%s""", (action, p.user_id, reason, sid))
        auditlog.write(cur, p.org_id, p.user_id, p.role, f"screening_override:{action}", sid, {"reason": reason}, p.ip)
    return {"screening_id": sid, "decision": action}


def get_policy(org_id) -> dict:
    with pg.tx(org_id) as cur:
        cur.execute("SELECT policy FROM screening_policy")
        r = cur.fetchone()
    return r[0] if r else {}


def set_policy(p, policy: dict):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("""INSERT INTO screening_policy (org_id, policy) VALUES (%s,%s)
                       ON CONFLICT (org_id) DO UPDATE SET policy=EXCLUDED.policy""", (p.org_id, json.dumps(policy)))


# ---------------------------------------------------------------------------------------------------------------------
# Read auditing and restricted (need-to-know) cases
# ---------------------------------------------------------------------------------------------------------------------
def audit_view(p, alert_id: str, restricted: bool):
    """Record that this person opened a case. A restricted case: every view. An ordinary case: once per person per hour, so the
    log shows who looked without drowning in page reloads."""
    with pg.tx(p.org_id, actor=p.actor) as cur:
        if not restricted:
            cur.execute("""SELECT 1 FROM audit_events WHERE org_id=%s AND actor_id=%s AND action='case_viewed' AND target=%s
                           AND at > now() - interval '1 hour' LIMIT 1""", (p.org_id, p.user_id, alert_id))
            if cur.fetchone():
                return
        auditlog.write(cur, p.org_id, p.user_id, p.role, "case_viewed", alert_id, {"restricted": restricted}, p.ip)


def customer_hidden(p, customer_id: str) -> bool:
    """True when every way to this customer is a restricted case the caller may not see (searches answer 'not found')."""
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT customer_hidden(%s, %s)", (p.org_id, customer_id))
        return bool(cur.fetchone()[0])


def set_restricted(p, alert_id: str, restricted: bool, reason: str):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT restricted FROM alerts WHERE id=%s FOR UPDATE", (alert_id,))
        r = cur.fetchone()
        if not r:
            raise NotFound(alert_id)
        if r[0] == restricted:
            raise Conflict("This case is already " + ("restricted" if restricted else "open to everyone who can work cases"))
        cur.execute("UPDATE alerts SET restricted=%s, restricted_by=%s, restricted_at=now() WHERE id=%s",
                    (restricted, p.user_id if restricted else None, alert_id))
        if not restricted:
            cur.execute("DELETE FROM case_access_grants WHERE alert_id=%s", (alert_id,))
        auditlog.write(cur, p.org_id, p.user_id, p.role, "case_restricted" if restricted else "case_unrestricted", alert_id,
                       {"reason": reason}, p.ip)


def grant_case_access(p, alert_id: str, user_id: str):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT restricted FROM alerts WHERE id=%s", (alert_id,))
        r = cur.fetchone()
        if not r:
            raise NotFound(alert_id)
        if not r[0]:
            raise Conflict("Only restricted cases have a list of named people")
        cur.execute("""SELECT 1 FROM tenant_memberships m JOIN role_permissions rp ON rp.role_id = m.role_id
                       WHERE m.user_id=%s AND m.tenant_id=%s AND m.status='active' AND rp.perm='cases.view'""", (user_id, p.org_id))
        if not cur.fetchone():
            raise Conflict("That person isn't an active member who can view cases")
        cur.execute("""INSERT INTO case_access_grants (org_id, alert_id, user_id, granted_by) VALUES (%s,%s,%s,%s)
                       ON CONFLICT DO NOTHING""", (p.org_id, alert_id, user_id, p.user_id))
        auditlog.write(cur, p.org_id, p.user_id, p.role, "case_access_granted", alert_id, {"user": user_id}, p.ip)


def revoke_case_access(p, alert_id: str, user_id: str):
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("DELETE FROM case_access_grants WHERE alert_id=%s AND user_id=%s RETURNING 1", (alert_id, user_id))
        if not cur.fetchone():
            raise NotFound(user_id)
        auditlog.write(cur, p.org_id, p.user_id, p.role, "case_access_revoked", alert_id, {"user": user_id}, p.ip)


def case_access_list(p, alert_id: str) -> list[dict]:
    with pg.tx(p.org_id, actor=p.actor) as cur:
        cur.execute("SELECT user_id, granted_by, created_at FROM case_access_grants WHERE alert_id=%s ORDER BY created_at", (alert_id,))
        return [{"user_id": str(r[0]), "granted_by": str(r[1]) if r[1] else None, "granted_at": r[2]} for r in cur.fetchall()]

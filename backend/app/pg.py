"""PostgreSQL access. Every request runs in a transaction with the tenant set,
so row-level security scopes every query to one organization."""
import os
from contextlib import contextmanager
from psycopg_pool import ConnectionPool

_pool = None
def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        # sslmode=verify-full in production: encrypted and the server certificate is checked
        _pool = ConnectionPool(os.environ["DATABASE_URL"], min_size=2, max_size=20,
                               kwargs={"autocommit": False}, open=True)
    return _pool


@contextmanager
def tx(org_id=None, platform: bool = False, actor=None, access_session=None):
    """Transaction scoped to a tenant. SET LOCAL resets at commit, so pooled
    connections never leak one tenant's context into another request.

    `actor` is the signed-in person (never an API key). The row-level-security policies then also require that this person
    has an active membership in the tenant (or a live owner access session), so a revoked membership stops working in the
    database even if application code kept the tenant in hand. No actor = a machine or system context (API key, sign-in
    lookups, scripts): the tenant scoping still applies, the membership check does not."""
    with pool().connection() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('app.org_id', %s, true)", (str(org_id) if org_id else "",))
                cur.execute("SELECT set_config('app.platform', %s, true)", ("on" if platform else "off",))
                cur.execute("SELECT set_config('app.actor', %s, true)", (str(actor) if actor else "",))
                # an owner working inside a tenant: every audit event written in this transaction is tagged with the session
                cur.execute("SELECT set_config('app.access_session', %s, true)", (str(access_session) if access_session else "",))
                yield cur

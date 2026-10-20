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
def tx(org_id=None, platform: bool = False):
    """Transaction scoped to a tenant. SET LOCAL resets at commit, so pooled
    connections never leak one tenant's context into another request."""
    with pool().connection() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('app.org_id', %s, true)", (str(org_id) if org_id else "",))
                cur.execute("SELECT set_config('app.platform', %s, true)", ("on" if platform else "off",))
                yield cur

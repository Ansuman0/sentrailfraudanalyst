"""Registry of scheduled or background jobs that touch tenant data.

There are none yet. Every job added later (dormant-membership sweep, access-review reminders, audit streaming, tenant deletion)
registers itself here as `TENANT_JOBS["name"] = callable(org_id)`; tests/test_isolation_e2e.py runs each one for tenant A and
proves tenant B's data is not read, changed or logged.
"""
from typing import Callable

TENANT_JOBS: dict[str, Callable] = {}

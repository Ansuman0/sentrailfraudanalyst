"""Registry of scheduled or background jobs.

TENANT_JOBS["name"] = callable(org_id): run once per live tenant (dormant sweep, review cycle, audit streaming, export clean-up).
tests/test_isolation_e2e.py runs each one for tenant A and proves tenant B's data is not read, changed or logged.
GLOBAL_JOBS["name"] = callable(): work that is not about one tenant (platform staff review, tenant data removal, housekeeping).
Registered by app/governance.py; run by app/jobs.py (python -m scripts.run_jobs, in the worker container).
"""
from typing import Callable

TENANT_JOBS: dict[str, Callable] = {}
GLOBAL_JOBS: dict[str, Callable] = {}

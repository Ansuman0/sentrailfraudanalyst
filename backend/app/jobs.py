"""The job runner: runs every registered job (app/access/jobs.py) once, or on a schedule.

One run = every global job, then every tenant job for each live tenant. A failing job for one tenant is logged, recorded in
job_runs and never stops the others. A database lock keeps two runners from working at the same time (the worker container and a
manual `python -m scripts.run_jobs`), so a job never races itself.
"""
import logging
import time

from app import governance                       # noqa: F401  registers its jobs
from app import pg
from app.access import jobs

log = logging.getLogger("sentrail.jobs")
LOCK_KEY = 7_070_707


def _record(name: str, ok: bool, detail: str):
    with pg.tx(platform=True) as cur:
        cur.execute("""INSERT INTO job_runs (name, last_run_at, last_ok, last_detail) VALUES (%s, now(), %s, %s)
                       ON CONFLICT (name) DO UPDATE SET last_run_at=now(), last_ok=EXCLUDED.last_ok, last_detail=EXCLUDED.last_detail""",
                    (name, ok, detail[:500]))


def live_tenants() -> list[str]:
    with pg.tx(platform=True) as cur:
        cur.execute("SELECT id FROM organizations WHERE status IN ('active','trial') ORDER BY created_at")
        return [str(r[0]) for r in cur.fetchall()]


def run_once(only: set[str] | None = None) -> dict:
    """Returns {job name: result or error text}. Returns {"skipped": "another runner is working"} if the lock is taken."""
    results: dict = {}
    with pg.pool().connection() as lock_conn:
        lock_conn.autocommit = True
        if not lock_conn.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0]:
            return {"skipped": "another runner is working"}
        try:
            for name, job in jobs.GLOBAL_JOBS.items():
                if only and name not in only:
                    continue
                try:
                    results[name] = job()
                    _record(name, True, str(results[name]))
                except Exception as e:           # noqa: BLE001 - recorded, the other jobs still run
                    log.exception("job failed", extra={"event": "job_failed", "job": name})
                    results[name] = f"failed: {type(e).__name__}"
                    _record(name, False, results[name])
            tenants = live_tenants()
            for name, job in jobs.TENANT_JOBS.items():
                if only and name not in only:
                    continue
                per, failed = [], 0
                for org in tenants:
                    try:
                        per.append(job(org))
                    except Exception as e:       # noqa: BLE001
                        failed += 1
                        log.exception("job failed", extra={"event": "job_failed", "job": name, "org_id": org})
                results[name] = {"tenants": len(tenants), "failed": failed}
                _record(name, failed == 0, str(results[name]))
        finally:
            lock_conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
    return results


def loop(every_seconds: int = 300):
    log.info("worker started", extra={"event": "worker_started"})
    while True:
        try:
            run_once()
        except Exception:                         # noqa: BLE001 - the worker never dies on one bad round
            log.exception("job round failed", extra={"event": "job_round_failed"})
        time.sleep(every_seconds)

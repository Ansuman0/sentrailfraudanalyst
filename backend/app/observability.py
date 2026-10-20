"""Log events for calls to other services (chain APIs, OFAC, the LLM). Metadata only: no URLs with addresses,
no headers, no prompts or responses."""
import functools
import logging
import time
from contextlib import contextmanager

log = logging.getLogger("sentrail.external")


def _category(exc: BaseException) -> str:
    return type(exc).__name__          # e.g. ReadTimeout, HTTPStatusError, ConnectError


@contextmanager
def external_call(target: str, operation: str, **fields):
    """Time one call. Logs external_api_request on success or external_api_failure (then re-raises).
    The caller may set result["failed"] = True for failures that don't raise."""
    result = {"failed": False}
    start = time.perf_counter()
    try:
        yield result
    except Exception as exc:
        log.warning("external call failed", extra={
            "event": "external_api_failure", "target_service": target, "operation": operation, "success": False,
            "error_category": _category(exc), "duration_ms": round((time.perf_counter() - start) * 1000, 1), **fields})
        raise
    ok = not result["failed"]
    log.log(logging.INFO if ok else logging.WARNING, "external call", extra={
        "event": "external_api_request" if ok else "external_api_failure", "target_service": target,
        "operation": operation, "success": ok, **({} if ok else {"error_category": "failed"}),
        "duration_ms": round((time.perf_counter() - start) * 1000, 1), **fields})


def observed(target: str, operation: str, none_is_failure: bool = False):
    """Decorator for async functions that call an outside service."""
    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*a, **kw):
            with external_call(target, operation) as res:
                out = await fn(*a, **kw)
                if none_is_failure and out is None:
                    res["failed"] = True
                return out
        return wrapper
    return deco

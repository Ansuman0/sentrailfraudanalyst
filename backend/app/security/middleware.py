"""Security headers, request IDs and rate limits."""
import logging
import re
import time
import uuid
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from app.logging_config import request_id_var, trace_id_var

log = logging.getLogger("sentrail.http")
SAFE_ID = re.compile(r"[A-Za-z0-9._-]{8,64}")          # anything else is replaced: no log injection
TRACEPARENT = re.compile(r"00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}")
QUIET_PATHS = {"/healthz", "/readyz"}                    # healthy probes: DEBUG, not INFO; a failing probe is still logged

limiter = Limiter(key_func=get_remote_address, default_limits=["300/minute"])


def api_key_or_ip(request: Request) -> str:
    """Rate-limit machine traffic per API key, not per IP: one ramp behind a NAT shouldn't share
    a limit with another, and one ramp rotating IPs shouldn't escape its own."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer sk_live_"):
        return "key:" + "_".join(auth.removeprefix("Bearer ").split("_")[:3])
    return get_remote_address(request)

HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        sent = request.headers.get("x-request-id", "")
        rid = sent if SAFE_ID.fullmatch(sent) else uuid.uuid4().hex
        tp = TRACEPARENT.fullmatch(request.headers.get("traceparent", ""))
        tokens = (request_id_var.set(rid), trace_id_var.set(tp.group(1) if tp else rid))
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers.update(HEADERS)
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            route = request.scope.get("route")
            level = logging.DEBUG if request.url.path in QUIET_PATHS and status < 400 else (
                logging.ERROR if status >= 500 else logging.WARNING if status >= 400 else logging.INFO)
            log.log(level, "request", extra={
                "event": "api_request", "method": request.method,
                # route template (e.g. /cases/{alert_id}), never the raw path or query string: ids stay out of logs
                "path": getattr(route, "path", "unmatched"), "status_code": status,
                "duration_ms": round((time.perf_counter() - start) * 1000, 1)})
            request_id_var.reset(tokens[0])
            trace_id_var.reset(tokens[1])

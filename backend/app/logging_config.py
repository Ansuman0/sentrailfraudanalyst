"""JSON logs for your log platform, with personal data scrubbed before anything is written."""
import contextvars
import json
import logging
import os
import re
import sys

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
LONG_DIGITS = re.compile(r"\b\d{12,19}\b")              # card-like numbers
SERVICE = "sentrail-api"
ENVIRONMENT = os.getenv("ENV") or "production"

# Set per request by the middleware; every log line written while handling it carries them.
request_id_var = contextvars.ContextVar("request_id", default=None)
trace_id_var = contextvars.ContextVar("trace_id", default=None)

# Structured fields a caller may pass with `extra=`: log.info("...", extra={"event": "x", "status_code": 200})
EXTRA_FIELDS = ("event", "method", "path", "status_code", "duration_ms", "error_code", "org_id", "user_id",
                "target_service", "operation", "success", "error_category", "provider", "model", "input_chars", "output_chars")
TOKENISH = re.compile(r"(Bearer\s+|sk_live_)[A-Za-z0-9._~+/=-]+")


def scrub(text: str) -> str:
    text = EMAIL.sub(r"•••@\1", text)
    text = LONG_DIGITS.sub("[number removed]", text)
    return TOKENISH.sub(r"\1[redacted]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        out = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname,
               "service": SERVICE, "environment": ENVIRONMENT,
               "logger": record.name, "msg": scrub(record.getMessage())}
        for k, v in (("request_id", request_id_var.get()), ("trace_id", trace_id_var.get())):
            if v:
                out[k] = v
        for k in EXTRA_FIELDS:
            if hasattr(record, k):
                out[k] = getattr(record, k)
        if record.exc_info:
            out["error"] = scrub(self.formatException(record.exc_info))
        return json.dumps(out, default=str)


def configure_logging(level=logging.INFO):
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(level)
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).handlers[:] = [h]

"""Request IDs, trace IDs and the api_request event reach the JSON log. No database needed."""
import io, json, logging, sys
sys.path.insert(0, ".")
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.logging_config import JsonFormatter
from app.security.middleware import SecurityHeaders

ok = True
def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS" if cond else "FAIL"), name)

buf = io.StringIO()
h = logging.StreamHandler(buf); h.setFormatter(JsonFormatter())
lg = logging.getLogger("sentrail.http"); lg.handlers[:] = [h]; lg.setLevel(logging.DEBUG); lg.propagate = False
lg2 = logging.getLogger("sentrail.test"); lg2.handlers[:] = [h]; lg2.propagate = False
app = FastAPI(); app.add_middleware(SecurityHeaders)
@app.get("/things/{tid}")
def things(tid: str):
    logging.getLogger("sentrail.test").warning("inside handler for jane@example.com")
    return {}
@app.get("/readyz")
def readyz(fail: bool = False):
    from fastapi.responses import JSONResponse
    return JSONResponse({}, status_code=503 if fail else 200)
@app.get("/boom")
def boom(): raise RuntimeError("x")
c = TestClient(app, raise_server_exceptions=False)

def lines(): return [json.loads(l) for l in buf.getvalue().splitlines()]

r = c.get("/things/SECRET123?card=4111111111111111", headers={"x-request-id": "req-abcdef12"})
check("request id echoed", r.headers["x-request-id"] == "req-abcdef12")
ev = [l for l in lines() if l.get("event") == "api_request"][-1]
check("api_request has id, status, duration", ev["request_id"] == "req-abcdef12" and ev["status_code"] == 200 and "duration_ms" in ev)
check("path is the route template", ev["path"] == "/things/{tid}")
check("service and environment present", ev["service"] and ev["environment"])
check("trace_id falls back to request id", ev["trace_id"] == "req-abcdef12")
check("raw id and card never logged", "SECRET123" not in buf.getvalue() and "4111" not in buf.getvalue())
inner = [l for l in lines() if l["logger"] == "sentrail.test"]
check("other loggers get the request id and scrubbing during the request", len(inner) == 1 and inner[0]["request_id"] == "req-abcdef12" and "jane@" not in inner[0]["msg"] and "•••@example.com" in inner[0]["msg"])

r = c.get("/things/x", headers={"x-request-id": "bad id\nforged", "traceparent": "00-" + "a"*32 + "-" + "b"*16 + "-01"})
check("unsafe request id replaced", r.headers["x-request-id"] != "bad id\nforged" and len(r.headers["x-request-id"]) == 32)
ev = [l for l in lines() if l.get("event") == "api_request"][-1]
check("trace_id taken from traceparent", ev["trace_id"] == "a"*32)

c.get("/boom")
ev = [l for l in lines() if l.get("event") == "api_request"][-1]
check("unhandled error logged as 500 at ERROR", ev["status_code"] == 500 and ev["level"] == "ERROR")
c.get("/readyz")
check("healthy probe logged at DEBUG", [l for l in lines() if l.get("path") == "/readyz"][-1]["level"] == "DEBUG")
c.get("/readyz?fail=true")
e = [l for l in lines() if l.get("path") == "/readyz"][-1]
check("failing probe logged at ERROR (so the readiness alert can see it)", e["level"] == "ERROR" and e["status_code"] == 503)

# ---- external calls, AI calls, audit events ----
import asyncio
from app.observability import observed, external_call
from app.agent import llm
from app.security import audit
for name in ("sentrail.external", "sentrail.ai", "sentrail.audit"):
    l = logging.getLogger(name); l.handlers[:] = [h]; l.setLevel(logging.DEBUG); l.propagate = False

def last(event): return [l for l in lines() if l.get("event") == event][-1]

@observed("etherscan", "fetch_eth_transfers")
async def good(): return [1]
@observed("trongrid", "fetch_trc20_transfers")
async def bad(): raise TimeoutError("https://api.trongrid.io/v1/accounts/TSECRETADDR secret-key")
@observed("ofac", "fetch_sdn_list", none_is_failure=True)
async def none(): return None

asyncio.run(good())
e = last("external_api_request")
check("external success logged", e["target_service"] == "etherscan" and e["success"] is True and "duration_ms" in e)
try: asyncio.run(bad())
except TimeoutError: pass
e = last("external_api_failure")
check("external exception logged and re-raised", e["target_service"] == "trongrid" and e["error_category"] == "TimeoutError")
check("exception text (urls, keys) not logged", "TSECRETADDR" not in buf.getvalue() and "secret-key" not in buf.getvalue())
asyncio.run(none())
check("None result counted as failure when asked", last("external_api_failure")["target_service"] == "ofac")

class R:
    def raise_for_status(self): pass
    def json(self): return {"message": {"content": " drafted text "}}
llm.httpx.post = lambda *a, **k: R()
out = llm.chat("system prompt PRIVATE", "user text PRIVATE")
e = last("ai_request_completed")
check("ai completed logged with sizes", out == "drafted text" and e["provider"] == "ollama" and e["output_chars"] == 12 and e["input_chars"] > 0)
def boom(*a, **k): raise ConnectionError("down")
llm.httpx.post = boom
try: llm.chat("s", "u")
except ConnectionError: pass
check("ai failure logged", last("ai_request_failed")["error_category"] == "ConnectionError")
check("prompt text never logged", "PRIVATE" not in buf.getvalue() and "drafted text" not in buf.getvalue())

class Cur:
    def execute(self, *a, **k): pass
    n = 0
    def fetchone(self):
        self.n += 1
        return None if self.n == 1 else (__import__("datetime").datetime(2026, 1, 1),)   # no previous event, then now()
import uuid
org, usr = uuid.uuid4(), uuid.uuid4()
audit.write(Cur(), org, usr, None, "login_failed", None, {"failed": 3}, "203.0.113.9")
e = last("audit_login_failed")
check("audit event logged with ids only", e["org_id"] == str(org) and e["user_id"] == str(usr) and "203.0.113.9" not in buf.getvalue())

sys.exit(0 if ok else 1)

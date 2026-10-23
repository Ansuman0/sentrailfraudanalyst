"""Sentrail API. Run: uvicorn app.main:app --reload"""
import io
import os
import uuid
import httpx
import pandas as pd
from fastapi import FastAPI, HTTPException, UploadFile, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app import config, db
from app.connectors import risk_lists
from app.services import cases, search as searchsvc, wallet_trace, screening
from app.detection import rules, scorer
from app.admin_api import router as admin_router
from app.security.rbac import Principal, require, api_key
from app.security.middleware import SecurityHeaders, limiter, api_key_or_ip
from app.security.rbac import install_handlers
from app.owner_access import router as access_router
from app.logging_config import configure_logging

app = FastAPI(title="Sentrail", version="0.3",
              docs_url="/docs" if config.IS_DEV else None, redoc_url=None, openapi_url="/openapi.json" if config.IS_DEV else None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SecurityHeaders)
app.add_middleware(CORSMiddleware, allow_origins=[os.environ.get("APP_URL", "http://localhost:5173")],
                   allow_credentials=True, allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                   allow_headers=["Authorization", "Content-Type", "X-Request-ID", "traceparent", "X-Sentrail-CSRF"],
                   expose_headers=["X-Request-ID"])
app.include_router(admin_router)
app.include_router(access_router)
install_handlers(app)
configure_logging()


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
def readyz():
    from app import pg
    try:
        with pg.pool().connection() as conn:
            conn.execute("SELECT 1")
    except Exception:
        raise HTTPException(503, "database unavailable")
    return {"status": "ready", "risk_lists": risk_lists.status()}


def _case_or_404(p: Principal, alert_id: str) -> dict:
    alert = db.get_alert(p, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


def _case_detail(p: Principal, alert: dict) -> tuple[dict, dict]:
    """(detail, facts) for any alert: scored from the organization's own transaction history when there
    is one, otherwise from the real-time screening that raised it. Never a 500 for a missing customer."""
    try:
        scored = cases.score_customer(p.org_id, alert["customer_id"])
        detail = {**scored, "transactions": cases.customer_transactions(p.org_id, alert["customer_id"])[:100],
                  "source": "transaction_history"}
        return detail, cases.case_facts(p.org_id, alert["customer_id"], scored)
    except cases.NoData:
        s = db.get_screening(p, alert.get("screening_id"))
        detail = {"customer_id": alert["customer_id"], "score": alert["score"], "band": alert["band"],
                  "reasons": alert["reasons"], "screening": s, "transactions": [], "source": "screening"}
        return detail, cases.screening_facts(alert, s)


@app.get("/alerts")
def list_alerts(band: str | None = Query(None, pattern="^(high|medium|low)$"),
                status: str = Query("open", pattern="^(open|pending_info|escalated|closed|awaiting_approval|str_filed)$"),
                p: Principal = Depends(require("cases.view", feature="alerts"))):
    return db.list_alerts(p, band, status)


@app.get("/cases/{alert_id}")
def get_case(alert_id: str, p: Principal = Depends(require("cases.view"))):
    alert = _case_or_404(p, alert_id)
    db.audit_view(p, alert_id, alert["restricted"])
    detail, _ = _case_detail(p, alert)
    return {"alert": alert, **detail}


class RestrictIn(BaseModel):
    restricted: bool
    reason: str = Field(min_length=5, max_length=500)


class GrantIn(BaseModel):
    user_id: uuid.UUID


@app.put("/cases/{alert_id}/restricted")
def restrict_case(alert_id: str, body: RestrictIn, p: Principal = Depends(require("cases.decide", "cases.restricted.view"))):
    """Mark a case need-to-know (for example one involving a colleague) or open it again. Needs both the right to work cases and the
    right to see restricted ones, so nobody can hide a case from themselves by accident or lock a colleague out of it."""
    _case_or_404(p, alert_id)
    try:
        db.set_restricted(p, alert_id, body.restricted, body.reason)
    except db.NotFound:
        raise HTTPException(404, "Alert not found")
    except db.Conflict as e:
        raise HTTPException(409, str(e))
    return {"alert_id": alert_id, "restricted": body.restricted}


@app.get("/cases/{alert_id}/access")
def case_access(alert_id: str, p: Principal = Depends(require("cases.restricted.view"))):
    _case_or_404(p, alert_id)
    return {"people": db.case_access_list(p, alert_id)}


@app.post("/cases/{alert_id}/access")
def grant_access(alert_id: str, body: GrantIn, p: Principal = Depends(require("cases.decide", "cases.restricted.view"))):
    _case_or_404(p, alert_id)
    try:
        db.grant_case_access(p, alert_id, str(body.user_id))
    except db.Conflict as e:
        raise HTTPException(409, str(e))
    return {"alert_id": alert_id, "user_id": str(body.user_id)}


@app.delete("/cases/{alert_id}/access/{user_id}")
def revoke_access(alert_id: str, user_id: uuid.UUID, p: Principal = Depends(require("cases.decide", "cases.restricted.view"))):
    _case_or_404(p, alert_id)
    try:
        db.revoke_case_access(p, alert_id, str(user_id))
    except db.NotFound:
        raise HTTPException(404, "That person isn't on the list")
    return {"revoked": str(user_id)}


@app.get("/search")
def search(q: str = Query(max_length=200), reason: str = Query(min_length=3), p: Principal = Depends(require("cases.view"))):
    kind = searchsvc.classify(q)
    db.audit(p, "search", kind.get("value") or "rejected", {"kind": kind["kind"], "reason": reason})
    if kind["kind"] == "rejected":
        raise HTTPException(400, kind["message"])
    if kind["kind"] == "wallet":
        return {"kind": "wallet", "network": kind["network"], "next": f"/wallets/{q}/trace"}
    if not cases.has_data(p.org_id):               # only this organization's own data is ever searched
        return {"kind": kind["kind"], "customers": [], "note": "No transaction history is loaded for your organization"}
    if kind["kind"] == "customer":
        try:
            if db.customer_hidden(p, kind["value"]):          # their only cases are restricted ones this person can't see
                raise cases.NoData(kind["value"])
            return {"kind": "customer", "result": cases.score_customer(p.org_id, kind["value"])}
        except cases.NoData:
            raise HTTPException(404, "No customer with that ID in your organization's data")
    t, *_ = cases.load(p.org_id)
    col = {"account": "account_id", "card": "card_last4", "tx_hash": "txn_id"}.get(kind["kind"])
    if col and col in t:
        found = t[t[col].astype(str) == kind["value"]].customer_id.unique().tolist()
        return {"kind": kind["kind"], "customers": [c for c in found if not db.customer_hidden(p, c)][:20]}
    return {"kind": kind["kind"], "customers": []}


@app.get("/wallets/{address}/trace")
async def trace_wallet(address: str, hops: int = Query(2, ge=0, le=3),
                       p: Principal = Depends(require("wallet.trace", feature="trace"))):
    try:
        result = await wallet_trace.trace(address, hops=hops)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except risk_lists.RiskListUnavailable:
        raise HTTPException(503, "The sanctions list couldn't be loaded, so this trace can't be trusted. Try again shortly")
    db.audit(p, "wallet_trace", address, {"exposure": result["exposure_score"]})
    return result


@app.post("/cases/{alert_id}/investigate")
def investigate(alert_id: str, p: Principal = Depends(require("str.draft", feature="ai"))):
    from app.agent import investigator            # loads LangGraph, Presidio and the LLM client on first use
    alert = _case_or_404(p, alert_id)
    if alert["status"] in ("closed", "str_filed"):
        raise HTTPException(409, f"This alert is {alert['status'].replace('_', ' ')}")
    _, facts = _case_detail(p, alert)
    try:
        out = investigator.investigate(facts)
    except (httpx.HTTPError, RuntimeError):         # model server down, model not pulled, or the provider settings are invalid
        raise HTTPException(503, "The AI model isn't available. Start the AI service (Ollama) and pull the model, then try again")
    db.save_ai_draft(p, alert_id, out["str_draft"])
    db.audit(p, "ai_investigation", alert_id, {"steps": out["steps"], "verification": out["verification"]})
    return out


class Decision(BaseModel):
    decision: str = Field(pattern="^(false_positive|request_info|escalate)$")
    reason: str = Field(min_length=5, max_length=2000)


@app.post("/cases/{alert_id}/decision")
def decide(alert_id: str, body: Decision, p: Principal = Depends(require("cases.decide"))):
    try:
        status = db.decide(p, alert_id, body.decision, body.reason)
    except db.NotFound:
        raise HTTPException(404, "Alert not found")
    except db.Conflict as e:
        raise HTTPException(409, str(e))
    return {"status": status}


class Assign(BaseModel):
    user_id: uuid.UUID | None = None          # null = unassign


@app.post("/cases/{alert_id}/assign")
def assign_case(alert_id: str, body: Assign, p: Principal = Depends(require("cases.decide"))):
    try:
        db.assign(p, alert_id, str(body.user_id) if body.user_id else None)
    except db.NotFound:
        raise HTTPException(404, "Alert not found")
    except db.Conflict as e:
        raise HTTPException(409, str(e))
    return {"assigned_to": str(body.user_id) if body.user_id else None}


class StrIn(BaseModel):
    final_text: str = Field(min_length=50, max_length=20000)


@app.post("/cases/{alert_id}/str/submit")
def submit_str(alert_id: str, body: StrIn, p: Principal = Depends(require("str.draft"))):
    try:
        db.submit_str(p, alert_id, body.final_text)
    except db.NotFound:
        raise HTTPException(404, "Alert not found")
    except db.Conflict as e:
        raise HTTPException(409, str(e))
    return {"status": "awaiting_approval"}


@app.post("/cases/{alert_id}/str/approve")
def approve_str(alert_id: str, p: Principal = Depends(require("str.approve"))):
    _case_or_404(p, alert_id)
    if not db.approve_str(p, alert_id):
        raise HTTPException(409, "Nothing to approve, or you drafted this STR. Another officer must approve it")
    return {"status": "str_filed"}


@app.get("/cases/{alert_id}/export")
def export_case(alert_id: str, reason: str = Query(min_length=5, max_length=500),
                p: Principal = Depends(require("data.export", feature="export"))):
    """Everything on one case, including the decrypted STR, for an examiner or law-enforcement request."""
    alert = _case_or_404(p, alert_id)
    detail, _ = _case_detail(p, alert)
    db.audit(p, "case_exported", alert_id, {"reason": reason})
    return {"alert": alert, **detail, "str": db.get_str(p, alert_id)}


REQUIRED_STATEMENT_COLUMNS = {"timestamp", "amount", "direction"}


@app.post("/upload")
async def upload_statement(file: UploadFile, customer_id: str = Query(max_length=64), expected_monthly: float = Query(0, ge=0),
                           p: Principal = Depends(require("cases.decide", feature="statements"))):
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(413, "Statements must be under 10 MB")
    try:
        df = pd.read_csv(io.BytesIO(data))
    except (ValueError, UnicodeDecodeError, pd.errors.ParserError):
        raise HTTPException(400, "The file couldn't be read as CSV")
    missing = REQUIRED_STATEMENT_COLUMNS - set(df.columns)
    if missing:
        raise HTTPException(400, f"Missing column(s): {', '.join(sorted(missing))}")
    if df.empty:
        raise HTTPException(400, "The statement has no rows")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["amount"] = pd.to_numeric(df["amount"], errors="coerce")
    bad = int(df["timestamp"].isna().sum() + df["amount"].isna().sum())
    if bad:
        raise HTTPException(400, f"{bad} value(s) in timestamp or amount couldn't be read")
    if not set(df["direction"].astype(str)).issubset({"in", "out"}):
        raise HTTPException(400, "direction must be 'in' or 'out'")
    for col, default in {"channel": "bank", "country": "", "merchant_category": "", "currency": "CAD",
                         "account_id": customer_id, "counterparty_id": ""}.items():
        if col not in df:
            df[col] = default
    hits = rules.run_rules(df, {"expected_monthly": expected_monthly})
    result = scorer.combine(hits, {"score": 0, "reasons": []}, {"score": 0, "reasons": []})
    db.audit(p, "statement_upload", customer_id, {"rows": len(df), "rule_hits": len(hits)})
    return {"rows": len(df), "rule_hits": hits, **result}


# ---------------- Real-time screening, called by the on/off-ramp with an API key ----------------

class ScreenRequest(BaseModel):
    direction: str = Field(pattern="^(deposit|withdrawal)$")
    customer_id: str = Field(min_length=1, max_length=64)
    address: str = Field(max_length=100)
    amount: float = Field(gt=0)
    asset: str = Field("USDT", min_length=2, max_length=12)
    fiat_value: float | None = Field(None, gt=0, description="Value in the reporting currency. Required unless asset is a stablecoin")
    client_ref: str | None = Field(None, min_length=1, max_length=100,
                                   description="The ramp's own transfer id. A retry with the same value returns the stored answer")
    travel_rule_ok: bool = False
    self_hosted: bool = True
    ownership_proven: bool = False


@app.post("/screen")
@limiter.limit("600/minute", key_func=api_key_or_ip)
async def screen(request: Request, req: ScreenRequest, p: Principal = Depends(api_key)):
    stored = db.find_screening_by_ref(p.org_id, req.client_ref)
    if stored:
        return stored
    policy = {**screening.POLICY, **db.get_policy(p.org_id)}
    try:
        result = await screening.screen_transfer(req.model_dump(), policy)
    except ValueError as e:
        raise HTTPException(400, str(e))
    sid = f"S-{uuid.uuid4().hex[:12]}"
    alert = None
    if result["decision"] in ("hold", "block"):
        alert = {"id": f"A-{sid}", "customer_id": req.customer_id, "score": result["score"],
                 "band": "high" if result["decision"] == "block" else "medium",
                 "reasons": [{"source": "Screening", "text": r} for r in result["reasons"] + result["signals"]][:4],
                 "channel": "crypto"}
    if not db.save_screening(p.org_id, sid, req.model_dump(), result, alert):
        return db.find_screening_by_ref(p.org_id, req.client_ref)     # a parallel retry stored it first
    db.audit(p, f"screen:{result['decision']}", sid, {"customer": req.customer_id, "score": result["score"],
                                                      "client_ref": req.client_ref})
    return {"screening_id": sid, **result}


class OverrideIn(BaseModel):
    action: str = Field(pattern="^(release|block)$")
    reason: str = Field(min_length=5, max_length=2000)


@app.get("/screenings/{sid}")
def get_screening(sid: str, p: Principal = Depends(require("cases.view", feature="screening"))):
    s = db.get_screening(p, sid)
    if not s:
        raise HTTPException(404, "Screening not found")
    return s


@app.post("/screenings/{sid}/override")
def override_screening(sid: str, body: OverrideIn, p: Principal = Depends(require("screening.override", feature="screening"))):
    try:
        return db.override_screening(p, sid, body.action, body.reason)
    except db.NotFound:
        raise HTTPException(404, "Screening not found")
    except db.Conflict as e:
        raise HTTPException(409, str(e))


@app.get("/policy")
def get_policy(p: Principal = Depends(require("cases.view"))):
    return {**screening.POLICY, **db.get_policy(p.org_id)}


class PolicyIn(BaseModel):
    hold_at: int = Field(ge=1, le=99)
    block_at: int = Field(ge=2, le=100)
    travel_rule_threshold: float = Field(ge=0)
    self_hosted_proof_above: float = Field(ge=0)
    always_block_sanctions: bool = True


@app.put("/policy")
def set_policy(body: PolicyIn, p: Principal = Depends(require("policy.edit"))):
    if body.block_at <= body.hold_at:
        raise HTTPException(422, "The block level must be higher than the hold level")
    before = db.get_policy(p.org_id)
    db.set_policy(p, body.model_dump())
    db.audit(p, "policy_change", "screening", {"before": before, "after": body.model_dump()})
    return body


# The API refuses to start if any route lacks a declared permission (see app/access/routes.py).
from app.access.routes import check_routes  # noqa: E402
check_routes(app)

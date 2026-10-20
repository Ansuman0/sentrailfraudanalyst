"""Detection and screening logic, no database or network needed.
Run: PYTHONPATH=. python tests/test_detection_unit.py"""
import asyncio
from datetime import datetime, timedelta, timezone

from app import config
from app.agent import guardrails
from app.connectors import risk_lists
from app.services import screening, search

ok = lambda cond, msg: print(("PASS " if cond else "FAIL ") + msg)
run = asyncio.run

# ---------------- AI figure check ----------------
facts = {"totals": {"bank_in": {"total": 48250.0, "count": 9}}, "period_days": 90,
         "reasons": [{"text": "9 different senders in 5 days"}],
         "transactions": [{"timestamp": "2022-09-01 00:20:00", "amount": "9500.0"}]}
v = guardrails.verify("The customer received 48,250.00 from 12 senders over 5 days.", facts)
ok(not v["ok"] and v["unverified"] == ["12"], "an invented small count (12 senders) is caught; 0-31 is no longer a free pass")
v = guardrails.verify("Received 48,250.00 from 9 senders in 5 days, first on 2022-09-01 and again on September 1, 2022, "
                      "over the last 90 days.", facts)
ok(v["ok"], "real figures, ISO dates and written-out dates that match the facts pass")
v = guardrails.verify("On March 3, 2022 the customer moved 9,500.00.", facts)
ok(v["unverified"] == ["March 3, 2022"], "a date that isn't in the facts is flagged as a whole date")
v = guardrails.verify("Funds were sent to <PERSON_1> and <WALLET_2>.", facts)
ok(v["ok"] and v["checked"] == 0, "numbers inside masking tokens aren't treated as figures")

# ---------------- fiat value and travel rule ----------------
P = screening.POLICY
ok(screening.fiat_value({"asset": "USDT", "amount": 1500}) == 1500, "stablecoin amount is its fiat value")
ok(screening.fiat_value({"asset": "BTC", "amount": 0.5, "fiat_value": 41000}) == 41000, "fiat_value is used when given")
try:
    screening.fiat_value({"asset": "BTC", "amount": 0.5}); ok(False, "BTC without fiat_value is rejected")
except ValueError:
    ok(True, "BTC without fiat_value is rejected (thresholds are in fiat, not coins)")
d, why = screening.decide(10, False, 41000, False, True, False, P)
ok(d == "hold" and any("Travel rule" in w for w in why), "0.5 BTC worth 41,000 without travel-rule info is HELD (was released)")
ok(screening.decide(10, False, 999.99, False, True, False, P)[0] == "release", "just under the threshold is released")
ok(screening.decide(10, False, 1000, False, True, False, P)[0] == "hold", "exactly at the threshold is held")
ok(screening.decide(5, True, 10, True, False, False, P) == ("block", ["Wallet is on a sanctions list"]), "OFAC hit always blocks")

# ---------------- wallet age needs complete history ----------------
now = datetime.now(timezone.utc)
ME = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"
def transfers(n):  # n recent deposits from n different senders, all in the last day
    return [{"from": f"TSender{i:028d}", "to": ME, "amount": 10.0, "timestamp": (now - timedelta(hours=i % 20)).isoformat()}
            for i in range(n)]
async def page_partial(address): return "tron", transfers(200), False
async def page_complete(address): return "tron", transfers(25), True
screening.fetch_history = page_partial
sig = run(screening.wallet_signals(ME))
ok(sig["age_days"] is None and not any("first used" in s for s in sig["signals"]) and sig["score"] == 0,
   "a busy wallet with only its latest 200 transfers is NOT called 'first used 0 days ago' (+35 removed)")
screening.fetch_history = page_complete
sig = run(screening.wallet_signals(ME))
ok(sig["age_days"] == 0 and sig["score"] == 35, "a genuinely new wallet with full history still scores new-wallet + many-senders")

# ---------------- sanctions list fails closed ----------------
async def no_ofac(): return None
risk_lists._fetch_ofac = no_ofac
risk_lists._state.update(ofac={}, ofac_loaded_at=0.0, next_refresh=0.0)
config.OFAC_REQUIRED = True
try:
    run(risk_lists.screen(ME)); ok(False, "screening without OFAC raises")
except risk_lists.RiskListUnavailable:
    ok(True, "if OFAC never loaded, screen() refuses to say 'not listed'")
r = run(screening.screen_transfer({"address": ME, "amount": 50, "asset": "USDT", "customer_id": "C-1",
                                    "direction": "deposit", "travel_rule_ok": True, "self_hosted": False}, P))
ok(r["decision"] == "hold" and not r["checks_complete"] and "sanctions list" in r["reasons"][0],
   "a transfer that couldn't be checked against sanctions is HELD, not released")

calls = {"n": 0}
async def ofac_once():
    calls["n"] += 1
    return {ME.lower() if ME.startswith("0x") else ME: {"label": "OFAC sanctioned address", "source": "OFAC SDN"}} if calls["n"] == 1 else None
risk_lists._fetch_ofac = ofac_once
risk_lists._state.update(ofac={}, ofac_loaded_at=0.0, next_refresh=0.0)
hit = run(risk_lists.screen(ME))
risk_lists._state["next_refresh"] = 0.0                      # force a refresh that fails
hit2 = run(risk_lists.screen(ME))
ok(hit and hit2 and calls["n"] == 2, "a failed refresh keeps the last good OFAC list instead of dropping it")
ok(risk_lists._state["next_refresh"] - __import__("time").time() <= risk_lists.RETRY_SECONDS + 1, "after a failed refresh it retries within a minute")

async def chain_down(address): raise __import__("httpx").ConnectError("down")
screening.fetch_history = chain_down
r = run(screening.screen_transfer({"address": ME, "amount": 50, "asset": "USDT", "customer_id": "C-1",
                                    "direction": "deposit"}, P))
ok(r["decision"] == "hold" and "chain data" in r["reasons"][0], "if chain data can't be fetched, the transfer is held (was a 500)")

# ---------------- search classification ----------------
ok(search.classify("4111111111111111")["kind"] == "rejected", "a full card number is refused")
ok(search.classify("c-2291") == {"kind": "customer", "value": "C-2291"}, "customer IDs are recognised")

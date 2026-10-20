"""ChainGuard: real-time screening of crypto deposits and withdrawals.

Called by the on/off-ramp BEFORE a deposit is credited or a withdrawal is sent.
Returns release / hold / block in a few seconds, with plain-language reasons.
Held and blocked transfers become alerts in the AlertIQ queue.

Fails closed: if chain data or the sanctions list can't be checked, the transfer is HELD
for an analyst with a reason saying so. It is never released unchecked.
"""
from datetime import datetime, timezone
import httpx

from app.connectors.blockchain import fetch_history, detect_network
from app.connectors import risk_lists
from app.services.wallet_trace import _top_receivers

# Default policy. Stored per institution and editable by compliance.
# Thresholds are in the institution's reporting currency (fiat), not in coins.
POLICY = {
    "hold_at": 40,                 # score >= hold_at  -> hold for analyst review
    "block_at": 75,                # score >= block_at -> block and raise an alert
    "travel_rule_threshold": 1000, # Canada: VC transfers of 1,000 or more need travel rule info
    "self_hosted_proof_above": 1000,
    "always_block_sanctions": True,
}

# Coins whose amount already equals its value in the reporting currency (close enough for thresholds).
# Everything else (BTC, ETH, TRX...) must come with fiat_value from the ramp's own pricing.
STABLECOINS = {"USDT", "USDC", "DAI", "PYUSD", "TUSD", "USDP", "FDUSD", "QCAD", "CADC"}


def fiat_value(req: dict) -> float:
    if req.get("fiat_value") is not None:
        return float(req["fiat_value"])
    asset = (req.get("asset") or "").upper()
    if asset in STABLECOINS:
        return float(req["amount"])
    raise ValueError(f"fiat_value is required for {asset or 'this asset'}: thresholds are set in fiat, "
                     "and the coin amount alone can't be compared with them")


def _age_days(transfers):
    if not transfers:
        return 0
    first = min(datetime.fromisoformat(t["timestamp"]) for t in transfers)
    return (datetime.now(timezone.utc) - first).days


async def wallet_signals(address: str) -> dict:
    """Behavioural signals from public chain data, each with a readable reason."""
    _, tx, complete = await fetch_history(address)
    norm = (lambda x: x.lower()) if address.startswith("0x") else (lambda x: x)
    me = norm(address)
    ins = [t for t in tx if norm(t["to"]) == me]
    outs = [t for t in tx if norm(t["from"]) == me]
    senders = {t["from"] for t in ins}
    signals, score = [], 0
    # Age-based signals need the FULL history. With only the latest page, a busy exchange wallet
    # would look "first used today", so they're skipped instead of guessed.
    age = _age_days(tx) if complete else None
    if age is not None and age <= 7:
        score += 20; signals.append(f"Wallet first used {age} day(s) ago")
    if age is not None and len(senders) >= 20 and age <= 30:
        score += 15; signals.append(f"Received from {len(senders)} different wallets in under a month")
    in_amt, out_amt = sum(t["amount"] for t in ins), sum(t["amount"] for t in outs)
    if in_amt and out_amt / in_amt > 0.95 and len(outs) >= 3:
        score += 10; signals.append("Passes almost everything it receives straight on (pass-through wallet)")
    if outs and len({t["to"] for t in outs}) == len(outs) and len(outs) >= 5:
        score += 10; signals.append("Each payment goes to a new wallet (possible peel chain)")
    return {"score": score, "signals": signals, "age_days": age, "history_complete": complete, "tx_count": len(tx),
            "counterparties": _top_receivers(address, tx, 10) + [(s, 0) for s in list(senders)[:10]]}


async def exposure(address: str, counterparties) -> dict:
    """Direct listing + 1-hop exposure to listed wallets. Raises RiskListUnavailable."""
    direct = await risk_lists.screen(address)
    indirect = []
    for cp, _ in counterparties:
        hit = await risk_lists.screen(cp)
        if hit:
            indirect.append({"address": cp, **hit})
    score = 100 if direct else (45 if indirect else 0)
    return {"direct": direct, "indirect": indirect, "score": score}


def decide(total: int, sanctioned: bool, value: float, travel_rule_ok: bool,
           self_hosted: bool, ownership_proven: bool, policy=POLICY) -> tuple[str, list[str]]:
    """value is the transfer's value in the reporting currency."""
    why = []
    if sanctioned and policy["always_block_sanctions"]:
        return "block", ["Wallet is on a sanctions list"]
    if value >= policy["travel_rule_threshold"] and not travel_rule_ok:
        why.append("Travel rule information is missing for this amount")
    if self_hosted and value >= policy["self_hosted_proof_above"] and not ownership_proven:
        why.append("Customer hasn't proven they own this self-hosted wallet")
    if total >= policy["block_at"]:
        return "block", why + [f"Risk score {total} is at or above the block level ({policy['block_at']})"]
    if total >= policy["hold_at"] or why:
        return "hold", why + ([f"Risk score {total} is at or above the review level ({policy['hold_at']})"]
                              if total >= policy["hold_at"] else [])
    return "release", ["Risk score is below the review level and all checks passed"]


def _unchecked(network, value, reason) -> dict:
    return {"decision": "hold", "score": 0, "reasons": [reason + ". Held for an analyst instead of releasing it unchecked"],
            "signals": [], "direct_listing": None, "indirect_exposure": [], "wallet_age_days": None,
            "network": network, "fiat_value": value, "checks_complete": False}


async def screen_transfer(req: dict, policy: dict = POLICY) -> dict:
    """req: {direction, customer_id, address, amount, asset, fiat_value?, travel_rule_ok, self_hosted, ownership_proven}"""
    address = req["address"].strip()
    network = detect_network(address)
    if not network:
        raise ValueError("Not a recognised wallet address")
    value = fiat_value(req)
    try:
        sig = await wallet_signals(address)
    except (httpx.HTTPError, RuntimeError, KeyError, ValueError):
        return _unchecked(network, value, "Public chain data couldn't be fetched for this wallet")
    try:
        exp = await exposure(address, sig["counterparties"])
    except risk_lists.RiskListUnavailable:
        return _unchecked(network, value, "The sanctions list couldn't be checked")
    total = min(100, max(exp["score"], 0) + sig["score"])
    decision, reasons = decide(total, bool(exp["direct"] and "OFAC" in exp["direct"].get("source", "")),
                               value, req.get("travel_rule_ok", False),
                               req.get("self_hosted", True), req.get("ownership_proven", False), policy)
    return {"decision": decision, "score": total, "reasons": reasons,
            "signals": sig["signals"], "direct_listing": exp["direct"],
            "indirect_exposure": exp["indirect"], "wallet_age_days": sig["age_days"],
            "network": network, "fiat_value": value, "checks_complete": True}

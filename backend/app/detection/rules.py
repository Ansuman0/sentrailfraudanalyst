"""Rule engine: each rule returns a hit with a plain-language reason, or None.

Thresholds are examples for a demo. Tune them to your institution's risk
assessment and the reporting thresholds that apply to you.
"""
import pandas as pd

REPORT_THRESHOLD = 10_000
HIGH_RISK_COUNTRIES = {"IR", "KP", "MM"}  # example: FATF call-for-action list; keep this updated


def structuring(t: pd.DataFrame, days=7):
    recent = t[t.timestamp >= t.timestamp.max() - pd.Timedelta(days=days)]
    near = recent[(recent.amount >= REPORT_THRESHOLD * 0.9) & (recent.amount < REPORT_THRESHOLD)]
    if len(near) >= 3:
        return {"rule": "Structuring", "weight": 30,
                "reason": f"{len(near)} transactions just below {REPORT_THRESHOLD:,} in {days} days"}


def velocity_spike(t: pd.DataFrame, expected_monthly: float):
    last30 = t[t.timestamp >= t.timestamp.max() - pd.Timedelta(days=30)].amount.sum()
    if expected_monthly and last30 > 3 * expected_monthly:
        return {"rule": "Velocity spike", "weight": 25,
                "reason": f"30-day volume {last30:,.0f} is {last30/expected_monthly:.1f}x the declared {expected_monthly:,.0f}"}


def fan_in(t: pd.DataFrame, days=5, min_senders=8):
    recent = t[(t.direction == "in") & (t.timestamp >= t.timestamp.max() - pd.Timedelta(days=days))]
    n = recent.counterparty_id.nunique()
    if n >= min_senders:
        return {"rule": "Fan-in", "weight": 25,
                "reason": f"{n} different senders in {days} days"}


def rapid_movement(t: pd.DataFrame, hours=24, share=0.8):
    ins = t[t.direction == "in"].sort_values("timestamp")
    outs = t[t.direction == "out"]
    for _, row in ins.iterrows():
        window = outs[(outs.timestamp > row.timestamp) &
                      (outs.timestamp <= row.timestamp + pd.Timedelta(hours=hours))]
        if window.amount.sum() >= share * row.amount and row.amount > 1000:
            return {"rule": "Rapid in-and-out", "weight": 20,
                    "reason": f"{window.amount.sum()/row.amount:.0%} of a {row.amount:,.0f} deposit left within {hours}h"}


def high_risk_country(t: pd.DataFrame):
    hit = t[t.country.isin(HIGH_RISK_COUNTRIES)]
    if len(hit):
        return {"rule": "High-risk jurisdiction", "weight": 30,
                "reason": f"{len(hit)} transactions involving {', '.join(sorted(hit.country.unique()))}"}


def dormant_reactivation(t: pd.DataFrame, quiet_days=90):
    s = t.sort_values("timestamp").timestamp
    gaps = s.diff().dt.days
    if len(gaps) and gaps.max() >= quiet_days and t.amount.tail(5).sum() > 5000:
        return {"rule": "Dormant account reactivated", "weight": 15,
                "reason": f"Inactive for {int(gaps.max())} days, then {t.amount.tail(5).sum():,.0f} moved"}


def card_risk(t: pd.DataFrame):
    cards = t[t.channel == "card"]
    risky = cards[cards.merchant_category.isin({"gambling", "crypto_exchange", "money_transfer", "gift_cards"})]
    if len(cards) and len(risky) / len(cards) > 0.5:
        return {"rule": "Card spend pattern", "weight": 15,
                "reason": f"{len(risky)} of {len(cards)} card payments at gambling, gift card or crypto merchants"}


def run_rules(t: pd.DataFrame, profile: dict) -> list[dict]:
    checks = [structuring(t), velocity_spike(t, profile.get("expected_monthly", 0)), fan_in(t),
              rapid_movement(t), high_risk_country(t), dormant_reactivation(t), card_risk(t)]
    return [c for c in checks if c]

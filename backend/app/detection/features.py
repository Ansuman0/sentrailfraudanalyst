"""Per-customer behavioural features for the ML model, with plain-language names."""
import pandas as pd

LABELS = {
    "vol_30d": "30-day volume",
    "vol_ratio": "Volume vs declared income",
    "tx_count_7d": "Transactions in last 7 days",
    "uniq_senders_7d": "New senders in last 7 days",
    "near_threshold_share": "Share of amounts just below reporting threshold",
    "round_amount_share": "Share of round-number amounts",
    "out_in_ratio": "Money out vs money in",
    "crypto_share": "Share moved through crypto",
    "night_share": "Share of activity between midnight and 5am",
}


def build(t: pd.DataFrame, profile: dict) -> dict:
    end = t.timestamp.max()
    d30 = t[t.timestamp >= end - pd.Timedelta(days=30)]
    d7 = t[t.timestamp >= end - pd.Timedelta(days=7)]
    ins, outs = t[t.direction == "in"].amount.sum(), t[t.direction == "out"].amount.sum()
    exp = profile.get("expected_monthly") or 1
    return {
        "vol_30d": d30.amount.sum(),
        "vol_ratio": d30.amount.sum() / exp,
        "tx_count_7d": len(d7),
        "uniq_senders_7d": d7[d7.direction == "in"].counterparty_id.nunique(),
        "near_threshold_share": ((t.amount >= 9000) & (t.amount < 10000)).mean(),
        "round_amount_share": (t.amount % 100 == 0).mean(),
        "out_in_ratio": outs / ins if ins else 0,
        "crypto_share": (t.channel == "crypto").mean(),
        "night_share": (t.timestamp.dt.hour < 5).mean(),
    }


def build_all(txns: pd.DataFrame, profiles: dict) -> pd.DataFrame:
    rows = []
    for cid, t in txns.groupby("customer_id"):
        f = build(t, profiles.get(cid, {}))
        f["customer_id"] = cid
        if "is_laundering" in t:
            f["label"] = int(t.is_laundering.max())
        rows.append(f)
    return pd.DataFrame(rows).set_index("customer_id")

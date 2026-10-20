"""Loads an institution's OWN transaction data and scores its customers.

Data is per organization: data/orgs/<org_id>/transactions.parquet and profiles.json
(plus an optional model.joblib). The IBM demo dataset in data/ is served ONLY to the
organization named in DEMO_DATA_ORG_ID, so one tenant can never search or score
another tenant's customers.
"""
import json
import os
import pandas as pd
from functools import lru_cache

from app import config
from app.detection import rules, features, graph as graphmod, scorer


class NoData(KeyError):
    """This organization has no transaction history for the customer (or none at all)."""


def _data_dir(org_id) -> str | None:
    org_dir = f"{config.DATA_DIR}/orgs/{org_id}"
    if org_id and os.path.exists(f"{org_dir}/transactions.parquet"):
        return org_dir
    demo_org = os.environ.get("DEMO_DATA_ORG_ID")
    if org_id and demo_org and str(org_id) == demo_org and os.path.exists(f"{config.DATA_DIR}/transactions.parquet"):
        return config.DATA_DIR
    return None


@lru_cache(maxsize=16)
def load(org_id):
    path = _data_dir(org_id)
    if not path:
        raise NoData("No transaction data for this organization")
    t = pd.read_parquet(f"{path}/transactions.parquet")
    t["timestamp"] = pd.to_datetime(t["timestamp"])
    with open(f"{path}/profiles.json") as f:
        profiles = json.load(f)
    g = graphmod.build_graph(t)
    # Demo only: the dataset's laundering labels stand in for "accounts this institution already reported".
    flagged = set(t[t["is_laundering"] == 1].counterparty_id.unique()[:200]) if "is_laundering" in t else set()
    from app.detection.ml_model import RiskModel          # heavy (xgboost, shap): import only when needed
    model_path = f"{path}/model.joblib" if os.path.exists(f"{path}/model.joblib") else f"{config.DATA_DIR}/model.joblib"
    return t, profiles, g, flagged, RiskModel(model_path)


def has_data(org_id) -> bool:
    return _data_dir(org_id) is not None


def score_customer(org_id, cid: str) -> dict:
    t, profiles, g, flagged, model = load(org_id)
    ct = t[t.customer_id == cid]
    if ct.empty:
        raise NoData(cid)
    p = profiles.get(cid, {})
    hits = rules.run_rules(ct, p)
    ml = model.score(features.build(ct, p))
    net = graphmod.node_risk(g, ct.account_id.iloc[0], flagged)
    result = scorer.combine(hits, ml, net)
    return {"customer_id": cid, "profile": p, **result,
            "channels": sorted(ct.channel.unique().tolist()),
            "network": net.get("neighbors", [])}


def case_facts(org_id, cid: str, scored: dict, days: int = 90) -> dict:
    t, *_ = load(org_id)
    ct = t[t.customer_id == cid].sort_values("timestamp")
    ct = ct[ct.timestamp >= ct.timestamp.max() - pd.Timedelta(days=days)]
    by_channel = ct.groupby(["channel", "direction"]).amount.agg(["sum", "count"]).round(2)
    return {"profile": scored["profile"], "score": scored["score"], "reasons": scored["reasons"],
            "period_days": days,
            "totals": {f"{c}_{d}": {"total": r["sum"], "count": int(r["count"])}
                       for (c, d), r in by_channel.iterrows()},
            "transactions": ct.tail(40)[["timestamp", "direction", "amount", "currency", "channel",
                                         "counterparty_id", "country", "merchant_category"]]
                              .astype(str).to_dict("records")}


def screening_facts(alert: dict, screening: dict | None) -> dict:
    """Facts for an alert raised by real-time screening (no transaction history needed)."""
    return {"profile": {"customer_id": alert["customer_id"]}, "score": alert["score"], "reasons": alert["reasons"],
            "screening": screening or {}}


def customer_transactions(org_id, cid: str, channel: str | None = None) -> list[dict]:
    t, *_ = load(org_id)
    ct = t[t.customer_id == cid]
    if channel:
        ct = ct[ct.channel == channel]
    return ct.sort_values("timestamp", ascending=False).head(500).astype(str).to_dict("records")

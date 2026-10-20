"""Turn the IBM AMLworld CSV (Kaggle: 'IBM Transactions for Anti Money Laundering')
into AlertIQ's unified schema, add synthetic KYC profiles and card spend.

Usage: python scripts/prepare_data.py data/HI-Small_Trans.csv
"""
import json
import sys
import numpy as np
import pandas as pd

rng = np.random.default_rng(7)
src = pd.read_csv(sys.argv[1], nrows=int(sys.argv[2]) if len(sys.argv) > 2 else 500_000)
src.columns = ["timestamp", "from_bank", "from_acct", "to_bank", "to_acct", "amount_received",
               "receiving_currency", "amount_paid", "payment_currency", "payment_format", "is_laundering"]
src["timestamp"] = pd.to_datetime(src["timestamp"])
channel = src.payment_format.map({"Bitcoin": "crypto", "Credit Card": "card"}).fillna("bank")

out_rows = pd.DataFrame({"txn_id": [f"T{i}" for i in range(len(src))], "timestamp": src.timestamp,
                         "account_id": src.from_acct, "counterparty_id": src.to_acct, "direction": "out",
                         "amount": src.amount_paid, "currency": src.payment_currency, "channel": channel,
                         "is_laundering": src.is_laundering})
in_rows = out_rows.copy()
in_rows["account_id"], in_rows["counterparty_id"], in_rows["direction"] = src.to_acct, src.from_acct, "in"
in_rows["amount"], in_rows["currency"] = src.amount_received, src.receiving_currency
t = pd.concat([out_rows, in_rows], ignore_index=True)
t["customer_id"] = "C-" + t.account_id.astype("category").cat.codes.astype(str)
t["country"] = rng.choice(["CA", "US", "IN", "GB", "AE", "IR"], len(t), p=[.55, .2, .12, .08, .049, .001])
t["merchant_category"] = np.where(t.channel == "card",
                                  rng.choice(["grocery", "travel", "gambling", "gift_cards", "crypto_exchange"], len(t)), "")
t["card_last4"] = np.where(t.channel == "card", rng.integers(1000, 9999, len(t)).astype(str), "")
t.to_parquet("data/transactions.parquet")

profiles = {}
for cid, g in t.groupby("customer_id"):
    monthly = g[g.direction == "in"].amount.sum() / max(g.timestamp.dt.month.nunique(), 1)
    profiles[cid] = {"customer_id": cid, "occupation": rng.choice(["Student", "Engineer", "Retail worker", "Business owner"]),
                     "country": "CA", "kyc_risk": rng.choice(["low", "medium", "high"], p=[.7, .25, .05]),
                     "expected_monthly": round(float(monthly) * rng.uniform(0.6, 1.4), 2)}
json.dump(profiles, open("data/profiles.json", "w"))
print(f"{len(t):,} rows, {len(profiles):,} customers")

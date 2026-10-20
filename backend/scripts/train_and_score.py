"""Train the model, then score every customer and fill one organization's alert queue.
The demo dataset belongs to that organization only: put the same id in .env as DEMO_DATA_ORG_ID.
Usage: SEED_ORG_ID=<org uuid> python -m scripts.train_and_score"""
import json
import os
import pandas as pd
from app.detection import features, rules
from app.detection.ml_model import train
from app.services import cases
from app import db

org = os.environ["SEED_ORG_ID"]
os.environ.setdefault("DEMO_DATA_ORG_ID", org)
if os.environ["DEMO_DATA_ORG_ID"] != org:
    raise SystemExit("DEMO_DATA_ORG_ID points at a different organization than SEED_ORG_ID")

t = pd.read_parquet("data/transactions.parquet")
profiles = json.load(open("data/profiles.json"))
feats = features.build_all(t, profiles)
print("Model:", train(feats))

cases.load.cache_clear()
candidates = [cid for cid, ct in t.groupby("customer_id") if rules.run_rules(ct, profiles.get(cid, {}))]
print(f"{len(candidates)} customers hit at least one rule")
for i, cid in enumerate(candidates):
    s = cases.score_customer(org, cid)
    db.save_alert(org, {"id": f"A-{1000+i}", "customer_id": cid, "score": s["score"], "band": s["band"],
                        "reasons": s["reasons"][:4], "channel": ",".join(s["channels"])})
print(f"Alert queue ready. Add DEMO_DATA_ORG_ID={org} to .env so the API serves this data to that organization only.")

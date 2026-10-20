"""Synthetic sample data for the demo organizations, so a compliance officer has something to work with. ALL FAKE.

  python -m scripts.seed_demo_data        # after `python -m scripts.seed --demo`; safe to run again (it refreshes the same data)

For each demo organization it
  1. generates ~120 days of transactions for a few hundred made-up customers (normal salaried, small-business and crypto-hobby
     customers, plus customers that show the patterns the detection rules look for),
  2. writes data/orgs/<org_id>/transactions.parquet + profiles.json and trains a small risk model on them (model.joblib),
  3. scores every customer with the real detection code and raises an alert for each one at or above the "medium" band,
  4. adds a few real-time crypto screenings (the "Screened transfer" view) and a mix of alert statuses.
Wallet addresses are real public addresses, used only as labels; the screening results attached to them are made up.
Refuses to run when ENV is production. The model is trained on this synthetic data and is for demonstration only.
Run it where the API runs (it writes under DATA_DIR): `docker compose exec -T api python - < backend/scripts/seed_demo_data.py`.
"""
import json
import os
import random
import sys

import numpy as np
import pandas as pd

from app import config, pg
from app.security import audit
from app.detection import features, ml_model
from app.services import cases

DAYS = 120
END = pd.Timestamp.now().floor("h")
BAND_MEDIUM = 41

# Real, public addresses. They are only shown as counterparties; nothing here claims they are sanctioned.
WALLETS = ["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G",
           "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
           "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]

ORGS = [
    {"name": "Northwind Remit Inc.", "prefix": "C", "seed": 11, "normal": 220, "alert_base": 2000, "tag": "nw",
     "named": {"fan_in_crypto": ["C-2291"], "structuring": ["C-1877"], "card_risk": ["C-0954"]},
     "extra": {"fan_in_crypto": 2, "structuring": 1, "high_risk_country": 2, "dormant": 1, "pass_through": 2, "velocity": 1,
               "borderline_velocity": 2, "borderline_card": 1, "borderline_structuring": 1}, "rings": 1,
     "known_alerts": {"C-2291": "A-1042", "C-1877": "A-1039", "C-0954": "A-1033"}},
    {"name": "Maple Ridge Digital Assets", "prefix": "M", "seed": 23, "normal": 160, "alert_base": 3000, "tag": "mr",
     "named": {}, "extra": {"fan_in_crypto": 3, "structuring": 1, "card_risk": 1, "high_risk_country": 1, "dormant": 1,
                            "pass_through": 1, "velocity": 1, "borderline_velocity": 1, "borderline_card": 1,
                            "borderline_structuring": 1}, "rings": 1, "known_alerts": {}},
]

SCREENINGS = [  # customer (not in the transaction data, so the case view shows the screening), direction, address, amount, asset, decision, score, reasons, signals
    ("X-9101", "withdrawal", "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G", 4800, "USDT", "hold", 58,
     ["Transfer is above the Travel Rule threshold and no Travel Rule data was supplied"], ["Wallet received from 41 different senders in 3 days"]),
    ("X-9102", "deposit", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", 1.25, "ETH", "release", 8, [], []),
    ("X-9103", "withdrawal", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0.31, "BTC", "hold", 49,
     ["Self-hosted wallet: ownership not proven for this amount"], ["Wallet is old, but has received many small deposits recently"]),
    ("X-9104", "withdrawal", "TDemoScamCluster11111111111111111X", 12500, "USDT", "block", 100,
     ["Destination wallet is on the demo internal blocklist"], ["Reported as an investment scam cluster (demo list)"]),
    ("X-9105", "deposit", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 900, "USDT", "release", 12, [], []),
    ("X-9106", "withdrawal", "0x8589427373D6D84E98730D7795D8f6f8731FDA16", 2.4, "ETH", "hold", 66,
     ["Funds would reach a mixing service within two hops"], ["Counterparty is a privacy-protocol contract"]),
]


def acct(cid):
    return f"ACC-{cid}"


class Book:
    def __init__(self, rng):
        self.rng, self.rows, self.n = rng, [], 0

    def at(self, days_ago, hour=None):
        h = self.rng.randint(8, 20) if hour is None else hour
        t = (END - pd.Timedelta(days=days_ago)).replace(hour=h, minute=self.rng.randint(0, 59))
        return min(t, END)

    def add(self, cid, days_ago, direction, amount, channel="bank", cp="", country="CA", mcc="", currency="CAD", label=0, hour=None):
        self.n += 1
        self.rows.append({"txn_id": f"T{self.n:07d}", "timestamp": self.at(days_ago, hour), "customer_id": cid,
                          "account_id": acct(cid), "counterparty_id": cp, "direction": direction,
                          "amount": round(float(amount), 2), "currency": currency, "channel": channel, "country": country,
                          "merchant_category": mcc, "card_last4": f"{self.rng.randint(0, 9999):04d}" if channel == "card" else "",
                          "is_laundering": label})


MCC = ["groceries", "restaurants", "fuel", "retail", "transit", "pharmacy", "utilities"]


def card_spend(b, cid, days, per_week=(3, 6), amounts=(8, 140)):
    for d in np.arange(0.5, days, 7):
        for _ in range(b.rng.randint(*per_week)):
            mcc = b.rng.choice(MCC)
            b.add(cid, d + b.rng.uniform(0, 6.5), "out", b.rng.uniform(*amounts), "card", f"MRC-{mcc}-{b.rng.randint(1, 6)}", mcc=mcc)


def salaried(b, cid, salary, months=5, card=True):
    emp = f"ACC-EMP{b.rng.randint(100, 999)}"
    for m in range(months):
        b.add(cid, m * 30 + 2 + b.rng.randint(0, 2), "in", salary * b.rng.uniform(0.98, 1.02), cp=emp, mcc="payroll")
        b.add(cid, m * 30 + 5 + b.rng.randint(0, 2), "out", round(salary * 0.3, -1), cp=f"ACC-LANDLORD{b.rng.randint(1, 40)}", mcc="rent")
        for _ in range(b.rng.randint(1, 3)):
            b.add(cid, m * 30 + b.rng.uniform(8, 28), b.rng.choice(["in", "out"]), b.rng.uniform(40, 400), cp=f"ACC-F{b.rng.randint(1, 9)}-{cid}")
    if card:
        card_spend(b, cid, months * 30)


def normal_customer(b, cid):
    kind = b.rng.choices(["salaried", "business", "saver", "crypto"], [50, 20, 18, 12])[0]
    if kind == "business":
        clients = [f"ACC-CL{i}-{cid}" for i in range(5)]
        for m in range(5):
            for _ in range(b.rng.randint(3, 6)):
                d = m * 30 + b.rng.uniform(1, 27)
                b.add(cid, d, "in", b.rng.uniform(800, 4500), cp=b.rng.choice(clients), mcc="invoice")
                b.add(cid, d + b.rng.uniform(2, 5), "out", b.rng.uniform(500, 3000), cp=f"ACC-SUP{b.rng.randint(1, 4)}-{cid}", mcc="supplier")
        card_spend(b, cid, 150, (1, 3))
    else:
        salaried(b, cid, b.rng.choice(range(1800 if kind == "saver" else 2800, 7500, 100)), card=kind != "saver")
        if kind == "crypto":
            for _ in range(b.rng.randint(2, 5)):
                b.add(cid, b.rng.uniform(1, 110), "out", b.rng.uniform(100, 900), "crypto", "EXCH-01", currency="USDT")


def baseline(b, cid):
    salaried(b, cid, b.rng.choice(range(3000, 6000, 100)), months=4)


# ---- Patterns the detection rules look for. Each writes its own background activity, then the suspicious rows (label 1) ----
def fan_in_crypto(b, cid, wallet=None):
    baseline(b, cid)
    wallet = wallet or b.rng.choice(WALLETS)
    total = 0
    for i in range(12):
        a = b.rng.uniform(600, 2400); total += a
        b.add(cid, b.rng.uniform(1.0, 4.6), "in", a, cp=f"ACC-X{i}-{cid}", label=1)
    b.add(cid, 0.6, "out", total * 0.55, "crypto", wallet, currency="USDT", label=1)
    b.add(cid, 0.4, "out", total * 0.33, "crypto", wallet, currency="USDT", label=1)
    return 3000


def structuring(b, cid):
    baseline(b, cid)
    for d in sorted(b.rng.sample([0.5, 1.4, 2.6, 3.8, 5.0, 5.6], 5)):
        b.add(cid, d, "in", b.rng.uniform(9100, 9900), "cash", f"BRANCH-0{b.rng.randint(10, 60)}", label=1)
    return 4000


def card_risk(b, cid):
    salaried(b, cid, 3200, months=2, card=False)
    for i in range(40):
        risky = b.rng.random() < 0.72
        mcc = b.rng.choice(["gambling", "gift_cards", "crypto_exchange", "money_transfer"]) if risky else b.rng.choice(MCC)
        b.add(cid, b.rng.uniform(0.2, 45), "out", b.rng.uniform(40, 400), "card", f"MRC-{mcc}-{b.rng.randint(1, 5)}", mcc=mcc, label=int(risky))
    return 3200


def high_risk_country(b, cid):
    baseline(b, cid)
    for i in range(3):
        d = 6 + i * 12
        amt = b.rng.uniform(6000, 12000)
        b.add(cid, d, "in", amt, cp=f"ACC-SRC{i}-{cid}", label=1, hour=9)
        cc = b.rng.choice(["IR", "MM", "KP"])
        b.add(cid, d - 0.5, "out", amt * 0.45, "wire", f"ACC-{cc}-{b.rng.randint(100, 999)}", country=cc, label=1, hour=17)
        b.add(cid, d - 0.6, "out", amt * 0.45, "wire", f"ACC-{cc}-{b.rng.randint(100, 999)}", country=cc, label=1, hour=18)
    return 3500


def dormant(b, cid):
    for d in (121, 119, 118):
        b.add(cid, d, "in", b.rng.uniform(80, 400), cp=f"ACC-F1-{cid}")
    for d, direction, a in ((4.0, "in", 8800), (3.2, "in", 9400), (2.5, "in", 6900), (1.9, "out", 12000), (1.5, "out", 12500)):
        b.add(cid, d, direction, a * b.rng.uniform(0.95, 1.0), cp=f"ACC-DRM{b.rng.randint(1, 9)}-{cid}", label=1)
    return 2000


def pass_through(b, cid):
    baseline(b, cid)
    amt = b.rng.uniform(32000, 58000)
    b.add(cid, 2.0, "in", amt, "wire", f"ACC-PT-{cid}", label=1, hour=9)
    for i, share in enumerate((0.4, 0.3, 0.22)):
        b.add(cid, 1.9 - i * 0.08, "out", amt * share, "wire", f"ACC-PTO{i}-{cid}", country="AE", label=1, hour=14 + i)
    return 3500


def velocity(b, cid):
    baseline(b, cid)
    for _ in range(25):
        b.add(cid, b.rng.uniform(0.3, 28), b.rng.choice(["in", "out"]), b.rng.uniform(900, 2800), cp=f"ACC-V{b.rng.randint(1, 4)}-{cid}", label=1)
    return 3000


def borderline_velocity(b, cid):          # busy month, explained: not labelled
    baseline(b, cid)
    for _ in range(8):
        b.add(cid, b.rng.uniform(0.5, 25), "out", b.rng.uniform(800, 1900), cp=f"ACC-BV-{cid}")
    return 3200


def borderline_card(b, cid):
    salaried(b, cid, 2400, months=2, card=False)
    for i in range(30):
        risky = b.rng.random() < 0.58
        mcc = b.rng.choice(["gift_cards", "gambling"]) if risky else b.rng.choice(MCC)
        b.add(cid, b.rng.uniform(0.2, 40), "out", b.rng.uniform(20, 150), "card", f"MRC-{mcc}-{b.rng.randint(1, 5)}", mcc=mcc)
    return 2400


def borderline_structuring(b, cid):       # three deposits just under the threshold, e.g. proceeds of a sale
    baseline(b, cid)
    for d in (1.5, 3.0, 4.5):
        b.add(cid, d, "in", b.rng.uniform(9200, 9700), cp=f"ACC-SALE-{cid}")
    return 4500


PATTERNS = {f.__name__: f for f in (fan_in_crypto, structuring, card_risk, high_risk_country, dormant, pass_through, velocity,
                                    borderline_velocity, borderline_card, borderline_structuring)}


def ring(b, cids):
    for r, d in enumerate((20, 14, 8, 3)):
        for i, cid in enumerate(cids):
            nxt = cids[(i + 1) % len(cids)]
            amt = b.rng.uniform(7000, 8200)
            b.add(cid, d + 0.1 * i, "out", amt, cp=acct(nxt), label=1, hour=10)
            b.add(nxt, d + 0.1 * i - 0.05, "in", amt, cp=acct(cid), label=1, hour=10)
    for cid in cids:
        card_spend(b, cid, 60)


def build_org(spec):
    rng = random.Random(spec["seed"])
    np.random.seed(spec["seed"])
    b = Book(rng)
    declared, used = {}, set()

    def new_id():
        while True:
            cid = f"{spec['prefix']}-{rng.randint(1000, 9899)}"
            if cid not in used:
                used.add(cid); return cid

    for ids in spec["named"].values():
        used.update(ids)
    for kind, ids in spec["named"].items():
        for cid in ids:
            declared[cid] = PATTERNS[kind](b, cid)
    for kind, n in spec["extra"].items():
        for i in range(n):
            cid = new_id()
            declared[cid] = PATTERNS[kind](b, cid, WALLETS[3]) if kind == "fan_in_crypto" and i == 1 else PATTERNS[kind](b, cid)
    ring_ids = [[new_id() for _ in range(3)] for _ in range(spec["rings"])]
    for ids in ring_ids:
        ring(b, ids)
        declared.update({cid: 3000 for cid in ids})
    for _ in range(spec["normal"]):
        normal_customer(b, new_id())

    t = pd.DataFrame(b.rows).sort_values("timestamp").reset_index(drop=True)
    profiles = {}
    for cid, g in t.groupby("customer_id"):
        exp = declared.get(cid) or max(1000, round(g[g.direction == "in"].amount.sum() / (DAYS / 30) * 1.15, -2))
        profiles[cid] = {"customer_id": cid, "expected_monthly": exp, "country": "CA", "occupation": "synthetic demo customer"}
    return t, profiles


def refresh_org(org_id, spec):
    t, profiles = build_org(spec)
    d = f"{config.DATA_DIR}/orgs/{org_id}"
    os.makedirs(d, exist_ok=True)
    t.to_parquet(f"{d}/transactions.parquet")
    with open(f"{d}/profiles.json", "w") as f:
        json.dump(profiles, f)
    ml_model.MODEL_PATH = f"{d}/model.joblib"
    metrics = ml_model.train(features.build_all(t, profiles))
    cases.load.cache_clear()
    scored = {cid: cases.score_customer(str(org_id), cid) for cid in profiles}
    return t, scored, metrics


def write_alerts(org_id, spec, scored):
    todo = sorted(((c, s) for c, s in scored.items() if s["score"] >= BAND_MEDIUM), key=lambda cs: -cs[1]["score"])
    ids, n = {}, 0
    for cid, _ in todo:
        if cid in spec["known_alerts"]:
            ids[cid] = spec["known_alerts"][cid]
        else:
            n += 1; ids[cid] = f"A-{spec['alert_base'] + n}"
    rng = random.Random(spec["seed"] + 1)
    with pg.tx(str(org_id)) as cur:
        for rank, (cid, s) in enumerate(todo):
            channels = ",".join(s["channels"])
            cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, created_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s, now() - make_interval(hours => %s))
                           ON CONFLICT (org_id, id) DO UPDATE SET customer_id=EXCLUDED.customer_id, score=EXCLUDED.score,
                           band=EXCLUDED.band, reasons=EXCLUDED.reasons, channel=EXCLUDED.channel, created_at=EXCLUDED.created_at""",
                        (ids[cid], org_id, cid, s["score"], s["band"], json.dumps(s["reasons"]), channels, rng.randint(1, 90)))
        # a believable mix of statuses (set directly: this is sample data, not analyst decisions)
        movable = [ids[c] for c, _ in todo if c not in spec["known_alerts"]]
        for status, picks in (("escalated", movable[1:3]), ("pending_info", movable[4:6]), ("closed", movable[-3:])):
            for aid in picks:
                cur.execute("UPDATE alerts SET status=%s WHERE id=%s", (status, aid))
    return len(todo)


def write_screenings(org_id, spec):
    with pg.tx(str(org_id)) as cur:
        for i, (cust, direction, addr, amount, asset, decision, score, reasons, signals) in enumerate(SCREENINGS, 1):
            sid = f"S-demo{spec['tag']}{i:02d}"
            network = "tron" if addr.startswith("T") else "bitcoin" if addr[0] in "13b" else "ethereum"
            result = {"decision": decision, "score": score, "reasons": reasons, "signals": signals, "network": network,
                      "direct_listing": {"source": "Internal blocklist", "label": "Demo blocklisted wallet"} if decision == "block" else None,
                      "indirect_exposure": [], "wallet_age_days": 420 - i * 37, "fiat_value": float(amount), "checks_complete": True,
                      "demo": True}
            cur.execute("""INSERT INTO screenings (id, org_id, customer_id, direction, address, amount, score, decision, reasons,
                                                   client_ref, asset, fiat_value, result)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                        (sid, org_id, cust, direction, addr, amount, score, decision, json.dumps(reasons + signals),
                         f"demo-{spec['tag']}-{i}", asset, float(amount), json.dumps(result)))
            if decision in ("hold", "block"):
                cur.execute("""INSERT INTO alerts (id, org_id, customer_id, score, band, reasons, channel, status, screening_id)
                               VALUES (%s,%s,%s,%s,%s,%s,'crypto','open',%s) ON CONFLICT DO NOTHING""",
                            (f"A-{sid}", org_id, cust, score, "high" if decision == "block" else "medium",
                             json.dumps([{"source": "Screening", "text": r} for r in (reasons + signals)][:4]), sid))


def main():
    if config.ENV == "production":
        sys.exit("Refusing to create sample data in production")
    for spec in ORGS:
        with pg.tx(platform=True) as cur:
            cur.execute("SELECT id FROM organizations WHERE legal_name=%s", (spec["name"],))
            row = cur.fetchone()
        if not row:
            print(f"{spec['name']}: organization not found (run `python -m scripts.seed --demo` first), skipping"); continue
        org_id = row[0]
        t, scored, metrics = refresh_org(org_id, spec)
        n = write_alerts(org_id, spec, scored)
        write_screenings(org_id, spec)
        with pg.tx(platform=True) as cur:
            audit.write(cur, org_id, None, "operator", "demo_data_seeded", spec["name"], {"customers": len(scored), "alerts": n})
        bands = pd.Series([s["band"] for s in scored.values()]).value_counts().to_dict()
        print(f"{spec['name']}: {len(t):,} transactions, {len(scored)} customers, {n} alerts, bands {bands}, model AP {metrics['average_precision']}")


if __name__ == "__main__":
    main()

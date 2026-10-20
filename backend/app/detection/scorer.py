"""Blend rules + ML + graph into one 0-100 score with the reasons kept attached."""
from app import config


def combine(rule_hits: list[dict], ml: dict, graph: dict) -> dict:
    rule_score = min(100, sum(h["weight"] for h in rule_hits) * 1.5)
    w = config.WEIGHTS
    score = int(round(w["rules"] * rule_score + w["ml"] * ml["score"] + w["graph"] * graph["score"]))
    band = next(b for threshold, b in config.BANDS if score >= threshold)
    reasons = ([{"source": "rule", "text": h["reason"]} for h in rule_hits] +
               [{"source": "model", "text": f"{r['factor']}: {r['value']}", "share": r["share"]} for r in ml["reasons"]] +
               [{"source": "network", "text": t} for t in graph["reasons"]])
    return {"score": score, "band": band, "reasons": reasons,
            "parts": {"rules": round(rule_score), "ml": ml["score"], "graph": graph["score"]}}

"""Follow the money from one wallet, up to N hops.

Hop 0 = the address the analyst entered.
At each hop we keep only the largest outgoing counterparties (fan_out)
so the graph stays readable and API calls stay within free limits.
"""
from collections import defaultdict
from app.connectors.blockchain import fetch_transfers, detect_network
from app.connectors import risk_lists

HOP_RISK = {0: 100, 1: 80, 2: 60, 3: 40}  # exposure score by distance to a flagged wallet


def _summarize(address: str, transfers: list[dict]) -> dict:
    a = address.lower() if address.startswith("0x") else address
    def same(x): return (x.lower() if x.startswith("0x") else x) == a
    inflow = sum(t["amount"] for t in transfers if same(t["to"]))
    outflow = sum(t["amount"] for t in transfers if same(t["from"]))
    senders = {t["from"] for t in transfers if same(t["to"])}
    receivers = {t["to"] for t in transfers if same(t["from"])}
    times = sorted(t["timestamp"] for t in transfers)
    return {"inflow": round(inflow, 2), "outflow": round(outflow, 2),
            "unique_senders": len(senders), "unique_receivers": len(receivers),
            "tx_count": len(transfers), "first_seen": times[0] if times else None,
            "last_seen": times[-1] if times else None}


def _top_receivers(address: str, transfers: list[dict], n: int) -> list[tuple[str, float]]:
    totals = defaultdict(float)
    norm = lambda x: x.lower() if x.startswith("0x") else x
    for t in transfers:
        if norm(t["from"]) == norm(address) and norm(t["to"]) != norm(address):
            totals[t["to"]] += t["amount"]
    return sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:n]


async def trace(address: str, hops: int = 2, fan_out: int = 5) -> dict:
    network = detect_network(address)
    if not network:
        raise ValueError("Not a recognised wallet address")

    nodes, edges, hits = {}, [], []
    frontier = [address]
    summary = None

    for hop in range(hops + 1):
        next_frontier = []
        for addr in frontier:
            if addr in nodes:
                continue
            flag = await risk_lists.screen(addr)
            nodes[addr] = {"id": addr, "hop": hop, "flag": flag}
            if flag:
                hits.append({"address": addr, "hop": hop, **flag})
            if hop == hops:
                continue  # last layer: screen only, don't expand
            _, transfers = await fetch_transfers(addr)
            if hop == 0:
                summary = _summarize(addr, transfers)
            for to, amount in _top_receivers(addr, transfers, fan_out):
                edges.append({"from": addr, "to": to, "amount": round(amount, 2), "hop": hop + 1})
                next_frontier.append(to)
        frontier = next_frontier

    exposure = max((HOP_RISK.get(h["hop"], 20) for h in hits), default=0)
    return {"address": address, "network": network, "summary": summary,
            "nodes": list(nodes.values()), "edges": edges, "risk_hits": hits,
            "exposure_score": exposure,
            "explanation": _explain(hits)}


def _explain(hits: list[dict]) -> str:
    if not hits:
        return "No links to listed wallets found within the traced hops."
    closest = min(hits, key=lambda h: h["hop"])
    if closest["hop"] == 0:
        return f"This wallet is itself listed: {closest['label']} ({closest['source']})."
    return (f"Funds reach a listed wallet ({closest['label']}, {closest['source']}) "
            f"{closest['hop']} hop(s) away from this address.")

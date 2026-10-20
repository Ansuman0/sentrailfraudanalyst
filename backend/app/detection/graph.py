"""Network view of money movement: catches rings that look normal one payment at a time."""
import networkx as nx
import pandas as pd


def build_graph(txns: pd.DataFrame) -> nx.DiGraph:
    g = nx.DiGraph()
    for r in txns.itertuples():
        src, dst = (r.counterparty_id, r.account_id) if r.direction == "in" else (r.account_id, r.counterparty_id)
        if g.has_edge(src, dst):
            g[src][dst]["amount"] += r.amount
            g[src][dst]["count"] += 1
        else:
            g.add_edge(src, dst, amount=r.amount, count=1)
    return g


def node_risk(g: nx.DiGraph, account: str, flagged: set[str]) -> dict:
    if account not in g:
        return {"score": 0, "reasons": []}
    reasons, score = [], 0
    indeg, outdeg = g.in_degree(account), g.out_degree(account)
    if indeg >= 8 and outdeg <= 2:
        score += 35; reasons.append(f"Collects from {indeg} accounts and pays out to {outdeg} (funnel pattern)")
    try:
        cycles = [c for c in nx.simple_cycles(g.subgraph(nx.ego_graph(g, account, radius=3, undirected=True)))
                  if account in c and len(c) <= 4]
    except nx.NetworkXNoCycle:
        cycles = []
    if cycles:
        score += 30; reasons.append(f"Money returns to this account through a loop of {len(cycles[0])} accounts")
    und = g.to_undirected()
    dists = [nx.shortest_path_length(und, account, f) for f in flagged if f in und and nx.has_path(und, account, f)]
    if dists:
        d = min(dists)
        score += {1: 40, 2: 25, 3: 15}.get(d, 5)
        reasons.append(f"{d} hop(s) from a previously reported account")
    return {"score": min(score, 100), "reasons": reasons,
            "neighbors": [{"from": u, "to": v, **a} for u, v, a in g.edges(account, data=True)][:25]}

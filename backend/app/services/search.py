"""One search box: figure out what the analyst typed, then route it."""
import re
from app.connectors.blockchain import detect_network

def classify(q: str) -> dict:
    q = q.strip()
    network = detect_network(q)
    if network:
        return {"kind": "wallet", "network": network, "value": q}
    if re.fullmatch(r"(0x)?[a-fA-F0-9]{64}", q):
        return {"kind": "tx_hash", "value": q}
    if re.fullmatch(r"\d{4}", q) or q.lower().startswith("tok_"):
        return {"kind": "card", "value": q}  # last-4 or processor token, never a full PAN
    if re.fullmatch(r"\d{12,19}", q):
        return {"kind": "rejected", "value": None,
                "message": "Full card numbers aren't accepted. Search by last 4 digits or card token."}
    if re.fullmatch(r"C-\d+", q, re.I):
        return {"kind": "customer", "value": q.upper()}
    if re.fullmatch(r"[A-Z0-9]{6,20}", q, re.I):
        return {"kind": "account", "value": q}
    return {"kind": "name", "value": q}

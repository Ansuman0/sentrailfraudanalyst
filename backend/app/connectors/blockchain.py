"""Live on-chain data from free public APIs.

TRON  -> TronGrid  (TRC-20 transfers, e.g. USDT)
EVM   -> Etherscan API v2 (ERC-20 transfers + native ETH)
BTC   -> mempool.space (basic history)

Every connector returns the same normalized shape so the tracer
doesn't care which chain the money moved on. Each one also says whether it
returned the wallet's COMPLETE history or only the most recent page: callers
must not treat the oldest transfer of a partial page as the wallet's first use.
"""
import re
from datetime import datetime, timezone
import httpx

from app import config
from app.observability import observed

TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
EVM_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
BTC_RE = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")


def detect_network(address: str) -> str | None:
    address = address.strip()
    if TRON_RE.match(address):
        return "tron"
    if EVM_RE.match(address):
        return "ethereum"
    if BTC_RE.match(address):
        return "bitcoin"
    return None


def _ts(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def _transfer(tx_hash, frm, to, amount, asset, ts, network):
    return {"hash": tx_hash, "from": frm, "to": to, "amount": round(amount, 6),
            "asset": asset, "timestamp": ts, "network": network}


@observed("trongrid", "fetch_trc20_transfers")
async def fetch_tron(address: str, limit: int = 200) -> tuple[list[dict], bool]:
    headers = {"TRON-PRO-API-KEY": config.TRONGRID_API_KEY} if config.TRONGRID_API_KEY else {}
    url = f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20"
    params = {"limit": min(limit, 200), "only_confirmed": "true"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url, params=params, headers=headers)
        r.raise_for_status()
        body = r.json()
        rows = body.get("data", [])
    complete = len(rows) < min(limit, 200) and not body.get("meta", {}).get("fingerprint")
    out = []
    for t in rows:
        info = t.get("token_info", {})
        decimals = int(info.get("decimals", 6))
        out.append(_transfer(t["transaction_id"], t["from"], t["to"],
                             int(t["value"]) / 10 ** decimals, info.get("symbol", "TRC20"),
                             _ts(t["block_timestamp"] / 1000), "tron"))
    return out, complete


@observed("etherscan", "fetch_eth_transfers")
async def fetch_ethereum(address: str, limit: int = 200) -> tuple[list[dict], bool]:
    if not config.ETHERSCAN_API_KEY:
        raise RuntimeError("Set ETHERSCAN_API_KEY in .env to trace Ethereum wallets")
    base = "https://api.etherscan.io/v2/api"
    common = {"chainid": 1, "address": address, "sort": "desc", "page": 1,
              "offset": min(limit, 1000), "apikey": config.ETHERSCAN_API_KEY}
    out, complete = [], True
    async with httpx.AsyncClient(timeout=20) as client:
        tok = (await client.get(base, params={**common, "module": "account", "action": "tokentx"})).json()
        tok_rows = tok.get("result", []) if isinstance(tok.get("result"), list) else []
        complete &= len(tok_rows) < common["offset"]
        for t in tok_rows:
            out.append(_transfer(t["hash"], t["from"], t["to"],
                                 int(t["value"]) / 10 ** int(t.get("tokenDecimal") or 18),
                                 t.get("tokenSymbol", "ERC20"), _ts(int(t["timeStamp"])), "ethereum"))
        eth = (await client.get(base, params={**common, "module": "account", "action": "txlist"})).json()
        eth_rows = eth.get("result", []) if isinstance(eth.get("result"), list) else []
        complete &= len(eth_rows) < common["offset"]
        for t in eth_rows:
            if int(t.get("value", 0)) > 0:
                out.append(_transfer(t["hash"], t["from"], t["to"], int(t["value"]) / 1e18,
                                     "ETH", _ts(int(t["timeStamp"])), "ethereum"))
    return out, complete


MEMPOOL_PAGE = 25   # mempool.space returns at most 25 confirmed transactions per page


@observed("mempool.space", "fetch_btc_transfers")
async def fetch_bitcoin(address: str, limit: int = 50) -> tuple[list[dict], bool]:
    """Simplified: records value flowing into or out of the address per tx."""
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"https://mempool.space/api/address/{address}/txs")
        r.raise_for_status()
        page = r.json()
    complete = len(page) < MEMPOOL_PAGE
    txs = page[:limit]
    out = []
    for tx in txs:
        ts = _ts(tx.get("status", {}).get("block_time", 0))
        senders = {v["prevout"].get("scriptpubkey_address") for v in tx["vin"] if v.get("prevout")}
        for v in tx["vout"]:
            to = v.get("scriptpubkey_address")
            if to and (address in senders or to == address):
                frm = address if address in senders else next(iter(senders), "unknown")
                out.append(_transfer(tx["txid"], frm, to, v["value"] / 1e8, "BTC", ts, "bitcoin"))
    return out, complete


async def fetch_history(address: str) -> tuple[str, list[dict], bool]:
    """(network, transfers, complete). complete=False means older history exists that wasn't fetched."""
    network = detect_network(address)
    if network == "tron":
        return network, *await fetch_tron(address)
    if network == "ethereum":
        return network, *await fetch_ethereum(address)
    if network == "bitcoin":
        return network, *await fetch_bitcoin(address)
    raise ValueError("Not a recognised TRON, Ethereum or Bitcoin address")


async def fetch_transfers(address: str) -> tuple[str, list[dict]]:
    network, transfers, _ = await fetch_history(address)
    return network, transfers

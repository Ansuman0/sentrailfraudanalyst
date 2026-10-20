"""Public risk lists for wallet screening.

OFAC's SDN list includes sanctioned crypto addresses. The community repo
0xB10C/ofac-sanctioned-digital-currency-addresses republishes them as plain
text per asset. Check the repo for current file names before relying on it,
and always confirm hits against the official OFAC search tool.

You can also drop your own CSV at data/watchlist.csv with columns:
address,label,source   (e.g. internal blocklist, scam reports, Elliptic labels)

Behaviour:
- Lists are reloaded every RISK_LIST_TTL_SECONDS (default 6 hours), not cached forever.
- If a reload fails, the last good OFAC data is kept and a retry happens after a minute.
- If OFAC has NEVER loaded and OFAC_REQUIRED is true (the default), screen() raises
  RiskListUnavailable so callers hold the transfer instead of releasing it unchecked.
"""
import csv
import os
import time
import httpx

from app import config
from app.observability import observed

OFAC_BASE = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists"
OFAC_FILES = {"ethereum": "sanctioned_addresses_ETH.txt",
              "tron": "sanctioned_addresses_TRX.txt",
              "bitcoin": "sanctioned_addresses_XBT.txt"}
RETRY_SECONDS = 60


class RiskListUnavailable(Exception):
    """The sanctions list couldn't be loaded, so a 'not listed' answer can't be trusted."""


_state = {"ofac": {}, "watchlist": {}, "ofac_loaded_at": 0.0, "next_refresh": 0.0}


def _normalize(addr: str) -> str:
    return addr.lower() if addr.startswith("0x") else addr


def _load_watchlist() -> dict:
    out = {}
    path = f"{config.DATA_DIR}/watchlist.csv"
    if os.path.exists(path):
        with open(path) as f:
            for row in csv.DictReader(f):
                if row.get("address"):
                    out[_normalize(row["address"].strip())] = {"label": row["label"], "source": row["source"]}
    return out


@observed("ofac", "fetch_sdn_list", none_is_failure=True)
async def _fetch_ofac() -> dict | None:
    """All three files, or None if any of them failed (a partial list is treated as a failure)."""
    out = {}
    async with httpx.AsyncClient(timeout=20) as client:
        for network, fname in OFAC_FILES.items():
            try:
                r = await client.get(f"{OFAC_BASE}/{fname}")
            except httpx.HTTPError:
                return None
            if r.status_code != 200:
                return None
            for line in r.text.splitlines():
                if line.strip():
                    out[_normalize(line.strip())] = {"label": "OFAC sanctioned address", "source": "OFAC SDN",
                                                     "network": network}
    return out


async def refresh(force: bool = False) -> None:
    now = time.time()
    if not force and now < _state["next_refresh"]:
        return
    fresh = await _fetch_ofac()
    if fresh:
        _state.update(ofac=fresh, ofac_loaded_at=now, next_refresh=now + config.RISK_LIST_TTL_SECONDS)
    else:
        _state["next_refresh"] = now + RETRY_SECONDS      # keep the last good list, retry soon
    _state["watchlist"] = _load_watchlist()


def status() -> dict:
    loaded = _state["ofac_loaded_at"]
    return {"ofac_entries": len(_state["ofac"]), "ofac_loaded_at": loaded or None,
            "ofac_age_seconds": int(time.time() - loaded) if loaded else None,
            "watchlist_entries": len(_state["watchlist"])}


async def screen(address: str) -> dict | None:
    await refresh()
    if config.OFAC_REQUIRED and not _state["ofac_loaded_at"]:
        raise RiskListUnavailable("The sanctions list couldn't be loaded")
    key = _normalize(address)
    return _state["ofac"].get(key) or _state["watchlist"].get(key)


async def load_lists() -> dict:
    """Backwards-compatible: the merged lists."""
    await refresh()
    return {**_state["watchlist"], **_state["ofac"]}

"""Source registry: lookup, filter, fetch dispatch, and coverage stats."""

from __future__ import annotations

from . import parsers
from .catalog import CATALOG

PARSERS = {
    "ofac_sdn_xml": parsers.ofac_sdn_xml,
    "tor_exit_addresses": parsers.tor_exit_addresses,
    "tor_bulk_exitlist": parsers.tor_bulk_exitlist,
    "raw_iplist": parsers.raw_iplist,
    "feodo_csv": parsers.feodo_csv,
    "sslbl_csv": parsers.sslbl_csv,
    "urlhaus_csv": parsers.urlhaus_csv,
    "threatfox_csv": parsers.threatfox_csv,
    "ransomwhere_json": parsers.ransomwhere_json,
    "cisa_kev_json": parsers.cisa_kev_json,
    "esplora": parsers.esplora_txs,
    "blockscout_txlist": parsers.blockscout_txlist,
}

_BY_NAME = {s["name"]: s for s in CATALOG}


def get_source(name: str) -> dict:
    if name not in _BY_NAME:
        raise KeyError(f"unknown source: {name}")
    return _BY_NAME[name]


def list_sources(category=None, chain=None, keyless=None, integrated=None) -> list:
    out = []
    for s in CATALOG:
        if category and s["category"] != category:
            continue
        if chain and chain not in s["chains"]:
            continue
        if keyless is not None and s["keyless"] != keyless:
            continue
        if integrated is not None and s["integrated"] != integrated:
            continue
        out.append(s)
    return out


def fetch(name: str, client, address: str = None):
    """Fetch and parse a source. For address-based explorers pass `address`."""
    src = get_source(name)
    url = src["url"]
    if "{addr}" in url:
        if not address:
            raise ValueError(f"source {name} requires an address")
        url = url.replace("{addr}", address)
    chain0 = src["chains"][0] if src["chains"] else ""
    data = client.get(url)
    parser = PARSERS.get(src["parser"])
    if parser is None:
        return {"raw": data if isinstance(data, (bytes, bytearray)) else data,
                "note": f"{src['parser']}: catalog + raw fetch only in this version"}
    if src["parser"] == "esplora":
        return parser(data, address=address or "", chain=chain0 or "bitcoin", source=name)
    if src["parser"] == "blockscout_txlist":
        return parser(data, source=name, chain=chain0 or "ethereum")
    return parser(data, source=name)


def fetch_onchain(name: str, client, address: str = None, block: str = "latest"):
    """On-chain query dispatcher across explorer families (GET) and JSON-RPC (POST).

    Returns Lattice-schema transactions for esplora/blockscout/evm, and signature
    references for solana."""
    src = get_source(name)
    p = src["parser"]
    chain0 = src["chains"][0] if src["chains"] else ""
    if p == "evm_rpc":
        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                   "params": [block, True]}
        return parsers.evm_block(client.post(src["url"], payload), chain=chain0 or "ethereum")
    if p == "solana_rpc":
        if not address:
            raise ValueError("solana requires an address")
        payload = {"jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
                   "params": [address, {"limit": 25}]}
        return parsers.solana_signatures(client.post(src["url"], payload), source=name)
    if p == "xrpl_account_tx":
        if not address:
            raise ValueError("xrpl requires an address")
        payload = {"method": "account_tx",
                   "params": [{"account": address, "limit": 25,
                               "ledger_index_min": -1, "ledger_index_max": -1}]}
        return parsers.xrpl_account_tx(client.post(src["url"], payload), address=address, chain=chain0)
    if p in ("tron_account_tx", "blockchain_info"):
        if not address:
            raise ValueError(f"{name} requires an address")
        url = src["url"].replace("{addr}", address)
        data = client.get(url)
        fn = parsers.tron_account_tx if p == "tron_account_tx" else parsers.blockchain_info
        return fn(data, address=address, chain=chain0)
    return fetch(name, client, address=address)


def stats() -> dict:
    by_cat: dict = {}
    chains = set()
    keyless = 0
    integrated = 0
    for s in CATALOG:
        by_cat[s["category"]] = by_cat.get(s["category"], 0) + 1
        keyless += 1 if s["keyless"] else 0
        integrated += 1 if s["integrated"] else 0
        chains.update(s["chains"])
    return {"total": len(CATALOG), "keyless": keyless, "integrated": integrated,
            "by_category": dict(sorted(by_cat.items())), "chains": sorted(chains),
            "chain_count": len(chains)}

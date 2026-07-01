"""Feed parsers: raw bytes/str -> normalized Indicators (or Lattice transactions).

All parsers are pure functions of their input content, so they are tested
against local fixtures with zero network.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import xml.etree.ElementTree as ET

from .normalize import Indicator

_ASSET_CHAIN = {
    "XBT": "bitcoin", "BTC": "bitcoin", "ETH": "ethereum", "USDT": "ethereum",
    "USDC": "ethereum", "XMR": "monero", "LTC": "litecoin", "BCH": "bitcoin-cash",
    "BSV": "bitcoin-sv", "DASH": "dash", "ZEC": "zcash", "TRX": "tron",
    "XRP": "xrpl", "ARB": "arbitrum", "BASE": "base", "SOL": "solana",
}


def _text(content) -> str:
    return content.decode("utf-8", "replace") if isinstance(content, (bytes, bytearray)) else content


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def _is_ip(tok: str) -> bool:
    try:
        ipaddress.ip_address(tok)
        return True
    except ValueError:
        return False


def ofac_sdn_xml(content, source="ofac_sdn") -> list:
    """Extract 'Digital Currency Address' IDs from OFAC SDN/consolidated XML."""
    out = []
    try:
        root = ET.fromstring(_text(content))
    except ET.ParseError:
        return out
    for idel in root.iter():
        if _local(idel.tag) != "id":
            continue
        itype = inum = None
        for ch in idel:
            lt = _local(ch.tag)
            if lt == "idType":
                itype = (ch.text or "").strip()
            elif lt == "idNumber":
                inum = (ch.text or "").strip()
        if itype and inum and itype.lower().startswith("digital currency address"):
            asset = itype.split("-")[-1].strip().upper()
            out.append(Indicator("crypto-address", inum, source,
                                  chain=_ASSET_CHAIN.get(asset, ""),
                                  tags=["sanctions", "ofac"], meta={"asset": asset}))
    return out


def tor_exit_addresses(content, source="tor_exit_addresses") -> list:
    out = []
    for line in _text(content).splitlines():
        if line.startswith("ExitAddress"):
            parts = line.split()
            if len(parts) >= 2 and _is_ip(parts[1]):
                out.append(Indicator("ipv4", parts[1], source, tags=["tor-exit", "anonymizer"]))
    return out


def tor_bulk_exitlist(content, source="tor_bulk_exitlist") -> list:
    return raw_iplist(content, source=source, tags=["tor-exit", "anonymizer"])


def raw_iplist(content, source="raw_iplist", tags=None) -> list:
    tags = tags or ["blocklist"]
    out = []
    for line in _text(content).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        tok = line.split()[0].split(",")[0]
        tok = tok.split("/")[0]  # strip CIDR
        if _is_ip(tok):
            out.append(Indicator("ipv4", tok, source, tags=list(tags)))
    return out


def feodo_csv(content, source="feodo_ipblocklist") -> list:
    out = []
    text = "\n".join(l for l in _text(content).splitlines() if not l.startswith("#"))
    for row in csv.reader(io.StringIO(text)):
        for tok in row:
            tok = tok.strip().strip('"')
            if _is_ip(tok):
                out.append(Indicator("ipv4", tok, source, tags=["c2", "botnet"]))
                break
    return out


def sslbl_csv(content, source="sslbl_certs") -> list:
    out = []
    text = "\n".join(l for l in _text(content).splitlines() if not l.startswith("#"))
    for row in csv.reader(io.StringIO(text)):
        for tok in row:
            tok = tok.strip().strip('"')
            if re.fullmatch(r"[a-fA-F0-9]{40}", tok):
                out.append(Indicator("cert-sha1", tok.lower(), source, tags=["malicious-tls", "c2"]))
                break
            if _is_ip(tok):
                out.append(Indicator("ipv4", tok, source, tags=["malicious-tls", "c2"]))
                break
    return out


def urlhaus_csv(content, source="urlhaus") -> list:
    out = []
    text = "\n".join(l for l in _text(content).splitlines() if not l.startswith("#"))
    for row in csv.reader(io.StringIO(text)):
        for tok in row:
            tok = tok.strip().strip('"')
            if tok.startswith("http://") or tok.startswith("https://"):
                out.append(Indicator("url", tok, source, tags=["malware-distribution"]))
                break
    return out


def threatfox_csv(content, source="threatfox") -> list:
    out = []
    text = "\n".join(l for l in _text(content).splitlines() if not l.startswith("#"))
    for row in csv.reader(io.StringIO(text)):
        cells = [c.strip().strip('"') for c in row]
        for tok in cells:
            if tok.startswith("http"):
                out.append(Indicator("url", tok, source, tags=["ioc"]))
                break
            if _is_ip(tok.split(":")[0]):
                out.append(Indicator("ipv4", tok.split(":")[0], source, tags=["ioc"]))
                break
    return out


def ransomwhere_json(content, source="ransomwhere") -> list:
    out = []
    try:
        data = json.loads(_text(content))
    except json.JSONDecodeError:
        return out
    rows = data.get("result", data) if isinstance(data, dict) else data
    for r in rows or []:
        addr = r.get("address")
        if addr:
            out.append(Indicator("crypto-address", addr, source,
                                 chain=(r.get("blockchain") or "").lower(),
                                 tags=["ransomware"], meta={"family": r.get("family")}))
    return out


def cisa_kev_json(content, source="cisa_kev") -> list:
    out = []
    try:
        data = json.loads(_text(content))
    except json.JSONDecodeError:
        return out
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if cve:
            out.append(Indicator("cve", cve, source, tags=["kev", "exploited"],
                                 meta={"product": v.get("product")}))
    return out


def esplora_txs(content, address="", chain="bitcoin", source="btc_esplora") -> list:
    """Esplora /address/:addr/txs JSON -> Lattice transaction dicts.

    Returns Lattice-schema transactions (NOT Indicators) so chain analytics can
    run on live data. Values converted from satoshis to whole coin.
    """
    txs = []
    try:
        data = json.loads(_text(content))
    except json.JSONDecodeError:
        return txs
    for t in data:
        ins = []
        for vin in t.get("vin", []):
            po = vin.get("prevout") or {}
            addr = po.get("scriptpubkey_address")
            if addr:
                ins.append({"address": addr, "value": round((po.get("value") or 0) / 1e8, 8)})
        outs = []
        for vout in t.get("vout", []):
            addr = vout.get("scriptpubkey_address")
            if addr:
                outs.append({"address": addr, "value": round((vout.get("value") or 0) / 1e8, 8)})
        st = t.get("status") or {}
        txs.append({
            "txid": t.get("txid"), "asset": chain,
            "timestamp": st.get("block_time"),
            "inputs": ins, "outputs": outs,
        })
    return txs


def blockscout_txlist(content, source="eth_blockscout", chain="ethereum") -> list:
    """Blockscout `account/txlist` JSON -> Lattice transactions (account model:
    single from -> single to, value in wei)."""
    txs = []
    try:
        data = json.loads(_text(content))
    except json.JSONDecodeError:
        return txs
    for t in data.get("result", []) if isinstance(data, dict) else []:
        if not isinstance(t, dict):
            continue
        try:
            val = int(t.get("value", "0") or "0") / 1e18
        except ValueError:
            val = 0.0
        frm, to = t.get("from"), t.get("to")
        txs.append({
            "txid": t.get("hash"), "asset": chain,
            "timestamp": int(t.get("timeStamp", 0) or 0),
            "inputs": [{"address": frm, "value": round(val, 8)}] if frm else [],
            "outputs": [{"address": to, "value": round(val, 8)}] if to else [],
        })
    return txs


def _hexint(x):
    try:
        return int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)
    except (ValueError, TypeError):
        return 0


def evm_block(content, chain="ethereum") -> list:
    """eth_getBlockByNumber(full=True) JSON-RPC result -> Lattice transactions."""
    txs = []
    try:
        res = (json.loads(_text(content)) or {}).get("result") or {}
    except json.JSONDecodeError:
        return txs
    ts = _hexint(res.get("timestamp")) or None
    for t in res.get("transactions", []):
        if not isinstance(t, dict):
            continue
        val = _hexint(t.get("value")) / 1e18
        frm, to = t.get("from"), t.get("to")
        txs.append({
            "txid": t.get("hash"), "asset": chain, "timestamp": ts,
            "inputs": [{"address": frm, "value": round(val, 8)}] if frm else [],
            "outputs": [{"address": to, "value": round(val, 8)}] if to else [],
        })
    return txs


def solana_signatures(content, source="solana_rpc") -> list:
    """getSignaturesForAddress JSON-RPC result -> signature references.

    Solana full tx-graph extraction requires per-signature follow-up calls;
    this returns the signature list (live connectivity + activity), which is the
    first stage of on-chain tracing."""
    try:
        res = (json.loads(_text(content)) or {}).get("result") or []
    except json.JSONDecodeError:
        return []
    return [{"signature": r.get("signature"), "slot": r.get("slot"),
             "block_time": r.get("blockTime"), "err": r.get("err")}
            for r in res if isinstance(r, dict)]


def blockchain_info(content, address="", chain="bitcoin", source="btc_blockchain_info") -> list:
    """blockchain.info /rawaddr JSON -> Lattice transactions (values in sats)."""
    txs = []
    try:
        data = json.loads(_text(content))
    except json.JSONDecodeError:
        return txs
    for t in data.get("txs", []):
        ins = []
        for vin in t.get("inputs", []):
            po = vin.get("prev_out") or {}
            if po.get("addr"):
                ins.append({"address": po["addr"], "value": round((po.get("value") or 0) / 1e8, 8)})
        outs = []
        for o in t.get("out", []):
            if o.get("addr"):
                outs.append({"address": o["addr"], "value": round((o.get("value") or 0) / 1e8, 8)})
        txs.append({"txid": t.get("hash"), "asset": chain,
                    "timestamp": t.get("time"), "inputs": ins, "outputs": outs})
    return txs


def tron_account_tx(content, address="", chain="tron", source="tron_trongrid") -> list:
    """TronGrid account transactions -> Lattice transactions (TRX in sun/1e6)."""
    txs = []
    try:
        data = json.loads(_text(content))
    except json.JSONDecodeError:
        return txs
    for t in data.get("data", []):
        for c in (t.get("raw_data") or {}).get("contract", []):
            val = (c.get("parameter") or {}).get("value") or {}
            owner, to, amt = val.get("owner_address"), val.get("to_address"), val.get("amount")
            amount = round((amt or 0) / 1e6, 6) if amt else 0.0
            if owner or to:
                txs.append({"txid": t.get("txID"), "asset": chain,
                            "timestamp": t.get("block_timestamp"),
                            "inputs": [{"address": owner, "value": amount}] if owner else [],
                            "outputs": [{"address": to, "value": amount}] if to else []})
    return txs


def xrpl_account_tx(content, address="", chain="xrpl", source="xrpl_rpc") -> list:
    """rippled account_tx JSON-RPC -> Lattice transactions (Payment types; XRP in drops/1e6)."""
    txs = []
    try:
        res = (json.loads(_text(content)) or {}).get("result") or {}
    except json.JSONDecodeError:
        return txs
    for item in res.get("transactions", []):
        tx = item.get("tx") or item.get("tx_json") or {}
        acct, dest, amt = tx.get("Account"), tx.get("Destination"), tx.get("Amount")
        value = 0.0
        if isinstance(amt, str):
            try:
                value = round(int(amt) / 1e6, 6)
            except ValueError:
                value = 0.0
        if acct or dest:
            txs.append({"txid": tx.get("hash"), "asset": chain, "timestamp": tx.get("date"),
                        "inputs": [{"address": acct, "value": value}] if acct else [],
                        "outputs": [{"address": dest, "value": value}] if dest else []})
    return txs

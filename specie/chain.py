"""Blockchain analytics: address clustering, flow tracing, and mixer/peel-chain
heuristics for transparent-ledger cryptocurrencies (BTC/UTXO-style and
account-style inputs modeled uniformly).

All methods are heuristics that produce *investigative leads* with explicit
confidence. They do not assert ground truth. See docs/LIMITATIONS.md. Privacy
coins (e.g. Monero) are intentionally out of scope for deterministic tracing;
this module operates on transparent transaction data supplied by the caller.

Transaction schema (JSON list):
  {"txid": str, "asset": str, "timestamp": ISO8601,
   "inputs":  [{"address": str, "value": float}, ...],
   "outputs": [{"address": str, "value": float}, ...]}
"""

from __future__ import annotations

import json
from collections import deque

from .confidence import clamp


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def load_transactions(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _input_addrs(tx: dict) -> list:
    return [i["address"] for i in tx.get("inputs", [])]


def common_input_clustering(txs: list):
    """Common-input-ownership heuristic: addresses spent together in a single
    transaction are assumed to share a controller."""
    uf = UnionFind()
    for tx in txs:
        addrs = _input_addrs(tx)
        for a in addrs:
            uf.find(a)
        for a in addrs[1:]:
            uf.union(addrs[0], a)
    clusters: dict = {}
    for a in list(uf.parent.keys()):
        clusters.setdefault(uf.find(a), set()).add(a)
    result = [s for s in clusters.values()]
    mapping = {a: i for i, s in enumerate(result) for a in s}
    return result, mapping


def _build_flow(txs: list):
    fwd: dict = {}
    bwd: dict = {}
    for tx in txs:
        ins = tx.get("inputs", [])
        outs = tx.get("outputs", [])
        ts = tx.get("timestamp")
        for i in ins:
            for o in outs:
                fwd.setdefault(i["address"], []).append(
                    (tx["txid"], o["address"], o["value"], ts)
                )
        for o in outs:
            for i in ins:
                bwd.setdefault(o["address"], []).append(
                    (tx["txid"], i["address"], i["value"], ts)
                )
    return fwd, bwd


def trace(txs: list, seed: str, direction: str = "forward", max_hops: int = 4) -> dict:
    """BFS money-flow trace from a seed address, following value forward
    (funds sent onward) or backward (funds received from)."""
    fwd, bwd = _build_flow(txs)
    graph = fwd if direction == "forward" else bwd
    visited = {seed: 0}
    flows = []
    dq = deque([(seed, 0)])
    while dq:
        node, depth = dq.popleft()
        if depth >= max_hops:
            continue
        for (txid, nxt, value, ts) in graph.get(node, []):
            flows.append(
                {
                    "txid": txid,
                    "from": node if direction == "forward" else nxt,
                    "to": nxt if direction == "forward" else node,
                    "value": value,
                    "timestamp": ts,
                    "hop": depth + 1,
                }
            )
            if nxt not in visited:
                visited[nxt] = depth + 1
                dq.append((nxt, depth + 1))
    return {"seed": seed, "direction": direction, "reached": visited, "flows": flows}


def detect_mixer(txs: list, min_in: int = 3, min_out: int = 3, uniformity: float = 0.1) -> list:
    """Flag CoinJoin/mixer-like transactions: high fan-in, high fan-out, and
    near-uniform output values (low coefficient of variation)."""
    flagged = []
    for tx in txs:
        ins = tx.get("inputs", [])
        outs = tx.get("outputs", [])
        if len(ins) >= min_in and len(outs) >= min_out:
            vals = [o["value"] for o in outs]
            mean = sum(vals) / len(vals) if vals else 0.0
            if mean > 0:
                var = sum((v - mean) ** 2 for v in vals) / len(vals)
                cv = (var ** 0.5) / mean
                if cv <= uniformity:
                    score = clamp(0.6 + (uniformity - cv), 0.0, 0.95)
                    flagged.append(
                        {
                            "txid": tx["txid"],
                            "inputs": len(ins),
                            "outputs": len(outs),
                            "cv": round(cv, 4),
                            "score": round(score, 4),
                        }
                    )
    return flagged


def demix_candidates(txs: list, mixer_txids=None, amount_tol: float = 0.05) -> list:
    """Within a mixer/CoinJoin transaction, link inputs to outputs of nearly
    equal value (net of fee). Confidence falls when an input matches multiple
    outputs (ambiguity), which is the honest signal in equal-value mixing."""
    idx = {tx["txid"]: tx for tx in txs}
    if mixer_txids is None:
        mixer_txids = [m["txid"] for m in detect_mixer(txs)]
    candidates = []
    for txid in mixer_txids:
        tx = idx.get(txid)
        if not tx:
            continue
        for i in tx.get("inputs", []):
            iv = i["value"]
            if iv <= 0:
                continue
            matches = []
            for o in tx.get("outputs", []):
                rel = abs(o["value"] - iv) / iv
                if rel <= amount_tol:
                    matches.append((o["address"], o["value"], rel))
            if not matches:
                continue
            base = 0.7 if len(matches) == 1 else clamp(0.7 / len(matches) + 0.2, 0.0, 0.7)
            for (addr, val, rel) in matches:
                conf = round(clamp(base * (1.0 - rel), 0.0, 0.9), 4)
                candidates.append(
                    {
                        "txid": txid,
                        "input": i["address"],
                        "output": addr,
                        "input_value": iv,
                        "output_value": val,
                        "ambiguity": len(matches),
                        "confidence": conf,
                    }
                )
    return candidates


def detect_peel_chain(txs: list, min_len: int = 2, ratio: float = 3.0) -> list:
    """Detect peel chains: a sequence of transactions each splitting funds into
    a small 'peel' output and a large 'remainder' that continues the chain."""
    by_input: dict = {}
    for tx in txs:
        for i in tx.get("inputs", []):
            by_input.setdefault(i["address"], []).append(tx)

    def peel_step(tx):
        outs = tx.get("outputs", [])
        if len(outs) != 2:
            return None
        a, b = outs
        big, small = (a, b) if a["value"] >= b["value"] else (b, a)
        if small["value"] > 0 and big["value"] >= ratio * small["value"]:
            return big, small
        return None

    chains = []
    seen_starts = set()
    for tx in txs:
        if not peel_step(tx) or tx["txid"] in seen_starts:
            continue
        chain = []
        cur = tx
        guard = 0
        while cur and guard < 100:
            guard += 1
            st = peel_step(cur)
            if not st:
                break
            big, small = st
            chain.append(
                {
                    "txid": cur["txid"],
                    "remainder": big["address"],
                    "remainder_value": big["value"],
                    "peel": small["address"],
                    "peel_value": small["value"],
                }
            )
            nxts = by_input.get(big["address"], [])
            cur = nxts[0] if nxts else None
        if len(chain) >= min_len:
            for step in chain:
                seen_starts.add(step["txid"])
            chains.append(chain)
    return chains

"""Ledger transfer model + shared helpers for typology / network / temporal
analytics.

Where ``chain.py`` models UTXO-style crypto transactions (inputs/outputs), this
module models the more general **account-to-account transfer** that most
counter-threat-finance typologies are described against: a directed, timestamped
value movement between two entities (bank accounts, wallets, MSB customers,
trade counterparties). Both representations are transparent-ledger, offline, and
supplied entirely by the operator.

Transfer schema (JSON list):
  {"id": str, "src": str, "dst": str, "amount": float,
   "timestamp": ISO8601, "currency": str (opt), "channel": str (opt),
   "counterparty_country": str (opt), "goods_value": float (opt)}

Every helper is pure stdlib and side-effect free.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone


def load_transfers(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_ts(ts):
    """Parse an ISO-8601 timestamp to an aware UTC datetime. Returns None on
    failure so callers degrade gracefully rather than crashing on dirty data."""
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Fall back to date-only or space-separated forms.
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s[: len(fmt) + 2], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def epoch(ts) -> float:
    dt = parse_ts(ts)
    return dt.timestamp() if dt else 0.0


def entities(transfers) -> set:
    ents = set()
    for t in transfers:
        if t.get("src") is not None:
            ents.add(t["src"])
        if t.get("dst") is not None:
            ents.add(t["dst"])
    return ents


def outgoing(transfers) -> dict:
    """entity -> list of transfers where it is the source."""
    idx = defaultdict(list)
    for t in transfers:
        if t.get("src") is not None:
            idx[t["src"]].append(t)
    return idx


def incoming(transfers) -> dict:
    """entity -> list of transfers where it is the destination."""
    idx = defaultdict(list)
    for t in transfers:
        if t.get("dst") is not None:
            idx[t["dst"]].append(t)
    return idx


def adjacency(transfers) -> dict:
    """(src, dst) -> aggregated {count, amount, transfers}."""
    agg = {}
    for t in transfers:
        s, d = t.get("src"), t.get("dst")
        if s is None or d is None:
            continue
        rec = agg.setdefault((s, d), {"count": 0, "amount": 0.0, "transfers": []})
        rec["count"] += 1
        rec["amount"] += float(t.get("amount", 0.0))
        rec["transfers"].append(t)
    return agg


def mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def stdev(xs) -> float:
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5

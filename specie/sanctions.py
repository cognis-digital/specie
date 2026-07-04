"""OFAC-style sanctions screening.

Screens crypto addresses and names against a Specially Designated Nationals
(SDN)-style list. The bundled data/ofac_sample.json is SYNTHETIC sample data
for testing only. In production, ingest the real OFAC SDN list (or its
cryptocurrency-address enhancements) using the same schema:

  [{"name": str, "program": str, "aka": [str, ...],
    "addresses": {"crypto": [str, ...]}}]
"""

from __future__ import annotations

import json


def load_sdn(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _norm(s: str) -> str:
    return " ".join(s.lower().split())


def screen_addresses(addresses, sdn: list) -> list:
    """Exact-match crypto addresses against SDN crypto addresses. Address
    matches are definitional (confidence 1.0) when they hit."""
    hits = []
    addr_set = {a.lower() for a in addresses}
    for entry in sdn:
        for a in entry.get("addresses", {}).get("crypto", []):
            if a.lower() in addr_set:
                hits.append(
                    {
                        "match": a,
                        "type": "crypto-address",
                        "sdn_name": entry["name"],
                        "program": entry.get("program"),
                        "confidence": 1.0,
                    }
                )
    return hits


def screen_names(names, sdn: list) -> list:
    """Normalized exact-match of names/AKAs. Name matching is weaker than
    address matching (aliasing/collisions), so confidence is capped."""
    hits = []
    norm_names = {_norm(n): n for n in names}
    for entry in sdn:
        for c in [entry["name"], *entry.get("aka", [])]:
            key = _norm(c)
            if key in norm_names:
                hits.append(
                    {
                        "match": norm_names[key],
                        "type": "name",
                        "sdn_name": entry["name"],
                        "program": entry.get("program"),
                        "confidence": 0.85,
                    }
                )
    return hits

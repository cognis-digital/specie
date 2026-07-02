"""MISP event export.

Emits a MISP-format event (Attributes + Tags) alongside STIX, so findings drop
straight into a MISP instance for sharing. Deterministic UUIDv5 IDs.
"""

from __future__ import annotations

import json
import uuid

_NS = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

# MISP attribute type per chain (fallback 'btc' for unmapped transparent chains)
_CHAIN_MISP = {"bitcoin": "btc", "ethereum": "eth", "monero": "xmr"}


def _uuid(v: str) -> str:
    return str(uuid.uuid5(_NS, v))


def event_from_graph(graph, threat_actors, info="Cognis Lattice attribution",
                     date="2026-01-01") -> dict:
    attributes = []
    for e in graph.entities.values():
        if e.type == "crypto-address":
            val = e.attributes.get("address") or e.label
            chain = e.attributes.get("chain") or ""
            attributes.append({
                "uuid": _uuid("attr:wallet:" + val.lower()),
                "type": _CHAIN_MISP.get(chain, "btc"),
                "category": "Financial fraud", "to_ids": True, "value": val,
            })
        elif e.type == "ip-address":
            val = e.attributes.get("ip") or e.label
            attributes.append({
                "uuid": _uuid("attr:ip:" + val),
                "type": "ip-dst", "category": "Network activity",
                "to_ids": True, "value": val,
            })
    tags = [{"name": "cognis:lattice"}, {"name": "tlp:amber"}]
    if any(ta["sanctions"] for ta in threat_actors):
        tags.append({"name": "ofac:sanctioned"})
    return {"Event": {
        "uuid": _uuid("event:" + info + date),
        "info": info, "date": date,
        "threat_level_id": "2", "analysis": "1", "distribution": "1",
        "Orgc": {"name": "Cognis Digital LLC"},
        "Attribute": attributes, "Tag": tags,
    }}


def to_json(event: dict, indent: int = 2) -> str:
    return json.dumps(event, indent=indent)

"""STIX 2.1 export.

Emits a STIX 2.1 bundle (identity, indicators, threat-actors, relationships)
for sharing with law-enforcement partners. IDs are deterministic UUIDv5 so the
same graph always yields the same bundle (reproducible provenance). Timestamps
default to a fixed value and can be overridden; we avoid non-deterministic
clocks so evidentiary outputs are reproducible.
"""

from __future__ import annotations

import json
import uuid

# RFC 4122 URL namespace, used as a stable namespace for deterministic UUIDv5.
_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
DEFAULT_TS = "2026-01-01T00:00:00.000Z"


def _sid(objtype: str, value: str) -> str:
    return f"{objtype}--{uuid.uuid5(_NS, objtype + ':' + value)}"


def bundle_from_graph(graph, threat_actors, created: str = DEFAULT_TS) -> dict:
    objects = []
    identity_id = _sid("identity", "Specie")
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": created,
            "modified": created,
            "name": "Specie",
            "identity_class": "system",
        }
    )

    def common(o: dict) -> dict:
        o.setdefault("spec_version", "2.1")
        o.setdefault("created", created)
        o.setdefault("modified", created)
        o.setdefault("created_by_ref", identity_id)
        return o

    for e in graph.entities.values():
        if e.type == "crypto-address":
            addr = e.attributes["address"]
            objects.append(
                common(
                    {
                        "type": "indicator",
                        "id": _sid("indicator", "wallet:" + addr),
                        "name": f"Crypto address {addr}",
                        "pattern_type": "stix",
                        "pattern": f"[x-cognis-crypto-address:value = '{addr}']",
                        "valid_from": created,
                        "labels": ["malicious-activity"],
                    }
                )
            )
        elif e.type == "ip-address":
            ip = e.attributes["ip"]
            objects.append(
                common(
                    {
                        "type": "indicator",
                        "id": _sid("indicator", "ip:" + ip),
                        "name": f"IP address {ip}",
                        "pattern_type": "stix",
                        "pattern": f"[ipv4-addr:value = '{ip}']",
                        "valid_from": created,
                        "labels": ["anonymization"],
                    }
                )
            )

    for ta in threat_actors:
        taid = _sid("threat-actor", ta["id"])
        objects.append(
            common(
                {
                    "type": "threat-actor",
                    "id": taid,
                    "name": f"Threat actor {ta['id'][-8:]}",
                    "labels": ["criminal-enterprise"],
                    "confidence": int(round(ta["confidence"] * 100)),
                }
            )
        )
        for wc in ta["wallet_clusters"]:
            for a in wc["attributes"]["addresses"]:
                objects.append(
                    common(
                        {
                            "type": "relationship",
                            "id": _sid("relationship", "ta-wallet:" + taid + a),
                            "relationship_type": "attributed-to",
                            "source_ref": _sid("indicator", "wallet:" + a),
                            "target_ref": taid,
                        }
                    )
                )
        for ic in ta["infrastructure_clusters"]:
            for ip in ic["attributes"]["ips"]:
                objects.append(
                    common(
                        {
                            "type": "relationship",
                            "id": _sid("relationship", "ta-ip:" + taid + ip),
                            "relationship_type": "attributed-to",
                            "source_ref": _sid("indicator", "ip:" + ip),
                            "target_ref": taid,
                        }
                    )
                )

    return {"type": "bundle", "id": _sid("bundle", "specie:" + created), "objects": objects}


def to_json(bundle: dict, indent: int = 2) -> str:
    return json.dumps(bundle, indent=indent)

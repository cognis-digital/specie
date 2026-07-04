"""Core graph model: entities, edges, and a lightweight in-memory graph.

Pure stdlib so the platform runs offline / air-gapped with zero dependencies.
Entity and edge IDs are deterministic (content-addressed) so identical inputs
produce identical graphs and STIX bundles — important for reproducibility in
an evidentiary context.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def make_id(kind: str, value: str) -> str:
    h = hashlib.sha1(f"{kind}:{value}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}--{h}"


@dataclass
class Entity:
    id: str
    type: str
    label: str
    attributes: dict = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "attributes": self.attributes,
            "confidence": self.confidence,
        }


@dataclass
class Edge:
    source: str
    target: str
    relation: str
    confidence: float = 1.0
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class Graph:
    def __init__(self) -> None:
        self.entities: dict = {}
        self.edges: list = []

    def add_entity(self, e: Entity) -> Entity:
        if e.id not in self.entities:
            self.entities[e.id] = e
        return self.entities[e.id]

    def add_edge(self, edge: Edge) -> Edge:
        self.edges.append(edge)
        return edge

    def neighbors(self, node_id: str) -> list:
        out = []
        for e in self.edges:
            if e.source == node_id:
                out.append(e.target)
            elif e.target == node_id:
                out.append(e.source)
        return out

    def by_type(self, entity_type: str) -> list:
        return [e for e in self.entities.values() if e.type == entity_type]

    def to_dict(self) -> dict:
        return {
            "entities": [e.to_dict() for e in self.entities.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

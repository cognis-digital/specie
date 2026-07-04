"""Normalized indicator schema shared across all sources."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Indicator:
    kind: str          # crypto-address | ipv4 | url | cert-sha1 | cve | ioc | ttp
    value: str
    source: str
    chain: str = ""
    tags: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def key(self):
        return (self.kind, self.value.lower(), self.chain)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "source": self.source,
                "chain": self.chain, "tags": sorted(set(self.tags)), "meta": self.meta}


def dedupe(indicators: list) -> list:
    seen: dict = {}
    out = []
    for i in indicators:
        k = i.key()
        if k in seen:
            merged = sorted(set(seen[k].tags) | set(i.tags))
            seen[k].tags = merged
            continue
        seen[k] = i
        out.append(i)
    return out

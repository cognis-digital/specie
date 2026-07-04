"""Network / infrastructure attribution.

Enriches observed IPs with anonymizer classification (Tor/VPN/proxy), clusters
infrastructure by shared TLS certificate or self-hosted domain, and derives
temporal/behavioral signatures that persist across address rotation.

Observation schema (JSON list):
  {"ip": str, "timestamp": ISO8601, "asn": str, "cert_sha256": str,
   "domains": [str, ...], "ports": [int, ...], "tags": [str, ...]}

Clustering here is deliberately conservative: shared TLS certificate fingerprint
is a strong signal of common operation; shared domain is treated as supporting.
It does not attempt to defeat Tor cryptography — it correlates *observations*
the operator has lawfully collected. See docs/LIMITATIONS.md.
"""

from __future__ import annotations

import json
from collections import defaultdict

from .chain import UnionFind
from .confidence import clamp

ANON_TAGS = {"tor-exit", "tor", "vpn", "proxy"}


def load_observations(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def enrich(observations: list, known_tor=None, known_vpn=None, known_proxy=None) -> list:
    known_tor = set(known_tor or [])
    known_vpn = set(known_vpn or [])
    known_proxy = set(known_proxy or [])
    for o in observations:
        tags = set(o.get("tags", []))
        ip = o.get("ip")
        if ip in known_tor:
            tags.add("tor-exit")
        if ip in known_vpn:
            tags.add("vpn")
        if ip in known_proxy:
            tags.add("proxy")
        o["tags"] = sorted(tags)
        o["anonymized"] = bool(tags & ANON_TAGS)
    return observations


def fingerprint_clusters(observations: list) -> list:
    """Cluster IPs sharing a TLS certificate fingerprint or a self-hosted
    domain. Returns a list of sorted IP lists."""
    uf = UnionFind()
    ips = set()
    key_to_ips = defaultdict(list)
    for o in observations:
        ip = o["ip"]
        ips.add(ip)
        uf.find(ip)
        cert = o.get("cert_sha256")
        if cert:
            key_to_ips[("cert", cert)].append(ip)
        for d in o.get("domains", []):
            key_to_ips[("dom", d)].append(ip)
    for _key, iplist in key_to_ips.items():
        anchor = iplist[0]
        for other in iplist[1:]:
            uf.union(anchor, other)
    clusters = defaultdict(set)
    for ip in ips:
        clusters[uf.find(ip)].add(ip)
    return [sorted(s) for s in clusters.values()]


def temporal_signature(observations: list, ip: str) -> dict:
    """Activity-window signature for a single IP: observation count, active
    days, peak UTC hour, and an hour histogram."""
    hours = defaultdict(int)
    days = set()
    count = 0
    for o in observations:
        if o.get("ip") != ip:
            continue
        ts = o.get("timestamp")
        if not ts or "T" not in ts:
            continue
        count += 1
        date, timepart = ts.split("T", 1)
        days.add(date)
        try:
            hours[int(timepart[:2])] += 1
        except ValueError:
            pass
    peak = max(hours.items(), key=lambda kv: kv[1])[0] if hours else None
    return {
        "ip": ip,
        "observations": count,
        "active_days": len(days),
        "peak_hour_utc": peak,
        "hour_histogram": dict(sorted(hours.items())),
    }


def behavioral_correlate(observations: list, min_shared_days: int = 2) -> list:
    """Correlate IPs that are active on the same days (co-occurrence), a signal
    of shared operation. Returns candidate edges with confidence."""
    day_ips = defaultdict(set)
    for o in observations:
        ts = o.get("timestamp")
        ip = o.get("ip")
        if ts and ip and "T" in ts:
            day_ips[ts.split("T", 1)[0]].add(ip)
    pair_days = defaultdict(int)
    for _day, ipset in day_ips.items():
        ips = sorted(ipset)
        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                pair_days[(ips[i], ips[j])] += 1
    edges = []
    for (a, b), n in pair_days.items():
        if n >= min_shared_days:
            edges.append(
                {"a": a, "b": b, "shared_days": n, "confidence": round(clamp(0.3 + 0.2 * n), 4)}
            )
    return edges

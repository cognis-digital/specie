"""Fusion: merge chain clusters, infrastructure clusters, sanctions hits, and
analyst linkages into one threat-actor graph, then resolve connected
components into confidence-scored threat-actor profiles.

Linkage schema (JSON list) — analyst- or evidence-derived cross links:
  {"address": str, "ip": str, ...}          wallet-cluster <-> infra-cluster
  {"address": str, "address2": str, ...}    wallet-cluster <-> wallet-cluster
  {"ip": str, "ip2": str, ...}              infra-cluster  <-> infra-cluster
  each may include "source": str and "confidence": float
"""

from __future__ import annotations

import json

from . import chain as chainmod
from . import netattr as netmod
from . import sanctions as sancmod
from .confidence import Confidence
from .model import Edge, Entity, Graph, make_id


def load_linkages(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_graph(transactions=None, observations=None, linkages=None, sdn=None) -> Graph:
    g = Graph()
    transactions = transactions or []
    observations = observations or []
    linkages = linkages or []
    sdn = sdn or []

    # --- Blockchain: wallet clusters (incl. output-only singletons) ---
    addr_to_wallet: dict = {}
    if transactions:
        all_addrs = set()
        for tx in transactions:
            for i in tx.get("inputs", []):
                all_addrs.add(i["address"])
            for o in tx.get("outputs", []):
                all_addrs.add(o["address"])
        clusters, _ = chainmod.common_input_clustering(transactions)
        covered = set().union(*clusters) if clusters else set()
        for a in sorted(all_addrs - covered):
            clusters.append({a})
        for idx, s in enumerate(clusters):
            wid = make_id("wallet-cluster", "|".join(sorted(s)))
            g.add_entity(
                Entity(wid, "wallet-cluster", f"wallet-cluster-{idx + 1}",
                       {"addresses": sorted(s), "size": len(s)})
            )
            for a in s:
                addr_to_wallet[a] = wid
                aid = make_id("crypto-address", a)
                g.add_entity(Entity(aid, "crypto-address", a, {"address": a}))
                g.add_edge(Edge(aid, wid, "member-of", 0.9, ["common-input-heuristic"]))

    # --- Infrastructure clusters ---
    ip_to_infra: dict = {}
    if observations:
        for idx, s in enumerate(netmod.fingerprint_clusters(observations)):
            iid = make_id("infra-cluster", "|".join(sorted(s)))
            g.add_entity(
                Entity(iid, "infrastructure-cluster", f"infra-cluster-{idx + 1}",
                       {"ips": sorted(s), "size": len(s)})
            )
            for ip in s:
                ip_to_infra[ip] = iid
                pid = make_id("ip-address", ip)
                g.add_entity(Entity(pid, "ip-address", ip, {"ip": ip}))
                g.add_edge(Edge(pid, iid, "member-of", 0.8, ["tls-cert/domain-fingerprint"]))

    # --- Sanctions screening ---
    if sdn:
        known_addrs = [e.attributes["address"] for e in g.by_type("crypto-address")]
        for hit in sancmod.screen_addresses(known_addrs, sdn):
            sid = make_id("sanctioned-entity", hit["sdn_name"])
            g.add_entity(Entity(sid, "sanctioned-entity", hit["sdn_name"],
                                {"program": hit["program"]}))
            aid = make_id("crypto-address", hit["match"])
            g.add_edge(Edge(aid, sid, "sanctioned-as", 1.0, ["OFAC-SDN"]))

    # --- Analyst / evidence linkages ---
    for ln in linkages:
        conf = float(ln.get("confidence", 0.6))
        src = ln.get("source", "investigation")
        a, ip = ln.get("address"), ln.get("ip")
        a2, ip2 = ln.get("address2"), ln.get("ip2")
        if a and ip and a in addr_to_wallet and ip in ip_to_infra:
            g.add_edge(Edge(addr_to_wallet[a], ip_to_infra[ip],
                            "controlled-by-same-actor", conf, [src]))
        if a and a2 and a in addr_to_wallet and a2 in addr_to_wallet:
            g.add_edge(Edge(addr_to_wallet[a], addr_to_wallet[a2],
                            "controlled-by-same-actor", conf, [src]))
        if ip and ip2 and ip in ip_to_infra and ip2 in ip_to_infra:
            g.add_edge(Edge(ip_to_infra[ip], ip_to_infra[ip2],
                            "controlled-by-same-actor", conf, [src]))
    return g


def build_threat_actors(graph: Graph, keep_trivial: bool = False) -> list:
    """Resolve wallet/infra/sanction nodes into threat-actor profiles via
    connected components over same-actor and sanction edges."""
    uf = chainmod.UnionFind()
    relevant = {"wallet-cluster", "infrastructure-cluster", "sanctioned-entity"}
    node_ids = [e.id for e in graph.entities.values() if e.type in relevant]
    for nid in node_ids:
        uf.find(nid)

    addr_wallet = {e.source: e.target for e in graph.edges if e.relation == "member-of"
                   and graph.entities[e.target].type == "wallet-cluster"}
    for e in graph.edges:
        if e.relation == "controlled-by-same-actor":
            uf.union(e.source, e.target)
        elif e.relation == "sanctioned-as":
            wc = addr_wallet.get(e.source)
            if wc:
                uf.union(wc, e.target)

    comps: dict = {}
    for nid in node_ids:
        comps.setdefault(uf.find(nid), []).append(nid)

    actors = []
    for root, members in comps.items():
        wallets = [m for m in members if graph.entities[m].type == "wallet-cluster"]
        infra = [m for m in members if graph.entities[m].type == "infrastructure-cluster"]
        sanc = [m for m in members if graph.entities[m].type == "sanctioned-entity"]
        if not keep_trivial and not sanc and (len(wallets) + len(infra) < 2):
            continue
        weights, rationale = [], []
        if wallets:
            weights.append(0.6)
            rationale.append(f"{len(wallets)} wallet cluster(s)")
        if infra:
            weights.append(0.5)
            rationale.append(f"{len(infra)} infrastructure cluster(s)")
        if wallets and infra:
            weights.append(0.6)
            rationale.append("wallet<->infrastructure linkage")
        if sanc:
            weights.append(0.9)
            rationale.append("OFAC sanctions match")
        conf = Confidence.from_evidence(weights, rationale)
        actors.append(
            {
                "id": make_id("threat-actor", root),
                "wallet_clusters": [graph.entities[m].to_dict() for m in wallets],
                "infrastructure_clusters": [graph.entities[m].to_dict() for m in infra],
                "sanctions": [graph.entities[m].to_dict() for m in sanc],
                "confidence": conf.value,
                "confidence_band": conf.band,
                "rationale": conf.rationale,
            }
        )
    actors.sort(key=lambda t: -t["confidence"])
    return actors

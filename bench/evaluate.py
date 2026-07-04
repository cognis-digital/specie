"""Accuracy evaluation: run the analytics against planted ground truth and
report precision/recall/F1 and related metrics."""

from __future__ import annotations

import json

from specie import chain, fusion, netattr, sanctions, stix

from . import datagen
from .metrics import label_prf, pairwise_prf


def evaluate(dataset: dict) -> dict:
    txs = dataset["txs"]
    obs = netattr.enrich([dict(o) for o in dataset["obs"]])
    sdn = dataset["sdn"]
    truth = dataset["truth"]

    # Wallet clustering (pairwise over actor-address universe)
    clusters, _ = chain.common_input_clustering(txs)
    wallet = pairwise_prf(clusters, truth["wallets"], universe=truth["input_universe"])

    # Mixer detection (set labeling over all txids)
    pred_mixers = {m["txid"] for m in chain.detect_mixer(txs)}
    mixer = label_prf(pred_mixers, truth["mixers"])

    # Peel-chain recall (planted starts recovered)
    covered = set()
    for ch in chain.detect_peel_chain(txs):
        for step in ch:
            covered.add(step["txid"])
    starts = truth["peel_starts"]
    peel_recall = round(len(starts & covered) / len(starts), 4) if starts else 1.0

    # De-mix behavior (coverage + honest ambiguity/confidence)
    cands = chain.demix_candidates(txs)
    mixer_inputs = set()
    for tx in txs:
        if tx["txid"] in truth["mixers"]:
            for i in tx["inputs"]:
                mixer_inputs.add((tx["txid"], i["address"]))
    inputs_with_cand = {(c["txid"], c["input"]) for c in cands}
    demix = {
        "candidates": len(cands),
        "input_coverage": round(len(inputs_with_cand & mixer_inputs) / len(mixer_inputs), 4)
        if mixer_inputs else 0.0,
        "mean_ambiguity": round(sum(c["ambiguity"] for c in cands) / len(cands), 3) if cands else 0.0,
        "mean_confidence": round(sum(c["confidence"] for c in cands) / len(cands), 4) if cands else 0.0,
    }

    # Infrastructure clustering (pairwise over all IPs)
    iclusters = netattr.fingerprint_clusters(obs)
    universe_ips = {o["ip"] for o in obs}
    infra = pairwise_prf(iclusters, truth["infra"], universe=universe_ips)

    # Sanctions screening
    all_addr = set()
    for tx in txs:
        for i in tx["inputs"]:
            all_addr.add(i["address"])
        for o in tx["outputs"]:
            all_addr.add(o["address"])
    hits = {h["match"] for h in sanctions.screen_addresses(all_addr, sdn)}
    sanc = label_prf(hits, truth["sanctioned"])

    # Trace reachability (forward from each actor's first address)
    reached = 0
    for addrs in truth["actor_addrs"]:
        r = chain.trace(txs, addrs[0], "forward", 3)
        if len(r["reached"]) > 1:
            reached += 1
    trace_recall = round(reached / len(truth["actor_addrs"]), 4) if truth["actor_addrs"] else 1.0

    # Determinism: identical STIX bundle id across two independent runs
    lnk = []
    g1 = fusion.build_graph(txs, obs, lnk, sdn)
    g2 = fusion.build_graph(txs, obs, lnk, sdn)
    b1 = stix.bundle_from_graph(g1, fusion.build_threat_actors(g1))
    b2 = stix.bundle_from_graph(g2, fusion.build_threat_actors(g2))
    determinism = (stix.to_json(b1) == stix.to_json(b2))

    return {
        "dataset": {"transactions": len(txs), "observations": len(obs),
                    "sdn_entries": len(sdn), "actors": len(truth["actor_addrs"])},
        "wallet_clustering": wallet,
        "mixer_detection": mixer,
        "peel_chain_recall": peel_recall,
        "demix": demix,
        "infra_clustering": infra,
        "sanctions": sanc,
        "trace_recall": trace_recall,
        "determinism": determinism,
    }


def main():
    for profile in ("clean", "noisy"):
        print(f"\n===== profile: {profile} =====")
        print(json.dumps(evaluate(datagen.generate(profile=profile)), indent=2))


if __name__ == "__main__":
    main()

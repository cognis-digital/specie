"""Performance benchmarks: throughput and latency of the core analytics at
increasing transaction volumes. Deterministic inputs; wall-clock via
time.perf_counter."""

from __future__ import annotations

import json
import time

from specie import chain, fusion


def _perf_txs(n: int) -> list:
    """A chain of 2-input co-spends (worst-case clustering: one giant cluster)."""
    txs = []
    for i in range(n):
        txs.append({
            "txid": f"b{i}", "asset": "BTC", "timestamp": "2026-01-01T00:00:00Z",
            "inputs": [{"address": f"p{i}", "value": 1.0},
                       {"address": f"p{i + 1}", "value": 1.0}],
            "outputs": [{"address": f"o{i}", "value": 1.9}],
        })
    return txs


def benchmark(sizes=(2000, 10000, 40000)) -> list:
    rows = []
    for n in sizes:
        txs = _perf_txs(n)

        t0 = time.perf_counter()
        clusters, _ = chain.common_input_clustering(txs)
        t_cluster = time.perf_counter() - t0

        t0 = time.perf_counter()
        chain.detect_mixer(txs)
        t_mixer = time.perf_counter() - t0

        t0 = time.perf_counter()
        chain.detect_peel_chain(txs)
        t_peel = time.perf_counter() - t0

        t0 = time.perf_counter()
        fusion.build_graph(txs, [], [], [])
        t_build = time.perf_counter() - t0

        total = t_cluster + t_mixer + t_peel + t_build
        rows.append({
            "transactions": n,
            "clusters_found": len(clusters),
            "cluster_s": round(t_cluster, 4),
            "detect_mixer_s": round(t_mixer, 4),
            "detect_peel_s": round(t_peel, 4),
            "build_graph_s": round(t_build, 4),
            "total_s": round(total, 4),
            "tx_per_s": int(n / total) if total > 0 else None,
        })
    return rows


def main():
    print(json.dumps(benchmark(), indent=2))


if __name__ == "__main__":
    main()

"""Demo: network analytics — communities, centrality, and broker scoring.

Builds a two-community network bridged by a single broker account and shows how
betweenness/broker scoring surfaces the conduit as a priority target.

Run:  python examples/demo_network_brokers.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import network  # noqa: E402


def tx(i, s, d, amt=1000):
    return {"id": i, "src": s, "dst": d, "amount": amt,
            "timestamp": "2026-05-01T00:00:00Z"}


def main() -> int:
    # Community 1: A,B,C ; Community 2: X,Y,Z ; BROKER bridges them.
    transfers = [
        tx("1", "A", "B"), tx("2", "B", "C"), tx("3", "C", "A"),
        tx("4", "X", "Y"), tx("5", "Y", "Z"), tx("6", "Z", "X"),
        tx("7", "C", "BROKER"), tx("8", "BROKER", "X", 5000),
    ]

    print("=" * 68)
    print("  DEMO — Network analytics: communities + broker centrality")
    print("=" * 68)

    comps = network.connected_components(transfers)
    print(f"\nConnected components: {len(comps)}")
    labels = network.community_detection(transfers)
    groups = {}
    for ent, lab in labels.items():
        groups.setdefault(lab, []).append(ent)
    print(f"Communities detected: {len(groups)}")
    for lab, members in sorted(groups.items()):
        print(f"  community {lab}: {sorted(members)}")

    print("\nTop brokers (network conduits):")
    for b in network.top_brokers(transfers, k=3):
        print(f"  {b['entity']:8} broker={b['broker_score']:.2f}  "
              f"betweenness={b['betweenness']:.4f}  degree={b['degree']}")
    top = network.top_brokers(transfers, k=1)[0]
    print(f"\n=> '{top['entity']}' is the highest-value investigative target "
          "(it bridges both communities).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

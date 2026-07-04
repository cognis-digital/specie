"""Demo: layering-chain detection + path-of-funds tracing.

Shows a multi-hop value-preserving chain being detected as layering, then traces
the money flow from the chain's origin to its terminus.

Run:  python examples/demo_layering_trace.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import network, typologies  # noqa: E402

BASE = datetime(2026, 4, 1, tzinfo=timezone.utc)


def ts(h):
    return (BASE + timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    nodes = ["ORIGIN", "HOP1", "HOP2", "HOP3", "HOP4", "CASHOUT"]
    amt = 250000.0
    transfers = []
    for k in range(len(nodes) - 1):
        amt *= 0.98  # a small "fee" each hop, still value-preserving
        transfers.append({"id": f"h{k}", "src": nodes[k], "dst": nodes[k + 1],
                          "amount": round(amt, 2), "timestamp": ts(k * 12)})

    print("=" * 68)
    print("  DEMO — Layering chain + path-of-funds")
    print("=" * 68)
    for f in typologies.detect_layering(transfers):
        print(f"\n[{f.severity}] layering  score={f.score}  hops={f.features['hops']}")
        print("  path:", " -> ".join(str(e) for e in f.entities))

    print("\nPath-of-funds ORIGIN -> CASHOUT:")
    for p in network.path_of_funds(transfers, "ORIGIN", "CASHOUT"):
        print(f"  {' -> '.join(p['path'])}")
        print(f"  hops={p['hops']}  bottleneck={p['bottleneck_amount']}  "
              f"total_moved={p['total_moved']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

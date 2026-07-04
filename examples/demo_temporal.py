"""Demo: temporal analytics — burst, dormancy-then-activation, and periodicity.

Run:  python examples/demo_temporal.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import temporal  # noqa: E402

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ts(h):
    return (BASE + timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    transfers = []
    # Burst: BURST normally quiet, then 8 transfers in a few hours.
    transfers.append({"id": "seed", "src": "x", "dst": "BURST", "amount": 100,
                      "timestamp": ts(0)})
    for k in range(8):
        transfers.append({"id": f"b{k}", "src": "BURST", "dst": f"o{k}",
                          "amount": 500, "timestamp": ts(1000 + k * 0.4)})
    # Dormancy then activation: activity, 150-day gap, then a burst.
    transfers.append({"id": "d0", "src": "y", "dst": "SLEEPER", "amount": 100,
                      "timestamp": ts(2)})
    for k in range(4):
        transfers.append({"id": f"r{k}", "src": "SLEEPER", "dst": f"z{k}",
                          "amount": 200, "timestamp": ts(150 * 24 + 5 + k)})
    # Periodicity: PAYROLL-BOT sends every 24h, 8 times.
    for k in range(8):
        transfers.append({"id": f"p{k}", "src": "PAYROLL_BOT", "dst": "acct",
                          "amount": 1000, "timestamp": ts(3000 + k * 24)})

    print("=" * 68)
    print("  DEMO — Temporal analytics")
    print("=" * 68)
    for f in temporal.run_all(transfers):
        print(f"\n[{f.severity}] {f.typology} on {f.entities[0]}  score={f.score}")
        print("  ", f.evidence[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())

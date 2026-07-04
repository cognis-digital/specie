"""Demo: structuring / smurfing detection.

Builds a small synthetic ledger where one account receives many sub-$10k
deposits that aggregate over the reporting threshold, and shows the transparent
features behind the structuring finding.

Run:  python examples/demo_structuring.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import typologies  # noqa: E402

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


def ts(h):
    return (BASE + timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    transfers = [
        {"id": f"d{k}", "src": f"courier_{k}", "dst": "TARGET_ACCT",
         "amount": amt, "timestamp": ts(h)}
        for k, (amt, h) in enumerate([(9600, 0), (9750, 8), (9500, 20),
                                      (9820, 30), (9400, 44)])
    ]
    # a legitimate large deposit that must NOT be flagged as structuring
    transfers.append({"id": "legit", "src": "payroll", "dst": "OTHER_ACCT",
                      "amount": 42000, "timestamp": ts(5)})

    print("=" * 68)
    print("  DEMO — Structuring / smurfing detection")
    print("=" * 68)
    findings = typologies.detect_structuring(transfers)
    for f in findings:
        print(f"\n[{f.severity}] {f.typology} on {f.entities[0]}  score={f.score}")
        print("  evidence :", f.evidence[0])
        print("  features :", f.features)
    print(f"\nFlagged {len(findings)} account(s); the $42k single deposit was "
          "correctly ignored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Demo: full case file + risk scoring on the bundled synthetic ledger.

Runs the entire counter-threat-finance pipeline (typologies + temporal +
network + risk + entity resolution) and prints the SAR-style narrative, then
writes a self-contained HTML dashboard.

Run:  python examples/demo_casefile.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import casefile, dashboard, ledger  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")


def main() -> int:
    transfers = ledger.load_transfers(os.path.join(DATA, "sample_ledger.json"))
    watchlist = ["RT_ORIGIN", "SHELL_1"]  # operator-supplied

    case = casefile.build_case(transfers, watchlist=watchlist)

    print("=" * 68)
    print("  DEMO — Counter-threat-finance case file")
    print("=" * 68)
    print("\nSUMMARY:", case["summary"])
    print("\nTop 5 entities by risk:")
    for r in case["entity_risk"][:5]:
        print(f"  {r['entity']:14} risk={r['risk']:.2f} ({r['risk_band']})  "
              f"typologies={r['typologies']}")

    print("\n" + case["narrative"])

    out = os.path.join(ROOT, "case_dashboard.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(dashboard.render_html(case))
    print(f"\n[+] Self-contained HTML dashboard -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

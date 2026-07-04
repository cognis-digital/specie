"""Demo: the full typology zoo on one synthetic ledger.

Runs every illicit-finance typology detector against the bundled sample ledger
and prints one representative finding per typology with its transparent
features. A quick tour of what each detector looks for.

Run:  python examples/demo_typology_zoo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import ledger, temporal, typologies  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def main() -> int:
    transfers = ledger.load_transfers(os.path.join(DATA, "sample_ledger.json"))
    findings = (typologies.run_all(transfers, watchlist=["RT_ORIGIN", "SHELL_1"])
                + temporal.run_all(transfers))

    by_typ = {}
    for f in findings:
        by_typ.setdefault(f.typology, []).append(f)

    print("=" * 72)
    print("  DEMO — Illicit-finance typology zoo")
    print("=" * 72)
    order = ["structuring", "layering", "pass_through", "round_tripping",
             "trade_value_anomaly", "shell_nominee", "funnel_account",
             "sanctions_nexus", "burst_velocity", "dormancy_activation",
             "periodicity"]
    for typ in order:
        hits = by_typ.get(typ, [])
        if not hits:
            print(f"\n{typ}: (no finding)")
            continue
        best = max(hits, key=lambda f: f.score)
        print(f"\n{typ}  ({len(hits)} finding(s), showing strongest)")
        print(f"  [{best.severity}] score={best.score}")
        print("  entities:", ", ".join(str(e) for e in best.entities[:6]))
        print("  evidence:", best.evidence[0] if best.evidence else best.rationale)
    print(f"\nTotal findings across all typologies: {len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

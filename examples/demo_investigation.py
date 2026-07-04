"""Demo: an end-to-end analyst investigation walkthrough.

Ties the whole analytics layer together the way an analyst would work a lead:

  1. resolve duplicate identifiers,
  2. run every typology + temporal detector,
  3. score entity and network risk,
  4. pick the highest-risk network and trace the path of funds through it,
  5. emit an interop bundle for the case-management system.

Run:  python examples/demo_investigation.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import (  # noqa: E402
    exports, ledger, network, risk, temporal, typologies,
)

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def main() -> int:
    transfers = ledger.load_transfers(os.path.join(DATA, "sample_ledger.json"))
    watchlist = ["RT_ORIGIN", "SHELL_1"]

    print("=" * 72)
    print("  DEMO — End-to-end investigation walkthrough")
    print("=" * 72)

    # 1. Entity resolution
    mapping = network.resolve_entities(ledger.entities(transfers))
    merged = {c: [o for o in orig if o != c]
              for c, orig in _grouped(mapping).items() if len(orig) > 1}
    transfers = network.apply_resolution(transfers, mapping)
    print(f"\n[1] Entity resolution merged {len(merged)} duplicate group(s): "
          f"{ {c: v for c, v in merged.items()} }")

    # 2. Detectors
    findings = typologies.run_all(transfers, watchlist=watchlist) + temporal.run_all(transfers)
    print(f"[2] Detectors raised {len(findings)} findings across "
          f"{len({f.typology for f in findings})} typologies.")

    # 3. Risk
    entity_risk = risk.score_entities(findings)
    comps = network.connected_components(transfers)
    net_risk = risk.score_network(findings, comps)
    print(f"[3] {len(entity_risk)} entities flagged; "
          f"{len(net_risk)} networks scored.")
    top_net = net_risk[0]
    print(f"    Highest-risk network: {top_net['network_id']} "
          f"(risk {top_net['network_risk']:.2f}, {top_net['size']} entities, "
          f"typologies {top_net['typologies']})")

    # 4. Path of funds inside the top network
    members = top_net["entities"]
    if len(members) >= 2:
        src, dst = members[0], members[-1]
        paths = network.path_of_funds(transfers, src, dst, max_paths=1)
        if paths:
            print(f"[4] Path of funds {src} -> {dst}: "
                  f"{' -> '.join(paths[0]['path'])} "
                  f"(bottleneck {paths[0]['bottleneck_amount']})")
        else:
            print(f"[4] No directed path {src} -> {dst} within the network.")

    # 5. Export
    bundle = exports.stix_bundle(findings)
    print(f"[5] Exported STIX 2.1 bundle: {len(bundle['objects'])} objects, "
          f"id={bundle['id']}")
    print("\nInvestigation complete. All output is decision-support for analyst review.")
    return 0


def _grouped(mapping):
    groups = {}
    for original, canon in mapping.items():
        groups.setdefault(canon, []).append(original)
    return groups


if __name__ == "__main__":
    sys.exit(main())

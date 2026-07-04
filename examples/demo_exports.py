"""Demo: interop exports (JSON / CSV / STIX 2.1).

Runs the detectors on the bundled ledger and shows the same findings serialised
three ways so Cognis Lattice plugs into spreadsheets, SIEMs, and STIX consumers.

Run:  python examples/demo_exports.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import exports, ledger, temporal, typologies  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def main() -> int:
    transfers = ledger.load_transfers(os.path.join(DATA, "sample_ledger.json"))
    findings = (typologies.run_all(transfers, watchlist=["RT_ORIGIN", "SHELL_1"])
                + temporal.run_all(transfers))

    print("=" * 68)
    print("  DEMO — Interop exports")
    print("=" * 68)
    print(f"\n{len(findings)} findings.")

    print("\n--- CSV (first 4 lines) ---")
    for line in exports.findings_csv(findings).splitlines()[:4]:
        print(line)

    print("\n--- STIX 2.1 bundle ---")
    bundle = exports.stix_bundle(findings)
    types = {}
    for o in bundle["objects"]:
        types[o["type"]] = types.get(o["type"], 0) + 1
    print("bundle id:", bundle["id"])
    print("object type counts:", types)
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    print("sample indicator:", json.dumps(
        {k: ind[k] for k in ("id", "name", "confidence", "x_cognis_typology")}, indent=2))

    # Determinism check
    assert exports.stix_json(findings) == exports.stix_json(findings)
    print("\n[+] STIX export is deterministic (identical across runs).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

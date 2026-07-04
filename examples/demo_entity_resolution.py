"""Demo: fuzzy entity resolution.

Shows the resolver merging genuine name variants of one entity while keeping a
sequence-numbered cohort of distinct accounts separate.

Run:  python examples/demo_entity_resolution.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import network  # noqa: E402


def main() -> int:
    names = [
        "Acme Trading LLC", "Acme Trading, L.L.C.", "ACME TRADING Inc",
        "Zenith Holdings", "Zenith Holdings Ltd.",
        "customer_1", "customer_2", "customer_3",  # distinct enumerated accounts
    ]
    print("=" * 68)
    print("  DEMO — Fuzzy entity resolution")
    print("=" * 68)
    print("\nPairwise similarity (Dice over character bigrams):")
    for a, b in [("Acme Trading LLC", "Acme Trading, L.L.C."),
                 ("Zenith Holdings", "Zenith Holdings Ltd."),
                 ("customer_1", "customer_2"),
                 ("Acme Trading LLC", "Zenith Holdings")]:
        print(f"  {a!r:26} ~ {b!r:24} = {network.similarity(a, b):.3f}")

    mapping = network.resolve_entities(names)
    groups = {}
    for original, canon in mapping.items():
        groups.setdefault(canon, []).append(original)
    print("\nResolved clusters:")
    for canon, members in sorted(groups.items()):
        tag = "(merged)" if len(members) > 1 else ""
        print(f"  {canon!r}: {sorted(members)} {tag}")
    print(f"\n{len(names)} raw names -> {len(groups)} resolved entities. "
          "Numbered customers stayed distinct.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

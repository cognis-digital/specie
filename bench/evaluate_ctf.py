"""Accuracy evaluation for the counter-threat-finance analytics layer.

Runs the typology + temporal detectors against the planted ground truth from
``bench/ledgergen.py`` and reports per-typology recall (did we recover the
entity we planted to exhibit each pattern?) plus entity-resolution accuracy.
Deterministic; reproducible on any machine.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cognis_lattice import network, temporal, typologies  # noqa: E402

from bench import ledgergen  # noqa: E402


def _entity_recall(findings, typology, planted) -> dict:
    planted = set(planted)
    got = set()
    for f in findings:
        if f.typology == typology:
            got.update(str(e) for e in f.entities)
    recovered = sum(1 for p in planted if p in got)
    recall = round(recovered / len(planted), 4) if planted else 1.0
    return {"planted": len(planted), "recovered": recovered, "recall": recall}


def evaluate(seed: int = 4242) -> dict:
    data = ledgergen.generate(seed=seed)
    txs = data["transfers"]
    truth = data["truth"]
    watchlist = ["RT_ORIGIN", "SHELL_1"]

    findings = typologies.run_all(txs, watchlist=watchlist) + temporal.run_all(txs)

    per_typology = {}
    for typ, planted in truth.items():
        if not planted:
            continue
        per_typology[typ] = _entity_recall(findings, typ, planted)

    macro_recall = round(
        sum(v["recall"] for v in per_typology.values()) / len(per_typology), 4)

    # Entity-resolution accuracy: exactly one true merge pair is planted; every
    # numbered cohort must stay distinct.
    from cognis_lattice.ledger import entities as _ents
    mapping = network.resolve_entities(_ents(txs))
    merges = {c: [o for o in orig] for c, orig in _grouped(mapping).items()}
    true_merge = ("Acme Trading LLC" in mapping
                  and mapping.get("Acme Trading, L.L.C.") == mapping.get("Acme Trading LLC"))
    # False merges = any merged group besides the intended Acme pair.
    false_merges = sum(1 for c, members in merges.items()
                       if len(members) > 1 and not all("acme" in m.lower() for m in members))

    return {
        "dataset": {"transfers": len(txs), "typologies_planted": len(per_typology)},
        "per_typology_recall": per_typology,
        "macro_recall": macro_recall,
        "entity_resolution": {
            "true_merge_recovered": bool(true_merge),
            "false_merge_groups": false_merges,
        },
        "total_findings": len(findings),
    }


def _grouped(mapping) -> dict:
    groups = {}
    for original, canon in mapping.items():
        groups.setdefault(canon, []).append(original)
    return groups


def main():
    print(json.dumps(evaluate(), indent=2))


if __name__ == "__main__":
    main()

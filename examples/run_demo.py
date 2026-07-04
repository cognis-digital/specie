"""Minimal end-to-end example: build the fused graph and print a report.

Run from the repository root:  python examples/run_demo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from specie import chain, fusion, netattr, report, sanctions, stix  # noqa: E402

D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

txs = chain.load_transactions(os.path.join(D, "sample_transactions.json"))
obs = netattr.enrich(netattr.load_observations(os.path.join(D, "sample_infrastructure.json")))
sdn = sanctions.load_sdn(os.path.join(D, "ofac_sample.json"))
lnk = fusion.load_linkages(os.path.join(D, "sample_linkages.json"))

graph = fusion.build_graph(txs, obs, lnk, sdn)
actors = fusion.build_threat_actors(graph)

print(report.render_text(graph, actors))
bundle = stix.bundle_from_graph(graph, actors)
print(f"\nSTIX 2.1 bundle: {len(bundle['objects'])} objects, id={bundle['id']}")

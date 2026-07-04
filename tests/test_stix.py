import os

from specie import chain, fusion, netattr, sanctions, stix

D = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data"))


def _graph_and_actors():
    txs = chain.load_transactions(os.path.join(D, "sample_transactions.json"))
    obs = netattr.enrich(netattr.load_observations(os.path.join(D, "sample_infrastructure.json")))
    sdn = sanctions.load_sdn(os.path.join(D, "ofac_sample.json"))
    lnk = fusion.load_linkages(os.path.join(D, "sample_linkages.json"))
    g = fusion.build_graph(txs, obs, lnk, sdn)
    return g, fusion.build_threat_actors(g)


def test_bundle_shape():
    g, tas = _graph_and_actors()
    b = stix.bundle_from_graph(g, tas)
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "indicator", "threat-actor", "relationship"} <= types


def test_bundle_deterministic():
    g, tas = _graph_and_actors()
    assert stix.bundle_from_graph(g, tas)["id"] == stix.bundle_from_graph(g, tas)["id"]


def test_threat_actor_confidence_is_percentage():
    g, tas = _graph_and_actors()
    b = stix.bundle_from_graph(g, tas)
    for o in b["objects"]:
        if o["type"] == "threat-actor":
            assert 0 <= o["confidence"] <= 100

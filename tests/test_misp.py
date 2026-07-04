import os

from specie import fusion, misp, netattr, sanctions
from specie import chain

D = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data"))


def _graph_actors():
    txs = chain.load_transactions(os.path.join(D, "sample_transactions.json"))
    obs = netattr.enrich(netattr.load_observations(os.path.join(D, "sample_infrastructure.json")))
    sdn = sanctions.load_sdn(os.path.join(D, "ofac_sample.json"))
    lnk = fusion.load_linkages(os.path.join(D, "sample_linkages.json"))
    g = fusion.build_graph(txs, obs, lnk, sdn)
    return g, fusion.build_threat_actors(g)


def test_misp_event_shape():
    g, tas = _graph_actors()
    ev = misp.event_from_graph(g, tas)
    assert "Event" in ev
    attrs = ev["Event"]["Attribute"]
    types = {a["type"] for a in attrs}
    assert "btc" in types  # crypto addresses
    assert "ip-dst" in types  # infrastructure IPs
    assert all("uuid" in a and "value" in a for a in attrs)


def test_misp_sanctions_tag_and_determinism():
    g, tas = _graph_actors()
    ev = misp.event_from_graph(g, tas)
    tag_names = {t["name"] for t in ev["Event"]["Tag"]}
    assert "cognis:lattice" in tag_names
    assert "ofac:sanctioned" in tag_names  # sample has a sanctioned address
    assert misp.to_json(ev) == misp.to_json(misp.event_from_graph(g, tas))

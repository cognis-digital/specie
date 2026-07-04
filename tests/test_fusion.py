import os

from specie import chain, fusion, netattr, sanctions

D = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data"))


def _graph():
    txs = chain.load_transactions(os.path.join(D, "sample_transactions.json"))
    obs = netattr.enrich(netattr.load_observations(os.path.join(D, "sample_infrastructure.json")))
    sdn = sanctions.load_sdn(os.path.join(D, "ofac_sample.json"))
    lnk = fusion.load_linkages(os.path.join(D, "sample_linkages.json"))
    return fusion.build_graph(txs, obs, lnk, sdn)


def test_graph_has_all_entity_types():
    g = _graph()
    types = {e.type for e in g.entities.values()}
    assert {"wallet-cluster", "infrastructure-cluster", "crypto-address",
            "ip-address", "sanctioned-entity"} <= types


def test_top_threat_actor_fuses_all_evidence():
    tas = fusion.build_threat_actors(_graph())
    assert tas, "expected at least one meaningful threat actor"
    top = tas[0]
    assert top["sanctions"], "top actor should carry the OFAC hit"
    assert top["infrastructure_clusters"], "top actor should carry infrastructure"
    assert top["wallet_clusters"], "top actor should carry wallets"
    assert top["confidence_band"] == "HIGH"


def test_trivial_singletons_filtered():
    tas = fusion.build_threat_actors(_graph())
    # the lone peel-chain singletons should not surface as actors
    for ta in tas:
        assert ta["sanctions"] or (len(ta["wallet_clusters"]) + len(ta["infrastructure_clusters"]) >= 2)

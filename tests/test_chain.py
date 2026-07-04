import os

from specie import chain

DATA = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_transactions.json")
)


def load():
    return chain.load_transactions(DATA)


def test_common_input_clustering_groups_cospent():
    clusters, _ = chain.common_input_clustering(load())
    c = next(s for s in clusters if "addr-A1" in s)
    assert {"addr-A1", "addr-A2", "addr-A3"} <= c


def test_detect_mixer_flags_coinjoin():
    assert any(m["txid"] == "txM" for m in chain.detect_mixer(load()))


def test_non_mixer_not_flagged():
    assert all(m["txid"] != "tx0" for m in chain.detect_mixer(load()))


def test_peel_chain_found():
    chains = chain.detect_peel_chain(load())
    assert any(len(c) >= 3 for c in chains)


def test_demix_candidate_from_dep():
    cands = chain.demix_candidates(load())
    assert any(c["input"] == "addr-DEP" for c in cands)
    for c in cands:
        assert 0.0 <= c["confidence"] <= 0.9


def test_trace_forward_reaches_downstream():
    r = chain.trace(load(), "addr-A1", "forward", 4)
    assert "addr-A3" in r["reached"]
    assert "addr-DEP" in r["reached"]


def test_trace_backward():
    r = chain.trace(load(), "addr-DEP", "backward", 2)
    assert "addr-A2" in r["reached"] or "addr-A3" in r["reached"]

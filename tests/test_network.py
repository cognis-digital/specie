from cognis_lattice import network as net


def _tx(i, s, d, amt=100):
    return {"id": i, "src": s, "dst": d, "amount": amt,
            "timestamp": "2026-01-01T00:00:00Z"}


# ---- entity resolution ----
def test_normalize_name_strips_suffix_and_punct():
    # The corporate-suffix token "llc" is dropped; punctuation removed.
    assert net.normalize_name("Acme Trading LLC") == "acme trading"
    # Names with a "L.L.C." spelling still resolve as duplicates via similarity.
    assert net.similarity("Acme Trading, L.L.C.", "Acme Trading LLC") >= 0.82


def test_similarity_identical_after_norm():
    assert net.similarity("Acme Inc.", "Acme, Inc") == 1.0


def test_similarity_low_for_different():
    assert net.similarity("Acme Corp", "Zenith Holdings") < 0.4


def test_similarity_rejects_sequence_numbers():
    # Same stem, different trailing number -> not the same entity.
    assert net.similarity("account_1", "account_2") == 0.0


def test_resolve_merges_true_duplicate():
    m = net.resolve_entities(["Acme Trading LLC", "Acme Trading, L.L.C.", "Zenith"])
    assert m["Acme Trading LLC"] == m["Acme Trading, L.L.C."]
    assert m["Zenith"] == "Zenith"


def test_resolve_canonical_is_smallest():
    m = net.resolve_entities(["Bravo Co", "Bravo Company"])
    assert set(m.values()) == {min("Bravo Co", "Bravo Company")}


def test_resolve_does_not_merge_numbered_cohort():
    names = [f"depositor_{k}" for k in range(6)]
    m = net.resolve_entities(names)
    assert len(set(m.values())) == 6


def test_apply_resolution_rewrites():
    txs = [_tx("t", "Acme Trading, L.L.C.", "X")]
    m = net.resolve_entities(["Acme Trading LLC", "Acme Trading, L.L.C.", "X"])
    out = net.apply_resolution(txs, m)
    assert out[0]["src"] == m["Acme Trading, L.L.C."]


# ---- components / communities ----
def test_connected_components_split():
    txs = [_tx("t1", "A", "B"), _tx("t2", "C", "D")]
    comps = net.connected_components(txs)
    assert sorted(len(c) for c in comps) == [2, 2]


def test_connected_components_joined():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "C")]
    comps = net.connected_components(txs)
    assert len(comps) == 1 and set(comps[0]) == {"A", "B", "C"}


def test_components_deterministic():
    txs = [_tx("t1", "A", "B"), _tx("t2", "C", "D")]
    assert net.connected_components(txs) == net.connected_components(txs)


def test_community_detection_labels_all():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "C"), _tx("t3", "X", "Y")]
    labels = net.community_detection(txs)
    assert set(labels) == {"A", "B", "C", "X", "Y"}


def test_community_two_groups():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "A"),
           _tx("t3", "X", "Y"), _tx("t4", "Y", "X")]
    labels = net.community_detection(txs)
    assert labels["A"] == labels["B"]
    assert labels["X"] == labels["Y"]
    assert labels["A"] != labels["X"]


# ---- centrality / brokers ----
def test_centrality_broker_has_highest_betweenness():
    # star: B in the middle
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "C"),
           _tx("t3", "D", "B"), _tx("t4", "B", "E")]
    c = net.centrality(txs)
    assert c["B"]["betweenness"] >= max(c[n]["betweenness"] for n in ("A", "C", "D", "E"))


def test_broker_score_in_unit():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "C")]
    for v in net.centrality(txs).values():
        assert 0.0 <= v["broker_score"] <= 1.0


def test_top_brokers_sorted():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "C"), _tx("t3", "D", "B")]
    rows = net.top_brokers(txs, k=2)
    assert len(rows) == 2
    assert rows[0]["broker_score"] >= rows[1]["broker_score"]


# ---- path of funds ----
def test_path_of_funds_finds_route():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "C"), _tx("t3", "C", "D")]
    paths = net.path_of_funds(txs, "A", "D")
    assert paths and paths[0]["path"] == ["A", "B", "C", "D"]
    assert paths[0]["hops"] == 3


def test_path_of_funds_bottleneck():
    txs = [_tx("t1", "A", "B", amt=100), _tx("t2", "B", "C", amt=40)]
    paths = net.path_of_funds(txs, "A", "C")
    assert paths[0]["bottleneck_amount"] == 40


def test_path_of_funds_no_route():
    txs = [_tx("t1", "A", "B")]
    assert net.path_of_funds(txs, "A", "Z") == []


def test_path_of_funds_no_self_loop_cycle():
    txs = [_tx("t1", "A", "B"), _tx("t2", "B", "A"), _tx("t3", "B", "C")]
    paths = net.path_of_funds(txs, "A", "C")
    # path must be simple (no revisiting A)
    assert all(len(set(p["path"])) == len(p["path"]) for p in paths)

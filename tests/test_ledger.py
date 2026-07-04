from cognis_lattice import ledger


TX = [
    {"id": "t1", "src": "A", "dst": "B", "amount": 10, "timestamp": "2026-01-01T00:00:00Z"},
    {"id": "t2", "src": "B", "dst": "C", "amount": 5, "timestamp": "2026-01-02T12:00:00Z"},
    {"id": "t3", "src": "A", "dst": "C", "amount": 7, "timestamp": "2026-01-03T00:00:00Z"},
]


def test_parse_ts_z_suffix():
    dt = ledger.parse_ts("2026-01-01T00:00:00Z")
    assert dt is not None and dt.year == 2026


def test_parse_ts_bad_returns_none():
    assert ledger.parse_ts("not-a-date") is None
    assert ledger.parse_ts(None) is None


def test_parse_ts_date_only():
    assert ledger.parse_ts("2026-05-01") is not None


def test_epoch_monotonic():
    assert ledger.epoch("2026-01-02T00:00:00Z") > ledger.epoch("2026-01-01T00:00:00Z")


def test_epoch_bad_zero():
    assert ledger.epoch("garbage") == 0.0


def test_entities():
    assert ledger.entities(TX) == {"A", "B", "C"}


def test_outgoing_incoming():
    out = ledger.outgoing(TX)
    inc = ledger.incoming(TX)
    assert len(out["A"]) == 2
    assert len(inc["C"]) == 2
    assert "C" not in out


def test_adjacency_aggregates():
    adj = ledger.adjacency(TX)
    assert adj[("A", "B")]["count"] == 1
    assert adj[("A", "B")]["amount"] == 10


def test_mean_stdev():
    assert ledger.mean([2, 4, 6]) == 4
    assert ledger.mean([]) == 0.0
    assert ledger.stdev([5]) == 0.0
    assert round(ledger.stdev([2, 4, 6]), 4) == round((8 / 3) ** 0.5, 4)


def test_missing_side_ignored():
    txs = [{"id": "x", "src": "A", "amount": 1}]  # no dst
    assert ledger.entities(txs) == {"A"}
    assert ledger.adjacency(txs) == {}

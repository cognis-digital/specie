from bench import ledgergen
from cognis_lattice import typologies as typ


def _tx(i, s, d, amt, hours, **extra):
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ts = (base + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = {"id": i, "src": s, "dst": d, "amount": amt, "timestamp": ts}
    r.update(extra)
    return r


# ---- structuring ----
def test_structuring_flags_subthreshold_aggregate():
    txs = [_tx(f"s{k}", f"dep{k}", "ACCT", 9500, k * 2) for k in range(4)]
    f = typ.detect_structuring(txs)
    assert any("ACCT" in x.entities for x in f)


def test_structuring_ignores_single_large_deposit():
    txs = [_tx("s0", "dep", "ACCT", 50000, 0)]
    assert typ.detect_structuring(txs) == []


def test_structuring_ignores_below_min_count():
    txs = [_tx("s0", "dep0", "ACCT", 9500, 0), _tx("s1", "dep1", "ACCT", 9500, 2)]
    assert typ.detect_structuring(txs, min_count=3) == []


# ---- layering ----
def test_layering_detects_chain():
    txs = [_tx(f"l{k}", f"H{k}", f"H{k+1}", 1000, k * 5) for k in range(5)]
    f = typ.detect_layering(txs, min_len=4)
    assert f and f[0].features["hops"] >= 4


def test_layering_ignores_short_chain():
    txs = [_tx("l0", "H0", "H1", 1000, 0), _tx("l1", "H1", "H2", 1000, 5)]
    assert typ.detect_layering(txs, min_len=4) == []


# ---- pass-through ----
def test_pass_through_conduit():
    txs = [_tx("i", "src", "PT", 10000, 0), _tx("o", "PT", "dst", 9500, 2)]
    f = typ.detect_pass_through(txs)
    assert any("PT" in x.entities for x in f)


def test_pass_through_ignores_store_of_value():
    txs = [_tx("i", "src", "PT", 10000, 0), _tx("o", "PT", "dst", 1000, 2)]
    assert typ.detect_pass_through(txs) == []


# ---- round tripping ----
def test_round_tripping_cycle():
    txs = [_tx("c0", "O", "A", 1000, 0), _tx("c1", "A", "B", 990, 5),
           _tx("c2", "B", "O", 980, 10)]
    f = typ.detect_round_tripping(txs)
    assert any("O" in x.entities for x in f)


def test_round_tripping_no_cycle():
    txs = [_tx("c0", "O", "A", 1000, 0), _tx("c1", "A", "B", 990, 5)]
    assert typ.detect_round_tripping(txs) == []


# ---- trade value anomaly ----
def test_trade_over_invoicing():
    txs = [_tx("t", "imp", "exp", 100000, 0, goods_value=20000)]
    f = typ.detect_trade_value_anomaly(txs)
    assert f and f[0].features["direction"] == "over-invoicing"


def test_trade_under_invoicing():
    txs = [_tx("t", "imp", "exp", 5000, 0, goods_value=100000)]
    f = typ.detect_trade_value_anomaly(txs)
    assert f and f[0].features["direction"] == "under-invoicing"


def test_trade_within_tolerance_not_flagged():
    txs = [_tx("t", "imp", "exp", 105000, 0, goods_value=100000)]
    assert typ.detect_trade_value_anomaly(txs) == []


def test_trade_requires_goods_value():
    txs = [_tx("t", "imp", "exp", 105000, 0)]
    assert typ.detect_trade_value_anomaly(txs) == []


# ---- shell / nominee ----
def test_shell_cluster_flagged():
    shells = ["S1", "S2", "S3"]
    txs = []
    n = 0
    for a in shells:
        for b in shells:
            if a != b:
                n += 1
                txs.append(_tx(f"x{n}", a, b, 1000, n))
    f = typ.detect_shell_nominee(txs)
    assert any(set(shells) <= set(x.entities) for x in f)


# ---- sanctions nexus ----
def test_sanctions_nexus_proximity():
    txs = [_tx("t0", "WATCHED", "N1", 100, 0), _tx("t1", "N1", "N2", 100, 5)]
    f = typ.detect_sanctions_nexus(txs, ["WATCHED"], max_hops=2)
    hits = {e for x in f for e in x.entities}
    assert "N1" in hits and "N2" in hits and "WATCHED" not in hits


def test_sanctions_nexus_empty_watchlist():
    txs = [_tx("t0", "A", "B", 100, 0)]
    assert typ.detect_sanctions_nexus(txs, []) == []


def test_sanctions_nexus_hop_scoring_decreases():
    txs = [_tx("t0", "W", "N1", 100, 0), _tx("t1", "N1", "N2", 100, 5)]
    f = {x.entities[0]: x.score for x in typ.detect_sanctions_nexus(txs, ["W"])}
    assert f["N1"] > f["N2"]


# ---- funnel account ----
def test_funnel_account_fan_in_out():
    txs = [_tx(f"i{k}", f"src{k}", "FUNNEL", 3000, k,
               counterparty_country=["US", "GB", "DE", "SG", "FR"][k]) for k in range(5)]
    txs.append(_tx("o", "FUNNEL", "dst", 15000, 10))
    f = typ.detect_funnel_account(txs)
    assert any("FUNNEL" in x.entities for x in f)


def test_funnel_ignores_many_dests():
    txs = [_tx(f"i{k}", f"src{k}", "F", 3000, k) for k in range(6)]
    for k in range(5):
        txs.append(_tx(f"o{k}", "F", f"dst{k}", 1000, 20 + k))
    assert typ.detect_funnel_account(txs, max_dests=2) == []


# ---- run_all ----
def test_run_all_returns_findings():
    txs = ledgergen.generate()["transfers"]
    f = typ.run_all(txs, watchlist=["RT_ORIGIN"])
    assert len(f) > 0
    assert all(hasattr(x, "typology") for x in f)


def test_run_all_enabled_filter():
    txs = ledgergen.generate()["transfers"]
    f = typ.run_all(txs, enabled=["structuring"])
    assert {x.typology for x in f} == {"structuring"}


def test_run_all_recovers_all_planted():
    data = ledgergen.generate()
    f = typ.run_all(data["transfers"], watchlist=["RT_ORIGIN", "SHELL_1"])
    by = {}
    for x in f:
        by.setdefault(x.typology, set()).update(str(e) for e in x.entities)
    for t in ("structuring", "layering", "pass_through", "round_tripping",
              "trade_value_anomaly", "shell_nominee", "funnel_account"):
        planted = set(data["truth"][t])
        assert planted <= by.get(t, set()), t


def test_all_scores_in_unit_interval():
    txs = ledgergen.generate()["transfers"]
    for x in typ.run_all(txs, watchlist=["RT_ORIGIN"]):
        assert 0.0 <= x.score <= 1.0


def test_empty_input_no_crash():
    assert typ.run_all([]) == []

from datetime import datetime, timedelta, timezone

from bench import ledgergen
from cognis_lattice import temporal as tmp

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _tx(i, s, d, hours, amt=100):
    ts = (BASE + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": i, "src": s, "dst": d, "amount": amt, "timestamp": ts}


# ---- burst velocity ----
def test_burst_velocity_flags_spike():
    txs = [_tx("b0", "seed", "ACCT", 0)]
    txs += [_tx(f"x{k}", "ACCT", f"o{k}", 1000 + k * 0.3) for k in range(8)]
    f = tmp.detect_burst_velocity(txs)
    assert any("ACCT" in x.entities for x in f)


def test_burst_velocity_requires_min_events_in_window():
    # sparse: never a burst even though baseline is tiny
    txs = [_tx("b0", "A", "B", 0), _tx("b1", "A", "C", 5000)]
    assert tmp.detect_burst_velocity(txs) == []


def test_burst_velocity_uniform_not_flagged():
    txs = [_tx(f"u{k}", "A", f"o{k}", k * 100) for k in range(10)]
    assert tmp.detect_burst_velocity(txs) == []


# ---- dormancy activation ----
def test_dormancy_activation_flags_reactivation():
    txs = [_tx("d0", "seed", "ACCT", 0), _tx("d1", "ACCT", "x", 5)]
    txs += [_tx(f"r{k}", "ACCT", f"o{k}", 120 * 24 + 20 + k) for k in range(4)]
    f = tmp.detect_dormancy_activation(txs)
    assert any("ACCT" in x.entities for x in f)


def test_dormancy_ignores_continuous_activity():
    txs = [_tx(f"c{k}", "ACCT", f"o{k}", k * 24) for k in range(10)]
    assert tmp.detect_dormancy_activation(txs) == []


def test_dormancy_reports_gap_days():
    txs = [_tx("d0", "s", "ACCT", 0), _tx("d1", "ACCT", "x", 2)]
    txs += [_tx(f"r{k}", "ACCT", f"o{k}", 200 * 24 + k) for k in range(4)]
    f = tmp.detect_dormancy_activation(txs)
    assert f and f[0].features["dormant_days"] > 100


# ---- periodicity ----
def test_periodicity_regular_cadence():
    txs = [_tx(f"p{k}", "ACCT", f"o{k % 2}", k * 24) for k in range(8)]
    f = tmp.detect_periodicity(txs)
    assert any("ACCT" in x.entities for x in f)


def test_periodicity_irregular_not_flagged():
    hours = [0, 1, 50, 51, 300, 900]
    txs = [_tx(f"p{k}", "ACCT", "o", h) for k, h in enumerate(hours)]
    assert tmp.detect_periodicity(txs) == []


def test_periodicity_reports_interval():
    txs = [_tx(f"p{k}", "ACCT", "o", k * 12) for k in range(8)]
    f = tmp.detect_periodicity(txs)
    assert f and abs(f[0].features["mean_interval_hours"] - 12) < 1


# ---- run_all ----
def test_run_all_recovers_planted():
    data = ledgergen.generate()
    f = tmp.run_all(data["transfers"])
    by = {}
    for x in f:
        by.setdefault(x.typology, set()).update(str(e) for e in x.entities)
    assert "BURST_ACCT" in by.get("burst_velocity", set())
    assert "DORMANT_ACCT" in by.get("dormancy_activation", set())
    assert "PERIODIC_ACCT" in by.get("periodicity", set())


def test_run_all_scores_unit():
    txs = ledgergen.generate()["transfers"]
    for x in tmp.run_all(txs):
        assert 0.0 <= x.score <= 1.0


def test_empty_no_crash():
    assert tmp.run_all([]) == []


def test_dirty_timestamps_degrade_gracefully():
    txs = [{"id": "t", "src": "A", "dst": "B", "amount": 1, "timestamp": "bad"}]
    assert tmp.run_all(txs) == []

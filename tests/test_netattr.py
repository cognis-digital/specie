import os

from specie import netattr

DATA = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "sample_infrastructure.json")
)


def load():
    return netattr.load_observations(DATA)


def test_fingerprint_clusters_by_cert():
    clusters = netattr.fingerprint_clusters(load())
    c = next(s for s in clusters if "203.0.113.10" in s)
    assert "203.0.113.11" in c


def test_vpn_not_clustered_with_c2():
    clusters = netattr.fingerprint_clusters(load())
    c = next(s for s in clusters if "203.0.113.10" in s)
    assert "198.51.100.5" not in c


def test_enrich_marks_anonymizer():
    obs = netattr.enrich(load())
    tor = next(o for o in obs if o["ip"] == "203.0.113.10")
    assert tor["anonymized"] is True


def test_temporal_signature():
    sig = netattr.temporal_signature(load(), "203.0.113.10")
    assert sig["observations"] >= 2
    assert sig["active_days"] >= 2
    assert sig["peak_hour_utc"] == 11

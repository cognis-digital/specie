import os

from specie import sanctions

DATA = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "ofac_sample.json")
)


def load():
    return sanctions.load_sdn(DATA)


def test_screen_addresses_hit():
    hits = sanctions.screen_addresses(["addr-B1", "addr-A1"], load())
    assert any(h["match"] == "addr-B1" and h["confidence"] == 1.0 for h in hits)


def test_screen_addresses_no_false_positive():
    hits = sanctions.screen_addresses(["addr-A1", "addr-A2"], load())
    assert hits == []


def test_screen_names_alias():
    hits = sanctions.screen_names(["Test Actor One"], load())
    assert hits and hits[0]["type"] == "name"

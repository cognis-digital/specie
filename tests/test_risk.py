from cognis_lattice import risk
from cognis_lattice.findings import Finding


def test_score_entities_basic():
    fs = [Finding("structuring", ["A"], 0.8)]
    recs = risk.score_entities(fs)
    assert recs[0]["entity"] == "A"
    assert 0.0 <= recs[0]["risk"] <= 1.0


def test_multiple_typologies_raise_risk():
    single = risk.score_entities([Finding("structuring", ["A"], 0.7)])[0]["risk"]
    multi = risk.score_entities([
        Finding("structuring", ["A"], 0.7),
        Finding("funnel_account", ["A"], 0.7),
        Finding("burst_velocity", ["A"], 0.7),
    ])[0]["risk"]
    assert multi > single


def test_diversity_bonus_applied():
    recs = risk.score_entities([
        Finding("structuring", ["A"], 0.5),
        Finding("layering", ["A"], 0.5),
    ])
    assert recs[0]["diversity_bonus"] > 0


def test_same_typology_no_diversity_bonus():
    recs = risk.score_entities([
        Finding("structuring", ["A"], 0.5),
        Finding("structuring", ["A"], 0.6),
    ])
    assert recs[0]["diversity_bonus"] == 0.0
    assert recs[0]["typology_count"] == 1  # collapses to strongest per typology


def test_sanctions_nexus_high_weight():
    recs = risk.score_entities([Finding("sanctions_nexus", ["A"], 0.9)])
    assert recs[0]["risk"] >= 0.8


def test_contributions_are_explained():
    recs = risk.score_entities([Finding("structuring", ["A"], 0.8)])
    c = recs[0]["contributions"][0]
    for k in ("typology", "finding_id", "weight", "contribution", "evidence"):
        assert k in c


def test_records_sorted_desc():
    recs = risk.score_entities([
        Finding("periodicity", ["low"], 0.3),
        Finding("sanctions_nexus", ["high"], 0.9),
    ])
    assert recs[0]["entity"] == "high"


def test_score_network_aggregates():
    fs = [Finding("structuring", ["A"], 0.8), Finding("layering", ["B"], 0.6)]
    comps = [["A", "B", "C"]]
    nets = risk.score_network(fs, comps)
    assert nets[0]["size"] == 3
    assert nets[0]["flagged_entities"] == 2
    assert nets[0]["network_risk"] >= nets[0]["peak_entity_risk"]


def test_score_network_skips_unflagged_component():
    fs = [Finding("structuring", ["A"], 0.8)]
    comps = [["A"], ["X", "Y"]]
    nets = risk.score_network(fs, comps)
    assert len(nets) == 1


def test_prioritized_findings_top_n():
    fs = [Finding("a", ["1"], 0.9), Finding("b", ["2"], 0.5), Finding("c", ["3"], 0.1)]
    out = risk.prioritized_findings(fs, top=2)
    assert len(out) == 2 and out[0]["score"] == 0.9


def test_none_entity_ignored():
    recs = risk.score_entities([Finding("structuring", [None, "A"], 0.5)])
    assert all(r["entity"] is not None for r in recs)

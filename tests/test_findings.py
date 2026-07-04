from cognis_lattice.findings import Finding, sort_findings


def test_score_clamped_and_rounded():
    f = Finding(typology="x", entities=["a"], score=1.7)
    assert f.score == 1.0
    f2 = Finding(typology="x", entities=["a"], score=-0.5)
    assert f2.score == 0.0


def test_severity_bands():
    assert Finding("x", ["a"], 0.9).severity == "HIGH"
    assert Finding("x", ["a"], 0.6).severity == "MODERATE"
    assert Finding("x", ["a"], 0.2).severity == "LOW"
    assert Finding("x", ["a"], 0.0).severity == "NONE"


def test_id_is_deterministic_and_content_addressed():
    a = Finding("structuring", ["e1", "e2"], 0.5)
    b = Finding("structuring", ["e2", "e1"], 0.9)  # order-independent entities
    assert a.id == b.id
    c = Finding("layering", ["e1", "e2"], 0.5)
    assert a.id != c.id


def test_to_dict_shape():
    d = Finding("x", ["a"], 0.5, features={"k": 1}, evidence=["ev"], rationale="r").to_dict()
    for key in ("id", "typology", "entities", "score", "severity",
                "features", "evidence", "rationale"):
        assert key in d


def test_sort_findings_desc_by_score():
    fs = [Finding("a", ["1"], 0.2), Finding("b", ["2"], 0.9), Finding("c", ["3"], 0.5)]
    ordered = sort_findings(fs)
    assert [f.score for f in ordered] == [0.9, 0.5, 0.2]


def test_sort_is_stable_deterministic():
    fs = [Finding("b", ["1"], 0.5), Finding("a", ["2"], 0.5)]
    ordered = sort_findings(fs)
    # tie broken by typology then id
    assert ordered[0].typology == "a"

from bench import ledgergen
from cognis_lattice import casefile


def _txs():
    return ledgergen.generate()["transfers"]


def test_build_case_structure():
    case = casefile.build_case(_txs(), watchlist=["RT_ORIGIN", "SHELL_1"])
    for k in ("case_ref", "disclaimer", "summary", "entity_risk",
              "network_risk", "findings", "narrative", "top_brokers"):
        assert k in case


def test_case_ref_deterministic():
    a = casefile.build_case(_txs(), watchlist=["RT_ORIGIN"])
    b = casefile.build_case(_txs(), watchlist=["RT_ORIGIN"])
    assert a["case_ref"] == b["case_ref"]


def test_case_render_json_deterministic():
    a = casefile.build_case(_txs(), watchlist=["RT_ORIGIN"])
    b = casefile.build_case(_txs(), watchlist=["RT_ORIGIN"])
    assert casefile.render_json(a) == casefile.render_json(b)


def test_disclaimer_present_in_narrative():
    case = casefile.build_case(_txs())
    assert "DECISION-SUPPORT" in case["narrative"]


def test_entity_resolution_merges_reported():
    case = casefile.build_case(_txs(), resolve=True)
    # only the planted Acme duplicate should merge
    merged = {m for members in case["entity_merges"].values() for m in members}
    assert any("Acme" in m for m in merged)


def test_no_resolve_option():
    case = casefile.build_case(_txs(), resolve=False)
    assert case["entity_merges"] == {}


def test_summary_counts_consistent():
    case = casefile.build_case(_txs(), watchlist=["RT_ORIGIN"])
    s = case["summary"]
    assert s["findings"] == len(case["findings"])
    assert s["flagged_entities"] == len(case["entity_risk"])


def test_narrative_names_high_risk_entity():
    case = casefile.build_case(_txs(), watchlist=["RT_ORIGIN", "SHELL_1"])
    top = case["entity_risk"][0]["entity"]
    assert top in case["narrative"]


def test_empty_ledger_no_crash():
    case = casefile.build_case([])
    assert case["summary"]["findings"] == 0
    assert "DECISION-SUPPORT" in case["narrative"]


def test_render_text_equals_narrative():
    case = casefile.build_case(_txs())
    assert casefile.render_text(case) == case["narrative"]

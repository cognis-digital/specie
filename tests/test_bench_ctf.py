from bench import evaluate_ctf, ledgergen


def test_ledgergen_deterministic():
    a = ledgergen.generate()
    b = ledgergen.generate()
    assert a["transfers"] == b["transfers"]


def test_ledgergen_plants_all_typologies():
    truth = ledgergen.generate()["truth"]
    for typ in ("structuring", "layering", "pass_through", "round_tripping",
                "trade_value_anomaly", "shell_nominee", "funnel_account",
                "burst_velocity", "dormancy_activation", "periodicity"):
        assert truth[typ], typ


def test_evaluate_macro_recall_is_one():
    res = evaluate_ctf.evaluate()
    assert res["macro_recall"] == 1.0


def test_evaluate_per_typology_full_recall():
    res = evaluate_ctf.evaluate()
    for typ, m in res["per_typology_recall"].items():
        assert m["recall"] == 1.0, typ


def test_evaluate_entity_resolution_clean():
    res = evaluate_ctf.evaluate()
    er = res["entity_resolution"]
    assert er["true_merge_recovered"] is True
    assert er["false_merge_groups"] == 0


def test_evaluate_deterministic():
    assert evaluate_ctf.evaluate() == evaluate_ctf.evaluate()

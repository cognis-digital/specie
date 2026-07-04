import json
import os

from cognis_lattice import cli

DATA = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data"))
LEDGER = os.path.join(DATA, "sample_ledger.json")
WATCH = os.path.join(DATA, "sample_watchlist.json")


def test_sample_ledger_exists():
    assert os.path.exists(LEDGER)
    with open(LEDGER, encoding="utf-8") as f:
        txs = json.load(f)
    assert len(txs) > 50


def test_cli_typologies(capsys):
    rc = cli.main(["typologies", "--ledger", LEDGER, "--watchlist", WATCH, "--top", "5"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out) == 5


def test_cli_typologies_only_filter(capsys):
    rc = cli.main(["typologies", "--ledger", LEDGER, "--only", "structuring"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert all(f["typology"] == "structuring" for f in out)


def test_cli_network(capsys):
    rc = cli.main(["network", "--ledger", LEDGER, "--top", "3"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "components" in out and "top_brokers" in out
    assert len(out["top_brokers"]) == 3


def test_cli_resolve(capsys):
    rc = cli.main(["resolve", "--ledger", LEDGER])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["entities_after"] <= out["entities_before"]


def test_cli_trace_funds(capsys):
    rc = cli.main(["trace-funds", "--ledger", LEDGER,
                   "--src", "LAYER_SRC", "--dst", "LAYER_H4"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["paths"]


def test_cli_temporal(capsys):
    rc = cli.main(["temporal", "--ledger", LEDGER])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, list)


def test_cli_risk(capsys):
    rc = cli.main(["risk", "--ledger", LEDGER, "--watchlist", WATCH])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "entity_risk" in out and "network_risk" in out


def test_cli_case_text(capsys):
    rc = cli.main(["case", "--ledger", LEDGER, "--watchlist", WATCH])
    assert rc == 0
    assert "CASE" in capsys.readouterr().out


def test_cli_case_writes_files(tmp_path, capsys):
    j = tmp_path / "case.json"
    h = tmp_path / "case.html"
    s = tmp_path / "case.stix.json"
    c = tmp_path / "case.csv"
    rc = cli.main(["case", "--ledger", LEDGER, "--watchlist", WATCH,
                   "--json", str(j), "--html", str(h), "--stix", str(s), "--csv", str(c)])
    assert rc == 0
    for p in (j, h, s, c):
        assert p.exists() and p.stat().st_size > 0
    # HTML is a self-contained document
    assert h.read_text(encoding="utf-8").startswith("<!doctype html>")
    # STIX parses
    json.loads(s.read_text(encoding="utf-8"))


def test_cli_typologies_csv(tmp_path):
    c = tmp_path / "f.csv"
    rc = cli.main(["typologies", "--ledger", LEDGER, "--csv", str(c)])
    assert rc == 0
    assert c.read_text(encoding="utf-8").splitlines()[0].startswith("id,typology")

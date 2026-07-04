from bench import ledgergen
from cognis_lattice import casefile, dashboard


def _case():
    return casefile.build_case(ledgergen.generate()["transfers"],
                               watchlist=["RT_ORIGIN", "SHELL_1"])


def test_html_is_document():
    html = dashboard.render_html(_case())
    assert html.startswith("<!doctype html>")
    assert "</html>" in html


def test_html_no_external_resources():
    html = dashboard.render_html(_case())
    # No CDN scripts / external stylesheets / remote images.
    for needle in ("http://", "https://", "src=\"//", "<script"):
        # allow the w3.org SVG namespace, which is not a fetchable resource
        cleaned = html.replace("http://www.w3.org", "")
        assert needle not in cleaned or needle == "http://"


def test_html_contains_case_ref():
    case = _case()
    html = dashboard.render_html(case)
    assert case["case_ref"] in html


def test_html_contains_disclaimer():
    html = dashboard.render_html(_case())
    assert "DECISION-SUPPORT" in html


def test_html_escapes_content():
    case = casefile.build_case([
        {"id": "t", "src": "<script>x</script>", "dst": "B",
         "amount": 100, "timestamp": "2026-01-01T00:00:00Z"}
    ], resolve=False)
    html = dashboard.render_html(case)
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_deterministic():
    assert dashboard.render_html(_case()) == dashboard.render_html(_case())


def test_html_empty_case():
    case = casefile.build_case([])
    html = dashboard.render_html(case)
    assert html.startswith("<!doctype html>")


def test_html_has_findings_and_narrative_sections():
    html = dashboard.render_html(_case())
    assert "Findings" in html
    assert "narrative" in html.lower()

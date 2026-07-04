import csv
import io
import json

from cognis_lattice import exports
from cognis_lattice.findings import Finding

FS = [
    Finding("structuring", ["A"], 0.8, features={"x": 1}, evidence=["ev1"], rationale="r1"),
    Finding("layering", ["B", "C"], 0.6, evidence=["ev2"], rationale="r2"),
]


def test_findings_json_roundtrip():
    doc = json.loads(exports.findings_json(FS))
    assert len(doc) == 2
    assert doc[0]["typology"] == "structuring"


def test_findings_json_accepts_dicts():
    doc = json.loads(exports.findings_json([f.to_dict() for f in FS]))
    assert len(doc) == 2


def test_findings_csv_header_and_rows():
    out = exports.findings_csv(FS)
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 2
    assert rows[0]["typology"] == "structuring"
    assert "|" in rows[1]["entities"]  # multi-entity join


def test_csv_columns_stable():
    out = exports.findings_csv(FS)
    header = out.splitlines()[0]
    assert header.split(",") == exports.CSV_COLUMNS


def test_stix_bundle_shape():
    b = exports.stix_bundle(FS)
    assert b["type"] == "bundle"
    types = [o["type"] for o in b["objects"]]
    assert "identity" in types
    assert types.count("indicator") == 2
    assert types.count("note") == 2


def test_stix_deterministic_ids():
    b1 = exports.stix_bundle(FS)
    b2 = exports.stix_bundle(FS)
    assert exports.stix_json(FS) == exports.stix_json(FS)
    assert b1["id"] == b2["id"]


def test_stix_custom_properties_present():
    b = exports.stix_bundle(FS)
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert "x_cognis_typology" in ind
    assert "x_cognis_score" in ind
    assert ind["spec_version"] == "2.1"


def test_stix_confidence_mapped():
    b = exports.stix_bundle(FS)
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert 0 <= ind["confidence"] <= 100


def test_empty_findings_valid_bundle():
    b = exports.stix_bundle([])
    assert b["type"] == "bundle"
    assert any(o["type"] == "identity" for o in b["objects"])

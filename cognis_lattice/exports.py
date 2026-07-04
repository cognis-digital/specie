"""Interop exports for the analytics layer.

Serialises findings and case files so Cognis Lattice plugs into downstream
tooling:

  findings_json   canonical JSON list of findings
  findings_csv    flat CSV (one row per finding) for spreadsheets / SIEM ingest
  stix_bundle     a STIX 2.1 bundle representing each finding as an
                  ``indicator`` + ``observed-data``-style note, with
                  deterministic UUIDv5 ids (reproducible provenance)

The STIX here reuses the same deterministic-id discipline as ``stix.py`` and is
documented as STIX-2.1-compatible; custom ``x-cognis-*`` properties carry the
transparent feature payload so no analytic detail is lost on export.
"""

from __future__ import annotations

import csv
import io
import json
import uuid

_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
DEFAULT_TS = "2026-01-01T00:00:00.000Z"


def _as_dicts(findings):
    return [f if isinstance(f, dict) else f.to_dict() for f in findings]


def findings_json(findings, indent: int = 2) -> str:
    return json.dumps(_as_dicts(findings), indent=indent)


CSV_COLUMNS = ["id", "typology", "severity", "score", "entities", "evidence", "rationale"]


def findings_csv(findings) -> str:
    rows = _as_dicts(findings)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({
            "id": r.get("id", ""),
            "typology": r.get("typology", ""),
            "severity": r.get("severity", ""),
            "score": r.get("score", ""),
            "entities": "|".join(str(e) for e in r.get("entities", [])),
            "evidence": " ; ".join(r.get("evidence", [])),
            "rationale": r.get("rationale", ""),
        })
    return buf.getvalue()


def _sid(objtype: str, value: str) -> str:
    return f"{objtype}--{uuid.uuid5(_NS, objtype + ':' + value)}"


def stix_bundle(findings, created: str = DEFAULT_TS) -> dict:
    """STIX 2.1 bundle: one indicator + one note per finding. Deterministic ids."""
    rows = _as_dicts(findings)
    identity_id = _sid("identity", "Cognis Lattice CTF Analytics")
    objects = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": created, "modified": created,
        "name": "Cognis Lattice CTF Analytics", "identity_class": "system",
    }]

    def common(o):
        o.setdefault("spec_version", "2.1")
        o.setdefault("created", created)
        o.setdefault("modified", created)
        o.setdefault("created_by_ref", identity_id)
        return o

    # Confidence band -> STIX confidence integer (0-100), roughly.
    band_conf = {"HIGH": 85, "MODERATE": 60, "LOW": 30, "NONE": 5}

    for r in rows:
        fid = r.get("id", "")
        ents = [str(e) for e in r.get("entities", [])]
        pattern_vals = " OR ".join(
            f"x-cognis-entity:value = '{e}'" for e in ents) or "x-cognis-entity:value = 'unknown'"
        ind_id = _sid("indicator", fid)
        objects.append(common({
            "type": "indicator",
            "id": ind_id,
            "name": f"{r.get('typology', 'finding')} — {', '.join(ents) or 'n/a'}",
            "description": r.get("rationale", ""),
            "pattern_type": "stix",
            "pattern": f"[{pattern_vals}]",
            "valid_from": created,
            "confidence": band_conf.get(r.get("severity", "NONE"), 5),
            "labels": ["suspicious-activity"],
            "x_cognis_typology": r.get("typology"),
            "x_cognis_score": r.get("score"),
            "x_cognis_severity": r.get("severity"),
            "x_cognis_features": r.get("features", {}),
        }))
        note_txt = "; ".join(r.get("evidence", [])) or r.get("rationale", "")
        objects.append(common({
            "type": "note",
            "id": _sid("note", fid),
            "abstract": f"Evidence for {r.get('typology', 'finding')}",
            "content": note_txt,
            "object_refs": [ind_id],
        }))

    return {"type": "bundle", "id": _sid("bundle", "cognis-lattice-findings:" + created),
            "objects": objects}


def stix_json(findings, created: str = DEFAULT_TS, indent: int = 2) -> str:
    return json.dumps(stix_bundle(findings, created), indent=indent)

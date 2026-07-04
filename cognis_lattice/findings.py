"""Shared finding contract for the counter-threat-finance analytics layer.

Every detector in Cognis Lattice emits ``Finding`` objects rather than bare
booleans. A finding is an *explainable investigative lead*: it always carries

  - the ``typology`` (which pattern fired),
  - the ``entities`` it implicates,
  - a transparent ``features`` dict (the raw numbers the score was derived from),
  - a ``score`` in [0,1] with a coarse ``severity`` band,
  - human-readable ``evidence`` strings, and
  - a short machine ``rationale``.

This uniform shape lets the risk engine, case builder, and exporters consume
every detector identically, and lets an analyst audit *why* any lead was raised.
Nothing here asserts ground truth — every finding is decision-support, not a
determination. See ``docs/LIMITATIONS.md``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .confidence import band, clamp


@dataclass
class Finding:
    typology: str
    entities: list = field(default_factory=list)
    score: float = 0.0
    features: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    rationale: str = ""

    def __post_init__(self) -> None:
        self.score = round(clamp(float(self.score)), 4)

    @property
    def severity(self) -> str:
        return band(self.score)

    @property
    def id(self) -> str:
        """Deterministic content-addressed id so identical inputs -> identical
        finding ids (reproducible evidentiary output)."""
        payload = self.typology + "|" + "|".join(sorted(str(e) for e in self.entities))
        h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
        return f"finding--{h}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "typology": self.typology,
            "entities": list(self.entities),
            "score": self.score,
            "severity": self.severity,
            "features": self.features,
            "evidence": list(self.evidence),
            "rationale": self.rationale,
        }


def sort_findings(findings) -> list:
    """Stable, deterministic ordering: highest score first, then typology, id."""
    return sorted(findings, key=lambda f: (-f.score, f.typology, f.id))

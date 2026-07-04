"""Confidence scoring for attribution evidence.

We never emit a bare assertion. Every derived link carries a probability in
[0,1], a coarse band (HIGH/MODERATE/LOW), and the rationale behind it. Multiple
independent *supporting* signals are combined with a noisy-OR, which is
appropriate when each signal independently raises belief that a link is real.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HIGH = 0.80
MODERATE = 0.50


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def combine_supporting(weights) -> float:
    """Noisy-OR combination of independent supporting evidence.

    p = 1 - prod(1 - w_i). With no evidence, returns 0.0.
    """
    prod = 1.0
    for w in weights:
        prod *= (1.0 - clamp(w))
    return 1.0 - prod


def band(p: float) -> str:
    p = clamp(p)
    if p >= HIGH:
        return "HIGH"
    if p >= MODERATE:
        return "MODERATE"
    if p > 0.0:
        return "LOW"
    return "NONE"


@dataclass
class Confidence:
    value: float
    band: str
    rationale: list = field(default_factory=list)

    @classmethod
    def from_evidence(cls, weights, rationale=None) -> "Confidence":
        v = combine_supporting(weights)
        return cls(round(v, 4), band(v), list(rationale or []))

    def to_dict(self) -> dict:
        return {"value": self.value, "band": self.band, "rationale": self.rationale}

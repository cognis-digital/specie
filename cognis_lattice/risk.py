"""Risk scoring: combine detector findings into explainable entity- and
network-level risk scores.

The score is a transparent, auditable roll-up — never a black box:

  1. Each typology has a documented ``TYPOLOGY_WEIGHT`` (its inherent severity).
  2. For an entity, we take the strongest finding per typology (avoid double
     counting repeated hits of the same pattern) and combine them with a
     noisy-OR over weight*score, so independent typologies reinforce belief.
  3. A small diversity bonus rewards corroboration across *different* typologies
     (a structuring + funnel + burst entity is riskier than three structuring
     hits).

Every entity risk record lists the exact contributing findings and the arithmetic,
so an analyst can reproduce the number by hand. Decision-support, not a verdict.
"""

from __future__ import annotations

from collections import defaultdict

from .confidence import band, clamp, combine_supporting
from .findings import sort_findings

# Inherent severity weight per typology (0..1). Documented in docs/RISK.md.
TYPOLOGY_WEIGHT = {
    "sanctions_nexus": 1.00,
    "round_tripping": 0.85,
    "layering": 0.80,
    "funnel_account": 0.80,
    "structuring": 0.75,
    "shell_nominee": 0.70,
    "pass_through": 0.65,
    "trade_value_anomaly": 0.70,
    "dormancy_activation": 0.55,
    "burst_velocity": 0.50,
    "periodicity": 0.45,
}
DEFAULT_WEIGHT = 0.5
DIVERSITY_BONUS = 0.05  # per distinct extra typology, capped


def score_entities(findings, weights=None) -> list:
    """Roll up findings into per-entity risk records. Returns a list sorted by
    descending risk, each fully explaining its own score."""
    weights = {**TYPOLOGY_WEIGHT, **(weights or {})}
    # entity -> typology -> best finding
    by_entity = defaultdict(dict)
    for f in findings:
        w = weights.get(f.typology, DEFAULT_WEIGHT)
        contrib = clamp(w * f.score)
        for ent in f.entities:
            if ent is None:
                continue
            cur = by_entity[ent].get(f.typology)
            if cur is None or contrib > cur["contribution"]:
                by_entity[ent][f.typology] = {
                    "typology": f.typology,
                    "finding_id": f.id,
                    "finding_score": f.score,
                    "weight": w,
                    "contribution": round(contrib, 4),
                    "evidence": f.evidence,
                }
    records = []
    for ent, typ_map in by_entity.items():
        contribs = sorted(typ_map.values(),
                          key=lambda c: (-c["contribution"], c["typology"]))
        base = combine_supporting([c["contribution"] for c in contribs])
        n_typ = len(contribs)
        diversity = min(DIVERSITY_BONUS * (n_typ - 1), 0.15) if n_typ > 1 else 0.0
        risk = round(clamp(base + diversity), 4)
        records.append({
            "entity": ent,
            "risk": risk,
            "risk_band": band(risk),
            "typology_count": n_typ,
            "typologies": [c["typology"] for c in contribs],
            "diversity_bonus": round(diversity, 4),
            "base_noisy_or": round(base, 4),
            "contributions": contribs,
        })
    records.sort(key=lambda r: (-r["risk"], r["entity"]))
    return records


def score_network(findings, components) -> list:
    """Aggregate entity risk to the network (connected-component) level so an
    analyst can triage whole clusters. ``components`` is a list of entity lists
    (e.g. from ``network.connected_components``)."""
    ent_records = {r["entity"]: r for r in score_entities(findings)}
    out = []
    for i, comp in enumerate(components):
        risks = [ent_records[e]["risk"] for e in comp if e in ent_records]
        if not risks:
            continue
        # Network risk: noisy-OR of member risks (one very risky member lifts the
        # whole cluster), then reported with the peak and mean for context.
        net = round(clamp(combine_supporting(risks)), 4)
        typs = set()
        for e in comp:
            if e in ent_records:
                typs.update(ent_records[e]["typologies"])
        out.append({
            "network_id": f"network-{i + 1}",
            "size": len(comp),
            "flagged_entities": len(risks),
            "network_risk": net,
            "network_risk_band": band(net),
            "peak_entity_risk": round(max(risks), 4),
            "mean_entity_risk": round(sum(risks) / len(risks), 4),
            "typologies": sorted(typs),
            "entities": sorted(comp),
        })
    out.sort(key=lambda r: (-r["network_risk"], r["network_id"]))
    return out


def prioritized_findings(findings, top=None) -> list:
    """Deterministically ordered findings (highest score first) as dicts."""
    ordered = sort_findings(findings)
    if top:
        ordered = ordered[:top]
    return [f.to_dict() for f in ordered]

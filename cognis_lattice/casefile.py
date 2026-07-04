"""Case building: assemble findings + risk into a SAR-style narrative case file.

Produces an analyst aid modelled on the structure of a Suspicious Activity
Report narrative (Who / What / When / Where / Why / How), but it is explicitly
**decision-support, not a determination or a filed regulatory report**. Every
statement is traceable to a finding id and its transparent features.

Output is a structured ``dict`` (JSON-serialisable) plus a plain-text render.
No external services, no PII beyond what the operator supplied.
"""

from __future__ import annotations

import hashlib
import json

from . import network as netmod
from . import risk as riskmod
from . import temporal as tempmod
from . import typologies as typmod
from .findings import sort_findings

DISCLAIMER = (
    "DECISION-SUPPORT ONLY. This case file lists confidence-scored investigative "
    "leads generated from operator-supplied transaction data. It is NOT a "
    "determination of wrongdoing and NOT a filed regulatory report. All leads "
    "require independent analyst review. See docs/LIMITATIONS.md."
)


def build_case(transfers, watchlist=None, resolve=True, case_ref=None) -> dict:
    """Run the full analytics pipeline and assemble a case file for the highest
    risk network. ``resolve`` applies fuzzy entity resolution first."""
    from .ledger import entities as _ents
    mapping = {}
    if resolve:
        mapping = netmod.resolve_entities(_ents(transfers))
        transfers = netmod.apply_resolution(transfers, mapping)

    findings = (typmod.run_all(transfers, watchlist=watchlist)
                + tempmod.run_all(transfers))
    components = netmod.connected_components(transfers)
    entity_risk = riskmod.score_entities(findings)
    network_risk = riskmod.score_network(findings, components)
    brokers = netmod.top_brokers(transfers, k=5)

    merges = {}
    for original, canon in mapping.items():
        if original != canon:
            merges.setdefault(canon, []).append(original)

    ref = case_ref or _case_ref(transfers)
    narrative = _narrative(ref, findings, entity_risk, network_risk, brokers, merges)

    return {
        "case_ref": ref,
        "disclaimer": DISCLAIMER,
        "summary": {
            "transfers": len(transfers),
            "entities": len(_ents(transfers)),
            "findings": len(findings),
            "flagged_entities": len(entity_risk),
            "networks": len(network_risk),
            "highest_entity_risk": entity_risk[0]["risk"] if entity_risk else 0.0,
            "highest_network_risk": network_risk[0]["network_risk"] if network_risk else 0.0,
        },
        "entity_merges": merges,
        "top_brokers": brokers,
        "entity_risk": entity_risk,
        "network_risk": network_risk,
        "findings": [f.to_dict() for f in sort_findings(findings)],
        "narrative": narrative,
    }


def _case_ref(transfers) -> str:
    payload = json.dumps(
        [[t.get("id"), t.get("src"), t.get("dst"), t.get("amount")] for t in transfers],
        sort_keys=True,
    )
    h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:10].upper()
    return f"CL-CASE-{h}"


def _narrative(ref, findings, entity_risk, network_risk, brokers, merges) -> str:
    L = []
    L.append(f"CASE {ref} - Counter-Threat-Finance Analytic Narrative")
    L.append("")
    L.append("WHO:")
    if entity_risk:
        for r in entity_risk[:5]:
            L.append(f"  - {r['entity']} (risk {r['risk']:.2f}, {r['risk_band']}; "
                     f"typologies: {', '.join(r['typologies'])})")
    else:
        L.append("  - No entities crossed a reporting-worthy risk threshold.")
    if merges:
        L.append("  Entity resolution merged likely-duplicate identifiers:")
        for canon, orig in sorted(merges.items()):
            L.append(f"    * {canon} <= {', '.join(sorted(orig))}")
    L.append("")
    L.append("WHAT (typology leads, highest confidence first):")
    for f in sort_findings(findings)[:12]:
        ev = f.evidence[0] if f.evidence else f.rationale
        L.append(f"  - [{f.severity}] {f.typology}: {ev}")
    if not findings:
        L.append("  - No typology patterns detected.")
    L.append("")
    L.append("HOW (network structure):")
    if brokers:
        top = brokers[0]
        L.append(f"  - Highest broker centrality: {top['entity']} "
                 f"(broker score {top['broker_score']:.2f}, betweenness "
                 f"{top['betweenness']:.4f}) — a value conduit worth prioritising.")
    if network_risk:
        n = network_risk[0]
        L.append(f"  - Highest-risk network {n['network_id']}: {n['size']} entities, "
                 f"{n['flagged_entities']} flagged, network risk "
                 f"{n['network_risk']:.2f} ({n['network_risk_band']}); typologies "
                 f"{', '.join(n['typologies'])}.")
    L.append("")
    L.append("WHY THIS MATTERS:")
    L.append("  The combination of the above patterns is consistent with layered")
    L.append("  movement of illicit value. Each lead is confidence-scored and")
    L.append("  traceable to its underlying transfers for analyst verification.")
    L.append("")
    L.append("DISPOSITION: Refer for analyst review. " + DISCLAIMER)
    return "\n".join(L)


def render_text(case: dict) -> str:
    return case["narrative"]


def render_json(case: dict, indent: int = 2) -> str:
    return json.dumps(case, indent=indent)

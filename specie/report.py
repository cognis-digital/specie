"""Human-readable and JSON intelligence products."""

from __future__ import annotations

import json


def render_json(graph, threat_actors, extras=None) -> str:
    doc = {
        "platform": "Specie",
        "product": "counter-threat-finance-attribution",
        "graph": graph.to_dict(),
        "threat_actors": threat_actors,
    }
    if extras:
        doc["analytics"] = extras
    return json.dumps(doc, indent=2)


def render_text(graph, threat_actors, extras=None) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("  COGNIS LATTICE  |  Counter-Threat-Finance Attribution Report")
    lines.append("  Cognis Digital LLC - investigative leads, not adjudications")
    lines.append("=" * 72)
    lines.append(f"Entities: {len(graph.entities)}    Edges: {len(graph.edges)}    "
                 f"Threat actors: {len(threat_actors)}")
    lines.append("")
    for i, ta in enumerate(threat_actors, 1):
        lines.append(f"[{i}] Threat Actor {ta['id']}")
        lines.append(f"    Confidence : {ta['confidence']:.2f}  ({ta['confidence_band']})")
        lines.append(f"    Rationale  : {', '.join(ta['rationale']) or 'n/a'}")
        for wc in ta["wallet_clusters"]:
            lines.append(f"    Wallets    : {', '.join(wc['attributes']['addresses'])}")
        for ic in ta["infrastructure_clusters"]:
            lines.append(f"    Infra      : {', '.join(ic['attributes']['ips'])}")
        for s in ta["sanctions"]:
            lines.append(f"    !! OFAC    : {s['label']}  (program={s['attributes'].get('program')})")
        lines.append("")
    if extras:
        for key, val in extras.items():
            lines.append(f"-- {key} ({len(val)}) --")
            lines.append(json.dumps(val, indent=2))
            lines.append("")
    lines.append("NOTE: All links are confidence-scored leads for authorized investigative")
    lines.append("use only. Review docs/LIMITATIONS.md before acting on any output.")
    return "\n".join(lines)

"""Self-contained HTML case dashboard.

Renders a case file (from ``casefile.build_case``) into a single static HTML
document with inline CSS and a tiny inline SVG bar chart — **no external scripts,
stylesheets, fonts, or CDN dependencies**. Safe to open air-gapped or hand to a
partner as a single file. Everything is escaped.
"""

from __future__ import annotations

import html

_BAND_COLOR = {"HIGH": "#b91c1c", "MODERATE": "#b45309", "LOW": "#3f6212", "NONE": "#4b5563"}
_PURPLE = "#6D28D9"


def _esc(x) -> str:
    return html.escape(str(x), quote=True)


def _bar(score: float, band: str, width: int = 160) -> str:
    w = int(max(0.0, min(1.0, score)) * width)
    color = _BAND_COLOR.get(band, _PURPLE)
    return (f'<svg width="{width}" height="12" role="img" '
            f'aria-label="score {score:.2f}">'
            f'<rect width="{width}" height="12" fill="#e5e7eb" rx="3"/>'
            f'<rect width="{w}" height="12" fill="{color}" rx="3"/></svg>')


def _chip(text: str, band: str = "NONE") -> str:
    color = _BAND_COLOR.get(band, _PURPLE)
    return (f'<span style="background:{color};color:#fff;border-radius:10px;'
            f'padding:1px 8px;font-size:11px;white-space:nowrap;">{_esc(text)}</span>')


def render_html(case: dict) -> str:
    s = case.get("summary", {})
    parts = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>Cognis Lattice — Case {_esc(case.get('case_ref', ''))}</title>")
    parts.append("""<style>
      :root{--p:#6D28D9;}
      *{box-sizing:border-box;}
      body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        margin:0;color:#111827;background:#f9fafb;}
      header{background:var(--p);color:#fff;padding:20px 28px;}
      header h1{margin:0;font-size:20px;}
      header .ref{opacity:.85;font-size:13px;margin-top:4px;}
      main{max-width:1080px;margin:0 auto;padding:24px 28px 60px;}
      .cards{display:flex;flex-wrap:wrap;gap:12px;margin:8px 0 24px;}
      .card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;
        padding:12px 16px;min-width:120px;flex:1;}
      .card .n{font-size:22px;font-weight:700;color:var(--p);}
      .card .l{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em;}
      h2{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:#374151;
        border-bottom:2px solid var(--p);padding-bottom:6px;margin-top:32px;}
      .scroll{overflow-x:auto;}
      table{border-collapse:collapse;width:100%;font-size:13px;background:#fff;}
      th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eef0f3;vertical-align:top;}
      th{background:#f3f4f6;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:#4b5563;}
      code{background:#f3f4f6;border-radius:4px;padding:1px 5px;font-size:12px;}
      pre{background:#0b1020;color:#e5e7eb;padding:16px;border-radius:10px;overflow-x:auto;
        font-size:12.5px;line-height:1.5;}
      .disc{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:10px;
        padding:12px 16px;font-size:12.5px;margin:16px 0;}
      .muted{color:#6b7280;font-size:12px;}
    </style></head><body>""")
    parts.append("<header>")
    parts.append("<h1>&#128994; Cognis Lattice &mdash; Counter-Threat-Finance Case File</h1>")
    parts.append(f"<div class='ref'>Case {_esc(case.get('case_ref',''))} &middot; "
                 "decision-support, not a determination</div>")
    parts.append("</header><main>")

    parts.append(f"<div class='disc'>{_esc(case.get('disclaimer',''))}</div>")

    # Summary cards
    parts.append("<div class='cards'>")
    for label, key in (("Transfers", "transfers"), ("Entities", "entities"),
                       ("Findings", "findings"), ("Flagged", "flagged_entities"),
                       ("Networks", "networks")):
        parts.append(f"<div class='card'><div class='n'>{_esc(s.get(key,0))}</div>"
                     f"<div class='l'>{label}</div></div>")
    parts.append(f"<div class='card'><div class='n'>{s.get('highest_entity_risk',0):.2f}</div>"
                 "<div class='l'>Top entity risk</div></div>")
    parts.append("</div>")

    # Entity risk table
    parts.append("<h2>Entity risk</h2><div class='scroll'><table>")
    parts.append("<tr><th>Entity</th><th>Risk</th><th></th><th>Typologies</th></tr>")
    for r in case.get("entity_risk", [])[:40]:
        parts.append(
            f"<tr><td><code>{_esc(r['entity'])}</code></td>"
            f"<td>{r['risk']:.2f} {_chip(r['risk_band'], r['risk_band'])}</td>"
            f"<td>{_bar(r['risk'], r['risk_band'])}</td>"
            f"<td>{_esc(', '.join(r['typologies']))}</td></tr>")
    if not case.get("entity_risk"):
        parts.append("<tr><td colspan='4' class='muted'>No flagged entities.</td></tr>")
    parts.append("</table></div>")

    # Findings table
    parts.append("<h2>Findings</h2><div class='scroll'><table>")
    parts.append("<tr><th>Typology</th><th>Severity</th><th>Score</th>"
                 "<th>Entities</th><th>Evidence</th></tr>")
    for f in case.get("findings", [])[:80]:
        parts.append(
            f"<tr><td>{_esc(f['typology'])}</td>"
            f"<td>{_chip(f['severity'], f['severity'])}</td>"
            f"<td>{f['score']:.2f}</td>"
            f"<td>{_esc(', '.join(str(e) for e in f['entities']))}</td>"
            f"<td>{_esc('; '.join(f.get('evidence', [])))}</td></tr>")
    if not case.get("findings"):
        parts.append("<tr><td colspan='5' class='muted'>No findings.</td></tr>")
    parts.append("</table></div>")

    # Brokers
    if case.get("top_brokers"):
        parts.append("<h2>Top brokers (network conduits)</h2><div class='scroll'><table>")
        parts.append("<tr><th>Entity</th><th>Broker score</th><th>Betweenness</th>"
                     "<th>Degree</th><th>Volume</th></tr>")
        for b in case["top_brokers"]:
            parts.append(
                f"<tr><td><code>{_esc(b['entity'])}</code></td>"
                f"<td>{b['broker_score']:.2f}</td><td>{b['betweenness']:.4f}</td>"
                f"<td>{b['degree']}</td><td>{b['volume']:.2f}</td></tr>")
        parts.append("</table></div>")

    # Narrative
    parts.append("<h2>Analytic narrative (SAR-style)</h2>")
    parts.append(f"<pre>{_esc(case.get('narrative',''))}</pre>")

    parts.append("<p class='muted'>Generated by Cognis Lattice &middot; "
                 "self-contained, offline. &copy; Cognis Digital LLC.</p>")
    parts.append("</main></body></html>")
    return "".join(parts)

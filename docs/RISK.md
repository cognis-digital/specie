# Risk scoring & case building

The risk engine (`risk.py`) rolls detector `Finding`s up into an explainable
entity- and network-level risk score. It is a transparent, auditable
computation — never a black box — and every score can be reproduced by hand from
the record it emits.

## Entity risk

1. **Typology weight.** Each typology has a documented inherent-severity weight
   in `TYPOLOGY_WEIGHT` (e.g. `sanctions_nexus = 1.00`, `periodicity = 0.45`).
2. **Strongest-per-typology.** For each entity we keep the strongest finding per
   typology, so repeated hits of the *same* pattern do not inflate the score.
3. **Noisy-OR combination.** The per-typology contributions
   (`weight × finding_score`) are combined with a noisy-OR
   `1 − Π(1 − cᵢ)`, so independent typologies reinforce belief.
4. **Diversity bonus.** A small bonus (`0.05` per distinct extra typology, capped
   at `0.15`) rewards corroboration across *different* typologies — an entity
   flagged for structuring **and** funnelling **and** bursts is riskier than one
   flagged three times for the same pattern.

Every record lists its `contributions` (typology, finding id, weight,
contribution, evidence), its `base_noisy_or`, and its `diversity_bonus`, so the
final `risk` is fully traceable.

```python
from cognis_lattice import typologies, temporal, risk
findings = typologies.run_all(transfers, watchlist=watchlist) + temporal.run_all(transfers)
records = risk.score_entities(findings)   # sorted desc by risk
```

## Network risk

`risk.score_network(findings, components)` aggregates entity risk to the
connected-component level (from `network.connected_components`) so analysts can
triage whole clusters. Network risk is a noisy-OR of member risks — one very
risky member lifts the whole cluster — reported alongside the peak and mean
member risk for context.

## Case files

`casefile.build_case(transfers, watchlist=..., resolve=True)` runs the whole
pipeline (entity resolution → typologies + temporal → risk → brokers) and
assembles a **SAR-style narrative** structured as Who / What / How / Why /
Disposition. It is explicitly labelled **decision-support, not a determination
and not a filed regulatory report**. Every statement is traceable to a finding
id and its features.

- `casefile.render_text(case)` → the plain-text narrative.
- `casefile.render_json(case)` → the full structured case (deterministic).
- `dashboard.render_html(case)` → a self-contained HTML dashboard (no external
  scripts, stylesheets, fonts, or CDN dependencies — safe to open air-gapped or
  hand to a partner as a single file).

## Exports

`exports.py` serialises findings for downstream tooling:

- `findings_json` — canonical JSON.
- `findings_csv` — flat CSV (one row per finding) for spreadsheets / SIEM.
- `stix_bundle` / `stix_json` — STIX 2.1 bundle (one `indicator` + one `note`
  per finding) with deterministic UUIDv5 ids and `x_cognis_*` custom properties
  carrying the transparent feature payload.

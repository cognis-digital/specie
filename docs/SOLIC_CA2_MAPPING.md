# SOLIC Challenge Area 2 — Capability Mapping

How Cognis Lattice maps to the DoW SOLIC / ONIX OTA **Challenge Area 2:
Deanonymization of Illicit Internet Activities for Counter-Threat Finance.**

| Desired capability | Cognis Lattice | Module |
|---|---|---|
| IP deanonymization across Tor/VPN/proxy | Anonymizer enrichment + TLS/domain fingerprint clustering to correlate anonymized addresses to shared infrastructure | `netattr` |
| Behavioral & temporal IP analysis | Activity-window signatures + co-occurrence correlation producing durable network signatures | `netattr` |
| Blockchain analytics & wallet identification | Common-input clustering + forward/backward flow tracing across transparent ledgers | `chain` |
| De-mixing / de-tumbling with confidence | Mixer/CoinJoin detection + confidence-scored de-mix candidate linkage (honest ambiguity) | `chain` |
| Real-time alerting on high-value/known-actor activity | Watchlist screening hooks over the fused graph (address/name/known-infra) | `sanctions`, `fusion` |
| Unified IP + crypto threat-actor profiles | Connected-component fusion into one confidence-scored threat-actor graph | `fusion` |
| Illicit-finance typology detection | 8 typology detectors (structuring, layering, pass-through, round-tripping, trade-based value transfer, shell/nominee, sanctions-nexus, funnel-account), each explainable | `typologies` |
| Temporal behavioural analytics | Burst/velocity, dormancy-then-activation, periodicity over the transfer graph | `temporal` |
| Entity resolution & network segmentation | Fuzzy entity resolution, community detection, broker/centrality scoring, path-of-funds tracing | `network` |
| Analyst decision support | Explainable entity/network risk scoring + SAR-style narrative case files (leads, not determinations) | `risk`, `casefile` |
| Legally shareable products | Deterministic, provenance-tracked STIX 2.1 export (attribution graph and per-finding bundles); CSV/JSON interop; self-contained HTML case dashboard | `stix`, `exports`, `dashboard` |
| Compliance / self-hosting | Zero-dependency, offline/air-gap deployment; no data egress; no bundled sanctions/PII data | whole package |

## TRL posture (honest)

- **Components (TRL 5–6):** the clustering, tracing, infrastructure-fingerprinting,
  screening, and STIX-export methods are working, tested software.
- **Integrated fusion workflow (prototype):** the end-to-end fuse-to-STIX pipeline
  is demonstrable now (`cognis-lattice demo`) and is the artifact proposed for the
  July 24 pitch/demo, to be hardened against a Government-provided reference
  dataset post-award.

See the CA2 white paper for the full submission narrative.

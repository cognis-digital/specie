# Methods & Schemas

Every score in Specie comes from a documented heuristic. This file
states each one plainly so results are defensible.

## Data schemas

**Transactions** (`--tx`):
```json
{"txid": "tx0", "asset": "BTC", "timestamp": "2026-01-02T08:15:00Z",
 "inputs":  [{"address": "addr-A1", "value": 2.0}],
 "outputs": [{"address": "addr-A3", "value": 1.95}]}
```

**Infrastructure observations** (`--obs`):
```json
{"ip": "203.0.113.10", "timestamp": "2026-01-02T11:00:00Z", "asn": "AS64500",
 "cert_sha256": "…", "domains": ["panel.example-c2.net"], "ports": [443], "tags": ["tor-exit"]}
```

**Linkages** (`--linkages`) — analyst/evidence cross-links, each optionally with
`source` and `confidence`:
```json
{"address": "addr-A1", "ip": "203.0.113.10", "source": "seized-server-log", "confidence": 0.8}
{"address": "addr-A3", "address2": "addr-DEP", "source": "direct-spend", "confidence": 0.9}
```

**SDN list** (`--sdn`) — OFAC-style:
```json
{"name": "…", "program": "…", "aka": ["…"], "addresses": {"crypto": ["addr-B1"]}}
```

## Blockchain heuristics (`chain`)

- **Common-input clustering.** Addresses spent together in one transaction share
  a controller (multi-input heuristic). Union-find over co-spending inputs.
- **Money-flow tracing.** BFS over the address flow graph (input→output for
  forward, output→input for backward), bounded by `max_hops`.
- **Mixer/CoinJoin detection.** Flags transactions with high fan-in and fan-out
  and near-uniform output values (coefficient of variation ≤ threshold).
- **De-mix candidates.** Within a mixer, links inputs to outputs of near-equal
  value (net of fee). Confidence *decreases* with the number of equally-plausible
  matches — the honest signal in equal-value mixing.
- **Peel-chain detection.** Follows sequences of 2-output transactions where a
  large "remainder" continues and a small amount is "peeled" off.

## Infrastructure heuristics (`netattr`)

- **Anonymizer enrichment.** Tags IPs as Tor/VPN/proxy from tags or provided lists.
- **Fingerprint clustering.** Union-find over shared TLS certificate fingerprint
  (strong) and self-hosted domain (supporting).
- **Temporal signature.** Activity-hour histogram, active-day count, peak UTC hour.
- **Behavioral correlation.** IPs active on the same days (co-occurrence) with a
  minimum-shared-days threshold.

## Confidence model (`confidence`)

Independent supporting signals combine with a **noisy-OR**:
`p = 1 − Π(1 − wᵢ)`. Bands: `p ≥ 0.80 → HIGH`, `p ≥ 0.50 → MODERATE`,
`p > 0 → LOW`. Address–SDN matches are definitional (1.0); name matches are
capped (0.85) to reflect aliasing risk.

## Fusion (`fusion`)

Wallet clusters, infrastructure clusters, and sanction entities become graph
nodes; `controlled-by-same-actor` and `sanctioned-as` edges connect them.
Connected components become threat-actor profiles whose confidence is the
noisy-OR of the evidence types present. Trivial single-node components are
filtered unless they carry a sanction.

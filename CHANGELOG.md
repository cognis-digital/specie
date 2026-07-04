# Changelog

All notable changes to Cognis Lattice are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] — 2026-07-03

### Added
- **Counter-threat-finance analytics layer** operating on a general
  account-to-account **transfer** model, additive to the existing attribution
  engine (public API unchanged).
- **8 illicit-finance typology detectors** (`typologies.py`): structuring,
  layering, pass-through/rapid-movement, round-tripping, trade-based value
  transfer anomaly, shell/nominee clustering, sanctions-nexus proximity
  (operator-supplied watchlist — no bundled sanctions data), and funnel-account.
  Each emits a transparent feature set + score + evidence.
- **Temporal analytics** (`temporal.py`): burst/velocity, dormancy-then-activation,
  and periodicity detection.
- **Network analytics** (`network.py`): fuzzy entity resolution (Dice-bigram
  similarity with a sequence-number guard), connected components, deterministic
  label-propagation community detection, Brandes betweenness + broker scoring,
  and path-of-funds tracing.
- **Explainable risk scoring** (`risk.py`): per-entity and per-network risk via
  weighted noisy-OR with a cross-typology diversity bonus; every score is fully
  traceable to its contributing findings.
- **SAR-style case builder** (`casefile.py`) — narrative case file clearly
  labelled decision-support, not a determination.
- **Interop exports** (`exports.py`): findings → JSON, CSV, and STIX 2.1
  (indicator + note per finding, deterministic UUIDv5, `x_cognis_*` properties).
- **Self-contained HTML case dashboard** (`dashboard.py`) — no external scripts,
  stylesheets, fonts, or CDN dependencies.
- **Shared `Finding` contract** (`findings.py`) with deterministic content-
  addressed ids.
- **New CLI commands**: `typologies`, `network`, `resolve`, `trace-funds`,
  `temporal`, `risk`, and `case`.
- **Synthetic ledger generator** with planted ground truth (`bench/ledgergen.py`)
  and a CTF accuracy benchmark (`bench/evaluate_ctf.py`), gated in CI. Macro
  entity recall = 1.00 across all 11 detectors; 0 false entity-resolution merges.
- 10 runnable example demos (`examples/`) + a demo runner gating exit 0 in CI.
- Docs: `docs/ANALYTICS.md`, `docs/TYPOLOGIES.md`, `docs/RISK.md`. CodeQL config
  + workflow. Test suite grew from 48 to 176 tests.

## [0.4.1] — 2026-07-02

### Added
- Blockscout explorer instances for **Base, Optimism, Polygon, Arbitrum, and
  Gnosis** — live EVM address tracing on these chains via the existing normalized
  `blockscout_txlist` parser. Catalog now 61 sources / 59 keyless / 17 chains.

## [0.4.0] — 2026-07-02

### Added
- **MISP event export** (`misp.py`) alongside STIX 2.1 — Attributes (btc/eth/xmr,
  ip-dst) + Tags (cognis:lattice, tlp:amber, ofac:sanctioned), deterministic
  UUIDv5. CLI `--misp` on `demo` and `fuse`.
- **Full Solana transaction tracing** — `getTransaction` per signature, SOL
  transfers inferred from pre/post lamport balance deltas → Lattice transactions
  (`fetch_solana_txs`); `sources-address --chain solana` now returns full txs.
- **8 more feeds** (source catalog now 56, 54 keyless, 41 normalized): OpenPhish,
  PhishTank, DShield, Talos, Botvrij, Binary Defense, GreenSnow, UN SC sanctions.
  New `raw_urls` parser for URL feeds.

## [0.3.0] — 2026-07-01

### Added
- More normalized on-chain tracing parsers: **XRPL** (rippled `account_tx`),
  **Tron** (TronGrid account transactions), and **blockchain.info** (`rawaddr`).
  Lattice now normalizes live transactions across BTC/LTC (Esplora + blockchain.info),
  Ethereum/EVM (Blockscout + JSON-RPC), Solana (signatures), XRPL, and Tron —
  21 sources with normalized parsers.

## [0.2.1] — 2026-07-01

### Added
- Live on-chain tracing extended beyond BTC/LTC: **Ethereum & EVM chains**
  (Blockscout `txlist` GET + `eth_getBlockByNumber` JSON-RPC) and **Solana**
  (`getSignaturesForAddress`). JSON-RPC `POST` support added to the HTTP client
  (with the same cache/offline model). `registry.fetch_onchain` dispatches across
  esplora / blockscout / EVM-RPC / Solana. `sources-address` now traces ETH & SOL.
- Live-verified: 10,000 Ethereum transactions traced+clustered for a public address.

## [0.2.0] — 2026-07-01

### Added
- **Live intelligence source integration** (`cognis_lattice.sources`): a catalog
  of **48 sources** (46 keyless) across **16 blockchains** — sanctions (OFAC SDN,
  OpenSanctions, Ransomwhere), threat-intel (abuse.ch Feodo/URLhaus/ThreatFox/
  SSLBL, FireHOL, CINS, Spamhaus, Emerging Threats), Tor/anonymizer infrastructure,
  multi-chain explorers (Esplora/mempool/blockchair/RPC for BTC, ETH & EVM chains,
  Solana, Tron, XRPL, Algorand, LTC, DOGE, BCH), vuln-intel (CISA KEV/NVD/EPSS/
  ATT&CK), and chain registries.
- 18 normalized parsers → common `Indicator` schema; esplora chains parse to
  Lattice transactions for live on-chain tracing.
- HTTP client with on-disk cache + **offline/air-gap mode**.
- `feeds.build_intel` fuses feeds into sanctioned-address / Tor-exit / C2-IP /
  malicious-cert sets that plug into screening and attribution.
- CLI: `sources-list`, `sources-stats`, `sources-fetch`, `sources-intel`,
  `sources-address` (live on-chain trace).
- Source-coverage metrics added to `bench/run_all.py` / `RESULTS.md`;
  `tests/test_sources.py` gates catalog integrity, parsers, offline mode, fusion.

## [0.1.0] — 2026-06-30

Initial public release.

### Added
- Blockchain analytics: common-input wallet clustering, forward/backward money-flow
  tracing, mixer/CoinJoin detection, within-transaction de-mix candidate linkage,
  and peel-chain detection (`cognis_lattice.chain`).
- Network/infrastructure attribution: anonymizer (Tor/VPN/proxy) enrichment,
  TLS-certificate/domain fingerprint clustering, temporal signatures, and
  behavioral co-occurrence correlation (`cognis_lattice.netattr`).
- OFAC-style sanctions screening for crypto addresses and names
  (`cognis_lattice.sanctions`).
- Fusion engine building a confidence-scored threat-actor graph from all sources
  (`cognis_lattice.fusion`) with a noisy-OR confidence model
  (`cognis_lattice.confidence`).
- STIX 2.1 bundle export with deterministic IDs (`cognis_lattice.stix`).
- CLI (`cognis-lattice`) with `demo`, `cluster-chain`, `trace`, `detect-mixer`,
  `infra`, `screen`, and `fuse` subcommands.
- Zero-dependency (stdlib-only) design for offline / air-gapped deployment.
- Verification harness (`bench/`): deterministic ground-truth datasets, accuracy
  metrics (precision/recall/F1) on clean and noisy profiles, performance
  benchmarks, and a determinism check; results in `RESULTS.md`.
- 29 tests (24 unit + 5 verification gates); GitHub Actions CI across Python 3.9–3.13.

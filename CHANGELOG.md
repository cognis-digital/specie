# Changelog

All notable changes to Cognis Lattice are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

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

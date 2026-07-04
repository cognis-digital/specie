# Cognis Lattice — Verification Results

Reproduce with: `python bench/run_all.py` (regenerates this file).

Environment: CPython 3.14.0 on Windows/AMD64. Inputs are deterministic (fixed seed).

## Accuracy vs. planted ground truth

Metrics computed against known synthetic structure. The **clean** profile measures algorithmic correctness; the **noisy** profile injects a shared-service confounder that co-spends across actors, so clustering precision is *expected* to drop — an honest degradation measurement.

| Metric | Clean | Noisy |
|---|---|---|
| Wallet clustering (pairwise) | P=1.000 / R=1.000 / F1=1.000 | P=0.444 / R=1.000 / F1=0.615 |
| Mixer detection | P=1.000 / R=1.000 / F1=1.000 | P=1.000 / R=1.000 / F1=1.000 |
| Infrastructure clustering (pairwise) | P=1.000 / R=1.000 / F1=1.000 | P=1.000 / R=1.000 / F1=1.000 |
| Sanctions screening | P=1.000 / R=1.000 / F1=1.000 | P=1.000 / R=1.000 / F1=1.000 |
| Peel-chain recall | 1.000 | 1.000 |
| Trace reachability recall | 1.000 | 1.000 |
| STIX determinism (2 runs identical) | True | True |

### De-mix (equal-value mixing is intentionally ambiguous)

- Input coverage: **1.000** (fraction of mixer inputs given ≥1 candidate)
- Mean ambiguity: **4.0** candidate outputs per input
- Mean candidate confidence: **0.371** (scaled down by ambiguity, by design)

## Performance (single-thread, stdlib only)

| Transactions | Cluster (s) | Mixer (s) | Peel (s) | Build graph (s) | Total (s) | Tx/s |
|---:|---:|---:|---:|---:|---:|---:|
| 2,000 | 0.0031 | 0.0004 | 0.0013 | 0.0217 | 0.0265 | 75,565 |
| 10,000 | 0.0182 | 0.0017 | 0.0061 | 0.1272 | 0.1532 | 65,265 |
| 40,000 | 0.0863 | 0.007 | 0.0296 | 0.6095 | 0.7323 | 54,622 |

## Counter-threat-finance typology analytics (v0.5.0)

Per-typology **entity recall** against planted ground truth on a deterministic synthetic ledger (95 transfers, 10 planted typologies). Recall = did we recover the entity planted to exhibit each pattern.

| Typology | Planted | Recovered | Recall |
|---|---:|---:|---:|
| structuring | 1 | 1 | 1.000 |
| layering | 6 | 6 | 1.000 |
| pass_through | 1 | 1 | 1.000 |
| round_tripping | 4 | 4 | 1.000 |
| trade_value_anomaly | 2 | 2 | 1.000 |
| shell_nominee | 4 | 4 | 1.000 |
| funnel_account | 1 | 1 | 1.000 |
| burst_velocity | 1 | 1 | 1.000 |
| dormancy_activation | 1 | 1 | 1.000 |
| periodicity | 1 | 1 | 1.000 |
| **macro-average** | | | **1.000** |

Entity resolution: intended duplicate pair recovered = **True**, false-merge groups = **0** (numbered cohorts kept distinct). Total findings raised: 51.

## Intelligence source coverage

- **61 integrated sources** (59 keyless, 46 with normalized parsers)
- **17 blockchains** covered: algorand, arbitrum, avalanche, base, bitcoin, bitcoin-cash, bsc, dogecoin, ethereum, gnosis, litecoin, monero, optimism, polygon, solana, tron, xrpl
- By category: blockchain-explorer=25, chain-registry=2, sanctions=7, threat-intel=19, tor-infra=4, vuln-intel=4

All numbers above are produced by `bench/run_all.py` and gated in CI by `tests/test_bench.py` / `tests/test_sources.py`. See `docs/LIMITATIONS.md`.

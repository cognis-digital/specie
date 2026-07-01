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
| 2,000 | 0.0029 | 0.0002 | 0.0009 | 0.0174 | 0.0213 | 93,846 |
| 10,000 | 0.0272 | 0.0016 | 0.0044 | 0.1035 | 0.1367 | 73,133 |
| 40,000 | 0.0696 | 0.0064 | 0.0261 | 0.5348 | 0.6368 | 62,811 |

## Intelligence source coverage

- **48 integrated sources** (46 keyless, 34 with normalized parsers)
- **16 blockchains** covered: algorand, arbitrum, avalanche, base, bitcoin, bitcoin-cash, bsc, dogecoin, ethereum, litecoin, monero, optimism, polygon, solana, tron, xrpl
- By category: blockchain-explorer=20, chain-registry=2, sanctions=6, threat-intel=12, tor-infra=4, vuln-intel=4

All numbers above are produced by `bench/run_all.py` and gated in CI by `tests/test_bench.py` / `tests/test_sources.py`. See `docs/LIMITATIONS.md`.

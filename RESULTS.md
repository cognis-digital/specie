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
| 2,000 | 0.0032 | 0.0004 | 0.0012 | 0.022 | 0.0269 | 74,460 |
| 10,000 | 0.0148 | 0.0016 | 0.0048 | 0.1076 | 0.1288 | 77,623 |
| 40,000 | 0.0773 | 0.0066 | 0.0295 | 0.8039 | 0.9172 | 43,609 |

## Intelligence source coverage

- **56 integrated sources** (54 keyless, 41 with normalized parsers)
- **16 blockchains** covered: algorand, arbitrum, avalanche, base, bitcoin, bitcoin-cash, bsc, dogecoin, ethereum, litecoin, monero, optimism, polygon, solana, tron, xrpl
- By category: blockchain-explorer=20, chain-registry=2, sanctions=7, threat-intel=19, tor-infra=4, vuln-intel=4

All numbers above are produced by `bench/run_all.py` and gated in CI by `tests/test_bench.py` / `tests/test_sources.py`. See `docs/LIMITATIONS.md`.

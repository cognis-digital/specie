<!-- Cognis Digital — purple/white brand -->
<h1 align="center">🟣 Specie</h1>
<p align="center"><b>Counter-Threat-Finance Attribution &amp; Fusion Platform</b><br>
<i>Fuse IP/infrastructure deanonymization with multi-chain blockchain analytics into one confidence-scored, STIX-exportable threat-actor graph.</i></p>

<p align="center">
<img alt="license" src="https://img.shields.io/badge/license-COCL--1.0-6D28D9">
<img alt="python" src="https://img.shields.io/badge/python-3.9%2B-6D28D9">
<img alt="deps" src="https://img.shields.io/badge/dependencies-none%20(stdlib)-6D28D9">
<img alt="status" src="https://img.shields.io/badge/status-v0.5.0-6D28D9">
</p>

---

> **Built for:** SOLIC Accelerator / ONIX OTA — **Challenge Area 2: Deanonymization of Illicit Internet Activities for Counter-Threat Finance.**
> Specie removes the manual "stitch" between IP-attribution tools and blockchain-tracing tools: it fuses both into a single, provenance-tracked, confidence-scored intelligence product suitable for law-enforcement sharing — self-hosted, offline, and air-gap capable.

## Install

Specie is **pure Python stdlib with zero third-party runtime dependencies**, so
installation just puts the `specie` CLI on your `PATH`. Requires **Python 3.9+**.
The one-command installers create a local `.venv` and are safe to re-run.

**Windows (PowerShell)**

```powershell
git clone https://github.com/cognis-digital/cognis-lattice
cd cognis-lattice
.\install.ps1
.\.venv\Scripts\Activate.ps1
specie --help
```

**macOS**

```bash
git clone https://github.com/cognis-digital/cognis-lattice
cd cognis-lattice
./install.sh
source .venv/bin/activate
specie --help
```

**Linux**

```bash
git clone https://github.com/cognis-digital/cognis-lattice
cd cognis-lattice
./install.sh          # or: make install
source .venv/bin/activate
specie --help
```

**Docker**

```bash
git clone https://github.com/cognis-digital/cognis-lattice
cd cognis-lattice
docker build -t specie .
docker run --rm specie --help
# mount your data and run a command:
docker run --rm -v "$PWD/data:/app/data" specie sources-stats
```

**pip (no clone)** — install straight from the repo into any environment:

```bash
pip install "git+https://github.com/cognis-digital/cognis-lattice"
specie --help
```

## Why it exists

Foreign organized-crime and terrorist financiers hide behind anonymized internet
infrastructure (Tor, VPNs, proxies) **and** obfuscated cryptocurrency flows
(multi-hop, mixers, tumblers). Today those two attribution disciplines live in
separate, expensive, vendor-locked tools, and analysts stitch them together by
hand — slowly, and often in a form too messy to hand a law-enforcement partner.

**Specie fuses them.** IP/infrastructure attribution + blockchain
analytics → one threat-actor graph, every link carrying an explicit confidence
score and its rationale, exportable as STIX 2.1.

## Highlights

- 🔗 **Blockchain analytics** — common-input wallet clustering, forward/backward
  money-flow tracing, mixer/CoinJoin detection, de-mix candidate linkage, peel-chain detection.
- 🌐 **Infrastructure attribution** — Tor/VPN/proxy enrichment, TLS-cert & domain
  fingerprint clustering, temporal signatures, behavioral co-occurrence.
- 🛑 **Sanctions screening** — OFAC-style SDN matching for crypto addresses and names.
- 🧩 **Fusion & confidence** — connected-component threat-actor resolution with a
  noisy-OR confidence model (HIGH / MODERATE / LOW + rationale).
- 📤 **STIX 2.1 export** — deterministic, reproducible bundles for partner sharing.
- 🕵️ **Illicit-finance typology analytics** *(v0.5.0)* — structuring, layering,
  pass-through, round-tripping, trade-based value transfer, shell/nominee
  clustering, sanctions-nexus, and funnel-account detectors, each with
  transparent features + a score + evidence.
- 🧠 **Network + temporal analytics** *(v0.5.0)* — fuzzy entity resolution,
  community detection, broker/centrality scoring, path-of-funds tracing, plus
  burst/dormancy/periodicity detection.
- 📁 **Risk scoring + SAR-style case files** *(v0.5.0)* — explainable entity &
  network risk, a narrative case builder (decision-support, not a
  determination), and a self-contained HTML case dashboard (no CDN deps).
- 🔒 **Self-hostable / offline** — pure Python stdlib, **zero dependencies**,
  air-gap ready. Your data never leaves your enclave.

## Live intelligence sources (48 sources · 16 chains)

Lattice integrates **56 counter-threat-finance / deanonymization sources** (54
keyless) across **16 blockchains** — OFAC/UN sanctions, abuse.ch/FireHOL/Spamhaus/
OpenPhish/PhishTank/DShield/Talos threat-intel, Tor/anonymizer infrastructure, and
multi-chain explorers with **live transaction tracing on BTC, LTC, ETH & EVM
chains, Solana, XRPL, and Tron**. Findings export to **STIX 2.1 and MISP**. Keyless
feeds pull live and cache to disk for **offline / air-gap** replay. See
[`docs/SOURCES.md`](docs/SOURCES.md).

```bash
specie sources-stats                          # coverage
specie sources-fetch ofac_sdn                 # live sanctioned wallets
specie sources-fetch feodo_ipblocklist        # live C2 IPs
specie sources-intel --cache .cache           # fuse feeds
specie sources-address --chain bitcoin --address <ADDR>   # live on-chain trace
```

## Counter-threat-finance analytics (v0.5.0)

Beyond crypto/infra attribution, Lattice now analyses generic **account-to-account
transfers** for illicit-finance typologies and builds explainable, scored,
exportable cases. All stdlib, offline, deterministic.

```bash
# Run every typology + temporal detector, top 10 findings by score
specie typologies --ledger data/sample_ledger.json \
                          --watchlist data/sample_watchlist.json --top 10

# Network analytics: components, communities, broker centrality
specie network --ledger data/sample_ledger.json

# Trace the path of funds between two entities
specie trace-funds --ledger data/sample_ledger.json --src LAYER_SRC --dst LAYER_H4

# Full SAR-style case file + self-contained HTML dashboard + STIX/CSV
specie case --ledger data/sample_ledger.json --watchlist data/sample_watchlist.json \
                    --json case.json --html case.html --stix findings.stix.json --csv findings.csv
```

Detectors: **structuring, layering, pass-through, round-tripping, trade-based
value transfer, shell/nominee clustering, sanctions-nexus, funnel-account**, plus
**burst/dormancy/periodicity**. Each emits a transparent feature set, a score,
and evidence. See [`docs/ANALYTICS.md`](docs/ANALYTICS.md),
[`docs/TYPOLOGIES.md`](docs/TYPOLOGIES.md), and [`docs/RISK.md`](docs/RISK.md).
Sanctions/watchlist data is **operator-supplied — none is bundled.**

## Quick start

```bash
git clone https://github.com/cognis-digital/specie
cd specie
python -m specie demo --stix bundle.stix.json --json product.json
python examples/run_all_demos.py    # 10 runnable analytics demos
```

Example (bundled synthetic data) produces one HIGH-confidence threat actor
fusing three wallet clusters, a Tor-fronted infrastructure cluster, and an OFAC
sanctions match, plus mixer/peel-chain analytics and a STIX 2.1 bundle.

### Library / other commands

```bash
specie cluster-chain --tx data/sample_transactions.json
specie trace --tx data/sample_transactions.json --address addr-A1 --direction forward
specie detect-mixer --tx data/sample_transactions.json
specie infra --obs data/sample_infrastructure.json
specie screen --sdn data/ofac_sample.json --tx data/sample_transactions.json
specie fuse --tx data/sample_transactions.json --obs data/sample_infrastructure.json \
                    --linkages data/sample_linkages.json --sdn data/ofac_sample.json --stix out.stix.json
```

```python
from specie import chain, netattr, sanctions, fusion, stix
g = fusion.build_graph(transactions, observations, linkages, sdn)
actors = fusion.build_threat_actors(g)
bundle = stix.bundle_from_graph(g, actors)
```

## Data schemas

See [`docs/METHODS.md`](docs/METHODS.md) for transaction, observation, linkage,
and SDN schemas, and the exact heuristics behind every score.

## Honest scope & limitations

Specie produces **investigative leads with stated confidence — not
adjudications.** It operates on transparent-ledger transaction data and lawfully
collected network observations supplied by the operator. It does **not** break
Tor cryptography and does **not** claim deterministic de-anonymization of privacy
coins (e.g. Monero). Read [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) before
acting on any output.

## Verification & proof

Every capability is measured against **planted ground truth** on deterministic
synthetic datasets, and the metrics are gated in CI. Full, reproducible results
are in [`RESULTS.md`](RESULTS.md) (regenerate with `python bench/run_all.py`).

Measured on CPython 3.14 (clean profile recovers planted structure exactly; the
noisy profile injects a cross-actor confounder to show honest degradation):

| Metric | Clean | Noisy |
|---|---|---|
| Wallet clustering (pairwise) | P/R/F1 = 1.00 | R=1.00, P=0.44 (over-merge, by design) |
| Mixer detection | F1 = 1.00 | F1 = 1.00 |
| Infrastructure clustering | F1 = 1.00 | F1 = 1.00 |
| Sanctions screening | P/R = 1.00 | P/R = 1.00 |
| Peel-chain / trace recall | 1.00 | 1.00 |
| STIX determinism | ✓ identical across runs | ✓ |

**Counter-threat-finance typologies (v0.5.0):** macro-average **entity recall =
1.00** across all 11 typology/temporal detectors against planted ground truth on
a deterministic synthetic ledger (95 transfers); fuzzy entity resolution recovers
the one intended duplicate pair with **0 false merges** (numbered cohorts kept
distinct). Full per-typology table in [`RESULTS.md`](RESULTS.md).

Throughput (single-thread, stdlib only): **~52k–91k transactions/sec** for
clustering + mixer + peel + graph build (2k→40k tx). De-mix honestly reports mean
ambiguity 4.0 and reduced confidence 0.37 on equal-value mixing.

## Testing

```bash
python -m pytest -q             # 176 tests (attribution + CTF analytics + verification)
python bench/run_all.py         # regenerate RESULTS.md (incl. typology recall + source coverage)
python examples/run_all_demos.py  # 10 runnable demos, each exits 0
```

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** —
see [LICENSE](LICENSE). Non-commercial use is free; commercial use requires a
license (`licensing@cognis.digital`). Dual-use security software — see
[NOTICE](NOTICE) for acceptable use.

<p align="center"><sub>© 2026 Cognis Digital LLC · <a href="https://cognis.digital">cognis.digital</a></sub></p>

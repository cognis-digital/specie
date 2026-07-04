# Analytics layer overview (v0.5.0)

Cognis Lattice v0.5.0 adds a full **counter-threat-finance analytics layer** on
top of the existing attribution/fusion engine. Where the original engine fuses
IP-infrastructure and multi-chain crypto tracing into a threat-actor graph, the
analytics layer works over a general **account-to-account transfer** model and
turns raw transfers into explainable, scored, exportable investigative leads.

Everything remains pure Python stdlib, offline / air-gap friendly, deterministic,
and additive — the original public API is unchanged.

## Modules

| Module | Purpose |
|---|---|
| `findings.py` | The shared `Finding` contract every detector emits (typology, entities, features, score, evidence, rationale, deterministic id) |
| `ledger.py` | Transfer model + helpers (parse timestamps, adjacency, in/out indices) |
| `typologies.py` | 8 illicit-finance typology detectors (see [`TYPOLOGIES.md`](TYPOLOGIES.md)) |
| `temporal.py` | Burst/velocity, dormancy-then-activation, periodicity |
| `network.py` | Entity resolution, connected components, community detection, centrality/broker scoring, path-of-funds |
| `risk.py` | Explainable entity + network risk scoring (see [`RISK.md`](RISK.md)) |
| `casefile.py` | SAR-style narrative case builder |
| `exports.py` | Findings → JSON / CSV / STIX 2.1 |
| `dashboard.py` | Self-contained HTML case dashboard (no CDN deps) |

## Pipeline at a glance

```
transfers ──► entity resolution ──► typology + temporal detectors ──► findings
                                                                        │
                              network analytics (components/brokers)    │
                                          │                             ▼
                                          └────────────► risk scoring (entity + network)
                                                                        │
                                                                        ▼
                                            case file  ─►  narrative / JSON / HTML / STIX / CSV
```

## CLI

```bash
cognis-lattice typologies --ledger data/sample_ledger.json --watchlist data/sample_watchlist.json --top 10
cognis-lattice network     --ledger data/sample_ledger.json
cognis-lattice resolve     --ledger data/sample_ledger.json
cognis-lattice trace-funds --ledger data/sample_ledger.json --src LAYER_SRC --dst LAYER_H4
cognis-lattice temporal    --ledger data/sample_ledger.json
cognis-lattice risk        --ledger data/sample_ledger.json --watchlist data/sample_watchlist.json
cognis-lattice case        --ledger data/sample_ledger.json --watchlist data/sample_watchlist.json \
                           --json case.json --html case.html --stix findings.stix.json --csv findings.csv
```

## Library

```python
from cognis_lattice import ledger, typologies, temporal, network, risk, casefile, exports, dashboard

transfers = ledger.load_transfers("data/sample_ledger.json")
case = casefile.build_case(transfers, watchlist=["RT_ORIGIN", "SHELL_1"])
open("case.html", "w", encoding="utf-8").write(dashboard.render_html(case))
```

## Demos

Ten runnable, exit-0 demos live in [`../examples/`](../examples). Run them all:

```bash
python examples/run_all_demos.py
```

## Sample data

`data/sample_ledger.json` and `data/sample_watchlist.json` are **synthetic** —
generated deterministically by `bench/ledgergen.py`. No real PII or sanctions
data is bundled anywhere in this repository.

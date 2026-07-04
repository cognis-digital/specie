# Illicit-finance typologies

The v0.5.0 analytics layer adds transparent detectors for well-documented,
**unclassified** money-laundering / threat-finance typologies (as described in
public FATF, FinCEN, and Egmont Group guidance). Every detector operates on the
account-to-account **transfer** model and emits `Finding` objects — a transparent
feature set, a score in `[0,1]`, evidence, and a rationale.

> These are **investigative leads, not determinations**. A "hit" means the
> pattern is *consistent with* the typology and warrants analyst review. See
> [`LIMITATIONS.md`](LIMITATIONS.md).

## Transfer schema

```json
{"id": "t1", "src": "ACCT_A", "dst": "ACCT_B", "amount": 9500.0,
 "timestamp": "2026-01-02T08:15:00Z",
 "currency": "USD", "channel": "wire",
 "counterparty_country": "US", "goods_value": 20000.0}
```

`currency`, `channel`, `counterparty_country`, and `goods_value` are optional;
detectors degrade gracefully when they are absent.

## Detectors

| Typology | What it looks for | Key features |
|---|---|---|
| `structuring` | Many sub-threshold deposits into one account that aggregate over the reporting threshold within a rolling window | `near_band_count`, `window_total`, `aggregate_ratio` |
| `layering` | A value-preserving chain of transfers hopping through intermediaries | `hops`, `path_len`, `start/end_amount` |
| `pass_through` | An account that forwards most of its inflow onward within a short holding period (a conduit) | `forward_fraction`, `median_hold_hours` |
| `round_tripping` | Value that returns to its origin via a cycle | `cycle_len`, `origin/return_amount` |
| `trade_value_anomaly` | A payment that materially over- or under-values the stated goods (TBML) | `paid`, `goods_value`, `deviation`, `direction` |
| `shell_nominee` | A tight cluster of accounts transacting almost exclusively with each other | `cluster_size`, `external_fraction` |
| `sanctions_nexus` | Proximity (in transfer hops) to an **operator-supplied** watchlist | `hops_to_watchlist` |
| `funnel_account` | Many geographically dispersed sources fan-in, then concentrate to very few destinations | `source_count`, `region_count`, `dest_count` |
| `burst_velocity` | A transfer-rate spike far above an entity's own baseline | `peak_events_in_window`, `spike_ratio` |
| `dormancy_activation` | A long-dormant account that reactivates with a burst | `dormant_days`, `post_events` |
| `periodicity` | A near-fixed, machine-like transfer cadence (automation) | `mean_interval_hours`, `interval_cv` |

## Sanctions data

No sanctions or watchlist data is bundled. `sanctions_nexus` takes a list of
identifiers the **operator** supplies (e.g. from their own OFAC ingestion). This
keeps the tool clean of third-party list redistribution and PII.

## Tuning

Every threshold is an explicit keyword argument (e.g.
`detect_structuring(transfers, threshold=10000, band_frac=0.10, min_count=3)`),
so an analyst can tune and audit the sensitivity of each detector for their
jurisdiction and data.

## Accuracy

Per-typology recall against planted ground truth (deterministic synthetic
ledger) is reported in [`../RESULTS.md`](../RESULTS.md) and gated in CI by
`tests/test_bench_ctf.py`. Regenerate with `python bench/run_all.py`.

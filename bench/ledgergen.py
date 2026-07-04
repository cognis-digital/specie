"""Deterministic synthetic ledger generator with planted typology ground truth.

Given a fixed seed, ``generate()`` builds a list of account-to-account transfers
that intentionally contain each illicit-finance typology, together with the
ground-truth set of entities that were *planted* to exhibit each pattern. This
lets ``bench/evaluate_ctf.py`` measure detector recall against known structure —
reproducibly, on any machine. All data is synthetic; no real PII.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ts(hours: float) -> str:
    return (BASE + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate(seed: int = 4242) -> dict:
    rng = random.Random(seed)
    txs = []
    ctr = {"i": 0}
    truth = {k: set() for k in (
        "structuring", "layering", "pass_through", "round_tripping",
        "trade_value_anomaly", "shell_nominee", "funnel_account",
        "burst_velocity", "dormancy_activation", "periodicity")}

    def tid():
        ctr["i"] += 1
        return f"t{ctr['i']:05d}"

    def add(src, dst, amount, hours, **extra):
        rec = {"id": tid(), "src": src, "dst": dst,
               "amount": round(float(amount), 2), "timestamp": _ts(hours)}
        rec.update(extra)
        txs.append(rec)
        return rec

    # 1. Structuring: 5 sub-$10k deposits into STRUCT_ACCT within 48h.
    for k in range(5):
        add(f"depositor_{k}", "STRUCT_ACCT", rng.uniform(9200, 9800), 2 + k * 6)
    truth["structuring"].add("STRUCT_ACCT")

    # 2. Layering: a ~5-hop value-preserving chain.
    amt = 50000.0
    prev = "LAYER_SRC"
    chain_nodes = ["LAYER_SRC"]
    for k in range(5):
        nxt = f"LAYER_H{k}"
        add(prev, nxt, amt * rng.uniform(0.95, 1.02), 100 + k * 10)
        chain_nodes.append(nxt)
        prev = nxt
    for n in chain_nodes:
        truth["layering"].add(n)

    # 3. Pass-through: receives then forwards ~90% within a few hours.
    add("pt_in_a", "PASS_ACCT", 20000, 200)
    add("pt_in_b", "PASS_ACCT", 15000, 201)
    add("PASS_ACCT", "pt_out", 31000, 204)
    truth["pass_through"].add("PASS_ACCT")

    # 4. Round-tripping: a 4-node cycle back to origin.
    add("RT_ORIGIN", "RT_A", 8000, 300)
    add("RT_A", "RT_B", 7900, 305)
    add("RT_B", "RT_C", 7850, 312)
    add("RT_C", "RT_ORIGIN", 7800, 320)
    for n in ("RT_ORIGIN", "RT_A", "RT_B", "RT_C"):
        truth["round_tripping"].add(n)

    # 5. Trade value anomaly: over-invoicing.
    add("importer_x", "exporter_y", 500000, 400,
        goods_value=120000, counterparty_country="ZZ")
    truth["trade_value_anomaly"].update({"importer_x", "exporter_y"})

    # 6. Shell/nominee cluster: 4 accounts transacting almost only internally.
    shells = ["SHELL_1", "SHELL_2", "SHELL_3", "SHELL_4"]
    for a in range(len(shells)):
        for b in range(len(shells)):
            if a != b:
                add(shells[a], shells[b], rng.uniform(1000, 3000), 500 + a * 3 + b)
    add("SHELL_1", "outside_world", 200, 560)  # tiny external footprint
    for s in shells:
        truth["shell_nominee"].add(s)

    # 7. Funnel account: 6 sources (4 regions) fan-in, 1 dest fan-out.
    regions = ["US", "GB", "DE", "SG", "US", "GB"]
    for k in range(6):
        add(f"funnel_src_{k}", "FUNNEL_ACCT", rng.uniform(2000, 6000), 600 + k,
            counterparty_country=regions[k])
    add("FUNNEL_ACCT", "funnel_dest", 24000, 620)
    truth["funnel_account"].add("FUNNEL_ACCT")

    # 8. Burst velocity: BURST_ACCT normally sparse, then 8 tx in a 6h window.
    add("bg1", "BURST_ACCT", 500, 10)
    add("BURST_ACCT", "bg2", 400, 700)
    for k in range(8):
        add("BURST_ACCT", f"burst_out_{k}", rng.uniform(300, 900), 900 + k * 0.5)
    truth["burst_velocity"].add("BURST_ACCT")

    # 9. Dormancy then activation: activity, 120-day gap, then a burst.
    add("d0", "DORMANT_ACCT", 1000, 5)
    add("DORMANT_ACCT", "d1", 900, 8)
    reactivate = 120 * 24 + 20
    for k in range(5):
        add("DORMANT_ACCT", f"react_{k}", rng.uniform(500, 1500), reactivate + k)
    truth["dormancy_activation"].add("DORMANT_ACCT")

    # 10. Periodicity: PERIODIC_ACCT sends every 24h, 8 times.
    for k in range(8):
        add("PERIODIC_ACCT", f"per_dst_{k % 2}", 1000, 1000 + k * 24)
    truth["periodicity"].add("PERIODIC_ACCT")

    # Some organic noise so detectors have negatives to reject.
    for k in range(30):
        add(f"noise_a_{k}", f"noise_b_{rng.randint(0, 20)}",
            rng.uniform(50, 40000), rng.uniform(0, 1500))

    # Near-duplicate names for entity-resolution demo.
    add("Acme Trading LLC", "clean_counterparty", 4000, 50)
    add("Acme Trading, L.L.C.", "clean_counterparty", 4200, 60)

    return {"transfers": txs, "truth": {k: sorted(v) for k, v in truth.items()}}


if __name__ == "__main__":
    import json
    import os

    data = generate()
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.normpath(os.path.join(here, "..", "data", "sample_ledger.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data["transfers"], f, indent=2)
    wl = os.path.normpath(os.path.join(here, "..", "data", "sample_watchlist.json"))
    with open(wl, "w", encoding="utf-8") as f:
        json.dump(["RT_ORIGIN", "SHELL_1"], f, indent=2)
    print(f"[+] wrote {len(data['transfers'])} transfers -> {out}")
    print(f"[+] wrote sample watchlist -> {wl}")

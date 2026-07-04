"""Illicit-finance typology detectors.

Each detector implements a well-documented, *unclassified* money-laundering /
threat-finance typology (as described in public FATF, FinCEN, and Egmont Group
guidance) over the account-to-account transfer model in ``ledger.py``. Every
detector returns ``Finding`` objects: transparent features + a score in [0,1] +
evidence. Thresholds are explicit keyword arguments so an analyst can tune and
audit them.

These are investigative leads, not determinations. A structuring "hit" means
"this pattern is consistent with structuring and warrants review", never "this
is structuring." See ``docs/TYPOLOGIES.md`` and ``docs/LIMITATIONS.md``.

Implemented typologies:
  structuring        many sub-threshold deposits that aggregate over a threshold
  layering           long directed chains that move value through intermediaries
  pass_through       accounts that receive and rapidly forward ~the same value
  round_tripping     value that returns to (near) its origin via a cycle
  trade_value_anomaly invoice/payment value mismatch (trade-based value transfer)
  shell_nominee      dense small clusters with no external economic footprint
  sanctions_nexus    proximity (hops) to an operator-supplied watchlist
  funnel_account     many-region fan-in then concentrated fan-out
"""

from __future__ import annotations

from collections import defaultdict

from .confidence import clamp
from .findings import Finding
from .ledger import (
    adjacency,
    entities,
    epoch,
    incoming,
    mean,
    outgoing,
    parse_ts,
)


# --------------------------------------------------------------------------- #
# 1. Structuring / smurfing
# --------------------------------------------------------------------------- #
def detect_structuring(transfers, threshold=10000.0, band_frac=0.10,
                       min_count=3, window_hours=72.0) -> list:
    """Structuring: repeatedly moving amounts just under a reporting threshold
    so that no single transfer triggers a report, while the aggregate does.

    Features: number of sub-threshold "near-band" transfers into an entity
    within a rolling window, and whether their sum crosses the threshold."""
    lo = threshold * (1.0 - band_frac)
    inc = incoming(transfers)
    findings = []
    for ent, txs in inc.items():
        near = [t for t in txs if lo <= float(t.get("amount", 0)) < threshold]
        if len(near) < min_count:
            continue
        near.sort(key=lambda t: epoch(t.get("timestamp")))
        # Sliding window: does any window_hours span contain >= min_count and
        # aggregate over threshold?
        best = None
        w = window_hours * 3600.0
        i = 0
        for j in range(len(near)):
            while epoch(near[j].get("timestamp")) - epoch(near[i].get("timestamp")) > w:
                i += 1
            span = near[i:j + 1]
            total = sum(float(t.get("amount", 0)) for t in span)
            if len(span) >= min_count and total >= threshold:
                if best is None or len(span) > best[0]:
                    best = (len(span), total, span)
        if not best:
            continue
        cnt, total, span = best
        ratio = total / threshold
        score = clamp(0.45 + 0.08 * (cnt - min_count) + 0.15 * min(ratio - 1.0, 2.0))
        findings.append(Finding(
            typology="structuring",
            entities=[ent],
            score=score,
            features={"near_band_count": cnt, "window_total": round(total, 2),
                      "threshold": threshold, "aggregate_ratio": round(ratio, 3),
                      "band_low": round(lo, 2)},
            evidence=[f"{cnt} deposits in [{lo:.0f},{threshold:.0f}) within "
                      f"{window_hours:.0f}h totalling {total:.0f} (> {threshold:.0f})"],
            rationale="multiple sub-threshold deposits aggregate over reporting threshold",
        ))
    return findings


# --------------------------------------------------------------------------- #
# 2. Layering chains
# --------------------------------------------------------------------------- #
def detect_layering(transfers, min_len=4, amount_tol=0.25, max_gap_hours=168.0) -> list:
    """Layering: value hops through a chain of intermediaries, each forwarding a
    similar amount within a short time, obscuring the audit trail.

    Follows greedy value-preserving forward paths and flags chains >= min_len."""
    out = outgoing(transfers)
    findings = []
    seen_starts = set()

    def next_hop(ent, amount, after_ep):
        best = None
        for t in out.get(ent, []):
            ep = epoch(t.get("timestamp"))
            if ep < after_ep or (ep - after_ep) > max_gap_hours * 3600.0:
                continue
            amt = float(t.get("amount", 0))
            if amount <= 0:
                continue
            rel = abs(amt - amount) / amount
            if rel <= amount_tol and (best is None or rel < best[1]):
                best = (t, rel)
        return best[0] if best else None

    for t0 in sorted(transfers, key=lambda t: epoch(t.get("timestamp"))):
        s = t0.get("src")
        if s is None or t0.get("id") in seen_starts:
            continue
        chain_edges = [t0]
        cur = t0.get("dst")
        amt = float(t0.get("amount", 0))
        ep = epoch(t0.get("timestamp"))
        visited = {s, cur}
        guard = 0
        while cur is not None and guard < 100:
            guard += 1
            nxt = next_hop(cur, amt, ep)
            if not nxt or nxt.get("dst") in visited:
                break
            chain_edges.append(nxt)
            cur = nxt.get("dst")
            amt = float(nxt.get("amount", 0))
            ep = epoch(nxt.get("timestamp"))
            visited.add(cur)
        if len(chain_edges) >= min_len - 0:
            path = [chain_edges[0].get("src")] + [e.get("dst") for e in chain_edges]
            if len(path) < min_len:
                continue
            for e in chain_edges:
                if e.get("id"):
                    seen_starts.add(e["id"])
            hops = len(chain_edges)
            score = clamp(0.4 + 0.08 * (hops - min_len + 1))
            findings.append(Finding(
                typology="layering",
                entities=path,
                score=score,
                features={"hops": hops, "path_len": len(path),
                          "start_amount": round(float(t0.get("amount", 0)), 2),
                          "end_amount": round(amt, 2)},
                evidence=[f"value-preserving chain of {hops} hops: "
                          + " -> ".join(str(p) for p in path)],
                rationale="funds forwarded through a chain of intermediaries preserving value",
            ))
    return findings


# --------------------------------------------------------------------------- #
# 3. Rapid movement / pass-through
# --------------------------------------------------------------------------- #
def detect_pass_through(transfers, hold_hours=48.0, forward_frac=0.80,
                        min_amount=0.0) -> list:
    """Pass-through / rapid-movement: an account receives funds and forwards a
    large fraction onward within a short holding period, acting as a conduit
    rather than a store of value."""
    inc = incoming(transfers)
    out = outgoing(transfers)
    findings = []
    for ent, ins in inc.items():
        total_in = sum(float(t.get("amount", 0)) for t in ins)
        outs = out.get(ent, [])
        total_out = sum(float(t.get("amount", 0)) for t in outs)
        if total_in < min_amount or total_in <= 0 or not outs:
            continue
        frac = total_out / total_in
        if frac < forward_frac:
            continue
        # Median holding time between an inflow and the next outflow.
        in_eps = sorted(epoch(t.get("timestamp")) for t in ins)
        out_eps = sorted(epoch(t.get("timestamp")) for t in outs)
        holds = []
        j = 0
        for ie in in_eps:
            while j < len(out_eps) and out_eps[j] < ie:
                j += 1
            if j < len(out_eps):
                holds.append((out_eps[j] - ie) / 3600.0)
        med_hold = sorted(holds)[len(holds) // 2] if holds else None
        if med_hold is None or med_hold > hold_hours:
            continue
        score = clamp(0.4 + 0.3 * min(frac, 1.0) + 0.2 * (1 - med_hold / hold_hours))
        findings.append(Finding(
            typology="pass_through",
            entities=[ent],
            score=score,
            features={"total_in": round(total_in, 2), "total_out": round(total_out, 2),
                      "forward_fraction": round(frac, 3),
                      "median_hold_hours": round(med_hold, 2)},
            evidence=[f"forwarded {frac*100:.0f}% of inflow within a median "
                      f"{med_hold:.1f}h hold"],
            rationale="account forwards most of its inflow quickly (conduit behaviour)",
        ))
    return findings


# --------------------------------------------------------------------------- #
# 4. Round-tripping (cycles back to origin)
# --------------------------------------------------------------------------- #
def detect_round_tripping(transfers, max_len=6, amount_tol=0.35) -> list:
    """Round-tripping: value leaves an entity and returns to it (or a tightly
    linked account) via a cycle, often to fabricate economic activity."""
    adj = defaultdict(list)
    for t in transfers:
        s, d = t.get("src"), t.get("dst")
        if s is not None and d is not None and s != d:
            adj[s].append((d, float(t.get("amount", 0)), t))
    findings = []
    seen_cycles = set()

    for origin in list(adj.keys()):
        # DFS for a simple cycle back to origin, value roughly preserved.
        stack = [(origin, [origin], [], None)]
        while stack:
            node, path, edges, amt0 = stack.pop()
            for (nxt, amt, t) in adj.get(node, []):
                if nxt == origin and len(path) >= 3:
                    ok = True
                    if amt0 and amt0 > 0:
                        ok = abs(amt - amt0) / amt0 <= amount_tol
                    if not ok:
                        continue
                    cyc = tuple(path)
                    key = frozenset(cyc)
                    if key in seen_cycles:
                        continue
                    seen_cycles.add(key)
                    score = clamp(0.55 + 0.1 * (max_len - len(path)))
                    findings.append(Finding(
                        typology="round_tripping",
                        entities=list(path),
                        score=score,
                        features={"cycle_len": len(path),
                                  "origin_amount": round(amt0 or amt, 2),
                                  "return_amount": round(amt, 2)},
                        evidence=[f"funds return to {origin} via cycle "
                                  + " -> ".join(str(p) for p in path) + f" -> {origin}"],
                        rationale="value cycles back to its origin (fabricated flow)",
                    ))
                elif nxt not in path and len(path) < max_len:
                    stack.append((nxt, path + [nxt], edges + [t],
                                  amt0 if amt0 is not None else amt))
    return findings


# --------------------------------------------------------------------------- #
# 5. Trade-based value transfer anomaly
# --------------------------------------------------------------------------- #
def detect_trade_value_anomaly(transfers, min_deviation=0.30) -> list:
    """Trade-based value transfer: a payment materially over- or under-values the
    stated goods (over/under-invoicing) to move value across a border under cover
    of legitimate trade. Requires transfers to carry a ``goods_value`` field."""
    findings = []
    for t in transfers:
        gv = t.get("goods_value")
        amt = t.get("amount")
        if gv is None or amt is None:
            continue
        gv = float(gv)
        amt = float(amt)
        if gv <= 0:
            continue
        dev = (amt - gv) / gv
        if abs(dev) < min_deviation:
            continue
        direction = "over-invoicing" if dev > 0 else "under-invoicing"
        score = clamp(0.4 + 0.4 * min(abs(dev), 1.5) / 1.5)
        findings.append(Finding(
            typology="trade_value_anomaly",
            entities=[t.get("src"), t.get("dst")],
            score=score,
            features={"paid": round(amt, 2), "goods_value": round(gv, 2),
                      "deviation": round(dev, 3), "direction": direction,
                      "counterparty_country": t.get("counterparty_country")},
            evidence=[f"payment {amt:.0f} vs goods value {gv:.0f} "
                      f"({dev*100:+.0f}% {direction})"],
            rationale="trade payment materially mismatches stated goods value",
        ))
    return findings


# --------------------------------------------------------------------------- #
# 6. Shell / nominee clustering
# --------------------------------------------------------------------------- #
def detect_shell_nominee(transfers, min_cluster=3, max_external_frac=0.15) -> list:
    """Shell/nominee clustering: a tight group of accounts that transact almost
    exclusively with each other (little external economic footprint) — a hallmark
    of nominee networks and shell layering."""
    from .network import connected_components  # local import avoids cycle

    comps = connected_components(transfers)
    ents = entities(transfers)
    findings = []
    for comp in comps:
        if len(comp) < min_cluster:
            continue
        internal = 0.0
        external = 0.0
        cset = set(comp)
        for t in transfers:
            s, d = t.get("src"), t.get("dst")
            amt = float(t.get("amount", 0))
            if s in cset and d in cset:
                internal += amt
            elif s in cset or d in cset:
                external += amt
        total = internal + external
        if total <= 0:
            continue
        ext_frac = external / total
        if ext_frac > max_external_frac:
            continue
        score = clamp(0.4 + 0.3 * (1 - ext_frac) + 0.05 * (len(comp) - min_cluster))
        findings.append(Finding(
            typology="shell_nominee",
            entities=sorted(comp),
            score=score,
            features={"cluster_size": len(comp), "internal_value": round(internal, 2),
                      "external_value": round(external, 2),
                      "external_fraction": round(ext_frac, 3)},
            evidence=[f"{len(comp)}-account cluster with only {ext_frac*100:.0f}% "
                      "external value flow"],
            rationale="tightly interconnected cluster with minimal external footprint",
        ))
    return findings


# --------------------------------------------------------------------------- #
# 7. Sanctions-nexus proximity (operator-supplied watchlist)
# --------------------------------------------------------------------------- #
def detect_sanctions_nexus(transfers, watchlist, max_hops=2) -> list:
    """Sanctions-nexus proximity: how close (in transfer hops) each entity sits
    to an *operator-supplied* watchlist. No sanctions data is bundled — the
    caller passes the list of flagged identifiers. Closer proximity -> higher
    score."""
    watch = set(watchlist or [])
    if not watch:
        return []
    adj = defaultdict(set)
    for t in transfers:
        s, d = t.get("src"), t.get("dst")
        if s is not None and d is not None:
            adj[s].add(d)
            adj[d].add(s)
    findings = []
    # BFS distance from the watchlist set.
    dist = {w: 0 for w in watch if w in adj or w in entities(transfers)}
    frontier = list(dist)
    while frontier:
        nxt = []
        for node in frontier:
            for nb in adj.get(node, ()):
                if nb not in dist:
                    dist[nb] = dist[node] + 1
                    nxt.append(nb)
        frontier = nxt
    for ent, hops in dist.items():
        if ent in watch:
            continue
        if hops > max_hops:
            continue
        score = clamp(0.9 - 0.25 * (hops - 1))
        findings.append(Finding(
            typology="sanctions_nexus",
            entities=[ent],
            score=score,
            features={"hops_to_watchlist": hops, "max_hops": max_hops},
            evidence=[f"{hops} transfer hop(s) from an operator-supplied "
                      "watchlisted entity"],
            rationale="entity transacts within a few hops of a watchlisted identifier",
        ))
    return findings


# --------------------------------------------------------------------------- #
# 8. Funnel account (multi-region fan-in -> concentrated fan-out)
# --------------------------------------------------------------------------- #
def detect_funnel_account(transfers, min_sources=5, min_regions=3,
                          max_dests=2) -> list:
    """Funnel account: an account collects deposits from many geographically
    dispersed sources and forwards them through very few destinations — the
    classic funnel-account money-mule pattern."""
    inc = incoming(transfers)
    out = outgoing(transfers)
    findings = []
    for ent, ins in inc.items():
        srcs = {t.get("src") for t in ins if t.get("src") is not None}
        regions = {t.get("counterparty_country") for t in ins
                   if t.get("counterparty_country")}
        dests = {t.get("dst") for t in out.get(ent, []) if t.get("dst") is not None}
        if len(srcs) < min_sources or len(dests) > max_dests or not dests:
            continue
        # Region diversity is a supporting signal; not required if absent.
        region_ok = (len(regions) >= min_regions) if regions else True
        if not region_ok:
            continue
        total_in = sum(float(t.get("amount", 0)) for t in ins)
        score = clamp(0.45 + 0.04 * (len(srcs) - min_sources)
                      + 0.05 * max(len(regions), 0) + 0.1 * (max_dests + 1 - len(dests)))
        findings.append(Finding(
            typology="funnel_account",
            entities=[ent],
            score=score,
            features={"source_count": len(srcs), "region_count": len(regions),
                      "dest_count": len(dests), "total_in": round(total_in, 2)},
            evidence=[f"{len(srcs)} sources ({len(regions)} regions) funnel into "
                      f"{ent}, forwarded via {len(dests)} destination(s)"],
            rationale="many dispersed sources fan-in then concentrate to few destinations",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Registry + run-all
# --------------------------------------------------------------------------- #
DETECTORS = {
    "structuring": detect_structuring,
    "layering": detect_layering,
    "pass_through": detect_pass_through,
    "round_tripping": detect_round_tripping,
    "trade_value_anomaly": detect_trade_value_anomaly,
    "shell_nominee": detect_shell_nominee,
    "funnel_account": detect_funnel_account,
}


def run_all(transfers, watchlist=None, enabled=None) -> list:
    """Run every applicable typology detector and return a flat list of
    Findings. ``watchlist`` enables the sanctions-nexus detector; ``enabled``
    optionally restricts which typologies run."""
    findings = []
    for name, fn in DETECTORS.items():
        if enabled and name not in enabled:
            continue
        findings.extend(fn(transfers))
    if watchlist and (not enabled or "sanctions_nexus" in enabled):
        findings.extend(detect_sanctions_nexus(transfers, watchlist))
    return findings

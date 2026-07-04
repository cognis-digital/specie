"""Network analytics over the ledger transfer graph.

Pure-stdlib graph analytics used to turn a flat list of transfers into an
actionable network picture:

  entity resolution   fuzzy-match + merge identifiers that likely denote the
                      same real-world entity (name/alias normalisation)
  connected_components weakly-connected components of the transfer graph
  community_detection label-propagation communities (network segmentation)
  centrality           degree + betweenness + a broker score (who bridges the
                      network — high-value investigative targets)
  path_of_funds        shortest / value-weighted path(s) between two entities

All algorithms are deterministic (sorted iteration, fixed tie-breaks) so repeated
runs on the same input yield identical output — important for evidentiary use.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque

from .confidence import clamp
from .ledger import adjacency, entities


# --------------------------------------------------------------------------- #
# Entity resolution
# --------------------------------------------------------------------------- #
_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^a-z0-9 ]+")
_CORP = re.compile(r"\b(inc|incorporated|ltd|limited|llc|llp|corp|corporation|"
                   r"co|company|gmbh|sa|ag|plc|pte|bv|nv)\b")


def normalize_name(name: str) -> str:
    """Aggressively normalise an entity name for fuzzy comparison: lowercase,
    strip punctuation, drop common corporate suffixes, collapse whitespace."""
    s = (name or "").lower()
    s = _PUNCT.sub(" ", s)
    s = _CORP.sub(" ", s)
    s = _WS.sub(" ", s).strip()
    return s


def _bigrams(s: str) -> set:
    s = s.replace(" ", "")
    return {s[i:i + 2] for i in range(len(s) - 1)} if len(s) >= 2 else {s}


def _strip_digits(s: str) -> str:
    return "".join(c for c in s if not c.isdigit())


def similarity(a: str, b: str) -> float:
    """Dice coefficient over character bigrams of the normalised names, in
    [0,1]. Cheap, deterministic, dependency-free fuzzy match.

    Guard against merging *sequence-numbered* identifiers (``acct_1`` vs
    ``acct_2``): if two names are identical once digits are removed but their
    digit strings differ, they are almost certainly distinct enumerated
    entities, so we return 0. This avoids collapsing whole numbered cohorts."""
    na, nb = normalize_name(a), normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    da = "".join(c for c in na if c.isdigit())
    db = "".join(c for c in nb if c.isdigit())
    if da != db and _strip_digits(na) == _strip_digits(nb):
        return 0.0
    ba, bb = _bigrams(na), _bigrams(nb)
    inter = len(ba & bb)
    denom = len(ba) + len(bb)
    return round(2.0 * inter / denom, 4) if denom else 0.0


def resolve_entities(names, threshold=0.82) -> dict:
    """Cluster near-duplicate entity names. Returns a mapping
    ``{name: canonical_name}`` where canonical is the lexicographically-smallest
    member of each fuzzy cluster (deterministic)."""
    names = sorted(set(n for n in names if n))
    parent = {n: n for n in names}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            lo, hi = sorted((ra, rb))
            parent[hi] = lo

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if similarity(names[i], names[j]) >= threshold:
                union(names[i], names[j])
    return {n: find(n) for n in names}


def apply_resolution(transfers, mapping) -> list:
    """Return a new transfer list with src/dst rewritten to canonical entities."""
    out = []
    for t in transfers:
        t2 = dict(t)
        if t2.get("src") in mapping:
            t2["src"] = mapping[t2["src"]]
        if t2.get("dst") in mapping:
            t2["dst"] = mapping[t2["dst"]]
        out.append(t2)
    return out


# --------------------------------------------------------------------------- #
# Graph structure
# --------------------------------------------------------------------------- #
def _undirected_adj(transfers) -> dict:
    adj = defaultdict(set)
    for t in transfers:
        s, d = t.get("src"), t.get("dst")
        if s is not None and d is not None and s != d:
            adj[s].add(d)
            adj[d].add(s)
        elif s is not None:
            adj[s]  # ensure isolated nodes appear
        if d is not None:
            adj[d]
    return adj


def connected_components(transfers) -> list:
    """Weakly-connected components as sorted lists of entities (deterministic)."""
    adj = _undirected_adj(transfers)
    for e in entities(transfers):
        adj[e]
    seen = set()
    comps = []
    for start in sorted(adj):
        if start in seen:
            continue
        comp = []
        dq = deque([start])
        seen.add(start)
        while dq:
            n = dq.popleft()
            comp.append(n)
            for nb in sorted(adj[n]):
                if nb not in seen:
                    seen.add(nb)
                    dq.append(nb)
        comps.append(sorted(comp))
    return comps


def community_detection(transfers, max_iter=100) -> dict:
    """Deterministic synchronous label propagation. Returns
    ``{entity: community_label}`` where the label is the smallest entity id in
    the community (stable across runs)."""
    adj = _undirected_adj(transfers)
    for e in entities(transfers):
        adj[e]
    labels = {n: n for n in adj}
    nodes = sorted(adj)
    for _ in range(max_iter):
        changed = False
        # Asynchronous update (in place): converges on symmetric/bipartite
        # structures that oscillate under synchronous update. Deterministic
        # because nodes are visited in sorted order and ties break to the
        # smallest label.
        for n in nodes:
            if not adj[n]:
                continue
            counts = defaultdict(int)
            counts[labels[n]] += 0  # ensure own label is considered
            for nb in adj[n]:
                counts[labels[nb]] += 1
            best = min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
            if best != labels[n]:
                labels[n] = best
                changed = True
        if not changed:
            break
    return labels


# --------------------------------------------------------------------------- #
# Centrality + broker scoring
# --------------------------------------------------------------------------- #
def _brandes_betweenness(adj) -> dict:
    """Brandes' algorithm for unweighted betweenness centrality (stdlib)."""
    nodes = sorted(adj)
    cb = {v: 0.0 for v in nodes}
    for s in nodes:
        stack = []
        pred = {w: [] for w in nodes}
        sigma = {w: 0.0 for w in nodes}
        dist = {w: -1 for w in nodes}
        sigma[s] = 1.0
        dist[s] = 0
        dq = deque([s])
        while dq:
            v = dq.popleft()
            stack.append(v)
            for w in sorted(adj[v]):
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    dq.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        delta = {w: 0.0 for w in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                cb[w] += delta[w]
    n = len(nodes)
    norm = ((n - 1) * (n - 2)) if n > 2 else 1
    return {v: round(cb[v] / norm, 6) for v in nodes}


def centrality(transfers) -> dict:
    """Per-entity degree, in/out degree, betweenness, and a composite *broker
    score* (0..1). A broker sits between communities and moves value through —
    a priority investigative target."""
    adj = _undirected_adj(transfers)
    for e in entities(transfers):
        adj[e]
    indeg = defaultdict(int)
    outdeg = defaultdict(int)
    vol = defaultdict(float)
    for t in transfers:
        s, d = t.get("src"), t.get("dst")
        amt = float(t.get("amount", 0))
        if s is not None:
            outdeg[s] += 1
            vol[s] += amt
        if d is not None:
            indeg[d] += 1
            vol[d] += amt
    bet = _brandes_betweenness(adj)
    max_bet = max(bet.values()) if bet else 0.0
    max_deg = max((len(adj[n]) for n in adj), default=0)
    result = {}
    for n in sorted(adj):
        deg = len(adj[n])
        norm_bet = (bet[n] / max_bet) if max_bet else 0.0
        norm_deg = (deg / max_deg) if max_deg else 0.0
        # Broker: high betweenness AND balanced in/out (a conduit).
        bal = 0.0
        io = indeg[n] + outdeg[n]
        if io:
            bal = 1.0 - abs(indeg[n] - outdeg[n]) / io
        broker = round(clamp(0.6 * norm_bet + 0.25 * norm_deg + 0.15 * bal), 4)
        result[n] = {
            "degree": deg, "in_degree": indeg[n], "out_degree": outdeg[n],
            "volume": round(vol[n], 2), "betweenness": bet[n],
            "broker_score": broker,
        }
    return result


def top_brokers(transfers, k=10) -> list:
    c = centrality(transfers)
    rows = [{"entity": e, **v} for e, v in c.items()]
    rows.sort(key=lambda r: (-r["broker_score"], -r["betweenness"], r["entity"]))
    return rows[:k]


# --------------------------------------------------------------------------- #
# Path of funds
# --------------------------------------------------------------------------- #
def path_of_funds(transfers, src, dst, max_paths=3, max_len=8) -> list:
    """Trace directed money-flow paths from ``src`` to ``dst``. Returns up to
    ``max_paths`` paths, shortest first, each with the transfer ids and the
    minimum amount along the path (the bottleneck value that could have
    traversed the whole route)."""
    adj = defaultdict(list)
    for t in transfers:
        s, d = t.get("src"), t.get("dst")
        if s is not None and d is not None:
            adj[s].append((d, t))
    results = []
    # BFS enumerating simple paths, shortest first.
    dq = deque([(src, [src], [])])
    while dq and len(results) < max_paths:
        node, path, edges = dq.popleft()
        if len(path) > max_len:
            continue
        for (nxt, t) in sorted(adj.get(node, []), key=lambda x: str(x[0])):
            if nxt in path:
                continue
            npath = path + [nxt]
            nedges = edges + [t]
            if nxt == dst:
                amts = [float(e.get("amount", 0)) for e in nedges]
                results.append({
                    "path": npath,
                    "hops": len(nedges),
                    "transfer_ids": [e.get("id") for e in nedges],
                    "bottleneck_amount": round(min(amts), 2) if amts else 0.0,
                    "total_moved": round(sum(amts), 2),
                })
                if len(results) >= max_paths:
                    break
            else:
                dq.append((nxt, npath, nedges))
    return results

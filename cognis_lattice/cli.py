"""Cognis Lattice command-line interface.

Every Cognis tool ships a CLI, structured output, and a library API. Run
`cognis-lattice demo` for an end-to-end walkthrough on bundled sample data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import chain as chainmod
from . import fusion as fusionmod
from . import netattr as netmod
from . import misp as mispmod
from . import report as reportmod
from . import sanctions as sancmod
from . import stix as stixmod
from .sources import feeds as sfeeds
from .sources import registry as sreg
from .sources.client import HttpClient

_HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(_HERE, "..", "data"))


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _data(name):
    return os.path.join(DATA_DIR, name)


def _emit(obj):
    print(json.dumps(obj, indent=2))


def cmd_demo(args):
    txs = _load(_data("sample_transactions.json"))
    obs = netmod.enrich(_load(_data("sample_infrastructure.json")))
    sdn = _load(_data("ofac_sample.json"))
    lnk = _load(_data("sample_linkages.json"))
    g = fusionmod.build_graph(txs, obs, lnk, sdn)
    tas = fusionmod.build_threat_actors(g)
    extras = {
        "mixers": chainmod.detect_mixer(txs),
        "peel_chains": chainmod.detect_peel_chain(txs),
        "demix_candidates": chainmod.demix_candidates(txs),
    }
    print(reportmod.render_text(g, tas, extras))
    if args.stix:
        with open(args.stix, "w", encoding="utf-8") as f:
            f.write(stixmod.to_json(stixmod.bundle_from_graph(g, tas)))
        print(f"\n[+] STIX 2.1 bundle -> {args.stix}")
    if args.misp:
        with open(args.misp, "w", encoding="utf-8") as f:
            f.write(mispmod.to_json(mispmod.event_from_graph(g, tas)))
        print(f"[+] MISP event -> {args.misp}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(reportmod.render_json(g, tas, extras))
        print(f"[+] JSON product -> {args.json}")
    return 0


def cmd_cluster_chain(args):
    txs = _load(args.tx)
    clusters, _ = chainmod.common_input_clustering(txs)
    _emit([sorted(s) for s in clusters])
    return 0


def cmd_trace(args):
    txs = _load(args.tx)
    _emit(chainmod.trace(txs, args.address, args.direction, args.max_hops))
    return 0


def cmd_detect_mixer(args):
    txs = _load(args.tx)
    _emit({"mixers": chainmod.detect_mixer(txs),
           "demix_candidates": chainmod.demix_candidates(txs),
           "peel_chains": chainmod.detect_peel_chain(txs)})
    return 0


def cmd_infra(args):
    obs = netmod.enrich(_load(args.obs))
    _emit({"clusters": netmod.fingerprint_clusters(obs),
           "behavioral_edges": netmod.behavioral_correlate(obs)})
    return 0


def cmd_screen(args):
    sdn = _load(args.sdn)
    addrs = args.addresses.split(",") if args.addresses else []
    if args.tx:
        txs = _load(args.tx)
        for tx in txs:
            for side in ("inputs", "outputs"):
                addrs.extend(i["address"] for i in tx.get(side, []))
    _emit({"address_hits": sancmod.screen_addresses(sorted(set(addrs)), sdn)})
    return 0


def cmd_fuse(args):
    txs = _load(args.tx) if args.tx else []
    obs = netmod.enrich(_load(args.obs)) if args.obs else []
    lnk = _load(args.linkages) if args.linkages else []
    sdn = _load(args.sdn) if args.sdn else []
    g = fusionmod.build_graph(txs, obs, lnk, sdn)
    tas = fusionmod.build_threat_actors(g)
    if args.stix:
        with open(args.stix, "w", encoding="utf-8") as f:
            f.write(stixmod.to_json(stixmod.bundle_from_graph(g, tas)))
    if args.misp:
        with open(args.misp, "w", encoding="utf-8") as f:
            f.write(mispmod.to_json(mispmod.event_from_graph(g, tas)))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(reportmod.render_json(g, tas))
        print(f"[+] JSON product -> {args.out}")
    else:
        print(reportmod.render_text(g, tas))
    return 0


def cmd_sources_list(args):
    rows = sreg.list_sources(category=args.category, chain=args.chain,
                             keyless=(True if args.keyless else None),
                             integrated=(True if args.integrated else None))
    for s in rows:
        flag = "keyless" if s["keyless"] else "key-req"
        norm = "norm" if s["integrated"] else "raw "
        print(f"{s['name']:30} {s['category']:20} {flag:8} {norm}  {','.join(s['chains'])}")
    print(f"\n{len(rows)} sources")
    return 0


def cmd_sources_stats(args):
    _emit(sreg.stats())
    return 0


def cmd_sources_fetch(args):
    client = HttpClient(cache_dir=args.cache, offline=args.offline)
    res = sreg.fetch(args.name, client, address=args.address)
    if isinstance(res, list):
        rows = [r.to_dict() if hasattr(r, "to_dict") else r for r in res]
        print(json.dumps(rows[:args.limit], indent=2))
        print(f"\n{len(res)} records ({args.name})")
    else:
        print(res.get("note", str(res)))
    return 0


def cmd_sources_intel(args):
    client = HttpClient(cache_dir=args.cache, offline=args.offline)
    intel = sfeeds.build_intel(client, on_error="skip")
    _emit(sfeeds.summary(intel))
    if intel["errors"]:
        print("source errors:", json.dumps(intel["errors"], indent=2))
    return 0


def cmd_sources_address(args):
    client = HttpClient(cache_dir=args.cache, offline=args.offline)
    onchain = ("esplora", "blockscout_txlist", "solana_rpc",
               "xrpl_account_tx", "tron_account_tx", "blockchain_info")
    cands = [s for s in sreg.list_sources(chain=args.chain) if s["parser"] in onchain]
    if not cands:
        chains = sorted({c for s in sreg.list_sources() if s["parser"] in onchain for c in s["chains"]})
        print(f"no address-tracing explorer for chain '{args.chain}' (try: {', '.join(chains)})")
        return 1
    src = cands[0]
    if src["parser"] == "solana_rpc":
        txs = sreg.fetch_solana_txs(client, args.address, src["name"])
        print(f"[{src['name']}] {len(txs)} transactions (full) for {args.address}")
        res = txs
    else:
        res = sreg.fetch_onchain(src["name"], client, address=args.address)
        print(f"[{src['name']}] {len(res)} transactions for {args.address}")
    if res:
        clusters, _ = chainmod.common_input_clustering(res)
        print(f"wallet clusters (common-input heuristic): {len(clusters)}")
        print(json.dumps(res[:2], indent=2))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="cognis-lattice",
        description="Cognis Lattice — Counter-Threat-Finance Attribution & Fusion Platform",
    )
    p.add_argument("--version", action="version", version=f"cognis-lattice {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("demo", help="run end-to-end demo on bundled sample data")
    d.add_argument("--stix", help="write STIX 2.1 bundle to this path")
    d.add_argument("--misp", help="write MISP event to this path")
    d.add_argument("--json", help="write JSON intelligence product to this path")
    d.set_defaults(func=cmd_demo)

    c = sub.add_parser("cluster-chain", help="common-input wallet clustering")
    c.add_argument("--tx", required=True)
    c.set_defaults(func=cmd_cluster_chain)

    t = sub.add_parser("trace", help="trace money flow from a seed address")
    t.add_argument("--tx", required=True)
    t.add_argument("--address", required=True)
    t.add_argument("--direction", choices=["forward", "backward"], default="forward")
    t.add_argument("--max-hops", type=int, default=4)
    t.set_defaults(func=cmd_trace)

    m = sub.add_parser("detect-mixer", help="mixer/peel-chain/de-mix analysis")
    m.add_argument("--tx", required=True)
    m.set_defaults(func=cmd_detect_mixer)

    i = sub.add_parser("infra", help="infrastructure clustering + correlation")
    i.add_argument("--obs", required=True)
    i.set_defaults(func=cmd_infra)

    s = sub.add_parser("screen", help="OFAC-style sanctions screening")
    s.add_argument("--sdn", required=True)
    s.add_argument("--tx")
    s.add_argument("--addresses", help="comma-separated addresses")
    s.set_defaults(func=cmd_screen)

    f = sub.add_parser("fuse", help="fuse all sources into threat-actor profiles")
    f.add_argument("--tx")
    f.add_argument("--obs")
    f.add_argument("--linkages")
    f.add_argument("--sdn")
    f.add_argument("--out", help="write JSON product to this path")
    f.add_argument("--stix", help="write STIX 2.1 bundle to this path")
    f.add_argument("--misp", help="write MISP event to this path")
    f.set_defaults(func=cmd_fuse)

    sl = sub.add_parser("sources-list", help="list integrated intelligence sources")
    sl.add_argument("--category")
    sl.add_argument("--chain")
    sl.add_argument("--keyless", action="store_true")
    sl.add_argument("--integrated", action="store_true")
    sl.set_defaults(func=cmd_sources_list)

    ss = sub.add_parser("sources-stats", help="source coverage statistics")
    ss.set_defaults(func=cmd_sources_stats)

    sf = sub.add_parser("sources-fetch", help="fetch + parse one source")
    sf.add_argument("name")
    sf.add_argument("--offline", action="store_true")
    sf.add_argument("--cache", default=".cache")
    sf.add_argument("--address", help="for address-based explorers")
    sf.add_argument("--limit", type=int, default=20)
    sf.set_defaults(func=cmd_sources_fetch)

    si = sub.add_parser("sources-intel", help="build fused intel bundle from feeds")
    si.add_argument("--offline", action="store_true")
    si.add_argument("--cache", default=".cache")
    si.set_defaults(func=cmd_sources_intel)

    sa = sub.add_parser("sources-address", help="live on-chain address trace (esplora chains)")
    sa.add_argument("--chain", required=True)
    sa.add_argument("--address", required=True)
    sa.add_argument("--offline", action="store_true")
    sa.add_argument("--cache", default=".cache")
    sa.set_defaults(func=cmd_sources_address)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

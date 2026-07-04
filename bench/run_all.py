"""Run the full accuracy + performance suite and write reproducible artifacts:
bench/results.json (machine-readable) and RESULTS.md (human-readable proof)."""

from __future__ import annotations

import json
import os
import platform
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench import benchmark, datagen, evaluate, evaluate_ctf  # noqa: E402
from cognis_lattice.sources import registry as sreg  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _fmt_prf(m):
    return f"P={m['precision']:.3f} / R={m['recall']:.3f} / F1={m['f1']:.3f}"


def build_results():
    clean = evaluate.evaluate(datagen.generate(profile="clean"))
    noisy = evaluate.evaluate(datagen.generate(profile="noisy"))
    perf = benchmark.benchmark()
    env = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
    }
    ctf = evaluate_ctf.evaluate()
    return {"accuracy": {"clean": clean, "noisy": noisy}, "performance": perf,
            "ctf_analytics": ctf, "sources": sreg.stats(), "environment": env}


def render_md(res) -> str:
    clean, noisy = res["accuracy"]["clean"], res["accuracy"]["noisy"]
    env = res["environment"]
    L = []
    L.append("# Cognis Lattice — Verification Results\n")
    L.append("Reproduce with: `python bench/run_all.py` (regenerates this file).\n")
    L.append(f"Environment: {env['implementation']} {env['python']} on "
             f"{env['system']}/{env['machine']}. Inputs are deterministic (fixed seed).\n")

    L.append("## Accuracy vs. planted ground truth\n")
    L.append("Metrics computed against known synthetic structure. The **clean** profile "
             "measures algorithmic correctness; the **noisy** profile injects a shared-service "
             "confounder that co-spends across actors, so clustering precision is *expected* to "
             "drop — an honest degradation measurement.\n")
    L.append("| Metric | Clean | Noisy |")
    L.append("|---|---|---|")
    L.append(f"| Wallet clustering (pairwise) | {_fmt_prf(clean['wallet_clustering'])} | {_fmt_prf(noisy['wallet_clustering'])} |")
    L.append(f"| Mixer detection | {_fmt_prf(clean['mixer_detection'])} | {_fmt_prf(noisy['mixer_detection'])} |")
    L.append(f"| Infrastructure clustering (pairwise) | {_fmt_prf(clean['infra_clustering'])} | {_fmt_prf(noisy['infra_clustering'])} |")
    L.append(f"| Sanctions screening | {_fmt_prf(clean['sanctions'])} | {_fmt_prf(noisy['sanctions'])} |")
    L.append(f"| Peel-chain recall | {clean['peel_chain_recall']:.3f} | {noisy['peel_chain_recall']:.3f} |")
    L.append(f"| Trace reachability recall | {clean['trace_recall']:.3f} | {noisy['trace_recall']:.3f} |")
    L.append(f"| STIX determinism (2 runs identical) | {clean['determinism']} | {noisy['determinism']} |")
    L.append("")
    d = clean["demix"]
    L.append("### De-mix (equal-value mixing is intentionally ambiguous)\n")
    L.append(f"- Input coverage: **{d['input_coverage']:.3f}** (fraction of mixer inputs given ≥1 candidate)")
    L.append(f"- Mean ambiguity: **{d['mean_ambiguity']}** candidate outputs per input")
    L.append(f"- Mean candidate confidence: **{d['mean_confidence']:.3f}** (scaled down by ambiguity, by design)\n")

    L.append("## Performance (single-thread, stdlib only)\n")
    L.append("| Transactions | Cluster (s) | Mixer (s) | Peel (s) | Build graph (s) | Total (s) | Tx/s |")
    L.append("|---:|---:|---:|---:|---:|---:|---:|")
    for r in res["performance"]:
        L.append(f"| {r['transactions']:,} | {r['cluster_s']} | {r['detect_mixer_s']} | "
                 f"{r['detect_peel_s']} | {r['build_graph_s']} | {r['total_s']} | {r['tx_per_s']:,} |")
    L.append("")
    ctf = res.get("ctf_analytics")
    if ctf:
        L.append("## Counter-threat-finance typology analytics (v0.5.0)\n")
        L.append("Per-typology **entity recall** against planted ground truth on a "
                 f"deterministic synthetic ledger ({ctf['dataset']['transfers']} transfers, "
                 f"{ctf['dataset']['typologies_planted']} planted typologies). Recall = did we "
                 "recover the entity planted to exhibit each pattern.\n")
        L.append("| Typology | Planted | Recovered | Recall |")
        L.append("|---|---:|---:|---:|")
        for typ, m in ctf["per_typology_recall"].items():
            L.append(f"| {typ} | {m['planted']} | {m['recovered']} | {m['recall']:.3f} |")
        L.append(f"| **macro-average** | | | **{ctf['macro_recall']:.3f}** |")
        L.append("")
        er = ctf["entity_resolution"]
        L.append(f"Entity resolution: intended duplicate pair recovered = "
                 f"**{er['true_merge_recovered']}**, false-merge groups = "
                 f"**{er['false_merge_groups']}** (numbered cohorts kept distinct). "
                 f"Total findings raised: {ctf['total_findings']}.\n")

    s = res["sources"]
    L.append("## Intelligence source coverage\n")
    L.append(f"- **{s['total']} integrated sources** ({s['keyless']} keyless, "
             f"{s['integrated']} with normalized parsers)")
    L.append(f"- **{s['chain_count']} blockchains** covered: {', '.join(s['chains'])}")
    L.append("- By category: " + ", ".join(f"{k}={v}" for k, v in s["by_category"].items()))
    L.append("")
    L.append("All numbers above are produced by `bench/run_all.py` and gated in CI by "
             "`tests/test_bench.py` / `tests/test_sources.py`. See `docs/LIMITATIONS.md`.\n")
    return "\n".join(L)


def main():
    res = build_results()
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    with open(os.path.join(ROOT, "RESULTS.md"), "w", encoding="utf-8") as f:
        f.write(render_md(res))
    print("[+] wrote bench/results.json and RESULTS.md")
    print(render_md(res))


if __name__ == "__main__":
    main()

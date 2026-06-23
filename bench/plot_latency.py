#!/usr/bin/env python3
"""Plot PreToolUse hook latency from the bench harness CSVs.

Inputs (in --dir, default bench/results):
  bench-e2e.csv        config,class,latency_ns   (from `gensee bench --mode e2e`)
  bench-breakdown.csv  class,phase,mean_ns        (from `gensee bench --mode breakdown`)

Outputs:
  latency-cdf.png        e2e CDF, with vs without gensee-crate
  latency-breakdown.png  per-phase breakdown for a few typical request types
"""
import argparse, csv, os
from collections import defaultdict
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PHASES = ["parse", "intents", "evaluate", "serialize"]
PHASE_COLORS = {"parse": "#9ecae1", "intents": "#c7e9c0", "evaluate": "#fc9272", "serialize": "#dadaeb"}


def load_e2e(path):
    by_cfg = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            by_cfg[row["config"]].append(int(row["latency_ns"]) / 1000.0)  # -> microseconds
    return {k: np.sort(np.array(v)) for k, v in by_cfg.items()}


def load_breakdown(path):
    by_class = defaultdict(dict)
    with open(path) as f:
        for row in csv.DictReader(f):
            by_class[row["class"]][row["phase"]] = int(row["mean_ns"]) / 1000.0
    return by_class


def pct(sorted_us, q):
    return sorted_us[min(len(sorted_us) - 1, int(round((len(sorted_us) - 1) * q)))]


def plot_cdf(e2e, out):
    fig, ax = plt.subplots(figsize=(8, 5))
    styles = {"with": ("#d62728", "with gensee-crate"), "without": ("#1f77b4", "without (no-op floor)")}
    for cfg, (color, label) in styles.items():
        if cfg not in e2e:
            continue
        xs = e2e[cfg]
        ys = np.arange(1, len(xs) + 1) / len(xs)
        ax.plot(xs, ys, color=color, lw=2, label=label)
        for q, ls in [(0.50, ":"), (0.99, "--")]:
            v = pct(xs, q)
            ax.axvline(v, color=color, ls=ls, lw=0.8, alpha=0.6)
            ax.annotate(f"p{int(q*100)}={v:.0f}µs", (v, q), color=color, fontsize=8,
                        xytext=(4, -10 if cfg == "without" else 4), textcoords="offset points")
    ax.set_xscale("log")
    ax.set_xlabel("Added in-process latency per PreToolUse decision (µs, log scale)")
    ax.set_ylabel("CDF")
    ax.set_title("PreToolUse hook latency overhead — with vs without gensee-crate")
    ax.grid(True, which="both", ls=":", alpha=0.4)
    ax.legend(loc="lower right")
    # Budget is 200ms p50 / 500ms p99 ADDED latency = 200000 / 500000 µs — far off-chart.
    ax.text(0.02, 0.95, "budget: 200ms p50 / 500ms p99 added\n(≈1000× to the right — not shown)",
            transform=ax.transAxes, fontsize=8, va="top", color="gray")
    fig.tight_layout()
    fig.savefig(out, dpi=140)
    print("wrote", out)


def plot_breakdown(bd, out):
    classes = [c for c in ["read_benign", "exec_cmd", "exec_script", "web_fetch"] if c in bd]
    fig, ax = plt.subplots(figsize=(8, 5))
    bottoms = np.zeros(len(classes))
    for phase in PHASES:
        vals = np.array([bd[c].get(phase, 0.0) for c in classes])
        ax.bar(classes, vals, bottom=bottoms, label=phase, color=PHASE_COLORS[phase])
        bottoms += vals
    for i, c in enumerate(classes):
        ax.annotate(f"{bottoms[i]:.0f}µs", (i, bottoms[i]), ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("mean latency per decision (µs)")
    ax.set_title("Per-phase latency breakdown by request type\n(shares only — totals not comparable to e2e numbers)")
    ax.legend(title="phase")
    ax.grid(True, axis="y", ls=":", alpha=0.4)
    fig.tight_layout()
    fig.savefig(out, dpi=140)
    print("wrote", out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="bench/results")
    a = ap.parse_args()
    e2e_csv = os.path.join(a.dir, "bench-e2e.csv")
    bd_csv = os.path.join(a.dir, "bench-breakdown.csv")
    if os.path.exists(e2e_csv):
        plot_cdf(load_e2e(e2e_csv), os.path.join(a.dir, "latency-cdf.png"))
    if os.path.exists(bd_csv):
        plot_breakdown(load_breakdown(bd_csv), os.path.join(a.dir, "latency-breakdown.png"))


if __name__ == "__main__":
    main()

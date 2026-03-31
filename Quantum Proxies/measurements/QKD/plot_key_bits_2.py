#!/usr/bin/env python3
"""
plot_newly_buffered_bits_timeseries.py

Time-series plot for CSV:
time_sec,newly_buffered_bits

Designed for bursty series (many zeros + spikes).
"""

import argparse
import sys

import matplotlib
import matplotlib.pyplot as plt


# --- IEEE-friendly style (mirrors the attached script) ---
matplotlib.rcParams.update({
    "font.size": 9,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "font.family": "sans-serif",
})


def parse_args():
    p = argparse.ArgumentParser(
        description="Plot newly_buffered_bits vs elapsed time (supports multiple input files)."
    )
    p.add_argument("input_files", nargs="+",
                   help="Input file(s): CSV with columns time_sec,newly_buffered_bits.")
    p.add_argument("-o", "--output", default="newly_buffered_bits_timeseries.pdf",
                   help="Output filename (default: newly_buffered_bits_timeseries.pdf)")
    p.add_argument("-l", "--labels", nargs="+", default=None,
                   help="Labels for each file (must match number of input files). If omitted, filenames are used.")
    p.add_argument("--layout", choices=["overlay", "subplots"], default="subplots",
                   help="overlay: all series in one axes; subplots: one row per file (default: subplots).")
    p.add_argument("--nonzero", action="store_true",
                   help="Plot only points where newly_buffered_bits > 0 (recommended for bursty series).")
    p.add_argument("--stem", action="store_true",
                   help="Use impulse/stem style (vertical lines). Great with --nonzero.")
    p.add_argument("--step", action="store_true",
                   help="Use a step plot (piecewise-constant).")
    p.add_argument("--cumsum", action="store_true",
                   help="Plot cumulative sum of bits instead of instantaneous newly_buffered_bits.")
    return p.parse_args()


def _split_fields(line: str):
    line = line.strip()
    if "," in line:
        return [p.strip() for p in line.split(",")]
    return line.split()


def load_timeseries(filename):
    """
    Returns (times, bits) as lists of floats.
    Skips headers / non-numeric rows.
    """
    times, bits = [], []
    with open(filename, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = _split_fields(line)
            if len(parts) < 2:
                continue
            try:
                t = float(parts[0])
                b = float(parts[1])
            except ValueError:
                continue
            times.append(t)
            bits.append(b)
    return times, bits


def apply_filters(t, b, nonzero=False, cumsum=False):
    if cumsum:
        running = 0.0
        b2 = []
        for x in b:
            running += x
            b2.append(running)
        b = b2

    if nonzero:
        t2, b2 = [], []
        for ti, bi in zip(t, b):
            if bi > 0:
                t2.append(ti)
                b2.append(bi)
        return t2, b2

    return t, b


def plot_one(ax, t, b, label, args):
    if not t:
        return False

    if args.stem:
        # impulses from 0 to value
        ax.vlines(t, [0] * len(t), b, label=label, linewidth=1.0)
        # optional marker on top (helps readability)
        ax.plot(t, b, linestyle="None", marker="o", markersize=2, label=None)
    elif args.step:
        ax.step(t, b, where="post", label=label, linewidth=1.0)
    else:
        ax.plot(t, b, label=label, linewidth=1.0)

    return True


def style_axes(ax, ylabel):
    ax.set_ylabel(ylabel)
    ax.grid(True, which="major", linestyle="-", linewidth=0.6, alpha=0.8)
    ax.grid(True, which="minor", linestyle="--", linewidth=0.4, alpha=0.4)
    ax.minorticks_on()


def main():
    args = parse_args()

    if args.labels and len(args.labels) != len(args.input_files):
        print("Error: number of labels must match number of input files.", file=sys.stderr)
        sys.exit(1)

    labels = args.labels[:] if args.labels else args.input_files[:]

    ylabel = "Cumulative buffered bits (bits)" if args.cumsum else "Keys (bits)"

    if args.layout == "overlay":
        fig, ax = plt.subplots(figsize=(3.5, 2.5))
        plotted_any = False

        for fname, lab in zip(args.input_files, labels):
            t, b = load_timeseries(fname)
            t, b = apply_filters(t, b, nonzero=args.nonzero, cumsum=args.cumsum)
            ok = plot_one(ax, t, b, lab, args)
            plotted_any = plotted_any or ok

        if not plotted_any:
            print("Error: no valid data to plot (after filtering).", file=sys.stderr)
            sys.exit(1)

        ax.set_xlabel("Elapsed time (s)")
        style_axes(ax, ylabel)
        if len(args.input_files) > 1:
            ax.legend(frameon=False)

    else:
        # subplots: one row per file
        n = len(args.input_files)
        # heuristic: IEEE-ish width; height grows with n
        fig_h = max(2.5, 1.35 * n)
        fig, axes = plt.subplots(nrows=n, ncols=1, sharex=True, figsize=(3.5, fig_h))
        if n == 1:
            axes = [axes]

        plotted_any = False

        for ax, fname, lab in zip(axes, args.input_files, labels):
            t, b = load_timeseries(fname)
            t, b = apply_filters(t, b, nonzero=args.nonzero, cumsum=args.cumsum)
            ok = plot_one(ax, t, b, lab, args)
            plotted_any = plotted_any or ok

            style_axes(ax, ylabel)
            ax.legend([lab], frameon=False, loc="upper right")

        if not plotted_any:
            print("Error: no valid data to plot (after filtering).", file=sys.stderr)
            sys.exit(1)

        axes[-1].set_xlabel("Elapsed time (s)")

    fig.tight_layout()
    fig.savefig(args.output)
    print(f"Plot saved to {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
plot_delay_boxplot_ieee_notitle.py

IEEE-style box plots of delay (2nd column) with original grid style,
no figure title (LaTeX will provide description), and linear Y-axis.

- First column: time (ignored)
- Second column: delay (plotted)
- Optional --y-ms converts seconds → milliseconds.
"""

import argparse
import sys

import matplotlib
import matplotlib.pyplot as plt

# --- IEEE-friendly style ---
matplotlib.rcParams.update({
    "font.size": 9,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "font.family": "sans-serif",
})


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create IEEE-style box plots of delay (2nd column)."
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="Input text file(s) with columns: Time, Delay, (third column ignored)."
    )
    parser.add_argument(
        "-o", "--output",
        default="delay_boxplot.pdf",
        help="Output PDF filename (default: delay_boxplot.pdf)"
    )
    parser.add_argument(
        "-l", "--labels",
        nargs="+",
        default=None,
        help="Labels for each file (must match number of input files). If omitted, filenames are used."
    )
    parser.add_argument(
        "--y-ms",
        action="store_true",
        help="Interpret delay values as seconds and convert to milliseconds."
    )
    return parser.parse_args()


def load_delays(filename):
    delays = []
    with open(filename, "r") as f:
        for idx, line in enumerate(f):
            if idx == 0:
                continue
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                d = float(parts[1])
            except ValueError:
                continue
            delays.append(d)
    return delays


def main():
    args = parse_args()

    if args.labels and len(args.labels) != len(args.input_files):
        print("Error: number of labels must match number of input files.", file=sys.stderr)
        sys.exit(1)

    all_delays = []
    labels = args.labels[:] if args.labels else []

    for fname in args.input_files:
        delays = load_delays(fname)
        if not delays:
            print(f"Warning: no valid delay values found in '{fname}', skipping.", file=sys.stderr)
            continue

        if args.y_ms:
            delays = [d * 1000.0 for d in delays]  # seconds → milliseconds

        all_delays.append(delays)

        if args.labels is None:
            labels.append(fname)

    if not all_delays:
        print("Error: no valid delay data found in any file.", file=sys.stderr)
        sys.exit(1)

    # IEEE single-column figure width (no DPI override)
    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    bp = ax.boxplot(
        all_delays,
        vert=True,
        showmeans=True,
        meanline=True,
        patch_artist=True,
        labels=labels,
        boxprops=dict(linewidth=1.0, color="black"),
        whiskerprops=dict(linewidth=1.0, color="black"),
        capprops=dict(linewidth=1.0, color="black"),
        medianprops=dict(linewidth=1.2, color="darkred"),
        meanprops=dict(linewidth=1.0, color="blue"),
    )

    # Light fill
    for patch in bp["boxes"]:
        patch.set_facecolor("#d9d9d9")
        patch.set_alpha(0.9)
    #ax.set_yscale('log')
    # Y-axis label
    ax.set_ylabel("Delay (ms)" if args.y_ms else "Delay (s)")

    # No title — LaTeX will provide description
    # (intentionally omitted)

    # Rotate x-axis labels slightly
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")

    # Original grid style (IEEE-friendly, subtle)
    ax.grid(True, which="major", linestyle="-", linewidth=0.6, alpha=0.8)
    ax.grid(True, which="minor", linestyle="--", linewidth=0.4, alpha=0.4)
    ax.minorticks_on()

    fig.tight_layout()
    fig.savefig(args.output)
    print(f"Box plot saved to {args.output}")


if __name__ == "__main__":
    main()

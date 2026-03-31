#!/usr/bin/env python3
"""
plot_rtt_boxplot_multi.py

Read RTT measurements from one or more CSV files and generate
a single PDF with multiple box plots (split into two subplots) styled for 
scientific publications. Includes color discrimination between Legacy and PQC proxies.
"""
#USE: python3 plot_rtt_boxplot_multi.py     packetrusher_times_http.csv packetrusher_times_http_long.csv packetrusher_times_https.csv packetrusher_times_https_long.csv packetrusher_times_falcon.csv packetrusher_times_falcon_long.csv packetrusher_times_mldsa.csv packetrusher_times_mldsa_long.csv packetrusher_times_qkd.csv packetrusher_times_qkd_long.csv   -l "HTTP" "HTTP slow" "HTTPS" "HTTPS slow" "BIKE/Falcon" "BIKE/Falcon slow" "ML-KEM/DSA" "ML-KEM/DSA slow" "QKD/PSK" "QKD/PSK slow"     -o reg_compare6.pdf 


import argparse
import csv
import sys
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# --- Styling Configuration ---
LEGACY_LABELS = ["HTTP", "HTTPS"]
COLOR_LEGACY = "#D0D0D0"  # Light Gray for baselines
COLOR_NOVEL = "#85C1E9"   # Light Blue for PQC/QKD implementations

def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a publication-ready PDF with split RTT [ms] box plots."
    )
    parser.add_argument(
        "input_csvs",
        nargs="+",
        help="Input CSV file(s) produced by measure_rtt.py"
    )
    parser.add_argument(
        "-o", "--output",
        default="rtt_boxplot_multi.pdf",
        help="Output PDF filename (default: rtt_boxplot_multi.pdf)"
    )
    parser.add_argument(
        "-t", "--title",
        default=None,
        help="Title for the plot (optional, usually omitted in papers in favor of captions)"
    )
    parser.add_argument(
        "-l", "--labels",
        nargs="+",
        default=None,
        help="Labels for each CSV (must be the same number as input CSVs)."
    )
    return parser.parse_args()


def load_rtt_values(filename):
    """Load values from CSV, converting seconds → milliseconds if needed."""
    rtts = []
    with open(filename, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rtt_str = (row.get("rtt_ms") or row.get("elapsed_seconds") or "").strip()
            if not rtt_str:
                continue

            try:
                value = float(rtt_str)
                # Safely check if this came from the elapsed_seconds column
                if row.get("elapsed_seconds") and row.get("elapsed_seconds").strip() == rtt_str:
                    value *= 1000.0   # seconds → milliseconds
                rtts.append(value)
            except ValueError:
                continue

    return rtts


def set_publication_style():
    """Applies global styling suited for scientific papers."""
    plt.rcParams.update({
        "font.family": "serif",        
        "font.size": 10,               
        "axes.labelsize": 11,          
        "axes.titlesize": 11,          
        "xtick.labelsize": 10,         
        "ytick.labelsize": 10,         
        "legend.fontsize": 10,
        "axes.linewidth": 1.0,         
        "lines.linewidth": 1.2,        
        "pdf.fonttype": 42,            
        "ps.fonttype": 42,
    })


def apply_box_colors(bplot, labels):
    """Iterates through generated box patches and colors them based on category."""
    for patch, label in zip(bplot['boxes'], labels):
        # Check if the label corresponds to a legacy protocol
        if label.strip() in LEGACY_LABELS:
            patch.set_facecolor(COLOR_LEGACY)
        else:
            patch.set_facecolor(COLOR_NOVEL)


def main():
    args = parse_args()

    if args.labels is not None and len(args.labels) != len(args.input_csvs):
        print("Error: number of labels must match number of input CSV files.", file=sys.stderr)
        sys.exit(1)

    labels = args.labels[:] if args.labels is not None else args.input_csvs[:]

    fast_rtts, fast_labels = [], []
    slow_rtts, slow_labels = [], []

    # Automatically group into Fast vs Slow based on the label text
    for csv_file, label in zip(args.input_csvs, labels):
        rtts = load_rtt_values(csv_file)
        if not rtts:
            print(f"Warning: no valid RTT values found in '{csv_file}', skipping.", file=sys.stderr)
            continue

        if "slow" in label.lower():
            slow_rtts.append(rtts)
            # Clean label for consistent X-axis across subplots
            clean_label = label.replace(" slow", "").replace(" Slow", "")
            slow_labels.append(clean_label)
        else:
            fast_rtts.append(rtts)
            fast_labels.append(label)

    if not fast_rtts and not slow_rtts:
        print("Error: no valid RTT values found in any CSV file.", file=sys.stderr)
        sys.exit(1)

    set_publication_style()

    # Create a wider figure with 1 row, 2 columns, sharing the Y-axis
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.5), sharey=True)
    ax_fast, ax_slow = axes

    # Base styling for lines (faces will be overridden by apply_box_colors)
    medianprops = dict(color='black', linewidth=1.2, linestyle='-')
    meanprops = dict(color='#444444', linewidth=1.2, linestyle='--')
    whiskerprops = dict(color='black', linewidth=1.0)
    capprops = dict(color='black', linewidth=1.0)
    boxprops = dict(color='black', linewidth=1.0)

    # Plot Fast Succession
    if fast_rtts:
        bplot_fast = ax_fast.boxplot(
            fast_rtts, vert=True, showmeans=True, meanline=True, patch_artist=True,
            labels=fast_labels, boxprops=boxprops,
            medianprops=medianprops, meanprops=meanprops, whiskerprops=whiskerprops, capprops=capprops
        )
        apply_box_colors(bplot_fast, fast_labels)
        ax_fast.set_title("Quick Succession")
        ax_fast.set_ylabel("Registration Time [ms]")

    # Plot Slow Succession
    if slow_rtts:
        bplot_slow = ax_slow.boxplot(
            slow_rtts, vert=True, showmeans=True, meanline=True, patch_artist=True,
            labels=slow_labels, boxprops=boxprops,
            medianprops=medianprops, meanprops=meanprops, whiskerprops=whiskerprops, capprops=capprops
        )
        apply_box_colors(bplot_slow, slow_labels)
        ax_slow.set_title("Slow Succession (Cold Start)")

    # Apply consistent formatting to both subplots
    for ax in axes:
        ax.yaxis.grid(True, linestyle='--', alpha=0.6, color='#CCCCCC')
        ax.set_axisbelow(True)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")

    # Add a unified Custom Legend to explain the colors
    legend_elements = [
        mpatches.Patch(facecolor=COLOR_LEGACY, edgecolor='black', linewidth=1.0, label='Legacy (Native)'),
        mpatches.Patch(facecolor=COLOR_NOVEL, edgecolor='black', linewidth=1.0, label='Proposed (PQC Proxies)')
    ]
    
    # Place legend BELOW the subplots
    fig.legend(handles=legend_elements, loc='upper center', bbox_to_anchor=(0.5, 0.05), ncol=2, frameon=False)

    # Reset title position back to normal
    if args.title:
        fig.suptitle(args.title, y=1.05)

    plt.tight_layout()
    # bbox_inches="tight" ensures the bounding box expands to include the legend at the bottom
    fig.savefig(args.output, format="pdf", bbox_inches="tight")
    print(f"Publication-ready split box plot saved to {args.output}")


if __name__ == "__main__":
    main()
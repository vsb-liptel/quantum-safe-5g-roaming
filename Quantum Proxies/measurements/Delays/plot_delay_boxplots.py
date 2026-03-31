#!/usr/bin/env python3
"""
plot_flow_boxplot.py

Read delay data from one or more space/tab/comma-separated files 
and generate a single PDF with boxplots styled for scientific publications.

Expected input format:
Time 1-10.45.14.48-10.100.1.205 Aggregate-Flow
0.000000 0.000477 0.000477
0.001000 0.000422 0.000422
"""

import argparse
import sys
import matplotlib.pyplot as plt

def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a publication-ready PDF boxplot for flow delays."
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="Input data file(s) containing the time and delay columns"
    )
    parser.add_argument(
        "-o", "--output",
        default="flow_boxplot.pdf",
        help="Output PDF filename (default: flow_boxplot.pdf)"
    )
    parser.add_argument(
        "-l", "--labels",
        nargs="+",
        default=None,
        help="Labels for each data series (must match the number of input files)."
    )
    return parser.parse_args()


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


def load_delay_values(filename):
    """
    Load Delay values from a file.
    Assumes Delay is the second column in seconds, converts to microseconds (us).
    """
    delays = []
    
    with open(filename, 'r') as f:
        lines = f.readlines()
        
        # Skip header if the first line starts with 'Time' or contains strings
        start_idx = 0
        if len(lines) > 0 and ("Time" in lines[0] or "Aggregate-Flow" in lines[0]):
            start_idx = 1
            
        for line in lines[start_idx:]:
            # Split by whitespace or commas
            line = line.replace(',', ' ')
            parts = line.strip().split()
            
            if len(parts) >= 2:
                try:
                    # Convert delay to microseconds (assuming input is in seconds)
                    d = float(parts[1]) * 1_000_000 
                    delays.append(d)
                except ValueError:
                    continue

    return delays


def main():
    args = parse_args()

    if args.labels is not None and len(args.labels) != len(args.input_files):
        print("Error: number of labels must match number of input files.", file=sys.stderr)
        sys.exit(1)

    labels = args.labels[:] if args.labels is not None else args.input_files[:]

    set_publication_style()

    all_delays = []
    valid_labels = []

    for filename, label in zip(args.input_files, labels):
        delays = load_delay_values(filename)
        
        if not delays:
            print(f"Warning: no valid data found in '{filename}', skipping.", file=sys.stderr)
            continue
            
        all_delays.append(delays)
        valid_labels.append(label)

    if not all_delays:
        print("Error: no valid data found in any file.", file=sys.stderr)
        sys.exit(1)

    # Create figure (single subplot since we're just plotting side-by-side distributions)
    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    # Base styling for lines matching your original script
    medianprops = dict(color='black', linewidth=1.2, linestyle='-')
    meanprops = dict(color='#444444', linewidth=1.2, linestyle='--')
    whiskerprops = dict(color='black', linewidth=1.0)
    capprops = dict(color='black', linewidth=1.0)
    boxprops = dict(color='black', linewidth=1.0)

# ---------------------------------------------------------
    # Generate the violin plot
    # ---------------------------------------------------------
    vplot = ax.violinplot(
        all_delays, 
        vert=True, 
        showmeans=True, 
        showmedians=True, 
        showextrema=True
    )

    # Violin plots do not take a 'labels' argument directly, 
    # so we set the x-ticks and labels manually:
    ax.set_xticks([i + 1 for i in range(len(valid_labels))])
    ax.set_xticklabels(valid_labels)

    # Fill violins with the publication-friendly color and set transparency
    COLOR_FILL = "#85C1E9"
    for pc in vplot['bodies']:
        pc.set_facecolor(COLOR_FILL)
        pc.set_edgecolor('black')
        pc.set_alpha(0.7)  # Transparency helps visualize dense overlapping data

    # Style the lines (means, medians, extrema) to match your original black/grey theme
    for partname in ('cbars', 'cmins', 'cmaxes', 'cmeans', 'cmedians'):
        vp = vplot.get(partname)
        if vp:
            vp.set_linewidth(1.2)
            if partname == 'cmeans':
                vp.set_edgecolor('#444444')
                vp.set_linestyle('--')  # Mean line as dashed
            else:
                vp.set_edgecolor('black')
    # ---------------------------------------------------------

    # Formatting axes
    ax.set_ylabel(r"Delay [$\mu$s]")
    
    # Styling grid and spines to match your original script exactly
    ax.yaxis.grid(True, linestyle='--', alpha=0.6, color='#CCCCCC')
    ax.set_axisbelow(True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    # Rotate labels if they might be long
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")

    plt.tight_layout()
    fig.savefig(args.output, format="pdf", bbox_inches="tight")
    print(f"Publication-ready flow delay boxplot saved to {args.output}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
plot_flow_delay.py

Read time-based flow data from one or more space/tab/comma-separated files 
and generate a single PDF line plot styled for scientific publications.

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
        description="Create a publication-ready PDF line plot for flow delays."
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="Input data file(s) containing the time and delay columns"
    )
    parser.add_argument(
        "-o", "--output",
        default="flow_delay.pdf",
        help="Output PDF filename (default: flow_delay.pdf)"
    )
    parser.add_argument(
        "-l", "--labels",
        nargs="+",
        default=None,
        help="Labels for each data series (must match the number of input files)."
    )
    parser.add_argument(
        "--x-unit",
        choices=["s", "ms"],
        default="s",
        help="Unit for the X-axis (default: s). 'ms' will multiply input time by 1000."
    )
    parser.add_argument(
        "--x-max",
        type=float,
        default=None,
        help="Maximum value for the X-axis (in the chosen unit) to zoom in on a specific timeframe."
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


def load_flow_data(filename, x_unit, x_max):
    """
    Load Time and Delay values from a file.
    Assumes Delay is in seconds in the file and converts it to microseconds (us).
    """
    times = []
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
                    t = float(parts[0])
                    # Convert delay to microseconds (assuming input is in seconds)
                    d = float(parts[1]) * 1_000_000 
                    
                    if x_unit == "ms":
                        t *= 1000.0
                        
                    if x_max is not None and t > x_max:
                        # Since it's a timeseries, we can stop reading once we pass x_max
                        break
                        
                    times.append(t)
                    delays.append(d)
                except ValueError:
                    continue

    return times, delays


def main():
    args = parse_args()

    if args.labels is not None and len(args.labels) != len(args.input_files):
        print("Error: number of labels must match number of input files.", file=sys.stderr)
        sys.exit(1)

    labels = args.labels[:] if args.labels is not None else args.input_files[:]

    set_publication_style()

    # Create figure
    fig, ax = plt.subplots(figsize=(7.0, 3.5))

    # Distinct markers/styles can be added if overlapping is an issue,
    # but for dense time series, plain lines usually look best.
    colors = ['#1f77b4', '#d62728', '#2ca02c', '#ff7f0e', '#9467bd', '#8c564b']

    plotted_any = False
    for i, (filename, label) in enumerate(zip(args.input_files, labels)):
        times, delays = load_flow_data(filename, args.x_unit, args.x_max)
        
        if not times:
            print(f"Warning: no valid data found in '{filename}', skipping.", file=sys.stderr)
            continue
            
        color = colors[i % len(colors)]
        ax.plot(times, delays, label=label, color=color, alpha=0.85)
        plotted_any = True

    if not plotted_any:
        print("Error: no valid data found in any file.", file=sys.stderr)
        sys.exit(1)

    # Formatting axes
    ax.set_xlabel(f"Time [{args.x_unit}]")
    ax.set_ylabel(r"Delay [$\mu$s]")
    
    # Styling grid and spines to match the boxplot
    ax.yaxis.grid(True, linestyle='--', alpha=0.6, color='#CCCCCC')
    ax.xaxis.grid(True, linestyle='--', alpha=0.6, color='#CCCCCC')
    ax.set_axisbelow(True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # Optional: set x limit exactly if specified
    if args.x_max is not None:
        ax.set_xlim(left=0, right=args.x_max)
    else:
        ax.set_xlim(left=0)

    # Place legend
    ax.legend(loc='best', frameon=False)

    plt.tight_layout()
    fig.savefig(args.output, format="pdf", bbox_inches="tight")
    print(f"Publication-ready flow delay plot saved to {args.output}")


if __name__ == "__main__":
    main()
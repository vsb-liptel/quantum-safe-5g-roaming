#!/usr/bin/env python3
"""
plot_cumulative_volume.py

Read traffic capture CSV files and plot the cumulative volume in SI Kilobytes (kB).
"""

import argparse
import sys
import csv
import matplotlib.pyplot as plt

# ==========================================
# ------------- CONFIGURATION --------------
# ==========================================
# Choose the X-axis mode: 
# 0 -> 0-100% registration progress
# 1 -> Absolute time in milliseconds
X_AXIS_MODE = 0
# ==========================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a publication-ready PDF plot for cumulative traffic volume."
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="Input CSV data file(s) containing Time and Cumulative Volume."
    )
    parser.add_argument(
        "-o", "--output",
        default="cumulative_volume.pdf",
        help="Output PDF filename (default: cumulative_volume.pdf)"
    )
    parser.add_argument(
        "-l", "--labels",
        nargs="+",
        default=None,
        help="Labels for each data series (must match the number of input files)."
    )
    return parser.parse_args()


def set_publication_style():
    """Applies global styling suited for IEEE scientific papers."""
    plt.rcParams.update({
        "font.family": "serif",        
        "font.size": 8,               
        "axes.labelsize": 9,          
        "axes.titlesize": 9,          
        "xtick.labelsize": 8,         
        "ytick.labelsize": 8,         
        "legend.fontsize": 8,
        "axes.linewidth": 1.0,         
        "lines.linewidth": 1.5,        
        "pdf.fonttype": 42,            
        "ps.fonttype": 42,
    })


def load_cumulative_data(filename, mode):
    """
    Loads Time and Cumulative Volume from the CSV.
    Converts Time based on the chosen mode (0 for percent, 1 for ms).
    Converts Volume to true SI Kilobytes (kB).
    """
    times = []
    volumes = []
    
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                t_key = next((k for k in row.keys() if 'Time' in k), None)
                v_key = next((k for k in row.keys() if 'Cumulative Volume' in k or 'Total' in k), None)
                
                t = float(row[t_key])
                v = float(row[v_key]) / 1000.0  # Convert Bytes to true SI kB
                
                times.append(t)
                volumes.append(v)
            except (ValueError, TypeError, StopIteration):
                continue

    # Process time array based on selected mode
    if times:
        t_min = min(times)
        
        if mode == 0:
            t_max = max(times)
            duration = t_max - t_min
            if duration > 0:
                times = [((t - t_min) / duration) * 100.0 for t in times]
            else:
                times = [0.0 for t in times]
                
        elif mode == 1:
            # Subtract minimum time so all graphs start at T=0, then convert to ms
            times = [(t - t_min) * 1000.0 for t in times]

    return times, volumes


def main():
    args = parse_args()

    if args.labels is not None and len(args.labels) != len(args.input_files):
        print("Error: number of labels must match number of input files.", file=sys.stderr)
        sys.exit(1)

    labels = args.labels[:] if args.labels is not None else args.input_files[:]

    set_publication_style()

    fig, ax = plt.subplots(figsize=(3.5, 2.8))

    colors = ['#1f77b4', '#d62728', '#2ca02c', '#ff7f0e', '#9467bd', '#8c564b']
    linestyles = ['-', '--', ':', '-.']

    plotted_any = False
    for i, (filename, label) in enumerate(zip(args.input_files, labels)):
        times, volumes = load_cumulative_data(filename, X_AXIS_MODE)
        
        if not times:
            print(f"Warning: no valid data found in '{filename}', skipping.", file=sys.stderr)
            continue
            
        color = colors[i % len(colors)]
        l_style = linestyles[i % len(linestyles)]
        
        ax.step(times, volumes, label=label, color=color, linestyle=l_style, alpha=0.9, where='post')
        plotted_any = True

    if not plotted_any:
        print("Error: no valid data found in any file.", file=sys.stderr)
        sys.exit(1)

    # Dynamic Axis Formatting based on Mode
    if X_AXIS_MODE == 0:
        ax.set_xlabel("Registration Progress [%]")
        ax.set_xlim(left=0, right=100)
    elif X_AXIS_MODE == 1:
        ax.set_xlabel("Time [ms]")
        ax.set_xlim(left=0) # Automatically scale the right side based on the slowest protocol

    ax.set_ylabel("Cumulative Volume [kB]")
    
    ax.yaxis.grid(True, linestyle='--', alpha=0.6, color='#CCCCCC')
    ax.xaxis.grid(True, linestyle='--', alpha=0.6, color='#CCCCCC')
    ax.set_axisbelow(True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    ax.set_ylim(bottom=0)

    ax.legend(loc='upper left', frameon=True, facecolor='white', framealpha=0.85, edgecolor='none')

    plt.tight_layout()
    fig.savefig(args.output, format="pdf", bbox_inches="tight")
    mode_str = "0-100%" if X_AXIS_MODE == 0 else "absolute ms"
    print(f"Publication-ready cumulative volume plot saved to {args.output} (Mode: {mode_str})")


if __name__ == "__main__":
    main()
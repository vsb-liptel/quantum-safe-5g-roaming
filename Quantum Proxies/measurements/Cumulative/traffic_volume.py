#!/usr/bin/env python3

from scapy.all import sniff, IP
import pandas as pd
import time
import signal
import sys

# ---- CONFIGURATION ----
TARGET_IP = "10.100.1.207"     # <- CHANGE this to your target IP
TARGET_PORTS = []              # <- List of ports, e.g., [80, 443]. Leave empty [] for all ports.
OUTPUT_CSV = "traffic_n9_ml.csv" 
INTERFACE = "ens18"            
# ------------------------

# Global state
start_time = None
total_bytes = 0
data_log = []

def signal_handler(sig, frame):
    print("\nInterrupted. Saving CSV...")
    # Using the 3 columns requested: Time, Instantaneous (Packet) Size, Cumulative Total
    df = pd.DataFrame(data_log, columns=["Time (s)", "Packet Size (Bytes)", "Cumulative Volume (Bytes)"])
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved to {OUTPUT_CSV} with {len(df)} records.")
    sys.exit(0)

def process_packet(pkt):
    global start_time, total_bytes

    # The BPF filter handles the IP and Port matching at the kernel level,
    # so we just need to record the data here.
    pkt_len = len(pkt)           # Full frame size (including Ethernet)
    pkt_time = float(pkt.time)   # High-precision kernel timestamp

    if start_time is None:
        start_time = pkt_time
        print(f"Started capture at {time.ctime(start_time)}")

    elapsed = pkt_time - start_time
    total_bytes += pkt_len
    
    # Appending: [Timestamp, Size of this packet, Cumulative total]
    # Keeping 6 decimal places for microseconds resolution
    data_log.append([round(elapsed, 6), pkt_len, total_bytes])

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

# Construct BPF Filter dynamically
bpf_filter = f"host {TARGET_IP}"
if TARGET_PORTS:
    # Creates a string like: host 10.100.1.207 and (port 80 or port 443)
    port_conds = " or ".join([f"port {p}" for p in TARGET_PORTS])
    bpf_filter += f" and ({port_conds})"

print(f"Starting traffic capture on {INTERFACE}...")
print(f"Target IP: {TARGET_IP}")
if TARGET_PORTS:
    print(f"Target Ports: {TARGET_PORTS}")
print(f"Active BPF Filter: '{bpf_filter}'")
print("Press Ctrl+C to stop and save data...")

# Start sniffing
# store=0 prevents Scapy from keeping packets in memory, avoiding RAM exhaustion
sniff(filter=bpf_filter, prn=process_packet, iface=INTERFACE, store=0)
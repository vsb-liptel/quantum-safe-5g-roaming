#!/usr/bin/env python3
import subprocess
import time
import csv
import os
import sys
import queue      # <-- ADDED
import threading  # <-- ADDED

# ----------------------------------------
# CONFIGURATION
# ----------------------------------------

RUNS = 100                              # how many times to run packetrusher
OUTPUT_CSV = "packetrusher_times_mldsa.csv"  # CSV filename

PACKETRUSHER_CMD = ["sudo", "./packetrusher", "ue"]

START_KEYWORD = "Initiating Registration"
END_KEYWORD   = "PDU address received"

WAIT_AFTER_MEASUREMENT = 0             # seconds to wait after detection
WAIT_BEFORE_NEXT_RUN = 0              # cooldown between runs
TIMEOUT_SECONDS = 60                   # max time allowed per run before skipping
# ----------------------------------------


def enqueue_output(out, q):
    """Reads lines from the stream and puts them in a queue."""
    for line in out:
        q.put(line)
    q.put(None)  # Sentinel value to signal EOF (Process finished)

def run_single_measurement(run_id, timeout_seconds=TIMEOUT_SECONDS):
    """
    Runs packetrusher once and returns elapsed time in seconds.
    Returns None on timeout or missing start/end markers.
    
    Uses a background thread and queue to avoid buffering deadlocks.
    """
    proc = subprocess.Popen(
        PACKETRUSHER_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    # Set up the queue and background reading thread
    q = queue.Queue()
    t = threading.Thread(target=enqueue_output, args=(proc.stdout, q))
    t.daemon = True  # Ensures the thread dies when the main program exits
    t.start()

    start_time = None
    end_time = None
    deadline = time.time() + timeout_seconds

    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                print(f"[run {run_id}] TIMEOUT after {timeout_seconds} seconds → aborting run.")
                return None

            try:
                # Pull from the queue, waiting at most until the deadline
                line = q.get(timeout=remaining)
            except queue.Empty:
                # queue.get() timed out before getting a line
                print(f"[run {run_id}] TIMEOUT (no output) after {timeout_seconds} seconds → aborting run.")
                return None

            # Check if the thread sent the EOF sentinel
            if line is None:
                print(f"[run {run_id}] Process ended without completing registration.")
                return None

            line = line.strip()
            print(f"[run {run_id:02d}] {line}")

            # Detect start event
            if START_KEYWORD in line:
                start_time = time.time()
                print(f"START ts = {start_time:.6f}")

            # Detect end event
            elif END_KEYWORD in line and start_time is not None:
                end_time = time.time()
                delta = end_time - start_time

                print(f"END ts = {end_time:.6f}")
                print(f"DELTA = {delta:.6f}")

                time.sleep(WAIT_AFTER_MEASUREMENT)
                return delta

    finally:
        # Cleanup
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    file_exists = os.path.exists(OUTPUT_CSV)

    with open(OUTPUT_CSV, "a" if file_exists else "w", newline="") as f:
        writer = csv.writer(f)

        # Write header only once
        if not file_exists:
            writer.writerow(["run", "elapsed_seconds"])

        print(f"Starting {RUNS} measurements...\n")

        for i in range(1, RUNS + 1):
            print(f"\n----- RUN {i}/{RUNS} -----")

            result = run_single_measurement(i)

            if result is None:
                print(f"[run {i}] No valid measurement (timeout or missing markers).")
                writer.writerow([i, ""])
            else:
                writer.writerow([i, f"{result:.6f}"])

            f.flush()

            print(f"Waiting {WAIT_BEFORE_NEXT_RUN} seconds before next run...\n")
            time.sleep(WAIT_BEFORE_NEXT_RUN)

    print(f"\nAll runs completed. Results saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

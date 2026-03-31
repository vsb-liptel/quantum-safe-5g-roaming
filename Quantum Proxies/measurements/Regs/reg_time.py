#!/usr/bin/env python3
import subprocess
import time

# Keywords to detect
start_keyword = "Initiating Registration"
end_keyword = "PDU address received"

# Start the external command
proc = subprocess.Popen(
    ["sudo", "./packetrusher", "ue"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

start_time = None
end_time = None

print("Listening for events...")

try:
    for line in proc.stdout:
        line = line.strip()
        print(line)  # optional: comment this out if you don’t want live log

        if start_keyword in line:  # or START_KEYWORD
            start_time = time.time()
            print(f"START ts = {start_time:.6f}")

        elif end_keyword in line and start_time is not None:  # or END_KEYWORD
            end_time = time.time()
            delta = end_time - start_time
            print(f"END   ts = {end_time:.6f}")
            print(f"DELTA   = {delta:.6f}")

except KeyboardInterrupt:
    print("Interrupted, stopping...")

finally:
    proc.terminate()

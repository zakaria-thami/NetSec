#!/usr/bin/env python3
"""
tcpdump_handler.py

This script runs tcpdump to capture network traffic and writes packet information
to a JSON file named 'packets.json'.
"""

import subprocess
import time
import json
import sys
import signal

CAPTURE_DURATION = 60  # seconds to capture traffic
OUTPUT_FILE = "packets.json"

def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting tcpdump capture.")
    sys.exit(0)

def parse_packet_line(line):
    """
    A simple parser that wraps the raw tcpdump line into a dict.
    For a real project, implement more detailed parsing.
    """
    return {"raw": line.strip()}

def capture_traffic(duration=CAPTURE_DURATION):
    print(f"[*] Starting tcpdump capture for {duration} seconds...")
    # Using '-l' for line-buffered output and '-n' to disable name resolution.
    tcpdump_cmd = ["sudo", "tcpdump", "-l", "-n"]

    packets = []
    start_time = time.time()

    # Launch tcpdump process
    process = subprocess.Popen(
        tcpdump_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  # ensures we get string output in Python 3
    )

    try:
        # Read line by line from tcpdump’s stdout.
        for line in process.stdout:
            packet = parse_packet_line(line)
            packets.append(packet)
            if time.time() - start_time > duration:
                print("[*] Capture duration reached. Terminating tcpdump.")
                process.terminate()
                break
    except KeyboardInterrupt:
        print("\n[!] User interruption. Terminating tcpdump.")
        process.terminate()

    # Wait for process to terminate cleanly
    process.wait()

    print(f"[*] Captured {len(packets)} packets. Writing to {OUTPUT_FILE}...")
    try:
        with open(OUTPUT_FILE, "w") as f:
            json.dump(packets, f, indent=2)
        print("[*] JSON file created successfully.")
    except Exception as e:
        print(f"[!] Error writing JSON file: {e}")

def main():
    signal.signal(signal.SIGINT, signal_handler)
    capture_traffic()

if __name__ == "__main__":
    main()

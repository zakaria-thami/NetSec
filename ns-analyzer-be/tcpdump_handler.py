#!/usr/bin/env python3
"""
tcpdump_handler.py

This script runs tcpdump to capture network traffic and saves packets in a dynamically provided PCAP file.
"""

import subprocess
import sys
import signal

CAPTURE_DURATION = 60  # Default capture duration in seconds
DEFAULT_OUTPUT_FILE = "packets.pcap"  # Default filename if none is provided


def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting tcpdump capture.")
    sys.exit(0)


def capture_traffic(output_file, duration=CAPTURE_DURATION):
    print(f"[*] Starting tcpdump capture for {duration} seconds...")

    tcpdump_cmd = ["tcpdump", "-i", "eth0", "-w", output_file]

    try:
        process = subprocess.Popen(tcpdump_cmd)
        process.wait(timeout=duration)
        process.terminate()
        print(f"[*] Capture complete. PCAP saved to {output_file}")
    except subprocess.TimeoutExpired:
        print(f"[*] Capture duration reached. Stopping tcpdump.")
        process.terminate()
    except KeyboardInterrupt:
        print("\n[!] User interruption. Terminating tcpdump.")
        process.terminate()
    except Exception as e:
        print(f"[!] Error running tcpdump: {e}")
        sys.exit(1)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    # Read filename from arguments
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    else:
        output_file = DEFAULT_OUTPUT_FILE

    capture_traffic(output_file)


if __name__ == "__main__":
    main()

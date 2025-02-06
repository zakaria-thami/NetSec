#!/usr/bin/env python3
"""
tcpdump_handler.py

This script runs tcpdump to capture network traffic and saves packets in a PCAP file.
"""

import subprocess
import sys
import signal

CAPTURE_DURATION = 60 
OUTPUT_FILE = "packets.pcap"


def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting tcpdump capture.")
    sys.exit(0)


def capture_traffic(duration=CAPTURE_DURATION):
    print(f"[*] Starting tcpdump capture for {duration} seconds...")

    tcpdump_cmd = ["sudo", "tcpdump", "-i", "eth0", "-w", OUTPUT_FILE]

    try:
        process = subprocess.Popen(tcpdump_cmd)
        process.wait(timeout=duration)
        process.terminate()
        print(f"[*] Capture complete. PCAP saved to {OUTPUT_FILE}")
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
    capture_traffic()


if __name__ == "__main__":
    main()

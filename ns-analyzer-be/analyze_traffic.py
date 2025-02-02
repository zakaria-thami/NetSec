#!/usr/bin/env python3
"""
analyze_traffic.py

This script analyzes the JSON file (packets.json) containing captured network traffic.
It performs a frequency count of protocol keywords found in the raw packet data
and extracts IP addresses to identify the most active hosts.
"""

import json
import sys
import re
from collections import Counter

INPUT_FILE = "packets.json"

# List of protocol keywords to search for.
PROTOCOL_KEYWORDS = ["ARP", "IP", "TCP", "UDP", "ICMP"]

# Regular expression for extracting IP addresses
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')


def load_packets(filename=INPUT_FILE):
    try:
        with open(filename, "r") as f:
            packets = json.load(f)
        return packets
    except Exception as e:
        print(f"[!] Failed to load {filename}: {e}")
        sys.exit(1)


def analyze_packets(packets):
    protocol_counts = {proto: 0 for proto in PROTOCOL_KEYWORDS}
    protocol_counts["Other"] = 0
    ip_counter = Counter()

    for packet in packets:
        raw_data = packet.get("raw", "")
        found = False

        # Count protocol occurrences
        for proto in PROTOCOL_KEYWORDS:
            if proto in raw_data:
                protocol_counts[proto] += 1
                found = True
                break  # Assume one protocol per packet for simplicity
        if not found:
            protocol_counts["Other"] += 1

        # Extract and count IP addresses
        ips = IP_PATTERN.findall(raw_data)
        ip_counter.update(ips)

    return protocol_counts, ip_counter


def main():
    print("[*] Loading captured packets from JSON...")
    packets = load_packets()
    print(f"[*] {len(packets)} packets loaded. Analyzing...")

    protocol_results, ip_results = analyze_packets(packets)

    print("[*] Analysis Results:")
    print("\n[Protocol Statistics]")
    for protocol, count in protocol_results.items():
        print(f"  {protocol}: {count} packets")

    print("\n[Top 10 Active IP Addresses]")
    for ip, count in ip_results.most_common(10):
        print(f"  {ip}: {count} occurrences")


if __name__ == "__main__":
    main()

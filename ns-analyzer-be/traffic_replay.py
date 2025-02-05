#!/usr/bin/env python3
"""
traffic_replay.py

This script reads a PCAP file and replays the packets on the network.
"""

from scapy.all import rdpcap, sendp
import sys


def replay_pcap(pcap_file, interface="eth0"):
    """
    Replays packets from a PCAP file onto the specified network interface.
    """
    print(f"[*] Loading packets from {pcap_file}...")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: File {pcap_file} not found.")
        sys.exit(1)

    print(f"[*] Loaded {len(packets)} packets. Starting replay on {interface}...")

    try:
        for packet in packets:
            sendp(packet, iface=interface, verbose=False)
        print("[*] Replay completed successfully.")
    except Exception as e:
        print(f"[!] Error while sending packets: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python traffic_replay.py <pcap_file> [interface]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    net_interface = sys.argv[2] if len(sys.argv) > 2 else "eth0"  # Default interface

    replay_pcap(pcap_path, net_interface)

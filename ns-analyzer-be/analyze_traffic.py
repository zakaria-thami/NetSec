#!/usr/bin/env python3
"""
analyze_traffic.py

Analyzes a PCAP file and provides detailed insights:
- Protocol analysis
- Most active IPs
- Most used ports
- Port scanning detection
- Suspicious packet detection (ARP spoofing, flooding, and unexpected replies)
"""

from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP, DNS, DHCP
from collections import Counter, defaultdict
import sys

INPUT_FILE = "packets.pcap"

def load_pcap(filename=INPUT_FILE):
    """Loads packets from a PCAP file."""
    try:
        packets = rdpcap(filename)
        return packets
    except FileNotFoundError:
        print(f"[!] Error: File {filename} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to load {filename}: {e}")
        sys.exit(1)

def analyze_packets(packets):
    """Analyzes packets and collects network insights."""
    protocol_counts = Counter()
    ip_counts = Counter()
    dest_ip_counts = Counter()
    port_counts = Counter()
    traffic_per_ip = defaultdict(int)
    timestamps = []

    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_counts[src_ip] += 1
            dest_ip_counts[dst_ip] += 1
            traffic_per_ip[src_ip] += len(packet)
            timestamps.append(packet.time)

        if packet.haslayer(TCP):
            protocol_counts["TCP"] += 1
            port_counts[packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            protocol_counts["UDP"] += 1
            port_counts[packet[UDP].dport] += 1
        elif packet.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
        elif packet.haslayer(ARP):
            protocol_counts["ARP"] += 1
        elif packet.haslayer(DNS):
            protocol_counts["DNS"] += 1
        elif packet.haslayer(DHCP):
            protocol_counts["DHCP"] += 1

    return {
        "protocol_counts": protocol_counts,
        "ip_counts": ip_counts.most_common(5),
        "dest_ip_counts": dest_ip_counts.most_common(5),
        "top_ports": port_counts.most_common(5),
        "traffic_per_ip": traffic_per_ip,
        "timestamps": timestamps,
    }

def detect_port_scanning(packets):
    """Detects port scanning attempts by analyzing TCP SYN packets."""
    scan_threshold = 10
    ip_scans = defaultdict(set)

    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # TCP SYN flag
            ip_scans[packet[IP].src].add(packet[TCP].dport)

    return {ip: ports for ip, ports in ip_scans.items() if len(ports) > scan_threshold}

### 🔥 ARP Spoofing Detection Functions 🔥 ###

def detect_arp_spoofing(packets):
    """Detects ARP spoofing by checking IP-MAC inconsistencies."""
    arp_table = {}  # Maps IPs to MAC addresses
    spoofed_ips = {}

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            if src_ip in arp_table and arp_table[src_ip] != src_mac:
                spoofed_ips[src_ip] = {"old_mac": arp_table[src_ip], "new_mac": src_mac}

            arp_table[src_ip] = src_mac

    return spoofed_ips

def detect_arp_flooding(packets):
    """Detects ARP flooding by counting ARP replies per sender."""
    arp_reply_counts = Counter()

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            src_mac = packet[ARP].hwsrc
            arp_reply_counts[src_mac] += 1

    return {mac: count for mac, count in arp_reply_counts.items() if count > 10}

def detect_unexpected_arp_replies(packets):
    """Detects ARP replies that were not preceded by an ARP request."""
    arp_requests = set()
    suspicious_replies = []

    for packet in packets:
        if packet.haslayer(ARP):
            if packet[ARP].op == 1:  # ARP Request
                arp_requests.add(packet[ARP].pdst)
            elif packet[ARP].op == 2 and packet[ARP].psrc not in arp_requests:
                suspicious_replies.append(f"Unexpected ARP Reply from {packet[ARP].psrc}")

    return suspicious_replies

def print_summary(results, packets):
    """Prints the analysis results, including ARP spoofing detection."""
    print("\n[*] Traffic Analysis:")
    print("  - TCP Packets:", results["protocol_counts"]["TCP"])
    print("  - UDP Packets:", results["protocol_counts"]["UDP"])
    print("  - ICMP Packets:", results["protocol_counts"]["ICMP"])
    print("  - ARP Packets:", results["protocol_counts"]["ARP"])
    print("  - DNS Packets:", results["protocol_counts"]["DNS"])
    print("  - DHCP Packets:", results["protocol_counts"]["DHCP"])

    print("\n[*] Most Active Source IPs:")
    for ip, count in results["ip_counts"]:
        print(f"  - {ip}: {count} packets")

    print("\n[*] Most Contacted Destination IPs:")
    for ip, count in results["dest_ip_counts"]:
        print(f"  - {ip}: {count} packets")

    print("\n[*] Most Used Ports:")
    for port, count in results["top_ports"]:
        print(f"  - Port {port}: {count} packets")

    print("\n[*] Possible Port Scanning:")
    port_scans = detect_port_scanning(packets)
    if port_scans:
        for ip, ports in port_scans.items():
            print(f"  - {ip} scanned {len(ports)} ports: {list(ports)[:5]}...")
    else:
        print("  - No port scanning detected.")

    ### 🚨 ARP Spoofing Detection Results 🚨 ###
    print("\n[*] ARP Spoofing Detection:")
    spoofed_ips = detect_arp_spoofing(packets)
    flooding_attacks = detect_arp_flooding(packets)
    unexpected_replies = detect_unexpected_arp_replies(packets)

    if spoofed_ips:
        print("[!] MAC inconsistencies detected:")
        for ip, macs in spoofed_ips.items():
            print(f"  - {ip} changed MAC: {macs['old_mac']} -> {macs['new_mac']}")
    else:
        print("  - No MAC inconsistencies found.")

    if flooding_attacks:
        print("[!] Possible ARP Flooding detected:")
        for mac, count in flooding_attacks.items():
            print(f"  - MAC {mac} sent {count} ARP replies.")
    else:
        print("  - No ARP Flooding detected.")

    if unexpected_replies:
        print("[!] Unexpected ARP Replies found:")
        for alert in unexpected_replies:
            print(f"  - {alert}")
    else:
        print("  - No unexpected ARP replies detected.")

if __name__ == "__main__":
    print(f"[*] Loading packets from {INPUT_FILE}...")
    packets = load_pcap()
    print(f"[*] {len(packets)} packets loaded. Running analysis...")

    analysis_results = analyze_packets(packets)
    print_summary(analysis_results, packets)

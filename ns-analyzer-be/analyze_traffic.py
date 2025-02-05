#!/usr/bin/env python3
"""
analyze_traffic.py

Analyzes a PCAP file and classifies network traffic into attacks:
- Benign
- Port Scan
- DNS Flood
- Dictionary Attack
- SYN Flood
- ICMP Flood
- UDP Flood
- ARP Flood
"""

from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP, DNS, DHCP
from collections import Counter, defaultdict
import os

def load_pcap(filename):
    """Loads packets from a PCAP file and handles errors."""
    try:
        if not os.path.exists(filename):
            return {"error": f"File {filename} not found."}

        packets = rdpcap(filename)
        if not packets:
            return {"error": f"No packets found in {filename}."}

        return packets
    except Exception as e:
        return {"error": f"Error loading {filename}: {str(e)}"}

def analyze_packets(packets):
    """Analyzes packets and collects network traffic information."""
    protocol_counts = Counter()
    ip_counts = Counter()
    dest_ip_counts = Counter()
    port_counts = Counter()
    traffic_per_ip = defaultdict(int)

    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_counts[src_ip] += 1
            dest_ip_counts[dst_ip] += 1
            traffic_per_ip[src_ip] += len(packet)

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
        "protocol_counts": dict(protocol_counts),
        "most_active_ips": dict(ip_counts.most_common(5)),
        "most_contacted_ips": dict(dest_ip_counts.most_common(5)),
        "most_used_ports": dict(port_counts.most_common(5)),
        "traffic_per_ip": dict(traffic_per_ip),
    }

### 🚨 Attack Detection Functions 🚨 ###

def detect_port_scan(packets):
    """Detects Port Scan attacks based on SYN packets to multiple ports."""
    scan_threshold = 10
    ip_scans = defaultdict(set)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == 2:
            ip_scans[packet[IP].src].add(packet[TCP].dport)

    return {ip: len(ports) for ip, ports in ip_scans.items() if len(ports) > scan_threshold}

def detect_syn_flood(packets):
    """Detects SYN Flood attacks based on a high number of SYN packets."""
    syn_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == 2:
            syn_counts[packet[IP].src] += 1

    return {ip: count for ip, count in syn_counts.items() if count > 100}

def detect_dns_flood(packets):
    """Detects a DNS Flood attack based on excessive DNS requests."""
    dns_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNS):
            dns_counts[packet[IP].src] += 1

    return {ip: count for ip, count in dns_counts.items() if count > 50}

def detect_udp_flood(packets):
    """Detects UDP Flood attacks based on a high volume of UDP packets."""
    udp_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(UDP):
            udp_counts[packet[IP].src] += 1

    return {ip: count for ip, count in udp_counts.items() if count > 200}

def detect_icmp_flood(packets):
    """Detects ICMP Flood attacks based on excessive ICMP requests."""
    icmp_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            icmp_counts[packet[IP].src] += 1

    return {ip: count for ip, count in icmp_counts.items() if count > 100}

def detect_arp_flooding(packets):
    """Detects an ARP Flood attack by counting ARP replies per MAC."""
    arp_reply_counts = Counter()

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            arp_reply_counts[packet[ARP].hwsrc] += 1

    return {mac: count for mac, count in arp_reply_counts.items() if count > 10}

def classify_attacks(packets):
    """Classifies network traffic based on detected attacks."""
    attack_labels = {}

    port_scan = detect_port_scan(packets)
    syn_flood = detect_syn_flood(packets)
    dns_flood = detect_dns_flood(packets)
    udp_flood = detect_udp_flood(packets)
    icmp_flood = detect_icmp_flood(packets)
    arp_flood = detect_arp_flooding(packets)

    if port_scan:
        attack_labels["Port Scan"] = port_scan
    if syn_flood:
        attack_labels["SYN Flood"] = syn_flood
    if dns_flood:
        attack_labels["DNS Flood"] = dns_flood
    if udp_flood:
        attack_labels["UDP Flood"] = udp_flood
    if icmp_flood:
        attack_labels["ICMP Flood"] = icmp_flood
    if arp_flood:
        attack_labels["ARP Flood"] = arp_flood

    if not attack_labels:
        attack_labels["Benign"] = {"No threats detected": len(packets)}

    return attack_labels

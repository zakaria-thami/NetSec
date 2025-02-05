#!/usr/bin/env python3
"""
analyze_traffic.py

Analyzes a PCAP file and classifies network traffic into the following attacks:
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
import sys

INPUT_FILE = "merged_output.pcap"

def load_pcap(filename=INPUT_FILE):
    """Loads packets from a PCAP file and handles errors."""
    try:
        packets = rdpcap(filename)
        if not packets:
            print(f"[!] Error: No packets found in {filename}.")
            sys.exit(1)
        return packets
    except FileNotFoundError:
        print(f"[!] Error: The file {filename} was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error while loading {filename}: {e}")
        sys.exit(1)

def analyze_packets(packets):
    """Analyzes packets and collects network traffic information."""
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
        "ip_counts": ip_counts,
        "dest_ip_counts": dest_ip_counts,
        "top_ports": port_counts,
        "traffic_per_ip": traffic_per_ip,
        "timestamps": timestamps,
    }

### 🚨 Attack Detection Functions 🚨 ###

def detect_port_scan(packets):
    """Detects Port Scan attacks based on SYN packets to multiple ports."""
    scan_threshold = 10
    ip_scans = defaultdict(set)

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[TCP].flags == 2:  # TCP SYN flag
                ip_scans[packet[IP].src].add(packet[TCP].dport)

    return {ip: len(ports) for ip, ports in ip_scans.items() if len(ports) > scan_threshold}

def detect_syn_flood(packets):
    """Detects SYN Flood attacks based on a high number of SYN packets."""
    syn_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[TCP].flags == 2:  # TCP SYN flag
                syn_counts[packet[IP].src] += 1

    return {ip: count for ip, count in syn_counts.items() if count > 100}

def detect_dns_flood(packets):
    """Detects a DNS Flood attack based on excessive DNS requests from a single source."""
    dns_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNS):
            dns_counts[packet[IP].src] += 1

    return {ip: count for ip, count in dns_counts.items() if count > 50}

def detect_arp_flooding(packets):
    """Detects an ARP Flood attack by counting the number of ARP replies per MAC."""
    arp_reply_counts = Counter()

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            arp_reply_counts[packet[ARP].hwsrc] += 1

    return {mac: count for mac, count in arp_reply_counts.items() if count > 10}

def detect_udp_flood(packets):
    """Detects UDP Flood attacks based on a high volume of UDP packets from a single source."""
    udp_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(UDP):
            udp_counts[packet[IP].src] += 1

    return {ip: count for ip, count in udp_counts.items() if count > 200}

def detect_icmp_flood(packets):
    """Detects ICMP Flood attacks based on excessive ICMP requests from a single source."""
    icmp_counts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            icmp_counts[packet[IP].src] += 1

    return {ip: count for ip, count in icmp_counts.items() if count > 100}

def detect_dictionary_attack(packets):
    """Detects Dictionary Attacks based on multiple failed login attempts (many SYN packets to SSH/FTP)."""
    ssh_attempts = Counter()
    ftp_attempts = Counter()

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[TCP].flags == 2:  # SYN flag
                if packet[TCP].dport == 22:  # SSH
                    ssh_attempts[packet[IP].src] += 1
                elif packet[TCP].dport == 21:  # FTP
                    ftp_attempts[packet[IP].src] += 1

    return {
        "SSH": {ip: count for ip, count in ssh_attempts.items() if count > 10},
        "FTP": {ip: count for ip, count in ftp_attempts.items() if count > 10}
    }

def classify_attacks(packets):
    """Classifies network traffic based on detected attacks."""
    attack_labels = {}

    port_scan = detect_port_scan(packets)
    syn_flood = detect_syn_flood(packets)
    dns_flood = detect_dns_flood(packets)
    arp_flood = detect_arp_flooding(packets)
    udp_flood = detect_udp_flood(packets)
    icmp_flood = detect_icmp_flood(packets)
    dictionary_attack = detect_dictionary_attack(packets)

    if port_scan:
        attack_labels["Port Scan"] = port_scan
    if syn_flood:
        attack_labels["SYN Flood"] = syn_flood
    if dns_flood:
        attack_labels["DNS Flood"] = dns_flood
    if arp_flood:
        attack_labels["ARP Flood"] = arp_flood
    if udp_flood:
        attack_labels["UDP Flood"] = udp_flood
    if icmp_flood:
        attack_labels["ICMP Flood"] = icmp_flood
    if dictionary_attack["SSH"] or dictionary_attack["FTP"]:
        attack_labels["Dictionary Attack"] = dictionary_attack

    if not attack_labels:
        attack_labels["Benign"] = {"No threats detected": len(packets)}

    return attack_labels

def print_summary(results, packets):
    """Prints the analysis results with detailed counts of suspicious packets."""
    print("\n[*] Traffic Analysis:")
    for proto, count in results["protocol_counts"].items():
        print(f"  - {proto}: {count} packets")

    print("\n[*] Most Active Source IPs:")
    for ip, count in results["ip_counts"].most_common(5):
        print(f"  - {ip}: {count} packets")

    print("\n[*] Most Contacted Destination IPs:")
    for ip, count in results["dest_ip_counts"].most_common(5):
        print(f"  - {ip}: {count} packets")

    print("\n[*] Most Used Ports:")
    for port, count in results["top_ports"].most_common(5):
        print(f"  - Port {port}: {count} packets")
    print("\n[*] Traffic Classification:")
    attack_labels = classify_attacks(packets)
    for attack, details in attack_labels.items():
        print(f"  - {attack}:")
        for entity, count in details.items():
            print(f"    - {entity}: {count} packets")

if __name__ == "__main__":
    print(f"[*] Loading packets from {INPUT_FILE}...")
    packets = load_pcap()
    print(f"[*] {len(packets)} packets loaded. Running analysis...")

    analysis_results = analyze_packets(packets)
    print_summary(analysis_results, packets)

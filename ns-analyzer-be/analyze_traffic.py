#!/usr/bin/env python3
"""
analyze_traffic.py

<<<<<<< HEAD
Analyzes a PCAP file and provides detailed insights:
- Protocol analysis
- Most active IPs
- Most used ports
- Port scanning detection
- Suspicious packet detection (ARP spoofing, flooding, and unexpected replies)
=======
This script analyzes the JSON file (packets.json) containing captured network traffic.
It performs a frequency count of protocol keywords found in the raw packet data,
extracts IP addresses, and identifies the most active hosts along with protocol statistics.
It also determines protocols based on port numbers when explicit protocol names are missing.
>>>>>>> 6335f0cf0774a7a2dcd206e17daca9462e2956c2
"""

from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP, DNS, DHCP
from collections import Counter, defaultdict
import sys
<<<<<<< HEAD
=======
import re
from collections import defaultdict, Counter
>>>>>>> 6335f0cf0774a7a2dcd206e17daca9462e2956c2

INPUT_FILE = "packets.pcap"

<<<<<<< HEAD
def load_pcap(filename=INPUT_FILE):
    """Loads packets from a PCAP file."""
=======
# List of protocol keywords to search for.
PROTOCOL_KEYWORDS = [
    "FTP (Data)",
    "FTP (Control)",
    "SSH",
    "Telnet",
    "SMTP",
    "DNS",
    "DHCP (Server)",
    "DHCP (Client)",
    "TFTP",
    "HTTP",
    "POP3",
    "IMAP",
    "SNMP",
    "SNMP Trap",
    "LDAP",
    "HTTPS",
    "SMB",
    "SMTPS",
    "Syslog",
    "SMTP (Submission)",
    "LDAPS",
    "IMAPS",
    "POP3S",
    "Microsoft SQL Server",
    "Oracle Database",
    "NFS",
    "cPanel (HTTP)",
    "cPanel (HTTPS)",
    "WHM (HTTP)",
    "WHM (HTTPS)",
    "Webmail (HTTP)",
    "Webmail (HTTPS)",
    "ZooKeeper",
    "Docker (Unencrypted)",
    "Docker (TLS)",
    "Node.js",
    "MySQL",
    "RDP",
    "PostgreSQL",
    "VNC",
    "CouchDB",
    "Redis",
    "IRC",
    "HTTP Alt",
    "HTTP/HTTPS Alt",
    "HTTPS Alt",
    "PHP-FPM",
    "Prometheus",
    "Prometheus (TLS)",
    "Elasticsearch",
    "Elasticsearch (Cluster)",
    "MongoDB",
    "MongoDB (HTTP)",
    "DB2",
    "Hadoop (NameNode)",
    "Hadoop (DataNode)"
]

# Common port-to-protocol mappings
PORT_MAPPING = {
    "20": "FTP (Data)",
    "21": "FTP (Control)",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "67": "DHCP (Server)",
    "68": "DHCP (Client)",
    "69": "TFTP",
    "80": "HTTP",
    "110": "POP3",
    "143": "IMAP",
    "161": "SNMP",
    "162": "SNMP Trap",
    "389": "LDAP",
    "443": "HTTPS",
    "445": "SMB",
    "465": "SMTPS",
    "514": "Syslog",
    "587": "SMTP (Submission)",
    "636": "LDAPS",
    "993": "IMAPS",
    "995": "POP3S",
    "1433": "Microsoft SQL Server",
    "1521": "Oracle Database",
    "2049": "NFS",
    "2082": "cPanel (HTTP)",
    "2083": "cPanel (HTTPS)",
    "2086": "WHM (HTTP)",
    "2087": "WHM (HTTPS)",
    "2095": "Webmail (HTTP)",
    "2096": "Webmail (HTTPS)",
    "2181": "ZooKeeper",
    "2375": "Docker (Unencrypted)",
    "2376": "Docker (TLS)",
    "3000": "Node.js",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5900": "VNC",
    "5984": "CouchDB",
    "6379": "Redis",
    "6667": "IRC",
    "8000": "HTTP Alt",
    "8080": "HTTP/HTTPS Alt",
    "8443": "HTTPS Alt",
    "8888": "HTTP Alt",
    "9000": "PHP-FPM",
    "9090": "Prometheus",
    "9091": "Prometheus (TLS)",
    "9200": "Elasticsearch",
    "9300": "Elasticsearch (Cluster)",
    "27017": "MongoDB",
    "28017": "MongoDB (HTTP)",
    "50000": "DB2",
    "50070": "Hadoop (NameNode)",
    "50075": "Hadoop (DataNode)"
}


# Regular expressions
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
PORT_PATTERN = re.compile(r'(?<=\.)(\d{1,5})(?=\s)')  # Extracts port numbers

def load_packets(filename=INPUT_FILE):
>>>>>>> 6335f0cf0774a7a2dcd206e17daca9462e2956c2
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
<<<<<<< HEAD
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
=======
    protocol_counts = {proto: 0 for proto in PROTOCOL_KEYWORDS}
    protocol_counts["Other"] = 0
    ip_data = defaultdict(lambda: Counter())  # Dictionary to store protocol counts per IP

    for packet in packets:
        raw_data = packet.get("raw", "")
        matched_protocol = "Other"
        
        # Identify protocol and count occurrences
        for proto in PROTOCOL_KEYWORDS:
            if proto in raw_data:
                matched_protocol = proto
                break  # Assume one protocol per packet for simplicity
        
        # Check for port-based protocol detection even if 'IP' is mentioned
        ports = PORT_PATTERN.findall(raw_data)
        for port in ports:
            if port in PORT_MAPPING:
                matched_protocol = PORT_MAPPING[port]
                break
        
        protocol_counts[matched_protocol] += 1
        
        # Extract and count IP addresses with protocol association
        ips = IP_PATTERN.findall(raw_data)
        for ip in ips:
            ip_data[ip][matched_protocol] += 1

    return protocol_counts, ip_data
>>>>>>> 6335f0cf0774a7a2dcd206e17daca9462e2956c2

    return {ip: ports for ip, ports in ip_scans.items() if len(ports) > scan_threshold}

### 🔥 ARP Spoofing Detection Functions 🔥 ###

def detect_arp_spoofing(packets):
    """Detects ARP spoofing by checking IP-MAC inconsistencies."""
    arp_table = {}  # Maps IPs to MAC addresses
    spoofed_ips = {}

<<<<<<< HEAD
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
=======
    print("\n[Top 10 Active IP Addresses and Protocol Breakdown]")
    sorted_ips = sorted(ip_results.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]
    for ip, protocols in sorted_ips:
        print(f"  {ip}:")
        for proto, count in protocols.items():
            print(f"    {proto}: {count} packets")
>>>>>>> 6335f0cf0774a7a2dcd206e17daca9462e2956c2

if __name__ == "__main__":
    print(f"[*] Loading packets from {INPUT_FILE}...")
    packets = load_pcap()
    print(f"[*] {len(packets)} packets loaded. Running analysis...")

    analysis_results = analyze_packets(packets)
    print_summary(analysis_results, packets)

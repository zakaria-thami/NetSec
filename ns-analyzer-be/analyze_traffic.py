#!/usr/bin/env python3
"""
analyze_traffic.py

This script analyzes the JSON file (packets.json) containing captured network traffic.
It performs a frequency count of protocol keywords found in the raw packet data,
extracts IP addresses, and identifies the most active hosts along with protocol statistics.
It also determines protocols based on port numbers when explicit protocol names are missing.
"""

import json
import sys
import re
from collections import defaultdict, Counter

INPUT_FILE = "packets.json"

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

def main():
    print("[*] Loading captured packets from JSON...")
    packets = load_packets()
    print(f"[*] {len(packets)} packets loaded. Analyzing...")

    protocol_results, ip_results = analyze_packets(packets)

    print("[*] Analysis Results:")
    print("\n[Protocol Statistics]")
    for protocol, count in protocol_results.items():
        print(f"  {protocol}: {count} packets")

    print("\n[Top 10 Active IP Addresses and Protocol Breakdown]")
    sorted_ips = sorted(ip_results.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]
    for ip, protocols in sorted_ips:
        print(f"  {ip}:")
        for proto, count in protocols.items():
            print(f"    {proto}: {count} packets")

if __name__ == "__main__":
    main()

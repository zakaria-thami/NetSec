#!/usr/bin/env python3
# -.- coding: utf-8 -.-

import nmap
import socket
import json

def scan_network(network):
    """
    Scan the network and return a list of hosts with their IP, MAC, and hostname.
    
    :param network: The network to scan (e.g., '192.168.1.0/24')
    :return: A list of dictionaries containing host information
    """
    hosts_list = []
    nm = nmap.PortScanner()
    
    # Perform the scan
    scan_result = nm.scan(hosts=network, arguments='-sn')
    
    # Parse the scan results
    for host, info in scan_result['scan'].items():
        if info['status']['state'] == 'up':
            host_info = {
                'ip': info['addresses'].get('ipv4', 'N/A'),
                'mac': info['addresses'].get('mac', 'N/A'),
                'hostname': 'N/A'
            }
            
            # Try to resolve the hostname
            try:
                host_info['hostname'] = socket.gethostbyaddr(host_info['ip'])[0]
            except (socket.herror, socket.gaierror):
                pass
            
            hosts_list.append(host_info)
    
    return hosts_list

def save_to_json(hosts_list, filename="scan_results.json"):
    """
    Save the scanned hosts list into a JSON file.
    
    :param hosts_list: A list of dictionaries containing host information
    :param filename: Name of the JSON file to save the results
    """
    data = {
        "network_scan": hosts_list
    }
    
    with open(filename, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4)
    
    print(f"\n[+] Scan results saved to {filename}")

def display_hosts(hosts_list):
    """
    Display the list of hosts in a nicely formatted way.
    
    :param hosts_list: A list of dictionaries containing host information
    """
    print("\n{:<15} {:<20} {:<30}".format("IP Address", "MAC Address", "Hostname"))
    print("-" * 65)
    for host in hosts_list:
        print("{:<15} {:<20} {:<30}".format(host['ip'], host['mac'], host['hostname']))

if __name__ == '__main__':
    # Define the network to scan (e.g., '192.168.1.0/24')
    network = '192.168.1.0/24'
    
    # Scan the network
    hosts = scan_network(network)
    
    # Display the results
    display_hosts(hosts)
    
    # Save results to JSON
    save_to_json(hosts)

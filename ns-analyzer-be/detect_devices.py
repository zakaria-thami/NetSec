#!/usr/bin/env python3
# -.- coding: utf-8 -.-
import nmap
import socket
import json
import netifaces
import ipaddress

def get_local_network():
    """
    Detect the local network interface and return the network CIDR.
    :return: Network CIDR string (e.g., '192.168.1.0/24')
    """
    # Get default gateway interface
    default_gateway = netifaces.gateways()['default']
    if not default_gateway:
        raise RuntimeError("No default gateway found")
    
    gateway_interface = default_gateway[netifaces.AF_INET][1]
    
    # Get interface addresses
    interface_info = netifaces.ifaddresses(gateway_interface)
    if netifaces.AF_INET not in interface_info:
        raise RuntimeError(f"No IPv4 address found for interface {gateway_interface}")
    
    # Get IP address and netmask
    ip_info = interface_info[netifaces.AF_INET][0]
    ip_address = ip_info['addr']
    netmask = ip_info['netmask']
    
    # Calculate network CIDR
    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    return str(network)

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

def save_to_json(hosts_list, filename="devices.json"):
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
        print("{:<15} {:<20} {:<30}".format(
            host['ip'], host['mac'], host['hostname']))

if __name__ == '__main__':
    try:
        # Automatically detect the network
        network = get_local_network()
        print(f"[+] Detected network: {network}")
        
        # Scan the network
        print("[+] Starting network scan...")
        hosts = scan_network(network)
        
        # Display the results
        display_hosts(hosts)
        
        # Save results to JSON
        save_to_json(hosts)
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        exit(1)
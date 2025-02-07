#!/usr/bin/env python3
# -.- coding: utf-8 -.-
import json
import os

import nmap
import socket
import netifaces
import ipaddress

DEVICES_FILE = "devices.json"
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

def scan_network():
    """
    Scan the network and return a list of hosts with their IP, MAC, and hostname.
    :param network: The network to scan (e.g., '192.168.1.0/24')
    :return: A list of dictionaries containing host information
    """
    network=get_local_network()
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



class DeviceManager:
    """Handles loading, saving, and retrieving reports."""
    
    @staticmethod
    def load_devices():
        """Loads existing devices from the JSON file."""
        if not os.path.exists(DEVICES_FILE):
            return {}

        try:
            with open(DEVICES_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {}  # Return an empty dictionary if JSON is corrupted

    """ @staticmethod
    def save_devices():
        
        reports = DeviceManager.load_devices()
        reports[report_id] = data
        with open(DEVICES_FILE, "w") as file:
            json.dump(reports, file, indent=4)
    """

    @staticmethod
    def save_devices(devices_list):
        data = {"network_scan": devices_list}
        
        try:
            with open(self.devices_file, "w") as file:
                json.dump(data, file, indent=4)
            return True
        except (IOError, json.JSONEncodeError) as e:
            print(f"Error saving devices: {str(e)}")
            return False
    
  
#!/usr/bin/env python3
# -.- coding: utf-8 -.-

import json  # Import json for reading/writing JSON files
import os  # Import os for interacting with the file system

import nmap  # Import nmap for network scanning
import socket  # Import socket for resolving hostnames
import netifaces  # Import netifaces for accessing network interfaces
import ipaddress  # Import ipaddress for handling network addresses

DEVICES_FILE = "devices.json"  # File name where device data will be stored

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
    network = get_local_network()  # Get the local network CIDR
    hosts_list = []  # Initialize an empty list to store hosts' information
    nm = nmap.PortScanner()  # Initialize nmap PortScanner

    # Perform the network scan using nmap with '-sn' argument (ping scan)
    scan_result = nm.scan(hosts=network, arguments='-sn')

    # Parse the scan results to extract useful host data
    for host, info in scan_result['scan'].items():
        if info['status']['state'] == 'up':  # Only consider hosts that are up
            host_info = {
                'ip': info['addresses'].get('ipv4', 'N/A'),  # Get IP address or 'N/A' if not found
                'mac': info['addresses'].get('mac', 'N/A'),  # Get MAC address or 'N/A' if not found
                'hostname': 'N/A'  # Default hostname as 'N/A'
            }
            
            # Try to resolve the hostname from the IP address
            try:
                host_info['hostname'] = socket.gethostbyaddr(host_info['ip'])[0]
            except (socket.herror, socket.gaierror):
                pass  # Ignore errors if hostname resolution fails

            # Add the host's information to the list
            hosts_list.append(host_info)
    
    return hosts_list  # Return the list of hosts

# DeviceManager class handles loading, saving, and retrieving device reports
class DeviceManager:
    """Handles loading, saving, and retrieving reports."""
    
    @staticmethod
    def load_devices():
        """Loads existing devices from the JSON file."""
        if not os.path.exists(DEVICES_FILE):  # If the devices file doesn't exist, return an empty dictionary
            return {}

        try:
            # Try to open the file and load its JSON data
            with open(DEVICES_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            # If JSON is corrupted, return an empty dictionary
            return {}

    """ 
    @staticmethod
    def save_devices():
        This method is commented out. The purpose is to save device data into the file.
        """

    @staticmethod
    def save_devices(devices_list):
        """Saves the list of devices to a JSON file."""
        data = {"network_scan": devices_list}  # Wrap the devices list in a dictionary
        
        try:
            # Try to open the devices file and save the data
            with open(self.devices_file, "w") as file:
                json.dump(data, file, indent=4)
            return True  # Return True if successful
        except (IOError, json.JSONEncodeError) as e:
            # If an error occurs during saving, print the error and return False
            print(f"Error saving devices: {str(e)}")
            return False

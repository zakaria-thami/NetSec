import subprocess
import psutil
import json
import re

def get_default_gateway():
    """Fetch the default gateway."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "default via" in line:
                return line.split()[2]  # Extract gateway IP
    except Exception as e:
        return str(e)
    return "Not found"

def get_mac_address(interface="eth0"):
    """Fetch the MAC address of the specified network interface."""
    try:
        result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
        match = re.search(r"link/ether ([0-9a-fA-F:]+)", result.stdout)
        return match.group(1) if match else "Not found"
    except Exception as e:
        return str(e)



def get_open_ports():
    """Fetch a list of currently open ports."""
    open_ports = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                open_ports.append(conn.laddr.port)
    except Exception as e:
        return str(e)
    return open_ports

def get_network_info():
    """Collect all network details into a dictionary."""
    network_data = {
        "default_gateway": get_default_gateway(),
        "mac_address": get_mac_address(),
        "open_ports": get_open_ports(),
    }
    return network_data

if __name__ == "__main__":
    print(json.dumps(get_network_info(), indent=4))

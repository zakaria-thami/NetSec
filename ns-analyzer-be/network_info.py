import subprocess  # Import subprocess for running shell commands
import psutil  # Import psutil to get network connection information
import json  # Import json for formatting the output
import re  # Import re for regular expression matching

# Function to fetch the default gateway of the system
def get_default_gateway():
    """Fetch the default gateway."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)  # Run the 'ip route' command
        for line in result.stdout.split("\n"):  # Split the output by newlines
            if "default via" in line:  # Look for the default gateway in the output
                return line.split()[2]  # Extract and return the gateway IP
    except Exception as e:
        return str(e)  # Return the error message if something goes wrong
    return "Not found"  # Return 'Not found' if no gateway is detected

# Function to fetch the MAC address of the specified network interface
def get_mac_address(interface="eth0"):
    """Fetch the MAC address of the specified network interface."""
    try:
        result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)  # Run the 'ip link' command for the given interface
        match = re.search(r"link/ether ([0-9a-fA-F:]+)", result.stdout)  # Use regular expression to match the MAC address
        return match.group(1) if match else "Not found"  # Return the MAC address if found, otherwise 'Not found'
    except Exception as e:
        return str(e)  # Return the error message if something goes wrong

# Function to fetch a list of currently open ports
def get_open_ports():
    """Fetch a list of currently open ports."""
    open_ports = []  # List to store open ports
    try:
        for conn in psutil.net_connections(kind="inet"):  # Iterate over network connections
            if conn.status == "LISTEN":  # Check if the connection is in 'LISTEN' state
                open_ports.append(conn.laddr.port)  # Add the port number to the list
    except Exception as e:
        return str(e)  # Return the error message if something goes wrong
    return open_ports  # Return the list of open ports

# Function to collect all network details into a dictionary
def get_network_info():
    """Collect all network details into a dictionary."""
    network_data = {
        "default_gateway": get_default_gateway(),  # Get default gateway
        "mac_address": get_mac_address(),  # Get MAC address
        "open_ports": get_open_ports(),  # Get open ports
    }
    return network_data  # Return the collected network information

# Main block that runs when the script is executed directly
if __name__ == "__main__":
    print(json.dumps(get_network_info(), indent=4))  # Print the network information as a nicely formatted JSON

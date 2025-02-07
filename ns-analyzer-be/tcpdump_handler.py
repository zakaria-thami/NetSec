#!/usr/bin/env python3
"""
tcpdump_handler.py

This script runs tcpdump to capture network traffic and saves packets in a dynamically provided PCAP file.
"""

import subprocess  # Import subprocess for running system commands
import sys  # Import sys for system-specific parameters and functions
import signal  # Import signal to handle interruptions gracefully




CAPTURE_DURATION = 30 # Duration (in seconds) for capturing network traffic
DEFAULT_OUTPUT_FILE = "packets.pcap"  # Name of the file where captured packets will be saved

# Signal handler for gracefully handling keyboard interruptions (Ctrl+C)
def signal_handler(sig, frame):
    print("\n[!] Interrupted. Exiting tcpdump capture.")  # Print message on interrupt
    sys.exit(0)  # Exit the script cleanly

# Function to capture network traffic using tcpdump
def capture_traffic(output_file, duration=CAPTURE_DURATION):
    
    print(f"[*] Starting tcpdump capture for {duration} seconds...")  # Inform the user about the capture duration

    # tcpdump command to capture network traffic on eth0 and write to the OUTPUT_FILE
    tcpdump_cmd = ["tcpdump", "-i", "eth0", "-w", output_file]

    try:
        # Start tcpdump process
        process = subprocess.Popen(tcpdump_cmd)
        # Wait for the capture to complete or until the timeout occurs
        process.wait(timeout=duration)
        # Terminate the tcpdump process after the duration
        process.terminate()
        print(f"[*] Capture complete. PCAP saved to {output_file}")  # Inform the user that capture is complete
        
    except subprocess.TimeoutExpired:
        # Handle case where the capture time expires
        print(f"[*] Capture duration reached. Stopping tcpdump.")
        process.terminate()
    except KeyboardInterrupt:
        # Handle case where the user interrupts the process with Ctrl+C
        print("\n[!] User interruption. Terminating tcpdump.")
        process.terminate()
    except Exception as e:
        # Handle any unexpected errors
        print(f"[!] Error running tcpdump: {e}")
        sys.exit(1)  # Exit the script with an error status



# Main function to set up signal handling and start the traffic capture
def main():
    signal.signal(signal.SIGINT, signal_handler)  # Set up signal handler for interrupts (Ctrl+C)

    # Read filename from arguments
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    else:
        output_file = DEFAULT_OUTPUT_FILE

    capture_traffic(output_file)


# If the script is run directly (not imported), execute the main function
if __name__ == "__main__":
    main()

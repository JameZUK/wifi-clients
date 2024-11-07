#!/usr/bin/env python3

from scapy.all import *
from collections import defaultdict
import threading
import signal
import sys
import argparse
import time

# Dictionary to store BSSID -> SSID mapping
bssid_ssid_map = {}
# Dictionary to store SSID -> set of client MAC addresses
network_clients = defaultdict(set)
# Dictionary to store BSSID -> Signal Strength
bssid_signal_strength = {}

# Global variable to control sniffing
sniffing = True

# Function to handle packet processing
def packet_handler(packet):
    # (Same as before)
    # [Omitted for brevity; use the same packet_handler function from the previous script]

# Function to stop sniffing
def stop_sniffing(signum, frame):
    global sniffing
    sniffing = False
    print("\nStopping scan...")

def display_results():
    print("\n{:<30} {:<15} {:<15}".format('SSID', 'Clients', 'Signal(dBm)'))
    print("-" * 60)
    for ssid, clients in network_clients.items():
        # Find BSSIDs corresponding to the SSID
        bssids = [bssid for bssid, s in bssid_ssid_map.items() if s == ssid]
        # Get the signal strength for the first BSSID found
        signal_strength = bssid_signal_strength.get(bssids[0], 'N/A') if bssids else 'N/A'
        print("{:<30} {:<15} {:<15}".format(ssid, len(clients), signal_strength))
    print("\nPress Ctrl+C to stop the scan.\n")

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode (e.g., wlan0mon)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    args = parser.parse_args()

    interface = args.interface
    interval = args.interval

    print(f"Starting WiFi scan on interface {interface}. Press Ctrl+C to stop.")

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, stop_sniffing)

    # Start sniffing packets in a separate thread
    def sniff_packets():
        while sniffing:
            sniff(iface=interface, prn=packet_handler, timeout=1, store=0)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

    # Periodically display results
    try:
        while sniffing:
            time.sleep(interval)
            display_results()
    except KeyboardInterrupt:
        pass

    sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
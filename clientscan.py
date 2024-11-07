#!/usr/bin/env python3

from scapy.all import *
from collections import defaultdict
import threading
import signal
import sys

# Dictionary to store SSID -> set of client MAC addresses
network_clients = defaultdict(set)
# Dictionary to store SSID signal strengths
network_signals = {}

# Function to handle packet processing
def packet_handler(packet):
    # Check for Beacon and Probe Response frames (to get SSIDs)
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr2
        # Signal strength
        signal = packet.dBm_AntSignal
        network_signals[ssid] = signal

    # Check for Data frames to find clients associated with APs
    if packet.haslayer(Dot11):
        if packet.type == 2:
            addr1 = packet.addr1  # Destination MAC
            addr2 = packet.addr2  # Source MAC
            addr3 = packet.addr3  # BSSID

            # Check if the packet is from a client to an AP or vice versa
            if addr1 and addr2 and addr3:
                # Assuming addr1 is the AP and addr2 is the client
                # Or vice versa, depending on the ToDS and FromDS bits
                # For simplicity, we consider both possibilities
                for ssid, signal in network_signals.items():
                    network_clients[ssid].add(addr1)
                    network_clients[ssid].add(addr2)
                    network_clients[ssid].add(addr3)

# Function to stop sniffing on signal interrupt
def stop_sniff(signal, frame):
    print("\nScan complete. Processing results...\n")
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, stop_sniff)

def main():
    print("Starting WiFi scan. Press Ctrl+C to stop.")

    # Start sniffing packets
    sniff(iface="wlan0", prn=packet_handler, store=0)

    # After sniffing is stopped, display the results
    print("{:<30} {:<15} {:<10}".format('SSID', 'Clients', 'Signal(dBm)'))
    print("-" * 60)
    for ssid, clients in network_clients.items():
        signal = network_signals.get(ssid, 'N/A')
        print("{:<30} {:<15} {:<10}".format(ssid, len(clients), signal))

if __name__ == "__main__":
    main()
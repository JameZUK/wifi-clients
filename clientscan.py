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
# Global variable to control debug output
debug_mode = False

# Function to handle packet processing
def packet_handler(packet):
    # Debugging output to confirm packet capture
    if debug_mode:
        print(f"Captured packet: {packet.summary()}")

    # Check for Beacon and Probe Response frames (to get SSIDs)
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr2
        # Signal strength
        signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
        if debug_mode:
            print(f"Detected SSID: {ssid}, BSSID: {bssid}, Signal: {signal}")
        bssid_ssid_map[bssid] = ssid
        bssid_signal_strength[bssid] = signal

    # Check for Data frames to find clients associated with APs
    if packet.haslayer(Dot11) and packet.type == 2 and packet.subtype == 0:  # Data frames
        addr1 = packet.addr1  # Receiver MAC
        addr2 = packet.addr2  # Transmitter MAC
        addr3 = packet.addr3  # BSSID

        # ToDS and FromDS bits
        to_ds = packet.FCfield & 0x1 != 0
        from_ds = packet.FCfield & 0x2 != 0

        if to_ds and not from_ds:
            # Data frame from station to AP
            client_mac = addr2
            bssid = addr1
        elif from_ds and not to_ds:
            # Data frame from AP to station
            client_mac = addr1
            bssid = addr2
        elif not from_ds and not to_ds:
            # Data frame between stations in the same BSS
            client_mac = addr2
            bssid = addr3
        else:
            # WDS frame or other
            return

        # Map client to SSID using BSSID
        ssid = bssid_ssid_map.get(bssid)
        if ssid:
            if debug_mode:
                print(f"Associating client {client_mac} with SSID {ssid}")
            network_clients[ssid].add(client_mac)

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
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    global debug_mode
    debug_mode = args.debug

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
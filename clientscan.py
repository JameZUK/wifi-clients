#!/usr/bin/env python3

from pywifi import PyWiFi, const
from pywifi import Profile
from scapy.all import *
from collections import defaultdict
import threading
import signal
import sys
import argparse
import time
from datetime import datetime

# Dictionaries for SSID and client tracking
bssid_ssid_map = {}
network_clients = defaultdict(set)
bssid_signal_strength = {}

# Global variables to control scanning and debugging
sniffing = True
debug_mode = False
wifi_interface = None

# Function to initialize the WiFi interface using pywifi
def initialize_wifi_interface(interface_name):
    wifi = PyWiFi()
    iface = None
    for iface in wifi.interfaces():
        if iface.name() == interface_name:
            return iface
    raise Exception(f"Interface {interface_name} not found. Ensure it's in monitor mode.")

# Function to perform a faster network scan using pywifi
def fast_scan_for_ssids(iface):
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Performing fast scan for SSIDs...")
    iface.scan()  # Start scanning
    time.sleep(2)  # Wait for scan results to be available (may vary by OS)
    scan_results = iface.scan_results()
    
    active_channels = set()
    for network in scan_results:
        ssid = network.ssid
        bssid = network.bssid
        channel = network.freq  # Frequency in MHz
        signal = network.signal  # Signal strength in dBm

        # Convert frequency to channel number for 2.4GHz and 5GHz bands
        if 2412 <= channel <= 2472:  # 2.4 GHz band
            channel = (channel - 2407) // 5
        elif 5170 <= channel <= 5825:  # 5 GHz band
            channel = (channel - 5000) // 5

        active_channels.add(channel)
        bssid_ssid_map[bssid] = ssid
        bssid_signal_strength[bssid] = signal
        if debug_mode:
            print(f"Found SSID '{ssid}' on channel {channel} with BSSID {bssid}")

    return list(active_channels)

# Function to process packets and track clients
def packet_handler(packet):
    if packet.type == 1:  # Ignore Control frames
        return

    # Process SSID information from Beacon/Probe Response frames
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr2
        signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
        bssid_ssid_map[bssid] = ssid
        bssid_signal_strength[bssid] = signal

    # Process Data frames to find clients associated with APs
    if packet.haslayer(Dot11) and packet.type == 2:  # Data frame
        addr1, addr2, addr3 = packet.addr1, packet.addr2, packet.addr3
        to_ds, from_ds = packet.FCfield & 0x1 != 0, packet.FCfield & 0x2 != 0

        # Determine direction to map client/AP based on ToDS/FromDS
        if to_ds and not from_ds:
            client_mac, bssid = addr2, addr1
        elif from_ds and not to_ds:
            client_mac, bssid = addr1, addr2
        elif not from_ds and not to_ds:
            client_mac, bssid = addr2, addr3
        else:
            return

        ssid = bssid_ssid_map.get(bssid)
        if ssid:
            network_clients[ssid].add(client_mac)

# Function to stop sniffing
def stop_sniffing(signum, frame):
    global sniffing
    sniffing = False
    print("\nStopping scan...")

def display_results():
    print("\nCurrent Results:")
    for ssid, clients in network_clients.items():
        signal_strength = bssid_signal_strength.get(next(iter(clients), None), 'N/A')
        print(f"SSID: {ssid}, Clients: {len(clients)}, Signal: {signal_strength}")

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface for pywifi (e.g., wlan0)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    global debug_mode, wifi_interface
    debug_mode = args.debug

    interface_name = args.interface
    interval = args.interval

    print(f"Starting WiFi scan on interface {interface_name}. Press Ctrl+C to stop.")

    # Initialize pywifi interface
    wifi_interface = initialize_wifi_interface(interface_name)

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, stop_sniffing)

    # Start sniffing packets in a separate thread
    def sniff_packets():
        while sniffing:
            sniff(iface=interface_name, prn=packet_handler, timeout=1, store=0)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

    # Periodically update the list of active channels based on available SSIDs
    while sniffing:
        active_channels = fast_scan_for_ssids(wifi_interface)
        display_results()
        time.sleep(interval)

    sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
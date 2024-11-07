#!/usr/bin/env python3

from scapy.all import *
from collections import defaultdict
import threading
import signal
import sys
import argparse
import time
import subprocess
import re
from datetime import datetime

# Dictionaries for SSID and client tracking
bssid_ssid_map = {}
network_clients = defaultdict(set)
bssid_signal_strength = {}
ssid_channels = defaultdict(set)  # Track channels for each SSID

# Global variables to control scanning and debugging
sniffing = True
debug_mode = False
available_channels = []

# Function to retrieve supported channels from the WiFi interface
def get_supported_channels(interface):
    global available_channels
    try:
        # Run iwlist to get channel information
        iwlist_output = subprocess.check_output(['iwlist', interface, 'channel'], text=True)
        # Find all channel numbers in the iwlist output
        available_channels = re.findall(r'Channel (\d+)', iwlist_output)
        available_channels = list(map(int, available_channels))  # Convert to integers
        print(f"Supported channels for {interface}: {available_channels}")
    except subprocess.CalledProcessError:
        print(f"Failed to retrieve channels for interface {interface}. Ensure it's in monitor mode.")
        sys.exit(1)

# Function to initialize interface in monitor mode
def set_monitor_mode(interface):
    subprocess.call(['sudo', 'ifconfig', interface, 'down'])
    subprocess.call(['sudo', 'iwconfig', interface, 'mode', 'monitor'])
    subprocess.call(['sudo', 'ifconfig', interface, 'up'])
    print(f"Interface {interface} set to monitor mode.")

# Function to perform a quick scan to detect available SSIDs and channels
def passive_scan_for_ssids(interface):
    active_channels = set()
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning for active SSIDs...")

    for channel in available_channels:
        # Switch to the channel
        subprocess.call(['iwconfig', interface, 'channel', str(channel)])
        time.sleep(0.2)  # Short dwell time for faster scanning

        # Capture packets to detect SSIDs
        packets = sniff(iface=interface, timeout=1, count=50, store=True)
        for packet in packets:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = packet[Dot11].addr2
                if ssid:
                    active_channels.add(channel)
                    bssid_ssid_map[bssid] = ssid
                    bssid_signal_strength[bssid] = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
                    ssid_channels[ssid].add(channel)  # Track channels per SSID
                    if debug_mode:
                        print(f"Found SSID '{ssid}' on channel {channel}")
    if debug_mode:
        print(f"Active channels detected: {active_channels}")
    return list(active_channels)

# Function to switch WiFi channels for main scan
def hop_channel(interface, channels):
    for channel in channels:
        if not sniffing:
            break
        subprocess.call(['iwconfig', interface, 'channel', str(channel)])
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning on Channel {channel}")
        time.sleep(0.5)  # Short dwell time per channel for real-time responsiveness

# Function to handle packet processing and track clients
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
        channels = sorted(ssid_channels[ssid])  # Retrieve channels for this SSID
        signal_strength = bssid_signal_strength.get(next(iter(clients), None), 'N/A')
        print(f"SSID: {ssid}, Channels: {', '.join(map(str, channels))}, Clients: {len(clients)}, Signal: {signal_strength}")

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode (e.g., wlan0mon)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    parser.add_argument('--scan_interval', type=int, default=30, help='Interval in seconds for rescanning SSIDs')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    global debug_mode
    debug_mode = args.debug

    interface = args.interface
    interval = args.interval
    scan_interval = args.scan_interval  # SSID scan interval

    print(f"Starting WiFi scan on interface {interface}. Press Ctrl+C to stop.")

    # Set interface to monitor mode
    set_monitor_mode(interface)

    # Get supported channels from the interface
    get_supported_channels(interface)

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, stop_sniffing)

    # Start sniffing packets in a separate thread
    def sniff_packets():
        while sniffing:
            sniff(iface=interface, prn=packet_handler, timeout=1, store=0)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

    # Periodically update the list of active channels based on available SSIDs
    last_scan_time = 0
    while sniffing:
        current_time = time.time()
        if current_time - last_scan_time >= scan_interval:
            active_channels = passive_scan_for_ssids(interface)
            last_scan_time = current_time
        if not active_channels:
            active_channels = available_channels  # Fallback to all channels if none detected
        hop_channel(interface, active_channels)
        display_results()
        time.sleep(interval)

    sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
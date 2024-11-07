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
import logging
from datetime import datetime

# Dictionary to store BSSID -> SSID mapping
bssid_ssid_map = {}
# Dictionary to store SSID -> set of client MAC addresses
network_clients = defaultdict(set)
# Dictionary to store BSSID -> Signal Strength
bssid_signal_strength = {}

# Global variables to control sniffing and debugging
sniffing = True
debug_mode = False
channels = []

# Initialize logging
def setup_logging():
    logging.basicConfig(
        filename="wifi_scan.log",
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logging.info("Starting WiFi scanner...")

# Function to get supported channels from the interface
def get_supported_channels(interface):
    global channels
    try:
        # Run iwlist to get channel information
        iwlist_output = subprocess.check_output(['iwlist', interface, 'channel'], text=True)
        # Find all channel numbers in the iwlist output
        channels = re.findall(r'Channel (\d+)', iwlist_output)
        channels = list(map(int, channels))  # Convert to integers
        if debug_mode:
            print(f"Supported channels: {channels}")
        else:
            logging.info(f"Supported channels: {channels}")
    except subprocess.CalledProcessError:
        print(f"Failed to retrieve channels for interface {interface}. Ensure it's in monitor mode.")
        sys.exit(1)

# Function to switch WiFi channels
def hop_channel(interface):
    for channel in channels:
        if not sniffing:  # Stop hopping if sniffing has stopped
            break
        subprocess.call(['iwconfig', interface, 'channel', str(channel)])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if debug_mode:
            print(f"Switched to channel {channel}")
        else:
            logging.info(f"Switched to channel {channel} at {timestamp}")
        time.sleep(1)  # Pause on each channel for 1 second

# Function to handle packet processing
def packet_handler(packet):
    # Ignore Control frames and focus on Beacon, Probe Response, and Data frames
    if packet.type == 1:  # Type 1 = Control frame
        if debug_mode:
            print("Ignoring Control frame.")
        return

    # Debugging output to confirm packet capture type
    if debug_mode:
        frame_type = "Management" if packet.type == 0 else "Data" if packet.type == 2 else "Unknown"
        print(f"Captured {frame_type} frame: {packet.summary()}")

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
    if packet.haslayer(Dot11) and packet.type == 2:  # Data frame
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
    logging.info("Stopping scan...")

def display_results():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not debug_mode:
        logging.info(f"Results at {timestamp}:")
    print("\n{:<30} {:<15} {:<15}".format('SSID', 'Clients', 'Signal(dBm)'))
    print("-" * 60)
    for ssid, clients in network_clients.items():
        # Find BSSIDs corresponding to the SSID
        bssids = [bssid for bssid, s in bssid_ssid_map.items() if s == ssid]
        # Get the signal strength for the first BSSID found
        signal_strength = bssid_signal_strength.get(bssids[0], 'N/A') if bssids else 'N/A'
        print("{:<30} {:<15} {:<15}".format(ssid, len(clients), signal_strength))
        # Log each SSID and client count
        if not debug_mode:
            logging.info(f"SSID: {ssid}, Clients: {len(clients)}, Signal(dBm): {signal_strength}")
    print("\nPress Ctrl+C to stop the scan.\n")

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode (e.g., wlan0mon)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    global debug_mode
    debug_mode = args.debug

    # Setup logging
    setup_logging()

    interface = args.interface
    interval = args.interval

    print(f"Starting WiFi scan on interface {interface}. Press Ctrl+C to stop.")
    logging.info(f"Starting WiFi scan on interface {interface}.")

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

    # Channel hopping loop
    while sniffing:
        hop_channel(interface)

    sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
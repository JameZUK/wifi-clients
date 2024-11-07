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
bssid_signal_strength = defaultdict(lambda: defaultdict(int))  # Track signal by SSID and channel
ssid_channels = defaultdict(set)  # Track channels for each SSID

# Global variables to control scanning and debugging
sniffing = True
debug_mode = False
selected_channels = [1, 6, 11, 13]  # Reduced set for testing stability
channel_lock = threading.Lock()  # Lock to coordinate channel switching
interface = None  # Global variable to hold interface name
sniff_socket = None  # To manage Scapy's sniffing socket

# Function to retrieve supported channels from the WiFi interface
def get_supported_channels(interface):
    global selected_channels
    try:
        # Run iwlist to get channel information
        iwlist_output = subprocess.check_output(['iwlist', interface, 'channel'], text=True)
        # Find all channel numbers in the iwlist output
        available_channels = re.findall(r'Channel (\d+)', iwlist_output)
        available_channels = list(map(int, available_channels))  # Convert to integers
        print(f"Available channels for {interface}: {available_channels}")
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
    global sniffing
    active_channels = set()
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning for active SSIDs...")

    for channel in selected_channels:
        if not sniffing:
            break  # Stop scanning if sniffing flag is set to False

        # Switch to the channel, with lock to prevent socket errors during sniffing
        with channel_lock:
            subprocess.call(['iwconfig', interface, 'channel', str(channel)])
        time.sleep(2)  # Ensure stability before resuming sniffing

        # Capture packets to detect SSIDs
        packets = sniff(iface=interface, timeout=2, count=50, store=True)
        for packet in packets:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                # Replace empty SSID with <HIDDEN>
                if not ssid:
                    ssid = "<HIDDEN>"
                bssid = packet[Dot11].addr2
                signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100  # Default low if not detected
                if ssid:
                    active_channels.add(channel)
                    bssid_ssid_map[bssid] = ssid
                    ssid_channels[ssid].add(channel)  # Track all channels the SSID appears on
                    bssid_signal_strength[ssid][channel] = max(bssid_signal_strength[ssid][channel], signal)
                    if debug_mode:
                        print(f"Found SSID '{ssid}' on channel {channel} with signal {signal} dBm")
    if debug_mode:
        print(f"Active channels detected: {active_channels}")
    return list(active_channels)

# Function to switch WiFi channels in main scan and reset socket
def hop_channel(interface, channels):
    global sniff_socket
    for channel in channels:
        if not sniffing:
            break

        # Stop the existing socket before switching channels
        if sniff_socket:
            sniff_socket.close()
            sniff_socket = None

        # Switch to the next channel with lock to prevent socket errors during sniffing
        with channel_lock:
            subprocess.call(['iwconfig', interface, 'channel', str(channel)])
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning on Channel {channel}")
        time.sleep(5)  # Longer dwell time per channel for stability

# Function to handle packet processing and track clients
def packet_handler(packet):
    if not sniffing:
        return  # Stop processing if sniffing flag is set to False
    if packet.type == 1:  # Ignore Control frames
        return

    # Process SSID information from Beacon/Probe Response frames
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        # Replace empty SSID with <HIDDEN>
        if not ssid:
            ssid = "<HIDDEN>"
        bssid = packet[Dot11].addr2
        signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100
        bssid_ssid_map[bssid] = ssid
        bssid_signal_strength[ssid][packet[Dot11].Channel] = signal

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
    global sniffing, sniff_socket
    sniffing = False
    print("\nStopping scan...")
    if sniff_socket:
        sniff_socket.close()

def display_results():
    print("\nCurrent Results:")
    for ssid, clients in network_clients.items():
        channels = sorted(ssid_channels[ssid])
        primary_channel = max(bssid_signal_strength[ssid], key=bssid_signal_strength[ssid].get)  # Channel with strongest signal
        signal_strength = bssid_signal_strength[ssid][primary_channel]
        print(f"SSID: {ssid}, Primary Channel: {primary_channel}, Other Channels: {', '.join(map(str, channels))}, Clients: {len(clients)}, Signal: {signal_strength} dBm")

def sniff_packets():
    global sniffing, sniff_socket
    while sniffing:
        try:
            # Close and reinitialize the socket for each sniffing attempt
            if sniff_socket:
                sniff_socket.close()
            sniff_socket = L2ListenSocket(iface=interface)
            
            # Capture packets with the reinitialized socket
            with channel_lock:
                sniff(opened_socket=sniff_socket, prn=packet_handler, timeout=5, store=0)
        except Exception as e:
            print(f"Socket error: {e}. Retrying in 5 seconds...")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode (e.g., wlan0mon)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    parser.add_argument('--scan_interval', type=int, default=30, help='Interval in seconds for rescanning SSIDs')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    global debug_mode, sniffing, interface
    debug_mode = args.debug

    interface = args.interface
    interval = args.interval
    scan_interval = args.scan_interval  # SSID scan interval

    print(f"Starting WiFi scan on interface {interface}. Press Ctrl+C to stop.")

    # Set interface to monitor mode
    set_monitor_mode(interface)

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, stop_sniffing)

    # Start the sniffing thread
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Main loop for scanning and display
    last_scan_time = 0
    try:
        while sniffing:
            current_time = time.time()
            if current_time - last_scan_time >= scan_interval:
                active_channels = passive_scan_for_ssids(interface)
                last_scan_time = current_time
            if not active_channels:
                active_channels = selected_channels  # Fallback to pre-selected channels if none detected
            hop_channel(interface, active_channels)
            display_results()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Exiting gracefully...")

    # Ensure all threads and sockets are properly closed
    sniffing = False
    if sniff_socket:
        sniff_socket.close()
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
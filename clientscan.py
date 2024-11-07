#!/usr/bin/env python3

from scapy.all import *
from collections import defaultdict
import threading
import signal
import sys
import argparse
import time
from datetime import datetime
import logging
import pyric
import pyric.pyw as pyw
from pyric.utils import channels  # Import channels module

# Dictionaries for SSID and client tracking
bssid_ssid_map = {}
network_clients = defaultdict(set)
bssid_signal_strength = defaultdict(lambda: defaultdict(int))  # Track signal by SSID and channel
ssid_channels = defaultdict(set)  # Track channels for each SSID

# Global variables to control scanning and debugging
sniffing = True
debug_mode = False
selected_channels = []  # To be populated dynamically
channel_lock = threading.Lock()  # Lock to coordinate channel switching
interface = None  # Global variable to hold interface name

# Function to convert frequency to channel number
def freq_to_channel(freq):
    # 2.4 GHz band
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    elif freq == 2484:
        return 14
    # 5 GHz band
    elif 5000 <= freq <= 6000:
        return (freq - 5000) // 5
    else:
        return None

# Corrected function to retrieve supported channels using PyRIC
def get_supported_channels(interface):
    global selected_channels
    try:
        # Get the wireless interface
        iface = pyw.getcard(interface)
        # Get the list of supported frequencies
        frequencies = pyw.devfreqs(iface)
        # Map frequencies to channels
        for freq in frequencies:
            channel = channels.rf2ch(freq)
            # Include channels in 2.4 GHz and 5 GHz bands
            if channel and (1 <= channel <= 14 or 36 <= channel <= 165):
                selected_channels.append(channel)
        # Remove duplicates and sort
        selected_channels = sorted(set(selected_channels))
        print(f"Available channels for {interface}: {selected_channels}")
    except pyric.error as e:
        print(f"Failed to retrieve channels for interface {interface}: {e}")
        sys.exit(1)

# Function to initialize interface in monitor mode
def set_monitor_mode(interface):
    try:
        iface = pyw.getcard(interface)
        pyw.down(iface)
        pyw.modeset(iface, 'monitor')
        pyw.up(iface)
        print(f"Interface {interface} set to monitor mode.")
    except pyric.error as e:
        print(f"Failed to set {interface} to monitor mode: {e}")
        sys.exit(1)

# Function to perform a quick scan to detect available SSIDs and channels
def passive_scan_for_ssids(interface, sniff_timeout, sniff_count):
    global sniffing
    active_channels = set()
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning for active SSIDs...")

    for channel in selected_channels:
        if not sniffing:
            break  # Stop scanning if sniffing flag is set to False

        # Switch to the channel, with lock to prevent socket errors during sniffing
        with channel_lock:
            try:
                iface = pyw.getcard(interface)
                pyw.chset(iface, channel)
            except pyric.error as e:
                if debug_mode:
                    print(f"Failed to set channel {channel} on interface {interface}: {e}")
                continue
        time.sleep(0.5)  # Reduced sleep for faster scanning

        # Capture packets to detect SSIDs
        try:
            packets = sniff(iface=interface, timeout=sniff_timeout, count=sniff_count, store=True)
        except Exception as e:
            if debug_mode:
                print(f"Error during sniffing on channel {channel}: {e}")
            continue  # Skip to the next channel

        for packet in packets:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') or "<HIDDEN>"
                bssid = packet[Dot11].addr2
                # Extract signal strength and channel
                if packet.haslayer(RadioTap):
                    radiotap = packet[RadioTap]
                    signal = radiotap.dBm_AntSignal if hasattr(radiotap, 'dBm_AntSignal') else -100
                    freq = radiotap.ChannelFrequency if hasattr(radiotap, 'ChannelFrequency') else None
                    channel = freq_to_channel(freq) if freq else None
                else:
                    signal = -100
                    channel = None
                if ssid and channel:
                    active_channels.add(channel)
                    bssid_ssid_map[bssid] = ssid
                    ssid_channels[ssid].add(channel)
                    # Update signal strength only if the new signal is stronger
                    if signal > bssid_signal_strength[ssid].get(channel, -100):
                        bssid_signal_strength[ssid][channel] = signal
                        if debug_mode:
                            print(f"Updated signal strength for SSID '{ssid}' on channel {channel}: {signal} dBm")
                    if debug_mode:
                        print(f"Found SSID '{ssid}' on channel {channel} with signal {signal} dBm")
                elif debug_mode:
                    print(f"Failed to extract channel information for SSID '{ssid}'")
    if debug_mode:
        print(f"Active channels detected: {active_channels}")
    return list(active_channels)

# Function to switch WiFi channels in main scan
def hop_channel(interface, channels, sleep_time):
    for channel in channels:
        if not sniffing:
            break

        # Switch to the next channel with lock to prevent socket errors during sniffing
        with channel_lock:
            try:
                iface = pyw.getcard(interface)
                pyw.chset(iface, channel)
            except pyric.error as e:
                if debug_mode:
                    print(f"Failed to set channel {channel} on interface {interface}: {e}")
                continue
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning on Channel {channel}")
        time.sleep(sleep_time)  # Adjustable sleep time for faster scanning

# Function to handle packet processing and track clients
def packet_handler(packet):
    if not sniffing:
        return  # Stop processing if sniffing flag is set to False
    if packet.type == 1:  # Ignore Control frames
        return

    # Process SSID information from Beacon/Probe Response frames
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') or "<HIDDEN>"
        bssid = packet[Dot11].addr2
        # Extract signal strength and channel
        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            signal = radiotap.dBm_AntSignal if hasattr(radiotap, 'dBm_AntSignal') else -100
            freq = radiotap.ChannelFrequency if hasattr(radiotap, 'ChannelFrequency') else None
            channel = freq_to_channel(freq) if freq else None
        else:
            signal = -100
            channel = None
        bssid_ssid_map[bssid] = ssid
        if channel:
            ssid_channels[ssid].add(channel)
            # Update signal strength only if the new signal is stronger
            if signal > bssid_signal_strength[ssid].get(channel, -100):
                bssid_signal_strength[ssid][channel] = signal
                if debug_mode:
                    print(f"Updated signal strength for SSID '{ssid}' on channel {channel}: {signal} dBm")
        elif debug_mode:
            print(f"Failed to extract channel information for SSID '{ssid}'")

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
        channels = sorted(ssid_channels[ssid])
        if bssid_signal_strength[ssid]:  # Ensure there is signal strength data
            primary_channel = max(bssid_signal_strength[ssid], key=lambda ch: bssid_signal_strength[ssid][ch])
            signal_strength = bssid_signal_strength[ssid][primary_channel]
        else:
            primary_channel = "N/A"
            signal_strength = "N/A"

        print(f"SSID: {ssid}, Primary Channel: {primary_channel}, Other Channels: {', '.join(map(str, channels))}, Clients: {len(clients)}, Signal: {signal_strength} dBm")

def sniff_packets(sniff_timeout, sniff_count):
    global sniffing
    while sniffing:
        # Retry logic for socket failures
        try:
            with channel_lock:
                sniff(iface=interface, prn=packet_handler, timeout=sniff_timeout, count=sniff_count, store=0)
        except Exception as e:
            if debug_mode:  # Only print the error if debug mode is enabled
                print(f"Socket error: {e}. Retrying in 5 seconds...")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode (e.g., wlan0)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    parser.add_argument('--scan_interval', type=int, default=30, help='Interval in seconds for rescanning SSIDs')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--sniff_timeout', type=float, default=1.0, help='Timeout in seconds for sniffing packets during passive scan')
    parser.add_argument('--sniff_count', type=int, default=50, help='Number of packets to capture during passive scan')
    parser.add_argument('--hop_sleep', type=float, default=0.5, help='Sleep time in seconds after hopping to a new channel')
    args = parser.parse_args()

    global debug_mode, sniffing, interface, selected_channels
    debug_mode = args.debug

    interface = args.interface
    interval = args.interval
    scan_interval = args.scan_interval  # SSID scan interval
    sniff_timeout = args.sniff_timeout
    sniff_count = args.sniff_count
    hop_sleep = args.hop_sleep

    # Configure logging to suppress Scapy warnings if debug_mode is off
    if not debug_mode:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    else:
        logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

    print(f"Starting WiFi scan on interface {interface}. Press Ctrl+C to stop.")

    # Set interface to monitor mode
    set_monitor_mode(interface)

    # Get supported channels (dynamically includes 2.4 GHz and 5 GHz)
    get_supported_channels(interface)

    if not selected_channels:
        print("No channels detected. Exiting.")
        sys.exit(1)

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, stop_sniffing)

    # Start the sniffing thread
    sniff_thread = threading.Thread(target=sniff_packets, args=(sniff_timeout, sniff_count))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Main loop for scanning and display
    last_scan_time = 0
    active_channels = selected_channels.copy()  # Initialize with all selected channels

    try:
        while sniffing:
            current_time = time.time()
            if current_time - last_scan_time >= scan_interval:
                active_channels = passive_scan_for_ssids(interface, sniff_timeout, sniff_count)
                last_scan_time = current_time
            if not active_channels:
                active_channels = selected_channels.copy()  # Fallback to pre-selected channels if none detected
            hop_channel(interface, active_channels, hop_sleep)
            display_results()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Exiting gracefully...")

    sniffing = False
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
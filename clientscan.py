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
import errno  # Import errno module

# Dictionaries for SSID and client tracking
bssid_ssid_map = {}
network_clients = defaultdict(set)
bssid_signal_strength = defaultdict(lambda: defaultdict(int))  # Track signal by SSID and channel
ssid_channels = defaultdict(set)  # Track channels for each SSID
ssid_bssids = defaultdict(set)  # Track BSSIDs (APs) per SSID

# Global variables to control scanning and debugging
sniffing = True
debug_mode = False
selected_channels = []  # To be populated dynamically
channel_lock = threading.Lock()  # Lock to coordinate channel switching
interface = None  # Global variable to hold interface name
sniffing_event = threading.Event()
sniffing_event.set()  # Start with the event set, allowing sniffing to proceed

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

# Helper function to get card with retries
def get_card_with_retries(interface, max_retries=5, sleep_time=0.1):
    retry_count = 0
    while retry_count < max_retries:
        try:
            card = pyw.getcard(interface)
            return card  # Successfully obtained the card
        except pyric.error as e:
            if e.errno in [errno.ENOBUFS, errno.EAGAIN]:
                if debug_mode:
                    print(f"getcard failed with errno {e.errno} ({e.strerror}), retrying after sleep")
                time.sleep(sleep_time)
                retry_count += 1
            else:
                print(f"Failed to get card for interface {interface}: {e}")
                return None
    print(f"Failed to get card for interface {interface} after {max_retries} retries")
    return None

# Helper function to set channel with retries
def set_channel_with_retries(iface, channel, max_retries=5, sleep_time=0.1):
    retry_count = 0
    while retry_count < max_retries:
        try:
            pyw.chset(iface, channel)
            current_channel = pyw.chget(iface)
            if current_channel == channel:
                return True  # Successfully set the channel
            else:
                if debug_mode:
                    print(f"Warning: Interface channel is {current_channel}, expected {channel}")
                time.sleep(sleep_time)
                retry_count += 1
        except pyric.error as e:
            if e.errno in [errno.ENOBUFS, errno.EAGAIN]:
                if debug_mode:
                    print(f"Channel set failed with errno {e.errno} ({e.strerror}), retrying after sleep")
                time.sleep(sleep_time)
                retry_count += 1
            else:
                print(f"Failed to set channel {channel} on interface {interface}: {e}")
                return False
    print(f"Failed to set channel {channel} on interface {interface} after {max_retries} retries")
    return False

# Function to get supported channels
def get_supported_channels(interface):
    global selected_channels
    try:
        # Get the wireless interface
        with channel_lock:
            iface = get_card_with_retries(interface)
            if iface is None:
                print(f"Failed to get card for interface {interface}. Exiting.")
                sys.exit(1)
            # Get the list of supported channels (as integers)
            chs = pyw.devchs(iface)  # Returns a list of channel numbers
        selected_channels = []
        for channel in chs:
            freq = channels.ch2rf(channel)  # Get the frequency corresponding to the channel
            if freq is None:
                if debug_mode:
                    print(f"Could not get frequency for Channel {channel}")
                continue
            if debug_mode:
                print(f"Detected Channel: {channel}, Frequency: {freq} MHz")
            # Include standard Wi-Fi channels in 2.4 GHz and 5 GHz bands
            if (1 <= channel <= 14) or (36 <= channel <= 165):
                selected_channels.append(channel)
                if debug_mode:
                    print(f"Added Channel {channel} to selected_channels")
            else:
                if debug_mode:
                    print(f"Skipping unsupported or invalid Channel {channel}")
        # Remove duplicates and sort
        selected_channels = sorted(set(selected_channels))
        print(f"Available channels for {interface}: {selected_channels}")
    except pyric.error as e:
        print(f"Failed to retrieve channels for interface {interface}: {e}")
        sys.exit(1)

# Function to initialize interface in monitor mode
def set_monitor_mode(interface, getcard_retries):
    try:
        with channel_lock:
            iface = get_card_with_retries(interface, max_retries=getcard_retries)
            if iface is None:
                print(f"Failed to get card for interface {interface}. Exiting.")
                sys.exit(1)
            pyw.down(iface)
            pyw.modeset(iface, 'monitor')
            pyw.up(iface)
            print(f"Interface {interface} set to monitor mode.")
    except pyric.error as e:
        print(f"Failed to set {interface} to monitor mode: {e}")
        sys.exit(1)

# Function to perform a quick scan to detect available SSIDs and channels
def passive_scan_for_ssids(interface, sniff_timeout, sniff_count, getcard_retries, setchannel_retries):
    global sniffing
    active_channels = set()
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scanning for active SSIDs...")

    # Pause the sniffing thread
    sniffing_event.clear()

    for channel in selected_channels:
        if not sniffing:
            break  # Stop scanning if sniffing flag is set to False

        if debug_mode:
            print(f"\nAttempting to scan on Channel {channel}")

        # Synchronize access to the interface
        with channel_lock:
            iface = get_card_with_retries(interface, max_retries=getcard_retries)
            if iface is None:
                continue  # Skip to the next channel if unable to get card

            success = set_channel_with_retries(iface, channel, max_retries=setchannel_retries)
            if not success:
                continue  # Skip to next channel

            if debug_mode:
                print(f"Successfully set interface {interface} to Channel {channel}")

        time.sleep(0.5)  # Slight delay to ensure the adapter is ready

        # Determine sniffing parameters based on the band
        if 1 <= channel <= 14:
            # 2.4 GHz channel
            channel_sniff_timeout = sniff_timeout
            channel_sniff_count = sniff_count
        else:
            # 5 GHz channel
            channel_sniff_timeout = sniff_timeout * 2  # Increase timeout for 5 GHz
            channel_sniff_count = sniff_count * 2      # Increase packet count for 5 GHz

        if debug_mode:
            print(f"Sniffing on Channel {channel} for {channel_sniff_timeout}s, capturing {channel_sniff_count} packets")

        # Capture packets to detect SSIDs
        try:
            packets = sniff(iface=interface, timeout=channel_sniff_timeout, count=channel_sniff_count, store=True)
            if debug_mode:
                print(f"Captured {len(packets)} packets on Channel {channel}")
        except Exception as e:
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
                    channel_from_packet = freq_to_channel(freq) if freq else None
                    if debug_mode:
                        print(f"Packet Frequency: {freq}, Mapped Channel: {channel_from_packet}")
                else:
                    signal = -100
                    channel_from_packet = None
                    if debug_mode:
                        print("Packet does not have RadioTap layer; cannot extract frequency and signal strength.")
                if ssid and channel_from_packet:
                    active_channels.add(channel_from_packet)
                    bssid_ssid_map[bssid] = ssid
                    ssid_channels[ssid].add(channel_from_packet)
                    ssid_bssids[ssid].add(bssid)  # Track BSSID (AP) per SSID
                    # Update signal strength only if the new signal is stronger
                    if signal > bssid_signal_strength[ssid].get(channel_from_packet, -100):
                        bssid_signal_strength[ssid][channel_from_packet] = signal
                        if debug_mode:
                            print(f"Updated signal strength for SSID '{ssid}' on channel {channel_from_packet}: {signal} dBm")
                    if debug_mode:
                        print(f"Found SSID '{ssid}' (BSSID: {bssid}) on channel {channel_from_packet} with signal {signal} dBm")
                elif debug_mode:
                    print(f"Failed to extract channel information for SSID '{ssid}'")
        if debug_mode:
            print(f"Active channels detected so far: {sorted(active_channels)}")

    # Resume the sniffing thread
    sniffing_event.set()

    if debug_mode:
        print(f"Total active channels detected: {sorted(active_channels)}")
    return list(active_channels)

# Function to switch WiFi channels in main scan
def hop_channel(interface, channels, sleep_time, band_switch_delay, getcard_retries, setchannel_retries):
    previous_band = None  # Keep track of the previous channel's band
    for channel in channels:
        if not sniffing:
            break

        # Determine the current band
        if 1 <= channel <= 14:
            current_band = '2.4 GHz'
        else:
            current_band = '5 GHz'

        # Check if the band has changed
        if previous_band and current_band != previous_band:
            # Band has changed; wait for band_switch_delay before switching
            if debug_mode:
                print(f"Band changing from {previous_band} to {current_band}. Waiting for {band_switch_delay} seconds before switching.")
            time.sleep(band_switch_delay)
        else:
            # Band has not changed; wait for regular sleep_time before switching
            time.sleep(sleep_time)

        with channel_lock:
            iface = get_card_with_retries(interface, max_retries=getcard_retries)
            if iface is None:
                continue  # Skip to the next channel if unable to get card

            success = set_channel_with_retries(iface, channel, max_retries=setchannel_retries)
            if not success:
                continue  # Skip to next channel

            if debug_mode:
                print(f"Set interface {interface} to channel {channel} successfully.")

        previous_band = current_band  # Update previous_band after successful switch

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning on Channel {channel}")

# Function to handle packet processing and track clients
def packet_handler(packet):
    if not sniffing:
        return  # Stop processing if sniffing flag is set to False

    if packet.type == 1:  # Ignore Control frames
        if debug_mode:
            print("Ignoring Control frame.")
        return

    if debug_mode:
        print(f"Processing packet of type {packet.type} and subtype {packet.subtype}")

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
            if debug_mode:
                print(f"Packet Frequency: {freq}, Mapped Channel: {channel}")
        else:
            signal = -100
            channel = None
            if debug_mode:
                print("Packet does not have RadioTap layer; cannot extract frequency and signal strength.")
        bssid_ssid_map[bssid] = ssid
        ssid_bssids[ssid].add(bssid)  # Track BSSIDs (APs) per SSID
        if channel:
            ssid_channels[ssid].add(channel)
            # Update signal strength only if the new signal is stronger
            if signal > bssid_signal_strength[ssid].get(channel, -100):
                bssid_signal_strength[ssid][channel] = signal
                if debug_mode:
                    print(f"Updated signal strength for SSID '{ssid}' on channel {channel}: {signal} dBm")
        elif debug_mode:
            print(f"Failed to extract channel information for SSID '{ssid}'")
        if debug_mode:
            print(f"Processed Beacon/Probe Response for SSID '{ssid}' (BSSID: {bssid})")

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
            if debug_mode:
                print("Packet has both ToDS and FromDS bits set; ignoring.")
            return

        ssid = bssid_ssid_map.get(bssid)
        if ssid:
            network_clients[ssid].add(client_mac)
            if debug_mode:
                print(f"Associated Client {client_mac} with SSID '{ssid}'")
        elif debug_mode:
            print(f"BSSID {bssid} not found in bssid_ssid_map; cannot associate client.")

# Function to stop sniffing
def stop_sniffing(signum, frame):
    global sniffing
    sniffing = False
    print("\nStopping scan...")

def display_results():
    print("\nCurrent Results:")
    # Get all SSIDs that have been detected
    all_ssids = set(ssid_channels.keys())
    for ssid in all_ssids:
        clients = network_clients.get(ssid, set())
        channels = sorted(ssid_channels[ssid])
        ap_count = len(ssid_bssids.get(ssid, set()))  # Get number of APs
        if bssid_signal_strength[ssid]:  # Ensure there is signal strength data
            primary_channel = max(bssid_signal_strength[ssid], key=lambda ch: bssid_signal_strength[ssid][ch])
            signal_strength = bssid_signal_strength[ssid][primary_channel]
        else:
            primary_channel = "N/A"
            signal_strength = "N/A"

        print(f"SSID: {ssid}, APs: {ap_count}, Primary Channel: {primary_channel}, Other Channels: {', '.join(map(str, channels))}, Clients: {len(clients)}, Signal: {signal_strength} dBm")

def sniff_packets(sniff_timeout, sniff_count):
    global sniffing
    while sniffing:
        # Wait for the sniffing_event to be set
        sniffing_event.wait()
        try:
            with channel_lock:
                sniff(iface=interface, prn=packet_handler, timeout=sniff_timeout, count=sniff_count, store=0)
        except Exception as e:
            print(f"Socket error: {e}. Retrying in 5 seconds...")
            time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="WiFi Scanner to count clients per SSID and AP.")
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode (e.g., wlan0)')
    parser.add_argument('-t', '--interval', type=int, default=5, help='Interval in seconds between output updates')
    parser.add_argument('--scan_interval', type=int, default=30, help='Interval in seconds for rescanning SSIDs')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--sniff_timeout', type=float, default=1.5, help='Timeout in seconds for sniffing packets during passive scan')
    parser.add_argument('--sniff_count', type=int, default=100, help='Number of packets to capture during passive scan')
    parser.add_argument('--hop_sleep', type=float, default=1.0, help='Sleep time in seconds after hopping to a new channel')
    parser.add_argument('--band_switch_delay', type=float, default=5.0, help='Delay in seconds when switching between 2.4 GHz and 5 GHz bands')
    # Added retry parameters
    parser.add_argument('--getcard_retries', type=int, default=5, help='Max retries for getting the wireless card')
    parser.add_argument('--setchannel_retries', type=int, default=5, help='Max retries for setting the channel')
    args = parser.parse_args()

    global debug_mode, sniffing, interface, selected_channels
    debug_mode = args.debug

    interface = args.interface
    interval = args.interval
    scan_interval = args.scan_interval  # SSID scan interval
    sniff_timeout = args.sniff_timeout
    sniff_count = args.sniff_count
    hop_sleep = args.hop_sleep
    band_switch_delay = args.band_switch_delay
    getcard_retries = args.getcard_retries  # New
    setchannel_retries = args.setchannel_retries  # New

    # Configure logging to suppress Scapy warnings if debug_mode is off
    if not debug_mode:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    else:
        logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

    print(f"Starting WiFi scan on interface {interface}. Press Ctrl+C to stop.")

    # Set interface to monitor mode
    set_monitor_mode(interface, getcard_retries)

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
                active_channels = passive_scan_for_ssids(interface, sniff_timeout, sniff_count, getcard_retries, setchannel_retries)
                last_scan_time = current_time
            if not active_channels:
                active_channels = selected_channels.copy()  # Fallback to pre-selected channels if none detected
            if debug_mode:
                print(f"Active channels to scan: {active_channels}")
            hop_channel(interface, active_channels, hop_sleep, band_switch_delay, getcard_retries, setchannel_retries)
            display_results()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Exiting gracefully...")

    sniffing = False
    sniffing_event.set()  # Ensure the sniffing thread is not blocked
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join()
    print("\nFinal Results:")
    display_results()

if __name__ == "__main__":
    main()
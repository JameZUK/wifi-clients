# Advanced Wi-Fi Scanner & Client Monitor

This Python script is a powerful tool for scanning Wi-Fi networks, identifying active SSIDs, their Access Points (APs), channels, signal strengths, and counting connected clients. It leverages Scapy for packet sniffing and manipulation, and PyRIC for wireless interface control (like setting monitor mode and hopping channels).

## Features

* **Monitor Mode Setup:** Automatically attempts to set the specified wireless interface into monitor mode.
* **Dynamic Channel Discovery:** Detects supported channels on the wireless interface across both 2.4 GHz and 5 GHz bands.
* **Passive SSID & Channel Scanning:**
    * Periodically scans to discover active SSIDs, the BSSIDs (APs) broadcasting them, and the channels they operate on.
    * Identifies the primary channel for an SSID based on the strongest signal.
    * Detects other channels an SSID might be operating on.
* **Targeted Client Sniffing:**
    * Focuses sniffing efforts on channels where active SSIDs have been detected.
    * Hops between these active channels to capture client activity.
* **Signal Strength Monitoring:** Extracts and displays signal strength (in dBm) from RadioTap headers.
* **Client Counting:** Counts the number of unique client devices associated with each discovered SSID.
* **AP Counting:** Counts the number of distinct APs (BSSIDs) detected for each SSID.
* **Robust Interface Control:**
    * Implements retry mechanisms for setting interface mode and channels, handling common transient errors.
    * Includes a specific delay when switching between 2.4 GHz and 5 GHz bands for improved stability.
* **Concurrency:** Uses threading for simultaneous channel hopping, packet sniffing, and periodic passive scans.
* **Debug Mode:** Offers a verbose debug output for troubleshooting and detailed insight into its operations.
* **Customizable Parameters:** Allows configuration of scan intervals, sniffing timeouts, packet counts, and retry attempts via command-line arguments.
* **Graceful Shutdown:** Handles Ctrl+C to stop scanning and display final results.

## Requirements

* **Python 3.x**
* **Linux Operating System:** PyRIC and monitor mode capabilities are typically best supported on Linux.
* **Wireless Adapter Supporting Monitor Mode:** Your Wi-Fi card must be capable of being put into monitor mode.
* **Root/Sudo Privileges:** Required for setting monitor mode and raw packet sniffing.
* **Python Libraries:**
    * `scapy`
    * `pyric`

## Installation

1.  **Ensure Python 3 and pip are installed.**
    Most modern Linux distributions come with Python 3. You can check with `python3 --version` and `pip3 --version`.

2.  **Install dependencies:**
    ```bash
    sudo pip3 install scapy pyric
    ```
    *(Use `pip` instead of `pip3` if `pip` is explicitly linked to Python 3 on your system)*

## Usage

Run the script from the terminal with root/sudo privileges.

```bash
sudo python3 your_script_name.py -i <interface_name> [options]
```
*(Replace `your_script_name.py` with the actual filename of the Python script).*

**Example:**
```bash
sudo python3 your_script_name.py -i wlan0mon
```
or if your interface is `wlan0` and needs to be put into monitor mode by the script:
```bash
sudo python3 your_script_name.py -i wlan0
```

### Command-Line Arguments:

| Argument                 | Short | Default | Description                                                                 |
| ------------------------ | ----- | ------- | --------------------------------------------------------------------------- |
| `--interface`            | `-i`  | *None* | **Required.** Wireless interface to use (e.g., `wlan0`, `wlan0mon`).          |
| `--interval`             | `-t`  | 5       | *(Currently unused in the provided script's main loop logic)* Interval in seconds between output updates.            |
| `--scan_interval`        |       | 30      | Interval in seconds for re-scanning for active SSIDs and their channels.    |
| `--debug`                |       | False   | Enable debug output for verbose logging.                                    |
| `--sniff_timeout`        |       | 1.5     | Timeout (seconds) for sniffing packets on each channel during passive & active scans. |
| `--sniff_count`          |       | 100     | Number of packets to capture on each channel during passive & active scans.   |
| `--hop_sleep`            |       | 1.0     | Sleep time (seconds) after hopping to a new channel (within the same band). |
| `--band_switch_delay`    |       | 5.0     | Additional delay (seconds) when switching between 2.4 GHz and 5 GHz bands.    |
| `--getcard_retries`      |       | 5       | Max retries for getting the wireless card handle using PyRIC.               |
| `--setchannel_retries`   |       | 5       | Max retries for setting the wireless channel using PyRIC.                   |

### Example with more options:

To scan on `wlan0`, rescan for SSIDs every 60 seconds, enable debug mode, and use a longer sniff timeout:
```bash
sudo python3 your_script_name.py -i wlan0 --scan_interval 60 --debug --sniff_timeout 3
```

## How It Works

1.  **Initialization:**
    * Parses command-line arguments.
    * Sets the specified wireless interface into monitor mode using PyRIC.
    * Retrieves a list of all channels supported by the interface.
    * Starts a dedicated background thread for packet sniffing.

2.  **Main Operational Loop:**
    * **Passive SSID Discovery (`passive_scan_for_ssids`):**
        * Periodically (controlled by `--scan_interval`), this function pauses the main sniffing thread.
        * It then iterates through all supported channels.
        * On each channel, it sniffs for a short duration (defined by `--sniff_timeout` and `--sniff_count`) to capture Beacon and Probe Response frames.
        * From these frames, it extracts SSID names, BSSIDs (AP MAC addresses), operating channels, and signal strengths.
        * This information is used to build a map of active networks and determine which channels are actually in use (`active_channels`).
        * The main sniffing thread is then resumed.
    * **Targeted Channel Hopping (`hop_channel`):**
        * The script iterates through the `active_channels` identified by the passive scan (or all supported channels if none were found).
        * For each channel in this list, it sets the wireless interface to that specific channel.
        * The background sniffing thread automatically starts capturing packets on this newly set channel.
        * Delays (`--hop_sleep`, `--band_switch_delay`) are introduced between hops for stability.
    * **Continuous Packet Sniffing (`sniff_packets` & `packet_handler`):**
        * This function runs in a separate thread.
        * It continuously captures packets on whatever channel the `hop_channel` function has currently set.
        * The `packet_handler` processes these packets:
            * **Beacon/Probe Response Frames:** Used to update information about SSIDs, BSSIDs, channels, and signal strengths.
            * **Data Frames:** Analyzed to identify client MAC addresses and associate them with the BSSID (and thus SSID) they are communicating with by checking `ToDS` and `FromDS` flags.
    * **Display Results:** After a full cycle of hopping through the active channels, the script prints a summary of discovered SSIDs, the number of APs for each, their primary operating channel, other detected channels, the count of connected clients, and the signal strength on the primary channel.
    * The loop (passive scan, channel hopping, display) continues until the user presses `Ctrl+C`.

## Important Considerations

* **Permissions:** This script requires root or `sudo` privileges to set the wireless interface to monitor mode and to perform raw packet sniffing.
* **Monitor Mode Support:** Your wireless adapter and its driver must support monitor mode. You can check this using tools like `iwconfig` or `airmon-ng`. Some interfaces might need to be put into monitor mode manually first (e.g., creating a `monX` interface), though this script attempts to do it automatically.
* **PyRIC Compatibility:** PyRIC is primarily designed for Linux systems. This script may not work on Windows or macOS without significant modifications.
* **Legality and Ethics:** Use this script responsibly and ethically. Only scan networks for which you have explicit permission. Unauthorized scanning or attempts to access networks can be illegal in many jurisdictions. This tool is intended for educational and network analysis purposes in controlled environments.

## TODO / Potential Enhancements

* Utilize the parsed `--interval` argument for controlling display update frequency independently of channel hop cycles if desired.
* Option to save scan results to a file (e.g., CSV, JSON).
* More granular client-to-BSSID (AP) mapping in the output.
* Detection and reporting of network security protocols (WEP, WPA, WPA2, WPA3).
* Graphical User Interface (GUI).

## License

This project is open-source. You are encouraged to fork, modify, and use it.
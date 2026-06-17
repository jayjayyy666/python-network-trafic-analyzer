# Simple Network Traffic Analyzer

A lightweight Python tool for real-time network packet sniffing, statistical analysis, and basic cyber security anomaly detection. The project captures network packets, processes their layers (IP, TCP, UDP, ICMP), and leverages the **Pandas** library to identify potential security threats like port scanning or stealth scans.

---

## Features

* **Real-time Sniffing:** Captures network traffic on specified network interfaces using `Scapy`.
* **Protocol Parsing:** Extracts deep packet details including Source/Destination IPs, Protocols, Port numbers, and TCP flags.
* **Traffic Statistics:** Calculates packet counts by protocol, average packet size, and total data volume.
* **Anomaly & Threat Detection:**
  * **Port Scanning:** Detects if a single IP address is probing multiple different ports.
  * **TCP NULL Scans:** Identifies stealth reconnaissance packets with no TCP flags set.
  * **Data Exfiltration / DoS:** Flags unusually large packets (>1500 bytes).
* **Data Export:** Automatically saves all captured packet data into a structured `traffic_report.csv` file for further analysis (e.g., in Excel).

---

## Prerequisites & Installation

Since packet sniffing interacts directly with the network interface card (NIC), you need to install specific system dependencies and Python libraries.

### 1. System Requirements
* **Windows:** Download and install [Npcap](https://npcap.com/). (Make sure to check "Install Npcap in WinPcap API-compatible Mode" during installation).
* **Linux:** Install `libpcap` via your package manager (e.g., `sudo apt install libpcap-dev`).
* **macOS:** Standard installation usually includes `libpcap` by default.

### 2. Python Libraries
Install the required Python dependencies using `pip`:

```bash
pip install scapy pandas

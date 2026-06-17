#!/usr/bin/env python3
"""
Network traffic analyzer with basic anomaly detection.
"""

import pandas as pd
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Global list to store packet information
packets = []


def packet_callback(pkt):
    """Process each captured packet and extract relevant fields."""
    if IP in pkt:
        pkt_info = {
            "time": datetime.fromtimestamp(float(pkt.time)),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "proto": pkt[IP].proto,
            "size": len(pkt),
            "sport": None,
            "dport": None,
            "flags": "",
        }

        # Extract TCP specific fields
        if TCP in pkt:
            pkt_info["sport"] = pkt[TCP].sport
            pkt_info["dport"] = pkt[TCP].dport
            pkt_info["flags"] = str(pkt[TCP].flags)

        # Extract UDP specific fields
        elif UDP in pkt:
            pkt_info["sport"] = pkt[UDP].sport
            pkt_info["dport"] = pkt[UDP].dport

        # Extract ICMP specific fields
        elif ICMP in pkt:
            pkt_info["flags"] = f"Type: {pkt[ICMP].type}"

        packets.append(pkt_info)


def analyze_traffic(df):
    """Perform basic traffic analysis and anomaly detection."""
    print("\n" + "=" * 30)
    print("      Results of analyzing traffic")
    print("=" * 30)

    # 1. Basic Statistics
    print("\n[+] Packet counts by protocol (6=TCP, 17=UDP, 1=ICMP):")
    print(df['proto'].value_counts())

    print(f"\n[+] Average packet size: {df['size'].mean():.1f} bytes")
    print(f"[+] Total data volume: {df['size'].sum()} bytes")

    # 2. Anomaly Detection
    print("\n[+] Scanning for anomalies...")
    anomalies_found = False

    # Port scanning detection (More than 5 unique ports from the same source IP)
    port_scan = df.groupby('src_ip')['dport'].nunique()
    for ip, unique_ports in port_scan.items():
        if unique_ports > 5:
            print(f" ⚠️  SUSPICIOUS: Port Scanning detected from IP {ip}! (Targeted {unique_ports} unique ports)")
            anomalies_found = True

    # Stealth scans detection (TCP Null Scan - no flags set)
    null_scans = df[(df['proto'] == 6) & (df['flags'] == "")]
    if not null_scans.empty:
        print(f" ⚠️  ALERT: Detected {len(null_scans)} TCP packets with no flags (Potential NULL Scan)!")
        anomalies_found = True

    # Large packet detection (Potential data exfiltration or DoS)
    large_packets = df[df['size'] > 1500]
    if not large_packets.empty:
        print(f" ⚠️  NOTICE: Found {len(large_packets)} unusually large packets (>1500B).")
        anomalies_found = True

    if not anomalies_found:
        print(" ✅ No obvious anomalies detected.")

    print("=" * 30)
    return df


def main():
    print("Starting network traffic analyzer...")
    print("Capturing 50 packets on the loopback interface (lo)...")

    # Sniff 50 packets on loopback. Change iface to "wlan0" or "eth0" for live network traffic.
    sniff(iface="lo", prn=packet_callback, count=50, store=False)

    if not packets:
        print("No packets captured. Try running 'ping 127.0.0.1' in another terminal to generate traffic.")
        return

    # Convert the list of dictionaries into a Pandas DataFrame
    df = pd.DataFrame(packets)
    print(f"\nSuccessfully captured {len(df)} packets.")

    # Run analysis
    analyze_traffic(df)

    # Save results to a CSV file
    output_file = "traffic_report.csv"
    df.to_csv(output_file, index=False)
    print(f"\nData has been saved to: {output_file}")


if __name__ == "__main__":
    main()
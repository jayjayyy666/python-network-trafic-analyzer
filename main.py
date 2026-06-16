#!/usr/bin/env python3
"""
Simple network traffic analyzer with anomaly detection.
Fill in the TODO sections to complete the implementation.
"""

import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Global list to hold packet info
packets = []

def packet_callback(pkt):
    """Process each captured packet and extract relevant fields."""
    if IP in pkt:
        pkt_info = {
            "time": datetime.fromtimestamp(pkt.time),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "proto": pkt[IP].proto,
            "size": len(pkt),
        }
        # TODO: Extract TCP/UDP/ICMP specific fields (sport, dport, flags, etc.)
        # HINT: Use pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags for TCP
        # Similarly for UDP and ICMP.
        packets.append(pkt_info)

def analyze_traffic(df):
    """Perform basic traffic analysis and anomaly detection."""
    # TODO: Basic statistics
    # - Count packets per protocol
    # - Size distribution
    # - Unique connections
    # TODO: Anomaly detection
    # - Port scanning: many destination ports from same source IP
    # - Unusually large/small packets
    # - Suspicious TCP flag combinations (NULL, Xmas, FIN)
    # Return results as dict or DataFrame for reporting
    pass

def main():
    print("Starting network traffic analyzer...")
    # Capture packets (adjust iface and count as needed, or set sniff continuously)
    # For testing, use loopback interface and a limited number of packets:
    sniff(iface="lo", prn=packet_callback, count=200, store=False)

    if not packets:
        print("No packets captured.")
        return

    df = pd.DataFrame(packets)
    print(f"Captured {len(df)} packets.")

    results = analyze_traffic(df)

    # TODO: Output results (print summary, save to CSV, plot graphs)
    # Example:
    # print(results)
    # df.to_csv("traffic.csv", index=False)

if __name__ == "__main__":
    main()
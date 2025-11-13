Aim

To implement network packet sniffing using Wireshark for capturing, filtering, saving, and analyzing network traffic (authorized use only).

Procedure

1. Install Wireshark:
   - Debian/Ubuntu: `sudo apt update && sudo apt install -y wireshark`
   - RHEL/CentOS: `sudo dnf install -y wireshark-qt`
2. Enable non-root capture (optional): `sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)`
3. List interfaces (dumpcap): `dumpcap -D`
4. Start Wireshark GUI: `wireshark &` or `sudo wireshark`
5. In Wireshark: Capture → Options → select interface
6. Set a capture filter (BPF) in Capture Options, e.g. `tcp port 80` or `host 192.168.1.10`
7. Click Start to begin capturing
8. Stop capture with the red Stop button
9. Save capture: File → Save As → `/path/to/capture.pcapng`
10. Apply display filters in GUI, e.g. `http`, `dns`, `ip.addr==192.168.1.10`
11. Export objects: File → Export Objects → HTTP (or other protocol)
12. Convert or process captures if needed: `editcap -F pcap capture.pcapng capture.pcap`

Expected outcomes

- A saved capture file (`capture.pcapng`).
- Filtered packet views and protocol breakdowns in the GUI.
- Exported objects and extracted artifacts when applicable.
- Identification of endpoints, ports, protocols, and timestamps.

Conclusion

Wireshark provides a GUI-driven workflow for packet capture and analysis; use it only on authorized networks and hosts.

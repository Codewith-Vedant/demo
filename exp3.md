Aim

To implement network packet sniffing using Wireshark/tshark for capturing, filtering, saving, and analyzing network traffic (authorized use only).

Procedure

1. Install Wireshark/tshark:
   - Debian/Ubuntu: `sudo apt update && sudo apt install -y wireshark tshark`
   - RHEL/CentOS: `sudo dnf install -y wireshark-cli wireshark-qt`
2. Allow non-root capture (optional): `sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)`
3. List interfaces: `tshark -D`
4. Start GUI capture: `wireshark &` (or run as root: `sudo wireshark`)
5. Capture to file (CLI): `sudo tshark -i eth0 -w /tmp/capture.pcapng`
6. Capture limited packets: `sudo tshark -i eth0 -c 100 -w capture.pcapng`
7. Capture with BPF (capture filter): `sudo tshark -i eth0 -f "tcp port 80" -w http.pcapng`
8. Apply display filter when reading: `tshark -r capture.pcapng -Y "http && ip.addr==192.168.1.10" -V`
9. Extract fields to CSV: `tshark -r capture.pcapng -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport > extracted.csv`
10. Convert pcapng to pcap: `editcap -F pcap capture.pcapng capture.pcap`

Expected outcomes

- A saved capture file (`capture.pcapng`) containing recorded packets.
- Filtered views of traffic matching BPF or display filters.
- Extracted CSV of selected fields for analysis.
- Identification of protocols, endpoints, ports, and timestamps for inspected flows.

Conclusion

Wireshark/tshark provide powerful packet-capture and analysis capabilities; use them only on networks and hosts you own or have explicit permission to monitor.

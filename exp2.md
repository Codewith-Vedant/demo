Aim

To utilize Nmap (Network Mapper) for comprehensive network discovery, host enumeration, port scanning, and service detection to identify active devices and services within a network infrastructure.

Procedure

1. Discover live hosts: `nmap -sn 192.168.1.0/24`
2. Full TCP port scan: `nmap -sS -p- 192.168.1.0/24`
3. Service/version detection and default scripts: `nmap -sV -sC -p 1-65535 192.168.1.0/24`
4. OS detection and aggressive checks (requires root): `sudo nmap -A -T4 192.168.1.0/24`
5. Save outputs: `nmap -oA scan-results 192.168.1.0/24`

Expected outcomes

- A list of active hosts (IP and optionally MAC addresses).
- Open ports and associated services for each host.
- Detected service versions and common application footprints.
- OS fingerprints and additional host metadata where possible.
- Saved scan files (`.nmap`, `.xml`, `.gnmap`) for analysis.

Conclusion

Nmap produces a detailed inventory of devices, ports, and services useful for network mapping and asset identification; always run scans only with proper authorization.

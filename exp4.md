Aim

To deploy and configure the Kioptrix vulnerable machine in Oracle VM VirtualBox, establish appropriate network settings for safe pentesting (isolated lab + optional internet access), and verify connectivity between host and VM.

Procedure

1. Obtain the Kioptrix VM (OVA or image) from a trusted, authorized source.
2. Open VirtualBox → File → Import Appliance → select the Kioptrix `.ova` (or create a new VM and attach the downloaded disk image).
3. VM settings → System/CPU/RAM: assign minimal required resources (e.g., 1–2 CPU, 1–2 GB RAM).
4. Network configuration:
   - Adapter 1: NAT (keeps VM able to reach internet; optional).
   - Adapter 2: Host-only Adapter (creates isolated lab network between host and VM). Enable Adapter 2 if you want host↔VM connectivity without exposing the VM to the real network.
   - Optional: If you need the VM on the same LAN as other devices, use Bridged Adapter instead (only with permission).
5. (Optional NAT port forwarding) VirtualBox → Network → Adapter 1 (NAT) → Advanced → Port Forwarding: add rules (e.g., Host port 2222 → Guest port 22) to allow SSH from host to VM.
6. Adjust Promiscuous Mode (Network → Adapter → Advanced) to `Allow All` if required for certain captures or monitoring.
7. Start the VM.
8. Inside VM: verify its IP addresses:
   - `ip addr` or `ifconfig`
9. On host: find VM on host-only network:
   - `ip addr` (show host-only interface), then `arp -a` or `nmap -sn <host-only-subnet>` to list VMs.
10. Verify connectivity:
   - From host to VM (host-only): `ping <vm-hostonly-ip>`
   - From VM to host: `ping <host-hostonly-ip>`
   - If NAT internet is enabled: from VM `ping 8.8.8.8` and `curl -I http://example.com` to check outbound access.
11. Save VM snapshot after initial configuration for quick rollback: VirtualBox → Machine → Take Snapshot.

---

Download & High-level Exploitation Approach (no credentials or exploit payloads)

1. Download:
   - Visit a trusted lab resource (e.g., VulnHub) and download the Kioptrix image/OVA to a controlled lab machine. Do not use images from untrusted sources.
2. Import/Prepare:
   - Import the OVA into VirtualBox or attach the downloaded disk image to a new VM. Ensure the VM is isolated on a host-only network (plus optional NAT) as described above.
3. Reconnaissance (non-destructive):
   - From the host, perform host discovery and port/service scans (e.g., `nmap -sS -sV -p- <target>`) to enumerate live hosts and services.
4. Exploit available:
    Machine has vulnerable Samba 2.2.1a
    Exploit link: https://www.exploit-db.com/exploits/10
5. Download and compile:

    gcc samba-exploit.c -o samba-2.2.1a-exploit

    cd samba-2.2.1a-exploit
    
    ./samba-2.2.1a-exploit -b 0 <IP_OF_VULNERALE_MACHINE>

Expected outcomes

- A downloaded and isolated Kioptrix VM in VirtualBox.
- A non-destructive reconnaissance report detailing services and versions.
- Confirmed applicability of publicly documented vulnerabilities (within the isolated lab) or documented false positives.
- A remediation checklist and snapshot-based rollback point.

Conclusion

Download Kioptrix from trusted sources and perform reconnaissance, enumeration, and controlled exploitation only within an isolated lab and with explicit authorization; never share exploit payloads or attack code outside the authorized testing context.

Expected outcomes

- Kioptrix VM imported and bootable in VirtualBox.
- Host-only network established allowing host↔VM communication.
- Optional NAT internet access or port-forwarding for remote connections from host.
- Verified IP addresses and successful ping/scan responses between host and VM.
- A snapshot available for safe rollback.

Conclusion

Kioptrix can be safely deployed in VirtualBox with a host-only network (plus optional NAT) to enable isolated penetration testing; always ensure proper authorization and isolate the VM from production networks.

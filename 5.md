Aim

To demonstrate setting up a controlled penetration-testing lab by installing Kali Linux in VMware and provisioning a separate vulnerable VM (isolated network) for safe, authorized testing and learning.

Procedure

1. Prepare host and downloads:
	- Ensure the host machine meets VMware requirements and has virtualization enabled in BIOS/UEFI.
	- Download VMware Workstation Player (or VMware Workstation Pro) for your OS from the official VMware site.
	- Download Kali Linux ISO from the official Kali website and obtain a vulnerable VM image (e.g., from VulnHub or intentionally vulnerable appliances) from trusted sources.
2. Install VMware:
	- Windows/macOS/Linux: run the VMware installer and follow prompts to install VMware Workstation Player/Pro.
3. Create Kali VM:
	- Open VMware → Create a New Virtual Machine → choose "Installer disc image (iso)" → select the Kali ISO.
	- Follow the New VM wizard: allocate CPU (1–2 cores), RAM (2–4 GB or more), and disk (20+ GB), choose UEFI/BIOS as appropriate.
	- Complete the Kali installation inside the VM (graphical installer), set a secure password, and install VMware Tools/VMware Tools equivalent (open-vm-tools) for better integration.
4. Create Vulnerable VM:
	- Option A (OVA/image): Import the vulnerable appliance via File → Open or use "Deploy OVF Template" if available.
	- Option B (create from ISO): Create a new VM and attach the vulnerable OS ISO or disk image, then install per vendor instructions.
5. Networking & isolation:
	- In VMware VM settings, configure networking to isolate the lab:
	  - Use a Host-only network (VMnet1) to allow host↔VM communication without exposing VMs to the real network.
	  - Optionally enable NAT for internet access if lab tasks require updates; avoid bridged mode unless intentionally testing on the LAN and you have authorization.
	- Place Kali and the vulnerable VM on the same Host-only network to enable interaction while keeping them isolated.
6. Snapshots & safety:
	- Take snapshots of both VMs before any testing to allow quick rollback (VM → Snapshot → Take Snapshot).
7. Basic, non-destructive testing techniques (authorized lab only):
	- From Kali, perform host discovery: `nmap -sn <host-only-subnet>`
	- Enumerate services: `nmap -sS -sV -p- <target-ip>`
	- Web discovery: use a browser or non-destructive tools to view public web pages on the target VM.
	- Use passive information-gathering and documentation to record findings.
8. Cleanup:
	- Revert to snapshots after testing to return to a clean state and delete any generated sensitive artifacts.

Expected outcomes

- A functional Kali Linux VM in VMware with VMware Tools installed.
- A separate vulnerable VM deployed and reachable from the Kali VM over an isolated host-only network.
- Successful non-destructive reconnaissance and service enumeration reports saved for analysis.
- Snapshots available to restore clean VM states after testing.

Conclusion

Installing Kali in VMware and provisioning a vulnerable VM on a host-only network provides a safe environment to practice penetration-testing techniques; always operate in isolated labs and only test systems you own or are explicitly authorized to assess.

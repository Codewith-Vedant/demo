# Implementation of networking commands to retrieve device information and network configuration using Linux

This file lists 8 highly popular Linux commands for getting device information and basic network configuration. Packet-capture commands are intentionally excluded. Each entry includes the command, its purpose, and an example.

**Ethics & Legal:** Use these commands only on systems you own or where you have explicit authorization.

---

## Selected 8 Popular Commands (no packet-capture)

1. `uname -a` — Purpose: Show kernel, hostname, kernel version and architecture.
   - Example: `uname -a`

2. `hostnamectl` — Purpose: Show/manage system hostname and basic OS information (systemd systems).
   - Example: `hostnamectl`

3. `lscpu` — Purpose: Display CPU architecture and details.
   - Example: `lscpu`

4. `ip addr` (or `ip a`) — Purpose: Show IP addresses assigned to interfaces.
   - Example: `ip addr show`

5. `ip route` — Purpose: Show routing table and default gateway.
   - Example: `ip route show`

6. `ss -tulwn` — Purpose: Show listening sockets and open connections (replacement for `netstat`).
   - Example: `ss -tulwn`

7. `ping <host>` — Purpose: Basic ICMP reachability check and latency.
   - Example: `ping -c 4 8.8.8.8`

8. `traceroute <host>` (or `tracepath`) — Purpose: Show network path and hops to a destination.
   - Example: `traceroute 8.8.8.8`

---

## Short Notes

- Prefer `ip` and `ss` for modern Linux over legacy `ifconfig`/`netstat`.
- Use `sudo` where required for privileged commands.
- Run potentially disruptive commands only with permission and understanding.

---

If you want, I can now:
- create a small `collect-netinfo.sh` script that runs these 8 commands and saves output to a report file, or
- produce distro-specific variants (Debian/Ubuntu vs RHEL/CentOS).

File: `/workspaces/csl/exp1.md`

---

## Google Dorking — Responsible OSINT Examples (8 safe queries)

Use these responsibly and only to find information that is publicly available or for domains you own or have permission to assess. Replace placeholders like `[domain]`, `[organization]` or `[person name]` before running the query.

1. `site:[domain] intitle:"about" OR intitle:"about us"` — Purpose: Find the organization's public "About" page and high-level contact/mission info.

2. `site:[domain] inurl:contact OR inurl:"contact-us"` — Purpose: Locate official contact pages and support addresses.

3. `site:linkedin.com "[Organization]"` — Purpose: Find the organization's public LinkedIn profile and employee listings (publicly posted).

4. `site:github.com "[Organization]" OR "[Organization]" in:readme` — Purpose: Find public GitHub repositories and projects associated with the organization.

5. `site:[domain] filetype:pdf "annual report" OR "press release"` — Purpose: Locate public PDFs (reports, press releases) published by the organization.

6. `intitle:"team" OR intitle:"leadership" "[Organization]"` — Purpose: Find publicly listed leadership/team pages.

7. `"[person name]" site:linkedin.com OR site:twitter.com OR site:github.com` — Purpose: Search for public social/profile pages for an individual (publicly posted info only).

8. `site:[domain] "careers" OR "jobs" OR "open position"` — Purpose: Find public job listings or hiring pages which often list teams, locations, and contact HR channels.

Note: These queries are designed to find legitimate, publicly posted information (company pages, press releases, public profiles). Do not use search queries to hunt for credentials, leaked data, or private/internal systems. If you need more targeted OSINT techniques for a legal assessment, confirm scope and authorization and I can suggest safe methodologies.


- `ss -tulwn` : Purpose: Show listening sockets and open connections (replacement for netstat).

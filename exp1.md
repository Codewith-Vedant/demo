# Implementation of networking commands to retrieve device information and network configuration using Linux

Aim

To implement and use a concise set of Linux commands to collect device information and basic network configuration, and to perform responsible passive OSINT (Google dorking) to locate publicly available organizational information.

Procedure

1. Run the eight chosen commands to gather host and network data:
   - `uname -a`, `hostnamectl`, `lscpu`, `ip addr`, `ip route`, `ss -tulwn`, `ping <host>`, `traceroute <host>`
2. Record outputs to a timestamped report (e.g., redirect outputs into a single file).
3. Perform responsible Google dorking using placeholder-based queries to collect only publicly posted information (replace `[domain]`, `[org]`, `[person]`).
4. Review and store findings securely, and remove sensitive local artifacts if required.

Expected outcomes

- A compact inventory of system details: kernel, hostname, CPU, and basic hardware identifiers.
- Network configuration snapshot: interfaces, assigned IPs, routes, listening services, and basic connectivity checks.
- A small set of saved report files containing command outputs for later review.
- A list of publicly available organizational pages and profiles found via safe Google dork queries.

Conclusion

Using these eight commands alongside responsible Google dorking yields a fast, legal-first method to map device attributes and basic network state; always obtain authorization before probing or collecting data from systems or domains you do not own.

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

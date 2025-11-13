# Implementation of Vulnerability Assessment using NESSUS Tool

## Aim

To install, configure, and utilize Tenable Nessus vulnerability scanner on Ubuntu to conduct comprehensive network vulnerability assessments, generate detailed observation reports, and provide actionable remediation recommendations for identified security vulnerabilities.

## Theory

### What is Nessus?

Nessus is a proprietary vulnerability scanner developed by Tenable. It is the industry-leading tool for identifying vulnerabilities, configuration issues, compliance violations, and malware in networks, systems, and applications. Nessus can scan thousands of devices simultaneously and discover vulnerabilities that could expose systems to cyber threats.

### Why Nessus is Important?

**Security Benefits:**
- Identifies zero-day vulnerabilities before attackers discover them
- Detects misconfigurations and policy violations
- Provides prioritized remediation recommendations
- Integrates with compliance frameworks (PCI-DSS, HIPAA, SOC2)
- Enables proactive security posture management

**Operational Benefits:**
- Scans large networks quickly and efficiently
- Provides detailed, actionable reports
- Supports authenticated scans for deeper insights
- Offers customizable scan policies for different scenarios
- Integrates with ticketing and SIEM systems

### Nessus Versions

**Nessus Essentials (Free)**
- Unlimited scans on up to 16 IPs
- Web-based interface
- Access to 50,000+ plugins
- Basic vulnerability scanning
- Best for personal use and small testing

**Nessus Professional**
- Unlimited scanning capacity
- Compliance auditing (PCI-DSS, HIPAA, CIS)
- Web application scanning
- Advanced features and priority support
- For small organizations

**Nessus Manager / Cloud**
- Enterprise-level deployment
- Multiple scanner management
- Advanced reporting and analytics
- Vulnerability Priority Rating (VPR)
- For large organizations

### How Nessus Works

**Scanning Process:**
1. **Plugin Download**: Nessus downloads and compiles security check plugins (50,000+)
2. **Network Scanning**: Probes target systems for open ports and services
3. **Vulnerability Detection**: Matches findings against vulnerability database
4. **Risk Assessment**: Assigns severity based on CVSS scores
5. **Report Generation**: Creates detailed vulnerability reports

### Vulnerability Severity Levels

**Critical (CVSS 9.0-10.0)**
- Immediate exploitation risk
- Requires urgent remediation
- Could lead to complete system compromise
- Examples: Remote code execution, SQL injection

**High (CVSS 7.0-8.9)**
- Exploitable with moderate effort
- Should be patched within days
- Could allow unauthorized access
- Examples: Authentication bypass, privilege escalation

**Medium (CVSS 4.0-6.9)**
- Lower exploitation probability
- Address within weeks
- May require specific conditions to exploit
- Examples: Weak encryption, outdated software

**Low (CVSS 0.1-3.9)**
- Limited security impact
- Address within months
- Minimal exploitability
- Examples: Information disclosure, weak headers

**Info**
- Informational only
- No direct security threat
- Useful for documentation

### Scan Types in Nessus

**1. Basic Network Scan**
- Default scan for vulnerability detection
- No credentials required
- Identifies common vulnerabilities
- Best for reconnaissance

**2. Advanced Scan**
- Customizable plugin selection
- Credential-based authenticated scanning
- Deeper vulnerability detection
- Flexible targeting options

**3. Web Application Scan**
- Specifically for web applications
- Detects: SQL injection, XSS, CSRF
- Tests authentication mechanisms
- Analyzes client-side vulnerabilities

**4. Host Discovery**
- Maps active devices on network
- Identifies open ports
- Discovers services and OS information
- No vulnerability scanning

**5. Compliance Scan**
- Checks against compliance standards
- Frameworks: PCI-DSS, HIPAA, CIS Benchmarks
- Generates compliance reports
- Tracks policy violations

**6. Malware Scan**
- Detects malicious software
- Identifies compromised systems
- Checks for backdoors
- Available in advanced versions

### CVSS Scoring System

**CVSS v3.1 Metrics:**

| Metric | Description |
|--------|-------------|
| Attack Vector | How vulnerability is exploited (Network, Adjacent, Local, Physical) |
| Attack Complexity | Effort required to exploit (Low, High) |
| Privileges Required | Access level needed (None, Low, High) |
| User Interaction | Whether user action needed (None, Required) |
| Scope | Impact beyond vulnerable component (Unchanged, Changed) |
| Confidentiality Impact | Data disclosure impact (None, Low, High) |
| Integrity Impact | Data modification impact (None, Low, High) |
| Availability Impact | System availability impact (None, Low, High) |

**Score Calculation**: 0.0 to 10.0 (Higher = More severe)

### Vulnerability Priority Rating (VPR)

Modern approach beyond CVSS considering:
- **Age of vulnerability**: How long it's been public
- **Threat activity**: Real-world exploitation attempts
- **Threat intensity**: Frequency of attacks
- **Exploit availability**: Public exploits exist
- **Threat sources**: Dark web mentions, hacker forums

## Prerequisites

### System Requirements
- Ubuntu 20.04 LTS or higher
- Minimum 4GB RAM (8GB+ recommended)
- 20GB free disk space (for Nessus installation and plugins)
- Network connectivity to target systems
- Root or sudo privileges
- Modern web browser for interface

### Network Requirements
- Access to target systems
- Appropriate firewall rules allowing scans
- Credentials for authenticated scans (optional)
- Network connectivity from scanner to targets

### Software Requirements
- curl or wget for downloading
- dpkg for package management
- systemctl for service management

## Procedure

### Part 1: Download and Install Nessus on Ubuntu

#### Step 1: Check System Requirements
```bash
# Check Ubuntu version
lsb_release -a

# Check available disk space
df -h /

# Check RAM
free -h

# Verify internet connectivity
ping -c 1 8.8.8.8
```

#### Step 2: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 3: Download Nessus for Ubuntu

Visit official Tenable website:
```
https://www.tenable.com/downloads/nessus
```

Or download using curl:
```bash
# Download latest Nessus Essentials (Ubuntu 20.04+, 64-bit)
sudo curl --request GET \
  --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.7.2-ubuntu1404_amd64.deb' \
  --output '/tmp/Nessus-10.7.2-ubuntu1404_amd64.deb'

# Verify download
ls -lh /tmp/Nessus*.deb

# Optional: Verify SHA256 checksum
# Get checksum from Tenable website and verify:
sha256sum /tmp/Nessus-10.7.2-ubuntu1404_amd64.deb
```

#### Step 4: Install Nessus Package
```bash
# Install using dpkg
sudo dpkg -i /tmp/Nessus-10.7.2-ubuntu1404_amd64.deb

# Wait for installation to complete (may take 2-5 minutes)
```

#### Step 5: Start Nessus Service
```bash
# Start the Nessus daemon service
sudo systemctl start nessusd.service

# Enable to start on boot
sudo systemctl enable nessusd.service

# Verify service is running
sudo systemctl status nessusd.service

# Should show: "Active: active (running)"
```

#### Step 6: Verify Nessus Installation
```bash
# Check Nessus version
/opt/nessus/sbin/nessuscli -v

# Check service status
sudo systemctl is-active nessusd

# View Nessus processes
ps aux | grep nessus | grep -v grep
```

---

### Part 2: Initial Setup and Registration

#### Step 1: Access Nessus Web Interface
```bash
# Open web browser and navigate to
https://localhost:8834/

# Or use IP address
https://<YOUR_UBUNTU_IP>:8834/
```

**Note**: You may see SSL certificate warning. Click "Advanced" or "Proceed anyway" as Nessus uses self-signed certificates.

#### Step 2: Register for Activation Code (Free)

**Option A: Online Registration**
1. At welcome screen, click **"Register for Nessus Essentials"**
2. Enter your details:
   - Full Name
   - Email address
   - Company name
3. Click **"Register"**
4. Check email for activation code
5. Copy activation code

**Option B: Offline Registration** (if no internet)
1. At setup screen, note the Challenge Code
2. Visit: https://plugins.nessus.org/v2/offline.php
3. Enter Challenge Code and Activation Code
4. Get License Code
5. Paste License Code in Nessus interface

#### Step 3: Create Administrator Account
```
1. Username: admin (or your preferred username)
2. Password: Strong password (mix of uppercase, lowercase, numbers, symbols)
3. Click "Submit"
```

#### Step 4: Wait for Plugin Compilation
```
Nessus will compile 50,000+ security plugins
- This process takes 15-30 minutes
- Monitor progress at: https://localhost:8834/#/settings/about/events
- Status updates every minute
- DO NOT close browser or restart service
```

#### Step 5: Verify Installation Complete
```bash
# Check plugin compilation status
curl -s -k https://localhost:8834/nessus6.js | grep -i "compiled"

# Or check logs
tail -50 /opt/nessus/var/nessus/nessusd.log | grep -i "compiled\|finished"
```

---

### Part 3: Understanding the Nessus Interface

#### Step 1: Login to Nessus Dashboard
```
https://localhost:8834/

Username: admin (or your created username)
Password: Your chosen password
```

#### Step 2: Explore Dashboard Sections

**Main Menu Options:**
- **Scans**: Create, manage, and run vulnerability scans
- **Policies**: Define scan configurations and templates
- **Settings**: System configuration, user management
- **About**: Version info, plugin status, event logs

#### Step 3: Understand Scan Dashboard
```
Left Panel:
- My Scans: Your created scans
- Compliance: Compliance-specific scans
- Templates: Pre-configured scan templates

Top Right:
- New Scan: Create new vulnerability scan
- Upload: Import scan files
- Settings: Configure Nessus
```

---

### Part 4: Create Your First Vulnerability Scan

#### Step 1: Navigate to Scans
```
Click: "Scans" menu
Click: "New Scan" button (top right)
```

#### Step 2: Select Scan Template
Choose from templates:
- **Basic Network Scan** (recommended for beginners)
- **Advanced Scan**
- **Web Application Scan**
- **Host Discovery**

```
For this example, select: "Basic Network Scan"
```

#### Step 3: Configure Scan Settings

**General Settings Tab:**

| Setting | Value | Description |
|---------|-------|-------------|
| Scan Name | "Ubuntu Lab Scan" or custom | Descriptive name for your scan |
| Description | Optional | Add scan notes |
| Target | 192.168.1.100 or IP/CIDR | IP address or range to scan |
| Schedule | Off (for manual scans) | Leave off for first scan |

**Specify Target**
```
Click: "Targets" section
Enter Target IP/Range:
- Single IP: 192.168.1.100
- CIDR Range: 192.168.1.0/24
- Multiple IPs: 192.168.1.100, 192.168.1.101, 192.168.1.102
- Hostname: target.example.com
```

**Discovery Tab:**
```
Port scanning: Standard ports (22, 80, 443, etc.)
Service enumeration: Enabled
OS Identification: Enabled
```

**Assessment Tab:**
```
Web applications: Enabled
Databases: Enabled
SNMP enumeration: Enabled
```

**Credentials Tab (Optional)**

For deeper scanning, add credentials:

**SSH Credentials:**
```
Username: your_username
Password: OR SSH key file
Port: 22 (default)
```

**SMB Credentials (Windows):**
```
Username: DOMAIN\username
Password: password
```

#### Step 4: Save Scan Configuration
```
Click: "Save" button (top right)
Scan is now saved and ready to launch
```

---

### Part 5: Launch and Monitor Scans

#### Step 1: Launch the Scan
```
From Scans menu:
Find your created scan
Click: Launch button (play icon) or
Click scan name, then "Launch" button
```

#### Step 2: Monitor Scan Progress
```
Real-time progress shows:
- Scan completion percentage
- Elapsed time
- Vulnerabilities discovered so far
- Hosts scanned
- Estimated time remaining

Current Status View:
Refresh automatically every 10 seconds
```

#### Step 3: Track Scanning Activity
```bash
# Monitor from terminal (optional)
tail -f /opt/nessus/var/nessus/nessusd.log | grep "scanning\|scan"

# Or check scan status via API
curl -s -k https://localhost:8834/nessus6.js | grep -i "scan_status"
```

#### Step 4: Wait for Scan Completion
```
Initial scan of single host: 5-15 minutes
Network range (Class C): 30-60 minutes
Time varies based on:
- Network speed
- Number of hosts
- Ports discovered
- Services detected
- Plugins running

DO NOT interrupt scan (let it complete)
```

---

### Part 6: Analyze Scan Results

#### Step 1: View Scan Results
```
Click: Completed scan name
Results display automatically after completion
```

#### Step 2: Understand Results Dashboard

**Key Sections:**

1. **Vulnerability Summary**
   - Total vulnerabilities found
   - Breakdown by severity (Critical, High, Medium, Low, Info)
   - Visual charts and graphs

2. **Hosts Summary**
   - List of scanned hosts
   - Vulnerabilities per host
   - Severity distribution

3. **Vulnerability Details**
   - Complete list of found vulnerabilities
   - Each vulnerability shows:
     - Plugin ID
     - CVE reference
     - CVSS score
     - Risk factor
     - Remediation details

#### Step 3: Filter and Search Results

**Filter by Severity:**
```
Click: Severity filter
Select: Critical (to see critical issues first)
View filtered results
```

**Search for Specific CVE:**
```
Search box: Enter CVE ID (e.g., CVE-2021-12345)
Shows only matching vulnerabilities
```

**Filter by Plugin Type:**
```
Click: Plugin type dropdown
Select: SQL Injection, XSS, or other categories
```

#### Step 4: Examine Individual Vulnerabilities

**Click any vulnerability to view:**
- **Vulnerability Description**: What is the issue
- **CVSS Score**: Severity rating
- **Risk Factor**: How dangerous it is
- **Affected Plugin**: Which check found it
- **Solution**: How to fix it
- **See Also**: Related resources
- **References**: CVE links, advisories

**Example Vulnerability Details:**
```
Name: Apache Web Server Version Detection
Plugin ID: 10330
CVSS Score: 5.3 (Medium)
Risk Factor: Medium

Description:
It is possible to determine the version of Apache 
web server running on the remote host.

Solution:
Disable the server banner or modify it so version 
information is not disclosed.

References:
https://httpd.apache.org/docs/
CVE: CVE-2018-1283
```

#### Step 5: Identify High-Risk Vulnerabilities
```
Review "Critical" and "High" severity vulnerabilities first
- These require immediate attention
- May allow remote code execution
- Could lead to system compromise

Medium severity: Address within weeks
Low severity: Address within months
```

---

### Part 7: Generate Observation Reports

#### Step 1: Access Report Generation

```
From scan results:
Click: "Report" button (top menu)
Or Select: Vulnerabilities → Export
```

#### Step 2: Choose Report Format

**Available Formats:**

| Format | Best For | Extension |
|--------|----------|-----------|
| PDF | Formal reports, presentations | .pdf |
| HTML | Interactive viewing, web sharing | .html |
| CSV | Data analysis, spreadsheets | .csv |
| Nessus | Reimporting, archival | .nessus |

#### Step 3: Generate PDF Report

**Step-by-Step:**

```
1. Click: "Generate Report"
2. Select Format: "PDF"
3. Choose Template: "Detailed Report" or "Executive Summary"
4. Configure Options:
   - Include vulnerabilities: Yes
   - Include remediation: Yes
   - Include CVSS details: Yes
5. Click: "Generate"
```

**Report Template Options:**
- **Full Report**: Complete vulnerability details
- **Executive Summary**: High-level overview
- **Compliance Report**: For regulatory compliance
- **Custom**: Select specific sections

#### Step 4: Monitor Report Generation
```
Report generation takes 5-15 minutes
Shows progress bar
Do not close browser until complete
```

#### Step 5: Download Report
```
Once generated:
Click: Download link
File saved to: ~/Downloads/scan_report_[date].pdf
```

#### Step 6: Generate CSV Report (for Analysis)

```
1. Click: "Export" or "Generate Report"
2. Select Format: "CSV"
3. Choose Columns to Include:
   - Plugin ID
   - CVE
   - CVSS Score
   - Risk Factor
   - Host
   - Vulnerability Description
   - Solution
4. Click: "Generate"
5. Download CSV file
6. Open in Excel or Google Sheets for analysis
```

---

### Part 8: Create Detailed Observation Report

#### Step 1: Extract Key Information

**From Nessus results, document:**

1. **Executive Summary**
   - Total vulnerabilities found
   - Critical count
   - High count
   - Affected hosts

2. **Vulnerability Breakdown**
   - By severity level
   - By vulnerability type
   - By affected service

3. **Top Critical Issues**
   - List top 5-10 critical vulnerabilities
   - Include CVE IDs
   - CVSS scores
   - Immediate risks

#### Step 2: Create Observation Report Script

```bash
# Create automated report generation
cat > /usr/local/bin/nessus_report.sh << 'EOF'
#!/bin/bash

REPORT_FILE="/tmp/observation_report_$(date +%Y%m%d_%H%M%S).txt"
SCAN_NAME="$1"

{
  echo "=========================================="
  echo "NESSUS VULNERABILITY ASSESSMENT REPORT"
  echo "=========================================="
  echo "Date: $(date)"
  echo "Scan: $SCAN_NAME"
  echo ""
  
  echo "VULNERABILITY SUMMARY"
  echo "====================="
  echo "Critical Issues: $(grep -c 'Critical' /opt/nessus/var/nessus/scans/$SCAN_NAME/*.nessus 2>/dev/null || echo 'N/A')"
  echo "High Issues: $(grep -c 'High' /opt/nessus/var/nessus/scans/$SCAN_NAME/*.nessus 2>/dev/null || echo 'N/A')"
  echo "Medium Issues: $(grep -c 'Medium' /opt/nessus/var/nessus/scans/$SCAN_NAME/*.nessus 2>/dev/null || echo 'N/A')"
  echo "Low Issues: $(grep -c 'Low' /opt/nessus/var/nessus/scans/$SCAN_NAME/*.nessus 2>/dev/null || echo 'N/A')"
  echo ""
  
  echo "RECOMMENDATIONS"
  echo "==============="
  echo "1. Address all CRITICAL vulnerabilities immediately"
  echo "2. Create remediation plan for HIGH severity issues"
  echo "3. Schedule medium-term fixes for MEDIUM severity"
  echo "4. Document addressed vulnerabilities"
  echo ""
  
  echo "Report Generated: $(date)"
} | tee $REPORT_FILE

echo "Report saved to: $REPORT_FILE"
```

#### Step 3: Document Findings

**Create manual observation report with:**

```
VULNERABILITY ASSESSMENT OBSERVATION REPORT
============================================

Target: [IP address or hostname]
Date: [Date of scan]
Scanner: Nessus [version]
Scan Duration: [Time taken]

FINDINGS SUMMARY:
- Critical Vulnerabilities: [X]
- High Vulnerabilities: [Y]
- Medium Vulnerabilities: [Z]
- Low Vulnerabilities: [W]
- Total: [X+Y+Z+W]

CRITICAL FINDINGS (Immediate Action Required):
1. [Vulnerability Name]
   - CVE: [ID]
   - CVSS Score: [Score]
   - Affected Host: [IP]
   - Risk: [Detailed risk]
   - Remediation: [Fix steps]

HIGH FINDINGS (Address Within 30 Days):
[Similar format]

MEDIUM FINDINGS (Address Within 90 Days):
[Similar format]

REMEDIATION PRIORITIES:
1. [First priority fix]
2. [Second priority fix]
3. [Third priority fix]

NEXT STEPS:
- Schedule remediation activities
- Assign responsibility
- Track progress
- Schedule re-scan after fixes

Report Prepared By: [Name]
Date: [Date]
```

---

### Part 9: Remediation and Follow-up

#### Step 1: Prioritize Vulnerabilities

**Risk Matrix:**
```
CRITICAL & High Risk CVSS (9-10):
→ Fix IMMEDIATELY (within 24 hours)
→ May lead to complete system compromise

HIGH Risk CVSS (7-8.9):
→ Fix urgently (within 1 week)
→ Exploitable with moderate effort

MEDIUM Risk CVSS (4-6.9):
→ Fix soon (within 1 month)
→ Lower exploitation probability

LOW Risk CVSS (0.1-3.9):
→ Fix eventually (within quarter)
→ Minimal direct security impact
```

#### Step 2: Create Remediation Plan

```bash
# Create remediation tracking
cat > /tmp/remediation_plan.txt << 'EOF'
REMEDIATION ACTION PLAN
========================

Vulnerability: [Name]
Priority: [Critical/High/Medium/Low]
CVSS Score: [Score]
Target Host: [IP]

Current Status: Identified
Assigned To: [Person]
Due Date: [Date based on severity]

Remediation Steps:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Verification:
- Run re-scan after fix
- Confirm vulnerability resolved
- Document completion

Status Updates:
[Track progress here]
EOF

cat /tmp/remediation_plan.txt
```

#### Step 3: Document Fixes

```
For each vulnerability addressed:

1. Note the fix applied
2. Record date of remediation
3. Schedule re-scan
4. Verify vulnerability resolved
5. Update tracking spreadsheet
```

#### Step 4: Schedule Re-scans

```
After remediation:

1. Wait 24-48 hours for systems to stabilize
2. Run scan on same targets
3. Compare new results with previous
4. Verify vulnerabilities are resolved
5. Document any new issues
```

---

### Part 10: Advanced Nessus Features

#### Step 1: Authenticated Scanning

**For deeper vulnerability detection:**

```bash
# In Nessus scan settings:
1. Click: "Credentials" tab
2. Add SSH/SMB credentials
3. Enter username and password
4. Select appropriate authentication type
5. Save and re-run scan

Benefits:
- Detect vulnerabilities inside systems
- Check installed package versions
- Verify security configurations
- Access permission issues
```

#### Step 2: Create Custom Scan Policies

```
From main menu:
1. Click: "Policies"
2. Click: "Create Policy"
3. Select: Base template
4. Configure: Plugins to enable/disable
5. Customize: Specific checks for your environment
6. Save: For future use
```

#### Step 3: Schedule Recurring Scans

```
From scan settings:
1. Click: "Schedule" tab
2. Enable: "Recurring"
3. Set: Frequency (daily, weekly, monthly)
4. Configure: Time to run scans
5. Set: Automatic cleanup of old scans

Benefits:
- Continuous monitoring
- Trend analysis
- Compliance proof
- Early threat detection
```

#### Step 4: Integration and API

```bash
# Nessus REST API example
# List all scans:
curl -s -k -X GET \
  -H "X-ApiKeys: accessKey=YOUR_ACCESS_KEY;secretKey=YOUR_SECRET_KEY" \
  https://localhost:8834/scans

# Export scan results programmatically
curl -s -k -X POST \
  -H "X-ApiKeys: accessKey=YOUR_ACCESS_KEY;secretKey=YOUR_SECRET_KEY" \
  https://localhost:8834/scans/{scan_id}/export
```

---

## Expected Outcomes

After implementing Nessus vulnerability assessment, you will achieve:

1. **Comprehensive Vulnerability Discovery**
   - Identify all known vulnerabilities on target systems
   - Discover misconfigurations and policy violations
   - Find outdated software and missing patches
   - Detect potential security weaknesses

2. **Detailed Observation Reports**
   - Professional vulnerability reports (PDF/HTML)
   - Executive summary for management
   - Technical details for IT teams
   - Actionable remediation steps

3. **Risk Prioritization**
   - Clear severity classifications
   - CVSS and VPR scores
   - Remediation timelines
   - Business impact assessment

4. **Compliance Documentation**
   - Compliance check results
   - Policy violation details
   - Audit trail documentation
   - Regulatory requirement mapping

5. **Continuous Security Improvement**
   - Baseline for future comparisons
   - Metrics for security posture
   - Tracking of remediation progress
   - Trend analysis over time

6. **Actionable Intelligence**
   - Specific fix recommendations
   - Configuration changes needed
   - Patch applications required
   - Best practices guidance

## Conclusion

Nessus provides a comprehensive vulnerability management solution enabling organizations to systematically identify, prioritize, and remediate security vulnerabilities. By conducting regular scans and following the remediation process:

- Reduce overall risk profile
- Maintain security compliance
- Demonstrate due diligence
- Protect critical assets
- Enable informed security decisions

The combination of automated vulnerability detection with manual risk assessment creates a robust security program.

## Important Security Considerations

**Ethical Use:**
- Only scan systems you own or have permission to scan
- Unauthorized scanning may be illegal
- Document all scanning activities
- Maintain audit logs
- Follow your organization's policies

**Best Practices:**
- Scan during maintenance windows when possible
- Avoid scanning during peak hours
- Test scan settings in non-production first
- Keep Nessus plugins updated regularly
- Maintain secure credentials
- Review reports for false positives
- Prioritize remediation by risk
- Document all findings

## Quick Reference

```bash
# Start Nessus service
sudo systemctl start nessusd.service

# Access Nessus web interface
https://localhost:8834/

# Check service status
sudo systemctl status nessusd.service

# View plugins status
tail -f /opt/nessus/var/nessus/nessusd.log

# Download plugins manually
cd /opt/nessus/var/nessus/plugins
ls -lh

# Restart service
sudo systemctl restart nessusd.service
```

## Download Links

- **Nessus Downloads**: https://www.tenable.com/downloads/nessus
- **Nessus Documentation**: https://docs.tenable.com/nessus/
- **CVE Database**: https://cve.mitre.org/
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **Tenable Blog**: https://www.tenable.com/blog

This comprehensive guide enables security professionals to deploy, operate, and leverage Nessus for effective vulnerability management and security assessment.

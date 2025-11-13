# Study of Log Analysis: Server Event Log / Firewall Logs / Security Logs

## Aim

To understand, locate, extract, and analyze various types of Linux logs including system event logs, firewall logs, and security logs on Ubuntu using command-line tools to monitor system activity, detect security threats, and troubleshoot system issues.

## Theory

### What are System Logs?

System logs are text-based records that capture events occurring on a Linux system. They document:
- System startup and shutdown events
- Authentication attempts (successful and failed)
- Service activities and errors
- Firewall rule violations
- Hardware events and errors
- Application activities
- Network connections

### Why Log Analysis Matters?

**Security Perspective:**
- Detect unauthorized access attempts
- Identify brute force attacks
- Trace security breaches
- Monitor suspicious activities
- Comply with security policies

**Operational Perspective:**
- Troubleshoot system issues
- Monitor application performance
- Identify resource bottlenecks
- Plan capacity upgrades
- Audit user activities

**Compliance Perspective:**
- Meet regulatory requirements (GDPR, HIPAA, SOC2)
- Maintain audit trails
- Document system changes
- Prove compliance with policies

### Linux Log Architecture

**Centralized Logging System:**
- **rsyslog**: Default logging daemon on Ubuntu (handles syslog protocol)
- **journald**: systemd's logging service (newer, binary format)
- **auditd**: Linux audit framework for advanced auditing

**Log Storage:**
- Text files in `/var/log` directory
- Binary journal in `/var/log/journal` (systemd)
- Rotated logs with `.1`, `.2` extensions
- Compressed old logs with `.gz` extension

### Log Format Structure

**Standard Syslog Format:**
```
Timestamp Hostname Process[PID]: Message
Nov 13 22:45:12 ubuntu sshd[2341]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
```

**Components:**
- **Timestamp**: Date and time of event
- **Hostname**: Name of the system
- **Process**: Name of service/application
- **PID**: Process ID in brackets
- **Message**: Detailed description of event

### Important Log Types and Locations

| Log File | Location | Purpose |
|----------|----------|---------|
| System Log | `/var/log/syslog` (Ubuntu) or `/var/log/messages` | General system messages, startup info |
| Auth Log | `/var/log/auth.log` | Authentication attempts, user logins, sudo commands |
| Kernel Log | `/var/log/kern.log` | Kernel events, hardware errors, boot messages |
| Boot Log | `/var/log/boot.log` | System startup messages and services |
| Cron Log | `/var/log/cron` or in syslog | Scheduled job (cron) execution |
| Daemon Log | `/var/log/daemon.log` | Background daemon activities |
| Apache Access | `/var/log/apache2/access.log` | HTTP requests to web server |
| Apache Error | `/var/log/apache2/error.log` | Web server errors and issues |
| Firewall Log | `/var/log/ufw.log` (UFW) or iptables logs | Blocked/allowed network packets |
| Secure Log | `/var/log/secure` (RHEL/CentOS) | Security-related events |
| Failed Login | `/var/log/faillog` | Failed login attempts (binary) |
| Last Login | `/var/log/lastlog` | Last successful logins (binary) |
| MySQL/MariaDB | `/var/log/mysql/error.log` | Database errors and activities |
| SSH Daemon | Mixed in `/var/log/auth.log` and journald | SSH connection attempts |

### Firewall Logging

**UFW (Uncomplicated Firewall):**
- Default firewall on Ubuntu
- Logs to `/var/log/ufw.log`
- Tracks blocked and allowed packets
- Records source IP, destination port, protocol

**Log Entry Structure:**
```
Nov 13 22:45:30 ubuntu kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.5 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
```

**Components:**
- **[UFW BLOCK]**: Action taken (BLOCK or ALLOW)
- **IN**: Incoming network interface
- **OUT**: Outgoing network interface
- **SRC**: Source IP address
- **DST**: Destination IP address
- **PROTO**: Protocol (TCP, UDP, ICMP)
- **SPT**: Source port
- **DPT**: Destination port

### Security Events to Monitor

1. **Failed Login Attempts**: Indicates brute force or unauthorized access attempts
2. **Root/sudo Access**: Tracks privileged command execution
3. **File Modifications**: Changes to system files or permissions
4. **Network Connections**: Inbound/outbound connections, port access
5. **Package Changes**: Installation/removal of software
6. **Authentication Failures**: PAM (Pluggable Authentication Modules) errors
7. **Service Errors**: Service startup failures or crashes
8. **Privilege Escalation**: Unauthorized attempts to gain higher privileges

## Prerequisites

- Ubuntu 20.04 LTS or higher
- Root or sudo privileges
- Terminal access
- Basic command-line knowledge
- Text editors (nano, vi) for config files

## Procedure

### Part 1: Understanding Log Locations and Directory Structure

#### Step 1: Navigate to Log Directory
```bash
cd /var/log
ls -la
```

#### Step 2: View Log Directory Structure
```bash
tree /var/log
```

If tree is not installed:
```bash
sudo apt install -y tree
tree /var/log -L 2
```

#### Step 3: List All Available Logs
```bash
# List text logs
ls -lh /var/log/*.log

# List subdirectories with logs
ls -lhd /var/log/*/
```

#### Step 4: Check Log Disk Space Usage
```bash
# Total size of log directory
du -sh /var/log

# Individual log file sizes
du -sh /var/log/* | sort -h

# Find largest log files
find /var/log -type f -printf '%s %p\n' | sort -rn | head -20
```

---

### Part 2: System Log Analysis (Syslog/Messages)

#### Step 1: View Complete System Log
```bash
# View entire syslog
sudo cat /var/log/syslog

# View with paging (spacebar to navigate)
sudo less /var/log/syslog

# View last 50 lines
sudo tail -50 /var/log/syslog

# View last 100 lines with continuous update
sudo tail -f /var/log/syslog
```

#### Step 2: Search System Log for Specific Keywords
```bash
# Search for errors
sudo grep -i "error" /var/log/syslog

# Search for warnings
sudo grep -i "warning" /var/log/syslog

# Search for specific service (e.g., SSH)
sudo grep "sshd" /var/log/syslog

# Search for specific IP address
sudo grep "192.168.1.100" /var/log/syslog
```

#### Step 3: Filter by Date/Time Range
```bash
# Show logs from last hour
sudo grep "$(date +'%b %d %H:' -d '1 hour ago')" /var/log/syslog | tail

# Show logs from today
sudo grep "$(date '+%b %d')" /var/log/syslog | head -20

# Show logs from specific date
sudo grep "Nov 13" /var/log/syslog
```

#### Step 4: Advanced Filtering with awk and cut
```bash
# Extract specific columns (timestamp and message)
sudo awk '{print $1, $2, $3, $NF}' /var/log/syslog

# Count occurrences of each process
sudo awk '{print $5}' /var/log/syslog | sort | uniq -c | sort -rn

# Show only specific priority levels
sudo grep -E "CRITICAL|ERROR|WARNING" /var/log/syslog
```

---

### Part 3: Authentication and Security Log Analysis

#### Step 1: View Authentication Log
```bash
# View complete auth log
sudo cat /var/log/auth.log

# View last 50 auth entries
sudo tail -50 /var/log/auth.log

# Continuously monitor auth log
sudo tail -f /var/log/auth.log
```

#### Step 2: Find Failed Login Attempts
```bash
# Show all failed password attempts
sudo grep "Failed password" /var/log/auth.log

# Count failed attempts per user
sudo grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Count failed attempts per IP address
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# Show failed attempts in last 24 hours
sudo grep "Failed password" /var/log/auth.log | tail -100
```

#### Step 3: Find Invalid User Attempts
```bash
# Search for invalid user attempts
sudo grep "Invalid user" /var/log/auth.log

# Count invalid user attempts by username
sudo grep "Invalid user" /var/log/auth.log | awk '{print $5}' | sort | uniq -c | sort -rn

# Count invalid attempts per IP
sudo grep "Invalid user" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```

#### Step 4: Analyze Successful Logins
```bash
# Show successful SSH logins
sudo grep "Accepted password\|Accepted publickey" /var/log/auth.log

# Count successful logins per user
sudo grep "Accepted password\|Accepted publickey" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -rn

# Show which users logged in today
sudo grep "Accepted" /var/log/auth.log | grep "$(date '+%b %d')" | awk '{print $1, $2, $3, $9}' | sort -u
```

#### Step 5: Track Sudo Command Usage
```bash
# Show all sudo commands executed
sudo grep "sudo:" /var/log/auth.log

# Count sudo commands per user
sudo grep "sudo:" /var/log/auth.log | awk '{print $6}' | sort | uniq -c | sort -rn

# Show failed sudo attempts
sudo grep "sudo.*COMMAND=" /var/log/auth.log | grep -i denied

# Track who used sudo to become root
sudo grep "sudo.*USER=root" /var/log/auth.log
```

---

### Part 4: Kernel and Boot Log Analysis

#### Step 1: View Kernel Messages
```bash
# View kernel log file
sudo cat /var/log/kern.log

# View last 50 kernel messages
sudo tail -50 /var/log/kern.log

# View kernel messages with dmesg (current boot only)
sudo dmesg
```

#### Step 2: Search for Kernel Errors
```bash
# Find all kernel errors
sudo grep -i "error" /var/log/kern.log

# Find all kernel warnings
sudo grep -i "warning" /var/log/kern.log

# Find hardware-related messages
sudo grep -i "hardware\|device\|pci\|usb" /var/log/kern.log

# Find memory-related messages
sudo grep -i "memory\|out of memory\|oom" /var/log/kern.log
```

#### Step 3: View Boot Messages
```bash
# View boot log
sudo cat /var/log/boot.log

# View systemd boot information
systemd-analyze

# Show time taken by each service during boot
systemd-analyze blame | head -20

# Show service dependencies during boot
systemd-analyze critical-chain
```

#### Step 4: Check Hardware Issues
```bash
# Show all hardware-related kernel messages
sudo dmesg | grep -i "hardware\|driver\|firmware"

# Check for disk errors
sudo dmesg | grep -i "disk\|sda\|sdb\|io error"

# Check for CPU/temperature issues
sudo dmesg | grep -i "thermal\|temperature\|cpu"

# Find all module load errors
sudo dmesg | grep -i "failed\|error" | head -20
```

---

### Part 5: Firewall Log Analysis (UFW)

#### Step 1: Enable UFW Logging
```bash
# Check if UFW is installed
sudo apt list --installed | grep ufw

# Install if not present
sudo apt install -y ufw

# Enable UFW logging
sudo ufw logging on

# Check logging status
sudo ufw status verbose
```

#### Step 2: Set UFW Logging Level
```bash
# Set to low level (logs blocked packets only)
sudo ufw logging low

# Set to medium level (logs blocked and allowed)
sudo ufw logging medium

# Set to high level (detailed logging)
sudo ufw logging high

# Turn off logging
sudo ufw logging off
```

#### Step 3: View UFW Logs
```bash
# View current UFW log file
sudo cat /var/log/ufw.log

# View last 100 firewall events
sudo tail -100 /var/log/ufw.log

# Monitor UFW logs in real-time
sudo tail -f /var/log/ufw.log
```

#### Step 4: Analyze Blocked Connections
```bash
# Show all blocked packets
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log

# Count blocked packets per IP
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | awk '{print $12}' | cut -d'=' -f2 | sort | uniq -c | sort -rn

# Show blocked ports
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | awk '{print $18}' | cut -d'=' -f2 | sort | uniq -c | sort -rn

# Find most recent blocked attempts
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | tail -20
```

#### Step 5: Analyze Allowed Connections
```bash
# Show all allowed packets
sudo grep "\[UFW ALLOW\]" /var/log/ufw.log

# Count allowed packets per source IP
sudo grep "\[UFW ALLOW\]" /var/log/ufw.log | awk '{print $12}' | cut -d'=' -f2 | sort | uniq -c | sort -rn

# Show allowed destination ports
sudo grep "\[UFW ALLOW\]" /var/log/ufw.log | awk '{print $18}' | cut -d'=' -f2 | sort | uniq -c | sort -rn
```

#### Step 6: Track Specific Attack Patterns
```bash
# Port scanning attempts (multiple blocked ports from same IP)
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | awk '{print $12}' | cut -d'=' -f2 | sort | uniq -c | awk '$1 > 10 {print $0}'

# SSH brute force attempts (port 22)
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | grep "DPT=22" | awk '{print $12}' | cut -d'=' -f2 | sort | uniq -c | sort -rn

# DNS attacks (port 53)
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | grep "DPT=53" | wc -l

# HTTP scanning (ports 80, 443)
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | grep "DPT=80\|DPT=443" | head -20
```

---

### Part 6: Using journalctl for systemd Logs

#### Step 1: View systemd Journal
```bash
# View all journal entries
sudo journalctl

# View last 50 entries
sudo journalctl -n 50

# View entries in reverse order (newest first)
sudo journalctl -r | head -50

# Monitor journal in real-time
sudo journalctl -f
```

#### Step 2: Filter by Service
```bash
# Show logs for specific service (e.g., SSH)
sudo journalctl -u ssh.service

# Show logs for multiple services
sudo journalctl -u ssh.service -u apache2.service

# Show logs since service started
sudo journalctl -u ssh.service --since today
```

#### Step 3: Filter by Priority Level
```bash
# Show only errors and above
sudo journalctl -p err

# Show warnings and above
sudo journalctl -p warning

# Show info level
sudo journalctl -p info

# Show debug level
sudo journalctl -p debug

# Priority levels: emerg(0), alert(1), crit(2), err(3), warning(4), notice(5), info(6), debug(7)
```

#### Step 4: Filter by Time Range
```bash
# Show logs from last hour
sudo journalctl --since "1 hour ago"

# Show logs from today
sudo journalctl --since today

# Show logs from specific date
sudo journalctl --since "2025-11-13"

# Show logs between specific times
sudo journalctl --since "2025-11-13 10:00:00" --until "2025-11-13 15:00:00"

# Show logs from yesterday
sudo journalctl --since "yesterday"
```

#### Step 5: Combined Filters
```bash
# SSH service errors in last 24 hours
sudo journalctl -u ssh.service -p err --since "24 hours ago"

# All services' warnings and errors today
sudo journalctl -p warning --since today

# Specific service with all messages since boot
sudo journalctl -u apache2.service -b
```

#### Step 6: Search and Extract Specific Information
```bash
# Search for specific keyword
sudo journalctl -g "authentication failure"

# Find all entries containing error
sudo journalctl | grep -i "error"

# Extract timestamps and messages
sudo journalctl --output short-iso | head -20

# Output as JSON for processing
sudo journalctl --output json | head -1 | python3 -m json.tool

# Show in table format
sudo journalctl --output table
```

---

### Part 7: Apache Web Server Log Analysis

#### Step 1: View Apache Access Logs
```bash
# View complete access log
sudo cat /var/log/apache2/access.log

# View last 100 requests
sudo tail -100 /var/log/apache2/access.log

# Monitor access log in real-time
sudo tail -f /var/log/apache2/access.log
```

#### Step 2: View Apache Error Logs
```bash
# View error log
sudo cat /var/log/apache2/error.log

# View recent errors
sudo tail -50 /var/log/apache2/error.log

# Monitor errors in real-time
sudo tail -f /var/log/apache2/error.log

# Find all errors
sudo grep -i "error" /var/log/apache2/error.log
```

#### Step 3: Analyze HTTP Status Codes
```bash
# Count all HTTP status codes
sudo awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

# Find all 404 errors (not found)
sudo grep " 404 " /var/log/apache2/access.log

# Find most common 404 errors
sudo grep " 404 " /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20

# Find all 500 errors (server error)
sudo grep " 500 " /var/log/apache2/access.log

# Find 401/403 errors (auth/forbidden)
sudo grep " 401 \| 403 " /var/log/apache2/access.log | wc -l
```

#### Step 4: Analyze Request Source
```bash
# Count requests per IP address
sudo awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Find requests from specific IP
sudo grep "192.168.1.100" /var/log/apache2/access.log

# Find most requested pages
sudo awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Find most common user agents
sudo awk '{print $(NF-1)}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10
```

#### Step 5: Detect Attack Patterns
```bash
# SQL injection attempts
sudo grep -i "select\|union\|insert\|update\|delete" /var/log/apache2/access.log

# Directory traversal attempts
sudo grep -i "\\.\\./\\|\\.\\.\\\\" /var/log/apache2/access.log

# Large number of 401 errors (brute force)
sudo grep " 401 " /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | awk '$1 > 5'

# Requests from same IP with multiple 404s (scanning)
sudo grep " 404 " /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | awk '$1 > 10'
```

---

### Part 8: Creating Log Analysis Reports

#### Step 1: Create Comprehensive Security Audit Script
```bash
# Create analysis script
sudo cat > /usr/local/bin/log_audit.sh << 'EOF'
#!/bin/bash

echo "=========================================="
echo "SECURITY LOG AUDIT REPORT"
echo "Generated: $(date)"
echo "=========================================="

echo ""
echo "1. FAILED LOGIN ATTEMPTS (Last 24 hours)"
echo "==========================================="
sudo grep "Failed password" /var/log/auth.log | tail -20 | cut -c1-120

echo ""
echo "2. TOP 10 IPs WITH FAILED LOGINS"
echo "==========================================="
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "3. INVALID USER ATTEMPTS"
echo "==========================================="
sudo grep "Invalid user" /var/log/auth.log | awk '{print $5}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "4. SUDO COMMAND USAGE"
echo "==========================================="
sudo grep "sudo:" /var/log/auth.log | tail -10 | awk '{print $1,$2,$3,$6,$11}' | cut -c1-100

echo ""
echo "5. FIREWALL BLOCKED CONNECTIONS"
echo "==========================================="
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | tail -10

echo ""
echo "6. TOP 10 BLOCKED IPs"
echo "==========================================="
sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | awk '{print $12}' | cut -d'=' -f2 | sort | uniq -c | sort -rn | head -10

echo ""
echo "7. APACHE ERROR SUMMARY"
echo "==========================================="
sudo tail -10 /var/log/apache2/error.log

echo ""
echo "8. APACHE STATUS CODE DISTRIBUTION"
echo "==========================================="
sudo awk '{print $9}' /var/log/apache2/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -10

echo ""
echo "Report Complete - $(date)"
EOF

# Make executable
sudo chmod +x /usr/local/bin/log_audit.sh

# Run report
sudo /usr/local/bin/log_audit.sh
```

#### Step 2: Create Threat Detection Script
```bash
# Create threat detection
sudo cat > /usr/local/bin/threat_detection.sh << 'EOF'
#!/bin/bash

ALERT_THRESHOLD=10
REPORT_FILE="/tmp/threat_report_$(date +%s).txt"

{
  echo "THREAT DETECTION REPORT - $(date)"
  echo "=================================="
  echo ""
  
  # Check for brute force attempts
  ATTEMPTS=$(sudo grep "Failed password" /var/log/auth.log | wc -l)
  if [ $ATTEMPTS -gt $ALERT_THRESHOLD ]; then
    echo "[ALERT] High failed login attempts detected: $ATTEMPTS"
    echo "Top attacking IPs:"
    sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -5
  fi
  
  echo ""
  
  # Check for firewall blocks
  BLOCKS=$(sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | wc -l)
  if [ $BLOCKS -gt $ALERT_THRESHOLD ]; then
    echo "[ALERT] High firewall blocks detected: $BLOCKS"
    echo "Most blocked IPs:"
    sudo grep "\[UFW BLOCK\]" /var/log/ufw.log | awk '{print $12}' | cut -d'=' -f2 | sort | uniq -c | sort -rn | head -5
  fi
  
  echo ""
  echo "Report saved to: $REPORT_FILE"
} | tee $REPORT_FILE

cat $REPORT_FILE
```

#### Step 3: Setup Automated Log Monitoring
```bash
# Install logwatch for automated log analysis
sudo apt install -y logwatch

# Configure logwatch
sudo nano /etc/logwatch/conf/logwatch.conf

# Run logwatch for daily report
sudo logwatch --output mail --format html --range yesterday

# View logwatch output
sudo logwatch --output file --filename /tmp/logwatch.txt --range today
cat /tmp/logwatch.txt
```

---

### Part 9: Advanced Log Processing with Command-Line Tools

#### Step 1: Using grep for Pattern Matching
```bash
# Case-insensitive search
sudo grep -i "error" /var/log/syslog

# Invert match (show lines without pattern)
sudo grep -v "ESTABLISHED" /var/log/syslog

# Show line numbers
sudo grep -n "Failed" /var/log/auth.log | head -10

# Search multiple patterns
sudo grep -E "error|warning|critical" /var/log/syslog

# Count matches
sudo grep -c "Failed password" /var/log/auth.log
```

#### Step 2: Using awk for Data Extraction
```bash
# Print specific columns
sudo awk '{print $1, $2, $3, $5}' /var/log/auth.log

# Filter by column value
sudo awk '$9 == "Failed" {print $0}' /var/log/auth.log

# Calculate statistics
sudo awk '{print $1}' /var/log/apache2/access.log | sort | uniq | wc -l

# Extract and count unique values
sudo awk '{print $5}' /var/log/auth.log | sort | uniq -c | sort -rn | head -20
```

#### Step 3: Using cut for Field Extraction
```bash
# Extract specific delimiter-separated fields
sudo cut -d' ' -f1,5 /var/log/auth.log | head -20

# Extract character range
sudo cut -c1-10 /var/log/syslog | head -20

# Extract multiple fields
sudo cut -d: -f1,3 /etc/passwd | head -20
```

#### Step 4: Using sed for Stream Editing
```bash
# Delete lines containing pattern
sudo sed -i '/DEBUG/d' /var/log/syslog.bak

# Replace text in file
sudo sed -i 's/OLD_TEXT/NEW_TEXT/g' /var/log/syslog.bak

# Extract specific line range
sudo sed -n '1,100p' /var/log/syslog

# Print lines matching pattern
sudo sed -n '/error/p' /var/log/apache2/error.log
```

#### Step 5: Using sort and uniq for Data Aggregation
```bash
# Sort by second column numerically
sort -k2 -n /var/log/syslog

# Sort in reverse order
sort -r /var/log/syslog

# Find unique values and count
sort /var/log/auth.log | uniq -c | sort -rn | head -20

# Find duplicates
sort /var/log/syslog | uniq -d

# Sort by field with delimiter
sort -t: -k3 -n /etc/passwd
```

---

### Part 10: Real-Time Log Monitoring Dashboard

#### Step 1: Create Real-Time Monitoring Script
```bash
# Create monitoring dashboard
sudo cat > /usr/local/bin/log_monitor.sh << 'EOF'
#!/bin/bash

while true; do
  clear
  echo "====== REAL-TIME LOG MONITOR ======"
  echo "Time: $(date)"
  echo ""
  
  echo "Recent Failed SSH Attempts:"
  tail -5 /var/log/auth.log | grep -i "failed\|invalid"
  
  echo ""
  echo "Recent Firewall Blocks:"
  tail -5 /var/log/ufw.log | grep "\[UFW BLOCK\]"
  
  echo ""
  echo "Recent Apache Errors:"
  tail -5 /var/log/apache2/error.log
  
  echo ""
  echo "Current Apache Requests/sec (last 10 entries):"
  tail -10 /var/log/apache2/access.log | wc -l
  
  sleep 10
done
EOF

sudo chmod +x /usr/local/bin/log_monitor.sh

# Run monitor
sudo /usr/local/bin/log_monitor.sh
```

---

## Expected Outcomes

After implementing this log analysis system, you will be able to:

1. **Locate All Log Files**: Know exactly where system, security, firewall, and application logs are stored

2. **Extract Specific Events**: Use grep, awk, and other tools to find specific events in massive log files

3. **Identify Security Threats**:
   - Brute force attacks (multiple failed logins)
   - Port scanning (multiple blocked ports)
   - Unauthorized access attempts
   - Suspicious command execution

4. **Analyze Network Activity**:
   - Blocked/allowed connections
   - Source IP addresses
   - Destination ports and protocols
   - Attack patterns

5. **Monitor Web Server Activity**:
   - HTTP status codes
   - Most accessed pages
   - Error trends
   - Potential attacks (SQL injection, directory traversal)

6. **Create Automated Reports**: Generate daily/hourly security reports

7. **Real-Time Monitoring**: Watch logs as they happen and respond to threats immediately

## Conclusion

Linux log analysis is a fundamental skill for system administrators and security professionals. By mastering the command-line tools and understanding log locations and formats, you can:

- **Detect Security Incidents**: Identify breaches and attacks early
- **Troubleshoot Issues**: Quickly find root causes of problems
- **Maintain Compliance**: Prove adherence to security policies
- **Optimize Performance**: Identify resource bottlenecks
- **Respond to Threats**: Take immediate action on security events

Regular log analysis, combined with automated monitoring and alerting, creates a comprehensive security monitoring strategy.

## Quick Reference Command Guide

```bash
# View logs
sudo tail -f /var/log/syslog          # Monitor syslog
sudo cat /var/log/auth.log            # View authentication
sudo grep "Failed" /var/log/auth.log  # Failed logins
sudo journalctl -u ssh -f             # Monitor SSH via journald
sudo grep "[UFW BLOCK]" /var/log/ufw.log  # Firewall blocks

# Search patterns
sudo grep -r "error" /var/log/        # Search all logs
sudo grep -E "error|warning|critical" /var/log/syslog

# Analyze
sudo awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn
sudo tail -100 /var/log/auth.log | grep "Failed" | awk '{print $(NF-3)}' | sort | uniq -c

# Real-time
sudo tail -f /var/log/syslog
sudo journalctl -f
```

## Important Notes

- Always use `sudo` to read log files (they contain sensitive information)
- Log files rotate regularly (check with `logrotate`)
- Compressed logs (`.gz`) can be read with `zcat`: `sudo zcat /var/log/syslog.1.gz`
- Configure log retention in `/etc/rsyslog.conf` and `/etc/logrotate.d/`
- Backup important logs regularly for compliance
- Use tools like ELK (Elasticsearch, Logstash, Kibana) for large-scale log analysis

# Implementation of Database Password Auditing

## Aim

To implement and conduct a comprehensive database password security audit using industry-standard tools including John the Ripper for password cracking, Hashcat for GPU-accelerated password recovery, and various database auditing techniques to identify weak, exposed, or compromised passwords in database systems.

## Theory

### What is Database Password Auditing?

Database password auditing is the systematic process of testing and evaluating the strength, security, and compliance of passwords stored in databases. It involves:

- Extracting password hashes from databases
- Testing passwords against known vulnerabilities
- Identifying weak or default credentials
- Verifying password policy compliance
- Detecting reused or compromised passwords

### Why Database Password Auditing Matters

Weak database passwords are a critical security risk because:
- **Database breaches**: Attackers gain access to entire datasets
- **Compliance violations**: Regulatory requirements (GDPR, HIPAA, PCI-DSS) mandate strong passwords
- **Lateral movement**: Compromised database credentials enable attacks on other systems
- **Data exfiltration**: Unauthorized access leads to sensitive data theft

### Password Hashing and Storage

Databases use cryptographic hashing to store passwords securely. Common algorithms include:

**Weak/Legacy Algorithms (NOT RECOMMENDED):**
- MD5: Fast (300,000 hashes/second), easily cracked, no salting
- SHA-1: Faster than bcrypt, deprecated, known vulnerabilities
- SHA-256: Fast, designed for data integrity not passwords

**Modern/Secure Algorithms (RECOMMENDED):**
- bcrypt: Slow (1 hash/second), uses salt automatically, adaptive cost factor
- Argon2id: Memory-hard, resistant to GPU attacks, industry standard
- PBKDF2: Iterative, NIST-approved, requires high iteration count (600k+)
- scrypt: Memory-intensive, GPU-resistant

### Salting and Hashing

**Salt**: A random string added to passwords before hashing
- Makes rainbow table attacks impractical
- Ensures identical passwords hash to different values
- Should be unique per user
- Minimum 16 bytes recommended

**Process**:
```
Plaintext Password → Add Salt → Hash Algorithm → Stored Hash
example123        + random   → bcrypt         → $2b$12$K1h3...
```

### Password Cracking Techniques

**1. Dictionary Attack**: Tries common passwords from word lists
- Fast but limited to known words
- Effective against weak passwords
- Tools: John the Ripper, Hashcat

**2. Brute Force Attack**: Tries all possible character combinations
- Slow but guaranteed to find password eventually
- Feasible for short passwords
- More effective with GPU acceleration

**3. Rainbow Table Attack**: Uses precomputed hash-to-password mappings
- Extremely fast for unsalted hashes
- Ineffective against salted passwords
- Requires massive storage space
- Example: Cain & Abel, RainbowCrack

**4. Hybrid Attack**: Combines dictionary words with brute force rules
- Tries dictionary word + numbers/symbols
- Example: "password123", "Password!", "Pass@word"

**5. Mask Attack**: Uses patterns instead of pure brute force
- More efficient than full brute force
- Example: ?u?l?l?l?d (Uppercase-Lowercase-Lowercase-Lowercase-Digit)

### John the Ripper

**What It Is**: Open-source password security auditing tool
- Supports hundreds of hash formats
- Available for Unix/Linux, Windows, macOS
- Free community edition
- Runs on CPU

**Supported Hash Formats**:
- Unix: MD5, SHA-1, SHA-256, SHA-512, bcrypt, MD5-crypt
- Windows: LM hashes, NTLM, Domain Cached Credentials
- Web Applications: WordPress, Drupal, Joomla
- Databases: MySQL, PostgreSQL, Oracle, SQL Server

### Hashcat

**What It Is**: Advanced password recovery utility with GPU acceleration
- World's fastest password cracker
- Supports 300+ hash algorithms
- Runs on GPU (NVIDIA, AMD) and CPU
- Significantly faster than John the Ripper

**Performance Advantage**:
- CPU: 1-10 hashes per second (bcrypt)
- GPU (RTX 4090): Thousands to millions of hashes per second
- Speed depends on hash type and GPU model

**Hardware Requirements**:
- NVIDIA GPU: CUDA Toolkit support
- AMD GPU: ROCm driver
- Minimum 2GB VRAM recommended

### Database-Specific Auditing

**MySQL/MariaDB Password Extraction**:
```sql
SELECT user, authentication_string FROM mysql.user;
```

**PostgreSQL Password Extraction**:
```sql
SELECT usename, valuntil, usesuper FROM pg_shadow;
```

**SQL Server Password Extraction**:
```sql
SELECT name, type, type_desc, is_disabled FROM sys.sql_logins;
```

## Prerequisites

### System Requirements
- Ubuntu 20.04/22.04 LTS or higher
- Minimum 4GB RAM (8GB+ recommended for Hashcat)
- 20GB free disk space
- Terminal access with sudo privileges
- NVIDIA GPU (optional but recommended for Hashcat)

### Software to Install
- John the Ripper
- Hashcat (optional, requires GPU)
- Database tools (MySQL client, PostgreSQL client)
- Git for downloading tools

## Procedure

### Part 1: Install John the Ripper on Ubuntu

#### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Dependencies
```bash
sudo apt install -y build-essential libssl-dev zlib1g-dev yum-utils git
```

#### Step 3: Install John the Ripper from Repository (Easy Method)

**Option A: Using APT (Simplest)**
```bash
sudo apt install -y john john-data
```

**Option B: From Snap (Latest Version)**
```bash
sudo snap install john-the-ripper
```

**Option C: Compile from Source (Most Control)**
```bash
# Download source
cd ~/Downloads
git clone https://github.com/openwall/john.git
cd john/src

# Compile
./configure
make -s clean && make -s 

# Add to PATH
cd ../run
./john --test
```

#### Step 4: Verify Installation
```bash
john --version
```

Output should show version: `John the Ripper 1.9.0-jumbo-1`

---

### Part 2: Install Hashcat on Ubuntu

**Note**: Hashcat requires NVIDIA CUDA or GPU drivers. CPU-only installation is possible but significantly slower.

#### Step 1: Check for NVIDIA GPU (Optional)
```bash
lspci | grep -i nvidia
```

If you see GPU listed, proceed. If no GPU, you can still use Hashcat on CPU.

#### Step 2: Install NVIDIA Drivers and CUDA (GPU Users Only)

**Check current driver:**
```bash
nvidia-smi
```

**Install CUDA Toolkit:**
```bash
# Download CUDA from NVIDIA
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-ubuntu2204.pin
sudo mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600

# Add NVIDIA repository
wget https://developer.download.nvidia.com/compute/cuda/12.6.3/local_installers/cuda-repo-ubuntu2204-12-6-local_12.6.3-560.35.03-1_amd64.deb
sudo dpkg -i cuda-repo-ubuntu2204-12-6-local_12.6.3-560.35.03-1_amd64.deb
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys A4B469963BF863CC

# Install CUDA
sudo apt update
sudo apt install -y cuda-toolkit
```

#### Step 3: Install Hashcat

**Option A: From Repository**
```bash
sudo apt install -y hashcat
```

**Option B: Download Latest Version**
```bash
cd ~/Downloads
wget https://hashcat.net/files/hashcat-6.2.6.tar.gz
tar xzf hashcat-6.2.6.tar.gz
cd hashcat-6.2.6
make
./hashcat --version
```

#### Step 4: Verify Hashcat Installation
```bash
hashcat --version
hashcat -I  # Show device information
```

---

### Part 3: Database Password Extraction

#### Step 1: Extract MySQL Password Hashes

**Connect to MySQL:**
```bash
mysql -u root -p
```

**View password hashes:**
```sql
SELECT user, authentication_string FROM mysql.user;
```

**Export hashes to file:**
```bash
mysql -u root -p -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user WHERE authentication_string != '';" > ~/hashes.txt
```

**Exit MySQL:**
```sql
EXIT;
```

#### Step 2: Extract Linux System Passwords (if available)

**Combine passwd and shadow files:**
```bash
sudo unshadow /etc/passwd /etc/shadow > ~/linux_hashes.txt
```

---

### Part 4: Prepare Password Wordlist

#### Step 1: Download Common Wordlist

**Rockyou.txt (Most Popular)**:
```bash
cd ~/Downloads

# Download rockyou.txt if not available
# Usually located at: /usr/share/wordlists/rockyou.txt (on Kali)

# If not available, create a simple wordlist
cat > wordlist.txt << 'EOF'
password
123456
password123
admin
letmein
welcome
qwerty
12345678
1234567890
dragon
monkey
batman
superman
football
soccer
baseball
basketball
hockey
tennis
golf
cricket
EOF
```

#### Step 2: Create Test Password Hash File

```bash
# Create a test hash file with common passwords
cat > test_hashes.txt << 'EOF'
admin:$2b$10$nOUIs5kJ7naTruVH3Su9SO07oWvVJrGEUOUVUWxkT0LKAf6mw5p8C
user:$2b$10$zlyH9c7bVDhxPZO9.4s8Hups1e9maVrHaXSGWP0HwajKn4E7qFDJm
test:$2b$10$E9rnMkwvZ3jP5c9K7xL2huKTBKKe6fYQ3P0A1m8v9C7x3N5D2H8pG
EOF
```

**Note**: These are example hashes for bcrypt format.

---

### Part 5: Password Cracking with John the Ripper

#### Step 1: Basic Dictionary Attack

```bash
john --wordlist=wordlist.txt test_hashes.txt
```

#### Step 2: Use Single Mode (Brute Force Numbers)

```bash
john --single test_hashes.txt
```

#### Step 3: Use Wordlist with Rules (Most Effective)

```bash
john --wordlist=wordlist.txt --rules=best64 test_hashes.txt
```

#### Step 4: View Cracked Passwords

```bash
john --show test_hashes.txt
```

#### Step 5: Specify Hash Format

```bash
john --format=bcrypt --wordlist=wordlist.txt test_hashes.txt
```

#### Step 6: Advanced: Multi-threaded Attack

```bash
john --wordlist=wordlist.txt --format=bcrypt --fork=4 test_hashes.txt
```

#### Step 7: Increment Mode (Brute Force with Character Set)

```bash
john --incremental=Digits --length=8 test_hashes.txt
```

#### Step 8: Show Attack Progress

```bash
john --status
```

---

### Part 6: Password Cracking with Hashcat

#### Step 1: Identify Hash Type

```bash
# Hash type 3200 = bcrypt
# Hash type 5500 = MySQL
# Hash type 1000 = NTLM

# Use hashcat to identify
hashcat -h | grep -i bcrypt
```

#### Step 2: Basic Dictionary Attack with Hashcat

```bash
hashcat -m 3200 test_hashes.txt wordlist.txt
```

**Format breakdown:**
- `-m 3200`: Hash type (bcrypt)
- `test_hashes.txt`: File containing hashes
- `wordlist.txt`: Wordlist file

#### Step 3: GPU-Accelerated Attack

```bash
# Specify GPU device
hashcat -d 1 -m 3200 test_hashes.txt wordlist.txt
```

#### Step 4: Brute Force Attack with Mask

```bash
# ?d = digit (0-9)
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?s = special (!@#$%...)

# Example: 8-character password with all types
hashcat -m 3200 test_hashes.txt --mask=?u?l?l?l?d?s?s?d
```

#### Step 5: Combination Attack

```bash
hashcat -m 3200 test_hashes.txt -a 1 wordlist.txt wordlist.txt
```

#### Step 6: Hybrid Attack (Wordlist + Mask)

```bash
# Append 2 digits to each word
hashcat -m 3200 test_hashes.txt -a 6 wordlist.txt ?d?d
```

#### Step 7: View Progress

```bash
hashcat -m 3200 test_hashes.txt wordlist.txt -S
```

#### Step 8: Show Cracked Results

```bash
hashcat -m 3200 test_hashes.txt wordlist.txt --show
```

---

### Part 7: Database Security Audit Workflow

#### Step 1: Audit MySQL Users and Permissions

```bash
mysql -u root -p << 'EOF'
-- Show all users
SELECT user, host FROM mysql.user;

-- Show password policy
SELECT * FROM mysql.user WHERE User != 'root'\G

-- Check user privileges
SHOW GRANTS FOR 'dbuser'@'localhost';

-- Find weak passwords (empty or old hashes)
SELECT user, authentication_string FROM mysql.user 
WHERE authentication_string = '' OR authentication_string IS NULL;
EOF
```

#### Step 2: Export Hashes for Auditing

```bash
# Export MySQL hashes
mysql -u root -p -B -N -e "SELECT CONCAT(user, '::', authentication_string) FROM mysql.user WHERE authentication_string != '';" > mysql_hashes_audit.txt

# Format for John the Ripper
cat mysql_hashes_audit.txt | sed 's/::/:/g' > john_ready_hashes.txt
```

#### Step 3: Run Audit Against MySQL Hashes

```bash
john --wordlist=wordlist.txt --format=mysql-sha1 john_ready_hashes.txt
```

#### Step 4: Generate Audit Report

```bash
# Create report
cat > password_audit_report.txt << 'EOF'
PASSWORD AUDIT REPORT
====================
Date: $(date)
System: MySQL Database Audit

Audit Summary:
- Total Users: [Check with query]
- Users with Weak Passwords: [Check with John]
- Default Credentials Found: [List]
- Recommended Actions: [Remediation steps]
EOF

john --show john_ready_hashes.txt >> password_audit_report.txt
```

---

### Part 8: Create Audit Dashboard Script

```bash
# Create audit script
cat > database_password_audit.sh << 'EOF'
#!/bin/bash

echo "=== Database Password Auditing Dashboard ==="
echo "Date: $(date)"
echo ""

# Check John the Ripper status
echo "1. John the Ripper Status:"
john --version
echo ""

# Check Hashcat status  
echo "2. Hashcat Status:"
hashcat --version
hashcat -I | head -5
echo ""

# Show recent cracking attempts
echo "3. Recently Cracked Passwords:"
john --show 2>/dev/null | tail -10
echo ""

# Database security metrics
echo "4. Database Users Count:"
mysql -u root -p -N -e "SELECT COUNT(*) FROM mysql.user;" 2>/dev/null || echo "MySQL not accessible"
echo ""

echo "Audit Complete!"
EOF

chmod +x database_password_audit.sh
./database_password_audit.sh
```

---

## Expected Outcomes

After implementing this database password auditing system, you should be able to:

1. **Extract Database Passwords**: Successfully export password hashes from MySQL, PostgreSQL, SQL Server, or Linux systems

2. **Crack Weak Passwords**: 
   - Dictionary attacks identify common passwords
   - Brute force attacks test all combinations
   - Hybrid attacks combine wordlists with rules

3. **Identify Security Issues**:
   - Weak password hashes (MD5, SHA-1)
   - Default credentials (admin/password)
   - Missing salts on passwords
   - Compliance violations

4. **Generate Audit Reports**:
   - List of cracked passwords
   - Security vulnerability assessment
   - Recommendations for password policy improvements
   - Timeline of audit activities

5. **Performance Metrics**:
   - John the Ripper: 1,000+ passwords/second (CPU-based)
   - Hashcat: 1,000,000+ passwords/second (GPU-based)
   - Success rate: 40-80% with good wordlists

## Conclusion

Database password auditing using John the Ripper and Hashcat provides organizations with critical visibility into password security weaknesses. By:

- Regularly extracting and testing database password hashes
- Identifying weak, reused, or default credentials
- Implementing strong password policies
- Enforcing modern hashing algorithms (bcrypt, Argon2)
- Using adequate salts and cost factors

Organizations can significantly reduce the risk of credential-based attacks and database breaches. This lab demonstrates that password security is not passive—it requires active testing and continuous improvement.

## Important Security Notes

**LEGAL AND ETHICAL CONSIDERATIONS:**

⚠️ **WARNING**: Password cracking should only be performed on systems you own or have explicit written permission to test. Unauthorized password cracking is illegal and unethical.

**Best Practices:**
- Only test on authorized systems
- Maintain detailed audit logs
- Secure cracked password lists
- Report findings responsibly
- Remediate identified weaknesses
- Follow your organization's security policies

## Common Hash Types Reference

| Hash Type | Name | Hashcat ID | John Format |
|-----------|------|-----------|------------|
| MD5 | MD5 | 0 | raw-md5 |
| SHA-1 | SHA-1 | 100 | raw-sha1 |
| SHA-256 | SHA-256 | 1400 | raw-sha256 |
| bcrypt | bcrypt | 3200 | bcrypt |
| MySQL | MySQL 5.x | 300 | mysql |
| PostgreSQL | PostgreSQL | 12100 | postgres |
| NTLM | Windows NTLM | 1000 | nt |
| DES | Unix DES | 1500 | descrypt |

## Download Links

- **John the Ripper**: https://www.openwall.com/john/
- **Hashcat**: https://hashcat.net/hashcat/
- **Wordlists**: https://github.com/danielmiessler/SecLists
- **Rockyou.txt**: Included in Kali Linux or download from wordlist repositories
- **OWASP Password Recommendations**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## Troubleshooting

**John the Ripper won't start:**
```bash
# Ensure proper installation
john --test

# If error, reinstall
sudo apt reinstall -y john
```

**Hashcat GPU not detected:**
```bash
# Check GPU
hashcat -I

# If not detected, install CUDA drivers
nvidia-smi
```

**Hash format not recognized:**
```bash
# List all supported formats
john --list=formats

hashcat -h | grep -i format
```

**Slow cracking speed:**
- Use GPU acceleration (Hashcat)
- Use smaller wordlists
- Optimize mask patterns
- Check CPU/GPU usage: `top`, `nvidia-smi`

---

This comprehensive guide enables organizations to conduct thorough database password security audits using industry-standard tools, identify vulnerabilities, and implement remediation strategies.

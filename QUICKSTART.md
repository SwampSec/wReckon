#!/bin/bash
# WRECKON QUICK REFERENCE GUIDE
# v2.0+ - Enhanced Web Pentesting Framework

cat << 'EOF'

╔══════════════════════════════════════════════════════════════════════════════╗
║                  RECKON v2.0 - QUICK REFERENCE GUIDE                         ║
║              Enhanced Pentesting Framework - Vulnerability Scanning           ║
╚══════════════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════════════════
 QUICK START
════════════════════════════════════════════════════════════════════════════════

1. INSTALL TOOLS:
   sudo bash install-tools.sh

2. SINGLE HOST SCAN:
   ./wreckon.sh 192.168.1.100

3. BATCH SCAN:
   ./wreckon.sh /path/to/hostlist.txt

4. REVIEW RESULTS:
   cd 192.168.1.100
   cat VULNERABILITY_REPORT_*.txt
   cat reckon

════════════════════════════════════════════════════════════════════════════════
 CONFIGURATION
════════════════════════════════════════════════════════════════════════════════

Edit these variables at the top of wreckon.sh:

# Port Scanning
tports=100              # Number of top ports (100-1000 recommended)
udp=False               # Enable UDP scanning (slower but thorough)
tcp=True                # Enable TCP scanning

# Features
dns_enum=True           # Domain/DNS enumeration
ssl_scan=True           # SSL/TLS vulnerability testing
owasp_scan=True         # OWASP Top 10 checks
web_vuln_scan=True      # Web app vulnerability scanning
password_test=False     # Credential testing (False for OSCP compliance)
service_vuln_scan=True  # Service-specific vulnerability checks

════════════════════════════════════════════════════════════════════════════════
 SCANNING PHASES
════════════════════════════════════════════════════════════════════════════════

PHASE 1: DISCOVERY (10-60 seconds)
├─ Quick port scan (top 100 TCP/UDP ports)
├─ Service identification
├─ DNS enumeration
├─ Zone transfer attempts
└─ WHOIS information gathering

PHASE 2: VULNERABILITY SCANNING (5-30 minutes)
├─ Service-specific NSE scripts
├─ SSL/TLS security analysis
├─ OWASP Top 10 checks
├─ SQL injection testing
├─ Path traversal detection
├─ WAF detection
└─ Information disclosure scanning

PHASE 3: DEEP ENUMERATION (30 min - 3 hours)
├─ Web server scanning (Nikto)
├─ Directory enumeration (dirb)
├─ SMB enumeration (enum4linux)
├─ Full port scan (all 65,535 ports)
├─ Detailed NSE scripts
├─ User enumeration
└─ Service-specific testing

PHASE 4: REPORTING (1-2 minutes)
├─ Consolidate findings
├─ Classify by severity
├─ Generate statistics
└─ Create summary report

════════════════════════════════════════════════════════════════════════════════
 OUTPUT FILES & INTERPRETATION
════════════════════════════════════════════════════════════════════════════════

MAIN REPORT:
  VULNERABILITY_REPORT_[timestamp].txt
  └─ Summary of all findings by severity

SCANNING PHASES:
  quickscan                 → TCP port scan results
  quickudpscan              → UDP port scan results
  [port]-version            → Service version info
  [port]-nse                → NSE script findings
  [port]-nikto              → Web vulnerabilities
  [port]-dirb               → Discovered directories
  [port]-ssl-test           → SSL/TLS issues
  [port]-sqlmap             → SQL injection tests
  [port]-owasp              → OWASP findings
  [port]-info-disclosure    → Information leaks
  [port]-waf                → WAF detection

DNS & WHOIS:
  dns-forward-lookup        → A/AAAA records
  dns-reverse-lookup        → Reverse DNS
  dns-axfr                  → Zone transfer results (CRITICAL if successful)
  whois-lookup              → WHOIS information

SMB ENUMERATION:
  smb-enum4linux            → SMB shares, users, policies
  [port]-smb-nsedef         → SMB vulnerabilities
  smb-nsevulns              → SMB-specific CVEs

MAIN LOG:
  reckon                    → Complete scan log

════════════════════════════════════════════════════════════════════════════════
 CRITICAL FINDINGS INDICATORS
════════════════════════════════════════════════════════════════════════════════

🔴 CRITICAL - Immediate Action Required:
   • SQL injection vulnerabilities
   • Remote code execution (RCE)
   • Authentication bypass
   • Zone transfer successful
   • Unauthenticated SMB access
   • Default credentials identified
   • Known critical CVEs (CVSS 9.0+)

🟠 HIGH - High Priority:
   • OWASP Top 10 vulnerabilities
   • Weak SSL/TLS configuration
   • Unencrypted services
   • Privilege escalation paths
   • Information disclosure
   • Directory traversal

🟡 MEDIUM - Medium Priority:
   • Service version outdated (but no known exploits)
   • Weak ciphers (not immediately exploitable)
   • HTTP methods enabled
   • Information leakage

════════════════════════════════════════════════════════════════════════════════
 COMMON VULNERABILITY TYPES SCANNED
════════════════════════════════════════════════════════════════════════════════

INJECTION ATTACKS:
  ✓ SQL Injection
  ✓ LDAP Injection
  ✓ Command Injection
  ✓ Path Traversal (LFI/RFI)

AUTHENTICATION & SESSION:
  ✓ Weak credentials
  ✓ Session fixation
  ✓ Privilege escalation
  ✓ User enumeration

CRYPTOGRAPHY & SECURITY:
  ✓ Weak SSL/TLS versions
  ✓ Weak ciphers
  ✓ Certificate issues
  ✓ Heartbleed, POODLE, etc.

WEB APPLICATION:
  ✓ CSRF tokens
  ✓ XSS vulnerabilities
  ✓ Open redirects
  ✓ Security misconfiguration

NETWORK SERVICES:
  ✓ FTP weak security
  ✓ SMTP relay issues
  ✓ SNMP community strings
  ✓ RPC endpoints
  ✓ DNS zone transfers

════════════════════════════════════════════════════════════════════════════════
 COMMAND CHEAT SHEET
════════════════════════════════════════════════════════════════════════════════

# Make script executable
chmod +x wreckon.sh

# Run with verbose output
./wreckon.sh 192.168.1.100 | tee verbose-scan.log

# Scan specific network range (create file with one IP per line)
cat << 'LIST' > targets.txt
192.168.1.100
192.168.1.101
192.168.1.102
LIST
./wreckon.sh targets.txt

# Review findings
cd 192.168.1.100
grep -i "VULNERABLE\|vulnerable\|critical" VULNERABILITY_REPORT_*.txt
grep "sql\|SQL" *-sqlmap
grep "VULNERABLE" *-ssl-test

# Count findings by type
grep -h "VULNERABLE" * | sort | uniq -c | sort -rn

# Extract web directories found
cat *-dirb | grep "^+" | sed 's/+ //' | sort -u

# List all services identified
cat *-version | grep "open" | awk '{print $3}' | sort | uniq -c

════════════════════════════════════════════════════════════════════════════════
 TROUBLESHOOTING
════════════════════════════════════════════════════════════════════════════════

PERMISSION DENIED:
  chmod +x wreckon.sh

NMAP NOT FOUND:
  sudo apt-get install -y nmap

SPECIFIC TOOL ERRORS:
  grep "not found\|ERROR\|error" reckon | head -20

SLOW SCANS:
  • Reduce tports value (e.g., 20 or 50)
  • Disable UDP scanning (udp=False)
  • Check network connectivity
  • Run single target instead of batch

FALSE POSITIVES:
  • Always verify with manual tools (curl, nc, etc)
  • Use multiple sources to confirm
  • Check tool-specific documentation

════════════════════════════════════════════════════════════════════════════════
 FUTURE MODULES (COMING SOON)
════════════════════════════════════════════════════════════════════════════════

API TESTING MODULE:
  • REST API endpoint discovery
  • GraphQL introspection
  • API authentication testing
  • Rate limiting assessment
  • JWT token analysis

CLOUD TESTING MODULE:
  • AWS S3 bucket enumeration
  • Azure blob storage scanning
  • Google Cloud Storage assessment
  • Misconfiguration detection
  • IAM role analysis

CONTAINER SCANNING MODULE:
  • Docker registry enumeration
  • Kubernetes cluster assessment
  • Container vulnerability scanning

IaC SCANNING MODULE:
  • Terraform misconfiguration detection
  • CloudFormation analysis
  • Helm chart security review

════════════════════════════════════════════════════════════════════════════════
 OSCP EXAM COMPLIANCE
════════════════════════════════════════════════════════════════════════════════

✅ OSCP COMPLIANT:
  ✓ No Metasploit multi-handler usage
  ✓ No automated exploitation
  ✓ Manual verification required
  ✓ All tools available in Kali
  ✓ No commercial tools
  ✓ Scanning and enumeration only

⚠️  IMPORTANT NOTES:
  ✓ Always get written authorization before testing
  ✓ Manual enumeration is still required
  ✓ Combine with other methodologies
  ✓ Verify findings before reporting
  ✓ Document all testing activities

════════════════════════════════════════════════════════════════════════════════
 REFERENCES & RESOURCES
════════════════════════════════════════════════════════════════════════════════

OWASP Top 10:
  https://owasp.org/www-project-top-ten/

Nmap NSE Documentation:
  https://nmap.org/nsedoc/

NIST Vulnerability Standards:
  https://nvlpubs.nist.gov/

PCI DSS Requirements:
  https://www.pcisecuritystandards.org/

════════════════════════════════════════════════════════════════════════════════

Questions? Review README_ENHANCED.md for detailed documentation

EOF

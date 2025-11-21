#!/bin/bash
# INDEX - Reckon v2.0 Documentation Guide

cat << 'EOF'

╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║                    🎯 RECKON v2.0 - DOCUMENTATION INDEX                       ║
║                  Enhanced Penetration Testing Automation Framework             ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 MAIN DOCUMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 UPGRADE_SUMMARY.md (START HERE! ⭐)
   • Complete upgrade overview
   • What's new in v2.0
   • Quick start guide (3 steps)
   • Key features summary
   • Before/after comparison
   → Read this first to understand changes

📄 QUICKSTART.md (PRACTICAL GUIDE)
   • 4-phase workflow visualization
   • Common command examples
   • Configuration quick reference
   • Output file interpretation
   • Critical finding indicators
   • Troubleshooting tips
   → Read this when getting started

📄 README_ENHANCED.md (COMPREHENSIVE REFERENCE)
   • Detailed feature documentation
   • Installation instructions
   • Configuration guide
   • Performance optimization
   • Advanced features
   • Future roadmap
   • External resources
   → Read for in-depth information

📄 FEATURES.md (TECHNICAL DETAILS)
   • Complete feature list
   • Configuration reference
   • Vulnerability categories
   • Scanning functions
   • File descriptions
   • Version history
   → Read for specific feature details

📄 README.md (ORIGINAL)
   • Preserved original documentation
   • Historical context
   → Reference for original v1.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 EXECUTABLE SCRIPTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔨 wreckon.sh (MAIN SCANNER)
   • Enhanced penetration testing automation
   • 993 lines of code (vs 440 in v1.0)
   • 4-phase scanning approach
   • Integrated vulnerability scanning
   • Auto tool detection
   → Usage: ./wreckon.sh <target>

🔨 install-tools.sh (TOOL INSTALLER)
   • Automated tool installation
   • Installs required and optional tools
   • Requires sudo privileges
   • Safe tool availability checking
   → Usage: sudo bash install-tools.sh

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 GETTING STARTED (5-MINUTE SETUP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. INSTALL TOOLS (2 minutes)
   $ sudo bash install-tools.sh

2. RUN SCAN (1 second to 90 minutes depending on target)
   $ ./wreckon.sh 192.168.1.100

3. REVIEW RESULTS (30 seconds)
   $ cd 192.168.1.100
   $ cat VULNERABILITY_REPORT_*.txt

4. INVESTIGATE FINDINGS (ongoing)
   $ grep -i "CRITICAL\|HIGH" VULNERABILITY_REPORT_*.txt

5. (OPTIONAL) CUSTOMIZE CONFIGURATION
   $ vi wreckon.sh  # Edit lines 6-16

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 READING GUIDE BY USE CASE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

👤 First-Time User
   1. Read: UPGRADE_SUMMARY.md (5 min)
   2. Read: QUICKSTART.md (10 min)
   3. Do: Install tools (2 min)
   4. Do: Run test scan (30 sec)

🛠️  System Administrator
   1. Read: README_ENHANCED.md - Prerequisites (5 min)
   2. Read: FEATURES.md - Configuration (10 min)
   3. Do: Install tools with options (5 min)
   4. Configure: Edit wreckon.sh (5 min)

🔒 Penetration Tester
   1. Read: UPGRADE_SUMMARY.md (5 min)
   2. Read: QUICKSTART.md - Vulnerability Categories (10 min)
   3. Read: README_ENHANCED.md - Advanced Features (15 min)
   4. Scan: Run comprehensive assessment

📚 Developer
   1. Read: FEATURES.md - Scanning Functions (10 min)
   2. Read: README_ENHANCED.md - Future Roadmap (5 min)
   3. Review: wreckon.sh - Module Framework (10 min)
   4. Plan: Implement future modules

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✨ KEY FEATURES AT A GLANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NEW CAPABILITIES IN v2.0:

🔍 Discovery & Reconnaissance
   ✓ DNS enumeration with zone transfer attempts
   ✓ WHOIS information gathering
   ✓ Comprehensive service identification
   ✓ Reverse DNS lookups

🛡️ Vulnerability Scanning
   ✓ SSL/TLS security testing (Heartbleed, weak ciphers)
   ✓ SQL injection detection (SQLmap)
   ✓ OWASP Top 10 compliance checks
   ✓ Path traversal and LFI/RFI testing
   ✓ Information disclosure detection
   ✓ WAF identification and fingerprinting
   ✓ Service-specific vulnerability checks

📊 Service Enumeration
   ✓ Enhanced HTTP/HTTPS scanning
   ✓ SMB/CIFS enumeration
   ✓ FTP vulnerability testing
   ✓ SMTP user enumeration
   ✓ SNMP testing

📈 Professional Reporting
   ✓ Consolidated vulnerability reports
   ✓ Severity-based finding classification
   ✓ Comprehensive statistics
   ✓ Evidence organization

🔧 Architecture
   ✓ Tool auto-detection
   ✓ Modular design for future expansion
   ✓ API testing framework (v2.1+)
   ✓ Cloud testing framework (v2.2+)
   ✓ Container scanning framework (v2.3+)
   ✓ IaC scanning framework (v2.4+)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 VULNERABILITY COVERAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CATEGORIES ASSESSED:

✅ Injection Attacks
   • SQL Injection
   • LDAP Injection
   • Command Injection
   • Path Traversal (LFI/RFI)

✅ Authentication & Access
   • Weak credentials
   • Session fixation
   • Privilege escalation
   • User enumeration

✅ Cryptography
   • Weak SSL/TLS versions
   • Weak ciphers
   • Certificate issues
   • Known crypto vulnerabilities

✅ Web Application (OWASP)
   • Broken access control
   • Sensitive data exposure
   • XML external entities
   • Security misconfiguration
   • Unvalidated redirects

✅ Network Services
   • Unencrypted communication
   • Default credentials
   • Anonymous access
   • Known service exploits

✅ Information Disclosure
   • HTTP headers
   • Server version info
   • Debug pages
   • Source repositories
   • Backup files

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📈 STATISTICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CODE METRICS:
   • Main script: 993 lines (vs 440 v1.0) → 125% increase
   • Documentation: 2,655 total lines
   • Functions: 35 (vs 20 v1.0) → 75% more functions
   • Scanning tools integrated: 8+ open-source tools
   • Vulnerability checks: 50+ distinct checks

TIME ESTIMATES:
   • Installation: 2 minutes
   • Single scan: 30-90 minutes (comprehensive)
   • Quick scan: 10-30 seconds (ports only)
   • Report generation: 1-2 minutes

COMPATIBILITY:
   • ✅ Kali Linux
   • ✅ Debian-based systems
   • ✅ Ubuntu
   • ✅ Any Linux with tools installed
   • ✅ OSCP exam compliant

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 QUICK LINKS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DOCUMENTATION:
   • Overview: UPGRADE_SUMMARY.md
   • Quick Guide: QUICKSTART.md
   • Full Reference: README_ENHANCED.md
   • Technical Details: FEATURES.md

TOOLS:
   • Main Script: wwreckon.sh
   • Installer: install-tools.sh

LEARNING PATHS:
   • New User Path: UPGRADE_SUMMARY → QUICKSTART → FEATURES
   • Expert Path: README_ENHANCED → wreckon.sh code
   • Administrator Path: FEATURES → install-tools.sh → QUICKSTART

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❓ FAQ / COMMON QUESTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Q: How do I install everything?
A: Run: sudo bash install-tools.sh

Q: How do I run a basic scan?
A: Run: ./wreckon.sh 192.168.1.100

Q: What vulnerabilities does it find?
A: See FEATURES.md - Vulnerability Coverage section

Q: Is it OSCP compliant?
A: Yes! See README_ENHANCED.md - OSCP Compliance section

Q: How long does a scan take?
A: 30-90 minutes typically. See QUICKSTART.md - Performance section

Q: Can I run it on multiple targets?
A: Yes! Create a file with one IP per line, then: ./wreckon.sh file.txt

Q: What if a tool is missing?
A: It's skipped gracefully. Install missing tools with install-tools.sh

Q: Can I customize the scan?
A: Yes! Edit variables at top of wreckon.sh. See FEATURES.md - Configuration

Q: What does the report show?
A: Complete vulnerability assessment. See QUICKSTART.md - Output Files

Q: How do I interpret findings?
A: See QUICKSTART.md - Critical Finding Indicators & Output Files

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  IMPORTANT REMINDERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔒 SECURITY & LEGAL:
   • Always get written authorization before testing
   • Unauthorized network scanning is illegal
   • This tool is for authorized testing only
   • Follow all applicable laws and regulations
   • Practice responsible disclosure

✅ BEST PRACTICES:
   • Test in authorized environments only
   • Verify findings with manual testing
   • Document all activities
   • Report findings responsibly
   • Combine with manual enumeration

🎯 COMPLIANCE:
   • OSCP exam compliant ✓
   • No Metasploit multi-handler ✓
   • No automated exploitation ✓
   • Manual verification required ✓

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 NEXT STEPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. READ THIS FIRST:
   → UPGRADE_SUMMARY.md (5 min overview)

2. THEN READ:
   → QUICKSTART.md (practical examples)

3. THEN DO:
   → sudo bash install-tools.sh (2 min)
   → ./wreckon.sh <test-target> (30-90 min)

4. THEN REVIEW:
   → VULNERABILITY_REPORT_*.txt (findings)

5. OPTIONALLY READ:
   → README_ENHANCED.md (deep dive)
   → FEATURES.md (technical reference)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📞 SUPPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Having issues?

1. Check QUICKSTART.md Troubleshooting section
2. Read README_ENHANCED.md Troubleshooting section
3. Review FEATURES.md Technical Details
4. Check if tools are installed: sudo bash install-tools.sh

Need to report a bug?
- GitHub Issues (if using Git)
- Check original project: Malice-in-Chains/Reckon

═══════════════════════════════════════════════════════════════════════════════════

                   ✨ Ready to scan! ✨
                   
                   ./wreckon.sh <target>

═══════════════════════════════════════════════════════════════════════════════════

EOF

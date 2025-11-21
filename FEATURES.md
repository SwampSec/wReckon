# Reckon v2.0 - Feature Summary & Configuration Guide

## UPGRADE SUMMARY

Your Reckon bash script has been successfully upgraded from a basic reconnaissance tool to a **comprehensive penetration testing framework** with integrated vulnerability scanning capabilities.

### What's New

#### 1. **Automated Discovery Phase**
- DNS enumeration (A, AAAA, MX, NS, TXT records)
- Zone transfer attempts (AXFR)
- WHOIS information gathering
- Reverse DNS lookups
- Automatic service identification on non-standard ports

#### 2. **Vulnerability Scanning Integration**
- **SSL/TLS Analysis**: Heartbleed, weak ciphers, certificate issues (testssl.sh)
- **SQL Injection Testing**: Automated SQLmap integration
- **OWASP Top 10**: Web application vulnerability checks
- **Path Traversal**: LFI/RFI detection
- **Information Disclosure**: Header analysis, version info, debug pages
- **WAF Detection**: Firewall identification and fingerprinting
- **Service-Specific Testing**: FTP, SMTP, SMB, SNMP vulnerabilities
- **Template-Based Scanning**: Nuclei integration for rapid matching

#### 3. **Enhanced Service Enumeration**
- FTP vulnerability detection
- SMTP user enumeration and relay testing
- SMB share enumeration and permissions
- SNMP community string testing
- Service version CVE correlation

#### 4. **Web Application Security**
- OWASP Top 10 compliance checks
- Common vulnerability patterns (XSS, CSRF, XXE, etc.)
- Header security analysis
- Insecure HTTP methods detection
- HTTP authentication finder
- Slowloris/DoS detection

#### 5. **Consolidated Reporting**
- Automatic vulnerability report generation
- Finding classification by severity (Critical, High, Medium)
- Statistics: Open ports, services, vulnerabilities count
- Evidence organization by scan type
- Timeline and performance metrics

#### 6. **Modular Architecture**
- Tool availability auto-detection
- Graceful degradation if tools missing
- Framework for future API testing module
- Framework for future Cloud testing module
- Framework for future Container scanning module
- Framework for future IaC scanning module

### Key Improvements Over v1.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Port Scanning | ✓ | ✓ |
| Service Identification | ✓ | ✓ |
| HTTP Enumeration | ✓ | ✓✓ |
| SMB Enumeration | ✓ | ✓✓ |
| Vulnerability Scanning | ✗ | ✓ |
| SSL/TLS Testing | ✗ | ✓ |
| SQL Injection Testing | ✗ | ✓ |
| DNS Enumeration | ✗ | ✓ |
| WAF Detection | ✗ | ✓ |
| Information Disclosure | ✗ | ✓ |
| Consolidated Reporting | ✗ | ✓ |
| Modular Design | ✗ | ✓ |
| Tool Auto-detection | ✗ | ✓ |

## QUICK START

### 1. Installation
```bash
cd /path/to/Reckon
sudo bash install-tools.sh
```

### 2. Running a Scan
```bash
./wreckon.sh 192.168.1.100
```

### 3. Viewing Results
```bash
cd 192.168.1.100
cat VULNERABILITY_REPORT_*.txt
```

## CONFIGURATION

Edit these variables in `wreckon.sh` (lines 6-16):

```bash
# Port Scanning
tports=100              # Top N ports (default: 100)
udp=False               # Enable UDP scanning
tcp=True                # Enable TCP scanning

# Vulnerability Scanning Features
dns_enum=True           # DNS reconnaissance
ssl_scan=True           # SSL/TLS testing
owasp_scan=True         # OWASP Top 10 checks
web_vuln_scan=True      # Web app scanning
password_test=False     # Password testing (disabled for OSCP)
service_vuln_scan=True  # Service vulnerability checks
```

## SCANNING PHASES (4-Phase Approach)

### Phase 1: Discovery (10-60 seconds)
Rapid identification of target infrastructure
- Quick port scan
- Service detection
- DNS enumeration
- WHOIS information

### Phase 2: Vulnerability Scanning (5-30 minutes)
Identify exploitable issues
- Service vulnerabilities
- SSL/TLS security
- Web application issues
- SQL injection testing
- WAF detection

### Phase 3: Deep Enumeration (30 min - 3 hours)
Comprehensive service scanning
- Web server scanning (Nikto)
- Directory enumeration (dirb)
- SMB enumeration
- Full port scan
- User enumeration

### Phase 4: Reporting (1-2 minutes)
Consolidated findings
- Unified vulnerability report
- Severity classification
- Statistics and evidence

## GENERATED FILES

After scan completion, you'll have:

```
target_directory/
├── VULNERABILITY_REPORT_[timestamp].txt  ← MAIN FINDINGS
├── reckon                                 ← COMPLETE LOG
├── quickscan / quickudpscan              ← PORT SCAN RESULTS
├── [port]-version                         ← SERVICE INFO
├── [port]-nse                            ← NSE FINDINGS
├── [port]-nikto                          ← WEB VULNERABILITIES
├── [port]-dirb                           ← DIRECTORIES
├── [port]-ssl-test                       ← SSL/TLS ISSUES
├── [port]-sqlmap                         ← SQL INJECTION
├── [port]-owasp                          ← OWASP FINDINGS
├── [port]-info-disclosure                ← INFO LEAKS
├── [port]-waf                            ← WAF DETECTION
├── dns-*                                  ← DNS INFO
├── whois-lookup                          ← WHOIS INFO
└── smb-enum4linux                        ← SMB DETAILS
```

## VULNERABILITY CATEGORIES

### SQL Injection
- Automated testing via SQLmap
- Parameter fuzzing
- Database version detection
- Data extraction testing

### SSL/TLS Issues
- Weak protocols (SSLv3, TLS 1.0)
- Weak ciphers
- Heartbleed vulnerability
- Certificate validation issues
- POODLE, BEAST, etc.

### Web Application (OWASP Top 10)
- Broken authentication
- Sensitive data exposure
- XML external entities (XXE)
- Broken access control
- Security misconfiguration
- Unvalidated redirects
- Insufficient logging

### Information Disclosure
- HTTP headers
- Server version information
- Debug pages and error messages
- Source code repositories (Git, SVN)
- Backup files

### Service-Specific
- Anonymous FTP access
- SMTP relay issues
- Null SMB sessions
- Weak SNMP community strings
- Unencrypted services

## FUTURE EXPANSION ROADMAP

The script includes frameworks for future modules:

### API Testing Module (Coming v2.1)
- REST API endpoint discovery
- GraphQL introspection
- API authentication testing
- Rate limiting assessment
- JWT token analysis
- SOAP endpoint testing

### Cloud Testing Module (Coming v2.2)
- AWS S3 bucket enumeration
- Azure blob storage scanning
- Google Cloud Storage assessment
- Misconfiguration detection
- IAM role analysis
- CloudFront configuration review

### Container Scanning Module (Coming v2.3)
- Docker registry enumeration
- Kubernetes cluster assessment
- Container vulnerability scanning
- Container escape testing
- Image layer analysis

### IaC Scanning Module (Coming v2.4)
- Terraform misconfiguration detection
- CloudFormation analysis
- Helm chart security review
- Secrets detection in code

## REQUIRED VS OPTIONAL TOOLS

### Required (Core Functionality)
- nmap
- curl
- dig
- whois

### Highly Recommended
- nikto (web server scanning)
- dirb (directory enumeration)
- enum4linux (SMB enumeration)
- testssl.sh (SSL/TLS testing)
- sqlmap (SQL injection)

### Optional (Enhanced Capabilities)
- nuclei (template-based scanning)
- ffuf (fuzzing)
- zaproxy (web proxy)

## PERFORMANCE TIPS

1. **Faster Scans**
   - Reduce tports to 20-50 for quick scan
   - Disable UDP scanning
   - Target high-value services only

2. **Thorough Scans**
   - Keep tports at 100-1000
   - Enable UDP scanning for comprehensive test
   - Include all vulnerability checks

3. **Network Optimization**
   - Ensure good connectivity to target
   - Run from network close to target
   - Consider network conditions and latency

## SECURITY NOTES

### OSCP Compliance ✅
- No Metasploit multi-handler
- No automated exploitation
- Manual verification required
- All tools in Kali Linux
- Scanning and enumeration only

### Authorization ⚠️
- Always get written permission
- Test only systems you own or authorized
- Follow responsible disclosure
- Document all activities
- Report findings professionally

## TROUBLESHOOTING

### Script won't run
```bash
chmod +x wreckon.sh
```

### Missing tools
```bash
sudo bash install-tools.sh
```

### Permission issues
```bash
sudo ./wreckon.sh <target>
```

### Slow performance
- Check network connectivity
- Reduce tports value
- Run single target vs batch
- Check system resources

## FILES INCLUDED

- `wreckon.sh` - Main script (upgraded with vulnerability scanning)
- `install-tools.sh` - Automated tool installation
- `README_ENHANCED.md` - Detailed documentation
- `QUICKSTART.md` - Quick reference guide
- `FEATURES.md` - This file
- `LICENSE` - Original license
- `README.md` - Original README

## EXAMPLE USAGE

```bash
# Single target
./wreckon.sh 192.168.1.100

# Domain name
./wreckon.sh targetdomain.com

# Batch scan
./wreckon.sh /path/to/targets.txt

# View results
cd 192.168.1.100
cat VULNERABILITY_REPORT_*.txt | less
```

## FURTHER CUSTOMIZATION

Each scanning function can be individually configured:
- `dns_recon()` - DNS enumeration
- `whois_lookup()` - WHOIS data
- `ssl_tls_scan()` - SSL/TLS testing
- `sqlmap_scan()` - SQL injection
- `web_app_vuln_scan()` - OWASP testing
- `cve_check_services()` - CVE correlation
- `service_vuln_check()` - Service-specific tests

Enable/disable functions by commenting in `mainfunction()`.

## VERSION HISTORY

- **v1.0** - Original reconnaissance script
- **v2.0** - Vulnerability scanning, discovery, reporting (CURRENT)
- **v2.1** - API testing module (planned)
- **v2.2** - Cloud testing module (planned)
- **v2.3** - Container scanning module (planned)
- **v2.4** - IaC scanning module (planned)

---

**Questions?** See README_ENHANCED.md for comprehensive documentation.
**Quick help?** See QUICKSTART.md for quick reference.
**Issues?** Check the troubleshooting section above.

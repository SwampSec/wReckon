# Reckon v2.0 - Enhanced Penetration Testing Automation Framework

A comprehensive wrapper script written in bash that automates reconnaissance, discovery, vulnerability scanning, and enumeration tasks during penetration testing. Originally designed for OSCP exam efficiency, now enhanced with extensive vulnerability assessment capabilities.

* Reckon adheres to all OSCP exam restrictions: https://support.offensive-security.com/#!oscp-exam-guide.md

## What's New in v2.0

### Major Enhancements

#### 🔍 Discovery & Reconnaissance
- **DNS Enumeration**: Comprehensive DNS record gathering, zone transfer attempts, WHOIS lookups
- **Service Detection**: Automatic version and service identification on non-standard ports
- **Multi-stage Scanning**: Organized discovery workflow for efficient enumeration

#### 🛡️ Vulnerability Scanning
- **SSL/TLS Analysis**: Heartbleed, weak ciphers, certificate validation issues (testssl.sh)
- **SQL Injection Testing**: Automated SQLmap integration for web parameter testing
- **OWASP Top 10**: Comprehensive web application vulnerability checks
- **Path Traversal**: Directory traversal and LFI/RFI detection
- **Information Disclosure**: Header analysis, version information, debug pages, VCS directories
- **WAF Detection**: Identify and fingerprint Web Application Firewalls

#### 🎯 Service-Specific Testing
- **FTP**: Anonymous access, weak credentials, known vulnerabilities
- **SMTP**: User enumeration, relay testing, vulnerability assessment
- **SMB/CIFS**: Share enumeration, null sessions, privilege escalation vectors
- **SNMP**: Community string enumeration, system information extraction
- **General Services**: CVE correlation with identified service versions

#### 📊 Advanced Features
- **Template-Based Scanning**: Nuclei integration for rapid vulnerability matching
- **Fuzzing**: Directory and parameter fuzzing (ffuf support)
- **Tool Availability Detection**: Gracefully handles missing optional tools
- **Consolidated Reporting**: Unified vulnerability assessment report generation
- **Finding Classification**: Critical, High, Medium risk categorization

### Prerequisites

#### Required Tools
- nmap (with NSE)
- curl
- wget  
- dig (bind-utils)
- whois

#### Optional Enhanced Tools (Recommended)
- nikto - Web server vulnerability scanning
- dirb - Directory enumeration
- enum4linux - SMB enumeration
- testssl.sh - SSL/TLS vulnerability testing
- sqlmap - SQL injection testing
- nuclei - Template-based scanning
- ffuf - Fuzzing

#### Installation on Kali Linux
```bash
sudo apt-get update
sudo apt-get install -y nmap nikto dirb enum4linux

# Optional enhanced tools
curl https://raw.githubusercontent.com/drwetter/testssl.sh/master/testssl.sh > testssl.sh && chmod +x testssl.sh
sudo apt-get install -y sqlmap

# Nuclei (requires Go 1.18+)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# ffuf
go install github.com/ffuf/ffuf@latest
```

## Usage

### Basic Scanning
```bash
# Single host
./wwreckon.sh 10.10.10.10

# Domain name
./wwreckon.sh scanme.nmap.org

# Host list (one per line)
./wwreckon.sh /home/user/targets.txt
```

### Configuration
Edit the script's configuration section to customize:

```bash
# Port scanning options
tports=100              # Number of top ports to scan
udp=False               # Enable UDP scanning (slower)
tcp=True                # Enable TCP scanning

# Feature toggles
dns_enum=True           # DNS reconnaissance and enumeration
ssl_scan=True           # SSL/TLS vulnerability scanning
owasp_scan=True         # OWASP Top 10 checks
web_vuln_scan=True      # Web app vulnerability scanning
password_test=False     # Credential & password testing
service_vuln_scan=True  # Service-specific vulnerability checks
```

## 4-Phase Workflow

### Phase 1: Discovery
**Goal**: Rapid identification of target infrastructure

- Quick port scan (top 100 TCP/UDP ports by default)
- Service version detection
- DNS reconnaissance (A, AAAA, MX, NS records)
- Zone transfer attempts (AXFR)
- WHOIS information gathering
- **Time**: 10-60 seconds

**Output**:
- quickscan, quickudpscan files
- dns-forward-lookup, dns-reverse-lookup, dns-axfr, whois-lookup

### Phase 2: Vulnerability Scanning
**Goal**: Identify exploitable vulnerabilities

- Service vulnerability assessment via NSE scripts
- SSL/TLS security analysis
- Web application scanning (OWASP Top 10)
- SQL injection testing
- Path traversal detection
- Information disclosure identification
- WAF detection
- **Time**: 5-30 minutes (depending on target complexity)

**Output**:
- *-ssl-test (SSL vulnerabilities)
- *-sqlmap (SQL injection findings)
- *-owasp (OWASP findings)
- *-info-disclosure (information leaks)
- *-waf (WAF detection results)

### Phase 3: Deep Enumeration
**Goal**: Comprehensive service enumeration and scanning

- Web server scanning (Nikto)
- Directory enumeration (dirb)
- SMB enumeration (enum4linux)
- Full port scan (all 65,535 TCP/UDP ports)
- Detailed NSE script execution
- User enumeration (SMTP, SNMP)
- Service-specific exploitation testing
- **Time**: 30 minutes - 3 hours

**Output**:
- *-nikto (web vulnerabilities)
- *-dirb (discovered directories)
- *-nse (NSE script results)
- smb-enum4linux (SMB enumeration)
- fullscan (all ports)

### Phase 4: Reporting & Consolidation
**Goal**: Unified findings summary and evidence

- Consolidate all findings into a single report
- Classify findings by severity (Critical, High, Medium)
- Generate statistics (ports, services, vulnerabilities)
- Organize evidence files
- **Time**: 1-2 minutes

**Output**:
- VULNERABILITY_REPORT_*.txt (main findings summary)
- reckon (comprehensive log file)
- Organized directory structure with all scan results

## Output & Results

### Directory Structure
```
./target/
├── quickscan                 # Initial port scan
├── quickudpscan              # UDP port scan
├── [port]-version            # Service version info
├── [port]-nikto              # Web scan results
├── [port]-dirb               # Directory enumeration
├── [port]-nse                # NSE script results
├── [port]-ssl-test           # SSL/TLS vulnerabilities
├── [port]-sqlmap             # SQL injection tests
├── [port]-owasp              # OWASP findings
├── [port]-info-disclosure    # Information disclosure
├── [port]-waf                # WAF detection
├── dns-forward-lookup        # DNS A/AAAA records
├── dns-reverse-lookup        # Reverse DNS
├── dns-axfr                  # Zone transfer results
├── whois-lookup              # WHOIS information
├── smb-enum4linux            # SMB enumeration
├── VULNERABILITY_REPORT_*.txt # Summary report
└── reckon                    # Main log file
```

### Report Contents

The generated VULNERABILITY_REPORT includes:

1. **Critical Findings**: CVEs, RCE, Authentication Bypass
2. **High Risk Findings**: OWASP vulnerabilities, Nuclei templates
3. **Medium Risk**: Service information, potential issues
4. **Web Server Findings**: Nikto and dirb results
5. **SSL/TLS Issues**: Certificate and encryption vulnerabilities
6. **SMB Vulnerabilities**: Share permissions, known exploits
7. **DNS Issues**: Zone transfer success, information disclosure
8. **Statistics**: Total ports, services, vulnerability count

## Vulnerability Categories Assessed

### Web Application (OWASP Top 10)
- A01: Broken Access Control
- A02: Cryptographic Failures (SSL/TLS)
- A03: Injection (SQL, LDAP, Command)
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Logging & Monitoring
- A10: SSRF

### Network Services
- Weak Authentication
- Known Vulnerabilities (CVE)
- Unencrypted Communication
- Unnecessary Services
- Default Credentials

### DNS Security
- Zone Transfers Allowed
- DNS Spoofing Risk
- Information Disclosure

### Cryptography
- Weak SSL/TLS Versions
- Weak Ciphers
- Certificate Issues
- Heartbleed, POODLE, etc.

## Advanced Features

### Modular Architecture
The script is designed with modularity in mind for easy expansion:

```bash
# Future: API Testing Module
# - REST API endpoint discovery
# - GraphQL introspection  
# - API authentication testing

# Future: Cloud Testing Module
# - AWS S3 bucket enumeration
# - Azure blob storage scanning
# - Google Cloud Storage assessment
# - Misconfiguration detection

# Future: Container Scanning Module
# - Docker registry enumeration
# - Kubernetes cluster assessment
# - Container vulnerability scanning

# Future: IaC Scanning Module
# - Terraform misconfiguration detection
# - CloudFormation analysis
# - Helm chart security review
```

### Tool Integration
Reckon automatically detects available tools and gracefully degrades:
- Missing tools are skipped with warnings
- Core functionality continues without optional tools
- Tool availability check at scan start

### Parallel Processing
- Background scanning: Nikto, dirb, and SQLmap run concurrently
- Efficient port testing with optimized nmap parameters
- Time optimization through staged scanning

## Performance Considerations

### Scan Time Estimates
- Quick Scan (top 100 ports): 10-30 seconds
- Version Detection: 2-5 minutes
- Web Application Scanning: 10-20 minutes
- Full Port Scan: 20 minutes - 1 hour
- **Total for comprehensive scan**: 30-90 minutes

### Optimization Tips
1. Adjust `tports` parameter for faster initial scans
2. Disable UDP scanning if not needed (`udp=False`)
3. Reduce service_vuln_scan for faster enumeration
4. Run against network with low latency to target
5. Consider tool-specific timeout adjustments

## Troubleshooting

### Script Not Executing
```bash
chmod +x wreckon.sh
./wreckon.sh <target>
```

### Missing Tools
```bash
# Check which tools are missing
./wreckon.sh <target> 2>&1 | grep "not found"

# Install missing tools
sudo apt-get install -y nikto dirb enum4linux testssl.sh sqlmap
```

### Permission Denied Errors
```bash
# Some NSE scripts require root
sudo ./wreckon.sh <target>
```

### Slow Scans
- Check network connectivity to target
- Reduce top-ports value
- Disable UDP scanning
- Run single-target instead of batch

### False Positives
- Always verify findings with manual testing
- Use multiple tools to confirm vulnerabilities
- Check tool-specific documentation for interpretation

## OSCP Compliance

✅ Adheres to all OSCP exam restrictions:
- No Metasploit multi-handler (auxiliary modules only)
- No automated exploitation (scanning only)
- Manual verification of findings
- All tools in default Kali installation or open-source
- No commercial tools or restricted scripts

## Limitations

1. **Not a replacement for manual testing** - Provides rapid enumeration, not comprehensive penetration testing
2. **False positives possible** - Always validate findings
3. **Evasion awareness** - Consider IDS/IPS monitoring
4. **Target-specific** - Network conditions affect scan times
5. **Tool quality** - Results depend on underlying tool accuracy

## Best Practices

1. Always get written authorization before testing
2. Validate all findings manually
3. Use in controlled lab environments first
4. Document all findings with evidence
5. Report responsibly and provide remediation guidance
6. Consider target's IDS/IPS when tuning scans
7. Combine with manual enumeration for best results

## Future Roadmap

- [ ] API Testing Module (REST/GraphQL/SOAP)
- [ ] Cloud Platform Scanning (AWS/Azure/GCP)
- [ ] Container Security Assessment
- [ ] Infrastructure as Code Analysis
- [ ] Credential Validation Module
- [ ] Reporting Dashboard/Web Interface
- [ ] Integration with Shodan/Censys
- [ ] Community Vulnerability Database
- [ ] Multi-threading for faster scans
- [ ] JSON/XML output formats

## References & Resources

### Vulnerability Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-115](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf)
- [PCI DSS](https://www.pcisecuritystandards.org/)

### Tools Documentation
- [Nmap NSE](https://nmap.org/nsedoc/)
- [Nikto](https://www.cirt.net/Nikto2)
- [SQLmap](http://sqlmap.org/)
- [testssl.sh](https://github.com/drwetter/testssl.sh)
- [Nuclei](https://nuclei.projectdiscovery.io/)

## Author & License

**Original Developer**: MaliceInChains (maliceinchains106@gmail.com)

**Enhanced Version (v2.0+)**: 
- Vulnerability Scanning Integration
- Discovery Automation
- Comprehensive Reporting
- Module Framework for Expansion

**License**: Same as original project

---

**Note**: This script is provided for authorized security testing only. Unauthorized network scanning is illegal. Always obtain proper authorization before testing.

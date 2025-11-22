# wReckon Network Segmentation Testing
## IPv4/IPv6 Detection & ICMP Analysis

---

## Overview

Network segmentation testing identifies firewall rules, ACLs, and network boundaries that restrict traffic flow. wReckon now includes:

- **Automatic IP Version Detection** - Distinguishes IPv4 vs IPv6 automatically
- **ICMP Reconnaissance** - Ping analysis with TTL detection for network hops
- **TCP/UDP Segmentation Testing** - Tests connectivity to common ports
- **Network Boundary Mapping** - Identifies firewall restrictions and filtering

---

## Automatic IPv4/IPv6 Detection

wReckon automatically detects whether a target is IPv4, IPv6, or a domain name that may resolve to either:

### How It Works

```bash
# IPv4 Address (auto-detected)
./wreckon.sh 192.168.1.100
# → Detected: ipv4

# IPv6 Address (auto-detected)
./wreckon.sh 2001:db8::1
# → Detected: ipv6

# Domain Name (auto-resolves and detects)
./wreckon.sh example.com
# → Queries DNS for A and AAAA records
# → Uses IPv4 by default, or IPv6 if configured
```

### Configuration

Enable both IPv4 and IPv6 testing:

```bash
./wreckon.sh --config
SET test_ipv6 = true
# Will now test both if available
```

---

## ICMP Reconnaissance

ICMP testing (ping/ping6) reveals important network information:

### Enable ICMP Monitoring

```bash
./wreckon.sh --config
SET icmp_monitor = true
SET test_ipv6 = true  # Optional: test IPv6 too
done

# Then scan a target
./wreckon.sh 10.10.10.10
```

### What ICMP Reveals

#### 1. Host Reachability
- **Host responds to ping** → Not firewalled, reachable
- **No ping response** → May be behind firewall or down

#### 2. TTL Analysis
TTL (Time To Live) indicates network hops:

```
TTL 64 detected
→ Likely Linux/Mac, probably 1-2 hops away

TTL 128 detected
→ Likely Windows, probably 1-2 hops away

TTL 32 detected
→ Heavily firewalled or many network hops (7+ jumps)
```

#### 3. Network Segmentation
```
TTL decreased significantly
→ Target is behind multiple firewalls/proxies
→ You are on different network segment
```

### Output Files

ICMP tests create:
- `icmp-ping-test` - Raw ping output
- `icmp-ping-test.summary` - Response times
- `icmp-ttl-analysis` - TTL values for analysis

### Example Output

```
[!] ICMP/Ping Reconnaissance on 10.10.10.100 (IPV4)
[-]      Sending 4 ICMP packets...
[✓] Target responds to ICMP
[-]      Host is reachable and not firewalled against ICMP
[-]      TTL Analysis (suggests network hops):
    ttl=64 detected
[-]      Response time: min/avg/max/stddev = 1.2/1.5/2.0/0.3 ms
```

---

## Network Segmentation Testing

### TCP Connectivity Testing

Tests if common TCP ports are accessible:

```bash
SET icmp_monitor = true
SET tcp = true

# Scans: 22 (SSH), 80 (HTTP), 443 (HTTPS)
# Results saved to: tcp-segmentation-test
```

#### TCP Results Interpretation

```
22/tcp open ssh
→ SSH is accessible

80/tcp filtered
→ Firewall blocks HTTP

443/tcp closed ssh
→ HTTPS port rejected
```

### UDP Connectivity Testing

Tests UDP port accessibility:

```bash
SET udp = true
SET icmp_monitor = true

# Scans: 53 (DNS), 123 (NTP), 161 (SNMP)
# Results saved to: udp-segmentation-test
```

#### UDP Results Interpretation

```
53/udp open dns
→ DNS queries allowed

123/udp filtered ntp
→ NTP is blocked

161/udp unreachable snmp
→ SNMP access denied
```

---

## Packet Capture Filters (ICMP)

Capture ICMP traffic separately during network testing:

### ICMP Filter Syntax

**IPv4 ICMP:**
```bash
SET pcap_filter = "icmp"
SET monitor_interface = "eth0"
```

**IPv6 ICMP:**
```bash
SET pcap_filter = "icmp6"
SET monitor_interface = "eth0"
```

**ICMP and Other Protocols:**
```bash
SET pcap_filter = "icmp or tcp port 80 or udp port 53"
```

### Analyzing ICMP Captures

```bash
# View all ICMP packets
tcpdump -r capture.pcap "icmp"

# Extract ICMP details
tcpdump -r capture.pcap "icmp" -vv

# Count ICMP types
tcpdump -r capture.pcap "icmp" | grep -E "echo|reply" | wc -l

# Identify ICMP from specific host
tcpdump -r capture.pcap "icmp and host 10.10.10.10" -vv
```

---

## Network Segmentation Test Scenarios

### Scenario 1: Identify VLAN/Network Boundaries

```bash
# Configuration
./wreckon.sh --config
SET icmp_monitor = true
SET tcp = true
SET udp = true
done

# Run scan
./wreckon.sh 10.20.30.100

# Analysis
# Check output files:
# - icmp-ttl-analysis → shows how far target is
# - tcp-segmentation-test → which TCP ports accessible
# - udp-segmentation-test → which UDP ports accessible

# Conclusion: If TTL low but ports open, likely same segment
#            If TTL high and ports filtered, likely different segment
```

### Scenario 2: Firewall Rule Detection

```bash
# Test both IPv4 and IPv6
SET test_ipv6 = true
SET icmp_monitor = true

# Scan target
./wreckon.sh target.example.com

# Results show:
# IPv4: ICMP blocked, TCP 80/443 open
# IPv6: ICMP allowed, TCP 80/443 blocked
# → Conclusion: Different firewall rules for IPv4 vs IPv6
```

### Scenario 3: DMZ vs Internal Network

```bash
# DMZ Server Test
./wreckon.sh 203.0.113.50

# Results:
# ICMP: Responds (TTL=64)
# TCP 22: Filtered
# TCP 80: Open
# TCP 443: Open
# → Conclusion: DMZ host, only HTTP(S) accessible

# Internal Server Test
./wreckon.sh 192.168.1.100

# Results:
# ICMP: Responds (TTL=64)
# TCP 22: Open
# TCP 80: Filtered
# TCP 3389: Open
# → Conclusion: Internal host with SSH and RDP
```

### Scenario 4: VPN/Tunnel Detection

```bash
# Test through VPN
SET icmp_monitor = true
SET monitor_interface = "tun0"  # VPN interface

./wreckon.sh 10.8.0.0/24

# High TTL + specific port patterns = likely remote network
# Low latency despite high TTL = likely encrypted tunnel
```

---

## Configuration Reference

### Network Segmentation Options

| Option | Values | Purpose |
|--------|--------|---------|
| `icmp_monitor` | True/False | Enable ICMP ping testing |
| `test_ipv6` | True/False | Test IPv6 targets |
| `ip_version` | ipv4/ipv6 | Auto-detected target type |
| `tcp` | True/False | Enable TCP connectivity tests |
| `udp` | True/False | Enable UDP connectivity tests |
| `icmp_filter` | filter | tcpdump ICMP filter syntax |

### Complete Configuration Example

```bash
./wreckon.sh --config

SET icmp_monitor = true
SET test_ipv6 = true
SET tcp = true
SET udp = true
SET monitor_interface = eth0
SET pcap_filter = "icmp or icmp6"
SET tports = 1000

done

# Now run scan
./wreckon.sh 10.10.10.10
```

---

## Advanced Workflows

### Workflow 1: Complete Network Segmentation Assessment

**Terminal 1: Monitor ICMP traffic**
```bash
./wreckon.sh --monitor
# Select eth0, filter: "icmp or icmp6"
```

**Terminal 2: Enable all segmentation tests**
```bash
./wreckon.sh --config
SET icmp_monitor = true
SET test_ipv6 = true
SET tcp = true
SET udp = true
done
```

**Terminal 3: Run scan**
```bash
./wreckon.sh 10.10.10.100
```

**Result:** Complete picture of:
- Network hops (TTL analysis)
- ICMP filtering
- TCP/UDP port accessibility
- Packet captures for forensics

### Workflow 2: Firewall Rule Reverse Engineering

```bash
# Test from different interfaces
./wreckon.sh --config
SET icmp_monitor = true
SET monitor_interface = eth0
SET pcap_filter = "icmp"
done

# Test target A
./wreckon.sh 10.10.10.10

# Switch interface
SET monitor_interface = tun0
./wreckon.sh 10.10.10.10

# Compare results to identify rules
```

### Workflow 3: Network Segmentation Mapping

Scan entire subnet to map firewall rules:

```bash
# Create target list
seq 1 254 | awk '{print "10.10.10."$1}' > targets.txt

# Configure for speed
./wreckon.sh --config
SET icmp_monitor = true
SET tports = 100
SET tcp = true
done

# Scan all
./wreckon.sh targets.txt

# Analyze patterns in results
```

---

## Troubleshooting

### "Target does not respond to ICMP"

**Causes:**
- ICMP filtered by firewall
- Host is down
- Reverse firewall rule

**Solution:**
- Try TCP connectivity tests
- Check if other hosts respond
- Verify target is correct

### IPv6 Detection Not Working

**Check:**
```bash
dig target.com AAAA
# If no results, target doesn't have IPv6
```

**Solution:**
- Verify IPv6 is available on network
- Check `dig` is installed
- Manually set: `SET test_ipv6 = false`

### TTL Analysis Shows 0

**Cause:** Target on local network (no routing)

**Solution:** Normal for local subnet, not a problem

### UDP Port Testing Unreliable

**Cause:** UDP is connectionless, harder to test

**Solution:**
- Use port-specific tools
- Combine with TCP results
- Check firewall logs if available

---

## Quick Reference

### Enable All Network Segmentation Tests

```bash
./wreckon.sh --config
SET icmp_monitor = true
SET test_ipv6 = true
SET tcp = true
SET udp = true
done

./wreckon.sh 192.168.1.100
```

### Capture ICMP Traffic

```bash
./wreckon.sh --monitor
# Filter: icmp or icmp6
```

### Scan IPv6 Target

```bash
./wreckon.sh 2001:db8::1
# Auto-detected as IPv6
```

### Firewall Rule Detection

1. Enable ICMP, TCP, UDP tests
2. Scan target from multiple networks
3. Compare results
4. Identify rule patterns

---

## Output Files Reference

During network segmentation testing, these files are created:

| File | Contains |
|------|----------|
| `icmp-ping-test` | Raw ping output and response times |
| `icmp-ping-test.summary` | Ping response statistics |
| `icmp-ttl-analysis` | TTL values for network hops analysis |
| `tcp-segmentation-test` | TCP port accessibility results |
| `udp-segmentation-test` | UDP port accessibility results |
| `reckon` | Complete scan log with all findings |

---

## Security Considerations

⚠️ **Legal Notice:**
- Only test networks you own or have permission to test
- ICMP reconnaissance may trigger IDS/IPS alerts
- Network segmentation testing is considered active reconnaissance
- Unauthorized network testing is illegal

---

**Created for wReckon v2.3+**  
**Last Updated: November 22, 2025**

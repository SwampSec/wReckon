# wReckon Network Monitoring Module
## Interactive Packet Capture with tcpdump

---

## Overview

The Network Monitoring Module allows you to capture live network traffic with tcpdump and save it to a `.pcap` file. You can:
- **Select network interface** (eth0, en0, tun0, wlan0, VPN interfaces, etc.)
- **Apply traffic filters** (port numbers, protocols, IP addresses)
- **Automatically log packets** with timestamp
- **View packet statistics** after capture
- **Preserve evidence** in standard PCAP format for later analysis

---

## Quick Start

### Launch Network Monitor
```bash
./wreckon.sh --monitor
# or use short form:
./wreckon.sh -m
```

### Interactive Menu
```
[!] Available Network Interfaces:
    [1] eth0 (192.168.1.100)
    [2] en0 (192.168.1.105)
    [3] tun0 (10.8.0.5)
    [4] docker0

Select interface number (or enter custom interface name): 
```

---

## Interface Selection

### By Number
Simply enter the number corresponding to your interface:
```
Select interface number: 1
✓ Selected interface: eth0
```

### By Name
Enter the interface name directly:
```
Select interface number: tun0
✓ Selected interface: tun0
```

### Common Interfaces by OS

**Linux:**
- `eth0`, `eth1` - Ethernet
- `wlan0` - WiFi
- `tun0`, `tap0` - VPN/Tunnel
- `docker0`, `veth*` - Container networks

**macOS:**
- `en0` - Primary interface
- `en1`, `en2` - Secondary interfaces
- `utun0`, `utun1` - VPN tunnels

**All Systems:**
- `lo`, `lo0` - Loopback (excluded from menu)

---

## Traffic Filters

### No Filter (Capture Everything)
```
Enter tcpdump filter: [Press Enter]
Captures: All packets on the interface
```

### Filter by Port
```
Enter tcpdump filter: tcp port 80
Captures: HTTP traffic
```

```
Enter tcpdump filter: udp port 53
Captures: DNS queries
```

### Filter by Protocol
```
Enter tcpdump filter: tcp
Captures: All TCP traffic
```

```
Enter tcpdump filter: udp
Captures: All UDP traffic
```

### Filter by IP Address
```
Enter tcpdump filter: host 192.168.1.100
Captures: Traffic to/from specific host
```

```
Enter tcpdump filter: src 10.10.10.10
Captures: Traffic from specific source
```

```
Enter tcpdump filter: dst 10.10.10.10
Captures: Traffic to specific destination
```

### Combined Filters
```
Enter tcpdump filter: tcp port 443 and host 10.10.10.10
Captures: HTTPS traffic to/from specific host
```

```
Enter tcpdump filter: (tcp port 22 or tcp port 3389) and not host 192.168.1.1
Captures: SSH or RDP except from specific IP
```

### Filter Examples for Pentesting

**Capture web traffic:**
```
tcp port 80 or tcp port 8080 or tcp port 443
```

**Capture DNS and HTTP:**
```
udp port 53 or tcp port 80
```

**Capture traffic between two hosts:**
```
host 192.168.1.100 and host 192.168.1.50
```

**Capture unencrypted traffic (no HTTPS/SSH):**
```
tcp port 80 or tcp port 21 or tcp port 23 or tcp port 25
```

**Capture SYN packets:**
```
tcp[tcpflags] & tcp-syn != 0
```

---

## Output Files

Capture files are saved to `pcap_captures/` directory:

```
pcap_captures/
├── capture_eth0_20251121_101530.pcap
├── capture_tun0_20251121_102045.pcap
└── capture_en0_20251121_103215.pcap
```

**Filename Format:** `capture_[interface]_[YYYYMMDD_HHMMSS].pcap`

---

## Analyzing Captures

### View Packet Summary
During or after capture, view packet details:
```bash
tcpdump -r pcap_captures/capture_eth0_20251121_101530.pcap
```

### Count Packets by Protocol
```bash
tcpdump -r capture.pcap | grep -i "tcp" | wc -l
```

### Extract HTTP Headers
```bash
tcpdump -r capture.pcap -A | grep -i "host\|user-agent\|authorization"
```

### View Unencrypted Data
```bash
tcpdump -r capture.pcap -A | strings | grep -E "password|login|username|secret"
```

### Filter Specific Traffic from File
```bash
tcpdump -r capture.pcap "tcp port 80"
```

### Export to Different Format
```bash
tcpdump -r capture.pcap -w capture_filtered.pcap "tcp port 443"
```

### Use with Wireshark
```bash
wireshark pcap_captures/capture_eth0_20251121_101530.pcap
```

---

## Common Use Cases

### 1. Monitor Target HTTP Traffic
```
Interface: eth0
Filter: tcp port 80 and host 10.10.10.100
Purpose: Capture unencrypted HTTP requests/responses
```

### 2. Monitor DNS Lookups
```
Interface: tun0
Filter: udp port 53
Purpose: See what hosts the target is resolving
```

### 3. Monitor VPN Traffic
```
Interface: tun0
Filter: (blank - all traffic)
Purpose: Capture everything tunneled through VPN
```

### 4. Monitor Credentials in Transit
```
Interface: eth0
Filter: tcp port 21 or tcp port 23 or tcp port 25
Purpose: Capture FTP, Telnet, SMTP credentials
```

### 5. Monitor Database Traffic
```
Interface: eth0
Filter: tcp port 3306 or tcp port 5432 or tcp port 1433
Purpose: MySQL, PostgreSQL, or MSSQL traffic
```

### 6. Monitor SSH Activity
```
Interface: eth0
Filter: tcp port 22
Purpose: Capture SSH connections (encrypted but useful for fingerprinting)
```

---

## Permissions & Privileges

**tcpdump requires elevated privileges:**
- The script automatically uses `sudo` if not running as root
- You'll be prompted for your password on first run
- Subsequent runs in the same session won't prompt again

```bash
./wreckon.sh --monitor
[!] tcpdump requires elevated privileges. Using sudo...
[sudo] password for user:
```

---

## Proof of Concept & Evidence

### Create Timestamped Evidence
The automatic timestamp ensures chronological evidence:
```
capture_eth0_20251121_101530.pcap  # Exactly when capture occurred
```

### Verify Capture Integrity
```bash
# Check file signature (PCAP magic number)
hexdump -C capture.pcap | head -1
# Should show: 00000000  d4 c3 b2 a1 ...
```

### Document Findings
```bash
# Get capture statistics
capinfos pcap_captures/capture_eth0_20251121_101530.pcap

# Create evidence report
ls -lh pcap_captures/ > evidence_manifest.txt
md5sum pcap_captures/*.pcap >> evidence_manifest.txt
```

---

## Integration with Pentesting Workflow

### During Reconnaissance
```bash
# Start monitoring while running scans
./wreckon.sh --monitor
# Select target interface & apply filters
# While capturing, run your other scans in another terminal
```

### During Exploitation
```bash
# Monitor for data exfiltration
./wreckon.sh --monitor
# Filter: tcp port 4444 or tcp port 5555  (C2 ports)
```

### Post-Exploitation
```bash
# Verify lateral movement traffic
./wreckon.sh --monitor
# Filter: host 192.168.1.100 and not port 22
```

---

## Troubleshooting

### "Permission denied" Error
```bash
# Run with sudo explicitly:
sudo ./wreckon.sh --monitor

# Or configure sudo for tcpdump without password:
sudo visudo
# Add: your_user ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
```

### Interface Not Found
```bash
# List all interfaces:
ip link show          # Linux
ifconfig -l           # macOS
ipconfig /all         # Windows (different tool)

# Then use the exact interface name
```

### No Packets Captured
- Verify filter syntax: `man tcpdump` for examples
- Check if traffic exists: use broader filter first
- Verify you selected the correct interface

### Large File Size
- Use filters to reduce capture size
- Rotate captures manually: stop and start new capture
- Consider snapshot length: `tcpdump -s 0` (full packets, larger files)

---

## Advanced Features

### Capture with Details
```bash
# After capture, view with packet details
tcpdump -r capture.pcap -vv
```

### Extract Unencrypted Payloads
```bash
# Show ASCII content from captured packets
tcpdump -r capture.pcap -A | strings
```

### Create Packet Statistics
```bash
# Generate summary statistics
tshark -r capture.pcap -q -z io,phs -z io,stat,1
```

### Monitor Multiple Interfaces Simultaneously
```bash
# Run separate captures in background
./wreckon.sh --monitor &
# Select first interface, let it run
# Then open another terminal and run again
./wreckon.sh --monitor &
```

---

## Security Considerations

⚠️ **Legal Notice:**
- Ensure you have permission to capture network traffic
- Only capture traffic on networks/systems you own or have authorized access to
- Network monitoring without consent is illegal in most jurisdictions

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `./wreckon.sh --monitor` | Launch interactive monitor |
| `./wreckon.sh -m` | Short form |
| `Ctrl+C` | Stop active capture |
| `tcpdump -r file.pcap` | Read capture file |
| `ls pcap_captures/` | List all captures |

---

## Configuration Options

Edit `wreckon.sh` top section to change defaults:

```bash
# === NETWORK MONITORING ===
# Enable tcpdump packet capture monitoring
network_monitor=False
# Default network interface (eth0, en0, tun0, etc)
monitor_interface="eth0"
# Packet capture filter (empty = all traffic)
pcap_filter=""
# Output directory for pcap files
pcap_output_dir="pcap_captures"
```

---

**Created for wReckon v2.1+**  
**Last Updated: November 21, 2025**
